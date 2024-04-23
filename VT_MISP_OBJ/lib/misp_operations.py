import os
from pathlib import Path
from pymisp import PyMISP
from pymisp import MISPEvent, MISPObject, MISPAttribute, MISPSighting
from lib.virus_total import VT
from lib.malware import Malware
from datetime import datetime
import yara
import lief
import tlsh
import logging

logging.basicConfig(filename='misp.log', filemode='w', format='%(asctime)s: %(levelname)s: %(message)s', level=logging.INFO)

class mispOp():
    def __init__(self, url, misp_api_key, vt_api_key) -> None:
        # Set up MISP API client
        misp_api_key = misp_api_key
        misp_url = url
        #try: 
        self.misp = PyMISP(misp_url, misp_api_key, False, True) 
        self.vt = VT(vt_api_key)

        country = 'BR'
        malwares = self.vt.search(country)
            
        if malwares:
            logging.info(f'{country} :: Total malwares uploaded: {len(malwares)}')
            print(f'{country} :: Total malwares uploaded: {len(malwares)}')
            self.process_samples(malwares, country)

        country = 'CL'
        malwares = self.vt.search(country)
    
        if malwares:
            logging.info(f'{country} :: Total malwares uploaded: {len(malwares)}')
            print(f'{country} :: Total malwares uploaded: {len(malwares)}')
            self.process_samples(malwares, country)
        #except Exception as err:
        #    print(f'Error: {err}')
        #    logging.error(f'Error at __init__: {err}')


    # Function to check if a yara rule exists for a given sample
    def check_for_yara_rule(self, sample_path):
        # Get all rules
        rules_list = []
        rules_folder = Path(os.path.abspath(__file__)).parents[1].joinpath('yara')
        for folderName, subfolders, filenames in os.walk(rules_folder):
            for filename in filenames:
                # Compile the YARA rules
                rules = yara.compile(filepath=os.path.join(rules_folder, filename))

                # Run the YARA rules on the file
                matches = rules.match(sample_path)
                if matches:
                    rules_list.append(matches)

        # Check if any rules matched
        if rules_list:
            logging.info(f"Matched {len(rules_list)} YARA rule(s)")
            return matches
        else:
            logging.info(f"No YARA rules matched")
        return ''

    def get_tlsh_text_section(self, file_path):
        try:
            # Check if the file is a PE or ELF
            if lief.is_pe(file_path):
                binary = lief.PE.parse(file_path)
            elif lief.is_elf(file_path):
                binary = lief.ELF.parse(file_path)
            else:
                logging.info(f"{file_path} is not a PE or ELF file")
                return None
            # Get the text section
            text_section = binary.get_section(".text")
            if text_section is not None:
                # Get the data from the text section
                text_data = text_section.content
                # Convert memory view to bytes
                text_data_bytes = bytes(text_data)
                # Calculate the tlsh hash of the text section
                tlsh_hash = tlsh.hash(text_data_bytes)

                if tlsh_hash == 'TNULL': #Without '\0'
                    return None
                return tlsh_hash
            else:
                logging.info(f"{file_path} doesn't have a .text section")
                return None
        except Exception as e:
            logging.error(f"An error occurred: {e}")
            return None
    
    def add_sightings_to_hash(self, event_id:int, hash_value:str, last_seen:str, detection:int):
        # Add if the last date seen is different
        # Get the event
        event = self.misp.get_event(event_id)
        force_update = False
        hash_attribute = None
        # Find the object containing the hash
        for obj in event['Event']['Object']:
            for attribute in obj['Attribute']:
                # check if the last seen is more recent than the stored one
                if attribute['object_relation'] == 'last-seen':
                    date_unix_epoch = int(datetime.strptime(last_seen, '%Y-%m-%d %H:%M:%S').timestamp())
                    if int(attribute['timestamp']) < date_unix_epoch: 
                        # Update the last_seen
                        attribute['timestamp'] = date_unix_epoch
                        attribute['value'] = f"{last_seen}.000000+0000"
                        
                        force_update = True

                        # Update the attribute
                        self.misp.update_attribute(attribute)
                        logging.info('The attribute last-seen was updated')

                # Check if it is sha256 attribute
                if attribute['value'] == hash_value and attribute['type'] == 'sha256':
                    hash_attribute = attribute

                # Check if it is detection attribute
                if attribute['object_relation'] == 'detection':
                    # Update the detection
                    attribute['value'] = detection

                    # Update the attribute
                    self.misp.update_attribute(attribute)

                # Update sha256
                if force_update:  
                    if hash_attribute:
                        # Increase the sightings
                        sight = MISPSighting()
                        if hash_attribute is not None:
                            # Add a sighting
                            self.misp.add_sighting(sighting=sight, attribute=hash_attribute)

                        # Activate the to_ids
                        hash_attribute['to_ids'] = True

                        # Update the attribute
                        self.misp.update_attribute(hash_attribute)
                        
                        logging.info(f'Event {event_id} updated')
                        return
                    else:
                        continue
        logging.info(f"Event {event_id} don't need be updated")
        return

    def event_exists(self, tlsh_hash):
        try:
            # Search for events with the TLSH hash
            search_results = self.misp.search(value=tlsh_hash, type='tlsh')           
            
            # Return the event if one was found, None otherwise
            if search_results:
                return search_results[0].get('Event').get('id')
            else:
                return None
        except Exception as err:
            logging.error(f'Event_exists error: {err}')

    def process_samples(self, malware_list:Malware, country:str):
        #try:
        # Process the hashes that do not already exist in MISP
        for malware in malware_list:
            # Check if the hashes already exist in MISP
            existing_hash = self.misp.search(value=malware.sha256, type_attribute='sha256')
            
            # Hash sent again
            if existing_hash:
                event_id = None
                if existing_hash[0].get('Event').get('Attribute'):
                    event_id = existing_hash[0].get('Event').get('Attribute')[0].get('event_id')
                if not event_id:
                    event_id = existing_hash[0].get('Event')['id']
                print(f'Event_id: {event_id}')
                print(f'Hash was already indexed at event {event_id} ({malware.sha256})')
                logging.info(f'Hash was already indexed at event {event_id} ({malware.sha256})')
                self.add_sightings_to_hash(event_id, malware.sha256, malware.last_submission_date, malware.reputation)
                pass
            # New hash
            else:
                logging.info(f'New hash: {malware.sha256}')
                # Download the sample to check our yara rules and tlsh
                file_path = self.vt.download(malware.sha256)

                # If the file is a PE or ELF the tlsh is calculated only for text section
                tlsh = self.get_tlsh_text_section(file_path)

                if tlsh:
                    malware.tlsh = tlsh
                
                # Search for events with the TLSH hash
                event_exists = self.event_exists(malware.tlsh)

                # Check if an event with this TLSH hash already exists in MISP
                if event_exists:
                    logging.info(f'Add a new object at event')
                    print(f'Add a new object at event')
                    # Add the hash as an attribute to the existing event
                    event_id = event_exists
                    event = self.misp.get_event(event_id, pythonify=True)  
                else:
                    logging.info(f'New tlsh: {malware.tlsh}')

                    # Create a new event with the hash
                    event_obj = MISPEvent()
                    event_obj.info = f'Event for {malware.tlsh}'  # Required
                    event_obj.distribution = 0  
                    event_obj.threat_level_id = 3
                    event_obj.analysis = 1
                    event_obj.add_tag('tlp:red')
                    event = self.misp.add_event(event_obj, pythonify=True)
                    event_id = event.id

                    # Add the TLSH hash as an attribute to the event
                    attribute = MISPAttribute()
                    attribute.type = 'tlsh'
                    attribute.value = malware.tlsh
                    attribute.category = 'Payload delivery'
                    attribute.to_ids = False
                    if tlsh:
                        attribute.add_tag(f'MPH:content:.text')
                    self.misp.add_attribute(event_id, attribute, pythonify=True)

                print(f'Event id: {event_id}')
                logging.info(f'Event id: {event_id}')
            
                # Create a new object
                new_object = MISPObject('mph_sample')
                new_object = event.add_object(new_object)

                # Add the SHA256 hash to the object
                hash_attribute = new_object.add_attribute('sha256', type='sha256',
                        value=malware.sha256, disable_correlation=True, to_ids=False)
                hash_attribute.add_tag(f'MPH:submitted-country: {country}')

                for obj in event.get('Object', []):
                    if 'meta-category' in obj: continue
                    obj['meta-category'] = 'misc'
                    obj['template_uuid'] = 'c24dec0c-3431-49a4-b1e4-77d45fe96e73'

                # Add the country to the object
                new_object.add_attribute('country', type='text', value=country, disable_correlation=True)

                # Add the link to the object
                new_object.add_attribute('url', type='url', value=malware.url, disable_correlation=True, to_ids=False)

                # Add the first-seen to the object
                new_object.add_attribute('first-seen', type='datetime', value=malware.first_submission_date, disable_correlation=True)

                # Add the last-seen to the object
                new_object.add_attribute('last-seen', type='datetime', value=malware.last_submission_date, disable_correlation=True)

                # Add the number of detections in VT to the object
                new_object.add_attribute('detection', type='counter', value=malware.reputation, disable_correlation=True)

                # Add the info about signed of file
                new_object.add_attribute('signed', type='boolean', value=malware.signed, disable_correlation=True)

                # Add the malware type to the object
                new_object.add_attribute('type', type='text', value=malware.file_type, disable_correlation=True)

                # Add the malware compiler to the object
                new_object.add_attribute('compiler', type='text', value=malware.compiler, disable_correlation=True)

                # Add the malware language-code to the object
                new_object.add_attribute('language-code', type='text', value=malware.country_language, disable_correlation=True)
                
                # Add the malware filepath to the object
                new_object.add_attribute('filepath', type='text', value=file_path, disable_correlation=True)
            
                # Check for a YARA rule for the sample
                yara_rule = self.check_for_yara_rule(file_path)

                # Set event attributes based on yara rule presence
                if yara_rule:
                    for rule in yara_rule:
                        new_object.add_attribute(type='yara', value=rule)

                # Update the object to the event
                self.misp.update_event(event=event)
                
        #except Exception as err:
        #    logging.error(f'process_samples error: {err}')
            
