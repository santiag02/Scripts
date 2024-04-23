import os
import requests
import urllib3
from datetime import datetime
from lib.malware import Malware
from pprint import pprint

urllib3.disable_warnings()

class VT():
    def __init__(self, api_key:str)->None:
        # Set up VirusTotal API client
        self.vt_base_url = 'https://www.virustotal.com/api/v3/'
        self.vt_headers = {'x-apikey': api_key}

    def unixEpoch_to_utc(self, date:str):
        # Convert Unix timestamp to datetime
        utc_datetime = datetime.utcfromtimestamp(date)
        return str(utc_datetime)

    def search(self, country:str)->list:
        
        # Country: BR, CL
        # Search for samples in VirusTotal
        today = datetime.today().strftime('%Y-%m-%d') + 'T00:00:00+'
        query = f'(type:pe OR type:elf OR type:pdf OR type:email) AND positives:5+ AND ls:{today} AND submitter:{country}' 
        vt_params = {'query': query, 'limit': 100}
        vt_response = requests.get(self.vt_base_url + 'intelligence/search', params=vt_params, headers=self.vt_headers)
        response_data = vt_response.json()

        malwares = []
        # Get the hashes of the results
        for result in response_data['data']:
            compiler = None
            signed = False
            if result.get('attributes').get('detectiteasy'):
                    compiler = result.get('attributes').get('detectiteasy', {}).get('values')[0]['name']
            if result.get('attributes').get('signature_info'):
                if result.get('attributes').get('signature_info').get('verified') == 'Signed':
                    signed = True  
        
            sample = Malware(
                sha256= result.get('attributes').get('sha256'),
                tlsh = result.get('attributes').get('tlsh'),
                reputation = result.get('attributes').get('last_analysis_stats').get('malicious'),
                first_submission_date = self.unixEpoch_to_utc(result.get('attributes').get('first_submission_date')), 
                last_submission_date = self.unixEpoch_to_utc(result.get('attributes').get('last_submission_date')),
                file_type = result.get('attributes').get('magic'),
                country_language = result.get('attributes').get('exiftool', {}).get('LanguageCode'),
                compiler = compiler,
                signed = signed
            )
            malwares.append(sample)
        
        return malwares

    def get_file(self, hash:str): 
        vt_response = requests.get(self.vt_base_url + 'files/' + hash, headers=self.vt_headers)
        result = vt_response.json()
        
        compiler = None
        signed = False
        if result.get('data').get('attributes').get('detectiteasy'):
                compiler = result.get('data').get('attributes').get('detectiteasy').get('values')[0]['name']
        if result.get('data').get('attributes').get('signature_info'):
            if result.get('data').get('attributes').get('signature_info').get('verified') == 'Signed':
                signed = True  

        sample = Malware(
            sha256= result.get('data').get('attributes').get('sha256'),
            tlsh = result.get('data').get('attributes').get('tlsh'),
            reputation = result.get('data').get('attributes').get('last_analysis_stats').get('malicious'),
            first_submission_date = self.unixEpoch_to_utc(result.get('data').get('attributes').get('first_submission_date')), 
            last_submission_date = self.unixEpoch_to_utc(result.get('data').get('attributes').get('last_submission_date')),
            file_type = result.get('data').get('attributes').get('magic'),
            country_language = result.get('data').get('attributes').get('exiftool', {}).get('LanguageCode'),
            compiler = compiler,
            signed = signed
        )
        
        return sample


    def download(self, sample_hash):
        # Download the sample from VirusTotal
        
        vt_response = requests.get(self.vt_base_url + f'files/{sample_hash}/download', headers=self.vt_headers)
        vt_sample_data = vt_response.content

        # Create a folder with the current date as the name
        date_str = datetime.now().strftime('%Y-%m-%d')
        folder_path = os.path.join('samples', date_str)

        # Check if the folder already exists
        if not os.path.exists(folder_path):
            # Create the folder if it doesn't exist
            os.makedirs(folder_path)

        # Save the sample to the folder
        file_path = os.path.join(folder_path, str(sample_hash))
        with open(file_path, 'wb') as f:
            f.write(vt_sample_data)

        return file_path

    def who_sent(self, hash:str):
        pass
