import requests
import bs4

url = "https://attack.mitre.org/techniques/"
technic_id = "T1595"

response = requests.get(url + technic_id)

if response.status_code == requests.codes.ok:
    mitre_page = bs4.BeautifulSoup(response.text, 'html.parser')
    groups_name = mitre_page.select('table.table:nth-child(4) > tbody:nth-child(2) > tr > td:nth-child(2) > a') # table.table:nth-child(4) > tbody:nth-child(2) > tr:nth-child(1) > td:nth-child(2)
    for group in groups_name:
        print(group.getText())
    #print(group_name[2].getText())


