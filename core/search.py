# -*- coding: utf-8 -*-

import requests
import json
import datetime
from functools import reduce
import textwrap

from core.colors import Colors

class Fetcher:

    def __init__(self):
        self.base_url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.80 Safari/537.36',
            'Content-Type': 'application/json'
        }
        self.params = { }
        self.names = { }
        self.colors = Colors()


    """
    This function is used to flatten nested lists
    """
    @staticmethod
    def flatten_list(lst) -> list:
        return list(reduce(lambda x, y: x + (y if isinstance(y, list) else [y]), lst, []))
    
    
    '''
    I use this to check if the list is nested. If it is, I flatten it. 
    '''
    def flatten_if_nested(self, lst) -> list:
        # Checking if any element in the list is a list itself
        if any(isinstance(i, list) for i in lst):
            return self.flatten_list(lst)
        return lst
    

    """
    Function to fetch CVEs via the search mode. You can give as many filters as you want to the function. My goal was to make the filtering mechanism as flexible as possible by
    "dynamically" constructing the URL depending on the filters you provide.
    """
    def fetch_cve_keywords(self, names, filters=None,  SAVE_TO_JSON=False, DEBUG=False) -> None:
        
        # The "l_params" list is used to store each URL for each vendor or product
        l_params = []

        # Debug info
        if DEBUG:
            print(self.colors.light_yellow(f'[DBG] Debug mode is set to: {DEBUG}'))
            print(self.colors.light_yellow(f'[DBG] SAVE_TO_JSON is set to: {SAVE_TO_JSON}'))

        # I have made two separate dictionaries for the so called "names", which are basically vendors and/or products you would search for. And then
        # we have the filters, which are the filtering mechanism you can use to narrow down the search (refer to the -h flag).
        # I'm not sure if this is the "elegant" way to do this, but for now it can "dnyamically" construct the URL depending on your filters.
        if names:
            for key, value in names.items():
                self.names.update({ key: value })

        if filters:
            for key, value in filters.items():
                self.params.update({ key: value })

        # Separating the key and the values for felixbility
        keys = list(self.names.keys())
        values = list(self.names.values())

        # Same as above but for the filters
        f_keys = list(self.params.keys())
        f_values = list(self.params.values())

        # If you are unsure what those values are, use the -d flag to enable the DEBUG mode which will print the results below
        if DEBUG:
            print(self.colors.light_yellow(f'[DBG] Found the following NAME keys: {keys}'))
            print(self.colors.light_yellow(f'[DBG] Found the following NAME values: {values}'))
            print(self.colors.light_yellow(f'[DBG] Found the following FILTER keys: {f_keys}'))
            print(self.colors.light_yellow(f'[DBG] Found the following FILTER values: {f_values}'))

        # Flattening the lists (it's a nested list)
        f_value = self.flatten_if_nested(values)

        # This is the URL "construction" mechanism. It will dynamically construct the URL depending on the filters you provide.
        # If you do not provide any filters, the standard URL will be only based on the keywordSearch key, which contains the "names" you provide.
        if not filters:
            for x in values:
                if isinstance(x, list): # If the value is a list, we need to iterate through it
                    for y in x:
                        l_params.append(f'{self.base_url}?{keys[0]}={y}')
                else:
                    l_params.append(f'{self.base_url}?{keys[0]}={x}')
        
        else:
            for x in values:
                if isinstance(x, list): # Same as above
                    for y in x:
                        url = f'{self.base_url}?{keys[0]}={y}'
                        for z, n in zip(f_keys, f_values):
                            url += f'&{z}={n}'
                        l_params.append(url)
                else:
                    url = f'{self.base_url}?{keys[0]}={x}'
                    for z, n in zip(f_keys, f_values):
                        url += f'&{z}={n}'
                    l_params.append(url)

        # Debug info
        if DEBUG:
            print(self.colors.light_yellow(f'[DBG] Constructed the following URL: {l_params}'))

        counter = 0 # Counter for tracking which vendor or product we are fetching the CVEs for
        # Fetching the CVEs
        try:
            for param in l_params:

                # The "results" list is used to store the fetched CVEs if you want to save them to a JSON file
                results = []

                # Debug info
                if DEBUG:
                    print(self.colors.light_yellow(f'[DBG] Requesting the following URL: [{param}]'))

                # Some error handling in case there is an issue with the API, internet connection, etc.
                try:
                    response = requests.get(param, headers=self.headers)
                    response.raise_for_status()
                    data = response.json()

                except Exception as e:
                    print(self.colors.light_red(f'[ERR] An error occured while fetching the data: {e}'))


                
                # Getting the amount of vulnerabilities found (amount of keys inside the 'vulnerabilities' key)
                amount = len(data['vulnerabilities'])
                if amount == 0:
                    print(self.colors.blue(f'[INF] Found 0 vulnerabilities for {f_value[counter]}'))
                    counter += 1
                    continue

                # Looping through the amount of vulnerabilities found
                for i in range(amount):
                    
                    # Printing this only once. Quick and dirty way xD
                    if i == 0:
                        print(self.colors.blue(f'[INF] Found {amount} vulnerabilities for {f_value[counter]}'))
                        print(Colors.bold(Colors.green(f'\nResults for {f_value[counter]}:\n')))
                    
                    # We can now fetch the keys and values from the JSON response
                    cve_id = data['vulnerabilities'][i]['cve']['id']
                    description = data['vulnerabilities'][i]['cve']['descriptions'][0]['value']
                    timestamp = data['vulnerabilities'][i]['cve']['published']
                    last_modified = data['vulnerabilities'][i]['cve']['lastModified']

                    # Default values for CVSS metrics
                    base_score = 'N/A'
                    base_severity = 'N/A'
                    version = 'N/A'

                    # I'm leaving it like this for now. Maybe I'll find a more elegant way to do this.
                    if 'metrics' in data['vulnerabilities'][i]['cve']:
                        metrics = data['vulnerabilities'][i]['cve']['metrics']

                    if DEBUG:
                        print(self.colors.light_yellow(f'[DBG] Found the following metrics: {json.dumps(metrics, indent=5)}'))

                    # Here we are handling the case if the CVSS version is 2.0. The key arrangement is different
                    # Depending on the CVSS Score version.
                    if 'cvssMetricV2' in metrics:
                        version = metrics['cvssMetricV2'][0]['cvssData']['version']
                        base_score = metrics['cvssMetricV2'][0]['cvssData']['baseScore']
                        base_severity = metrics['cvssMetricV2'][0]['baseSeverity']

                    # Handling version 3.0
                    if 'cvssMetricV30' in metrics:
                        version = metrics['cvssMetricV30'][0]['cvssData']['version']
                        base_score = metrics['cvssMetricV30'][0]['cvssData']['baseScore']
                        base_severity = metrics['cvssMetricV30'][0]['cvssData']['baseSeverity']

                    # Handling version 3.1
                    if 'cvssMetricV31' in metrics:
                        version = metrics['cvssMetricV31'][0]['cvssData']['version']
                        base_score = metrics['cvssMetricV31'][0]['cvssData']['baseScore']
                        base_severity = metrics['cvssMetricV31'][0]['cvssData']['baseSeverity']

                    # I'm not sure for this one
                    if 'cvssMetricV40' in metrics:
                        version = metrics['cvssMetricV40'][0]['cvssData']['version']
                        base_score = metrics['cvssMetricV40'][0]['cvssData']['baseScore']
                        base_severity = metrics['cvssMetricV40'][0]['cvssData']['baseSeverity']

                    # Using textwrap to align long descriptions properly
                    wrapped_desc = textwrap.fill(description, width=90, subsequent_indent=' ' * 24)

                    # Pretty printing everything :D                   
                    print(f'\tCVE ID: \t{cve_id}')
                    print(f'\tCVSS Version: \t{version}')
                    print(f'\tSeverity: \t{Colors.bold(base_severity)}')
                    print(f'\tBase Score: \t{base_score}')
                    print(f'\tPublished: \t{timestamp}')
                    print(f'\tLast Modified: \t{last_modified}')
                    print(f'\tDescription: \t{wrapped_desc}\n')

                   
                    # Saving the results into a list
                    results.append({
                        'CVE ID': cve_id,
                        'CVSS Version': version,
                        'Severity': base_severity,
                        'Base Score': base_score,
                        'Published': timestamp,
                        'Last Modified': last_modified,
                        'Description': description
                    })
                
                # Saving the results to a JSON file
                if SAVE_TO_JSON:
                   with open(f'cveorbit_results_{f_value[counter]}_{datetime.datetime.now().strftime("%Y%m%d%H%M%S")}.json', 'w') as f:
                        json.dump(results, f, indent=4)
                        print(self.colors.blue(f'[INF] Successfully exported the fetched CVEs to cveorbit_results_{f_value[counter]}_{datetime.datetime.now()}.json\n'))

                # Incrementing the counter to fetch the next vendor or product
                counter += 1

        except KeyboardInterrupt:
            print(self.colors.blue('[INF] You aborted the fetching process. Exiting...'))
            exit(0)

        except Exception as e:
            print(self.colors.light_red(f'[ERR] An error occured while fetching the data: {e}'))
            exit(1)
            
