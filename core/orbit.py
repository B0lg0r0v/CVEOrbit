# -*- coding: utf-8 -*-

from core.colors import Colors
from functools import reduce
import requests
import textwrap
import json
import time
import os
from datetime import datetime
import sys

class Orbit:

    def __init__(self):
        self.base_url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.80 Safari/537.36',
            'Content-Type': 'application/json'
        }
        self.params = { }
        self.names = { }
        self.colors = Colors()
        self.last_fetched_timestamp = None


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
    
    
    def search_engine(self, names, filters=None, SAVE_TO_JSON=False, DEBUG=False) -> list:
        
        # The "l_params" list is used to store each URL for each vendor or product
        l_params = []

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

        # The "results" list is used to store the fetched CVEs if you want to save them to a JSON file
        results = []
        for param in l_params:
                            
                # Debug info
                if DEBUG:
                    print(self.colors.light_yellow(f'[DBG] Requesting the following URL: [{param}]'))

                # The API can be overloaded, or unreachable for some reason, so I decided to still continue the requests until it is back to "normal"
                while True:

                    # Some error handling in case there is an issue with the API, internet connection, etc.
                    try:
                        response = requests.get(param, headers=self.headers)
                        response.raise_for_status()
                        data = response.json()

                        if response.status_code == 200:
                            if DEBUG:
                                print(self.colors.light_yellow(f'[DBG] HTTP response code: \t{response.status_code} OK'))
                            break

                    # Handling HTTP errors
                    except requests.exceptions.HTTPError as e:
                        if response.status_code >= 500:
                            print(self.colors.red(f'[ERR] HTTP error occurred: {e}'))
                            time.sleep(1800) # Sleep for 30 minutes in case of server error
                            continue

                        else:
                            print(self.colors.red(f'[ERR] HTTP error occurred: {e}'))
                            break
                    
                    except json.decoder.JSONDecodeError as e:
                        print(self.colors.red(f'[ERR] JSON error occurred: {e}'))
                        break

                # Checking the data variable for NoneType
                if data is None:
                    print(self.colors.red(f'[ERR] No data found for {f_value}'))
                    continue
                
                # Getting the amount of vulnerabilities found (amount of keys inside the 'vulnerabilities' key)
                amount = len(data['vulnerabilities'])
                if amount == 0:
                    #print(self.colors.blue(f'[INF] Found 0 vulnerabilities for {f_value}'))
                    continue

                # Looping through the amount of vulnerabilities found
                for i in range(amount):
                    
                    # Printing this only once. Quick and dirty way xD
                    if i == 0:
                        print(self.colors.blue(f'[INF] Found {amount} vulnerabilities for {f_value}'))
                        print(Colors.bold(Colors.green(f'\nResults for {f_value}:\n')))
                    
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

                
   
        return results
    

    def continuous_monitoring(self, names, filters, update_period, request_limit, SAVE_TO_JSON=False, DEBUG=False):
        
        request_count = 0
        timer = time.time()
        start_time = datetime.now().strftime('%Y-%m-%dT%H:%M:%S.000')
        file_path = 'cveorbit_monitoring.json'
        file_size_limit = 200 * 1024 * 1024

        # This is useless but I love it! xD
        spinner = ['|', '/', '-', '\\']

        # If there are more than 1 vendor or products, the search engine will do a GET request for each of them.
        values = list(names.values())
        f_values = self.flatten_if_nested(values)
        
        if len(f_values) > 1:
            request_limit /= len(f_values)

        try:
            while True:
                if request_count < request_limit:
                   
                    filters['pubStartDate'] = start_time
                    filters['pubEndDate'] = datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]

                    results = self.search_engine(names, filters, SAVE_TO_JSON, DEBUG)

                    if SAVE_TO_JSON:
                        if os.path.exists(file_path) and os.path.getsize(file_path) < file_size_limit:
                            mode = 'a'
                        else:
                            mode = 'w'

                        if results:
                            with open(file_path, mode) as f:
                                json.dump(results, f, indent=5)
                                f.write('\n')
                    
                    request_count += 1
                    if DEBUG:
                        print(self.colors.light_yellow(f'[DBG] Request count: \t\t{request_count}'))

                else:
                    elapsed_time = time.time() - timer

                    if elapsed_time < update_period:

                        if DEBUG:
                            print(self.colors.light_yellow(f'[DBG] Sleeping for: \t\t{update_period} seconds'))
                        
                        # Visual timer
                        for remaining in range(int(update_period), 0, -1):
                            for symbol in spinner:
                                sys.stdout.write(self.colors.blue(f"\r[INF] Sleeping: {remaining} seconds remaining {symbol}"))
                                sys.stdout.flush()
                                time.sleep(0.25)

                    request_count = 0
                    timer = time.time()
        
        except KeyboardInterrupt:
            print(self.colors.blue(f'\n[INF] You aborted the fetching process. Exiting...'))
            exit(0)