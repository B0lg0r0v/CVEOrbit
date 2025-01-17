# -*- coding: utf-8 -*-

from core.parser import parse_args
from core.colors import banner, Colors
from core.fetching import Fetcher

def main():

    # Initializing some classes
    args = parse_args()
    color = Colors()
    fetch = Fetcher()

    if not args.silent:
        banner()

    # Debug info
    g_DEBUG = args.debug

    if args.Mode == 'search':

        # Dicts for the names and filters
        # Names are basically the vendors or products you would search for
        # Filters are the filtering mechanism you can use to narrow down the search (refer to the -h flag)
        names = { }
        filters = { }

        # Handling this mess
        if args.output is False:

            # Supplying only keywords
            if args.filter_keywords and not any([
                args.filter_id,
                args.filter_severity_3,
                args.filter_severity_4,
                args.filter_last_modified_start_date,
                args.filter_last_modified_end_date,
                args.filter_published_start_date,
                args.filter_published_end_date
            ]):
                print(color.blue(f'[INF] Filtering with keywords: {args.filter_keywords}'))
                
                names['keywordSearch'] = args.filter_keywords
                fetch.fetch_cve_keywords(names, filters, SAVE_TO_JSON=False, DEBUG=g_DEBUG)

            # Supplying keywords and filters
            if args.filter_keywords:

                # Only keywords and severity v3
                if args.filter_severity_3 and not any([
                    args.filter_severity_4,
                    args.filter_last_modified_start_date,
                    args.filter_last_modified_end_date,
                    args.filter_published_start_date,
                    args.filter_published_end_date
                    ]):
                    print(color.blue(f'[INF] Filtering with keywords: {args.filter_keywords} and severity: {args.filter_severity_3}'))
                    
                    names['keywordSearch'] = args.filter_keywords
                    filters['cvssV3Severity'] = args.filter_severity_3
                    fetch.fetch_cve_keywords(names, filters, SAVE_TO_JSON=False, DEBUG=g_DEBUG)

                # Only keywords and severity v4
                if args.filter_severity_4 and not any([
                    args.filter_severity_3,
                    args.filter_last_modified_start_date,
                    args.filter_last_modified_end_date,
                    args.filter_published_start_date,
                    args.filter_published_end_date
                    ]):

                    print(color.blue(f'[INF] Filtering with keywords: {args.filter_keywords} and severity: {args.filter_severity_4}'))
                    
                    names['keywordSearch'] = args.filter_keywords
                    filters['cvssV4Severity'] = args.filter_severity_4
                    fetch.fetch_cve_keywords(names, filters, SAVE_TO_JSON=False, DEBUG=g_DEBUG)

                # Only keywords and last modified date
                if args.filter_last_modified_start_date and args.filter_last_modified_end_date and not any([
                    args.filter_severity_3,
                    args.filter_severity_4,
                    args.filter_published_start_date,
                    args.filter_published_end_date
                    ]):

                    print(color.blue(f'[INF] Filtering with keywords: {args.filter_keywords} and last modified date: {args.filter_last_modified_start_date} - {args.filter_last_modified_end_date}'))
                    
                    names['keywordSearch'] = args.filter_keywords
                    filters['lastModStartDate'] = args.filter_last_modified_start_date
                    filters['lastModEndDate'] = args.filter_last_modified_end_date
                    fetch.fetch_cve_keywords(names, filters, SAVE_TO_JSON=False, DEBUG=g_DEBUG)
                

                # Only keywords and last published date
                if args.filter_published_start_date and args.filter_published_end_date and not any([
                    args.filter_severity_3,
                    args.filter_severity_4,
                    args.filter_last_modified_start_date,
                    args.filter_last_modified_end_date
                    ]):

                    print(color.blue(f'[INF] Filtering with keywords: {args.filter_keywords} and published date: {args.filter_published_start_date} - {args.filter_published_end_date}'))
                    
                    names['keywordSearch'] = args.filter_keywords
                    filters['pubStartDate'] = args.filter_published_start_date
                    filters['pubEndDate'] = args.filter_published_end_date
                    fetch.fetch_cve_keywords(names, filters, SAVE_TO_JSON=False, DEBUG=g_DEBUG)

                #-------------------------------------------------------------#

                # Keywords, severity v3 and last modified date
                if args.filter_severity_3 and args.filter_last_modified_start_date and args.filter_last_modified_end_date:
                    print(color.blue(f'[INF] Filtering with keywords: {args.filter_keywords}, severity: {args.filter_severity_3} and last modified date: {args.filter_last_modified_start_date} - {args.filter_last_modified_end_date}'))
                    
                    names['keywordSearch'] = args.filter_keywords
                    filters['cvssV3Severity'] = args.filter_severity_3
                    filters['lastModStartDate'] = args.filter_last_modified_start_date
                    filters['lastModEndDate'] = args.filter_last_modified_end_date
                    fetch.fetch_cve_keywords(names, filters, SAVE_TO_JSON=False, DEBUG=g_DEBUG)
                
                # Keywords, severity v3 and last published date
                if args.filter_severity_3 and args.filter_published_start_date and args.filter_published_end_date:
                    print(color.blue(f'[INF] Filtering with keywords: {args.filter_keywords}, severity: {args.filter_severity_3} and published date: {args.filter_published_start_date} - {args.filter_published_end_date}'))
                    
                    names['keywordSearch'] = args.filter_keywords
                    filters['cvssV3Severity'] = args.filter_severity_3
                    filters['pubStartDate'] = args.filter_published_start_date
                    filters['pubEndDate'] = args.filter_published_end_date
                    fetch.fetch_cve_keywords(names, filters, SAVE_TO_JSON=False, DEBUG=g_DEBUG)

                # Keywords, severity v4 and last modified date
                if args.filter_severity_4 and args.filter_last_modified_start_date and args.filter_last_modified_end_date:
                    print(color.blue(f'[INF] Filtering with keywords: {args.filter_keywords}, severity: {args.filter_severity_4} and last modified date: {args.filter_last_modified_start_date} - {args.filter_last_modified_end_date}'))
                    
                    names['keywordSearch'] = args.filter_keywords
                    filters['cvssV4Severity'] = args.filter_severity_4
                    filters['lastModStartDate'] = args.filter_last_modified_start_date
                    filters['lastModEndDate'] = args.filter_last_modified_end_date
                    fetch.fetch_cve_keywords(names, filters, SAVE_TO_JSON=False, DEBUG=g_DEBUG)

                # Keywords, severity v4 and last published date
                if args.filter_severity_4 and args.filter_published_start_date and args.filter_published_end_date:
                    print(color.blue(f'[INF] Filtering with keywords: {args.filter_keywords}, severity: {args.filter_severity_4} and published date: {args.filter_published_start_date} - {args.filter_published_end_date}'))
                    
                    names['keywordSearch'] = args.filter_keywords
                    filters['cvssV4Severity'] = args.filter_severity_4
                    filters['pubStartDate'] = args.filter_published_start_date
                    filters['pubEndDate'] = args.filter_published_end_date
                    fetch.fetch_cve_keywords(names, filters, SAVE_TO_JSON=False, DEBUG=g_DEBUG)
                


            if args.filter_id:
                print(color.blue(f'[INF] Filtering with CVE-ID: {args.filter_id}'))
                
                names['cveId'] = args.filter_id
                fetch.fetch_cve_keywords(names, filters, SAVE_TO_JSON=False, DEBUG=g_DEBUG)

                

        elif args.output is True:

            if args.filter_keywords and not args.filter_severity_3:
                print(color.blue(f'[INF] Filtering with keywords: {args.filter_keywords}'))
                
                names['keywordSearch'] = args.filter_keywords
                fetch.fetch_cve_keywords(names, filters, SAVE_TO_JSON=True, DEBUG=g_DEBUG)

            if args.filter_keywords and args.filter_severity_3:
                print(color.blue(f'[INF] Filtering with keywords: {args.filter_keywords} and severity: {args.filter_severity_3}'))
                
                names['keywordSearch'] = args.filter_keywords
                filters['cvssV3Severity'] = args.filter_severity_3
                fetch.fetch_cve_keywords(names, filters, SAVE_TO_JSON=True, DEBUG=g_DEBUG)




if __name__ == '__main__':
    main()