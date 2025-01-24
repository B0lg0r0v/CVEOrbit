import argparse
import datetime

def common_args(parser, monitoring=True, search=True):

    # Creating groups for better visibility
    filtering_group = parser.add_argument_group('Filtering')
    options_group = parser.add_argument_group('Options')
    alert_group = parser.add_argument_group('Alerting')
    debug_group = parser.add_argument_group('Debugging')

    # Main orbit arguments
    if monitoring:
        filtering_group.add_argument('-fkey', '--filter-keywords', type=str, help='Used to filter the search with a specific keyword. For example vendor, product, etc.', nargs='+')
        filtering_group.add_argument('-fsv3', '--filter-severity-3', type=str, help='Used to filter the search with a specific severity (CVSSv3): LOW, MEDIUM, HIGH or CRITICAL')
        filtering_group.add_argument('-fsv4', '--filter-severity-4', type=str, help='Used to filter the search with a specific severity (CVSSv4): LOW, MEDIUM, HIGH or CRITICAL')

    # Only available in search mode
    if search:
        filtering_group.add_argument('-fkey', '--filter-keywords', type=str, help='Used to filter the search with specific keywords. For example vendor, product, etc.', nargs='+')
        filtering_group.add_argument('-fid', '--filter-id', type=str, help='Used to filter the search with a specific CVE. Format: CVE-YYYY-NNNN', nargs='+')
        filtering_group.add_argument('-fsv3', '--filter-severity-3', type=str, help='Used to filter the search with a specific severity (CVSSv3): LOW, MEDIUM, HIGH or CRITICAL')
        filtering_group.add_argument('-fsv4', '--filter-severity-4', type=str, help='Used to filter the search with a specific severity (CVSSv4): LOW, MEDIUM, HIGH or CRITICAL')
        filtering_group.add_argument('-flmsd', '--filter-last-modified-start-date', type=str, help='REQUIRES the "-flmed" argument to work. Used to filter the search with a start date for the "last modified date" key. Format: YYYY-MM-DDT00:00:00')
        filtering_group.add_argument('-flmed', '--filter-last-modified-end-date', type=str, help='REQUIRES the "-flmsd" argument to work. Used to filter the search with an end date for the "last modified date" key. Format: YYYY-MM-DDT00:00:00')
        filtering_group.add_argument('-fpsd', '--filter-published-start-date', type=str, help='REQUIRES the "-fped" argument to work. Used to filter the search with a start date for the published date. Format: YYYY-MM-DDT00:00:00')
        filtering_group.add_argument('-fped', '--filter-published-end-date', type=str, help='REQUIRES the "-fped" argument to work. Used to filter the search with an end date for the published date. Format: YYYY-MM-DDT00:00:00')

    # Only available in monitoring mode
    if monitoring:
        #options_group.add_argument('-lc', '--limit-cve', type=int, help='Limit the number of CVEs to be fetched', default=10)
        options_group.add_argument('-lr', '--limit-requests', type=int, help='Limit the number of requests to be made')
        options_group.add_argument('-up', '--update-period', type=int, help='Update period in seconds')
    
    # Globaly available option
    options_group.add_argument('-o', '--output', action='store_true', help='Output file to store the fetched CVEs (in JSON)')

    # Only available in monitoring mode
    if monitoring:
        alert_group.add_argument('-ae', '--alert-email', type=str, help='Email address to send alerts to')
        alert_group.add_argument('-ad', '--alert-discord', type=str, help='Discord webhook to send alerts to')
        alert_group.add_argument('-at', '--alert-telegram', type=str, help='Telegram bot token to send alerts to')
        alert_group.add_argument('-as', '--alert-slack', type=str, help='Slack webhook to send alerts to')
        alert_group.add_argument('-ate', '--alert-teams', type=str, help='Microsoft Teams webhook to send alerts to')

    # Debugging args
    debug_group.add_argument('-v', '--version', action='version', help='Show version information', version='CVEOrbit v0.1.1')
    debug_group.add_argument('-d', '--debug', action='store_true', help='Enable debug mode')
    debug_group.add_argument('-si', '--silent', action='store_true', help='Enable silent mode')


def parse_args():
    # Define argument parser
    parser = argparse.ArgumentParser(description='CVEOrbit: The continous CVE monitoring tool.')

    # Creating subparsers for different modes
    subparsers = parser.add_subparsers(dest='Mode', help='Mode to run the tool in', required=True)

    # Creating subparser for search mode
    search_group = subparsers.add_parser('search', help='Search for specific values')
    common_args(search_group, monitoring=False, search=True)

    # Creating subparser for continuous monitoring mode
    continuous_group = subparsers.add_parser('orbit', help='Continuous monitoring mode')
    common_args(continuous_group, monitoring=True, search=False)

    # Parse the arguments
    return parser.parse_args()