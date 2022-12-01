import argparse
import os
import sys
import re
import time
from typing import Optional
from typing import Sequence

# Load a file into a list.
def scan_file(file_name):
    with open(file_name, 'r') as f:
        return f.read().splitlines()

# Clean up the source file and create a backup of the original.
def clean_up(file_name):
    if os.path.exists(file_name):
        print('Cleaning up file: ' + file_name)
        # Create a copy of the original file.
        with open(file_name, 'r') as f:
            with open(file_name + '.bak', 'w') as f2:
                f2.write(f.read())
        print('Original file renamed to: ' + file_name + '.bak')
        # Remove any lines that contain the word 'Type:'
        with open(file_name, 'r') as f:
            lines = f.readlines()
        with open(file_name, 'w') as f:
            for line in lines:
                if 'Type:' not in line:
                    f.write(line)
        # Remove http:// and https:// from the file.
        with open(file_name, 'r') as f:
            lines = f.readlines()
        with open(file_name, 'w') as f:
            for line in lines:
                f.write(line.replace('http://', ''))
        with open(file_name, 'r') as f:
            lines = f.readlines()
        with open(file_name, 'w') as f:
            for line in lines:
                f.write(line.replace('https://', ''))
        # Remove everything after the first '/' in the line.
        with open(file_name, 'r') as f:
            lines = f.readlines()
        with open(file_name, 'w') as f:
            for line in lines:
                f.write(line.split('/')[0] + '\n')
        # Remove any lines that are blank.
        with open(file_name, 'r') as f:
            lines = f.readlines()
        with open(file_name, 'w') as f:
            for line in lines:
                if line.strip():
                    f.write(line)
        print('File: ' + file_name + ' cleaned up.')
    else:
        print('File: ' + file_name + ' does not exist.')

# RegEx for determining if a string is IP.
def is_ip_address(ip_address):
    if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', ip_address):
        return True
    else:
        return False

# RegEx for determining if a string is a domain.
def is_domain(domain):
    if re.match(r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$', domain):
        return True
    else:
        return False

# Search a list for IP addresses and return a list of IP addresses.
def get_ip_addresses(search_list):
    ip_addresses = []
    for line in search_list:
        if is_ip_address(line):
            ip_addresses.append(line)
    return ip_addresses

# Search a list for Domains and return a list of Domains.
def get_domains(search_list):
    domains = []
    for line in search_list:
        # If the line is not an IP address then it is a domain.
        if not is_ip_address(line) and is_domain(line):
            domains.append(line)
    return domains

# Write the query to a file. If one already exists then append a number that is 1 higher than the last.
def write_queries(ip_query, first_file_name):
    if os.path.exists(first_file_name + '.txt'):
        i = 1
        print('File: ' + first_file_name + ' already exists. Appending number to file name.')
        while os.path.exists(first_file_name + str(i) + '.txt'):
            i += 1
        with open(first_file_name + str(i) + '.txt', 'w') as f:
            f.write(ip_query)
        print('ElasticSearch query written to file: ' + first_file_name + str(i) + '.txt')
    else:
        print('File: ' + first_file_name + ' already exists. Appending number to file name.')
        with open(first_file_name + '.txt', 'w') as f:
            f.write(ip_query)
        print('ElasticSearch query written to file: ' + first_file_name + '.txt')

def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser()
    
    # Sub-Commands
    subparsers = parser.add_subparsers(dest='command')
    subparsers.required = True
    
    # Subparser for taking an alienvault IOC feed textfile and converting it into a list of ElasticSearch Queries.
    word_parser = subparsers.add_parser('alienvault', help='Take a list from AlienVault and create a ElasticSearch query.')
    
    # File argument for the alienvault subparser.
    word_parser.add_argument('-f', '--file', type=str, help='text file AlienVault IOCs')
    
    # If the user does not provide any arguments, print the help message.
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args(argv)
        
    # If the user enters word command
    if args.command == 'alienvault':
        if args.file:
            print('File: ', args.file)
            # Create backup of file.
            clean_up(args.file)
            ip_header = "{\"query\": {\"bool\": {\"minimum_should_match\": 1,\"should\": [\n"
            ip_footer = "]}}}"
            print('Generating list of IP addresses...')
            ip_addresses = get_ip_addresses(scan_file(args.file))
            print(ip_addresses)
            time.sleep(2)
            ip_query = ip_header
            for ip_address in ip_addresses:
                if ip_address == ip_addresses[-1]:
                    ip_query += "{\"match_phrase\": {\"destination.ip\": \"" + ip_address + "\"}},\n"
                    ip_query += "{\"match_phrase\": {\"source.ip\": \"" + ip_address + "\"}}\n"
                else:
                    ip_query += "{\"match_phrase\": {\"destination.ip\": \"" + ip_address + "\"}},\n"
                    ip_query += "{\"match_phrase\": {\"source.ip\": \"" + ip_address + "\"}},\n"
            ip_query += ip_footer
            print('IP addresses complete.')
            domains_header = "{\"query\": {\"bool\": {\"minimum_should_match\": 1,\"should\": [\n"
            domains_footer = "]}}}"
            print('Generating list of Domains...')
            domains = get_domains(scan_file(args.file))
            print(domains)
            time.sleep(2)
            domains_query = domains_header
            for domain in domains:
                # If the domain is last in domains list, do not add a comma.
                if domain == domains[-1]:
                    domains_query += "{\"wildcard\": {\"dns.question.name\": {\"value\": \"*" + domain + "*\",\"boost\": 1,\"rewrite\": \"constant_score\"}}}\n"
                else:
                    domains_query += "{\"wildcard\": {\"dns.question.name\": {\"value\": \"*" + domain + "*\",\"boost\": 1,\"rewrite\": \"constant_score\"}}},\n"
            domains_query += domains_footer
            print('Domains complete.')
            print('Writing ElasticSearch queries to files...')
            # Write the query to a file. If one already exists then append a number that is 1 higher than the last.
            write_queries(ip_query, 'ioc_ip_query')
            write_queries(domains_query, 'ioc_domain_query')
        else:
            print('Please provide a file.')