import argparse
import os
import sys
import random
import time
import re
from typing import Optional
from typing import Sequence

# RegEx for determining if a string is IP.
def is_ip_address(ip_address):
    if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', ip_address):
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
            print('Cleaning AlienVault IOCs text file...')
            with open((args.file), 'r') as f:
                lines = f.readlines()
            with open(args.file, 'w') as f:
                for line in lines:
                    if 'Type:' not in line:
                        f.write(line)
            print('Cleaning complete.')
            header = "{\"query\": {\"bool\": {\"minimum_should_match\": 1,\"should\": [\n"
            footer = "\n]}}}"
            print('Generating list of IP addresses...')
            ip_addresses = get_ip_addresses(scan_file(args.file))
            query = header
            for ip_address in ip_addresses:
                query += "{\"match_phrase\": {\"destination.ip\": \"" + ip_address + "\"}},\n"
                query += "{\"match_phrase\": {\"source.ip\": \"" + ip_address + "\"}},\n"
            query = query[:-1]
            query += footer
            print('Writing ElasticSearch query to file...')
            # Write the query to a file. If one already exists then append a number that is 1 higher than the last.
            new_file_name = 'ioc_query'
            if os.path.exists(new_file_name + '.txt'):
                i = 1
                print('File already exists. Appending number to file name.')
                while os.path.exists(new_file_name + str(i) + '.txt'):
                    i += 1
                with open(new_file_name + str(i) + '.txt', 'w') as f:
                    f.write(query)
                print('ElasticSearch query written to file: ' + new_file_name + str(i) + '.txt')
            else:
                print('File does not exist. Writing file.')
                with open(new_file_name + '.txt', 'w') as f:
                    f.write(query)
                print('ElasticSearch query written to file: ' + new_file_name + '.txt')
        else:
            print('Please provide a file.')