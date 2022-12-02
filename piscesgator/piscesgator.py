import argparse
import os
import sys
import re
import pandas as pd
import ipaddress
import colorama
from colorama import Fore, Back, Style
from typing import Optional
from typing import Sequence

# Initialize the colorama
colorama.init()

# Load a file into a list.
def scan_file(file_name):
    with open(file_name, 'r') as f:
        return f.read().splitlines()

# Clean up the source file and create a backup of the original.
# Someone smarter than I can probably optimize this function.
def otx_clean_up(file_name):
    if os.path.exists(file_name):
        print(Fore.CYAN + 'Cleaning up otx source file: ' + file_name + '.' + Style.RESET_ALL)
        # Create a copy of the original file.
        with open(file_name, 'r') as f:
            with open(file_name + '.bak', 'w') as f2:
                f2.write(f.read())
        print(Fore.CYAN + 'Original file renamed to: ' + file_name + '.bak' + Style.RESET_ALL)
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
        print(Fore.GREEN + 'File: ' + Fore.CYAN + file_name + Fore.GREEN + ' cleaned up.')
    else:
        print(Fore.RED + Style.BRIGHT + 'File: ' + Fore.CYAN + file_name + Fore.RED + Style.BRIGHT + ' does not exist.' + Style.RESET_ALL)
        sys.exit(1)

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
        print(Fore.CYAN + 'File: ' + first_file_name + ' already exists. Appending number to file name.' + Style.RESET_ALL)
        while os.path.exists(first_file_name + str(i) + '.txt'):
            i += 1
        with open(first_file_name + str(i) + '.txt', 'w') as f:
            f.write(ip_query)
        print(Fore.GREEN + 'ESQ written to file: ' + first_file_name + str(i) + '.txt' + Style.RESET_ALL)
    else:
        print(Fore.CYAN + 'File: ' + first_file_name + ' does not exist. Creating file.' + Style.RESET_ALL)
        with open(first_file_name + '.txt', 'w') as f:
            f.write(ip_query)
        print(Fore.GREEN + 'ESQ written to file: ' + first_file_name + '.txt' + Style.RESET_ALL)

def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser()
    
    # Sub-Commands
    subparsers = parser.add_subparsers(dest='command')
    subparsers.required = True
    
    # Subparser for taking an alienvault IOC feed textfile and converting it into a list of ElasticSearch Queries.
    word_parser = subparsers.add_parser('alienvault', help='Take a list from AlienVault and create a ElasticSearch query')
    
    # File argument for the alienvault subparser.
    word_parser.add_argument('-f', '--file', type=str, help='text file AlienVault IOCs')

     # Subparser for taking an alienvault IOC feed textfile and converting it into a list of ElasticSearch Queries.
    word_parser = subparsers.add_parser('fusioncenter', help='Take a list from Fusion Center xlsx and create a ElasticSearch query')
    
    # File argument for the alienvault subparser.
    word_parser.add_argument('-f', '--file', type=str, help='Fusion Center xlsx file')
    
    # File argument for the alienvault subparser.
    word_parser.add_argument('-c', '--cidrs', action='store_true', help='generate a ElasticSearch query for Malware CIDRs')

    # Arguments for 

    # If the user does not provide any arguments, print the help message.
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args(argv)
        
    # If the user enters alienvault command
    if args.command == 'alienvault':
        if args.file:
            print('OTX AlienVault File: ', args.file)
            # Create backup of file.
            otx_clean_up(args.file)
            ip_header = "{\"query\": {\"bool\": {\"minimum_should_match\": 1,\"should\": [\n"
            ip_footer = "]}}}"
            print('Generating list of IP addresses...')
            ip_addresses = get_ip_addresses(scan_file(args.file))
            print(ip_addresses)
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
            write_queries(ip_query, 'otx_ip_query')
            write_queries(domains_query, 'otx_domain_query')
        else:
            print(Fore.RED + Style.BRIGHT + 'Error: Please provide a txt file with OTX IOCs!' + Style.RESET_ALL)
            sys.exit(1)
    
    # If the user enters fusioncenter command
    elif args.command == 'fusioncenter':
        if args.file:
            # Open the excel file
            excel_file = pd.ExcelFile(os.path.join(os.getcwd(), args.file))
            # Check if sheet names are Malware CIDRs, Malware Domains, and Phishing.
            # If not, exit the program.
            if excel_file.sheet_names != ['Malware CIDRs', 'Malware Domains', 'Phishing']:
                print(Fore.RED + Style.BRIGHT + 'Error: This file is not formatted as expected!' + Style.RESET_ALL)
                sys.exit(1)
        
        if args.cidrs:
            print(Fore.CYAN + 'Writing ElasticSearch queries to files...' + Style.RESET_ALL)
            # Open the Malware CIDRs sheet
            malware_cidrs = excel_file.parse('Malware CIDRs')
            # Get all the rows in the CIDR Block column and load them into a list.
            cidr_list = malware_cidrs['TLP: GREEN'].tolist()
            ip_list = malware_cidrs['Unnamed: 3'].tolist()
            # Remove all brackets from the list &
            # Remove the first and last items from cidr_list and ip_list
            cidr_list = [x.replace('[', '') for x in cidr_list]
            cidr_list = [x.replace(']', '') for x in cidr_list]
            cidr_list.pop(0)
            cidr_list.pop(-1)
            ip_list.pop(0)
            ip_list.pop(-1)
            # Create the ElasticSearch query for CIDR ranges
            ranges_header = "{\"query\": {\"bool\": {\"minimum_should_match\": 1,\"should\": [\n"
            ranges_footer = "]}}}"
            print(Fore.CYAN + 'Generating list of IP address ranges...' + Style.RESET_ALL)
            print(Fore.CYAN + str(cidr_list) + Style.RESET_ALL)
            ranges_query = ranges_header
            for ip_range in cidr_list:
                network_address = ipaddress.IPv4Network(ip_range)
                if ip_range == cidr_list[-1]:
                    ranges_query += "{\"range\": {\"destination.ip\": {\"gte\": \"" + str(network_address[0]) + "\", \"lt\": \"" + str(network_address[-1]) + "\"}}},\n"
                    ranges_query += "{\"range\": {\"source.ip\": {\"gte\": \"" + str(network_address[0]) + "\", \"lt\": \"" + str(network_address[-1]) + "\"}}}\n"
                else:
                    ranges_query += "{\"range\": {\"destination.ip\": {\"gte\": \"" + str(network_address[0]) + "\", \"lt\": \"" + str(network_address[-1]) + "\"}}},\n"
                    ranges_query += "{\"range\": {\"source.ip\": {\"gte\": \"" + str(network_address[0]) + "\", \"lt\": \"" + str(network_address[-1]) + "\"}}},\n"
            ranges_query += ranges_footer
            print(Fore.WHITE + "=-------------------------------------------------------------------=" + Style.RESET_ALL)
            print(Fore.YELLOW + str(ranges_query) + Style.RESET_ALL)
            print(Fore.WHITE + "=-------------------------------------------------------------------=" + Style.RESET_ALL)
            print(Fore.CYAN + 'IP address ranges complete.' + Style.RESET_ALL)
            # Loop through cidr_list_c and remove everything after the last '.' in the string.
            cidr_list_c = cidr_list
            for i in range(len(cidr_list_c)):
                cidr_list_c[i] = cidr_list_c[i].split('.')[0] + '.' + cidr_list_c[i].split('.')[1] + '.' + cidr_list_c[i].split('.')[2] + '.'
                # Remove the last '.' from the string.
                cidr_list_c[i] = cidr_list_c[i][:-1]
                # Add each item from ip_list to the end of each item in cidr_list_c.
                cidr_list_c[i] = cidr_list_c[i] + ip_list[i]
            # Loop through cidr_list_c and check if there are any items with more than three '.' in them.
            # If there are, take first three numbers separted by '.' and the last number separated by '.' and combine them into one item.
            cidr_list_d = cidr_list_c
            for i in range(len(cidr_list_d)):
                if cidr_list_d[i].count('.') > 3:
                    cidr_list_d.append(cidr_list_d[i].split('.')[0] + '.' + cidr_list_d[i].split('.')[1] + '.' + cidr_list_d[i].split('.')[2] + '.' + cidr_list_d[i].split('.')[-1])
                    cidr_list_d[i] = cidr_list_d[i].split('.')[0] + '.' + cidr_list_d[i].split('.')[1] + '.' + cidr_list_d[i].split('.')[2] + '.' + cidr_list_d[i].split('.')[3]
            # Create the ElasticSearch query for single IP addresses
            ip_header = "{\"query\": {\"bool\": {\"minimum_should_match\": 1,\"should\": [\n"
            ip_footer = "]}}}"
            print(Fore.CYAN + 'Generating list of single IP addresses...' + Style.RESET_ALL)
            ip_addresses = cidr_list_d
            print(Fore.CYAN + str(ip_addresses) + Style.RESET_ALL)
            ip_query = ip_header
            for ip_address in ip_addresses:
                if ip_address == ip_addresses[-1]:
                    ip_query += "{\"match_phrase\": {\"destination.ip\": \"" + ip_address + "\"}},\n"
                    ip_query += "{\"match_phrase\": {\"source.ip\": \"" + ip_address + "\"}}\n"
                else:
                    ip_query += "{\"match_phrase\": {\"destination.ip\": \"" + ip_address + "\"}},\n"
                    ip_query += "{\"match_phrase\": {\"source.ip\": \"" + ip_address + "\"}},\n"
            ip_query += ip_footer
            print(Fore.WHITE + "=-------------------------------------------------------------------=" + Style.RESET_ALL)
            print(Fore.YELLOW + str(ip_query) + Style.RESET_ALL)
            print(Fore.WHITE + "=-------------------------------------------------------------------=" + Style.RESET_ALL)
            print(Fore.CYAN + 'Single IP addresses complete.' + Style.RESET_ALL)
            write_queries(ranges_query, 'fusion_cidr_query')
            write_queries(ip_query, 'fusion_ip_query')
        else:
            print(Fore.RED + Style.BRIGHT + 'Error: Please provide a xlsx file with Fusion Center IOCs!' + Style.RESET_ALL)
            sys.exit(1)