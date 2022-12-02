# using pandas open first_excel.xlsx

import pandas as pd
import os
import ipaddress
import time

# Get the current working directory
cwd = os.getcwd()
# Create a path to the excel file
excel_path = os.path.join(cwd, 'first_excel.xlsx')
# Open the excel file
excel_file = pd.ExcelFile(excel_path)
# Print the sheet names
print(excel_file.sheet_names)
# Check if sheet names are Malware CIDRs, Malware Domains, and Phishing.
# If not, exit the program.
if excel_file.sheet_names != ['Malware CIDRs', 'Malware Domains', 'Phishing']:
    print('Error: This file is not formatted as expected.')
    exit()

def get_fusion_cidrs(excel_file):
    # Open the Malware CIDRs sheet
    malware_cidrs = excel_file.parse('Malware CIDRs')
    # Get all the rows in the CIDR Block column and load them into a list.
    print(malware_cidrs)
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
    print('Generating list of IP address ranges...')
    print(cidr_list)
    ranges_query = ranges_header
    for ip_range in cidr_list:
        network_address = ipaddress.IPv4Network(ip_range)
        print(network_address[0])
        if ip_range == cidr_list[-1]:
            ranges_query += "{\"range\": {\"destination.ip\": {\"gte\": \"" + str(network_address[0]) + "\", \"lt\": \"" + str(network_address[-1]) + "\"}}},\n"
            ranges_query += "{\"range\": {\"source.ip\": {\"gte\": \"" + str(network_address[0]) + "\", \"lt\": \"" + str(network_address[-1]) + "\"}}}\n"
        else:
            ranges_query += "{\"range\": {\"destination.ip\": {\"gte\": \"" + str(network_address[0]) + "\", \"lt\": \"" + str(network_address[-1]) + "\"}}},\n"
            ranges_query += "{\"range\": {\"source.ip\": {\"gte\": \"" + str(network_address[0]) + "\", \"lt\": \"" + str(network_address[-1]) + "\"}}},\n"
    ranges_query += ranges_footer
    print(ranges_query)
    print('IP address ranges complete.')
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
    print('Generating list of IP addresses...')
    ip_addresses = cidr_list_d
    print(cidr_list_d)
    ip_query = ip_header
    for ip_address in ip_addresses:
        if ip_address == ip_addresses[-1]:
            ip_query += "{\"match_phrase\": {\"destination.ip\": \"" + ip_address + "\"}},\n"
            ip_query += "{\"match_phrase\": {\"source.ip\": \"" + ip_address + "\"}}\n"
        else:
            ip_query += "{\"match_phrase\": {\"destination.ip\": \"" + ip_address + "\"}},\n"
            ip_query += "{\"match_phrase\": {\"source.ip\": \"" + ip_address + "\"}},\n"
    ip_query += ip_footer
    print(ip_query)
    print('IP addresses complete.')
    return ranges_query, ip_query


get_fusion_cidrs(excel_file)

#"{\"query\": {\"bool\": {\"minimum_should_match\": 1,\"should\": ["

#"{\"range\": {\"destination.ip\": {\"gte\": \"92.118.39.0\", \"lt\": \"92.118.39.255\"}}}"

#]}}}