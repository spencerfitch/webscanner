# Name: Spencer Fitch
# netid: slf0232
#
# Comp_Sci 340: Intro to Networking
# Project 4
#
# report.py

# Exit Codes:
#   0 - exited normally
#   1 - bad commandline input

import sys

import json                         # parsing input_file.json
from texttable import Texttable     # formatting output_file.txt
import heapq                        # priorty queue for RTT table
import operator

if len(sys.argv) != 3:
    sys.stderr.write('report.py requires 2 arguments: input_file.json and output_file.txt')
    sys.exit(1)

with open(sys.argv[1], 'r') as input_file:
    input_json = json.load(input_file)

output_file = open(sys.argv[2], 'w')


# Dynamically size title to match table width
title_string = ' Report of website scan results from {0} '.format(sys.argv[1])
width_diff = 104 - len(title_string)
left_char = width_diff // 2
right_char = width_diff - left_char

left_string = ''
for i in range(left_char):
    left_string += '='
right_string = ''
for i in range(right_char):
    right_string += '='

full_title = left_string + title_string + right_string + '\n\n'

output_file.write(full_title)
table_of_contents = '== Table Guide ==\n' + \
                    '\t1: General Scan Data          - Scan Time, RTT Range, and RDNS Names\n' + \
                    '\t2: IP Address Data            - IPv4 Addresses, IPv6 Addresses, and IPv4 Geolocations)\n' + \
                    '\t3: Server Feature Data        - HTTP Server Software, Listening for HTTP, Redirect to HTTPS, and HSTS\n' + \
                    '\t4: Connection Security Data   - TLS Versions, and Root Certificate Authority\n' + \
                    '\t5: Round Trip Time Range      - List of RTT for all websites sorted by the minimum\n' + \
                    '\t6: Root CA Popularity         - List of all Root CAs ordered by their popularity\n' + \
                    '\t7: Server Software Popularity - List of all Server Software ordered by popularity\n' + \
                    '\t8: Server Feature Support     - List of percent support for various server features\n\n\n\n'


output_file.write(table_of_contents)

# Table Containing: HOST | Scan Time | RTT Range | Reverse DNS Names
gen_table = Texttable()
gen_table.set_cols_dtype(['t', 'f', 't', 't'])
gen_table.set_cols_align(['l', 'r', 'c', 'l'])
gen_table.set_cols_width([20, 14, 14, 43])
gen_table_rows = [['Website', 'Scan Time', 'Rount Trip\nTime Range', 'Reverse DNS\nNames']]

# Table containing: HOST | IPv4 | IPv6 | GeoLoc
ip_table = Texttable()
ip_table.set_cols_dtype(['t', 't', 't', 't'])
ip_table.set_cols_align(['l', 'l', 'l', 'l'])
ip_table.set_cols_width([20, 15, 36, 20])
ip_table_rows = [['Website', 'IPv4 Addresses', 'IPv6 Addresses', 'IPv4 Geolocations']]

# Server Feature Table: HOST | Web Server Software | Listening HTTP | Redirect HTTPS | HSTS
server_table = Texttable()
server_table.set_cols_dtype(['t', 't', 't', 't', 't'])
server_table.set_cols_align(['l', 'l', 'c', 'c', 'c'])
server_table.set_cols_width([20, 20, 12, 12, 12])
server_table_rows = [['Website', 'HTTP Server\nSoftware', 'Listening\nfor HTTP', 'Redirect\nto HTTPS', 'HTTP Strict\nTransport\nSecurity']]

# Connection Security Table: HOST | TLS versions | Root CA
security_table = Texttable()
security_table.set_cols_dtype(['t', 't', 't'])
security_table.set_cols_align(['l', 'c', 'c'])
security_table.set_cols_valign(['m', 'm', 'm'])
security_table.set_cols_width([28, 13, 30])
security_table_rows = [['Website', 'Supported TLS\nVersions', 'Root Certificate\nAuthority']]


# Values for later statistics
host_count = len(input_json.keys())

# [insecure_htp, redirect_https, hsts, ipv6]
flag_counts = [0,0,0,0]

rtt_queue = []

root_ca_count = {}
server_count = {}

tls_types = ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3']
tls_counts = [0,0,0,0,0,0]



for host in input_json.keys():
    sys.stdout.write('Writing {0}\n'.format(host))
    host_data = input_json[host]

    # GEN_TABLE
    rtt_range = host_data['rtt_range']
    heapq.heappush(rtt_queue, (rtt_range[0], (host, rtt_range[0], rtt_range[1])))

    rdns_string = ''
    for dns in host_data['rdns_names']:
        rdns_string += '{0}\n'.format(dns)
    rdns_string = rdns_string[:-1]

    gen_table_rows.append([host, host_data['scan_time'], '{0} to {1}'.format(rtt_range[0], rtt_range[1]), rdns_string])


    # IP_TABLE
    ip_row = [host]
    for cat in ['ipv4_addresses', 'ipv6_addresses', 'geo_locations']:
        # Build string for cat and append to row
        cat_string = ''
        for item in host_data[cat]:
            cat_string += '{0}\n'.format(item) if cat != 'geo_locations' else '"{0}"\n'.format(item)
        cat_string = cat_string[:-1]
        ip_row.append(cat_string)
    # Flag ipv6 if we got any
    if ip_row[2] != '': flag_counts[3] += 1
    ip_table_rows.append(ip_row)


    # SERVER_TABLE
    server_row = [host]

    server = host_data['http_server']
    if server:
        if server in server_count.keys():
            server_count[server] += 1
        else:
            server_count[server] = 1
    else:
        server = ''
    server_row.append(server)

    for i, cat in enumerate(['insecure_http', 'redirect_to_https', 'hsts']):
        flag = 'X' if host_data[cat] else ''
        # Add flag count if flagged
        if host_data[cat]: flag_counts[i] += 1
        server_row.append(flag)

    server_table_rows.append(server_row)


    # SECURITY_TABLE
    tls_string = ''
    for tls in host_data['tls_versions']:
        tls_counts[tls_types.index(tls)] += 1
        tls_string += '{0}\n'.format(tls)
    tls_string = tls_string[:-1]

    root_ca = host_data['root_ca']
    if root_ca in root_ca_count.keys():
        root_ca_count[root_ca] += 1
    else:
        root_ca_count[root_ca] = 1
    
    security_table_rows.append([host, tls_string, root_ca])



output_file.write('========================================== General Scan Data ===========================================\n')
gen_table.add_rows(gen_table_rows)
output_file.write(gen_table.draw()+'\n\n\n\n\n\n')

output_file.write('=========================================== IP Address Data ============================================\n')
ip_table.add_rows(ip_table_rows)
output_file.write(ip_table.draw()+'\n\n\n\n\n\n')

output_file.write('=================================== Server Feature Data ====================================\n')
server_table.add_rows(server_table_rows)
output_file.write(server_table.draw()+'\n\n\n\n\n\n')

output_file.write('=========================== Connection Security Data ============================\n')
security_table.add_rows(security_table_rows)
output_file.write(security_table.draw()+'\n\n\n\n\n\n')


# RTT_TABLE
rtt_table = Texttable()
rtt_table.set_deco(Texttable.HEADER | Texttable.BORDER)
rtt_table.set_cols_align(['l', 'r', 'r'])
rtt_table.set_cols_dtype(['t', 'i', 'i'])
rtt_table.set_cols_valign(['c', 'c', 'c'])
rtt_table.set_cols_width([28, 7, 7])

rtt_rows = [['Website', 'Min RTT\n(ms)', 'Max RTT\n(ms)']]
while len(rtt_queue) > 0:
    rtt_info = heapq.heappop(rtt_queue)[1]
    rtt_rows.append([rtt_info[0], rtt_info[1], rtt_info[2]])
rtt_table.add_rows(rtt_rows)

output_file.write('============== Round Trip Time Range ===============\n')
output_file.write(rtt_table.draw()+'\n\n\n\n\n\n')






# ROOTCA_TABLE
rootca_table = Texttable()
rootca_table.set_deco(Texttable.HEADER | Texttable.BORDER)
rootca_table.set_cols_align(['l', 'r', 'r'])
rootca_table.set_cols_dtype(['t', 'i', 'f'])
rootca_rows = [['Root Certificate Authority', 'Count', 'Percentage']]

# Code for sorting dictionary by value from: https://stackoverflow.com/questions/613183/how-do-i-sort-a-dictionary-by-value
sorted_ca = sorted(root_ca_count.items(), key=operator.itemgetter(1))
sorted_ca.reverse()

for root_ca in sorted_ca:
    rootca_rows.append([root_ca[0], root_ca[1], 100*(root_ca[1]/host_count)])
rootca_table.add_rows(rootca_rows)

output_file.write(rootca_table.draw()+'\n\n\n\n\n\n')








# SERVCOUNT_TABLE
servcount_table = Texttable()
servcount_table.set_deco(Texttable.HEADER | Texttable.BORDER)
servcount_table.set_cols_align(['l', 'r'])
servcount_table.set_cols_dtype(['t', 'i'])
servcount_rows = [['HTTP Server Software', 'Count']]

# Code for sorting dictionary by value from: https://stackoverflow.com/questions/613183/how-do-i-sort-a-dictionary-by-value
sorted_server = sorted(server_count.items(), key=operator.itemgetter(1))
sorted_server.reverse()

for server in sorted_server:
    servcount_rows.append([server[0], server[1]])
servcount_table.add_rows(servcount_rows)


output_file.write(servcount_table.draw()+'\n\n\n\n\n\n')








# PERCENT_TABLE
percent_table = Texttable()
percent_table.set_deco(Texttable.HEADER  | Texttable.BORDER)
percent_table.set_cols_align(['l', 'r'])
percent_table.set_cols_dtype(['t', 'f'])
percent_table.set_cols_width([15, 9])

f_percent = lambda x: (x/host_count)*100

flag_percents = list(map(f_percent, flag_counts))
tls_percents = list(map(f_percent, tls_counts))
percent_table.add_rows([
    ['Server Feature', '% Support'],
    ['SSLv2', tls_percents[0]],
    ['SSLv3', tls_percents[1]],
    ['TLSv1.0', tls_percents[2]],
    ['TLSv1.1', tls_percents[3]],
    ['TLSv1.2', tls_percents[4]],
    ['TLSv1.3', tls_percents[5]],
    ['Plain HTTP', flag_percents[0]],
    ['HTTPS Redirect', flag_percents[1]],
    ['HSTS', flag_percents[2]],
    ['IPv6', flag_percents[3]] 
])

output_file.write(percent_table.draw()+'\n')


sys.stdout.write('exited normally\n')
sys.exit(0)