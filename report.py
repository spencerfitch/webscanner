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
import heapq                        # priority queue for RTT table
import operator     



if len(sys.argv) != 3:
    sys.stderr.write('report.py requires 2 arguments: input_file.json and output_file.txt\n')
    sys.exit(1)

with open(sys.argv[1], 'r') as input_file:
    input_json = json.load(input_file)

output_file = open(sys.argv[2], 'w')



# For RTT table
rtt_queue = []

# For TLS version support table
host_count = 0
tls_types = ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3']
tls_counts = [0,0,0,0,0,0]

# [insecure_http, redirect_https, hsts, ipv6]
scan_counts = [0,0,0,0]

# For root_ca count
root_ca_count = {}

# For web server count
server_count = {}

output_file.write('============== Full Website Scan Results ==============\n')

for host in input_json.keys():
    host_data = input_json[host]
    host_count += 1

    output_file.write(host+'\n')
    output_file.write('\tScan Time: {0}\n'.format(host_data['scan_time']))

    output_file.write('\tIPv4 Addresses:\n')
    if len(host_data['ipv4_addresses']) == 0:
        # No IPv4 found
        output_file.write('\t\tNone found\n')
    else:
        # Print all found IPv6
        for ipv4 in host_data['ipv4_addresses']:
            output_file.write('\t\t{0}\n'.format(ipv4))
    
    
    output_file.write('\tIPv6 Addresses:\n')
    if len(host_data['ipv6_addresses']) == 0:
        # No IPv6 found
        output_file.write('\t\tNone found\n')
    else:
        scan_counts[3] += 1
        # Print all found IPv6
        for ipv6 in host_data['ipv6_addresses']:
            output_file.write('\t\t{0}\n'.format(ipv6))

    server = host_data['http_server']
    if server: 
        if server in server_count.keys():
            server_count[server] += 1
        else:
            server_count[server] = 1
    else:
        # Update server text if unable to get information
        server = 'Information not provided'
    output_file.write('\tWeb Server Software: {0}\n'.format(server))

    insecure_http = host_data['insecure_http']
    output_file.write('\tListening on Port 80: {0}\n'.format(insecure_http))
    if insecure_http: scan_counts[0] += 1

    redirect_https = host_data['redirect_to_https']
    if redirect_https: scan_counts[1] += 1
    output_file.write('\tHTTP page redirects to HTTPS: {0}\n'.format(redirect_https))

    hsts = host_data['hsts']
    if hsts: scan_counts[2] += 1
    output_file.write('\tHTTP Strict Transport Security enabled: {0}\n'.format(hsts))

    output_file.write('\tSupported TLS versions:\n')
    tls_data = host_data['tls_versions']
    if len(tls_data) == 0:
        # No TLS supported
        output_file.write('\t\tNone\n')
    else:
        # Print all supported tls versions
        for tls in tls_data:
            output_file.write('\t\t{0}\n'.format(tls))
            tls_counts[tls_types.index(tls)] += 1

    root_ca = host_data['root_ca']
    output_file.write('\tRoot Certificate Authority: {0}\n'.format(root_ca))
    # Increment root_ca count
    if root_ca in root_ca_count.keys():
        root_ca_count[root_ca] += 1
    else:
        root_ca_count[root_ca] = 1


    rtt_range = host_data['rtt_range']
    output_file.write('\tRound trip time range (ms): {0} to {1}\n'.format(rtt_range[0], rtt_range[1]))
    heapq.heappush(rtt_queue, (rtt_range[0], (host, rtt_range[0], rtt_range[1])))


    geo_locations = host_data['geo_locations']
    output_file.write('\tReal-world locations of IPv4 addresses:\n')
    if len(geo_locations) == 0:
        output_file.write('\t\tNone found\n')
    else:
        for loc in geo_locations:
            output_file.write('\t\t{0}\n'.format(loc))


    output_file.write('\n')

output_file.write('=======================================================\n\n')


output_file.write('\n==================== Scan Analysis ====================\n')

# RTT Table
rtt_table = Texttable()
rtt_table.set_deco(Texttable.HEADER)
rtt_table.set_cols_align(['l', 'r', 'r'])
rtt_table.set_cols_valign(['m', 'm', 'm'])
rtt_table.set_cols_dtype(['t', 'i', 'i'])

rtt_rows = [['Host', 'Min RTT\n(ms)', 'Max RTT\n(ms)']]
while len(rtt_queue) > 0:
    rtt_info = heapq.heappop(rtt_queue)[1]
    rtt_rows.append([rtt_info[0], rtt_info[1], rtt_info[2]])
rtt_table.add_rows(rtt_rows)

output_file.write(rtt_table.draw()+'\n\n')


# Root CA table
ca_table = Texttable()
ca_table.set_deco(Texttable.HEADER)
ca_table.set_cols_align(['l', 'c'])
ca_table.set_cols_valign(['m', 'm'])
ca_table.set_cols_dtype(['t', 'i'])

sorted_ca = sorted(root_ca_count.items(), key=operator.itemgetter(1))
sorted_ca.reverse()
root_rows = [['Root Certificate Authority', 'Count']]
for root_ca in sorted_ca:
    root_rows.append([root_ca[0], root_ca[1]])
ca_table.add_rows(root_rows)

output_file.write(ca_table.draw()+'\n\n')
    

# Web Server Table
server_table = Texttable()
server_table.set_deco(Texttable.HEADER)
server_table.set_cols_align(['l', 'c'])
server_table.set_cols_valign(['m', 'm'])
server_table.set_cols_dtype(['t', 'i'])
server_table.set_cols_width([40, 5])

sorted_server = sorted(server_count.items(), key=operator.itemgetter(1))
sorted_server.reverse()
server_rows = [['Web Server Software', 'Count']]
for server in sorted_server:
    server_rows.append([server[0], server[1]])
server_table.add_rows(server_rows)

output_file.write(server_table.draw()+'\n\n')


# Percentage table
percent_table = Texttable()
percent_table.set_deco(Texttable.HEADER)
percent_table.set_cols_align(['l', 'c'])
percent_table.set_cols_valign(['m', 'm'])
percent_table.set_cols_dtype(['t', 'f'])

f_percent = lambda x: (x/host_count)*100
percents = list(map(f_percent, scan_counts))
percent_table.add_rows([
    ['Server Feature', '% Support'],
    ['Plain HTTP', percents[0]],
    ['HTTPS Redirect', percents[1]],
    ['HSTS', percents[2]],
    ['IPv6', percents[3]]
])

output_file.write(percent_table.draw()+'\n')




output_file.close()

print('exited normally')
sys.exit(0)