# Name: Spencer Fitch
# netid: slf0232
#
# Comp_Sci 340: Intro to Networking
# Project 4
#
# scan.py

# Exit Codes:
#    0 - exited normally
#   10 - bad command line input

import sys
import time
import json
import subprocess



dns_resolvers = ['208.67.222.222', '1.1.1.1', '8.8.8.8', '8.26.56.26', '9.9.9.9', 
                 '64.6.65.6', '13.239.157.177', '91.239.100.100', '185.228.168.168', 
                 '77.88.8.7', '156.154.70.1', '198.101.242.72', '176.103.130.130']


def get_ip_addresses(website, ip_type):
    ip_addresses = []

    if (ip_type == 'ipv4'):
        nstype = "-type=A"
    elif (ip_type == 'ipv6'):
        nstype = "-type=AAAA"
    else:
        sys.stderr.write('Invalid ip_type passed to get_ip_addresses: ' + str(ip_type))
        return None

    for dns in dns_resolvers:
        
        result = subprocess.check_output(["nslookup", nstype, w, dns]).decode("utf-8") 
        split_result = result.split("\n\n")

        if (len(split_result) < 2):
            print('unable to split response: nslookup ' + str(nstype) + ' ' + str(w) + ' ' + str(dns))
            continue    
            
        for line in (split_result[1]).split('\n'):
            if line.split(': ')[0] == "Address":
                ip_addresses.append(line.split(': ')[1])

    return ip_addresses






# Check for command line argument
if len(sys.argv) != 3:
    sys.stderr.write("scan.py requires 2 arguments: input_file.txt and output_file.json \n")
    sys.exit(10)

# Load in websites from input file
websites = []
with open(sys.argv[1], "r") as input_file:
    for line in input_file:
        websites.append(line.split('\n')[0])

# Run scans
scans = {}
for w in websites:
    scans[w] = {
        "scan_time": time.time(),
        "ipv4_addresses": get_ip_addresses(w, 'ipv4'),
        "ipv6_addresses": get_ip_addresses(w, 'ipv6')}

# Write scan output to output file
with open(sys.argv[2], "w") as output_file:
    json.dump(scans, output_file, sort_keys=True, indent=4)

sys.stdout.write("exited succesfully")
sys.exit(0)