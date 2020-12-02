# Name: Spencer Fitch
# netid: slf0232
#
# Comp_Sci 340: Intro to Networking
# Project 4
#
# scan.py

# Exit Codes:
#    0 - exited normally
#    1 - bad command line input

# TODO
#   - Ask about hsts (should we only base it on redirects or should we try https connection too)
#   - Verify where I'm getting hsts and server data from
#   - Update TLS scan to use nmap for everything but tls1.3 (to check for lower ssl)
#   - Insecure HTTP should be 100%

import sys
from typing import List, Tuple

from shutil import which # Determining if command utility exits
import time         # for epoch time
import json         # for packaging result
import subprocess   # for making cmd scans
import http.client  # for http connections
import maxminddb    # for geolocations

#'91.239.100.100', 
dns_resolvers = ['208.67.222.222', '1.1.1.1', '8.8.8.8', '8.26.56.26', '9.9.9.9', 
                 '64.6.65.6', '185.228.168.168', 
                 '77.88.8.7', '156.154.70.1', '198.101.242.72', '176.103.130.130']
                 

def get_ip_addresses(website: str, ip_type: str) -> List[str]:
    ''' 
    Queries dns_resolvers for all ip addresses of webiste of particular ip_type

    Arguments:
        website : website to make DNS requests for
        ip_type : type of IP address to query for ('ipv4' or 'ipv6')
    Return:
        ip_addresses : list of all unique IP addresses for particular website
    '''
    ip_addresses = []

    if (ip_type == 'ipv4'):
        nstype = "-type=A"
    elif (ip_type == 'ipv6'):
        nstype = "-type=AAAA"
    else:
        sys.stderr.write('Invalid ip_type passed to get_ip_addresses: ' + str(ip_type))
        return None

    for dns in dns_resolvers:
        
        try:
            result = subprocess.check_output(["nslookup", nstype, w, dns], timeout=3, stderr=subprocess.STDOUT).decode("utf-8") 
        except subprocess.SubprocessError as e:
            # Did not return a result for this combination
            print(e)
            continue

        split_result = result.split("\n\n")  
            
        for line in (split_result[1]).split('\n'):
            split_line = line.split(': ')
            if (split_line[0] == "Address") and (split_line[1] not in ip_addresses):
                ip_addresses.append(split_line[1])

    ip_addresses.sort()
    return ip_addresses


def parse_url(url: str) -> Tuple[str, str, str]:
    '''
    Parse url into components: http(s), host, path

    Arguments:
        url (str) : full url to parse
    Returns:
        http_type (str) : http or https string
        host (str) : full hostname of website  
        path (str) : exact redirect path
    '''
    split_url = url.split('/')

    http_type = split_url[0]
    host = split_url[2]
    path = '/' + '/'.join(split_url[3:])

    return http_type, host, path


def get_https_data(host: str, path: str) -> Tuple[str, bool]:
    '''
    Return server info of basic https request

    Arguments:
        host : hostname of destination server
        path : path for destination resource
    Returns:
        server  : server info for HTTPS page
        hsts    : does HTTPS page support HTTPS Strict Transport Security
    '''
    try:
        # Establish HTTPS connection
        connection = http.client.HTTPSConnection(host, timeout=10)

        # Make request
        head = {'Host': host}
        connection.request('GET', path, headers=head)
        response = connection.getresponse()

        # Teardown connection
        connection.close()

        return response.getheader('Server'), (response.getheader('Strict-Transport-Security') != None)

    except:
        # HTTPS connection failed?
        print('HTTPS connection failed for : ' + host)
        return None, False



def follow_http_redirect(url: str, server: str) -> Tuple[str, bool, bool]:
    '''
    Indicates if HTTP 30X redirects to HTTPS site in <10 redirects

    Arguments:
        url     : full url to redirect to
        server  : initial server information
    Returns:
        server          : server info of final redirect
        redirect_https  : did redirects lead to HTTPS page
        hsts            : does final page support HTTP Strict Transport Security
    '''
    http_type, host, path = parse_url(url)

    if http_type == 'https:':
        # Initial redirect is https ---> No redirect follow needed
        server, hsts = get_https_data(host, path)
        return server, True, hsts

    count = 0
    while count < 10:
        try:
            # Establish connection
            connection = http.client.HTTPConnection(host, timeout=10)

            # Make request
            head = {'Host': host}
            connection.request('GET', path, headers=head)
            response = connection.getresponse()

            # Default server if further steps fail/redirect timeout
            server = response.getheader('Server')

            # Close connection
            connection.close()

            if response.code < 300 or response.code > 310:
                # Redirecting stopped before HTTPS reached
                return response.getheader('Server'), False, False
            
            # Parse redirect URL
            http_type, host, path = parse_url(response.getheader('Location'))

            if http_type == 'https:':
                # URL is https ---> Get server info and return true
                server, hsts = get_https_data(host, path)
                return server, True, hsts

            else:
                # URL not https ---> Try redirecting again
                count += 1
                continue

        except:
            # Redirect failed
            return server, False, False
    
    # Tried to redirect too many times
    return server, False, False



def get_http_data(website: str) -> Tuple[str, bool, bool, bool]:
    ''' 
    Retrieve HTTP request contents

    Arguments:
        website : host website to make HTTP request for
    Returns:

    '''

    try:
        # Establish connection
        connection = http.client.HTTPConnection(website, timeout=10)

        # Make GET request
        head = {'Host': website}
        connection.request('GET', '/', headers=head)
        response = connection.getresponse()
        
        # Read in response, so must be listening
        listen_http = True

        if response.code >= 300 and response.code <= 310:
            # Redirects directly to https
            server, redirect_https, hsts = follow_http_redirect(response.getheader('Location'), response.getheader('Server'))

        else:
            # No redirect attempt made ---> Try HTTPS
            redirect_https = False
            server = response.getheader('Server')
            #PAY ATTENTION TO THIS !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
            _, hsts = get_https_data(website, '/')
            #hsts = False

        connection.close()

    except Exception as e:
        sys.stdout.write('HTTP connection failed with error:\n{0}\n'.format(e))
        # Not listening for http connections
        connection.close()
        listen_http = False
        redirect_https = False
        hsts = False

        # Try https connection
        server, _ = get_https_data(website, '/')

    
    return server, listen_http, redirect_https, hsts


def get_tls_data(host: str) -> Tuple[List[str], str]:
    ''' 
    Retrieve TLS versions and root certificate for a given host

    Arguments:
        host : host URL to query
    Returns:
        tls_versions : list of supported TLS versions
        root_ca      : root certificate authority
    '''
    tls_strings = ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1', 'TLSv1.2']

    tls_versions = []

    # Get all supported encryptions (except TLSv1.3)
    command = 'nmap --script ssl-enum-ciphers -p 443 {0}'.format(host)
    try:
        response = subprocess.check_output(command, shell=True, timeout=10, stderr=subprocess.STDOUT).decode('utf-8')

        for line in response.split('\n|'):
            strip_line = (line.strip())[:-1]
            if strip_line in tls_strings:
            # TLS version match found ---> add to list
                tls_versions.append(strip_line)

    except subprocess.TimeoutExpired as e:
        # nmap timed out
        sys.stdout.write('{0}\n'.format(e))
    except subprocess.CalledProcessError:
        # nmap returned nonzero exit code
        sys.stdout.write('nmap on {0} returned non-zero exit code'.format(host))

    # Get TLSv1.3 with openssl
    try:
        result = subprocess.check_output('echo | openssl s_client -tls1_3 -connect {0}:443'.format(host), shell=True, timeout=2, stderr=subprocess.STDOUT)

        # Didn't thow error on nonzero return code, so must have successfully connected via TLSv1.3
        tls_versions.append('TLSv1.3')
    except subprocess.SubprocessError:
        # Nonzero return code (could not connect over TLSv1.3)
        pass

    try:
        result = subprocess.check_output('echo | openssl s_client -connect {0}:443'.format(host), shell=True, timeout=2, stderr=subprocess.STDOUT).decode('utf-8')
        # Parse result to retreive root_ca
        certificate_chain = result.split('---')[1]
        root = certificate_chain.split('\n')[-2]
        
        # Find name category of root
        categories = (root.split('i:')[-1]).split(', ')
        for i in range(len(categories)):
            cat = categories[i]
            if cat[0] == 'O':
                root_ca = cat.split(' = ')[-1]
                # Handle quoted expressions that get separated by ', ' split
                while root_ca[0] == '\"' and root_ca[-1] != '\"':
                    i += 1
                    root_ca = ', '.join([root_ca, categories[i]])
                break
    
    except subprocess.SubprocessError:
        # No tls supported ---> root_ca is none
        root_ca = None
    

    return tls_versions, root_ca




def get_dns_data(ipv4_addresses: List[str]) -> List[str]:
    '''
    Retrieve dns data for all ipv4 addresses

    Arguments:
        ipv4_addresses : all ipv4 addresses to query
    Returns:
        rdns : all rdns data for these ip addresses
    '''
    rdns = []

    for ipv4 in ipv4_addresses:
        # nslookup each ipv4 of website
        try:
            result = subprocess.check_output(['nslookup', '-type=PTR', ipv4], timeout=3, stderr=subprocess.STDOUT).decode('utf-8')
            split_result = result.split('Non-authoritative answer:\n')
            if len(split_result) < 2:
                # No answers provided
                continue

            lines = split_result[1].split('\n')

            for line in lines:
                if line == '':
                    # Hit blank line, so no more to read
                    break
                
                split_line = line.split('\t')
                for section in split_line:
                    if (section[:4] == 'name') and (section[7:] not in rdns):
                        #print('Adding {0} to rdns'.format(section[7:]))
                        rdns.append(section[7:])

        except subprocess.TimeoutExpired as e:
            sys.stdout.write('{0}\n'.format(e))
            continue

        except subprocess.SubprocessError:
            # Command returned nonzero exit code ---> try next combination
            #print('---------cp-error : nslookup -type=PTR {0}'.format(ipv4))
            continue
    
    return rdns



def parse_time(time_string: str) -> float:
    '''
    Parse time string to time in miliseconds

    Arguments:
        time_string : string of the form 'XmX.XXXs'
    Returns:
        time : equivalent time in milliseconds
    '''
    split_time = time_string[:-1].split('m')
    min_ms = float(split_time[0]) * 60000
    sec_ms = float(split_time[1]) * 1000
    return min_ms + sec_ms



def get_rtt_range(ipv4_addresses: List[str]) -> List[int]:
    '''
    Return range of rount trip time for all ipv4 addresses

    Arguments:
        ipv4_addresses : all ipv4 addresses to query
    Returns:
        rtt_range : [min,max] of rount trip time across all ipv4 addresses
    '''
    rtt_range = [float('inf'), 0]

    for ipv4 in ipv4_addresses:
        try:
            # Measure rtt from commandline
            result = subprocess.check_output(["sh", "-c", "time echo -e '\x1dclose\x0d' | telnet {0} 443".format(ipv4)], 
                                             timeout=3, stderr=subprocess.STDOUT).decode('utf-8')
        except subprocess.SubprocessError:
            # Failed to get rtt -> try next ipv4
            sys.stdout.write('Failed to connect to {0} to measure RTT\n'.format(ipv4))
            continue
            

        for line in result.split('\n'):
            if line[:4] == 'real':
                # Parse rtt
                rtt = parse_time(line.split('\t')[1])
                # Update rtt_range
                rtt_range = [min(rtt, rtt_range[0]), max(rtt, rtt_range[1])]
                # Continue to next ipv4
                break
    
    if rtt_range == [float('inf'), 0]:
        sys.stdout.write('Failed to make any connections to measure RTT of IPv4 addresses:\n{0}\n'.format(ipv4_addresses))

    return rtt_range
            


def get_geo_locations(ipv4_addresses: List[str]) -> List[str]:
    '''
    Retrieve all real-world locations for all of the ipv4 addresses

    Arguments:
        ipv4_addresses : list of ipv4 addresses to search
    Returns:
        geo_locations : list of real-world locations for the ipv4 addresses
    '''
    reader = maxminddb.open_database('GeoLite2-City.mmdb')

    geo_locations = []

    for ipv4 in ipv4_addresses:
        try:
            ip_data = reader.get(ipv4)
        except ValueError:
            # No data for ip in database
            continue
        
        loc_parts = []

        for cat in ['city', 'subdivisions', 'country']:
            try:
                cat_data = ip_data[cat]
                # Extract dict from list if needed
                if type(cat_data) == list: cat_data = cat_data[0]
                loc_parts.append(cat_data['names']['en'])
            except KeyError:
                # Data not in database
                #sys.stdout.write('{0}\t: key error - {1}\n'.format(ipv4, cat))
                #sys.stdout.write('{0}\t: available keys - {1}\n'.format(ipv4, ', '.join(ip_data.keys())))
                continue

        # Build loc and add to geo_locations if not already added
        loc = ', '.join(loc_parts)
        if (loc != '') and (loc not in geo_locations):
            geo_locations.append(loc)

    # Close database reader
    reader.close()

    return geo_locations







# Check for command line argument
if len(sys.argv) != 3:
    sys.stderr.write("scan.py requires 2 arguments: input_file.txt and output_file.json \n")
    sys.exit(1)

# Load in websites from input file
websites = []
with open(sys.argv[1], "r") as input_file:
    for line in input_file:
        websites.append(line.split('\n')[0])

# Run scans
scans = {}
for w in websites:
    sys.stdout.write('Scanning {0}\n'.format(w))

    scans[w] = {"scan_time": time.time()}

    if which('nslookup'):
        ipv4_addresses = get_ip_addresses(w, 'ipv4')
        ipv6_addresses = get_ip_addresses(w, 'ipv6')
        rdns = get_dns_data(ipv4_addresses)

        scans[w]['ipv4_addresses'] = ipv4_addresses
        scans[w]['ipv6_addresses'] = ipv6_addresses
        scans[w]['rdns_names'] = rdns
    else:
        # Necessary commandline utility available
        sys.stderr.write('WARNING report.py: nslookup command not detected on machine, so ipv4_addresses, ipv6_addresses, and rdns_names will not be included in {0}\n'.format(sys.argv[2]))


    http_server, listen_http, redirect_https, hsts = get_http_data(w)

    scans[w]['http_server'] = http_server
    scans[w]['insecure_http'] = listen_http
    scans[w]['redirect_to_https'] = redirect_https
    scans[w]['hsts'] = hsts

    if which('nmap') and which('openssl') and which('echo'):
        tls_versions, root_ca = get_tls_data(w)

        scans[w]['tls_versions'] = tls_versions
        scans[w]['root_ca'] = root_ca
    else:
        sys.stderr.write('WARNING report.py: nmap, openssl, or echo command not detected on machine, so tls_versions and root_ca will not be included in {0}\n'.format(sys.argv[2]))

    if which('sh') and which('echo') and which('time') and which('telnet'):
        rtt_range = get_rtt_range(ipv4_addresses)
        scans[w]['rtt_range'] = rtt_range
    else:
        sys.stderr.write('WARNING report.py: sh, echo, time, or telnet command not detected on machine, so rtt_range will not be included in {0}\n'.format(sys.argv[2]))

    geo_locations = get_geo_locations(ipv4_addresses)
    scans[w]['geo_locations'] = geo_locations


# Write scan output to output file
with open(sys.argv[2], "w") as output_file:
    json.dump(scans, output_file, sort_keys=True, indent=4)

sys.stdout.write("exited normally\n")
sys.exit(0)