#!/usr/bin/env python
""" Scan provided IP addresses

This script scans a list of IP addresses for various pieces of information:
  - IPv4 and IPv6 addresses
  - RDNS path
  - Root Certificate Authority
  - HTTP server architecture
  - Support for HTTPS
  - Redirecting to HTTPS
  - Support for HTTP Strict Transport Security (HSTS)
  - Supported TLS versions
  - Server Geolocations
  - Request Round-Trip-Time

This script was originally written as part of Comp_Sci 340 Introduction to Computer Networking 
in Fall Quarter 2020, but has since been updated for better readability and flexibility.

Comandline Arguments:
url_file -- line separated list of webiste URLs to scan
out_file -- output file to save JSON formatted results to
"""

from sys import argv, exit, stdout, stderr
from typing import List, Tuple

from shutil import which    # Determining if command utility exits
import time                 # for epoch time
import json                 # for packaging result
import subprocess           # for making cmd scans
import http.client          # for http connections
import maxminddb            # for geolocations


__author__ = 'Spencer Fitch'
__credits__ = ["Spencer Fitch"]

__version__ = "0.1.0"
__maintainer__ = "Spencer Fitch"
__email__ = "spencer@spencerfitch.com"
__status__ = "development"

LOG_STATUS = "{0} [STATUS] - ".format(argv[0])

dns_resolvers = ['208.67.222.222', '1.1.1.1', '8.8.8.8', '8.26.56.26', '9.9.9.9', 
                 '64.6.65.6', '185.228.168.168', '91.239.100.100',
                 '77.88.8.7', '156.154.70.1', '198.101.242.72', '176.103.130.130']
                 
https_failed = False

def get_ip_addresses(website: str, ip_type: str) -> List[str]:
    """
    Queries dns_resolvers for all ip addresses of webiste of particular ip_type

    Args:
        website (str):
            website to make DNS requests for
        ip_type (str):
            type of IP address to query for ('ipv4' or 'ipv6')
    Returns:
        List of all unique IP address strings for particular website.
        For example:
            ['104.69.219.34', '184.51.132.77, '23.2.28.215']
    """
    ip_addresses = []

    if (ip_type == 'ipv4'):
        nstype = "-type=A"
    elif (ip_type == 'ipv6'):
        nstype = "-type=AAAA"
    else:
        stderr.write('Invalid ip_type passed to get_ip_addresses: ' + str(ip_type))
        return None

    for dns in dns_resolvers:
        
        try:
            result = subprocess.check_output(["nslookup", nstype, w, dns], timeout=4, stderr=subprocess.STDOUT).decode("utf-8") 
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
    """
    Parse url into components: http(s), host, path

    Args:
        url (str): 
            full url to parse
    Returns:
        Tuple of split URL components of HTTP type, host website, and HTTP path.
        For example: 
            ("http", "google.com", "/images")
    """
    split_url = url.split('/')

    http_type = split_url[0][:-1]
    host = split_url[2]
    path = '/' + '/'.join(split_url[3:])

    return http_type, host, path


def get_https_data(host: str, path: str) -> Tuple[str, bool]:
    """
    Return server info of basic https request

    Args:
        host (str):
            hostname of destination server
        path (str):
            path for destination resource
    Returns:
        Tuple of server architecutre string and HSTS support flag.
        For example:
            ('nginx', False)
    """
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
        # HTTPS connection failed
        global https_failed
        https_failed = True
        stdout.write('{0} HTTPS connection failed for {0}'.format(LOG_STATUS, host))
        return None, False



def follow_http_redirect(url: str, server: str) -> Tuple[str, bool, bool]:
    '''
    Indicates if HTTP 30X redirects to HTTPS site in <10 redirects

    Args:
        url (str):
            full url to redirect to
        server (str):
            initial HTTP server information
    Returns:
        Tuple of final server information, whether the redirect resulted in
        an HTTPS server, and whether the HTTPS server supports HSTS.
        For example:
            ('nginx', True, False)
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

    Args:
        website (str):
            host website to make HTTP request for
    Returns:
        Tuple of server architecture string and flags for listening 
        for HTTP (port 80), redirecting to HTTPS, and support for HSTS.
        For example:
            ('nginx', True, True, False)
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
        stdout.write('{0}HTTP connection failed with error:\n{1}\n'.format(LOG_STATUS, e))
        # HTTP connection failed
        connection.close()
        server = None
        listen_http = False
        redirect_https = False
        hsts = False
    
    return server, listen_http, redirect_https, hsts


def get_tls_data(host: str) -> Tuple[List[str], str]:
    ''' 
    Retrieve TLS versions and root certificate for a given host

    Args:
        host (str):
            host URL to query
    Returns:
        Tuple of list of supported TLS versions and the host's Root
        Certificate Authority. For example:
            (['TLSv1.1', 'TLSv1.2'], 'DigiCert Inc')
    '''
    tls_strings = ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1', 'TLSv1.2']

    tls_versions = []

    global https_failed
    if https_failed:
        # Catch failed https before moving forward
        return tls_versions, None

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
        stdout.write('{0}nmap request timed out with error:\n{1}\n'.format(LOG_STATUS, e))
    except subprocess.CalledProcessError:
        # nmap returned nonzero exit code
        stdout.write('{0}nmap on {1} returned non-zero exit code'.format(LOG_STATUS, host))

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
    
    except subprocess.TimeoutExpired:
        # No tls supported ---> root_ca is none
        root_ca = None
    except subprocess.SubprocessError:
        root_ca = None
    

    return tls_versions, root_ca




def get_dns_data(ipv4_addresses: List[str]) -> List[str]:
    '''
    Retrieve dns data for all ipv4 addresses

    Args:
        ipv4_addresses (List[str]):
            all ipv4 addresses to query for DNS data
    Returns:
        List of Reverse DNS names found for the IP addresses. For example:
            ['apple.com', 'icloud.com', 'icloud.com.cn']
    '''
    rdns = []

    for ipv4 in ipv4_addresses:
        # nslookup each ipv4 of website
        try:
            result = subprocess.check_output(['nslookup', '-type=PTR', ipv4], timeout=4, stderr=subprocess.STDOUT).decode('utf-8')
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
            stdout.write('{0}nslookup timeout expired with error:\n{1}\n'.format(LOG_STATUS, e))
            continue

        except subprocess.SubprocessError:
            # Command returned nonzero exit code ---> try next combination
            #print('---------cp-error : nslookup -type=PTR {0}'.format(ipv4))
            continue
    
    return rdns



def parse_time(time_string: str) -> float:
    '''
    Parse time string to time in miliseconds

    Args:
    time_string (str):
        time string of the form 'XmX.XXXs'
    Returns:
        Equivalent time in milliseconds
    '''
    split_time = time_string[:-1].split('m')
    min_ms = float(split_time[0]) * 60000
    sec_ms = float(split_time[1]) * 1000
    return min_ms + sec_ms



def get_rtt_range(ipv4_addresses: List[str]) -> List[int]:
    '''
    Determine minimum and maximum rount trip time among IP addresses in
    milliseconds.

    Args:
        ipv4_addresses (List[str]):
            all ipv4 addresses to query
    Returns:
        Tuple of minimum and maximum round trip time among all IP addresses.
        For example:
            (23.0, 30.0)
    '''
    rtt_range = [float('inf'), 0]

    for ipv4 in ipv4_addresses:
        try:
            # Measure rtt from commandline
            global https_failed
            if https_failed:
                result = subprocess.check_output(["sh", "-c", "time echo -e '\x1dclose\x0d' | telnet {0} 80".format(ipv4)], 
                                                 timeout=3, stderr=subprocess.STDOUT).decode('utf-8')
            else:
                result = subprocess.check_output(["sh", "-c", "time echo -e '\x1dclose\x0d' | telnet {0} 443".format(ipv4)], 
                                                 timeout=3, stderr=subprocess.STDOUT).decode('utf-8')

        except subprocess.SubprocessError:
            # Failed to get rtt -> try next ipv4
            stdout.write('{0}Failed to connect to {0} to measure RTT\n'.format(LOG_STATUS, ipv4))
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
        stdout.write('{0}Failed to make any connections to measure RTT of IPv4 addresses:\n{0}\n'.format(LOG_STATUS, ipv4_addresses))
        rtt_range = [float('inf'), float('inf')]

    return rtt_range
            


def get_geo_locations(ipv4_addresses: List[str]) -> List[str]:
    '''
    Retrieve all real-world locations for all of the IPv4 addresses using
    specified GeoLite location information file.

    Args:
        ipv4_addresses (List[str]): 
            list of ipv4 addresses to search
    Returns:
        List of real-world locations for IPv4 addresses. For example:
            ['Singapore', 'United Kingdom', 'United States']
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
                #stdout.write('{0}\t: key error - {1}\n'.format(ipv4, cat))
                #stdout.write('{0}\t: available keys - {1}\n'.format(ipv4, ', '.join(ip_data.keys())))
                continue

        # Build loc and add to geo_locations if not already added
        loc = ', '.join(loc_parts)
        if (loc != '') and (loc not in geo_locations):
            geo_locations.append(loc)

    # Close database reader
    reader.close()

    return geo_locations





if __name__ == '__main__':

    # Check for command line argument
    if len(argv) != 3:
        stderr.write("scan.py requires 2 arguments: input_file.txt and output_file.json \n")
        exit(1)

    # Load in websites from input file
    websites = []
    with open(argv[1], "r") as input_file:
        for line in input_file:
            websites.append(line.split('\n')[0])

    # Run scans
    scans = {}
    for w in websites:
        https_failed = False
        stdout.write('{0}Scanning {1}\n'.format(LOG_STATUS, w))

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
            stderr.write('WARNING report.py: nslookup command not detected on machine, so ipv4_addresses, ipv6_addresses, and rdns_names will not be included in {0}\n'.format(argv[2]))


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
            stderr.write('WARNING report.py: nmap, openssl, or echo command not detected on machine, so tls_versions and root_ca will not be included in {0}\n'.format(argv[2]))

        if which('sh') and which('echo') and which('time') and which('telnet'):
            rtt_range = get_rtt_range(ipv4_addresses)
            scans[w]['rtt_range'] = rtt_range
        else:
            stderr.write('WARNING report.py: sh, echo, time, or telnet command not detected on machine, so rtt_range will not be included in {0}\n'.format(argv[2]))

        geo_locations = get_geo_locations(ipv4_addresses)
        scans[w]['geo_locations'] = geo_locations


    # Write scan output to output file
    with open(argv[2], "w") as output_file:
        json.dump(scans, output_file, sort_keys=True, indent=4)

    stdout.write("{0}exited normally\n".format(LOG_STATUS))
    exit(0)