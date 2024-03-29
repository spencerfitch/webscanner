#!/urs/bin/env python
""" Scan for information about websites

This module can obtain a variety of information about a given host website 
including IP addresses, reverse DNS results, TLS support, and more. 

Functions:

    full_scan(str, List[str], str) -> dict
    get_ipv4(str, List[str]) -> List[str]
    get_ipv6(str, List[str]) -> List[str]
    get_rdns(List[str]) -> List[str]
    get_http_data(str) -> Tuple[str, bool, bool]
    get_https_data(str) -> Tuple[bool, bool]
    get_tls_data(str) -> Tuple[List[str], str]
    get_rtt_range(List[str], bool) -> Tuple[int, int]
    get_geo_locations(List[str], str) -> List[str]

Misc Variables:

    __name__
    __author__
    __credits__
    __version__
    __email__
    __status__

    __dns_default__

"""

from http.client import HTTPConnection, HTTPSConnection
from sys import stdout, stderr
from typing import List, Tuple
from subprocess import check_output, STDOUT, CalledProcessError, TimeoutExpired, SubprocessError
from shutil import which

from maxminddb import open_database

__name__ = 'webscanner'
__author__ = 'Spencer Fitch'
__credits__ = ['Spencer Fitch']
__version__ = '0.5.1'
__email__ = 'spencer@spencerfitch.com'
__status__ = 'development'

__dns_default__ = [
    '1.1.1.1', '8.8.8.8', '8.26.56.26', '9.9.9.9', '64.6.65.6',
    '91.239.100.100', '185.228.168.168', '77.88.8.7', '156.154.70.1']


def full_scan(host: str, dns_resolvers: List[str] = __dns_default__, geo_file: str = None) -> dict:
    """
    Run a complete scan of a given website using all available functions.

    Args:
        host (str):
            host to conduct a full web scan of
        dns_resolvers (List[str]):
            List of DNS resolvers to use in finding IPv4 and IPv6 addresses.
            If excluded a default list of DNS resolvers will be used.
            If passed as None, IPv4 and IPv6 information will be excluded from the results
        geo_file (List[str]):
            Path to GeoLite2 database file. If excluded the geo_locations
            field will not be included in results.
    Returns:
        Dict of full results from web scan. For example:
        {
            'geo_locations': ['United States'],
            'hsts': False,
            'http_server': 'nginx',
            'ipv4_addresses': [
                '104.69.219.34',
                '23.194.107.92',
                '23.3.1.96'
            ],
            'ipv6_addresses': [
                '2607:f8b0:4004:809::200e',
                '2a00:1450:4010:c09::8b'
            ],
            'listen_http': True,
            'listen_https': True,
            'rdns_names': [
                'apple.com',
                'icloud.com',
                'icloud.com.cn'
            ]
            'redirect_to_https': True,
            'root_ca': 'DigiCert Inc',
            'rtt_range': (3.0, 25.0),
            'tls_versions': [
                'TLSv1.2',
                'TLSv1.3'
            ]

        }
    """
    scan_results = {}

    if not which('nslookup'):
        __write_warning('nslookup command not detected on machine, so ipv4_addresses, ipv6_addresses, and rdns_names cannot be found')
        scan_results['ipv4_addresses'] = []
        scan_results['ipv6_addresses'] = []
        scan_results['rdns_names'] = []
    elif not dns_resolvers:
        scan_results['ipv4_addresses'] = []
        scan_results['ipv6_addresses'] = []
        scan_results['rdns_names'] = []
    else:
        scan_results['ipv4_addresses'] = get_ipv4(host, dns_resolvers)
        scan_results['ipv6_addresses'] = get_ipv6(host, dns_resolvers)
        scan_results['rdns_names'] = get_rdns(scan_results['ipv4_addresses'])
    

    http_server, listen_http, redirect_to_https = get_http_data(host)

    scan_results['http_server'] = http_server
    scan_results['listen_http'] = listen_http
    scan_results['redirect_to_https'] = redirect_to_https

    listen_https, hsts = get_https_data(host)

    scan_results['listen_https'] = listen_https
    scan_results['hsts'] = hsts

    if not (which('nmap') and which('openssl') and which('echo')):
        __write_warning('nmap, openssl, or echo command not detected on machine, so tls_versoins and root_ca cannot be found')
        scan_results['tls_versions'] = []
        scan_results['root_ca'] = None

    else:
        tls_versions, root_ca = get_tls_data(host)

        scan_results['tls_versions'] = tls_versions
        scan_results['root_ca'] = root_ca

    if not (which('sh') and which('echo') and which('time') and which('telnet')):
        __write_warning('sh, echo, time, or telnet commands not detected on this machine, so rtt_range cannot be found')
        scan_results['rtt_range'] = [float('inf'), float('inf')]
    else:
        scan_results['rtt_range'] = get_rtt_range(scan_results['ipv4_addresses'])
    
    if not geo_file:
        scan_results['geo_locations'] = []
    else:
        scan_results['geo_locations'] = get_geo_locations(scan_results['ipv4_addresses'], geo_file)

    return scan_results

def get_ipv4(host: str, dns_resolvers: List[str] = __dns_default__) -> List[str]:
    """
    Query DNS resolvers for all IPv4 addresses of specified host

    Args:
        host (str):
            host to resolve IP addresses for
        dns_resolvers (List[str]):
            list of IP addresses of DNS servers
    Returns:
        List of unique IP addresses for particular host. For example:
            ['104.68.219.34', '184.51.132.77', '23.2.28.215']
    """
    return __get_ip_addresses(host, dns_resolvers, False)

def get_ipv6(host: str, dns_resolvers: List[str] = __dns_default__) -> List[str]:
    """
    Query DNS resolvers for all IPv6 addresses of specified host

    Args:
        host (str):
            host to resolve IP addresses for
        dns_resolvers (List[str]):
            list of IP addresses of DNS servers
    Returns:
        List of unique IP addresses for particular host. For example:
            ['2001:db8::2:1', '2001:db8:a::123']
    """
    return __get_ip_addresses(host, dns_resolvers, True)

def get_rdns(ipv4_addresses: List[str]) -> List[str]:
    """
    Retreive reverse DNS results for a given list of IPv4 addresses

    Args:
        ipv4_addresses (List[str]):
            all IPv4 addresses to query for DNS data
    Returns:
        List of reverse DNS names found for the IP addresses. For example:
            ['apple.com', 'icloud.com', 'icloud.com.cn']
    """
    rdns = []

    for ipv4 in ipv4_addresses:
        try:
            ns_result = check_output(
                ['nslookup', '-type=PTR', ipv4],
                timeout=4,
                stderr=STDOUT).decode('utf-8')
            
            split_result = ns_result.split('Non-authoritative answer:\n')

            if len(split_result) < 2:
                # No RDNS results found
                continue
            
            for line in split_result[1].split('\n'):
                if line == '':
                    # Blank line reached means no more RDNS to read
                    break
                    
                for section in line.split('\t'):
                    if section[:4] == 'name' and section[7:] not in rdns:
                        rdns.append(section[7:-1])
            
        except TimeoutExpired as e:
            __write_status('RDNS lookup for {0} timeout expired with error:\n{1}'.format(ipv4, e))
            continue

        except SubprocessError:
            __write_status('RDNS lookup for {0} exited with nonzero status code and error:\n{0}'.format(ipv4, e))
            continue

    return rdns

def get_http_data(host: str) -> Tuple[str, bool, bool]:
    """
    Retreive HTTP request contents

    Args:
        host (str):
            host to make HTTP request for
    Returns:
        Tuple of server architecture string, listening
        for HTTP flag, and redirecting to HTTPS flag. For example:
            ('nginx', True, False) 
    """
    http_response = __make_http_request(host, '/')

    if not http_response:
        # Not listening for HTTP requests so terminate scan
        return None, False, False

    server = http_response.getheader('Server')
    listen_http = True

    if 300 <= http_response.code <= 310:
        # Follow redirect for possible HTTPS
        redirect_to_https = __does_redirect_to_https(http_response.getheader('Location'))
        return server, listen_http, redirect_to_https
    
    redirect_to_https = False
        
    return server, listen_http, redirect_to_https

def get_https_data(host: str) -> Tuple[bool, bool]:
    """
    Retreive server information for basic HTTPS request

    Args:
        host (str):
            hostname to get HTTPS data information for
    Returns:
        Tuple of HTTPS support flag and HSTS support flag
        For example:
            (True, False)
    """
    https_response = __make_http_request(host, '/', https=True)

    if not https_response:
        return False, False

    https = True
    hsts = https_response.getheader('Strict-Transport-Security') != None

    return https, hsts

def get_tls_data(host: str) -> Tuple[List[str], str]:
    """
    Retrieve supported TLS versions and root certificate authority for a given host

    Args:
        host (str):
            hostname to query
    Returns:
        Tuple of list of supported TLS versions and the host's root
        certificate authority. For example:
            (['TLSv1.1', 'TLSv1.2', 'DigiCert Inc'])
    """
    TIMEOUT = 10
    TLS_STRINGS = ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1', 'TLSv1.2']

    tls_supported = []

    # Check for supported encryptions with nmap (except TLSv1.3)
    try:
        command = 'nmap --script ssl-enum-ciphers -p 443 {0}'.format(host)
        tls_response = check_output(command, shell=True, timeout=TIMEOUT, stderr=STDOUT).decode('utf-8')

        for line in tls_response.spit('\n|'):
            tls_entry = line.strip()[:-1]
            if tls_entry in TLS_STRINGS:
                tls_supported.append(tls_entry)
    
    except TimeoutExpired as e:
        __write_status('TLS version nmap request for {0} timed out with error:\n{1}'.format(host, e))
    except CalledProcessError as e:
        __write_status('TLS version nmap request for {0} returned non-zero exit code with error:\n{1}'.format(host, e))
    
    # Check for TLSv1.3 with openssl
    try:
        command = 'echo | openssl s_client -tls1_3 -connect {0}:443'.format(host)
        tls_response = check_output(command, shell=True, timeout=TIMEOUT, stderr=STDOUT).decode('utf-8')

        # No error thrown so must support TLSv1.3
        tls_supported.append('TLSv1.3')

    except SubprocessError:
        # Couldn't connect and thus no support for TLSv1.3
        pass

    # Retreive root certificate authority information
    try:
        command = 'echo | openssl s_client -connect {0}:443'.format(host)
        rca_response = check_output(command, shell=True, timeout=TIMEOUT, stderr=STDOUT).decode('utf-8')

        certificate_chain = rca_response.split('---')[1]
        root = certificate_chain.split('\n')[-2]

        # Find name category of root
        categories = (root.split('i:')[-1]).split(', ')
        for i, c in enumerate(categories):
            if c[0] == 'O':
                root_ca = c.split(' = ')[-1]

                if root_ca[0] == '\"':
                    # Combine quoted expression separated by ', ' split if needed
                    while root_ca[-1] != '\"':
                        i += 1
                        root_ca = ', '.join([root_ca, categories[i]])
                
                    # Trim off quote characters
                    root_ca = root_ca[1:-1]

                break
    
    except TimeoutExpired as e:
        __write_status('Root Certificate Authority openssl request for {0} timed out with error:\n{1}'.format(host, e))
        root_ca = None
    except SubprocessError as e:
        __write_status('Root Certificate Authority openssl request for {0} exited with non-zero status and error:\n{1}'.format(host, e))
        root_ca = None

    return tls_supported, root_ca

def get_rtt_range(ipv4_addresses: List[str], https: bool = False) -> Tuple[int, int]:
    """
    Determine minimum and maximum round trip time among all IP addresses 
    in milliseconds.

    Args:
        ipv4_addresses (List[str]):
            all ipv4 addresses to query
    Returns:
        Tuple of minimum and maximum round trip time among all IP addresses.
        For example:
            (23.0, 42.0)
    """
    TIMEOUT = 3
    PORT = 443 if https else 80

    rtt_range = [float('inf'), 0]
    update_rtt = lambda rtt: [min(rtt, rtt_range[0]), max(rtt, rtt_range[1])]

    for ipv4 in ipv4_addresses:
        try:
            command = ['sh', '-c', "time echo -e '\x1dclose\x0d' | telnet {0} {1}".format(ipv4, PORT)]
            rtt_response = check_output(command, timeout=TIMEOUT, stderr=STDOUT).decode('utf-8')

        except SubprocessError:
            __write_status('Failed to connect to {0} to measure RTT'.format(ipv4))
            continue

        for line in rtt_response.split('\n'):
            if line[:4] == 'real':
                rtt = __parse_rtt_time(line.split('\t')[1])
                rtt_range = update_rtt(rtt)
                break
    
    if rtt_range == [float('inf'), 0]:
        __write_status('Failed to make any connections to measure RTT of IPv4 addresses:\n{0}'.format(ipv4_addresses))
        rtt_range = [float('inf'), float('inf')]
    
    return rtt_range     

def get_geo_locations(ipv4_addresses: List[str], geo_file: str) -> List[str]:
    """
    Retreive all real-world locations for all of the IPv4 addresses using
    specified GeoLite location information file

    Args:
        ipv4_addresses (List[str]):
            list of IPv4 addresses to search
        geo_file (str):
            path to GeoLite2 database file to use for location data
    Returns:
        List of real-world locations associated with IPv4 addresses.
        For example:
            ['Singapore', 'United Kingdom', 'United States']
    """
    reader = open_database(geo_file)

    geo_locations = []

    for ipv4 in ipv4_addresses:
        try:
            ip_data = reader.get(ipv4)
        except ValueError:
            # No geodata for IPv4 address in database
            continue

        loc_parts = []
        for cat in ['city', 'subdivisions', 'country']:
            try:
                cat_data = ip_data[cat]
                # Extract dict from list if needed
                if type(cat_data) == list: cat_data = cat_data[0]
                loc_parts.append(cat_data['names']['en'])
            except KeyError:
                # Data category not in database
                continue

        # Merge location components and add if not already included
        loc = ', '.join(loc_parts)
        if loc != '' and loc not in geo_locations:
            geo_locations.append(loc)
    
    reader.close()
    return geo_locations


def __write_status(message: str) -> None:
    """
    Write a status message to stdout

    Args:
        message (str):
            formatted body of message to write
    """
    stdout.write('{0} [STATUS] - {1}\n'.format(__class__.__name__, message))
    return

def __write_warning(message: str) -> None:
    """
    Write a warning message to stderr

    Args:
        message (str):
            formatted body of message to write
    """
    stderr.write('{0} [WARNING] - {1}\n'.format(__class__.__name__, message))

def __write_error(message: str) -> None:
    """
    Write an error message to stderr

    Args:
        message (str):
            formatted body of message to write
    """
    stderr.write('{0} [ERROR] - {1}\n'.format(__class__.__name__, message))
    return

def __get_ip_addresses(host: str, dns_resolvers: List[str], ipv6: bool = False) -> List[str]:
    """
    Query DNS resolvers for all IP addresses of specified host

    Args:
        host (str):
            host to resolve IP addresses for
        dns_resolvers (List[str]):
            list of IP addresses of DNS servers
        ipv6 (bool):
            flag to search for IPv6 addresses, rather than IPv4
    Returns:
        List of unique IP addresses for particular host. For example:
            ['104.68.219.34', '184.51.132.77', '23.2.28.215']
    """
    ip_addresses = []

    nstype = '-type=A' if not ipv6 else '-type=AAAA'

    for dns in dns_resolvers:
        try:
            ns_result = check_output(
                ['nslookup', nstype, host, dns],
                timeout=4,
                stderr=STDOUT).decode('utf-8') 
        except SubprocessError as e:
            print(e)
            continue

        for line in (ns_result.split('\n\n')[1]).split('\n'):
            split_line = line.split(': ')
            if split_line[0] == "Address" and split_line[1] not in ip_addresses:
                ip_addresses.append(split_line[1])
    
    ip_addresses.sort()
    return ip_addresses

def __split_url(url: str) -> Tuple[str, str, str]:
    """
    Split URL into component parts with flag for HTTPS

    Args:
        url (str):
            full URL to split
    Returns:
        Tuple of split URL components of HTTPS flag, host website, 
        and HTTP path. For example:
            (True, 'google.com', '/images')
    """
    split = url.split('/')

    https = split[0][:-1] == 'https'
    host = split[2]
    path = '/' + '/'.join(split[3:])

    return https, host, path

def __make_http_request(host: str, path: str, https: bool = False)-> object:
    """
    Make web request of specified type to host at desired path

    Args:
        host (str):
            web host to make request to
        path (str):
            specific resource to request from host
        https (bool):
            flag to make HTTPS request instead of default HTTP request
    Returns:
        http.client.HTTPResponse object if request successful, otherwise None
    """
    TIMEOUT = 10
    try:
        if https:
            connection = HTTPSConnection(host, timeout=TIMEOUT)
        else:
            connection = HTTPConnection(host, timeout=TIMEOUT)

        head = {'Host': host}
        connection.request('GET', path, headers=head)
        response = connection.getresponse()

        connection.close()
        return response

    except Exception as e:
        connection.close()
        http_string = 'HTTPS' if https else 'HTTP'
        __write_status('{0} connection to {1} failed with error:\n{2}'.format(http_string, host+path, e))
        return None

def __does_redirect_to_https(url: str, attempts_remain: int = 10) -> bool:
    """
    Follow up to HTTP 30X redirects until HTTPS found or out of remaining attempts

    Args:
        url (str):
            full redirect url
        attempts_remain (int):
            current redirect attempts remaining
    Returns:
        Boolean indicating whether the HTTP request redirects to HTTPS
    """
    https, host, path = __split_url(url)

    if https:
        # Redirected to HTTPS
        return True

    if attempts_remain <= 0:
        __write_status('Failed to reach end of HTTP redirect path for {0} before redirect limit'.format(url))
        return False

    # Follow Redirect
    http_response = __make_http_request(host, path)

    if not http_response:
        # Redirect fialed
        return False

    if http_response.code < 300 or http_response.code > 310:
        # Redirecting stopped before HTTPS reached
        return False

    return __follow_http_redirect(http_response.getheader('Location'), attempts_remain-1) 

def __parse_rtt_time(time_string: str) -> int:
    """
    Parse time string into milliseconds

    Args:
        time_string (str):
            string of form 'XmX.XXXs'
    Returns:
        Equivalent time in milliseconds
    """
    split_time = time_string[:-1].split('m')

    min_ms = float(split_time[0]) * 60000
    sec_ms = float(split_time[1]) * 1000
    
    return min_ms + sec_ms
