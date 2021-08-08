#!/usr/bin/env python
""" Create a report from scanned website information

This script transcribes the JSON formatted results form the WebScanner class
and produces a formatted text report document for analysis.

Misc Variables:

    __author__
    __credits__
    __version__
    __email__
    __status__

Commandline Arguments:

    scan_file -- file of JSON formatted results from WebScanner class
    out_file -- output file to save text report to

"""

from collections import defaultdict
from errno import EACCES, EISDIR
from heapq import heappush
from json import load
from operator import itemgetter
from sys import argv, stderr, stdout
from typing import Text

from texttable import Texttable


__author__ = 'Spencer Fitch'
__credits__ = ['Spencer Fitch']
__version__ = '0.2.0'
__email__ = 'spencer@spencerfitch.com'
__status__ = 'development'


def pad_line(body: str, width: int, character: str = '=',  mode: str = 'b') -> str:
    """
    Pad line of text with specified character

    Args:
        body (str):
            contents of line to pad out
        character (str):
            character to pad line with
        width (int):
            total desired width of the line
        mode (str):
            mode to pad the line in ('l', 'r', or 'b')
    Returns:
        Line padded out to deisred width. For example:
            '=====30 Character Message====='
    """
    width_diff = width - len(body)
    if width_diff <= 0:
        return body


    if mode == 'l':
        padded = character*width_diff + body
    elif mode == 'r':
        padded = body + character*width_diff
    else:
        left_width = width_diff // 2
        right_width = width_diff - left_width
        padded = character*left_width + body + character*right_width

    return padded

def raise_arg_error(body: str):
    """Raise argument error for commandline input"""
    exit("{0} [Argument Error] - {1}".format(argv[0], body))

def write_status(body: str):
    """Write staus message to stdout"""
    stdout.write("{0} [Status] - {1}".format(argv[0], body))

def format_flag(flag: bool):
    """Format boolean flag for use in table"""
    return 'X' if flag else ''


if __name__ == '__main__':
    # Validate and read in command-line arguments
    CMD_ARGS = ['scan_file', 'out_file']
    if len(argv) != len(CMD_ARGS)+1:
        err = "{1} arguments required to run this file:\n\t{2}".format(
            len(CMD_ARGS),
            '\n\t'.join(CMD_ARGS)
        )
        raise_arg_error(err)

    scan_file = argv[1]
    out_file = argv[2]

    scan_data = load(open(scan_file, 'r', encoding='utf-8'))

    # Check writing to out_file before generating report
    try:
        with open(out_file, 'w') as f:
            f.write('\n')
            f.truncate(0)
            pass
    except IOError as e:
        if e.errno == EACCES:
            err = "insufficient permissionts to write output to '{0}'".format(out_file)
            raise_arg_error(err)
        elif e.errno == EISDIR:
            err = "specified output destination '{0}' is a directory".format(out_file)
            raise_arg_error(err)
        else:
            stderr.write(e)
            err = "unexpected error encountered when writing output to '{0}'".format(out_file)
            raise_arg_error(err)
    
    # Initialize tables
    tables = {
        'general': {
            'name': 'General Scan Data',
            'desc': 'RTT Range, and RDNS Names',
            'table': Texttable(),
            'rows': [['Host', 'Round Trip\nTime Range', 'Reverse DNS\nNames']]
        },
        'ip': {
            'name': 'IP Address Data',
            'desc': 'IPv4 Addresses, IPv6 Addresses, and IPv4 Geolocations',
            'table': Texttable(),
            'rows': [['Host', 'IPv4 Addresses', 'IPv6 Addresses', 'IPv4 Geolocations']]
        },
        'http': {
            'name': 'Server HTTP Feature Data',
            'desc': 'HTTP Server Software, Listening for HTTP, Listening for HTTPS, Redirect to HTTPS, and HSTS',
            'table': Texttable(),
            'rows': [['Website', 'HTTP Server\nSoftware', 'Listening\nfor HTTP', 'Listening\nfor HTTPS', 'Redirect\nto HTTPS', 'HTTP Strict\nTransport\nSecurity']]
        },
        'security': {
            'name': 'Connection Security Data',
            'desc': 'TLS Versions, and Root Certificate Authority',
            'table': Texttable(),
            'rows': [['Website', 'Supported TLS\nVersions', 'Root Certificate\nAuthority']]
        },
        'rtt': {
            'name': 'Round Trip Time Range',
            'desc': 'List of RTT for all websites sorted by the minimum',
            'table': Texttable(),
            'rows': [['Website', 'Min RTT\n(ms)', 'Max RTT\n(ms)']]
        },
        'rootca': {
            'name': 'Root CA Frequency',
            'desc': 'List of all Root CAs ordered by the number of occurences',
            'table': Texttable(),
            'rows': [['Root Certificate Authority', 'Count', 'Percentage']]
        },
        'serv_soft': {
            'name': 'Server Software Frequency',
            'desc': 'List of all Server Software ordered by the number of occurrences',
            'table': Texttable(),
            'rows': [['HTTP Server Software', 'Count']]
        },
        'serv_feat': {
            'name': 'Server Feature Support',
            'desc': 'List of percent support for various server features',
            'table': Texttable(),
            'rows': [['Server Feature', '% Support']]
        }
    }

    # Format tables
    tables['general']['table'].set_cols_dtype(['t', 't', 't'])
    tables['general']['table'].set_cols_align(['l', 'c', 'l'])
    tables['general']['table'].set_cols_width([20, 14, 43])

    tables['ip']['table'].set_cols_dtype(['t', 't', 't', 't'])
    tables['ip']['table'].set_cols_align(['l', 'l', 'l', 'l'])
    tables['ip']['table'].set_cols_width([20, 15, 36, 20])

    tables['http']['table'].set_cols_dtype(['t', 't', 't', 't', 't', 't'])
    tables['http']['table'].set_cols_align(['l', 'l', 'c', 'c', 'c', 'c'])
    tables['http']['table'].set_cols_width([20, 20, 12, 12, 12, 12])

    tables['security']['table'].set_cols_dtype(['t', 't', 't'])
    tables['security']['table'].set_cols_align(['l', 'c', 'c'])
    tables['security']['table'].set_cols_valign(['m', 'm', 'm'])
    tables['security']['table'].set_cols_width([28, 13, 30])

    tables['rtt']['table'].set_deco(Texttable.HEADER | Texttable.BORDER)
    tables['rtt']['table'].set_cols_align(['l', 'r', 'r'])
    tables['rtt']['table'].set_cols_dtype(['t', 'a', 'a'])
    tables['rtt']['table'].set_cols_valign(['c', 'c', 'c'])
    tables['rtt']['table'].set_cols_width([28, 7, 7])

    tables['rootca']['table'].set_deco(Texttable.HEADER | Texttable.BORDER)
    tables['rootca']['table'].set_cols_align(['l', 'r', 'r'])
    tables['rootca']['table'].set_cols_dtype(['t', 'i', 'f'])

    tables['serv_soft']['table'].set_deco(Texttable.HEADER | Texttable.BORDER)
    tables['serv_soft']['table'].set_cols_align(['l', 'r'])
    tables['serv_soft']['table'].set_cols_dtype(['t', 'f'])
    tables['serv_soft']['table'].set_cols_width([15, 9])

    tables['serv_feat']['table'].set_deco(Texttable.HEADER | Texttable.BORDER)
    tables['serv_feat']['table'].set_cols_align(['l', 'r'])
    tables['serv_feat']['table'].set_cols_dtype(['t', 'i'])

    # Initialize cummulative statistic trackers
    host_count = len(scan_data)
    f_percent = lambda x: 100 * (x / host_count)
    flags = ['listen_http', 'listen_https', 'hsts']
    flag_counts = {
        'listen_http': 0,
        'listen_https': 0,
        'redirect_to_https': 0,
        'hsts': 0
    }
    ipv6_count = 0
    rtt_queue = []
    rootca_counts = defaultdict(int)
    server_counts = defaultdict(int)
    tls_counts = {
        'SSLv2': 0,
        'SSLv3': 0,
        'TLSv1.0': 0,
        'TLSv1.1': 0,
        'TLSv1.2': 0,
        'TLSv1.3': 0
    }

    # Analyze all scan data
    for host in scan_data.keys():
        host_data = scan_data[host]

        rtt_range = host_data['rtt_range']

        # Track cummulative statistics
        for f in flags:
            flag_counts[f] += int(host_data[f])
        ipv6_count += int(0 < len(host_data['ipv6_addresses']))
        heappush(rtt_queue, (rtt_range[0], (host, rtt_range)))
        rootca_counts[host_data['root_ca']] += 1
        server_counts[host_data['http_server']] += 1
        for tls in host_data['tls_versions']:
            tls_counts[tls] += 1

        # Append host-based row data
        tables['general']['rows'].append([
            host,
            '{0} to {1}'.format(rtt_range[0], rtt_range[1]),
            '\n'.join(host_data['rdns_names'])
        ])
        tables['ip']['rows'].append([
            host,
            '\n'.join(host_data['ipv4_addresses']),
            '\n'.join(host_data['ipv6_addresses']),
            '"' + '"\n'.join(host_data['geo_locations']) + '"'
        ])
        tables['http']['rows'].append([
            host,
            host_data['http_server'],
            format_flag(host_data['listen_http']),
            format_flag(host_data['listen_https']),
            format_flag(host_data['redirect_to_https']),
            format_flag(host_data['hsts'])
        ])
        tables['security']['rows'].append([
            host,
            '\n'.join(host_data['tls_versions']),
            host_data['root_ca'] if host_data['root_ca'] else ''
        ])

    # Append summary row data
    for _, rtt in rtt_queue:
        tables['rtt']['rows'].append([
            rtt[0], 
            rtt[1][0], 
            rtt[1][1]
        ])
    rootca_counts = sorted(rootca_counts.items(), key=itemgetter(1))
    rootca_counts.reverse()
    for rca in rootca_counts:
        tables['rootca']['rows'].append([
            rca[0],
            rca[1],
            f_percent(rca[1])
        ])
    server_counts = sorted(server_counts.items(), key=itemgetter(1))
    server_counts.reverse()
    for server in server_counts:
        tables['serv_soft']['rows'].append([
            server[0],
            server[1]
        ])
    for tls in tls_counts.keys():
        tables['serv_feat']['rows'].append([
            tls,
            f_percent(tls_counts[tls])
        ])
    flag_rows = [
        ['Listen for HTTP', f_percent(flag_counts['listen_http'])],
        ['Listen for HTTPS', f_percent(flag_counts['listen_https'])],
        ['HTTPS Redirect', f_percent(flag_counts['redirect_to_https'])],
        ['HSTS', f_percent(flag_counts['hsts'])],
        ['IPv6', f_percent(ipv6_count)]
    ]
    for f in flag_rows:
        tables['serv_feat']['rows'].append(f)

    # Output report to file
    with open(out_file, 'w', encoding='utf-8') as f:
        # Document Title
        title_text = " Report of WebScanner Results from '{0}' ".format(scan_file)
        title = pad_line(title_text, 80)
        f.write('{0}\n\n'.format(title))

        # Table of Contents
        table_of_contents = ['===== Table of Contens =====']
        toc_padlen = max(map(lambda x: len(x['name']), tables.values())) + 1
        for i, t in enumerate(tables.values()):
            toc_entry = '{0}: {1} - {2}'.format(
                i+1, 
                pad_line(t['name'], toc_padlen, character=' ', mode='r'),
                t['desc'])
            table_of_contents.append(toc_entry)
        table_of_contents = '\n\t'.join(table_of_contents)
        f.write('{0}\n\n\n\n'.format(table_of_contents))

        # Table
        for t in tables.values():
            t['table'].add_rows(t['rows'])
            table_width = len(t['table'].draw().split('\n')[0])
            title = pad_line(' {0} '.format(t['name']), table_width)
            f.write('{0}\n{1}\n\n\n\n\n\n'.format(title, t['table'].draw()))

        write_status("Report of WebScanner results from '{0}' generated successfully and saved to '{0}'".format(scan_file, out_file))
        exit(0)