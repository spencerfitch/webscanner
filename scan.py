#!usr/bin/env python
""" Use webscanner module to scan list of websites

This script utilizes the webscanner module to scan a list of websites using provided
DNS resolvers and GeoLite2 file and save the results to a JSON output file. 

Misc Variables:

    __author__
    __credits__
    __version__
    __email__
    __status__

Comandline Arguments:

    url_file -- line separated list of webiste URLs to scan
    dns_file -- line separated list of DNS resolver IP addresses
    geo_file -- GeoLite2 location data file
    out_file -- output file to save JSON formatted results to

"""


from errno import EACCES, EISDIR
from sys import argv, stdout, stderr
from json import dump

import webscanner


__author__ = 'Spencer Fitch'
__credits__ = ['Spencer Fitch']
__version__ = '0.4.0'
__email__ = 'spencer@spencerfitch.com'
__status__ = 'development'


if __name__ == '__main__':
    
    # Check for command line arguments
    CMD_ARGS = [
        'url_file -- line separated list of webiste URLs to scan', 
        'dns_file -- line separated list of DNS resolver IP addresses',
        'geo_file -- GeoLite2 location data file', 
        'out_file -- output file to save JSON formatted results to']
    ERROR_ARG = '{0} [Argument Error] - '.format(argv[0])
    if len(argv) != len(CMD_ARGS) + 1:
        exit('{0}{1} arguments required to run this file:\n\t{2}'.format(ERROR_ARG, len(CMD_ARGS), '\n\t'.join(CMD_ARGS)))

    # Load in resources from files
    hosts = [l[:-1] for l in open(argv[1], 'r', encoding='utf-8')]
    dns_resolvers = [l[:-1] for l in open(argv[2], 'r', encoding='utf-8')]
    geo_file = argv[3]
    out_file = argv[4]

    # Check if out_file can be written to before running scan
    try:
        with open(out_file, 'w') as f:
            f.write('\n')
            f.truncate(0)
            pass
    except IOError as e:
        if e.errno == EACCES:
            exit("{0}insufficient perimissions to write output to '{1}'".format(ERROR_ARG, out_file))
        elif e.errno == EISDIR:
            exit("{0}specified output desintation '{1}' is a directory".format(ERROR_ARG, out_file))
        else:
            stderr.write(e)
            exit("{0}unexpected error encountered when writing output to '{1}'".format(ERROR_ARG, out_file))

    # Run scans
    scans = {}
    for h in hosts:
        stdout.write('{0} [STATUS] - Scanning {1}'.format(argv[0], h))

        scans[h] = webscanner.full_scan(h, dns_resolvers, argv[3])

    # Write scan results to output file
    with open(out_file, 'w') as f:
        dump(scans, f, sort_keys=True, indent=4)

    stdout.write('{0} [STATUS] - Scanning finished normally'.format(argv[0]))
    exit(0)