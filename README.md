# webscanner

The webscanner module can search for various pieces of information about a given website, including IP addresses, reverse DNS results, and HTTP support. 

This module was originally created as a final project for my introductory networking class in Fall 2020, but has since been adapted and updated for improved generalization and readibility. This repository also includes two scripts, *scan.py* and *report.py*, that respectively perform a full scan on a list of websites and produces a well-formatted text report for analysis. An example of these results can be seen in the *example_results* folder. 

## Usage
```python
import webscanner

# Obtain IPv4 and IPv6 addresses for a website
ipv4 = webscanner.get_ipv4('google.com')
ipv6 = webscanner.get_ipv6('google.com')

# Obtain geographic location of websites IPv4 addresses
geo_locations = webscanner.get_geo_locations(ipv4, 'GeoLite2-City.mmdb')

# Run a full scan for all available information
scan_results = webscanner.full_scan('google.com', geo_file='GeoLite2-City.mmdb')
```
