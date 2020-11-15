# Name: Spencer Fitch
# netid: slf0232
#
# Comp_Sci 340: Intro to Networking
# Project 4
#
# scan.py

import sys
import time

# Check for command line argument
if len(sys.argv) != 3:
    sys.stderr.write("scan.py requires 2 arguments: input_file.txt and output_file.json \n")
    sys.exit(10)

input_file = open(sys.argv[1], "r")
output_file = open(sys.argv[2], "w")

websites = []

for line in input_file:
    websites.append(line.split('\n')[0])

print(websites)

input_file.close()
output_file.close()