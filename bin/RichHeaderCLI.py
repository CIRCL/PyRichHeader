#!/usr/bin/env python
# -*- coding: utf-8 -*-

from richheader import RichHeader
import argparse

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Parse the Rich Header of a file.')
    parser.add_argument("-f", "--file", type=str, required=True, help="Path to the file to parse.")
    args = parser.parse_args()

    print(args.file)
    try:
        ph = RichHeader(args.file)
    except Exception as e:
        print('\t' + str(e))
        exit()
    compids, valid = ph.get_results()
    if not valid:
        print('\tChecksum not valid!')
    for key, value in compids:
        print('\tcompid: %08x\tcount: %d' % (key, value))
