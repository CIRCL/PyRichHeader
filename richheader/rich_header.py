#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import struct

# I'm trying not to bury the magic number...
CHECKSUM_MASK = 0x536e6144 # DanS (actuall SnaD)
RICH_TEXT = 'Rich'
RICH_TEXT_LENGTH = len(RICH_TEXT)
PE_START = 0x3c
PE_FIELD_LENGTH = 4

##
# A convenient exception to raise if the Rich Header doesn't exist.
class RichHeaderNotFoundException(Exception):
    def __init__(self):
        Exception.__init__(self, "Rich footer does not appear to exist")

##
# Locate the body of the data that contains the rich header This will be
# (roughly) between 0x3c and the beginning of the PE header, but the entire
# thing up to the last checksum will be needed in order to verify the header.
def get_file_header(file_name):
    f = open(file_name,'rb')

    #start with 0x3c
    f.seek(PE_START)
    data = f.read(PE_FIELD_LENGTH)

    if data == '': #File is empty, bail
        raise RichHeaderNotFoundException()
    end = struct.unpack('<L',data)[0] # get the value at 0x3c

    f.seek(0)
    data = f.read( end ) # read until that value is reached
    f.close()

    return data

##
# This class assists in parsing the Rich Header from PE Files.
# The Rich Header is the section in the PE file following the dos stub but
# preceding the lfa_new header which is inserted by link.exe when building with
# the Microsoft Compilers.  The Rich Heder contains the following:
# <pre>
# marker, checksum, checksum, checksum,
# R_compid_i, R_occurrence_i,
# R_compid_i+1, R_occurrence_i+1, ...
# R_compid_N-1, R_occurrence_N-1, Rich, marker
#
# marker = checksum XOR 0x536e6144
# R_compid_i is the ith compid XORed with the checksum
# R_occurrence_i is the ith occurrence  XORed with the checksum
# Rich = the text string 'Rich'
# The checksum is the sum of all the PE Header values rotated by their
# offset and the sum of all compids rotated by their occurrence counts.
# </pre>
# @see _validate_checksum code for checksum calculation
class ParsedRichHeader:
    ##
    # Creates a ParsedRichHeader from the specified PE File.
    # @throws RichHeaderNotFoundException if the file does not contain a rich header
    # @param file_name The PE File to be parsed
    def __init__(self, file_name):
        ## The file that was parsed
        self.file_name = file_name
        self._parse( file_name )

    ##
    # Used internally to parse the PE File and extract Rich Header data.
    # Initializes self.compids and self.valid_checksum.
    # @param file_name The PE File to be parsed
    # @throws RichHeaderNotFoundException if the file does not contain a rich header
    def _parse(self,file_name):
        #make sure there is a header:
        data = get_file_header( file_name )

        compid_end_index = data.find(RICH_TEXT)
        if compid_end_index == -1:
            raise RichHeaderNotFoundException()

        rich_offset = compid_end_index + RICH_TEXT_LENGTH

        checksum_text = data[rich_offset:rich_offset+4]
        checksum_value = struct.unpack('<L', checksum_text)[0]
        #start marker denotes the beginning of the rich header
        start_marker = struct.pack('<LLLL',checksum_value ^ CHECKSUM_MASK, checksum_value, checksum_value, checksum_value )[0]

        rich_header_start = data.find(start_marker)
        if rich_header_start == -1:
            raise RichHeaderNotFoundException()

        compid_start_index = rich_header_start + 16 # move past the marker and 3 checksums

        compids = dict()
        for i in range(compid_start_index, compid_end_index, 8):
            compid = struct.unpack('<L',data[i:i+4])[0] ^ checksum_value
            count = struct.unpack('<L',data[i+4:i+8])[0] ^ checksum_value
            compids[compid]=count

        ## A dictionary of compids and their occurrence counts
        self.compids = compids
        ## A value for later reference to see if the checksum was valid
        self.valid_checksum = self._validate_checksum( data, rich_header_start, checksum_value )

    ##
    # Compute the checksum value and see if it matches the checksum stored in
    # the Rich Header.
    # The checksum is the sum of all the PE Header values rotated by their
    # offset and the sum of all compids rotated by their occurrence counts
    # @param data A blob of binary data that corresponds to the PE Header data
    # @param rich_header_start The offset to marker, checksum, checksum, checksum
    # @returns True if the checksum is valid, false otherwise
    def _validate_checksum(self, data, rich_header_start, checksum):

        #initialize the checksum offset at which the rich header is located
        cksum = rich_header_start

        #add the value from the pe header after rotating the value by its offset in the pe header
        for i in range(0,rich_header_start):
            if PE_START <= i <= PE_START+PE_FIELD_LENGTH-1:
                continue
            temp = ord(data[i])
            cksum+= ((temp << (i%32)) | (temp >> (32-(i%32))) & 0xff)
            cksum &=0xffffffff

        #add each compid to the checksum after rotating it by its occurrence count
        for k in self.compids.keys():
            cksum += (k << self.compids[k]%32 | k >> ( 32 - (self.compids[k]%32)))
            cksum &=0xffffffff

        ## A convenient place for storing the checksum that was computing during checksum validation
        self.checksum = cksum

        return cksum == checksum

if __name__ == "__main__":
    ph = ParsedRichHeader(sys.argv[1])
    for key in ph.compids.keys():
        print ('compid: %08x\tcount: %d' % (key, ph.compids[key]))
    if ph.valid_checksum:
        print ("Checksum valid")
    else:
        print("Checksum not valid!")
