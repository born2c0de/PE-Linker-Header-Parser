#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Compatible with Python 2.7.6+ and 3.4.x+
# Works on Windows, Linux and OSX
# Python3 is the primary target. As dict::items() and range() is used, code might require more memory and run slower on Python2.
# I decided to write this class as none of the existing implementations worked for me :(.
# Resources used to write this script:
#   https://gist.github.com/skochinsky/07c8e95e33d9429d81a75622b5d24c8b (ROL code borrowed from here)
#   http://rcecafe.net/?p=27
#   http://ntcore.com/Files/richsign.htm
#   http://bytepointer.com/articles/the_microsoft_rich_header.htm
import struct
from collections import OrderedDict

__author__ = 'Sanchit Karve <write2sanchit@gmail.com>'


class InvalidHeaderError(Exception):
    '''Custom exception for cases where Rich or DanS header not found'''
    def __init__(self, err_msg):
        Exception.__init__(self, err_msg)


class PERichHeaderParser(object):
    '''
        Class to parse Rich Headers in PE Files.
        To use, pass filename when constructing object.
        Access the following elements once parsed:
            checksum_matches: bool
            entries         : OrderedDict of dicts
            filename        : Filename being parsed

        Raises Exception InvalidHeaderError if headers are not found.
    '''
    def __init__(self, filename):
        self.filename = filename
        self.checksum_matches = False
        self.entries = OrderedDict()
        self._parse()

    def _read_dword(self, file_obj):
        '''Reads four bytes from provided file_obj in little-endian format'''
        return struct.unpack('<I', file_obj.read(4))[0]

    def _parse(self):
        '''Parse the LinkerInfo header and verify checksums'''
        # Look for 'Rich' between start of file and start of PE header
        file_obj = open(self.filename, 'rb')
        file_obj.seek(0x3C)
        # Even though PE spec allows lfa_new to be a DWORD, only valid WORD values are accepted by the PE loader
        lfa_new = self._read_dword(file_obj) & 0xFFFF
        file_obj.seek(0)
        data = file_obj.read(lfa_new)
        rich_location = data.find(b'Rich')
        if rich_location == -1:
            raise InvalidHeaderError('Rich header does not exist')
        # DWORD next to 'Rich' magic bytes is the checksum in header
        file_obj.seek(rich_location + 0x4)
        header_checksum = self._read_dword(file_obj)
        # Assume Linkerinfo header starts at 0x80
        start_of_header = 0x80
        file_obj.seek(start_of_header)
        dans_header = self._read_dword(file_obj) ^ header_checksum
        # If 'DanS' magic bytes not found at 0x80, look for it between MZ and PE header
        if dans_header != 0x536E6144:
            # Brute force from 0x40 until PE header and look for 'DanS'
            start_of_header = 0x0
            file_obj.seek(0x40)
            search_range = (lfa_new - 0x40)
            for i in range(search_range // 0x4):
                dans_header = self._read_dword(file_obj) ^ header_checksum
                if dans_header == 0x536E6144:
                    start_of_header = 0x40 + (i * 4)
                    break
        if not start_of_header:
            raise InvalidHeaderError('Could not find start of Rich header')
        # Calculate checksum as the header is parsed
        checksum = start_of_header
        data = data[:start_of_header]
        for i, item in enumerate(data):
            # Do not include lfa_new field in checksum value
            if 0x3c <= i < 0x40:
                continue
            try:
                # ROL for Python 3
                checksum += ((item << (i % 32)) | (item >> (32 - (i % 32))) & 0xff)
            except TypeError:
                # ROL for Python 2
                item = ord(item)
                checksum += ((item << (i % 32)) | (item >> (32 - (i % 32))) & 0xff)
            checksum &= 0xFFFFFFFF
        # Let's finally start reading the data inside the linker header
        file_obj.seek(start_of_header)
        # 0x10 used to skip DanS magic DWORD and the 3 DWORD NULLs after it
        # 0x8 used as two DWORD elements are read for each element
        total_elements = (rich_location - start_of_header - 0x10) // 0x8
        # Skip the next 0x10 bytes from the start of the header as they do not contain relevant data
        file_obj.seek(start_of_header + 0x10)
        for i in range(total_elements):
            current_dword = self._read_dword(file_obj) ^ header_checksum
            c_id = current_dword >> 16
            build_version = current_dword & 0xFFFF
            used_count = self._read_dword(file_obj) ^ header_checksum
            # ROL again
            checksum += (current_dword << used_count % 32 | current_dword >> ( 32 - (used_count % 32)))
            checksum &= 0xFFFFFFFF
            # Add information to entries OrderedDict
            self.entries[c_id] = {'build_version': build_version, 'used_count': used_count}
        self.checksum_matches = True if checksum == header_checksum else False
        file_obj.close()

    def __str__(self):
        '''Return parsed information as a string'''
        ret = []
        ret.append('File: {f}'.format(f=self.filename))
        ret.append('ID\t\tBuildVersion\tUsed')
        for k, v in self.entries.items():
            ret.append('{i:3}\t\t{v:5}\t\t{c:3}'.format(i=k, v=v['build_version'], c=v['used_count']))
        ret.append('Checksum Match: {cm}'.format(cm=self.checksum_matches))
        return '\n'.join(ret)

    def __eq__(self, other):
        '''Returns True if all elements inside parsed header match'''
        if not isinstance(other, PERichHeaderParser):
            return False
        if len(self.entries) != len(other.entries):
            return False
        for k, v in self.entries.items():
            if k not in other.entries:
                return False
            if v != other.entries[k]:
                return False
        return self.checksum_matches == other.checksum_matches


def main(filename1, filename2):
    p = PERichHeaderParser(filename1)
    print(p)
    q = PERichHeaderParser(filename2)
    print(q)
    if p == q:
        print('Both files have identical linker headers')
    else:
        print('Both files have different linker headers')

if __name__ == '__main__':
    import sys
    try:
        main(sys.argv[1], sys.argv[2])
    except IndexError:
        print('Usage: {p} PEfilename1 PEfilename2'.format(p=sys.argv[0]))
