#!/usr/bin/env python
# Copyright (C) 2022 Subreption LLC. All rights reserved.
# This software is licensed under the Subreption Ukraine Defense License Version 1.0
# https://subreption.com/licensing/SUDL.txt
# Author: LH
#
# "And so, I found myself in possession of a large blob of data I could not understand.
#  Inside, the only clue I could find was a sequence of bytes. A sync word for Virtex 6.
#  There was a bitstream in that blob. If only we could understand what the bitstream
#  does..."
#
#  Here we are now. LH vs. VSKS, Chapter 2.
#
# This is a primitive parser for Virtex 6 bitstreams, that I have haphazardly put
# together reading Xilinx's PDF. It is not meant to be used with anything but the
# NOR/flash dump I was able to obtain in Chapter 1. It will work for any Virtex 6
# bitstream, including all VSKS bitstreams.
#
# Here's hoping to questions answered.
#
# If the device ID does not match the known values, check UG360 (Xilinx documentation)
# and find the device ID (32-bit word in hex) for the FPGA. Lift the heatsink and clean
# it to read the part number.
#

import time
import sys
import os
import struct
import ctypes

HDR_TYPE_BITSHIFT               = 29
TYPE1_WORDCOUNT_BITMASK         = 0x7ff
TYPE2_WORDCOUNT_BITMASK         = 0x7ffffff
OPCODE_BITSHIFT                 = 27
OPCODE_BITMASK                  = 0x3
REG_ADDR_BITSHIFT               = 13
REG_ADDR_BITMASK                = 0x3fff

OPCODE_NOOP                     = 0
OPCODE_REG_READ                 = 1
OPCODE_REG_WRITE                = 2
OPCODE_RESERVED                 = 3

TYPE1_PACKET_REGISTER_CRC       = 0
TYPE1_PACKET_REGISTER_FAR       = 1
TYPE1_PACKET_REGISTER_FDRI      = 2
TYPE1_PACKET_REGISTER_FDRO      = 3
TYPE1_PACKET_REGISTER_CMD       = 4
TYPE1_PACKET_REGISTER_CTL0      = 5
TYPE1_PACKET_REGISTER_MASK      = 6
TYPE1_PACKET_REGISTER_STAT      = 7
TYPE1_PACKET_REGISTER_LOUT      = 8
TYPE1_PACKET_REGISTER_COR0      = 9
TYPE1_PACKET_REGISTER_MFWR      = 10
TYPE1_PACKET_REGISTER_CBC       = 11
TYPE1_PACKET_REGISTER_IDCODE    = 12
TYPE1_PACKET_REGISTER_AXSS      = 13
TYPE1_PACKET_REGISTER_COR1      = 14
TYPE1_PACKET_REGISTER_CSOB      = 15
TYPE1_PACKET_REGISTER_WBSTAR    = 16
TYPE1_PACKET_REGISTER_TIMER     = 17
TYPE1_PACKET_REGISTER_BOOTSTS   = 18
TYPE1_PACKET_REGISTER_CTL1      = 19
TYPE1_PACKET_REGISTER_DWC       = 20

COMMAND_REGISTER_NULL           = 0
COMMAND_REGISTER_WCFG           = 1
COMMAND_REGISTER_START          = 5
COMMAND_REGISTER_RCRC           = 7
COMMAND_REGISTER_DESYNC         = 13

# Order must exactly match above
# UM360 p.112
CONFIGURATION_REGISTERS_STR = [
    "CRC",      # 0  R/W
    "FAR",      # 1  R/W
    "FDRI",     # 2  W
    "FDRO",     # 3  R
    "CMD",      # 4  R/W
    "CTL0",     # 5  R/W
    "MASK",     # 6  R/W
    "STAT",     # 7  R
    "LOUT",     # 8  W
    "COR0",     # 9  R/W
    "MFWR",     # 10 W
    "CBC",      # 11 W
    "IDCODE",   # 12 R/W
    "AXSS",     # 13 R/W
    "COR1",     # 14 R/W
    "CSOB",     # 15 W
    "WBSTAR",   # 16 R/W
    "TIMER",    # 17 R/W
    "?",        # 18
    "?",        # 19
    "?",        # 20
    "?",        # 21
    "BOOTSTS",  # 22 R
    "?",        # 23
    "CTL1",     # 24 R/W
    "?",        # 25
    "DWC"       # 26 R/W
]

# Order must exactly match above
COMMAND_REGISTER_STR = [
    "NULL",
    "WCFG",
    "MFW",
    "DGHIGH",
    "RCFG",
    "START",
    "RCAP",
    "RCRC",
    "AGHIGH",
    "SWITCH",
    "GRESTORE",
    "SHUTDOWN",
    "GCAPTURE",
    "DESYNC",
    "RESERVED",
    "IPROG",
    "CRCC",
    "LTIMER"
]

def get_bit(value, bit_index):
    return value & (1 << bit_index)

def cmdreg2str(reg):
    try:
        return COMMAND_REGISTER_STR[reg]
    except:
        return "?"

def configreg2str(reg):
    try:
        return CONFIGURATION_REGISTERS_STR[reg]
    except:
        return "?"

def opcode2str(opcode):
    if opcode == OPCODE_REG_WRITE:
        return "REG_WRITE"
    elif opcode == OPCODE_NOOP:
        return "NOOP"
    elif opcode == OPCODE_REG_READ:
        return "REG_READ"
    elif opcode == OPCODE_RESERVED:
        return "RESERVED"
    else:
        return "UNKNOWN %d" % (opcode)

def hexdump(desc, data):
    sys.stdout.write("%-25s [\n" % desc)

    printed = 0
    for c in data:
        sys.stdout.write("%02x" % (c))
        if printed > 7:
            printed = 0
            sys.stdout.write("\n")
        else:
            printed += 1

    sys.stdout.write("\n%-25s ]\n" % desc) 

class JazzyVirtexBitstreamParser(object):
    LOG_ERROR    = 1
    LOG_INFO     = 4
    LOG_VERBOSE  = 5
    LOG_DEBUG    = 6
    LOG_DEBUG2   = 7
    KNOWN_SYNCWORD = 0xaa995566
    XC6VLX130T_ID  = 0x0424a093
    KNOWN_VSKS_FPGA_DEVICES = [
        XC6VLX130T_ID
    ]

    def __init__(self, path, loglevel=LOG_DEBUG):
        self.f = open(path, 'rb')
        self.pos = 0
        self.loglevel = loglevel
        self.bytecount = os.path.getsize(path)
        self.stream_size = os.path.getsize(path)
        self.wordcount = 0
        self.curr_fdri_write_len = 0
        self.curr_crc_check = 0
        self.fdri_in_progress = False
        self.wordbytesize = 4
        self.words_per_frame = 81
        self.fdri_words = []

    def handle_type1(self, hdr, opcode, regaddr):
        wcount = (hdr & TYPE1_WORDCOUNT_BITMASK)
        if wcount > self.wordcount:
            raise Exception("packet contains out of bounds word count %d" % (wcount))

        if wcount > 0:
            # read the data
            pktwords = self.read_nwords(wcount)

            if regaddr == TYPE1_PACKET_REGISTER_IDCODE:
                device_id = pktwords[0]

                if device_id in self.KNOWN_VSKS_FPGA_DEVICES:
                    match_str = "MATCH!"
                else:
                    match_str = "MISMATCH! Decoding might be bogus!"

                self.log("Device ID: %08x (VSKS: %s): %s" % (device_id,
                    [' '.join('%08x' % (did) for did in self.KNOWN_VSKS_FPGA_DEVICES)],
                    match_str), self.LOG_DEBUG)

            elif regaddr == TYPE1_PACKET_REGISTER_CTL0:
                ctl0_word = pktwords[0]

                # Let's check the control register 0 settings
                ctl0_bit_dec = get_bit(ctl0_word, 6)
                if ctl0_bit_dec == 0:
                    self.log("CTL0 DEC (AES Decryptor) is DISABLED! (ctl0[6]=%d)" % (ctl0_bit_dec),
                        self.LOG_INFO)

                ctl0_bit_persist = get_bit(ctl0_word, 3)
                if ctl0_bit_persist != 0:
                    self.log("CTL0 PERSIST: M2:M0 cfg persistence enabled (ctl0[3]=%d)" % (ctl0_bit_persist),
                        self.LOG_INFO)

                sb = (ctl0_word >> 4) & 3
                efuse = (ctl0_word >> 2) & 1
                crc = (ctl0_word >> 1) & 1

                self.log("CTL0: security bits %d, dec %d, persist %d, crc extstat %d, efuse %d" % (sb,
                    ctl0_bit_dec, ctl0_bit_persist, crc, efuse), self.LOG_INFO)

            elif regaddr == TYPE1_PACKET_REGISTER_CMD:
                cmd = pktwords[0]
                self.log("RAW:%d:%08x CMD: execute %s" % (self.f.tell(), hdr,
                    cmdreg2str(cmd)), self.LOG_INFO)

            elif regaddr == TYPE1_PACKET_REGISTER_FDRI:
                self.log("RAW:%d:%08x FDRI: Configuration data is about to be loaded!" % (self.f.tell(),
                        hdr), self.LOG_INFO)

            elif regaddr == TYPE1_PACKET_REGISTER_COR0:
                pass

            elif regaddr == TYPE1_PACKET_REGISTER_FAR:
                # Configuration Memory Read Procedure (SelectMAP)
                # UG360 p.134
                sfaddr = pktwords[0]
                self.log("FAR: Starting Frame Address is %08x" % (sfaddr), self.LOG_INFO)

            elif regaddr == TYPE1_PACKET_REGISTER_TIMER:
                timer = pktwords[0]
                if timer == 0:
                    self.log("RAW:%d:%08x TIMER: Watchdog timer DISABLED." % (self.f.tell(),
                        hdr), self.LOG_INFO)
                else:
                    self.log("RAW:%d:%08x TIMER: Watchdog timer ENABLED." % (self.f.tell(),
                        hdr), self.LOG_INFO)

            return (True, pktwords)
        else:
            return (True, [])

    def handle_type2(self, type2_word, prev_pkt):
        hdr_type = (type2_word >> HDR_TYPE_BITSHIFT)
        opcode = ((type2_word >> OPCODE_BITSHIFT) & OPCODE_BITMASK)
        wcount = (type2_word & TYPE2_WORDCOUNT_BITMASK)
        regaddr = prev_pkt['regaddr']

        if wcount > 0:
            if wcount > self.wordcount:
                raise Exception("packet contains out of bounds word count %d" % (wcount))

            # read the data
            pktwords = self.read_nwords(wcount)

            if regaddr == TYPE1_PACKET_REGISTER_FDRI:
                word_idx = 0
                frame_words = self.words_per_frame
                frame_word = 0
                frame_num = 0
                for word in pktwords:
                    msg = "%06d: (frame %d:%d) word=%08x" % (word_idx, frame_num, frame_word, word)
                    self.log(msg, self.LOG_DEBUG2)

                    if frame_words - 1 == 0:
                        frame_num += 1
                        frame_words = self.words_per_frame
                        frame_word = 0
                    else:
                        frame_words -= 1
                        frame_word += 1

                    word_idx += 1

                self.fdri_words = pktwords

            return (True, pktwords)
        else:
            return (True, [])

    def log_packet(self, word, pkt):
        msg = 'RAW:%d:%08x TYPE:%d OPCODE(%.12s) ' % (self.f.tell(), word,
            pkt['type'], opcode2str(pkt['opcode']))

        # Add the regaddr if present (ex. NOOPs dont have it)
        if pkt['regaddr'] is not None:
            msg += ' ADDR:%.6s(%d) ' % (configreg2str(pkt['regaddr']), pkt['regaddr'])

        # If packet had words, include some information
        if pkt['wordcount'] > 0:
            msg += 'WORDS:%d' % (pkt['wordcount'])

        self.log(msg, self.LOG_DEBUG)

        # Print the words in hex
        if pkt['wordcount'] > 0:
            printed = 0
            for pktword in pkt['words']:
                if printed > 16:
                    self.log("   %08x.... (%d words omitted)" % (pktword,
                        len(pkt['words']) - printed), self.LOG_DEBUG)
                    break

                self.log("   %08x" % (pktword), self.LOG_DEBUG)
                printed += 1

    def parse(self):
        self.skip_dummy_words()

        self.log("Reading bus width pattern", self.LOG_DEBUG)
        self.read_bus_width_pattern()
        self.skip_dummy_words()

        self.log("Reading sync word", self.LOG_DEBUG)
        if self.read_syncword():
            self.log("Sync word OK: %08x" % (self.KNOWN_SYNCWORD), self.LOG_DEBUG)

        self.bytecount -= self.f.tell()
        self.wordcount = self.bytecount / self.wordbytesize

        self.packets = []

        prev_pkt = None

        while self.wordcount > 0:
            # must verify boundaries against wordcount
            word = self.read_word()

            # check and skip dummyword
            # dummywords after syncword are 0x00000000
            # before syncword they are 0xffffffff
            if word == 0x00000000 or word == 0xffffffff:
                continue

            # Get the packet type
            pkt_type = (word >> HDR_TYPE_BITSHIFT)
            opcode = ((word >> OPCODE_BITSHIFT) & OPCODE_BITMASK)

            if pkt_type == 1:
                regaddr =  ((word >> REG_ADDR_BITSHIFT) & REG_ADDR_BITMASK)
            elif prev_pkt != None and pkt_type == 2:
                if prev_pkt['type'] != 1:
                    self.log('(!!!) RAW:%d:%08x TYPE:%d OPCODE(%.12s) ' % (self.f.tell(),
                        word, pkt_type, opcode2str(opcode)),
                        self.LOG_ERROR)
                    raise Exception("type 2 not following type 1 packet!")

                regaddr = prev_pkt['regaddr']
            else:
                regaddr = None

            if pkt_type == 0:
                self.log('RAW:%d:%08x TYPE:%d OPCODE(%.12s) Packet type is zero??' % (self.f.tell(),
                        word, pkt_type, opcode2str(opcode)),
                        self.LOG_DEBUG)
                continue

            pktwords = []
            valid_pkt = False

            # Type 1 or Type 2 packet
            if pkt_type == 1 or pkt_type == 2:
                if opcode == OPCODE_REG_WRITE:
                    if pkt_type == 2:
                        # type 2 will read its own header and use previous regaddr
                        valid_pkt, pktwords = self.handle_type2(word, prev_pkt)
                    else:
                        # type 1 does not read a new header
                        valid_pkt, pktwords = self.handle_type1(word, opcode, regaddr)

            pktwordcnt = len(pktwords)

            pkt = {
                'orig_word' : word,
                'type'      : pkt_type,
                'opcode'    : opcode,
                'regaddr'   : regaddr,
                'wordcount' : pktwordcnt,
                'words'     : pktwords
            }

            self.packets.append(pkt)
            prev_pkt = pkt

            self.log_packet(word, pkt)

    def skip_dummy_words(self):
        skipped = 1
        word = self.read_word()
        while word == 0xffffffff:
            word = self.read_word()
            skipped += 1

        # move back one byte
        self.f.seek(-4, os.SEEK_CUR)
        skipped -= 1
        self.log("Skipped %d dummywords" % (skipped), self.LOG_DEBUG)

    """
    """
    def read_syncword(self):
        syncword = self.read_word()
        return syncword == self.KNOWN_SYNCWORD

    """
    Detects bus width pattern, skipping the preamble

    """
    def read_bus_width_pattern(self):
        # attempt to read the bus width pattern
        self.read_raw(-1, b'\x00\x00\x00\xBB') # bus width pattern (x8)
        self.read_raw(-1, b'\x11\x22\x00\x44') # bus width pattern (x8)

    def read_raw(self, length, expected=None):
        if expected != None:
            length = len(expected)

        data = self.f.read(length)
        # XXX raise exception if read length != len
        if expected != None:
            if data != expected:
                raise Exception("data does not match %s!=%s" % (data, expected))

        self.pos = self.f.tell()
        return data

    def read_word(self):
        word = self.read_raw(4)
        if len(word) != 4:
            raise Exception("reached end of file? (wordcount=%d)" % (self.wordcount))

        self.wordcount -= 1
        return struct.unpack('>I', word)[0]

    def read_nwords(self, count):
        words = []

        if count > self.wordcount:
            raise Exception("will read %d words out of bounds" % (self.count - self.wordcount))

        while len(words) < count:
            word = self.read_word()
            words.append(word)

        return words

    def close(self):
        self.f.close()

    def loglevelname(self, level):
        if (level == self.LOG_ERROR):
            return "  Error"
        if (level == self.LOG_INFO):
            return "   Info"
        if (level == self.LOG_VERBOSE):
            return "Verbose"
        if (level == self.LOG_DEBUG):
            return "  Debug"

    def log(self, msg, level=3):
        logtimefmt   = "%Y-%m-%d %H:%M:%S"
        if self.loglevel >= level:
            timestamp = time.time()
            logstring = "["+time.strftime(logtimefmt)+"] ["+self.loglevelname(level)+"] "+msg
            print(logstring)

def main(path):
    vsks_parser = JazzyVirtexBitstreamParser(path)
    vsks_parser.parse()

    with open('%s.frames_out' % path, 'wb') as outfile:
        for word in vsks_parser.fdri_words:
            packed = struct.pack('>I', word)
            outfile.write(packed)

if __name__ == '__main__':
    main(sys.argv[1])
