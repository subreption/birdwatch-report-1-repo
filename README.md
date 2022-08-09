# Ghost in the Orlan: demystifying a military drone platform

These are files related to our "Ghost in the Orlan: demystifying a military drone platform" report.
They include the FPGA NOR remapping exploit, bitstream parser and other "goodies".

The original report is also mirrored for convenience.

## Mirroring this repository

Please mirror or fork this repository freely!

## FPGA exploit and bitstream parser

### Getting started

- [Virtex 6 documentation and other references](xilinx-docs) (Fair use, Copyright belongs to Xilinx, Inc.)
- [Screenshots of interesting documentation tidbits](images)
- [Dumped bitstream (LZ4 compressed)](bitstream/vsks_nor_dump.bin.lz4)
- [Log output from my purpose-built bitstream parser](bitstream/vsks_nor_dump.dectxt)
- [Parser for Virtex 6 bitstream](src/bitstream_parser.py)
- [Exploit against the FPGA and its Linux kernel driver](src/BLABLABLA-LH_vs_fpga_nor.c)

## Authors and acknowledgment

The code in this repository was written by Larry H of Subreption LLC.

## License

This repository shall not be used or redistributed to third-parties with commercial intent or commercial use without prior written agreement from Subreption LLC or the author.

To all practical effects, the code and resources in this directory are dual-licensed:

 - Under a propietary license for business/commercial/government organizations forbidding all distribution, derivative work, etc.
 - Under the Attribution-NonCommercial-ShareAlike 4.0 International (https://creativecommons.org/licenses/by-nc-sa/4.0/) license for personal, academic and nonprofit use.

