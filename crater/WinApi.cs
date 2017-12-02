using System;
using System.Runtime.InteropServices;
using System.IO;

namespace WinAPI
{
    static class Kernel32
    {
        public static Int32 PROCESS_ALL_ACCESS = 0x1FFFFF;
        public static Int32 MEM_COMMIT = 0x00001000;

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr VirtualAllocEx(SafeHandle handle, IntPtr lpAddress, IntPtr dwSize, Int32 flAllocationType, Int32 flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(SafeHandle hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, IntPtr dwSize, ref IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(SafeHandle hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, IntPtr nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateRemoteThread(SafeHandle hProcess, IntPtr lpThreadAttributes, IntPtr dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, Int32 dwCreationFlags, out Int32 lpThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr LoadLibraryW(string lpFileName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern SafeHandle LoadLibrary(string lpFileName);

        [DllImport("kernel32.dll")]
        public static extern int GetCurrentProcessId();

        [DllImport("kernel32.dll")]
        public static extern SafeHandle GetModuleHandleW([MarshalAs(UnmanagedType.LPWStr)] string lpProcName);

        [DllImport("kernel32.dll")]
        public static extern IntPtr GetProcAddress(SafeHandle hModule, [MarshalAs(UnmanagedType.LPStr)] string lpProcName);

        [DllImport("kernel32.dll")]
        public static extern SafeHandle OpenProcess(Int32 dwDesiredAccess, Boolean bInheritHandle, Int32 dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateFileW(
             [MarshalAs(UnmanagedType.LPWStr)] string filename,
             [MarshalAs(UnmanagedType.U4)] UInt32 access,
             [MarshalAs(UnmanagedType.U4)] FileShare share,
             IntPtr securityAttributes,
             [MarshalAs(UnmanagedType.U4)] FileMode creationDisposition,
             [MarshalAs(UnmanagedType.U4)] FileAttributes flagsAndAttributes,
             IntPtr templateFile);
    }

}
