using System;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.Loader;

namespace SenjataLoader;

public static class Loader
{
    [UnmanagedCallersOnly]
    public static int Run(
        IntPtr asmBytesPtr, int asmBytesLen,
        IntPtr argsUtf16Ptr, int argsCharCount,
        int entryPointFlag)
    {
        try
        {
            var bytes = new byte[asmBytesLen];
            Marshal.Copy(asmBytesPtr, bytes, 0, asmBytesLen);

            var asm = AssemblyLoadContext.Default
                .LoadFromStream(new MemoryStream(bytes));

            var entry = asm.EntryPoint
                ?? throw new InvalidOperationException("assembly has no entry point");

            string[] argv = (entryPointFlag != 0 && argsUtf16Ptr != IntPtr.Zero)
                ? SplitArgs(Marshal.PtrToStringUni(argsUtf16Ptr, argsCharCount))
                : Array.Empty<string>();

            object[] invokeArgs = entry.GetParameters().Length == 0
                ? null
                : new object[] { argv };

            var rc = entry.Invoke(null, invokeArgs);
            return rc is int i ? i : 0;
        }
        catch (Exception ex)
        {
            try { Console.Error.WriteLine($"[SenjataLoader] {ex.GetType().Name}: {ex.Message}"); }
            catch { /* stdout/stderr might be closed; swallow */ }
            return -1;
        }
    }

    private static string[] SplitArgs(string cmdLine)
    {
        if (string.IsNullOrWhiteSpace(cmdLine)) return Array.Empty<string>();
        return cmdLine.Split((char[])null, StringSplitOptions.RemoveEmptyEntries);
    }
}
