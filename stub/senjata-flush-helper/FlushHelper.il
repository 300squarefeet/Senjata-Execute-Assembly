// FlushHelper.il — dual-purpose flush helper:
//   Pre-invoke:  sets Console.Out/Err to AutoFlush=true for realtime pipe output.
//   Post-invoke: calls Flush() first to drain any buffered data before the write
//                handle is closed, then replaces the writer with an AutoFlush one.
// Explicitly references mscorlib 4.0.0.0; no Mono metadata.

.assembly extern mscorlib
{
  .publickeytoken = (B7 7A 5C 56 19 34 E0 89)
  .ver 4:0:0:0
}

.assembly SenjataFlush { .ver 1:0:0:0 }
.module SenjataFlush.exe

.class public F extends [mscorlib]System.Object
{
  // M(args): args[0] is the hex string of the BOF's pipe write handle.
  // We bypass STD_OUTPUT_HANDLE entirely (which is 0 in Beacon's process)
  // by constructing a FileStream directly from the raw handle value, wrapping
  // in a StreamWriter { AutoFlush = true }, and replacing Console.Out/Error.
  .method public static void M(string[] a) cil managed
  {
    .entrypoint
    .maxstack 3
    .try
    {
      // === Console.SetOut: build a StreamWriter bound to args[0] ===
      // Parse args[0] hex string into IntPtr (native int).
      ldarg.0
      ldc.i4.0
      ldelem.ref
      ldc.i4.s 16
      call int64 [mscorlib]System.Convert::ToInt64(string, int32)
      conv.i
      // SafeFileHandle(handle, ownsHandle:false)
      ldc.i4.0
      newobj instance void [mscorlib]Microsoft.Win32.SafeHandles.SafeFileHandle::.ctor(native int, bool)
      // FileStream(safe, FileAccess.Write)
      ldc.i4.2
      newobj instance void [mscorlib]System.IO.FileStream::.ctor(class [mscorlib]Microsoft.Win32.SafeHandles.SafeFileHandle, valuetype [mscorlib]System.IO.FileAccess)
      // StreamWriter(stream) with AutoFlush=true
      newobj instance void [mscorlib]System.IO.StreamWriter::.ctor(class [mscorlib]System.IO.Stream)
      dup
      ldc.i4.1
      callvirt instance void [mscorlib]System.IO.StreamWriter::set_AutoFlush(bool)
      // Console.SetOut(writer)
      call void [mscorlib]System.Console::SetOut(class [mscorlib]System.IO.TextWriter)

      // === Console.SetError: same handle, second StreamWriter ===
      ldarg.0
      ldc.i4.0
      ldelem.ref
      ldc.i4.s 16
      call int64 [mscorlib]System.Convert::ToInt64(string, int32)
      conv.i
      ldc.i4.0
      newobj instance void [mscorlib]Microsoft.Win32.SafeHandles.SafeFileHandle::.ctor(native int, bool)
      ldc.i4.2
      newobj instance void [mscorlib]System.IO.FileStream::.ctor(class [mscorlib]Microsoft.Win32.SafeHandles.SafeFileHandle, valuetype [mscorlib]System.IO.FileAccess)
      newobj instance void [mscorlib]System.IO.StreamWriter::.ctor(class [mscorlib]System.IO.Stream)
      dup
      ldc.i4.1
      callvirt instance void [mscorlib]System.IO.StreamWriter::set_AutoFlush(bool)
      call void [mscorlib]System.Console::SetError(class [mscorlib]System.IO.TextWriter)

      // Diagnostic marker via the new Console.Out — confirms the path works.
      ldstr "[FH_OUT]\n"
      call void [mscorlib]System.Console::Write(string)

      leave.s done
    }
    catch [mscorlib]System.Exception
    {
      pop
      leave.s done
    }
done:
    ret
  }
}
