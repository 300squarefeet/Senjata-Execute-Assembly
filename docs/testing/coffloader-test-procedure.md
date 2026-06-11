# COFFLoader Test Procedure — senjata-execute-assembly v0.5.0

Functional test using [TrustedSec/COFFLoader](https://github.com/trustedsec/COFFLoader)
on a Windows x64 machine with .NET Framework 4.x.

---

## Prerequisites

| Requirement | Notes |
|---|---|
| Windows 10/11 x64 | .NET Framework 4.x pre-installed |
| COFFLoader64.exe | Build from source or use prebuilt |
| `senjata-execute-assembly.x64.o` | From `dist/` after `cargo make build` |
| Python 3 | For argument packing script below |
| A test .NET 4.x assembly | See minimal payload below |

Build COFFLoader (from Linux/Windows):
```
git clone https://github.com/trustedsec/COFFLoader
cd COFFLoader
make        # Linux (produces COFFLoader)
# or open in VS on Windows → build COFFLoader64.exe
```

---

## Step 1 — Minimal Test Assembly

Save as `HelloStomp.cs` and compile on Windows:

```csharp
using System;
class HelloStomp {
    static void Main(string[] args) {
        Console.WriteLine("[stomp-test] Hello from CLR!");
        Console.WriteLine("[stomp-test] TargetFramework: " +
            System.Runtime.InteropServices.RuntimeEnvironment.GetSystemVersion());
        Console.WriteLine("[stomp-test] args: " + string.Join(" ", args));
    }
}
```

```cmd
rem Compile to .NET 4.x EXE (adjust csc.exe path as needed)
"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe" ^
    /target:exe /platform:x64 /out:HelloStomp.exe HelloStomp.cs
```

---

## Step 2 — Pack Arguments

Copy `pack_bof_args.py` (below) to the same folder as the BOF and run:

```
python3 pack_bof_args.py HelloStomp.exe --asm-args "arg1 arg2" --out args.bin
```

The script produces `args.bin` in the exact `bof_pack("ziiiizzzizb", ...)` format
that CS uses and COFFLoader/BeaconDataParse expects.

---

## Step 3 — Execute

```cmd
COFFLoader64.exe local senjata-execute-assembly.x64.o args.bin
```

Expected output (printed by BeaconOutput → COFFLoader stdout):
```
[senjata] senjata-execute-assembly v0.5.0  -  Created by DAP
[senjata] MITRE ATT&CK: ...
[stomp-test] Hello from CLR!
[stomp-test] TargetFramework: v4.0.30319
[stomp-test] args: arg1 arg2
[+] senjata-execute-assembly finished
```

### Second invocation (BofState recovery test)

Run the same command again immediately. Expected: CLR is NOT re-initialised
(no second `Start()` call — BofState recovered from named file mapping).
Same output should appear.

---

## Step 4 — Negative Tests

| Test | How | Expected |
|---|---|---|
| Assembly too large for all victims | Pass >10 MB assembly | `[-] payload image exceeds all victim candidates` |
| Wrong architecture (x86) | Compile HelloStomp as /platform:x86 | `[-] TargetFramework...` or PE parser error |
| CoreCLR assembly (.NET 6+) | Pass a .NET 6 EXE | `[-] coreclr-no-stomp: use sacrificial mode` |

---

## `pack_bof_args.py`

```python
#!/usr/bin/env python3
"""
Pack arguments for senjata-execute-assembly BOF.
Wire format: ziiiizzzizb  (matches args.rs read order)
  z  app_domain   (string)
  i  amsi         (1=enable bypass, 0=skip)
  i  etw          (1=enable bypass, 0=skip)
  i  mailslot     (always 0 for inline/coffloader)
  i  entry_point  (0=Main, 1=EntryPoint)
  z  slot_name    (empty)
  z  pipe_name    (arbitrary; COFFLoader doesn't pre-create the pipe — BOF does)
  z  asm_args     (space-separated args string passed to assembly)
  i  mode         (0=single-file)
  z  main_name    (empty in single-file mode)
  b  asm_bytes    (the .NET assembly PE bytes)

CS bof_pack encoding per argument:
  z -> [u16 type=3][u32 len (incl null)][str bytes][0x00]
  i -> [u16 type=2][u32 len=4][i32 value]
  b -> [u16 type=8][u32 len][bytes]

Blob is prefixed with u32 total_length.
"""
import argparse, struct, sys

def pack_z(s: str) -> bytes:
    b = s.encode('utf-8') + b'\\x00'
    return struct.pack('<HI', 3, len(b)) + b

def pack_i(v: int) -> bytes:
    return struct.pack('<HIi', 2, 4, v)

def pack_b(data: bytes) -> bytes:
    return struct.pack('<HI', 8, len(data)) + data

def main():
    ap = argparse.ArgumentParser(description='Pack BOF args for senjata-execute-assembly')
    ap.add_argument('assembly', help='Path to .NET assembly EXE/DLL')
    ap.add_argument('--app-domain', default='senjata', help='AppDomain name')
    ap.add_argument('--amsi', type=int, default=1, help='AMSI bypass (1/0)')
    ap.add_argument('--etw',  type=int, default=1, help='ETW  bypass (1/0)')
    ap.add_argument('--entry-point', type=int, default=0, help='0=Main 1=EntryPoint')
    ap.add_argument('--pipe-name', default='\\\\\\\\.\\\\pipe\\\\senjata_test', help='Named pipe')
    ap.add_argument('--asm-args', default='', help='Space-separated args to pass')
    ap.add_argument('--out', default='args.bin', help='Output file')
    args = ap.parse_args()

    with open(args.assembly, 'rb') as f:
        asm_bytes = f.read()

    parts  = pack_z(args.app_domain)
    parts += pack_i(args.amsi)
    parts += pack_i(args.etw)
    parts += pack_i(0)                     # mailslot=0
    parts += pack_i(args.entry_point)
    parts += pack_z('')                    # slot_name (empty)
    parts += pack_z(args.pipe_name)
    parts += pack_z(args.asm_args)
    parts += pack_i(0)                     # mode=single-file
    parts += pack_z('')                    # main_name (empty)
    parts += pack_b(asm_bytes)

    blob = struct.pack('<I', len(parts)) + parts
    with open(args.out, 'wb') as f:
        f.write(blob)
    print(f'[+] wrote {len(blob)} bytes to {args.out}')
    print(f'    assembly: {args.assembly} ({len(asm_bytes)} bytes)')

if __name__ == '__main__':
    main()
```

---

## Static Analysis (macOS / no Windows required)

These checks can be run on any machine and are already part of `cargo make build`:

| Check | Command | Result |
|---|---|---|
| COFF format | `objdump -f dist/*.o` | `pe-x86-64` |
| Section names | `objdump -h dist/*.o` | `.text .rdata .data .pdata .xdata .bss` only |
| Entry point | `nm dist/*.o \| grep ' T go'` | present |
| Undefined symbols | `nm dist/*.o \| grep ' U '` | BeaconAPI + KERNEL32$ only |
| compiler-rt stubs | `nm dist/*.o \| grep ' U .*__chkstk'` | none |
| OPSEC gate | `cargo make validate` | no IOCs, no forbidden imports |

All of the above pass on the current `feat/rust-port` HEAD.
