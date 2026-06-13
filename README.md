# Senjata-Execute-Assembly

A patchless, OPSEC-hardened `execute-assembly` implementation for Cobalt Strike, written
in Rust. Ships as two complementary artefacts that share a single CLR-hosting core, so
the same evasion posture covers both inline and sacrificial execution paths.

Tested against current-generation .NET tooling: Rubeus, Seatbelt, SharpUp, Certify,
SharpDPAPI, SharpHound, Snaffler, winPEAS, and the broader Ghostpack family across
.NET Framework 2.x / 3.x / 4.x and .NET 6 / 7 / 8.

---

## Why another execute-assembly?

The stock Cobalt Strike `execute-assembly` and most public ports leak signal at three
layers:

1. **AMSI / ETW / AllocConsole** are patched with `0xC3` / `0x00` bytes at well-known
   offsets. EDRs flag both the patch event and the resulting unbacked .text in
   user-space.
2. **`Environment.Exit()`** inside the managed assembly walks all the way down to
   `RtlExitUserProcess`, taking Beacon with it.
3. **Imports / runtime calls** expose plaintext strings like `AmsiScanBuffer`,
   `EtwEventWrite`, `GetProcAddress`, `LoadLibrary` in `.rdata` and the BOF's IAT.

Senjata-Execute-Assembly addresses all three at the technique level:

- **Hardware breakpoints (DR0–DR3) + VEH dispatch** replace memory patches. AMSI/ETW
  return immediately; `RtlExitUserProcess` is redirected back into our cleanup point.
- **PEB-walking + DJB2 hashing** replaces every API resolution. No sensitive name
  ever appears in `.rdata` or the import table.
- **Indirect syscalls** are used for the two NT APIs we need (`NtGet/SetContextThread`
  for HWBP install and `NtProtectVirtualMemory` for the inline-mode CLR stomp). The
  `syscall` instruction stays inside ntdll.

---

## Highlights

- **Patchless AMSI + ETW + AllocConsole + `Environment.Exit` bypass** via hardware
  breakpoints — no memory patching at all
- **Two artefacts, one CLR core** — `senjata-execute-assembly.x64.o` (BOF, inline mode)
  and `senjata-runner.x64.dll` (post-ex DLL, sacrificial mode) share the same
  `clr-orchestrator`
- **Live output streaming** during multi-minute / multi-hour sacrificial runs — reader
  thread pumps pipe data to `BeaconOutput` on each check-in
- **NLog auto-routing** for tools like Snaffler and SharpHound that bypass
  `Console.Out` — runtime reflection redirects their loggers without per-tool source
  patches
- **Dual runtime support** — .NET Framework 2.x / 3.x / 4.x via the COM hosting path
  (ICLRMetaHost → ICorRuntimeHost → AppDomain.Load_2) and .NET 6 / 7 / 8 via direct
  CoreCLR hosting (`coreclr_initialize` + `coreclr_create_delegate`)
- **Explicit rejection** of mixed-mode (C++/CLI) and self-contained .NET 5+ single-file
  deployments — no silent failure
- **No plaintext API names** anywhere in either artefact — every module/export
  resolved via PEB walk + DJB2 hash compared against compile-time constants
- **Indirect syscalls** for `NtGet/SetContextThread` (HWBP install) and
  `NtProtectVirtualMemory` (CLR module stomp)
- **OPSEC validation gate** runs at build time — any plaintext API name or forbidden
  import that slips through fails CI

---

## Build

Toolchain pinned to nightly-2025-01-25 via `rust-toolchain.toml`. Cross-compiled from
Linux/macOS to `x86_64-pc-windows-gnu` with `-Z build-std=core,alloc` and
`-Z build-std-features=compiler-builtins-mem` (Beacon's loader does not provide
`memcpy`/`memset`/`memcmp`).

```bash
cargo make build
# outputs:
#   dist/senjata-execute-assembly.x64.o   (BOF — inline mode)
#   dist/senjata-runner.x64.dll           (post-ex DLL — sacrificial mode, default)
#   dist/senjata-execute-assembly.cna     (Aggressor dispatcher)
```

The build pipeline runs in order: cargo build (release) → `boflink` → section merge
(`x86_64-w64-mingw32-ld -r`) → OPSEC validation (`cargo make validate`) → copy `.cna`
to `dist/`. The OPSEC gate scans the linked artefacts for plaintext API/module names,
forbidden imports (`GetProcAddress`, `LoadLibrary*`), plaintext managed PE signatures
in `.rdata`, and compiler-rt undefined references. Any violation fails the build.

Reproducible build via Docker:

```bash
docker build -t senjata-build .
docker run --rm -v $PWD/dist:/work/dist senjata-build
```

---

## Operator usage

### Default: sacrificial process (universal compatibility)

```text
beacon> senjata-execute-assembly --dotnetassembly C:\corpus\Tool.exe \
        --assemblyargs <args>
```

The assembly runs in a freshly-spawned `dllhost.exe` (or whatever `spawnto_x64` is set
to). Output streams back to the operator on each Beacon check-in. Beacon stays
interactive for the duration. Assemblies that call `Environment.Exit()`, hang on
threads, or leave native handles open cannot harm Beacon because the runtime lives
in a separate process.

### Opt-in: inline mode for trusted tooling

```text
beacon> senjata-execute-assembly --inline --dotnetassembly C:\corpus\Rubeus.exe \
        --assemblyargs klist
```

Inline mode hosts the CLR inside Beacon's process, then loads the assembly via CLR
module stomping (see below). Smaller OPSEC footprint — no process spawn, no IPC, no
cross-process injection — but Beacon is blocked for the duration. Use only for tools
you trust to exit cleanly: Rubeus, SharpUp, Seatbelt, Certify, SharpDPAPI, and
similar quick utilities.

### Arguments

| Flag | Description |
|---|---|
| `--dotnetassembly <path>` | Path to the .NET assembly to execute (single-file mode) |
| `--dotnetassemblydir <dir>` | Directory of `.exe` + `.dll` deps (multi-file mode) |
| `--inline` | Opt into inline mode (BOF inside Beacon). Default is sacrificial. |
| `--noamsi` | Disable AMSI bypass (default: on) |
| `--noetw` | Disable ETW bypass (default: on) |
| `--mailslot` | Use mailslot stdout channel (default: named pipe) |
| `--appdomain <name>` | AppDomain name (default: `totesLegit`) |
| `--main` | Invoke `Main()` instead of the entry-point token |
| `--assemblyargs <args>` | Arguments passed to the target assembly's `Main` |
| `--slotname <name>` | Override the internal mailslot name |
| `--pipename <name>` | Override the internal named-pipe name |

### Tool compatibility

| Tool family | Default (sacrificial) | `--inline` |
|---|---|---|
| Rubeus, Seatbelt, SharpUp, Certify, SharpDPAPI | yes | yes |
| Snaffler | yes (NLog auto-routes) | yes |
| winPEAS | yes | not supported — calls `Environment.Exit` and spawns aggressive threads |
| SharpHound | yes | not recommended — long-running, may hold COM apartments |
| Other Ghostpack | yes | yes |

### Malleable C2 profile

`docs/profiles/senjata-recommended.profile` ships a snippet that pins `process-inject`
and `post-ex` to the OPSEC configuration the sacrificial path relies on
(`NtMapViewOfSection` + `NtQueueApcThread-s` instead of `VirtualAllocEx` +
`CreateRemoteThread`). Merge it into your existing profile.

---

## Evasion techniques

### 1. Hardware breakpoints + VEH for API neutralisation (patchless)

`opsec-hwbp` sets `DR0`–`DR3` to the addresses of `AmsiScanBuffer`, `NtTraceControl`
(or `EtwEventWrite`), `AllocConsole`, and `RtlExitUserProcess`, then registers a
vectored exception handler. When the CLR hits one of these APIs:

- **`rip → ret` callback** (AMSI / ETW / AllocConsole): the VEH scans ±500 bytes
  around the trap site for a `ret` gadget and redirects `RIP` there. The API returns
  immediately with no patching, no scan, no event.
- **Exit-trap callback** (`RtlExitUserProcess`): redirects `RIP` and `RSP` to a
  cleanup label captured before dispatch, abandoning the assembly's call stack. This
  is how `Environment.Exit()` inside the managed payload doesn't kill Beacon — we
  intercept right at the `RtlExitUserProcess` entry point and unwind to a known-good
  state.

`HwbpGuard` is an RAII wrapper that removes the descriptor from every process thread
on drop. Drop order matters: the exit-trap guard must drop before the engine so the
DR is cleared before the engine's own cleanup runs.

### 2. PEB walking + DJB2 hashing for API resolution

Every Windows API is resolved at runtime by walking
`TEB → PEB → Ldr → InMemoryOrderModuleList`, DJB2-hashing each module name, then
walking that module's export table and DJB2-hashing each export name. The hashes are
compared against constants computed at compile time via the `hash!("kernel32.dll")`
proc-macro. The plaintext names never enter the binary.

Result: the BOF's import table contains only the small `beacon_*` API set Cobalt
Strike's loader provides. No `kernel32.dll`, no `ntdll.dll`, no `amsi.dll`, no
`mscoree.dll`, no `coreclr.dll` in the import table or `.rdata`.

### 3. Compile-time XOR string encryption

`obf!("string")` encrypts every string literal at macro-expansion time using a
per-call-site XOR key derived from the source span. At runtime, the macro returns a
stack-resident `SecureStr<N>` whose `Drop` impl uses `core::ptr::write_volatile` to
zero the buffer. `hash!()` is the same idea for cases where only the hash is needed
— the plaintext never enters the binary at all.

### 4. Indirect syscalls via ntdll gadget

`opsec-bootstrap` scans ntdll for a `syscall; ret` (`0f 05 c3`) gadget, then for each
NT API it needs:

1. Reads the export stub
2. If the first bytes match the canonical `4c 8b d1` (`mov r10, rcx`), the stub is
   not hooked — call the export directly
3. Otherwise, extract the SSN from the (presumed-clean) stub and invoke a naked
   `indirect_syscall_n` function that sets `RAX = SSN` and jumps to the cached
   `syscall; ret` gadget

The `syscall` instruction never appears in the BOF's own `.text`. Currently used
for `NtGetContextThread`, `NtSetContextThread` (HWBP install/uninstall), and
`NtProtectVirtualMemory` (inline-mode CLR stomp).

### 5. CLR module stomping (inline mode)

Inline mode loads the assembly via `AppDomain.Load_2(identity)` — by GAC name, not by
raw bytes. Loading by identity bypasses AMSI's managed-buffer scan path naturally
because the CLR believes it's loading a signed GAC assembly.

To make the CLR actually run our payload, we register an `IHostMemoryManager` whose
`AcquiredVirtualAddressSpace` callback fires when the CLR maps the victim GAC DLL
(`System.Xml.Linq.dll`, `System.ServiceModel.dll`, etc.) into memory. The callback:

1. Verifies the mapping matches the selected victim's size (read from the GAC disk
   path before `Load_2`) within a ±64 KB band — protects against wrong-DLL stomp
   when the CLR maps a dependency first
2. Verifies the payload's PE structural integrity (`e_lfanew`, `SizeOfHeaders`,
   section table bounds)
3. Atomically clears the `pending` flag (single-stomp guard — prevents subsequent
   dependency maps from re-stomping)
4. Walks the payload's section table and overwrites each section in the mapping via
   `NtProtectVirtualMemory` + `memcpy` + restore-protection

Additional inline-mode hardening:

- **COMPLUS env tuning** before CLR `Start()`: `ZapDisable=1`,
  `AllowStrongNameBypass=1`, `GeneratePublisherEvidence=0` (prevents a 90-second CRL
  timeout on isolated hosts), `DisableAttachThread=1`, `LogEnable=0`,
  `DbgEnableMiniDump=0`. All saved before set and restored on every error path
- **Process-heap allocator** for `IHostMalloc` (the CLR's `EEStartup` makes
  thousands of small allocations — using `VirtualAlloc` per call exhausts address
  space due to 64 KB granularity)
- **Indirect `NtProtectVirtualMemory`** for the stomp itself (Task above), so the
  page-protection change does not surface as a `kernel32!VirtualProtect` call from
  the BOF thread
- **PEB ImageBase entropy** mixed into the BofState named-mapping derivation, so
  the `Local\<8hex>` name is unique per Beacon spawn (defeats static-regex
  fingerprinting)
- **Payload scrub** — once the stomp confirms the assembly is loaded, zero and
  `GlobalFree` the source buffer in our heap

### 6. Sacrificial mode — IPC and stomp-free

Sacrificial mode (`senjata-runner.x64.dll`) does not use CLR stomping. The Aggressor
script packages args + the runner DLL into a User-Defined Post-ex Kit (UDPK) blob;
Beacon spawns a sacrificial process, injects the DLL, and the runner hosts the CLR
from scratch in clean memory. Output streams over a named pipe that an early-spawned
reader thread pumps back to operator via `BeaconOutput`.

Because the CLR is in clean memory, sacrificial mode does not need stomping — it
uses standard `AppDomain.Load_3(byte[])` after installing the same HWBP bypasses as
inline. If the assembly crashes or calls `Environment.Exit`, only the sacrificial
process dies. Beacon stays interactive.

### 7. PE COR20 parsing for .NET runtime detection

`pe_parser.rs` reads the PE manually: DOS header → NT header → Optional Header
DataDirectory[14] (CLR Runtime Header) → COR20 header → metadata root (`BSJB`
signature → length-prefixed version string). Handles both PE32 (`0x10B`) and PE32+
(`0x20B`). Rejects mixed-mode (missing `COMIMAGE_FLAGS_ILONLY`).

Then it scans the assembly bytes for `TargetFrameworkAttribute`:

- `.NETFramework,Version=` → `clr_netfx::run` (CLR 4.x COM hosting)
- `.NETCoreApp,Version=`   → `clr_core::run` → `opsec_coreclr::run`

If neither marker is present, the BOF hard-errors with `TargetFrameworkUnknown`
rather than guessing.

### 8. BOF section compatibility

Beacon's loader recognises only the standard COFF section names (`.text`, `.rdata`,
`.data`, `.bss`, `.pdata`, `.xdata`). Rust's per-function sections need to be merged:

1. `-Z function-sections=no` in `.cargo/config.toml` suppresses most per-function
   sections
2. `x86_64-w64-mingw32-objcopy --rename-section .text.<foo>=.text` renames residual
   ones
3. `x86_64-w64-mingw32-ld -r` physically merges all `.text` sections into one

---

## Architecture

```
crates/
  rustbof / rustbof-derive   - vendored BOF runtime (not modified)
  opsec-strcrypt             - proc-macro: obf!(), obfw!(), hash!()
  opsec-strcrypt-rt          - runtime support for SecureStr / SecureWideStr
  opsec-peb                  - PEB walker + DJB2 export resolver
  opsec-bootstrap            - indirect-syscall engine
  opsec-hwbp                 - hardware breakpoint engine + VEH dispatch
  opsec-com                  - COM / CLR FFI vtables
  opsec-coreclr              - CoreCLR hosting bridge (.NET 6+)
  clr-orchestrator           - shared CLR-hosting logic
                               (pe_parser, io, cleanup, dispatch, netfx,
                                coreclr, flush, nlog, bypasses)

bofs/senjata-execute-assembly - BOF for inline mode (--inline flag)
                                staticlib -> COFF .o via boflink
bofs/senjata-runner           - post-ex DLL for sacrificial mode (default)
                                cdylib -> senjata-runner.x64.dll

stub/senjata-flush-helper     - FlushHelper.exe (rebinds Console.Out to raw
                                pipe handle)
stub/senjata-nlog-helper      - NLogConfigHelper.exe (reflects NLog at runtime;
                                routes Snaffler / SharpHound output via
                                ConsoleTarget)
stub/senjata-loader           - SenjataLoader.dll (CoreCLR managed bridge)
```

All `opsec-*` crates, `clr-orchestrator`, the BOF, and the post-ex DLL are `no_std`;
`extern crate alloc` where heap is needed. Lints enforce
`-D clippy::unwrap_used -D clippy::expect_used` on all owned crates.

---

## Development

### Tests

```bash
cargo make test
```

Runs host-side unit tests on the platform-agnostic `opsec-*` crates. The BOF and
sacrificial DLL are Windows-only; runtime validation is operator-manual on a Windows
lab host.

### Lint

```bash
cargo make lint
```

Clippy with the lint set above.

### OPSEC validation

Runs automatically as part of `cargo make build`. Standalone:

```bash
cargo make validate       # BOF .o
cargo make validate-dll   # runner .dll
```

Checks performed:

- Plaintext API/module names (`AmsiScanBuffer`, `NtTraceControl`, etc.) in `.rdata`
- Plaintext managed PE signatures in `.rdata` (catches unencrypted asset embeds)
- Forbidden import symbols (`GetProcAddress`, `LoadLibrary*`) in the symbol/import
  table
- BOF-only: undefined compiler-rt references (`__chkstk`, `__udivti3`, ...) that
  Beacon's loader cannot resolve
- DLL-only: 200 KB size budget

---

## Limitations / known issues

- **Inline mode + `Environment.Exit`**: protected by the exit-trap HWBP. Untrusted
  assemblies that touch COM apartments, STA threads, or native handles may still
  leave Beacon in an inconsistent state — prefer sacrificial for unknowns.
- **Inline mode + CLR cache**: the second run of inline mode against the same victim
  identity will hit CLR's loaded-assembly cache and return the first-run payload.
  Returns a clean `l3` error rather than crashing. To run a different assembly,
  restart Beacon.
- **.NET 5 self-contained single-file**: explicitly rejected during PE parse —
  there is no managed entry point in the conventional sense.
- **Mixed-mode (C++/CLI)**: explicitly rejected.
- **x86 / 32-bit**: not supported. x64 only.

---

## Credits

- [@rad9800](https://github.com/rad9800) — patchless hook technique
- [joaoviictorti/rustbof](https://github.com/joaoviictorti/rustbof) — Rust BOF framework
- [MEhrn00/boflink](https://github.com/MEhrn00/boflink) — COFF linker

---

## License

See LICENSE file.

---

## Disclaimer

This is offensive security research tooling. Use only against systems you own or have
explicit written authorisation to test. The author is not responsible for misuse.
