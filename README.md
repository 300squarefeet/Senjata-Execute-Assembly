# Senjata-Execute-Assembly

[![CI](https://github.com/300squarefeet/Senjata-Execute-Assembly/actions/workflows/ci.yml/badge.svg)](https://github.com/300squarefeet/Senjata-Execute-Assembly/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Cobalt%20Strike-blue.svg)]()
[![Rust](https://img.shields.io/badge/rust-nightly--2025--01--25-orange.svg)]()

A patchless, OPSEC-hardened `execute-assembly` implementation for Cobalt Strike,
written in Rust. Ships two complementary artefacts that share a single CLR-hosting
core, so the same evasion posture covers both inline and sacrificial execution paths.

Compatible with current-generation .NET tooling across .NET Framework 2.x / 3.x / 4.x
and .NET 6 / 7 / 8.

> ⚠️ **Authorised use only.** This is offensive security research tooling. Use only
> against systems you own or have explicit written authorisation to test.

---

## Table of contents

- [Features](#features)
- [Quick start](#quick-start)
- [Build](#build)
- [Usage](#usage)
- [Evasion techniques](#evasion-techniques)
- [Architecture](#architecture)
- [Development](#development)
- [Limitations](#limitations)
- [Credits](#credits)
- [License](#license)

---

## Features

- **Patchless AMSI + ETW + AllocConsole + `Environment.Exit` bypass** via hardware
  breakpoints (DR0–DR3) and a vectored exception handler — no memory patching at all
- **Two artefacts, one CLR core** — `senjata-execute-assembly.x64.o` (BOF, inline mode)
  and `senjata-runner.x64.dll` (post-ex DLL, sacrificial mode) share the same
  orchestrator crate
- **Live output streaming** during multi-minute / multi-hour sacrificial runs — reader
  thread pumps pipe data to `BeaconOutput` on each check-in
- **NLog auto-routing** for tools like Snaffler and SharpHound that bypass
  `Console.Out` — runtime reflection redirects their loggers without per-tool patches
- **Dual runtime support** — .NET Framework 2.x / 3.x / 4.x via COM hosting
  (`ICLRMetaHost` → `ICorRuntimeHost` → `AppDomain.Load_2`) and .NET 6 / 7 / 8 via
  direct CoreCLR hosting (`coreclr_initialize` + `coreclr_create_delegate`)
- **Explicit rejection** of mixed-mode (C++/CLI) and self-contained .NET 5+
  single-file deployments — no silent failure
- **No plaintext API names** anywhere in either artefact — every module/export
  resolved via PEB walk + DJB2 hash compared against compile-time constants
- **Indirect syscalls** for `NtGet/SetContextThread` (HWBP install) and
  `NtProtectVirtualMemory` (inline-mode CLR stomp)
- **OPSEC validation gate** runs at build time — any plaintext API name or forbidden
  import that slips through fails CI

---

## Quick start

Pre-built artefacts are published with each [release](../../releases). Drop them in
your Cobalt Strike scripts directory, load the `.cna`, and dispatch:

```text
beacon> senjata-execute-assembly --dotnetassembly C:\Tools\Rubeus.exe \
        --assemblyargs triage
```

To build from source, see [Build](#build) below.

---

## Build

Toolchain pinned to `nightly-2025-01-25` via `rust-toolchain.toml`. Cross-compiled
from Linux / macOS to `x86_64-pc-windows-gnu` with `-Z build-std=core,alloc` and
`-Z build-std-features=compiler-builtins-mem` (Beacon's loader does not provide
`memcpy` / `memset` / `memcmp`).

```bash
cargo make build
```

Outputs:

| File | Purpose |
|------|---------|
| `dist/senjata-execute-assembly.x64.o` | BOF — inline mode |
| `dist/senjata-runner.x64.dll` | Post-ex DLL — sacrificial mode (default) |
| `dist/senjata-execute-assembly.cna` | Aggressor dispatcher |

The build pipeline runs in order: `cargo build --release` → `boflink` → section merge
(`x86_64-w64-mingw32-ld -r`) → OPSEC validation → copy `.cna`. The OPSEC gate scans
the linked artefacts for plaintext API/module names, forbidden imports
(`GetProcAddress`, `LoadLibrary*`), plaintext managed PE signatures in `.rdata`, and
compiler-rt undefined references. Any violation fails the build.

### Reproducible build via Docker

```bash
docker build -t senjata-build .
docker run --rm -v $PWD/dist:/work/dist senjata-build
```

---

## Usage

### Default: sacrificial process

```text
beacon> senjata-execute-assembly --dotnetassembly C:\Tools\Seatbelt.exe \
        --assemblyargs all
```

The assembly runs in a freshly-spawned process (whatever `spawnto_x64` is set to).
Output streams back on each Beacon check-in. Beacon stays interactive for the
duration. Assemblies that call `Environment.Exit()`, hang on threads, or leave native
handles open cannot harm Beacon because the runtime lives in a separate process.

### Opt-in: inline mode

```text
beacon> senjata-execute-assembly --inline --dotnetassembly C:\Tools\Rubeus.exe \
        --assemblyargs klist
```

Inline mode hosts the CLR inside Beacon's process and loads the assembly via CLR
module stomping (see [Evasion techniques](#evasion-techniques)). Smaller OPSEC
footprint — no process spawn, no IPC, no cross-process injection — but Beacon is
blocked for the run. Use for tools that exit cleanly.

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

---

## Evasion techniques

### 1. Hardware breakpoints + VEH for API neutralisation

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
zero the buffer. `hash!()` is the same idea for cases where only the hash is needed —
the plaintext never enters the binary at all.

### 4. Indirect syscalls via ntdll gadget

`opsec-bootstrap` scans ntdll for a `syscall; ret` (`0f 05 c3`) gadget, then for each
NT API it needs:

1. Reads the export stub
2. If the first bytes match the canonical `4c 8b d1` (`mov r10, rcx`), the stub is
   not hooked — call the export directly
3. Otherwise, extract the SSN from the (presumed-clean) stub and invoke a naked
   `indirect_syscall_n` function that sets `RAX = SSN` and jumps to the cached
   `syscall; ret` gadget

The `syscall` instruction never appears in the BOF's own `.text`. Currently used for
`NtGetContextThread`, `NtSetContextThread` (HWBP install/uninstall), and
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
- **Process-heap allocator** for `IHostMalloc` (the CLR's `EEStartup` makes thousands
  of small allocations — using `VirtualAlloc` per call exhausts address space due to
  64 KB granularity)
- **Indirect `NtProtectVirtualMemory`** for the stomp itself, so the page-protection
  change does not surface as a `kernel32!VirtualProtect` call from the BOF thread
- **PEB ImageBase entropy** mixed into the BofState named-mapping derivation, so the
  `Local\<8hex>` name is unique per Beacon spawn (defeats static-regex
  fingerprinting)
- **Payload scrub** — once the stomp confirms the assembly is loaded, zero and
  `GlobalFree` the source buffer in our heap

### 6. Sacrificial mode — IPC and stomp-free

Sacrificial mode (`senjata-runner.x64.dll`) does not use CLR stomping. The Aggressor
script packages args + the runner DLL into a User-Defined Post-ex Kit (UDPK) blob;
Beacon spawns a sacrificial process, injects the DLL, and the runner hosts the CLR
from scratch in clean memory. Output streams over a named pipe that an
early-spawned reader thread pumps back to operator via `BeaconOutput`.

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
- `.NETCoreApp,Version=` → `clr_core::run` → `opsec_coreclr::run`

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
  rustbof / rustbof-derive   — vendored BOF runtime (unmodified)
  opsec-strcrypt             — proc-macro: obf!(), obfw!(), hash!()
  opsec-strcrypt-rt          — runtime support for SecureStr / SecureWideStr
  opsec-peb                  — PEB walker + DJB2 export resolver
  opsec-bootstrap            — indirect-syscall engine
  opsec-hwbp                 — hardware breakpoint engine + VEH dispatch
  opsec-com                  — COM / CLR FFI vtables
  opsec-coreclr              — CoreCLR hosting bridge (.NET 6+)
  clr-orchestrator           — shared CLR-hosting logic
                               (pe_parser, io, cleanup, dispatch, netfx,
                                coreclr, flush, nlog, bypasses)

bofs/senjata-execute-assembly — BOF for inline mode (--inline flag)
                                staticlib → COFF .o via boflink
bofs/senjata-runner           — post-ex DLL for sacrificial mode (default)
                                cdylib → senjata-runner.x64.dll

stub/senjata-flush-helper     — FlushHelper.exe (rebinds Console.Out to raw
                                pipe handle)
stub/senjata-nlog-helper      — NLogConfigHelper.exe (reflects NLog at runtime;
                                routes Snaffler / SharpHound output via
                                ConsoleTarget)
stub/senjata-loader           — SenjataLoader.dll (CoreCLR managed bridge)
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

## Limitations

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

## Contributing

Contributions are welcome. Before opening a PR:

1. Run `cargo make test` and `cargo make lint` locally
2. `cargo make build` must succeed end-to-end (both OPSEC validators print `OK`)
3. Keep the no-plaintext-API-names invariant — use `obf!()` and `hash!()` for any new
   string literals or API references

---

## Credits

- [@rad9800](https://github.com/rad9800) — patchless hook technique
- [joaoviictorti/rustbof](https://github.com/joaoviictorti/rustbof) — Rust BOF framework
- [MEhrn00/boflink](https://github.com/MEhrn00/boflink) — COFF linker

---

## License

Released under the MIT License. See [LICENSE](LICENSE).

---

## Disclaimer

This is offensive security research tooling. Use only against systems you own or have
explicit written authorisation to test. The author and contributors assume no
liability and are not responsible for any misuse or damage caused by this program.
