# Senjata-Execute-Assembly

Patchless C# runner for Cobalt Strike — dual-artefact system (BOF + postex DLL) with
a shared CLR core, so the same OPSEC posture covers both inline and sacrificial execution.
v0.3+ ships universal compatibility for Ghostpack, Snaffler, winPEAS, SharpHound, and
similar .NET tooling.

## Highlights

- **Patchless AMSI + ETW + AllocConsole + ExitProcess** bypass via hardware breakpoints (DR0–DR3) — no memory patching
- **Two artefacts, one CLR core** — `senjata-execute-assembly.x64.o` (BOF, inline) and `senjata-runner.x64.dll` (UDPK, sacrificial) share `clr-orchestrator`
- **Live output streaming** during multi-minute / multi-hour sacrificial runs via `bread_pipe` + reader thread → `BeaconOutput`
- **NLogConfigHelper** auto-routes NLog tools (Snaffler / SharpHound) to `Console.Out` — no per-tool source patches
- **Dual runtime support** — .NET Framework 2.x / 3.x / 4.x and .NET 6/7/8 via CoreCLR hosting
- **Explicit rejection** of mixed-mode (C++/CLI) and self-contained .NET 5+ single-file deployments — no silent failure
- **No plaintext API names** in either artefact — all module/export resolution via DJB2-hashed PEB walking
- **Bootstrap-only syscalls** for HWBP install (`NtGet/SetContextThread`) with hook detection and indirect syscall fallback

## Build

```bash
cargo make build
# outputs:
#   dist/senjata-execute-assembly.x64.o   (BOF — inline mode)
#   dist/senjata-runner.x64.dll           (UDPK — sacrificial mode, default)
#   dist/senjata-execute-assembly.cna     (Aggressor dispatcher)
```

Reproducible build via Docker:
```bash
docker build -t senjata-build .
docker run --rm -v $PWD/dist:/work/dist senjata-build
```

## Operator Usage

**Default behaviour: sacrificial process (universal compatibility).**

```text
beacon> senjata-execute-assembly --dotnetassembly C:\corpus\Tool.exe \
        --assemblyargs <args>
```

The assembly runs in a freshly-spawned `dllhost.exe` (or whatever your
`spawnto_x64` is set to), output streams back to operator each Beacon
check-in, and Beacon stays interactive for the duration.

**Opt-in inline mode (`--inline`) for trusted small tools:**

```text
beacon> senjata-execute-assembly --inline --dotnetassembly C:\corpus\Rubeus.exe \
        --assemblyargs klist
```

Inline mode runs the assembly inside Beacon's process. Smaller OPSEC
footprint (no process spawn) but blocks Beacon for the run and may
crash Beacon if the assembly leaves COM apartments / STA threads / native
handles alive. Use only for tools you trust to exit cleanly (Rubeus,
SharpUp, Seatbelt, Certify, SharpDPAPI, etc.).

**Removed in v0.3:** `--async`. The default is now sacrificial.

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

### Recommended Malleable C2 profile

`docs/profiles/senjata-recommended.profile` ships a snippet that pins
`process-inject` and `post-ex` to the configuration the OPSEC properties
documented in the spec rely on (`NtMapViewOfSection` + Earliest-Bird APC
instead of `VirtualAllocEx` + `CreateRemoteThread`). Merge it into your profile.

### Tool compatibility

| Tool family | Default (sacrificial) | --inline |
|---|---|---|
| Rubeus, Seatbelt, SharpUp, Certify, SharpDPAPI | ✅ | ✅ |
| Snaffler | ✅ (NLogConfigHelper auto-routes) | ✅ |
| winPEAS | ✅ | ❌ kills Beacon |
| SharpHound | ✅ | ⚠ skip |
| Other Ghostpack | ✅ | ✅ |

See `docs/superpowers/specs/2026-05-21-universal-csharp-runner-design.md` for the
full compatibility matrix and known limitations.

## Design

- `docs/superpowers/specs/2026-05-18-senjata-execute-assembly-rust-port-design.md` — original Rust-port architecture (v0.1)
- `docs/superpowers/specs/2026-05-20-bof-side-nlog-auto-config-design.md` — NLogConfigHelper sub-design (v0.2 reuse)
- `docs/superpowers/specs/2026-05-21-universal-csharp-runner-design.md` — dual-artefact redesign (v0.3, current)
- `docs/testing/2026-05-21-phase-7-matrix.md` — lab validation matrix (operator-fillable)

## Credits

- `@rad9800` for the patchless hook technique
- `joaoviictorti/rustbof` for the Rust BOF framework
- `MEhrn00/boflink` for the COFF linker
