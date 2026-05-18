# Senjata-Execute-Assembly

Patchless `execute-assembly` BOF for Cobalt Strike — Rust port of `PatchlessInlineExecute-Assembly`
with fixed .NET version detection, `Environment.Exit` crash trap, and hardened OPSEC.

## Highlights

- **Patchless AMSI + ETW bypass** via hardware breakpoints (DR0–DR3) — no memory patching
- **Survives `Environment.Exit()`** — RtlExitUserProcess HWBP redirects RIP/RSP back to the BOF cleanup point
- **Correctly handles all .NET Framework 2.x / 3.x / 4.x** assemblies via COR20 metadata-root parsing
- **Explicit rejection** of .NET Core / .NET 5+ and mixed-mode (C++/CLI) assemblies — no silent failure
- **No plaintext API names** in the binary — all module/export resolution via DJB2-hashed PEB walking
- **Bootstrap-only syscalls** — exactly two NTAPIs (`NtSet/GetContextThread`) with hook detection and Tartarus-Gate-lite fallback

## Build

```bash
cargo make build
# outputs dist/senjata-execute-assembly.x64.o and senjata-execute-assembly.cna
```

Reproducible build via Docker:
```bash
docker build -t senjata-build .
docker run --rm -v $PWD/dist:/work/dist senjata-build
```

## Use

In Cobalt Strike:
```
load /path/to/senjata-execute-assembly.cna
beacon> senjata-execute-assembly --dotnetassembly /opt/SharpCollection/Seatbelt.exe --amsi --etw --assemblyargs AntiVirus --mailslot
```

### Arguments

| Flag | Description |
|---|---|
| `--dotnetassembly <path>` | Path to the .NET assembly to execute (required) |
| `--amsi` | Install patchless AMSI bypass via HWBP |
| `--etw` | Install patchless ETW bypass via HWBP on `NtTraceControl` |
| `--mailslot` | Use mailslot stdout channel (default: named pipe) |
| `--appdomain <name>` | AppDomain name (default: `DefaultDomain`) |
| `--entrypoint <0\|1>` | Entry-point arg style (default: 1) |
| `--assemblyargs "<args>"` | Arguments passed to the assembly |
| `--slotname <name>` | Override the mailslot name |
| `--pipename <name>` | Override the named-pipe name |

## Design

See `docs/superpowers/specs/2026-05-18-senjata-execute-assembly-rust-port-design.md` for the full
architecture and OPSEC doctrine. See `docs/test-checklist.md` for the manual lab validation suite.

## Credits

- `PatchlessInlineExecute-Assembly` original C implementation (preserved in `legacy/`)
- `@rad9800` for the patchless hook technique
- `joaoviictorti/rustbof` for the Rust BOF framework
- `MEhrn00/boflink` for the COFF linker
