# Phase 7 Integration Matrix — Senjata Universal C# Runner

**Status:** TEMPLATE (operator fills in results on Windows VM)
**Spec:** `docs/superpowers/specs/2026-05-21-universal-csharp-runner-design.md`
**Plan:** `docs/superpowers/plans/2026-05-21-universal-csharp-runner.md` Phase 7

## Test environment

Fill in before running:

- VM image / OS build: `<e.g., Windows 10 22H2 build 19045 / Windows 11 23H2 build 22631>`
- Cobalt Strike Client/Teamserver version: `<e.g., 4.10.1>`
- Malleable C2 profile: `<profile name + path; should apply docs/profiles/senjata-recommended.profile snippet>`
- Build commit (HEAD when artefacts dropped to target): `<git rev-parse HEAD>`
- BOF size: `<bytes>` / DLL size: `<bytes>`
- Beacon sleep / jitter at test time: `<e.g., 30 / 20>`

## Corpus

All assemblies on the VM target at `C:\corpus\`. Build/collect on the operator host with:

```bash
mkdir -p /tmp/senjata-corpus && cd /tmp/senjata-corpus

# Already in this repo's arsenal-kit/ (operator-curated, untracked):
cp /Users/salma/Documents/Research/Senjata-Assembly/arsenal-kit/Hello.exe        .
cp /Users/salma/Documents/Research/Senjata-Assembly/arsenal-kit/Snaffler.exe     .   # patched build
cp /Users/salma/Documents/Research/Senjata-Assembly/arsenal-kit/winPEAS.exe      .

# Vanilla Snaffler (proves NLogConfigHelper works without per-tool patches)
# — build per Plan §Task 2.5 Step 2

# Ghostpack pre-built binaries from r3motecontrol/Ghostpack-CompiledBinaries:
#   Rubeus.exe, Seatbelt.exe, SharpUp.exe, Certify.exe, SharpDPAPI.exe

# SharpHound from BloodHoundAD/SharpHound releases:
#   SharpHound.exe (v2.5.x+)
```

Transfer the corpus dir to the VM at `C:\corpus\` (SMB / sftp / drag-drop).

## Matrix

Legend: ✅ pass · ❌ fail · ⚠ expected-fail (documented limitation) · ⏳ skipped/deferred · TTFO = time-to-first-output (sacrificial only)

| # | Tool | Args | Mode | Result | TTFO | Total | Beacon survived | Notes |
|---|---|---|---|---|---|---|---|---|
| 1 | Hello.exe | (none) | inline | | n/a | | | |
| 2 | Hello.exe | (none) | sacrificial | | | | | first-byte streaming check |
| 3 | HelloSlow.exe | (none) | sacrificial | | | | | streaming proof; line 1 should arrive in 1 sleep cycle |
| 4 | Rubeus.exe | `klist` | inline | | n/a | | | |
| 5 | Rubeus.exe | `klist` | sacrificial | | | | | |
| 6 | Seatbelt.exe | `-group=user` | inline | | n/a | | | |
| 7 | Seatbelt.exe | `-group=user` | sacrificial | | | | | |
| 8 | SharpUp.exe | `audit` | inline | | n/a | | | |
| 9 | SharpUp.exe | `audit` | sacrificial | | | | | |
| 10 | Snaffler.exe (patched) | `--help` | inline | | n/a | | | control: known good |
| 11 | Snaffler.exe (vanilla) | `--help` | inline | | n/a | | | **load-bearing: proves NLogConfigHelper** |
| 12 | Snaffler.exe (vanilla) | `--help` | sacrificial | | | | | helper works in postex DLL too |
| 13 | Snaffler.exe (vanilla) | `-s -i C:\Users\Public` | sacrificial | | | | | scan output streams live |
| 14 | winPEAS.exe | `systeminfo userinfo` | inline | ⚠ | n/a | | ❌ expected | documented as kills beacon |
| 15 | winPEAS.exe | `systeminfo userinfo` | sacrificial | | | | | beacon must survive |
| 16 | winPEAS.exe | `all` | sacrificial | | | | | ~5-15 min, live progress |
| 17 | SharpHound.exe | `-c All --outputdirectory C:\corpus` | sacrificial | | | | | ZIP to disk + live progress |
| 18 | Certify.exe | `find` | inline | | n/a | | | |
| 19 | Certify.exe | `find` | sacrificial | | | | | |
| 20 | SharpDPAPI.exe | `machinemasterkeys` | inline | | n/a | | | |
| 21 | SharpDPAPI.exe | `machinemasterkeys` | sacrificial | | | | | |

## Operator workflow per cell

1. From Cobalt Strike client, load `dist/senjata-execute-assembly.cna`. Confirm `dist/senjata-runner.x64.dll` sits alongside (auto-located by the .cna).
2. From a Beacon shell:
   - Inline: `senjata-execute-assembly --inline --dotnetassembly C:\corpus\Tool.exe --assemblyargs <args>`
   - Sacrificial: `senjata-execute-assembly --dotnetassembly C:\corpus\Tool.exe --assemblyargs <args>`
3. Capture:
   - Wallclock at dispatch and at first/last output line.
   - Beacon-survived check: send `ps` and `jobs` in a separate Beacon tab during sacrificial runs; verify the parent Beacon responds.
   - Sacrificial PID (from `jobs` immediately after dispatch).
4. Mark the matrix cell.

## Failure triage protocol

For each ❌, capture and append to a per-row section below:

- Full Beacon log output around the failure window (`/Library/Logs/cobaltstrike/...` or wherever the operator's log root is).
- `ps` snapshot before / during / after the run (use a second Beacon tab during the run).
- Relevant Windows Event Log entries (Sysmon if enabled): process creation, image load, thread injection events around the sacrificial PID.
- Suspected component (BOF, runner, orchestrator, helper, .cna) and reasoning.
- Reproducer steps and minimum-cell smaller test that still triggers the failure.

File a follow-up issue per failure with title pattern:
`Phase 7: <tool> <mode> — <one-line symptom>`

## Findings (filled during execution)

_(operator appends notes here)_

## Sign-off

- [ ] All "✅ expected" cells pass
- [ ] All "⚠ expected-fail" cells fail in the documented way (not differently)
- [ ] Beacon survived every sacrificial run
- [ ] No new failures filed as blockers
- [ ] Phase 7 tag created: `git tag -a phase-7-matrix -m "Phase 7 — integration matrix complete"`
