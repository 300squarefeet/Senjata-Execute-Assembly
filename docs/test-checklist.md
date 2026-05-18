# Senjata-Execute-Assembly — Manual Lab Test Checklist

## Setup
1. Win10 22H2 or Win11 23H2 VM, Defender on
2. Cobalt Strike teamserver + client
3. Load `dist/senjata-execute-assembly.cna`
4. Optional: enable ETW-TI logging via PerfView or `xperf`:
   - `xperf -on PROC_THREAD+LOADER+MEMINFO -stackwalk syscall`

## Functional
- [ ] SharpUp runs end-to-end, output captured
- [ ] Seatbelt with `--amsi --etw --assemblyargs AntiVirus` succeeds; beacon alive after
- [ ] 10x sequential Seatbelt invocations; final `shell whoami` succeeds
- [ ] SharpHound runs; async collection completes; beacon alive after
- [ ] Rubeus with `--amsi` flag runs against Defender; no detection
- [ ] .NET 2.0 custom tool runs (v2 CLR path)
- [ ] .NET 8 tool rejected with `[-] .NET Core/5+ assemblies are not supported`
- [ ] Mixed-mode C++/CLI dll rejected with `[-] mixed-mode (C++/CLI) assemblies are not supported`
- [ ] Throws.exe surfaces `assembly threw ...` message
- [ ] WinForms STA app surfaces InvalidOperationException, beacon alive
- [ ] CLR v2 -> v4 conflict in single beacon surfaces `IsLoadable returned false` error

## OPSEC
- [ ] `strings dist/senjata-execute-assembly.x64.o | grep -i amsi` — empty
- [ ] `strings dist/senjata-execute-assembly.x64.o | grep -i ntdll` — empty
- [ ] After one corpus invocation, ETW-TI trace shows ≤ 6 syscall events from the beacon thread (only NtSet/GetContextThread bootstrap)
- [ ] After cleanup, attach WinDbg: every beacon thread Dr0..Dr3 = 0, Dr7 = 0
- [ ] Defender real-time on; load assembly containing `Invoke-Mimikatz` string in body — successful execution

## Safety
- [ ] 100x corpus shuffle without beacon respawn
- [ ] WinDbg attached during corpus run shows no first-chance AV from our code
