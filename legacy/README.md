# Legacy C Implementation

This directory preserves the original C source for `PatchlessInlineExecute-Assembly`
as a reference implementation. It is intentionally NOT built by CI.

The Rust port lives under `bofs/senjata-execute-assembly/` and supporting
`crates/`. See `docs/superpowers/specs/2026-05-18-senjata-execute-assembly-rust-port-design.md`.

## Build (original instructions)

Run inside this directory via x64 Native Tools Command Prompt:

    cl.exe /c PatchlessinlineExecute-Assembly.c /GS- /FoPatchlessinlineExecute-Assemblyx64.o
