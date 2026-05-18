# SenjataLoader — Managed Bridge Stub

This is the ONLY non-Rust source code in the project.

## Why it exists

CoreCLR's `coreclr_create_delegate` requires an entry method in a managed
assembly. We use this stub as a bridge: native Rust → `coreclr_create_delegate`
→ this stub's `Run` method → `AssemblyLoadContext.LoadFromStream(byte[])`
→ target assembly executes purely from memory.

The target assembly bytes (the actual payload, e.g. SharpHound) never touch
disk. Only this stub touches disk briefly (~210 ms with `FILE_DELETE_ON_CLOSE`).

## Building (regenerate the committed blob)

When you change `Loader.cs`, run from the repo root:

```bash
bash stub/build-stub.sh
```

This produces `bofs/senjata-execute-assembly/assets/stub.dll.xor` — a
committed encrypted blob included into the BOF via `include_bytes!`.

Normal BOF builds (`cargo make build`) do not invoke `dotnet`. The .NET
SDK is a developer-only dependency for the stub source.

## Constraints

- Method must be `[UnmanagedCallersOnly]` for native ABI compat.
- Only primitive native types (`IntPtr`, `int`) in the signature.
- `Run` must be `public static`.
- The assembly name (`SenjataLoader`), type (`SenjataLoader.Loader`), and
  method (`Run`) are referenced from the Rust side via XOR-encrypted
  string literals. Do NOT rename without updating Rust call sites.
