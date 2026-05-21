//! Build script for senjata-runner.
//!
//! The runner cdylib is reflectively loaded into a sacrificial process by
//! Cobalt Strike's User-Defined Postex Kit. CS's smartinject rewrites the
//! DLL's Import Address Table at load time: any IAT entry whose module name
//! is `beacon.dll` and whose function name starts with `Beacon` is replaced
//! with a pointer to an in-process proxy. The proxy then forwards the call
//! to the Beacon-side handler via the named pipe whose handle is stored in
//! `gPipeHandle`.
//!
//! To get those IAT entries, we need the linker to see undefined references
//! to `BeaconPrintf`, `BeaconOutput`, etc., AND to resolve them against an
//! import library that says "these live in beacon.dll". We synthesize that
//! import library at build time from `beacon.def` using mingw's `dlltool`.
//!
//! The generated `libbeacon.a` is a stub import lib only — it never gets
//! loaded at runtime. It only serves to teach the linker the IAT layout.

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    // Only matters for the Windows target (the rest of the workspace runs
    // host-side unit tests on macOS/Linux where mingw isn't present).
    let target = env::var("TARGET").unwrap_or_default();
    if !target.contains("windows") {
        return;
    }

    let out_dir = match env::var("OUT_DIR") {
        Ok(v) => PathBuf::from(v),
        Err(_) => {
            eprintln!("OUT_DIR not set; cargo did not invoke this script correctly");
            std::process::exit(1);
        }
    };
    let manifest = match env::var("CARGO_MANIFEST_DIR") {
        Ok(v) => PathBuf::from(v),
        Err(_) => {
            eprintln!("CARGO_MANIFEST_DIR not set; cargo did not invoke this script correctly");
            std::process::exit(1);
        }
    };
    let def = manifest.join("beacon.def");
    let lib = out_dir.join("libbeacon.a");

    println!("cargo:rerun-if-changed={}", def.display());

    // Pick a dlltool. Prefer the mingw cross-tool; fall back to `dlltool`
    // for native mingw builds.
    let dlltool = if Command::new("x86_64-w64-mingw32-dlltool")
        .arg("--version")
        .output()
        .is_ok()
    {
        "x86_64-w64-mingw32-dlltool"
    } else {
        "dlltool"
    };

    let status = match Command::new(dlltool)
        .arg("-d")
        .arg(&def)
        .arg("-l")
        .arg(&lib)
        .arg("-m")
        .arg("i386:x86-64")
        // Match Win64 stdcall name decoration (none on x86_64-pc-windows-gnu).
        .arg("--no-leading-underscore")
        .status()
    {
        Ok(s) => s,
        Err(e) => {
            eprintln!("failed to invoke dlltool ({}): {}; install mingw-w64", dlltool, e);
            std::process::exit(1);
        }
    };
    if !status.success() {
        eprintln!("dlltool failed to build libbeacon.a from beacon.def");
        std::process::exit(1);
    }

    println!("cargo:rustc-link-search=native={}", out_dir.display());
    // dylib kind: link as an import library reference. With mingw, the
    // resulting IAT entries point at beacon.dll which CS smartinject
    // rewrites at reflective load time.
    println!("cargo:rustc-link-lib=dylib=beacon");

    // Override the PE AddressOfEntryPoint to our `DllEntryPoint` instead of
    // mingw's auto-injected `_DllMainCRTStartup`. CS's reflective loader
    // calls the address at `IMAGE_OPTIONAL_HEADER.AddressOfEntryPoint`;
    // mingw's stub then looks for a `DllMain` symbol by name (NOT
    // `DllEntryPoint`) and dispatches via the standard 3-arg `BOOL WINAPI
    // DllMain(HINSTANCE, DWORD, LPVOID)` signature — silently dropping the
    // 4th `startNamedPipe` arg CS UDPK provides.
    //
    // Without this override, `DllEntryPoint(DLL_POSTEX_ATTACH)` is never
    // reached, `StartNamedPipeServer` never runs, and operator-side
    // `bread_pipe` fails with `ERROR_FILE_NOT_FOUND`.
    //
    // Side effect: skipping the CRT startup stub leaves us without
    // `_CRT_INIT` / `_initterm` / global ctors. We're `no_std` so none of
    // that matters; the apiset CRT imports in the IAT become dead weight
    // that the loader still resolves (correctly) via the apiset schema.
    println!("cargo:rustc-link-arg=-Wl,-e,DllEntryPoint");
}
