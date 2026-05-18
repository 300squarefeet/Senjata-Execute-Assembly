use alloc::format;
use alloc::string::String;

#[derive(Debug)]
pub enum BofError {
    Args(crate::args::Error),
    PebResolve { module_hash: u32, export_hash: u32 },
    Hwbp(opsec_hwbp::Error),
    Bootstrap(opsec_bootstrap::Error),
    Clr { hr: i32, op: &'static str },
    PeParse(crate::pe_parser::Error),
    Io { last_error: u32, op: &'static str },
    MixedModeUnsupported,
    TargetFrameworkUnknown,
    ArchMismatch,
    AssemblyThrew { type_name: String, message: String },
}

impl BofError {
    pub fn format(&self) -> String {
        match self {
            BofError::Args(e) => format!("args parse: {e:?}"),
            BofError::PebResolve { module_hash, export_hash } => format!(
                "peb resolve failed (mod=0x{module_hash:08x} exp=0x{export_hash:08x})"
            ),
            BofError::Hwbp(e) => format!("hwbp: {e:?}"),
            BofError::Bootstrap(e) => format!("bootstrap: {e:?}"),
            BofError::Clr { hr, op } => format!("clr {op}: hr=0x{hr:08x}"),
            BofError::PeParse(e) => format!("pe parse: {e:?}"),
            BofError::Io { last_error, op } => format!("io {op}: err={last_error}"),
            BofError::MixedModeUnsupported => {
                "mixed-mode (C++/CLI) assemblies are not supported".into()
            }
            BofError::TargetFrameworkUnknown => {
                "could not detect TargetFrameworkAttribute in assembly bytes; \
                 rebuild with `TargetFramework` set (net48 / net6.0 / etc.) \
                 or use a fresh Roslyn compilation".into()
            }
            BofError::ArchMismatch => {
                "assembly targets x86 (32BITREQUIRED) but beacon is x64; recompile as AnyCPU or use an x64 build".into()
            }
            BofError::AssemblyThrew { type_name, message } => {
                format!("assembly threw {type_name}: {message}")
            }
        }
    }
}

