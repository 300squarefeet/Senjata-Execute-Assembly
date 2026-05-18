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
    DotNetCore,
    MixedModeUnsupported,
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
            BofError::DotNetCore => {
                format!(".NET Core/5+ not supported by legacy CLR hosting")
            }
            BofError::MixedModeUnsupported => {
                format!("mixed-mode (C++/CLI) assemblies are not supported")
            }
            BofError::AssemblyThrew { type_name, message } => {
                format!("assembly threw {type_name}: {message}")
            }
        }
    }
}
