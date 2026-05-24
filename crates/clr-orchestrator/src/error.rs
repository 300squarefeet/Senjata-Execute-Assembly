use alloc::format;
use alloc::string::String;

#[derive(Debug)]
pub enum OrchestratorError {
    PebResolve { module_hash: u32, export_hash: u32 },
    Hwbp(opsec_hwbp::Error),
    Bootstrap(opsec_bootstrap::Error),
    Clr { hr: i32, op: &'static str },
    PeParse(crate::pe_parser::Error),
    Io { last_error: u32, op: &'static str },
    MixedModeUnsupported,
    ArchMismatch,
    AssemblyThrew { type_name: String, message: String },
    /// CLR is already running in this process and no BofState exists.
    /// Stomp cannot be initialised; caller should fall back to Load_3.
    ClrAlreadyRunning,
}

impl OrchestratorError {
    pub fn format(&self) -> String {
        match self {
            Self::PebResolve { module_hash, export_hash } => format!(
                "peb resolve failed (mod=0x{module_hash:08x} exp=0x{export_hash:08x})"
            ),
            Self::Hwbp(e) => format!("hwbp: {e:?}"),
            Self::Bootstrap(e) => format!("bootstrap: {e:?}"),
            Self::Clr { hr, op } => format!("clr {op}: hr=0x{hr:08x}"),
            Self::PeParse(e) => format!("pe parse: {e:?}"),
            Self::Io { last_error, op } => format!("io {op}: err={last_error}"),
            Self::MixedModeUnsupported => {
                "mixed-mode (C++/CLI) assemblies are not supported".into()
            }
            Self::ArchMismatch => {
                "assembly targets x86 (32BITREQUIRED) but host is x64".into()
            }
            Self::AssemblyThrew { type_name, message } => {
                format!("assembly threw {type_name}: {message}")
            }
            Self::ClrAlreadyRunning => {
                "CLR already running in this Beacon process — stomp requires a fresh CLR.\n\
                 Use a new Beacon (inline stomp will work), or drop --inline for sacrificial mode."
                    .into()
            }
        }
    }
}
