//! BOF-side error type. Wraps `clr_orchestrator::OrchestratorError` and adds
//! the BOF-specific variants (args parsing).

use alloc::format;
use alloc::string::String;

#[derive(Debug)]
pub enum BofError {
    Args(crate::args::Error),
    Orchestrator(clr_orchestrator::OrchestratorError),
}

impl BofError {
    pub fn format(&self) -> String {
        match self {
            BofError::Args(e) => format!("args parse: {e:?}"),
            BofError::Orchestrator(e) => e.format(),
        }
    }
}

impl From<clr_orchestrator::OrchestratorError> for BofError {
    fn from(e: clr_orchestrator::OrchestratorError) -> Self {
        BofError::Orchestrator(e)
    }
}
