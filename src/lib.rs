//! Content Scanner agent for Sentinel.
//!
//! Scans uploaded files for malware using ClamAV daemon.

pub mod agent;
pub mod clamd;
pub mod config;

pub use agent::ContentScannerAgent;
pub use clamd::{ClamdClient, ClamdError, ScanResult};
pub use config::{Config, FailAction};
