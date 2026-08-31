//! modern-ip-scanner-core: LAN inventory and diff engine.
//!
//! See `docs/design.md` for the invariants this crate enforces.

pub mod diff;
pub mod discovery;
pub mod display;
pub mod export;
pub mod identity;
pub mod merge;
pub mod model;
pub mod netenv;
pub mod privilege;
pub mod scanner;
pub mod store;
pub mod util;

pub use model::*;
pub use scanner::{run_scan, ScanOptions};
