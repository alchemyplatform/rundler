mod bundle_proposer;
mod bundle_sender;
pub mod emit;
mod sender;
mod server;
mod signer;
mod task;
mod transaction_tracker;

use parse_display::Display;
use serde::{Deserialize, Serialize};
pub use server::{BuilderServer, LocalBuilderBuilder, RemoteBuilderClient};
pub use task::*;

#[derive(Display, Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[display(style = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum BundlingMode {
    Manual,
    Auto,
}
