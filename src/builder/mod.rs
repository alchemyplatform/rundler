mod bundle_proposer;
mod bundle_sender;
mod sender;
mod server;
mod signer;
mod task;
mod transaction_tracker;

use parse_display::Display;
use serde::{Deserialize, Serialize};
pub use server::{
    connect_remote_builder_client, BuilderClient, LocalBuilderClient, LocalBuilderServerRequest,
};
use strum::EnumIter;
pub use task::*;

#[derive(Display, Debug, Clone, Copy, Eq, PartialEq, EnumIter, Serialize, Deserialize)]
#[display(style = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum BundlingMode {
    Manual,
    Auto,
}
