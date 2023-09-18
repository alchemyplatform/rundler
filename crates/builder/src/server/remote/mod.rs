mod client;
pub use client::RemoteBuilderClient;

mod error;
#[allow(non_snake_case, unreachable_pub)]
pub mod protos;

mod server;
pub(crate) use server::spawn_remote_builder_server;
