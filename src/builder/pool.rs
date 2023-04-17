use ethers::types::H256;
use tokio::sync::broadcast;
use tonic::{async_trait, transport::Channel};

use crate::common::{
    handle::SpawnGuard,
    protos::{
        self,
        op_pool::{op_pool_client::OpPoolClient, SubscribeNewBlocksRequest},
    },
};

#[derive(Debug, Clone)]
pub struct NewBlock {
    pub hash: H256,
    pub number: u64,
}

#[async_trait]
pub trait PoolClient: Send + Sync + 'static {
    fn subscribe_new_blocks(&self) -> broadcast::Receiver<NewBlock>;
}

pub struct RemotePoolClient {
    rx: broadcast::Receiver<NewBlock>,
    _guard: SpawnGuard,
}

impl RemotePoolClient {
    pub fn new(client: OpPoolClient<Channel>) -> Self {
        let (tx, rx) = broadcast::channel(1000);
        let _guard = SpawnGuard::spawn_with_guard(Self::run(client, tx));
        Self { rx, _guard }
    }

    async fn run(mut client: OpPoolClient<Channel>, tx: broadcast::Sender<NewBlock>) {
        let mut stream = client
            .subscribe_new_blocks(SubscribeNewBlocksRequest {})
            .await
            .unwrap()
            .into_inner();

        while let Some(new_block) = stream.message().await.unwrap() {
            tracing::info!("Received new block: {:?}", new_block);
            let new_block = NewBlock {
                hash: protos::from_bytes(&new_block.hash).unwrap(),
                number: new_block.number,
            };
            tx.send(new_block).unwrap();
        }
    }
}

#[async_trait]
impl PoolClient for RemotePoolClient {
    fn subscribe_new_blocks(&self) -> broadcast::Receiver<NewBlock> {
        self.rx.resubscribe()
    }
}
