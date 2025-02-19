// This file is part of Rundler.
//
// Rundler is free software: you can redistribute it and/or modify it under the
// terms of the GNU Lesser General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later version.
//
// Rundler is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with Rundler.
// If not, see https://www.gnu.org/licenses/.

use std::{collections::HashMap, marker::PhantomData};

use alloy_eips::BlockId;
use alloy_primitives::BlockHash;
use alloy_provider::Provider as AlloyProvider;
use alloy_rpc_types_eth::{BlockNumberOrTag, BlockTransactionsKind};
use alloy_transport::Transport;
use parking_lot::RwLock;

use crate::ProviderResult;

struct BlockNumberCacheInner<AP, T> {
    inner: AP,
    block_hash_cache: RwLock<HashMap<BlockHash, BlockNumberOrTag>>,
    _marker: PhantomData<T>,
}

impl<AP, T> Clone for BlockNumberCacheInner<AP, T>
where
    AP: Clone,
{
    fn clone(&self) -> Self {
        BlockNumberCacheInner {
            inner: self.inner.clone(),
            block_hash_cache: RwLock::new(self.block_hash_cache.read().clone()),
            _marker: PhantomData,
        }
    }
}

impl<AP, T> BlockNumberCacheInner<AP, T> {
    fn new(provider: AP) -> Self {
        BlockNumberCacheInner {
            inner: provider,
            block_hash_cache: RwLock::new(HashMap::new()),
            _marker: PhantomData,
        }
    }
}

impl<AP, T> BlockNumberCacheInner<AP, T>
where
    T: Transport + Clone,
    AP: AlloyProvider<T>,
{
    async fn get_block_number_from_id(&self, block_id: BlockId) -> ProviderResult<BlockId> {
        match block_id {
            BlockId::Hash(block_hash) => {
                if let Some(&block_number) =
                    self.block_hash_cache.read().get(&block_hash.block_hash)
                {
                    return Ok(BlockId::Number(block_number));
                }

                match self
                    .inner
                    .get_block_by_hash(block_hash.block_hash, BlockTransactionsKind::Hashes)
                    .await?
                {
                    Some(block_data) => {
                        let block_number = BlockNumberOrTag::Number(block_data.header.number);
                        self.block_hash_cache
                            .write()
                            .insert(block_hash.block_hash, block_number);
                        Ok(BlockId::Number(block_number))
                    }
                    None => Ok(BlockId::Number(BlockNumberOrTag::Latest)),
                }
            }
            BlockId::Number(number) => Ok(BlockId::Number(number)),
        }
    }
}

/// Cache to map block hash to the block number
pub struct BlockNumberCache<AP, T>(BlockNumberCacheInner<AP, T>);

impl<AP, T> Clone for BlockNumberCache<AP, T>
where
    AP: Clone,
{
    fn clone(&self) -> Self {
        BlockNumberCache(self.0.clone())
    }
}

impl<AP, T> BlockNumberCache<AP, T> {
    /// Initializer function for the cache
    pub fn new(provider: AP) -> Self {
        BlockNumberCache(BlockNumberCacheInner::new(provider))
    }
}

impl<AP, T> BlockNumberCache<AP, T>
where
    T: Transport + Clone,
    AP: AlloyProvider<T>,
{
    pub(crate) async fn get_block_number_from_id(
        &self,
        block_id: BlockId,
    ) -> ProviderResult<BlockId> {
        self.0.get_block_number_from_id(block_id).await
    }
}
