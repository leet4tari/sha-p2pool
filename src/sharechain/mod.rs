// Copyright 2024. The Tari Project
//
// Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
// following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following
// disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
// following disclaimer in the documentation and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote
// products derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
// INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
// WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
// USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use std::sync::Arc;

use async_trait::async_trait;
use minotari_app_grpc::tari_rpc::NewBlockCoinbase;
use tari_common_types::{tari_address::TariAddress, types::FixedHash};
use tari_core::{
    consensus::ConsensusManager,
    proof_of_work::{randomx_factory::RandomXFactory, AccumulatedDifficulty, Difficulty},
};

use crate::sharechain::{error::ShareChainError, p2block::P2Block, p2chain::ChainAddResult};

/// Chain ID is an identifier which makes sure we apply the same rules to blocks.
/// Note: This must be updated when new logic applied to blocks handling.
pub const CHAIN_ID: usize = 2;

/// Using 5 and 4 m,eans uncles get 80% of the reward
pub const MAIN_REWARD_SHARE: u64 = 5;
pub const UNCLE_REWARD_SHARE: u64 = 4;

pub const DIFFICULTY_ADJUSTMENT_WINDOW: usize = 90;

pub const MIN_RANDOMX_DIFFICULTY: u64 = 1_000; // 1 Khs every ten seconds
pub const MIN_SHA3X_DIFFICULTY: u64 = 100_000_000; // 1 Mhs every ten seconds

pub mod error;
pub mod in_memory;
pub(crate) mod lmdb_block_storage;
pub mod p2block;
pub mod p2chain;
mod p2chain_level;

pub struct BlockValidationParams {
    random_x_factory: RandomXFactory,
    consensus_manager: ConsensusManager,
    genesis_block_hash: FixedHash,
}

impl BlockValidationParams {
    pub fn new(
        random_x_factory: RandomXFactory,
        consensus_manager: ConsensusManager,
        genesis_block_hash: FixedHash,
    ) -> Self {
        Self {
            random_x_factory,
            consensus_manager,
            genesis_block_hash,
        }
    }

    pub fn random_x_factory(&self) -> &RandomXFactory {
        &self.random_x_factory
    }

    pub fn consensus_manager(&self) -> &ConsensusManager {
        &self.consensus_manager
    }

    pub fn genesis_block_hash(&self) -> &FixedHash {
        &self.genesis_block_hash
    }
}

#[async_trait]
pub(crate) trait ShareChain: Send + Sync + 'static {
    async fn get_total_chain_pow(&self) -> AccumulatedDifficulty;
    /// Adds a new block if valid to chain.
    async fn submit_block(&self, block: Arc<P2Block>) -> Result<ChainAddResult, ShareChainError>;

    /// Add multiple blocks at once.
    async fn add_synced_blocks(&self, blocks: &[Arc<P2Block>]) -> Result<ChainAddResult, ShareChainError>;

    /// Returns the tip of height in chain (from original Tari block header)
    async fn tip_height(&self) -> Result<u64, ShareChainError>;

    /// Returns the tip of the chain.
    async fn get_tip(&self) -> Result<Option<(u64, FixedHash)>, ShareChainError>;

    /// Generate shares based on the previous blocks.
    async fn generate_shares(
        &self,
        new_tip_block: &P2Block,
        solo_mine: bool,
    ) -> Result<Vec<NewBlockCoinbase>, ShareChainError>;

    /// Generate a new block on tip of the chain.
    async fn generate_new_tip_block(
        &self,
        miner_address: &TariAddress,
        coinbase_extra: Vec<u8>,
    ) -> Result<Arc<P2Block>, ShareChainError>;

    // /// Return a new block that could be added via `submit_block`.
    // async fn new_block(&self, request: &SubmitBlockRequest, squad: Squad) -> Result<P2Block, ShareChainError>;

    /// Returns the requested blocks from this chain
    async fn get_blocks(&self, requested_blocks: &[(u64, FixedHash)]) -> Vec<Arc<P2Block>>;

    async fn request_sync(
        &self,
        their_blocks: &[(u64, FixedHash)],
        limit: usize,
        last_block_received: Option<(u64, FixedHash)>,
    ) -> Result<(Vec<Arc<P2Block>>, Option<(u64, FixedHash)>, AccumulatedDifficulty), ShareChainError>;

    async fn get_target_difficulty(&self, height: u64) -> Difficulty;

    async fn all_blocks(
        &self,
        start_height: Option<u64>,
        page_size: usize,
        main_chain_only: bool,
    ) -> Result<Vec<Arc<P2Block>>, ShareChainError>;

    async fn chain_pow(&self) -> AccumulatedDifficulty;

    async fn create_catchup_sync_blocks(&self, size: usize) -> Vec<(u64, FixedHash)>;
}
