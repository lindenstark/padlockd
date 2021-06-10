extern crate bls_signatures;
extern crate merkle_tree;
extern crate randomx_bindings;
extern crate rmp_serde;

extern crate serde;
use serde::{Deserialize, Serialize};

extern crate rocksdb;
use rocksdb::DB;

pub mod block;
use block::{Block, BlockHeader};

use std::{error::Error, fmt, time::SystemTime};

const BLOCK_TIME: f32 = 90f32; // target interval between blocks in seconds

// The amount of blocks to consider when getting averages, such as average difficulty
const PREVIOUS_BLOCKS_TO_CONSIDER: usize = 750;

pub struct Blockchain {
    pub db_dir: String,
    pub info: BlockchainInfo,
    pub db: DB,
}

impl Blockchain {
    pub fn new(db_dir: &str) -> Result<Self, Box<dyn Error>> {
        let db = DB::open_default(&db_dir)?;

        let info = match db.get(b"blockchain_info")? {
            Some(blockchain_info_bytes) => {
                rmp_serde::from_slice(&blockchain_info_bytes)?
            }
            None => {
                let blockchain_info = BlockchainInfo::default();
                db.put(
                    b"blockchain_info",
                    rmp_serde::to_vec(&blockchain_info)?,
                )?;
                blockchain_info
            }
        };

        Ok(Blockchain {
            db_dir: String::from(db_dir),
            info,
            db,
        })
    }

    pub fn get_block(&self, hash: &[u8]) -> Result<Block, BlockchainError> {
        let block_bytes = self.db.get(hash)?.ok_or(BlockchainError::new(
            BlockchainErrorKind::BlockDoesntExist,
        ))?;
        let block = Block::from_bytes(&block_bytes)?;
        Ok(block)
    }

    pub fn add_block(&mut self, block: Block) -> Result<(), BlockchainError> {
        if self.get_block(&block.hash).is_ok() {
            return Err(BlockchainError::new(
                BlockchainErrorKind::BlockAlreadyExists,
            ));
        }

        if block.header.height > self.info.height + 1 {
            return Err(BlockchainError::new(
                BlockchainErrorKind::SkippedBlock,
            ));
        }

        if block.header.height < self.info.height + 1 {
            return Err(BlockchainError::new(
                BlockchainErrorKind::BlockNotAtTop,
            ));
        }

        if block.header.previous_hash != self.info.top_block_hash {
            return Err(BlockchainError::new(
                BlockchainErrorKind::BlockPreviousHashWrong,
            ));
        }

        if block.header.difficulty_target != self.info.difficulty {
            return Err(BlockchainError::new(
                BlockchainErrorKind::BlockTargetDifficultyWrong,
            ));
        }

        if block.header.timestamp < self.info.past_median_timestamp {
            return Err(BlockchainError::new(
                BlockchainErrorKind::BlockTimestampTooEarly,
            ));
        }

        if block.header.timestamp > self.info.network_adjusted_time + 3600 {
            return Err(BlockchainError::new(
                BlockchainErrorKind::BlockInFuture,
            ));
        }

        if block.difficulty()? < self.info.difficulty {
            return Err(BlockchainError::new(
                BlockchainErrorKind::BlockNotEnoughWork,
            ));
        }

        if block.header.entry_difficulty != block.entry_difficulty()? {
            return Err(BlockchainError::new(
                BlockchainErrorKind::BlockEntryDifficultyWrong,
            ));
        }

        if block.header.max_allowed_entry_difficulty
            != self.info.max_allowed_entry_difficulty
        {
            return Err(BlockchainError::new(
                BlockchainErrorKind::BlockMaxAllowedEntryDifficultyWrong,
            ));
        }

        if !block.is_merkle_root_valid() {
            return Err(BlockchainError::new(
                BlockchainErrorKind::InvalidMerkleRoot,
            ));
        }

        let block_bytes = block.to_bytes()?;
        if block_bytes.len() > self.info.block_size_cap {
            return Err(BlockchainError::new(BlockchainErrorKind::BlockTooBig));
        }

        if block.check_signature(&self.db).is_err() {
            return Err(BlockchainError::new(BlockchainErrorKind::InvalidSignature))
        }

        let calculated_hash = block.calc_hash()?;
        if calculated_hash != block.hash {
            return Err(BlockchainError::new(BlockchainErrorKind::InvalidHash));
        }

        self.info.height += 1;
        self.info.top_block_hash = block.hash;
        self.info.is_empty = false;

        let key = KeyType::make_key(KeyType::Block, &block.hash);
        self.db.put(key, block_bytes)?;

        self.add_block_hash(&block)?;
        self.add_block_header(&block)?;

        self.update_median_timestamp()?;
        self.update_difficulty()?;
        self.update_entry_difficulty_limits()?;

        Ok(())
    }

    /// removes the top block from the blockchain
    pub fn del_top_block(&mut self) -> Result<(), BlockchainError> {
        let block_hash = self.get_block_hash(self.info.height)?;
        let block_header = self.get_block_header(&block_hash)?;

        self.del_block_hash(block_header.height)?;
        self.del_block_header(&block_hash)?;

        self.info.top_block_hash = block_header.previous_hash;
        self.info.height -= 1;

        let key = KeyType::make_key(KeyType::Block, &block_hash);
        self.db.delete(&key)?;

        self.update_median_timestamp()?;
        self.update_difficulty()?;
        self.update_entry_difficulty_limits()?;

        Ok(())
    }

    /// Adds the block's hash to the database, where the key is the block's
    /// height. Useful for accessing blocks without knowing their hash, and
    /// only knowing their height.
    fn add_block_hash(&self, block: &Block) -> Result<(), BlockchainError> {
        let key = KeyType::make_key(
            KeyType::BlockHeight,
            &block.header.height.to_le_bytes(),
        );
        self.db.put(key, block.hash)?;
        Ok(())
    }

    // Gets a blocks hash from it's height
    fn get_block_hash(
        &self,
        height: usize,
    ) -> Result<Vec<u8>, BlockchainError> {
        let key =
            KeyType::make_key(KeyType::BlockHeight, &height.to_le_bytes());

        let hash = self.db.get(key)?.ok_or(BlockchainError::new(
            BlockchainErrorKind::CantFindHashFromHeight,
        ))?;
        Ok(hash)
    }

    fn del_block_hash(&self, height: usize) -> Result<(), BlockchainError> {
        let key =
            KeyType::make_key(KeyType::BlockHeight, &height.to_le_bytes());
        self.db.delete(key)?;

        Ok(())
    }

    fn get_block_header(
        &self,
        hash: &[u8],
    ) -> Result<BlockHeader, BlockchainError> {
        let key = KeyType::make_key(KeyType::BlockHeader, hash);
        let header_bytes = self.db.get(key)?.ok_or(BlockchainError::new(
            BlockchainErrorKind::BlockHeaderDoesntExist,
        ))?;

        let header = rmp_serde::from_slice(&header_bytes)?;

        Ok(header)
    }

    fn add_block_header(&self, block: &Block) -> Result<(), BlockchainError> {
        let key = KeyType::make_key(KeyType::BlockHeader, &block.hash);
        let header_bytes = rmp_serde::to_vec(&block.header)?;

        self.db.put(key, &header_bytes)?;

        Ok(())
    }

    fn del_block_header(&self, hash: &[u8]) -> Result<(), BlockchainError> {
        let key = KeyType::make_key(KeyType::BlockHeader, &hash);
        self.db.delete(key)?;

        Ok(())
    }

    fn get_previous_n_block_headers(
        &self,
        amount: usize,
    ) -> Result<Vec<BlockHeader>, BlockchainError> {
        let mut block_headers: Vec<BlockHeader> = Vec::new();

        for i in 0..amount as isize {
            let block_index = self.info.height as isize - i;
            if block_index < 1 {
                break;
            }

            let block_hash = self.get_block_hash(block_index as usize)?;
            let block_header = self.get_block_header(&block_hash)?;
            block_headers.push(block_header)
        }
        Ok(block_headers)
    }

    /// The median timstamp is the median timestamp of the previous 21 blocks. If the current
    /// blockchain height is less than 11, it will choose the timestamp of the first block.
    fn update_median_timestamp(&mut self) -> Result<(), BlockchainError> {
        if self.info.height < 1 {
            return Ok(());
        }

        let mut block_index = self.info.height as isize - 11;
        if block_index < 1 {
            block_index = 1;
        }

        let block_hash = self.get_block_hash(block_index as usize)?;

        let block_header = self.get_block_header(&block_hash)?;

        self.info.past_median_timestamp = block_header.timestamp;

        Ok(())
    }

    fn update_difficulty(&mut self) -> Result<(), BlockchainError> {
        if self.info.height < 2 {
            return Ok(());
        }

        let block_headers = self.get_previous_n_block_headers(PREVIOUS_BLOCKS_TO_CONSIDER)?;

        let average_difficulty = {
            let mut total = 0u128;

            for header in &block_headers {
                total += header.difficulty_target as u128;
            }

            total as f32 / block_headers.len() as f32
        };

        println!("average difficulty: {}", average_difficulty);

        let average_block_time = {
            let mut total = 0i128;

            for (i, header) in block_headers.iter().enumerate().skip(1) {
                let last_header = &block_headers[i - 1];
                let block_time =
                    last_header.timestamp as i128 - header.timestamp as i128;
                total += block_time
            }

            total as f32 / block_headers.len() as f32
        };

        println!("average block time: {}", average_block_time);

        let network_hash_rate = average_difficulty / average_block_time;

        println!("network hash rate: {}", network_hash_rate);

        self.info.difficulty = network_hash_rate * BLOCK_TIME;

        Ok(())
    }

    fn update_entry_difficulty_limits(
        &mut self,
    ) -> Result<(), BlockchainError> {
        if self.info.height < 2 {
            return Ok(());
        }

        let block_headers = self.get_previous_n_block_headers(PREVIOUS_BLOCKS_TO_CONSIDER)?;

        let average_difficulty = {
            let mut total = 0u128;
            for header in &block_headers {
                total += header.difficulty_target as u128;
            }

            total as f32 / block_headers.len() as f32
        };

        let average_entry_difficulty = {
            let mut total = 0u128;
            for header in &block_headers {
                total += header.entry_difficulty as u128;
            }

            total as f32 / block_headers.len() as f32
        };

        println!("average entry difficulty: {}", average_entry_difficulty);

        self.info.entry_difficulty_multiplier =
            (average_difficulty * 0.05) / average_entry_difficulty;

        self.info.max_allowed_entry_difficulty =
            average_entry_difficulty * 1.5;

        Ok(())
    }
}

/// Contains information about the state of the blockchain
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq)]
pub struct BlockchainInfo {
    pub is_empty: bool,
    pub top_block_hash: [u8; 32],
    pub past_median_timestamp: u64,
    pub network_adjusted_time: u64,
    pub difficulty: f32,
    pub entry_difficulty_multiplier: f32,
    pub max_allowed_entry_difficulty: f32,
    pub block_size_cap: usize,
    pub height: usize,
}

impl Default for BlockchainInfo {
    fn default() -> Self {
        BlockchainInfo {
            is_empty: true,
            top_block_hash: [0u8; 32],
            past_median_timestamp: 0,
            network_adjusted_time: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            difficulty: 256f32,
            entry_difficulty_multiplier: 0.005,
            max_allowed_entry_difficulty: 4096f32,
            block_size_cap: 250000,
            height: 0,
        }
    }
}

/// Every key starts with a byte that determines what type of key it is.
enum KeyType {
    Block,
    BlockHeader,
    BlockHeight,
    PublicKey,
}

impl KeyType {
    fn make_key(key_type: KeyType, key: &[u8]) -> Vec<u8> {
        let mut key = key.to_vec();
        key.push(key_type.value());
        key.rotate_right(1);
        key
    }

    fn value(&self) -> u8 {
        match self {
            &Self::Block => 0x01,
            &Self::BlockHeader => 0x02,
            &Self::BlockHeight => 0x03,
            &Self::PublicKey => 0x04,
        }
    }
}

#[derive(Debug)]
pub struct BlockchainError {
    kind: BlockchainErrorKind,
    source: Option<Box<dyn Error>>,
}

impl BlockchainError {
    fn new(kind: BlockchainErrorKind) -> Self {
        Self { kind, source: None }
    }

    fn from_source(error: Box<dyn Error>) -> Self {
        Self {
            kind: BlockchainErrorKind::Other,
            source: Some(error),
        }
    }
}

impl Error for BlockchainError {}

impl fmt::Display for BlockchainError {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "{:?}", self)
    }
}

impl From<rocksdb::Error> for BlockchainError {
    fn from(error: rocksdb::Error) -> Self {
        BlockchainError::from_source(Box::new(error))
    }
}

impl From<rmp_serde::encode::Error> for BlockchainError {
    fn from(error: rmp_serde::encode::Error) -> Self {
        BlockchainError::from_source(Box::new(error))
    }
}

impl From<rmp_serde::decode::Error> for BlockchainError {
    fn from(error: rmp_serde::decode::Error) -> Self {
        BlockchainError::from_source(Box::new(error))
    }
}

impl From<block::BlockError> for BlockchainError {
    fn from(error: block::BlockError) -> Self {
        BlockchainError::from_source(Box::new(error))
    }
}

#[derive(Debug)]
enum BlockchainErrorKind {
    BlockDoesntExist,
    SkippedBlock,
    BlockNotAtTop,
    BlockTimestampTooEarly,
    BlockTooBig,
    BlockAlreadyExists,
    BlockNotEnoughWork,
    InvalidHash,
    BlockPreviousHashWrong,
    BlockTargetDifficultyWrong,
    BlockInFuture,
    InvalidMerkleRoot,
    CantFindHashFromHeight,
    BlockHeaderDoesntExist,
    BlockEntryDifficultyWrong,
    BlockMaxAllowedEntryDifficultyWrong,
    InvalidSignature,
    Other,
}
