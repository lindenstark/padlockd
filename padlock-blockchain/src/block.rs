use crate::randomx_bindings::{
    RandomxCache, RandomxError, RandomxFlags, RandomxVm,
};

use blake2::{Blake2b, Digest};
use bls_signatures::{PublicKey, Serialize, Signature};
use merkle_tree::MerkleTree;
use rocks::prelude::*;

use crate::KeyType;

use std::{convert::TryInto, error::Error, fmt};

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct Block {
    pub entries: Vec<Entry>,
    pub header: BlockHeader,
    pub randomx_input: Vec<u8>,
    pub hash: [u8; 32],
}

impl Block {
    pub fn new(
        previous_hash: [u8; 32],
        height: usize,
        mempool_entries: Vec<MempoolEntry>,
        randomx_input: Vec<u8>,
        timestamp: u64,
        difficulty_target: f32,
        entry_difficulty_multiplier: f32,
        max_allowed_entry_difficulty: f32,
        miner_address: [u8; 32],
    ) -> Result<Self, BlockError> {
        let mut signatures: Vec<Signature> = Vec::new();
        let mut entries: Vec<Entry> = Vec::new();

        for entry in mempool_entries {
            let signature = Signature::from_bytes(&entry.signature)?;
            signatures.push(signature);
            entries.push(entry.into());
        }

        let signature = bls_signatures::aggregate(&signatures)?.as_bytes();

        let block = Block::new_with_signature(
            previous_hash,
            height,
            entries,
            randomx_input,
            timestamp,
            difficulty_target,
            entry_difficulty_multiplier,
            max_allowed_entry_difficulty,
            miner_address,
            signature,
        )?;

        Ok(block)
    }

    pub fn new_with_signature(
        previous_hash: [u8; 32],
        height: usize,
        entries: Vec<Entry>,
        randomx_input: Vec<u8>,
        timestamp: u64,
        difficulty_target: f32,
        entry_difficulty_multiplier: f32,
        max_allowed_entry_difficulty: f32,
        miner_address: [u8; 32],
        signature: Vec<u8>,
    ) -> Result<Self, BlockError> {
        let merkle_tree = MerkleTree::new(&entries);
        let merkle_root = merkle_tree.root;

        let header = BlockHeader::new(
            previous_hash,
            height,
            merkle_root,
            timestamp,
            difficulty_target,
            0f32, // entry difficulty
            entry_difficulty_multiplier,
            max_allowed_entry_difficulty,
            miner_address,
            signature,
        );

        let flags = RandomxFlags::default();
        let cache = RandomxCache::new(flags, &header.concat())?;
        let vm = RandomxVm::new(flags, &cache)?;
        let hash = vm.hash(&randomx_input);

        let mut block = Block {
            entries,
            header,
            randomx_input,
            hash,
        };

        block.header.entry_difficulty = block.entry_difficulty()?;

        Ok(block)
    }

    pub fn miner_difficulty(&self) -> usize {
        let leading_zeros = {
            let mut leading_zeros = 0;
            for i in self.hash.iter() {
                leading_zeros += i.to_le().leading_zeros();
                if i.leading_zeros() < 8 {
                    break;
                }
            }
            leading_zeros
        };

        2usize.pow(leading_zeros)
    }

    pub fn entry_difficulty(&self) -> Result<f32, BlockError> {
        let mut entry_difficulty = 0f32;
        for entry in &self.entries {
            entry_difficulty += entry.difficulty()? as f32;
        }

        if entry_difficulty > self.header.max_allowed_entry_difficulty {
            entry_difficulty = self.header.max_allowed_entry_difficulty
        }
        
        Ok(entry_difficulty)
    }

    pub fn difficulty(&self) -> Result<f32, BlockError> {
        let miner_difficulty = self.miner_difficulty();
        let entry_difficulty = self.entry_difficulty()?;

        Ok(miner_difficulty as f32 + (entry_difficulty * self.header.entry_difficulty_multiplier))
    }

    pub fn calc_hash(&self) -> Result<[u8; 32], BlockError> {
        let key = self.header.concat();

        let flags = RandomxFlags::default();
        let cache = RandomxCache::new(flags, &key)?;
        let vm = RandomxVm::new(flags, &cache)?;
        let hash = vm.hash(&self.randomx_input);

        Ok(hash)
    }

    /// Collects every public key and message, then checks it against the aggregated signature of
    /// the block. Needs access to the databse in order to retrieve public keys from indexes.
    pub fn check_signature(&self, db: &rocks::db::DB) -> Result<(), BlockError> {
        // Get every public key from each entry
        let mut public_keys: Vec<PublicKey> = Vec::new();
        let mut messages: Vec<Vec<u8>> = Vec::new();

        for entry in &self.entries {
            if let Some(public_key_bytes) = &entry.public_key {

                let public_key = PublicKey::from_bytes(&public_key_bytes)?;
                public_keys.push(public_key);

            } else if let Some(public_key_index) = &entry.public_key_index {

                let public_key_index = public_key_index.to_le_bytes();

                let key =
                    KeyType::make_key(KeyType::PublicKey, &public_key_index);

                match db.get(ReadOptions::default_instance(), &key) {
					Ok(public_key_bytes) => {
		                let public_key = PublicKey::from_bytes(&public_key_bytes)?;
		              	public_keys.push(public_key);
					}
					
                	Err(_) => {
                		return Err(BlockError::new(BlockErrorKind::NoPublicKeyFound));
                	}
                }
            } else {
                return Err(BlockError::new(
                    BlockErrorKind::NoPublicKeyFound
                ));
            }

            let message = entry.to_bytes()?;
            messages.push(message);
        }

        // Convert messages to Vec<&[u8]>
        let messages: Vec<&[u8]> =
            messages.iter().map(|message| &message[..]).collect();

        let signature = Signature::from_bytes(&self.header.signature)?;
        if !bls_signatures::verify_messages(&signature, &messages, &public_keys)
        {
            return Err(BlockError::new(BlockErrorKind::InvalidSignature));
        }

        Ok(())
    }

    pub fn is_merkle_root_valid(&self) -> bool {
        let merkle_tree = MerkleTree::new(&self.entries);

        merkle_tree.root == self.header.merkle_root
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, BlockError> {
        let mut entries_bytes: Vec<Vec<u8>> = Vec::new();

        for entry in &self.entries {
            entries_bytes.push(entry.to_bytes()?);
        }

        let block_with_serialized_entries = BlockWithSerializedEntries {
            entries_bytes,
            header: self.header.clone(),
            randomx_input: self.randomx_input.clone(),
            hash: self.hash.clone()
        };

        let block_bytes = rmp_serde::to_vec(&block_with_serialized_entries)?;
        Ok(block_bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BlockError> {
        let block_with_serialized_entries: BlockWithSerializedEntries = rmp_serde::from_slice(bytes)?;

        let mut entries: Vec<Entry> = Vec::new();

        for entry_bytes in block_with_serialized_entries.entries_bytes {
            let entry = Entry::from_bytes(&entry_bytes)?;
            entries.push(entry);
        }

        let block = Block::new_with_signature(
            block_with_serialized_entries.header.previous_hash,
            block_with_serialized_entries.header.height,
            entries,
            block_with_serialized_entries.randomx_input,
            block_with_serialized_entries.header.timestamp,
            block_with_serialized_entries.header.difficulty_target,
            block_with_serialized_entries.header.entry_difficulty_multiplier,
            block_with_serialized_entries.header.max_allowed_entry_difficulty,
            block_with_serialized_entries.header.miner_address,
            block_with_serialized_entries.header.signature,
        )?;

        Ok(block)
    }
}

/// Because entries are serialized differently than everything else, this struct is for the mid
/// point in serialization; the entries have been serialized, but the rest hasn't.
#[derive(serde::Serialize, serde::Deserialize)]
struct BlockWithSerializedEntries {
    pub entries_bytes: Vec<Vec<u8>>,
    pub header: BlockHeader,
    pub randomx_input: Vec<u8>,
    pub hash: [u8; 32],
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct BlockHeader {
    pub previous_hash: [u8; 32],
    pub height: usize,
    pub merkle_root: [u8; 28],
    pub timestamp: u64,
    pub difficulty_target: f32,
    pub entry_difficulty: f32,
    pub entry_difficulty_multiplier: f32,
    pub max_allowed_entry_difficulty: f32,
    pub miner_address: [u8; 32],
    pub signature: Vec<u8>, // serde doesn't suport arrays past length 32, so vec is used
}

impl BlockHeader {
    pub fn new(
        previous_hash: [u8; 32],
        height: usize,
        merkle_root: [u8; 28],
        timestamp: u64,
        difficulty_target: f32,
        entry_difficulty: f32,
        entry_difficulty_multiplier: f32,
        max_allowed_entry_difficulty: f32,
        miner_address: [u8; 32],
        signature: Vec<u8>,
    ) -> Self {
        BlockHeader {
            previous_hash,
            height,
            merkle_root,
            timestamp,
            difficulty_target,
            entry_difficulty,
            entry_difficulty_multiplier,
            max_allowed_entry_difficulty,
            miner_address,
            signature,
        }
    }

    pub fn concat(&self) -> Vec<u8> {
        [
            self.previous_hash.to_vec(),
            self.height.to_le_bytes().into(),
            self.merkle_root.to_vec(),
            self.timestamp.to_le_bytes().into(),
            self.difficulty_target.to_le_bytes().into(),
            self.miner_address.to_vec(),
            self.signature.clone(),
        ]
        .concat()
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, PartialEq, Debug)]
pub struct Entry {
    pub coinfile_hashes: Vec<[u8; 8]>,
    pub output_hash: [u8; 8],
    pub public_key: Option<Vec<u8>>, // serde can't support arrays past 32, so a vec is used instead
    pub public_key_index: Option<u64>,
    pub proof_of_work: Vec<u8>,
}

impl Entry {
    pub fn new(
        coinfile_hashes: Vec<[u8; 8]>,
        output_hash: [u8; 8],
        public_key: Option<Vec<u8>>,
        public_key_index: Option<u64>,
        proof_of_work: Vec<u8>,
    ) -> Self {
        Self {
            coinfile_hashes,
            output_hash,
            public_key,
            public_key_index,
            proof_of_work,
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, BlockError> {
        if self.coinfile_hashes.len() > 255 {
            return Err(BlockError::new(BlockErrorKind::TooManyCoinfileHashes));
        }

        let coinfile_hashes_len = self.coinfile_hashes.len() as u8;

        let mut coinfile_hashes_bytes: Vec<u8> = Vec::new();
        for coinfile_hash in &self.coinfile_hashes {
            coinfile_hashes_bytes.append(&mut coinfile_hash.to_vec());
        }

        // 0 means it is a public_key, 1 means it is a public_key_index
        let mut is_public_key_index = 0u8;

        let mut public_key: Vec<u8> = match &self.public_key {
            Some(public_key) => public_key.clone(),
            None => {
                is_public_key_index = 1;
                self.public_key_index
                    .ok_or(BlockError::new(BlockErrorKind::NoPublicKeyFound))?
                    .to_le_bytes()
                    .to_vec()
            }
        };

        if self.proof_of_work.len() > u8::MAX as usize {
            return Err(BlockError::new(BlockErrorKind::PoWTooLong));
        }
        let proof_of_work_len = self.proof_of_work.len() as u8;

        let mut bytes: Vec<u8> = Vec::new();
        bytes.append(&mut coinfile_hashes_len.to_le_bytes().to_vec());
        bytes.append(&mut coinfile_hashes_bytes.to_vec());
        bytes.append(&mut self.output_hash.to_vec());
        bytes.append(&mut is_public_key_index.to_le_bytes().to_vec());
        bytes.append(&mut public_key);
        bytes.append(&mut proof_of_work_len.to_le_bytes().to_vec());
        bytes.append(&mut self.proof_of_work.clone());

        Ok(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BlockError> {
        let mut bytes = bytes.iter().copied();
        let coinfile_hashes_len = bytes.next().unwrap().clone() as usize;
        let mut coinfile_hashes = Vec::new();

        for _ in 0..coinfile_hashes_len {
            let coinfile_hash: Vec<u8> = (&mut bytes).take(8).collect();
            coinfile_hashes.push(coinfile_hash.try_into().unwrap());
        }

        let output_hash: Vec<u8> = (&mut bytes).take(8).collect();
        let output_hash: [u8; 8] = output_hash.try_into().unwrap();

        let is_public_key_index = bytes.next().unwrap().to_owned();
        let mut public_key = None;
        let mut public_key_index = None;

        if is_public_key_index == 0x00 {
            public_key = Some((&mut bytes).take(48).collect());
        } else if is_public_key_index == 0x01 {
            let public_key_index_bytes: Vec<u8> =
                (&mut bytes).take(8).collect();

            public_key_index = Some(u64::from_le_bytes(
                public_key_index_bytes.try_into().unwrap(),
            ));
        }

        let proof_of_work_len = bytes.next().unwrap().to_owned() as usize;
        let proof_of_work = bytes.take(proof_of_work_len).collect();

        Ok(Self {
            coinfile_hashes,
            output_hash,
            public_key,
            public_key_index,
            proof_of_work,
        })
    }

    fn hash(&self) -> Result<[u8; 64], BlockError> {
        let to_hash = self.to_bytes()?;

        let hash = Blake2b::digest(&to_hash)[..].try_into().unwrap();
        Ok(hash)
    }

    pub fn difficulty(&self) -> Result<usize, BlockError> {
        let leading_zeros = {
            let mut leading_zeros = 0;
            for i in self.hash()?.iter() {
                if i.leading_zeros() == 0 {
                    break;
                } else {
                    leading_zeros += i.leading_zeros();
                };
            }
            leading_zeros
        };

        Ok(2usize.pow(leading_zeros))
    }
}

#[cfg(test)]
impl Default for Entry {
    fn default() -> Self {
        Self {
            coinfile_hashes: vec![[0u8; 8]],
            output_hash: [0u8; 8],
            public_key: Some(vec![4u8; 48]),
            public_key_index: None,
            proof_of_work: vec![2u8; 4],
        }
    }
}

impl From<MempoolEntry> for Entry {
    fn from(mempool_entry: MempoolEntry) -> Self {
        mempool_entry.entry
    }
}

// An entry with a signature. Signatures aren't aggregated until they are added to a block, so
// until then they must be a MempoolEntry.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct MempoolEntry {
    entry: Entry,
    signature: Vec<u8>,
}

impl MempoolEntry {
    pub fn new(entry: Entry, signature: Vec<u8>) -> Self {
        Self {
            entry,
            signature,
        }
    }
}

#[test]
fn serialization_test() -> Result<(), Box<dyn Error>> {
    let mut entry = Entry::default();
    let bytes = entry.to_bytes()?;
    let new_entry = Entry::from_bytes(&bytes)?;

    assert!(entry == new_entry);

    entry.public_key = None;
    entry.public_key_index = Some(0u64);

    let bytes = entry.to_bytes()?;
    let new_entry = Entry::from_bytes(&bytes)?;
    assert!(entry == new_entry);

    Ok(())
}

impl From<Entry> for Vec<u8> {
    fn from(entry: Entry) -> Self {
        // Unwrap is okay as there are very few cases where serialization will
        // fail. If it does I will give whoever encounters it 20 CAD worth of
        // XPL
        entry.to_bytes().unwrap()
    }
}

#[derive(Debug)]
pub struct BlockError {
    kind: BlockErrorKind,
    source: Option<Box<dyn Error>>,
}

impl BlockError {
    fn new(kind: BlockErrorKind) -> Self {
        Self { kind, source: None }
    }
    fn from_source(error: Box<dyn Error>) -> Self {
        Self {
            kind: BlockErrorKind::Other,
            source: Some(error),
        }
    }
}

impl Error for BlockError {}

impl fmt::Display for BlockError {
    fn fmt(&self, formattor: &mut fmt::Formatter) -> fmt::Result {
        write!(formattor, "{:#?}", self)
    }
}

impl From<RandomxError> for BlockError {
    fn from(error: RandomxError) -> Self {
        BlockError::from_source(Box::new(error))
    }
}

impl From<rocks::error::Error> for BlockError {
    fn from(error: rocks::error::Error) -> Self {
        BlockError::from_source(Box::new(error))
    }
}

impl From<rmp_serde::encode::Error> for BlockError {
    fn from(error: rmp_serde::encode::Error) -> Self {
        BlockError::from_source(Box::new(error))
    }
}

impl From<rmp_serde::decode::Error> for BlockError {
    fn from(error: rmp_serde::decode::Error) -> Self {
        BlockError::from_source(Box::new(error))
    }
}

impl From<bls_signatures::Error> for BlockError {
    fn from(error: bls_signatures::Error) -> Self {
        BlockError::from_source(Box::new(error))
    }
}

#[derive(Debug)]
enum BlockErrorKind {
    NoPublicKeyFound,
    InvalidSignature,
    TooManyCoinfileHashes,
    PoWTooLong,
    Other,
}
