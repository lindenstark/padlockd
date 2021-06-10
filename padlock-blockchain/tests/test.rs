use std::{error::Error, fs, time::SystemTime};

use padlock_blockchain::block::Block;
use padlock_blockchain::block::BlockHeader;
use padlock_blockchain::block::Entry;
use padlock_blockchain::block::MempoolEntry;
use padlock_blockchain::Blockchain;

use bls_signatures::{PrivateKey, Serialize};
use rand::{rngs::OsRng, RngCore};
use randomx_bindings::{RandomxDataset, RandomxFlags, RandomxVm};

// 3 blocks should be the minimum testing amount. If it is less than that, there is no difficulty
// adjustment
const TEST_BLOCKS_TO_MINE: usize = 10000;
const START_DIFFICULTY: f32 = 2048f32;

#[test]
fn add_one_block() -> Result<(), Box<dyn Error>> {
    let mut blockchain = make_blockchain("./add_one_block_test")?;

    blockchain.add_block(mine_block(&blockchain)?)?;

    fs::remove_dir_all("./add_one_block_test")?;
    Ok(())
}

/// Creates blocks, mines them, then adds them to the blockchain. 
#[test]
fn add_many_blocks() -> Result<(), Box<dyn Error>> {
    let mut blockchain = make_blockchain("./add_many_blocks_test")?;

    for _ in 0..TEST_BLOCKS_TO_MINE {
        let block = mine_block(&blockchain)?;

        blockchain.add_block(block)?;

        blockchain.info.network_adjusted_time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }

    fs::remove_dir_all("./add_many_blocks_test")?;
    Ok(())
}

#[test]
fn block_reorganization() -> Result<(), Box<dyn Error>> {
    let mut blockchain = make_blockchain("./block_reorganization_test")?;

    for _ in 0..TEST_BLOCKS_TO_MINE {
        blockchain.add_block(mine_block(&blockchain)?)?;

        blockchain.info.network_adjusted_time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    let old_blockchain_info = blockchain.info.clone();
    blockchain.add_block(mine_block(&blockchain)?)?;

    println!("deleting top block");
    blockchain.del_top_block()?;

    assert!(blockchain.info == old_blockchain_info);

    fs::remove_dir_all("./block_reorganization_test")?;
    Ok(())
}

fn make_blockchain(dir: &str) -> Result<Blockchain, Box<dyn Error>> {
    let _ = fs::remove_dir_all(dir);
    let mut blockchain = Blockchain::new(dir)?;

    blockchain.info.network_adjusted_time = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_secs();
    blockchain.info.difficulty = START_DIFFICULTY;

    Ok(blockchain)
}

/// This is a very inefficient, and single threaded miner, this is used purely for testing
fn mine_block(blockchain: &Blockchain) -> Result<Block, Box<dyn Error>> {
    let mut block = Block::new(
        blockchain.info.top_block_hash,
        blockchain.info.height + 1,
        vec![make_entry()?, make_entry()?],
        vec![0u8],
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_secs(),
        blockchain.info.difficulty,
        blockchain.info.entry_difficulty_multiplier,
        blockchain.info.max_allowed_entry_difficulty,
        [0u8; 32],
    )?;

    let difficulty_target =
            blockchain.info.difficulty
            - block.entry_difficulty()?
            * block.header.entry_difficulty_multiplier;

    let (randomx_input, block_hash) =
        find_randomx_input(&block.header, difficulty_target)?;

    block.randomx_input = randomx_input;
    block.hash = block_hash;

    println!("{:#?} \n {:x?}", &block.header, &block.hash);

    Ok(block)
}

fn find_randomx_input(
    header: &BlockHeader,
    difficulty: f32,
) -> Result<(Vec<u8>, [u8; 32]), Box<dyn Error>> {
    let header = header.clone();
    let key = header.concat();

    let flags = RandomxFlags::default() | RandomxFlags::FULLMEM;

    const THREADS: u8 = 8;
    let dataset = RandomxDataset::new(flags, &key, THREADS)?;
    let vm = RandomxVm::new_fast(flags, &dataset)?;

    let mut nonce = Nonce::new();

    let complete_hash: [u8; 32];

    loop {
        let hash = vm.hash(&nonce.0);

        let leading_zeros = {
            let mut leading_zeros = 0;
            for i in hash.iter() {
                leading_zeros += i.to_le().leading_zeros();
                if i.leading_zeros() < 8 {
                    break;
                }
            }
            leading_zeros as usize
        };

        if 2usize.pow(leading_zeros as u32) >= difficulty as usize {
            complete_hash = hash;
            break;
        }
        nonce.increment();
    }

    Ok((nonce.0, complete_hash))
}

struct Nonce(Vec<u8>);

impl Nonce {
    fn new() -> Self {
        Nonce(vec![0])
    }

    fn increment(&mut self) {
        for byte in self.0.iter_mut() {
            if byte < &mut 255 {
                *byte += 1;
                break;
            }
        }

        if self.0.last().unwrap() == &255 {
            self.0.push(0);
        }
    }
}

fn make_entry() -> Result<MempoolEntry, Box<dyn Error>> {
    let mut rng = OsRng::default();
    let private_key = PrivateKey::generate(&mut rng);
    let public_key = private_key.public_key();

    let mut coinfile_hash = [0u8; 8];
    rng.fill_bytes(&mut coinfile_hash);

    let mut entry = Entry::new(
        vec![coinfile_hash],
        [0u8; 8],
        Some(public_key.as_bytes()),
        None,
        vec![0],
    );

    let mut nonce = Nonce::new();

    loop {
        entry.proof_of_work = nonce.0.clone();
        if entry.difficulty().unwrap() > 4096 {
            break;
        }
        nonce.increment();
    }

    let signature = private_key.sign(entry.to_bytes()?).as_bytes();

    let mempool_entry = MempoolEntry::new(entry, signature);

    Ok(mempool_entry)
}
