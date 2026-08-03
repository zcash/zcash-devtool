// To silence lints in the `uint::construct_uint!` macro.
#![allow(clippy::assign_op_pattern)]
#![allow(clippy::manual_div_ceil)]
#![allow(clippy::ptr_offset_with_cast)]

use sha2::{Digest, Sha256};
use std::cmp;
use std::convert::{TryFrom, TryInto};
use std::io::{self, Read};
use zcash_client_backend::proto::compact_formats::CompactBlock;

use zcash_encoding::Vector;
use zcash_primitives::{block::BlockHeader, transaction::Transaction};
use zcash_protocol::consensus::{self, BlockHeight, BranchId, NetworkUpgrade, Parameters};

use crate::data::Network;

use super::{
    Context, ZUint256,
    transaction::{extract_height_from_coinbase, is_coinbase},
};

const MIN_BLOCK_VERSION: i32 = 4;

uint::construct_uint! {
    pub(crate) struct U256(4);
}

impl U256 {
    fn from_compact(compact: u32) -> (Self, bool, bool) {
        let size = compact >> 24;
        let word = compact & 0x007fffff;
        let result = if size <= 3 {
            U256::from(word >> (8 * (3 - size)))
        } else {
            U256::from(word) << (8 * (size - 3))
        };
        (
            result,
            word != 0 && (compact & 0x00800000) != 0,
            word != 0
                && ((size > 34) || (word > 0xff && size > 33) || (word > 0xffff && size > 32)),
        )
    }
}

pub(crate) trait BlockParams: Parameters {
    fn equihash_n(&self) -> u32;
    fn equihash_k(&self) -> u32;
    fn pow_limit(&self) -> U256;
}

// Consensus parameters from zcashd's chainparams.cpp: regtest is the only
// Zcash network with Equihash (48, 5) and a powLimit above testnet's.
impl BlockParams for Network {
    fn equihash_n(&self) -> u32 {
        match self {
            Self::Main | Self::Test => 200,
            #[cfg(feature = "regtest_support")]
            Self::Regtest(_) => 48,
        }
    }

    fn equihash_k(&self) -> u32 {
        match self {
            Self::Main | Self::Test => 9,
            #[cfg(feature = "regtest_support")]
            Self::Regtest(_) => 5,
        }
    }

    fn pow_limit(&self) -> U256 {
        match self {
            Self::Main => U256::from_big_endian(
                &hex::decode("0007ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                    .unwrap(),
            ),
            Self::Test => U256::from_big_endian(
                &hex::decode("07ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                    .unwrap(),
            ),
            #[cfg(feature = "regtest_support")]
            Self::Regtest(_) => U256::from_big_endian(
                &hex::decode("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f")
                    .unwrap(),
            ),
        }
    }
}

/// The encoded size of an Equihash (48, 5) solution: 2^5 indices of
/// 48/(5+1) + 1 = 9 bits each. Mainnet and testnet's (200, 9) solutions are
/// 1344 bytes, so the length alone identifies a regtest header.
#[cfg(feature = "regtest_support")]
const EQUIHASH_48_5_SOLUTION_SIZE: usize = 36;

pub(crate) fn guess_params(header: &BlockHeader) -> Option<Network> {
    // Regtest is the only Zcash network using Equihash (48, 5), whose
    // solution size differs from the (200, 9) networks.
    #[cfg(feature = "regtest_support")]
    if header.solution.len() == EQUIHASH_48_5_SOLUTION_SIZE {
        return Some(Network::default_regtest());
    }

    // If the block target falls between the testnet and mainnet powLimit, assume testnet.
    let (target, is_negative, did_overflow) = U256::from_compact(header.bits);
    if !(is_negative || did_overflow)
        && target > Network::Main.pow_limit()
        && target <= Network::Test.pow_limit()
    {
        return Some(Network::Test);
    }

    None
}

/// Maps an inspection context network (which can only name main or test) onto
/// the wallet network type that carries block consensus parameters.
fn from_context(network: consensus::Network) -> Network {
    match network {
        consensus::Network::MainNetwork => Network::Main,
        consensus::Network::TestNetwork => Network::Test,
    }
}

fn check_equihash_solution(header: &BlockHeader, params: Network) -> Result<(), equihash::Error> {
    let eh_input = {
        let mut eh_input = vec![];
        header.write(&mut eh_input).unwrap();
        eh_input.truncate(4 + 32 + 32 + 32 + 4 + 4);
        eh_input
    };
    equihash::is_valid_solution(
        params.equihash_n(),
        params.equihash_k(),
        &eh_input,
        &header.nonce,
        &header.solution,
    )
}

fn check_proof_of_work(header: &BlockHeader, params: Network) -> Result<(), &str> {
    let (target, is_negative, did_overflow) = U256::from_compact(header.bits);
    let hash = U256::from_little_endian(&header.hash().0);

    if is_negative {
        Err("nBits is negative")
    } else if target.is_zero() {
        Err("target is zero")
    } else if did_overflow {
        Err("nBits overflowed")
    } else if target > params.pow_limit() {
        Err("target is larger than powLimit")
    } else if hash > target {
        Err("block hash larger than target")
    } else {
        Ok(())
    }
}

fn derive_block_commitments_hash(
    chain_history_root: [u8; 32],
    auth_data_root: [u8; 32],
) -> [u8; 32] {
    blake2b_simd::Params::new()
        .hash_length(32)
        .personal(b"ZcashBlockCommit")
        .to_state()
        .update(&chain_history_root)
        .update(&auth_data_root)
        .update(&[0; 32])
        .finalize()
        .as_bytes()
        .try_into()
        .unwrap()
}

pub(crate) struct Block {
    header: BlockHeader,
    txs: Vec<Transaction>,
}

impl Block {
    pub(crate) fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let header = BlockHeader::read(&mut reader)?;
        let txs = Vector::read(reader, |r| Transaction::read(r, BranchId::Sprout))?;

        Ok(Block { header, txs })
    }

    pub(crate) fn guess_params(&self) -> Option<Network> {
        guess_params(&self.header)
    }

    fn extract_height(&self) -> Option<BlockHeight> {
        self.txs.first().and_then(extract_height_from_coinbase)
    }

    /// Builds the Merkle tree for this block and returns its root.
    ///
    /// The returned `bool` indicates whether mutation was detected in the Merkle tree (a
    /// duplication of transactions in the block leading to an identical Merkle root).
    fn build_merkle_root(&self) -> ([u8; 32], bool) {
        // Safe upper bound for the number of total nodes.
        let mut merkle_tree = Vec::with_capacity(self.txs.len() * 2 + 16);
        for tx in &self.txs {
            merkle_tree.push(sha2::digest::generic_array::GenericArray::from(
                *tx.txid().as_ref(),
            ));
        }
        let mut size = self.txs.len();
        let mut j = 0;
        let mut mutated = false;
        while size > 1 {
            let mut i = 0;
            while i < size {
                let i2 = cmp::min(i + 1, size - 1);
                if i2 == i + 1 && i2 + 1 == size && merkle_tree[j + i] == merkle_tree[j + i2] {
                    // Two identical hashes at the end of the list at a particular level.
                    mutated = true;
                }
                let mut inner_hasher = Sha256::new();
                inner_hasher.update(merkle_tree[j + i]);
                inner_hasher.update(merkle_tree[j + i2]);
                merkle_tree.push(Sha256::digest(inner_hasher.finalize()));
                i += 2;
            }
            j += size;
            size = size.div_ceil(2);
        }
        (
            merkle_tree
                .last()
                .copied()
                .map(|root| root.into())
                .unwrap_or([0; 32]),
            mutated,
        )
    }

    fn build_auth_data_root(&self) -> [u8; 32] {
        fn next_pow2(x: u64) -> u64 {
            // Fails if `x` is greater than `1u64 << 63`, but this can't occur because a
            // block can't feasibly contain that many transactions.
            1u64 << (64 - x.saturating_sub(1).leading_zeros())
        }

        let perfect_size = next_pow2(self.txs.len() as u64) as usize;
        assert_eq!((perfect_size & (perfect_size - 1)), 0);
        let expected_size = cmp::max(perfect_size * 2, 1) - 1; // The total number of nodes.
        let mut tree = Vec::with_capacity(expected_size);

        // Add the leaves to the tree. v1-v4 transactions will append empty leaves.
        for tx in &self.txs {
            tree.push(<[u8; 32]>::try_from(tx.auth_commitment().as_bytes()).unwrap());
        }
        // Append empty leaves until we get a perfect tree.
        tree.resize(perfect_size, [0; 32]);

        let mut j = 0;
        let mut layer_width = perfect_size;
        while layer_width > 1 {
            let mut i = 0;
            while i < layer_width {
                tree.push(
                    blake2b_simd::Params::new()
                        .hash_length(32)
                        .personal(b"ZcashAuthDatHash")
                        .to_state()
                        .update(&tree[j + i])
                        .update(&tree[j + i + 1])
                        .finalize()
                        .as_bytes()
                        .try_into()
                        .unwrap(),
                );
                i += 2;
            }

            // Move to the next layer.
            j += layer_width;
            layer_width /= 2;
        }

        assert_eq!(tree.len(), expected_size);
        tree.last().copied().unwrap_or([0; 32])
    }
}

pub(crate) fn inspect_header(header: &BlockHeader, context: Option<Context>) {
    eprintln!("Zcash block header");
    inspect_header_inner(
        header,
        guess_params(header).or_else(|| context.and_then(|c| c.network()).map(from_context)),
    );
}

fn inspect_header_inner(header: &BlockHeader, params: Option<Network>) {
    eprintln!(" - Hash: {}", header.hash());
    eprintln!(" - Version: {}", header.version);
    if header.version < MIN_BLOCK_VERSION {
        // zcashd: version-too-low
        eprintln!("⚠️  Version too low",);
    }
    if let Some(params) = params {
        eprintln!(" - Network: {}", params.name());
        #[cfg(feature = "regtest_support")]
        if matches!(params, Network::Regtest(_)) {
            eprintln!(
                "🔎 Regtest detected from the Equihash (48, 5) solution size; height-dependent checks use the default regtest activation heights"
            );
        }
        if let Err(e) = check_equihash_solution(header, params) {
            // zcashd: invalid-solution
            eprintln!("⚠️  Invalid Equihash solution: {e}");
        }
        if let Err(e) = check_proof_of_work(header, params) {
            // zcashd: high-hash
            eprintln!("⚠️  Invalid Proof-of-Work: {e}");
        }
    } else {
        eprintln!(
            "🔎 To check contextual rules, add \"network\" to context (either \"main\" or \"test\")"
        );
    }
}

/// Used when a block hash is resolved via lightwalletd.
pub(crate) fn inspect_block_hash(block: &CompactBlock, network: &'static str) {
    eprintln!("Zcash block hash");
    eprintln!(" - Network: {network}");
    eprintln!(" - Height: {}", block.height());
}

pub(crate) fn inspect(block: &Block, context: Option<Context>) {
    eprintln!("Zcash block");
    let params = block
        .guess_params()
        .or_else(|| context.as_ref().and_then(|c| c.network()).map(from_context));
    inspect_header_inner(&block.header, params);

    let height = match block.txs.len() {
        0 => {
            // zcashd: bad-cb-missing
            eprintln!("⚠️  Missing coinbase transaction");
            None
        }
        txs => {
            eprintln!(" - {txs} transaction(s) including coinbase");

            if !is_coinbase(&block.txs[0]) {
                // zcashd: bad-cb-missing
                eprintln!("⚠️  vtx[0] is not a coinbase transaction");
                None
            } else {
                let height = block.extract_height();
                match height {
                    Some(h) => eprintln!(" - Height: {h}"),
                    // zcashd: bad-cb-height
                    None => eprintln!("⚠️  No height in coinbase transaction"),
                }
                height
            }
        }
    };

    for (i, tx) in block.txs.iter().enumerate().skip(1) {
        if is_coinbase(tx) {
            // zcashd: bad-cb-multiple
            eprintln!("⚠️  vtx[{i}] is a coinbase transaction");
        }
    }

    let (merkle_root, merkle_root_mutated) = block.build_merkle_root();
    if merkle_root != block.header.merkle_root {
        // zcashd: bad-txnmrklroot
        eprintln!("⚠️  header.merkleroot doesn't match transaction Merkle tree root");
        eprintln!("   - merkleroot (calc): {}", ZUint256(merkle_root));
        eprintln!(
            "   - header.merkleroot: {}",
            ZUint256(block.header.merkle_root)
        );
    }
    if merkle_root_mutated {
        // zcashd: bad-txns-duplicate
        eprintln!("⚠️  Transaction Merkle tree is malleable");
    }

    // The rest of the checks require network parameters and a block height.
    let (params, height) = match (params, height) {
        (Some(params), Some(height)) => (params, height),
        _ => return,
    };

    if params.is_nu_active(NetworkUpgrade::Nu5, height) {
        if block.txs[0].expiry_height() != height {
            // zcashd: bad-cb-height
            eprintln!(
                "⚠️  [NU5] coinbase expiry height ({}) doesn't match coinbase scriptSig height ({})",
                block.txs[0].expiry_height(),
                height
            );
        }

        if let Some(chain_history_root) = context.and_then(|c| c.chainhistoryroot) {
            let auth_data_root = block.build_auth_data_root();
            let block_commitments_hash =
                derive_block_commitments_hash(chain_history_root.0, auth_data_root);

            if block_commitments_hash != block.header.final_sapling_root {
                // zcashd: bad-block-commitments-hash
                eprintln!(
                    "⚠️  [NU5] header.blockcommitments doesn't match ZIP 244 block commitment"
                );
                eprintln!("   - chainhistoryroot:        {chain_history_root}");
                eprintln!("   - authdataroot:            {}", ZUint256(auth_data_root));
                eprintln!(
                    "   - blockcommitments (calc): {}",
                    ZUint256(block_commitments_hash)
                );
                eprintln!(
                    "   - header.blockcommitments: {}",
                    ZUint256(block.header.final_sapling_root)
                );
            }
        } else {
            eprintln!("🔎 To check header.blockcommitments, add \"chainhistoryroot\" to context");
        }
    } else if Some(height) == params.activation_height(NetworkUpgrade::Heartwood) {
        if block.header.final_sapling_root != [0; 32] {
            // zcashd: bad-heartwood-root-in-block
            eprintln!(
                "⚠️  This is the block that activates Heartwood but header.blockcommitments is not null"
            );
        }
    } else if params.is_nu_active(NetworkUpgrade::Heartwood, height) {
        if let Some(chain_history_root) = context.and_then(|c| c.chainhistoryroot) {
            if chain_history_root.0 != block.header.final_sapling_root {
                // zcashd: bad-heartwood-root-in-block
                eprintln!(
                    "⚠️  [Heartwood] header.blockcommitments doesn't match provided chain history root"
                );
                eprintln!("   - chainhistoryroot:        {chain_history_root}");
                eprintln!(
                    "   - header.blockcommitments: {}",
                    ZUint256(block.header.final_sapling_root)
                );
            }
        } else {
            eprintln!("🔎 To check header.blockcommitments, add \"chainhistoryroot\" to context");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zcash_primitives::block::{BlockHash, BlockHeaderData};

    /// Equihash (200, 9) solution size, used by mainnet and testnet.
    const EQUIHASH_200_9_SOLUTION_SIZE: usize = 1344;

    fn header(bits: u32, solution_len: usize) -> BlockHeader {
        BlockHeaderData {
            version: 4,
            prev_block: BlockHash([0; 32]),
            merkle_root: [0; 32],
            final_sapling_root: [0; 32],
            time: 0,
            bits,
            nonce: [0; 32],
            solution: vec![0; solution_len],
        }
        .freeze()
        .expect("header serializes")
    }

    /// zcashd testnet genesis nBits, which encodes exactly the testnet
    /// powLimit -- above mainnet's limit, so it identifies testnet.
    const TESTNET_POW_LIMIT_BITS: u32 = 0x2007ffff;

    #[test]
    fn guess_params_identifies_testnet_by_target_range() {
        let guessed = guess_params(&header(
            TESTNET_POW_LIMIT_BITS,
            EQUIHASH_200_9_SOLUTION_SIZE,
        ));
        assert!(matches!(guessed, Some(Network::Test)));
    }

    #[test]
    fn guess_params_cannot_distinguish_mainnet() {
        // A target below mainnet's powLimit is valid on every network, so
        // nothing can be inferred from it.
        let guessed = guess_params(&header(0x1d00ffff, EQUIHASH_200_9_SOLUTION_SIZE));
        assert!(guessed.is_none());
    }

    #[cfg(feature = "regtest_support")]
    #[test]
    fn guess_params_identifies_regtest_by_solution_size() {
        // Regtest's Equihash (48, 5) solution size differs from the 1344
        // bytes of the (200, 9) networks, regardless of the target.
        let guessed = guess_params(&header(0x200f0f0f, EQUIHASH_48_5_SOLUTION_SIZE));
        assert!(matches!(guessed, Some(Network::Regtest(_))));
    }

    #[cfg(feature = "regtest_support")]
    #[test]
    fn regtest_block_params_match_zcashd_chainparams() {
        // https://github.com/zcash/zcash/blob/master/src/chainparams.cpp (CRegTestParams)
        let params = Network::default_regtest();
        assert_eq!(params.equihash_n(), 48);
        assert_eq!(params.equihash_k(), 5);
        assert_eq!(params.pow_limit(), U256::from_big_endian(&[0x0f; 32]),);
        // The powLimit ordering the testnet guess relies on: main < test < regtest.
        assert!(Network::Main.pow_limit() < Network::Test.pow_limit());
        assert!(Network::Test.pow_limit() < params.pow_limit());
    }
}
