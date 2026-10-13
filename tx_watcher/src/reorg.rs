//! Chain reorganization detection and handling
//!
//! Tracks block hashes to detect when the canonical chain changes,
//! and invalidates any transactions that were confirmed on orphaned blocks.

use alloy::primitives::{B256, BlockHash};
use std::collections::{BTreeMap, HashMap, HashSet};
use tracing::{debug, warn};

/// Maximum number of recent blocks to track for reorg detection
const MAX_BLOCK_HISTORY: usize = 256;

/// Block info for reorg tracking
#[derive(Debug, Clone)]
pub struct BlockInfo {
    pub number: u64,
    pub hash: BlockHash,
    pub parent_hash: BlockHash,
}

/// Transaction confirmed in a specific block
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ConfirmedTx {
    pub tx_hash: B256,
    pub wallet: String,
    pub nonce: u64,
    pub block_number: u64,
    pub block_hash: BlockHash,
    pub confirmed_at_block: u64,
}

/// Result of processing a new block
#[derive(Debug)]
#[allow(dead_code)]
pub struct ReorgCheckResult {
    /// Depth of reorg (0 = no reorg)
    pub reorg_depth: u64,
    /// Blocks that were orphaned
    pub orphaned_blocks: Vec<BlockInfo>,
    /// Transactions that need to be re-validated
    pub affected_tx_hashes: Vec<B256>,
}

/// Tracks recent blocks and detects chain reorganizations
pub struct ReorgDetector {
    /// Recent blocks by number (for quick lookup)
    blocks_by_number: BTreeMap<u64, BlockInfo>,
    /// Block hash to number mapping
    hash_to_number: HashMap<BlockHash, u64>,
    /// Transactions confirmed in recent blocks (block_hash -> txs)
    confirmed_txs: HashMap<BlockHash, Vec<ConfirmedTx>>,
    /// All tracked tx hashes for quick lookup
    tracked_tx_hashes: HashSet<B256>,
    /// Finality threshold - transactions older than this are considered final
    finality_blocks: u64,
}

impl ReorgDetector {
    pub fn new(finality_blocks: u64) -> Self {
        Self {
            blocks_by_number: BTreeMap::new(),
            hash_to_number: HashMap::new(),
            confirmed_txs: HashMap::new(),
            tracked_tx_hashes: HashSet::new(),
            finality_blocks,
        }
    }

    /// Process a new block and check for reorgs
    pub fn process_block(&mut self, block: BlockInfo) -> ReorgCheckResult {
        let mut result = ReorgCheckResult {
            reorg_depth: 0,
            orphaned_blocks: Vec::new(),
            affected_tx_hashes: Vec::new(),
        };

        // Check if this block's parent matches our chain
        if let Some(expected_parent) = self.blocks_by_number.get(&(block.number.saturating_sub(1)))
            && expected_parent.hash != block.parent_hash
        {
            // Reorg detected! Find the fork point
            result = self.handle_reorg(&block);
        }

        // Add the new block
        self.add_block(block.clone());

        // Prune old blocks beyond finality
        self.prune_old_blocks(block.number);

        result
    }

    /// Add a block to our tracking
    fn add_block(&mut self, block: BlockInfo) {
        // Remove any existing block at this height (in case of reorg)
        if let Some(old_block) = self.blocks_by_number.remove(&block.number) {
            self.hash_to_number.remove(&old_block.hash);
            self.confirmed_txs.remove(&old_block.hash);
        }

        self.hash_to_number.insert(block.hash, block.number);
        self.blocks_by_number.insert(block.number, block);
    }

    /// Handle a detected reorganization
    fn handle_reorg(&mut self, new_block: &BlockInfo) -> ReorgCheckResult {
        let mut orphaned_blocks = Vec::new();
        let mut affected_tx_hashes = Vec::new();

        // Find the fork point by looking up new_block's parent_hash in our chain.
        // hash_to_number maps every tracked block hash to its block number, so a
        // successful lookup means new_block's direct parent exists on our chain and
        // that is the common ancestor.  If the parent isn't tracked we conservatively
        // treat block 0 as the fork point so that every block we hold above it gets
        // orphaned.
        let fork_number = if new_block.number == 0 {
            // Genesis block can never cause a reorg we need to handle.
            return ReorgCheckResult {
                reorg_depth: 0,
                orphaned_blocks: vec![],
                affected_tx_hashes: vec![],
            };
        } else if let Some(&num) = self.hash_to_number.get(&new_block.parent_hash) {
            // new_block's parent exists in our chain – that is the fork point.
            num
        } else {
            // Parent not tracked; orphan everything we hold below new_block.number.
            0
        };

        // Every block we have at heights (fork_number + 1) ..= new_block.number is
        // on the old chain and must be orphaned.  new_block.number itself is included
        // because it is being replaced by the incoming block.
        let orphan_start = fork_number + 1;
        let orphan_end = new_block.number; // inclusive

        for block_num in orphan_start..=orphan_end {
            if let Some(our_block) = self.blocks_by_number.get(&block_num) {
                orphaned_blocks.push(our_block.clone());

                if let Some(txs) = self.confirmed_txs.get(&our_block.hash) {
                    for tx in txs {
                        affected_tx_hashes.push(tx.tx_hash);
                    }
                }
            }
        }

        let reorg_depth = orphaned_blocks.len() as u64;

        if reorg_depth > 0 {
            warn!(
                reorg_depth,
                orphaned_blocks = orphaned_blocks.len(),
                affected_txs = affected_tx_hashes.len(),
                new_block_number = new_block.number,
                new_block_hash = ?new_block.hash,
                "Chain reorganization detected"
            );

            // Remove orphaned blocks from our tracking
            for block in &orphaned_blocks {
                self.blocks_by_number.remove(&block.number);
                self.hash_to_number.remove(&block.hash);

                // Remove confirmed txs from orphaned blocks
                if let Some(txs) = self.confirmed_txs.remove(&block.hash) {
                    for tx in txs {
                        self.tracked_tx_hashes.remove(&tx.tx_hash);
                    }
                }
            }
        }

        ReorgCheckResult {
            reorg_depth,
            orphaned_blocks,
            affected_tx_hashes,
        }
    }

    /// Record a transaction as confirmed in a specific block
    pub fn record_confirmed_tx(&mut self, tx: ConfirmedTx) {
        debug!(
            tx_hash = ?tx.tx_hash,
            block_number = tx.block_number,
            block_hash = ?tx.block_hash,
            "Recording confirmed transaction for reorg tracking"
        );

        self.tracked_tx_hashes.insert(tx.tx_hash);
        self.confirmed_txs
            .entry(tx.block_hash)
            .or_default()
            .push(tx);
    }

    /// Remove a transaction from tracking (e.g., after finality reached)
    pub fn remove_tx(&mut self, tx_hash: &B256) {
        self.tracked_tx_hashes.remove(tx_hash);

        // Also remove from confirmed_txs (less efficient but maintains consistency)
        for txs in self.confirmed_txs.values_mut() {
            txs.retain(|tx| tx.tx_hash != *tx_hash);
        }
    }

    /// Check if a transaction is being tracked
    #[allow(dead_code)]
    pub fn is_tracking(&self, tx_hash: &B256) -> bool {
        self.tracked_tx_hashes.contains(tx_hash)
    }

    /// Get transactions that have reached finality (can stop tracking)
    pub fn get_finalized_txs(&self, current_block: u64) -> Vec<ConfirmedTx> {
        let finality_cutoff = current_block.saturating_sub(self.finality_blocks);

        let mut finalized = Vec::new();

        for (block_hash, txs) in &self.confirmed_txs {
            if let Some(&block_number) = self.hash_to_number.get(block_hash)
                && block_number <= finality_cutoff
            {
                finalized.extend(txs.clone());
            }
        }

        finalized
    }

    /// Prune blocks older than finality threshold
    fn prune_old_blocks(&mut self, current_block: u64) {
        let cutoff = current_block.saturating_sub(MAX_BLOCK_HISTORY as u64);

        // Collect blocks to remove
        let to_remove: Vec<u64> = self
            .blocks_by_number
            .range(..cutoff)
            .map(|(&n, _)| n)
            .collect();

        for block_number in to_remove {
            if let Some(block) = self.blocks_by_number.remove(&block_number) {
                self.hash_to_number.remove(&block.hash);

                // Remove confirmed txs from pruned blocks (they're final now)
                if let Some(txs) = self.confirmed_txs.remove(&block.hash) {
                    for tx in txs {
                        self.tracked_tx_hashes.remove(&tx.tx_hash);
                    }
                }
            }
        }
    }

    /// Get the latest block we're tracking
    #[allow(dead_code)]
    pub fn latest_block(&self) -> Option<&BlockInfo> {
        self.blocks_by_number.values().next_back()
    }

    /// Get block by number
    pub fn get_block(&self, number: u64) -> Option<&BlockInfo> {
        self.blocks_by_number.get(&number)
    }

    /// Get block by hash
    #[allow(dead_code)]
    pub fn get_block_by_hash(&self, hash: &BlockHash) -> Option<&BlockInfo> {
        self.hash_to_number
            .get(hash)
            .and_then(|&n| self.blocks_by_number.get(&n))
    }

    /// Get count of tracked blocks
    #[allow(dead_code)]
    pub fn tracked_block_count(&self) -> usize {
        self.blocks_by_number.len()
    }

    /// Get count of tracked transactions
    #[allow(dead_code)]
    pub fn tracked_tx_count(&self) -> usize {
        self.tracked_tx_hashes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_block(number: u64, hash: u8, parent_hash: u8) -> BlockInfo {
        BlockInfo {
            number,
            hash: B256::from([hash; 32]),
            parent_hash: B256::from([parent_hash; 32]),
        }
    }

    fn make_tx(
        tx_hash: u8,
        wallet: &str,
        nonce: u64,
        block_number: u64,
        block_hash: u8,
    ) -> ConfirmedTx {
        ConfirmedTx {
            tx_hash: B256::from([tx_hash; 32]),
            wallet: wallet.to_string(),
            nonce,
            block_number,
            block_hash: B256::from([block_hash; 32]),
            confirmed_at_block: block_number + 12,
        }
    }

    #[test]
    fn test_no_reorg() {
        let mut detector = ReorgDetector::new(12);

        // Add sequential blocks
        let result1 = detector.process_block(make_block(100, 1, 0));
        assert_eq!(result1.reorg_depth, 0);

        let result2 = detector.process_block(make_block(101, 2, 1));
        assert_eq!(result2.reorg_depth, 0);

        let result3 = detector.process_block(make_block(102, 3, 2));
        assert_eq!(result3.reorg_depth, 0);
    }

    #[test]
    fn test_single_block_reorg() {
        let mut detector = ReorgDetector::new(12);

        // Build initial chain: 100 -> 101 -> 102
        detector.process_block(make_block(100, 1, 0));
        detector.process_block(make_block(101, 2, 1));
        detector.process_block(make_block(102, 3, 2));

        // Reorg: new block 103 claims parent is block 101 (hash=2), not block 102 (hash=3)
        // This means block 102 is orphaned
        let result = detector.process_block(make_block(103, 33, 2));

        // The reorg detection checks if block 102's hash matches the new block's parent
        // Block 102 has hash=3, new block has parent_hash=2, so block 102 is orphaned
        assert_eq!(result.reorg_depth, 1);
        assert_eq!(result.orphaned_blocks.len(), 1);
        assert_eq!(result.orphaned_blocks[0].hash, B256::from([3; 32]));
    }

    #[test]
    fn test_multi_block_reorg() {
        let mut detector = ReorgDetector::new(12);

        // Build initial chain: 100(hash=1) -> 101(hash=2) -> 102(hash=3) -> 103(hash=4)
        detector.process_block(make_block(100, 1, 0));
        detector.process_block(make_block(101, 2, 1));
        detector.process_block(make_block(102, 3, 2));
        detector.process_block(make_block(103, 4, 3));

        // New block 104 arrives whose parent_hash points to block 101 (hash=2),
        // skipping blocks 102 and 103.  Both 102 and 103 are on the old chain and
        // must be orphaned.
        let result = detector.process_block(make_block(104, 44, 2));

        assert_eq!(
            result.reorg_depth, 2,
            "blocks 102 and 103 should both be orphaned"
        );
        assert_eq!(result.orphaned_blocks.len(), 2);

        // Orphaned set must contain block 102 (hash=3) and block 103 (hash=4)
        let orphaned_hashes: Vec<B256> = result.orphaned_blocks.iter().map(|b| b.hash).collect();
        assert!(
            orphaned_hashes.contains(&B256::from([3; 32])),
            "block 102 should be orphaned"
        );
        assert!(
            orphaned_hashes.contains(&B256::from([4; 32])),
            "block 103 should be orphaned"
        );

        // Blocks 100 and 101 are pre-fork and must still be tracked
        assert!(detector.get_block(100).is_some());
        assert!(detector.get_block(101).is_some());
    }

    #[test]
    fn test_tx_tracking_through_reorg() {
        let mut detector = ReorgDetector::new(12);

        // Build chain
        detector.process_block(make_block(100, 1, 0));
        detector.process_block(make_block(101, 2, 1));

        // Confirm a transaction in block 101
        let tx_hash = B256::from([0xAB; 32]);
        detector.record_confirmed_tx(ConfirmedTx {
            tx_hash,
            wallet: "0x123".to_string(),
            nonce: 5,
            block_number: 101,
            block_hash: B256::from([2; 32]),
            confirmed_at_block: 113,
        });

        assert!(detector.is_tracking(&tx_hash));

        // Reorg: new block 102 claims parent is block 100 (hash=1), orphaning block 101
        let result = detector.process_block(make_block(102, 22, 1));

        assert_eq!(result.reorg_depth, 1);
        assert_eq!(result.affected_tx_hashes.len(), 1);
        assert_eq!(result.affected_tx_hashes[0], tx_hash);

        // Transaction should no longer be tracked
        assert!(!detector.is_tracking(&tx_hash));
    }

    #[test]
    fn test_deep_reorg_handling() {
        let mut detector = ReorgDetector::new(12);

        // Build a 10-block chain: 100(hash=1) -> 101(hash=2) -> ... -> 109(hash=10)
        // make_block(100+i, i+1, i): block number 100+i, hash byte=i+1, parent hash byte=i
        for i in 0..10u64 {
            detector.process_block(make_block(100 + i, (i + 1) as u8, i as u8));
        }

        // Add transactions to blocks 101-109 (block 100 is the fork point, kept intact)
        for i in 1..10u64 {
            detector.record_confirmed_tx(make_tx(
                (0xA0 + i) as u8,
                "0x123",
                i,
                100 + i,
                (i + 1) as u8,
            ));
        }

        assert_eq!(detector.tracked_tx_count(), 9);

        // New block 110 arrives with parent_hash = hash of block 100 (hash byte = 1).
        // The fork point is block 100, so blocks 101-109 (9 blocks) are all orphaned.
        let result = detector.process_block(make_block(110, 0xFF, 1));

        assert_eq!(
            result.reorg_depth, 9,
            "blocks 101-109 should all be orphaned"
        );
        assert_eq!(result.orphaned_blocks.len(), 9);
        assert_eq!(
            result.affected_tx_hashes.len(),
            9,
            "all 9 transactions should be affected"
        );

        // Block 100 is the common ancestor and must still be tracked
        assert!(detector.get_block(100).is_some());
    }

    #[test]
    fn test_multiple_txs_same_block_reorg() {
        let mut detector = ReorgDetector::new(12);

        detector.process_block(make_block(100, 1, 0));
        detector.process_block(make_block(101, 2, 1));

        // Add 5 transactions to block 101
        for i in 0..5 {
            detector.record_confirmed_tx(make_tx(
                (0xA0 + i) as u8,
                &format!("0x{}", i),
                i as u64,
                101,
                2,
            ));
        }

        assert_eq!(detector.tracked_tx_count(), 5);

        // Reorg: new block 102 claims parent is block 100 (hash=1), orphaning block 101
        let result = detector.process_block(make_block(102, 0xFF, 1));

        assert_eq!(
            result.affected_tx_hashes.len(),
            5,
            "All 5 transactions should be affected"
        );
        assert_eq!(
            detector.tracked_tx_count(),
            0,
            "All transactions should be removed"
        );
    }

    #[test]
    fn test_finality_threshold() {
        let mut detector = ReorgDetector::new(12);

        // Add blocks 100-120
        for i in 0..21 {
            detector.process_block(make_block(100 + i, (i + 1) as u8, i as u8));
        }

        // Add transaction at block 100
        detector.record_confirmed_tx(make_tx(0xAA, "0x123", 0, 100, 1));

        // At block 120, transaction at block 100 should be finalized (20 blocks > 12 finality)
        let finalized = detector.get_finalized_txs(120);

        assert_eq!(finalized.len(), 1);
        assert_eq!(finalized[0].block_number, 100);
    }

    #[test]
    fn test_block_pruning() {
        let mut detector = ReorgDetector::new(12);

        // Add MAX_BLOCK_HISTORY + 50 blocks
        for i in 0..(MAX_BLOCK_HISTORY + 50) as u64 {
            detector.process_block(make_block(i, ((i + 1) % 256) as u8, (i % 256) as u8));
        }

        // Should have pruned old blocks - allow some buffer for the pruning logic
        assert!(
            detector.tracked_block_count() <= MAX_BLOCK_HISTORY + 10,
            "Should prune blocks beyond MAX_BLOCK_HISTORY, got {}",
            detector.tracked_block_count()
        );
    }

    #[test]
    fn test_tx_removal_after_finality() {
        let mut detector = ReorgDetector::new(12);

        detector.process_block(make_block(100, 1, 0));

        let tx_hash = B256::from([0xAB; 32]);
        detector.record_confirmed_tx(ConfirmedTx {
            tx_hash,
            wallet: "0x123".to_string(),
            nonce: 0,
            block_number: 100,
            block_hash: B256::from([1; 32]),
            confirmed_at_block: 112,
        });

        assert!(detector.is_tracking(&tx_hash));

        // Remove the transaction
        detector.remove_tx(&tx_hash);

        assert!(!detector.is_tracking(&tx_hash));
    }

    #[test]
    fn test_get_block_by_hash() {
        let mut detector = ReorgDetector::new(12);

        detector.process_block(make_block(100, 1, 0));
        detector.process_block(make_block(101, 2, 1));

        let block = detector.get_block_by_hash(&B256::from([2; 32]));
        assert!(block.is_some());
        assert_eq!(block.unwrap().number, 101);

        let missing = detector.get_block_by_hash(&B256::from([99; 32]));
        assert!(missing.is_none());
    }

    #[test]
    fn test_latest_block_tracking() {
        let mut detector = ReorgDetector::new(12);

        detector.process_block(make_block(100, 1, 0));
        assert_eq!(detector.latest_block().unwrap().number, 100);

        detector.process_block(make_block(101, 2, 1));
        assert_eq!(detector.latest_block().unwrap().number, 101);

        detector.process_block(make_block(102, 3, 2));
        assert_eq!(detector.latest_block().unwrap().number, 102);
    }

    #[test]
    fn test_reorg_preserves_unaffected_blocks() {
        let mut detector = ReorgDetector::new(12);

        // Build chain: 100 -> 101 -> 102 -> 103
        detector.process_block(make_block(100, 1, 0));
        detector.process_block(make_block(101, 2, 1));
        detector.process_block(make_block(102, 3, 2));
        detector.process_block(make_block(103, 4, 3));

        // Reorg at 103 only
        detector.process_block(make_block(103, 44, 3));

        // Blocks 100-102 should still be there
        assert!(detector.get_block(100).is_some());
        assert!(detector.get_block(101).is_some());
        assert!(detector.get_block(102).is_some());

        // Block 103 should have new hash
        let block_103 = detector.get_block(103).unwrap();
        assert_eq!(block_103.hash, B256::from([44; 32]));
    }

    #[test]
    fn test_empty_detector() {
        let detector = ReorgDetector::new(12);

        assert!(detector.latest_block().is_none());
        assert_eq!(detector.tracked_block_count(), 0);
        assert_eq!(detector.tracked_tx_count(), 0);
    }

    #[test]
    fn test_first_block_no_reorg() {
        let mut detector = ReorgDetector::new(12);

        // First block should never trigger reorg
        let result = detector.process_block(make_block(0, 1, 0));
        assert_eq!(result.reorg_depth, 0);
    }

    #[test]
    fn test_three_block_reorg() {
        let mut detector = ReorgDetector::new(12);

        // Build chain: 100(hash=1) -> 101(hash=2) -> 102(hash=3) -> 103(hash=4) -> 104(hash=5)
        detector.process_block(make_block(100, 1, 0));
        detector.process_block(make_block(101, 2, 1));
        detector.process_block(make_block(102, 3, 2));
        detector.process_block(make_block(103, 4, 3));
        detector.process_block(make_block(104, 5, 4));

        // Confirm one transaction in each of the three blocks that will be orphaned
        detector.record_confirmed_tx(make_tx(0xA0, "0xaaa", 0, 102, 3));
        detector.record_confirmed_tx(make_tx(0xA1, "0xbbb", 1, 103, 4));
        detector.record_confirmed_tx(make_tx(0xA2, "0xccc", 2, 104, 5));

        assert_eq!(detector.tracked_tx_count(), 3);

        // New block 105 arrives with parent_hash = block 101 (hash=2).
        // Fork point is block 101; blocks 102, 103, 104 (3 blocks) are orphaned.
        let result = detector.process_block(make_block(105, 55, 2));

        assert_eq!(
            result.reorg_depth, 3,
            "blocks 102, 103, and 104 should be orphaned"
        );
        assert_eq!(result.orphaned_blocks.len(), 3);
        assert_eq!(result.affected_tx_hashes.len(), 3);

        let orphaned_numbers: Vec<u64> = result.orphaned_blocks.iter().map(|b| b.number).collect();
        assert!(orphaned_numbers.contains(&102));
        assert!(orphaned_numbers.contains(&103));
        assert!(orphaned_numbers.contains(&104));

        // Blocks 100 and 101 (pre-fork) must still be present
        assert!(detector.get_block(100).is_some());
        assert!(detector.get_block(101).is_some());

        // All orphaned transactions must be cleared
        assert_eq!(detector.tracked_tx_count(), 0);
    }

    #[test]
    fn test_reorg_parent_not_in_chain() {
        let mut detector = ReorgDetector::new(12);

        // Build a short chain: 100(hash=1) -> 101(hash=2)
        detector.process_block(make_block(100, 1, 0));
        detector.process_block(make_block(101, 2, 1));

        // Confirm transactions in both tracked blocks
        detector.record_confirmed_tx(make_tx(0xB0, "0xaaa", 0, 100, 1));
        detector.record_confirmed_tx(make_tx(0xB1, "0xbbb", 1, 101, 2));

        assert_eq!(detector.tracked_tx_count(), 2);

        // New block 102 arrives whose parent_hash (hash byte=0x77) is NOT in our chain.
        // The algorithm falls back to fork_number = 0, orphaning everything at
        // heights 1 ..= 102 that we hold — i.e. blocks 100 and 101.
        let result = detector.process_block(make_block(102, 0x99, 0x77));

        // Both tracked blocks should be orphaned
        assert!(
            result.reorg_depth >= 2,
            "should orphan at least the 2 tracked blocks"
        );
        assert!(result.orphaned_blocks.len() >= 2);
        assert_eq!(
            result.affected_tx_hashes.len(),
            2,
            "both transactions should be affected"
        );

        // The detector must have cleared the orphaned blocks
        assert!(detector.get_block(100).is_none());
        assert!(detector.get_block(101).is_none());
    }
}
