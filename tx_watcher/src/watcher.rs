//! Block subscription-based transaction watcher with reorg detection
//!
//! Tracks block hashes to detect chain reorganizations and invalidates
//! any transactions that were confirmed on orphaned blocks.

use crate::config::WatcherConfig;
use crate::error::{Result, WatcherError};
use crate::reorg::{BlockInfo, ConfirmedTx, ReorgDetector};
use crate::store::{TxStatus, TxStore};
use alloy::eips::BlockNumberOrTag;
use alloy::primitives::{Address, B256, keccak256};
use alloy::providers::{Provider, ProviderBuilder, RootProvider, WsConnect};
use alloy::rpc::types::TransactionReceipt;
use aws_sdk_dynamodb::Client as DynamoClient;
use aws_sdk_sqs::Client as SqsClient;
use chrono::{DateTime, Utc};
use futures::{StreamExt, stream};
use nonce_manager::{DynamoNonceManager, SendRejection, classify_send_error};
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::sleep;
use tracing::{debug, error, info, warn};

/// Cached transaction info for fast lookup
#[derive(Debug, Clone)]
struct CachedTx {
    wallet: String,
    tx_hash: String,
    nonce: u64,
    status: TxStatus,
    block_number: Option<u64>,
    block_hash: Option<String>,
    /// Exact signed bytes, present on SIGNED and PENDING rows — required for verbatim
    /// rebroadcast.
    signed_raw_tx: Option<Vec<u8>>,
    submitted_at: DateTime<Utc>,
    family_nonce: Option<u64>,
    replacement_generation: Option<u32>,
    replacement_active: bool,
    next_eligible_replacement_block: Option<u64>,
    replacement_max_bumps: Option<u32>,
    replacement_on_exhaust: Option<String>,
    replacement_action: Option<String>,
    replacement_exhausted: bool,
    /// Last time the watcher re-injected this row's exact bytes while PENDING. In-memory
    /// only (carried across cache refreshes); bounds re-injection to once per
    /// `stuck_threshold_secs` per transaction.
    last_rebroadcast: Option<DateTime<Utc>>,
}

type TxCache = Arc<RwLock<HashMap<B256, CachedTx>>>;

/// Result of checking a single transaction
struct TxCheckResult {
    mined_block: Option<u64>,
    block_hash: Option<B256>,
    success: bool,
    confirmations: u64,
}

/// Disposition of a SIGNED-row rebroadcast attempt. Pure classification so the
/// exact-byte recovery rule is unit-testable without a node: accepted/known bytes advance
/// directly; `nonce too low` requires proof that the stored hash has a receipt; every
/// other error leaves the row SIGNED for identical retry.
#[derive(Debug, PartialEq, Eq)]
enum RebroadcastDisposition {
    /// The node accepted the exact signed bytes (expected hash acked) or already had the
    /// transaction ("already known"). Advance the tracker to PENDING via `mark_broadcast`.
    MarkBroadcast,
    /// The nonce was consumed. Query the receipt for the exact stored hash before
    /// advancing; another transaction may have consumed the same nonce.
    CheckReceipt,
    /// The node acked a hash that disagrees with the signed bytes — impossible for
    /// identical bytes. Leave SIGNED; never re-sign.
    HashMismatch { node_hash: B256 },
    /// The node definitively refused these bytes (funds/fees/gas/encoding). The row is
    /// left SIGNED — an earlier ambiguous send may still be gossiping, so the nonce is
    /// **not** recycled here — but the refusal is logged at warn so operators can act.
    /// Bounded retry/age-out for refused rows is tracked separately (N-H3).
    Refused,
    /// Timeout or any other error. Leave SIGNED so a later block/cache pass rebroadcasts
    /// the identical bytes.
    LeaveSigned,
}

/// Disposition of a stale `RESERVED` reservation against the chain (requirement 4).
#[derive(Debug, PartialEq, Eq)]
enum StaleDisposition {
    /// `latest > nonce`: the nonce has been consumed on-chain (an external or mined tx
    /// spent it). Finalize it via `confirm_transaction`.
    Confirm,
    /// `latest <= nonce < pending`: the slot is occupied in the mempool but not proven
    /// mined. Leave RESERVED and fail closed.
    LeaveReserved,
    /// Neither latest nor pending has reached the nonce: safe to release for reuse.
    Release,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReplacementDecision {
    SpeedUp,
    Cancel,
    Exhaust,
    None,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReplacementQueueMessage {
    wallet: String,
    nonce: u64,
    expected_generation: u32,
    action: &'static str,
}

/// Transaction watcher with reorg detection and nonce finalization
pub struct TransactionWatcher {
    config: WatcherConfig,
    store: TxStore,
    cache: TxCache,
    reorg_detector: Arc<RwLock<ReorgDetector>>,
    last_processed_block: Arc<RwLock<Option<u64>>>,
    nonce_manager: DynamoNonceManager<RootProvider>,
    replacement_sqs: SqsClient,
}

impl TransactionWatcher {
    /// Build a watcher.
    ///
    /// DynamoDB is the sole nonce authority — there is no Redis. The nonce manager is
    /// constructed from the shared DynamoDB client, the per-chain tracker table, an HTTP
    /// `RootProvider` derived from `HTTP_RPC_URL`, and the chain id. Finalization is the
    /// watcher's only means of draining the pending set, so the manager is required (not
    /// optional); `main` builds the DynamoDB client and passes it here.
    pub fn new(
        config: WatcherConfig,
        store: TxStore,
        dynamo: DynamoClient,
        replacement_sqs: SqsClient,
    ) -> Result<Self> {
        // Use required_confirmations as finality threshold for reorg detection
        let finality_blocks = config.required_confirmations + 20; // Extra buffer

        // Build an HTTP RootProvider for the nonce manager. The URL is parsed strictly:
        // a silent localhost fallback would produce a manager that cannot reach the chain
        // if the provider is ever used (reconciliation).
        let url: alloy::transports::http::reqwest::Url = config
            .http_rpc_url
            .parse()
            .map_err(|e| WatcherError::Config(format!("invalid HTTP_RPC_URL: {e}")))?;
        let provider = Arc::new(RootProvider::new_http(url));
        let nonce_manager = DynamoNonceManager::with_defaults(
            dynamo,
            config.dynamodb_table.clone(),
            provider,
            config.chain_id,
        );

        Ok(Self {
            config,
            store,
            cache: Arc::new(RwLock::new(HashMap::new())),
            reorg_detector: Arc::new(RwLock::new(ReorgDetector::new(finality_blocks))),
            last_processed_block: Arc::new(RwLock::new(None)),
            nonce_manager,
            replacement_sqs,
        })
    }

    pub async fn run(&self) -> Result<()> {
        info!("Transaction watcher starting with reorg detection");
        self.refresh_cache().await?;
        // Resume from the persisted cursor so reorg tracking is backfilled across a
        // restart instead of starting blind at the first live header.
        match self.store.load_cursor(self.config.chain_id).await {
            Ok(Some(block)) => {
                info!(block, "Resuming from persisted watcher cursor");
                *self.last_processed_block.write().await = Some(block);
            }
            Ok(None) => info!("No persisted watcher cursor; starting from the live head"),
            Err(e) => {
                warn!(error = %e, "Failed to load watcher cursor; starting from the live head")
            }
        }
        // Baseline heartbeat so the container health check has a value before the
        // first block arrives (its start period covers connect + catch-up).
        self.write_heartbeat();

        loop {
            match self.run_subscription_loop().await {
                Ok(_) => info!("Subscription loop ended"),
                Err(e) => error!(error = %e, "Subscription loop failed"),
            }

            warn!(
                delay_secs = self.config.reconnect_delay.as_secs(),
                "Reconnecting..."
            );
            sleep(self.config.reconnect_delay).await;
        }
    }

    async fn run_subscription_loop(&self) -> Result<()> {
        let ws = WsConnect::new(&self.config.ws_rpc_url);
        let provider = ProviderBuilder::new()
            .connect_ws(ws)
            .await
            .map_err(|_| WatcherError::Subscription("WS connect failed".to_string()))?;

        info!("Connected to WebSocket");

        // Catch up on missed blocks during reconnect
        let current_block = provider
            .get_block_number()
            .await
            .map_err(WatcherError::Rpc)?;
        let last = { *self.last_processed_block.read().await };
        if let Some(last_block) = last
            && let Some((from, to)) = catch_up_range(last_block, current_block, MAX_CATCH_UP_BLOCKS)
        {
            warn!(
                from,
                to, last_block, current_block, "Catching up on missed blocks"
            );
            self.backfill_blocks(&provider, from, to).await;
        }

        let sub = provider
            .subscribe_blocks()
            .await
            .map_err(|_| WatcherError::Subscription("Block subscription failed".to_string()))?;

        let mut stream = sub.into_stream();
        let mut cache_refresh = tokio::time::interval(std::time::Duration::from_secs(60));

        info!("Listening for new blocks with reorg detection...");

        loop {
            tokio::select! {
                // A WebSocket that stays open but stops delivering headers is a silent
                // stall: without this timeout the loop would sit here forever looking
                // healthy. Treat "no header within block_stall_timeout" as a dead stream
                // and reconnect (catch-up then backfills anything missed).
                next = tokio::time::timeout(self.config.block_stall_timeout, stream.next()) => {
                    match next {
                        Ok(Some(header)) => {
                            // Providers can drop or coalesce headers. Without the missing
                            // blocks the reorg detector cannot compare parent hashes across
                            // the hole, so backfill them (bounded) before this header.
                            let last = { *self.last_processed_block.read().await };
                            if let Some(last_block) = last
                                && let Some((from, to)) = catch_up_range(
                                    last_block,
                                    header.number.saturating_sub(1),
                                    MAX_CATCH_UP_BLOCKS,
                                )
                            {
                                warn!(from, to, head = header.number, "Live block stream gap; backfilling");
                                self.backfill_blocks(&provider, from, to).await;
                            }
                            let block_info = BlockInfo {
                                number: header.number,
                                hash: header.hash,
                                parent_hash: header.parent_hash,
                            };

                            if let Err(e) = self
                                .process_block(&provider, block_info, header.timestamp)
                                .await
                            {
                                error!(block = header.number, error = %e, "Failed to process block");
                            }
                        }
                        Ok(None) => {
                            warn!("Block stream ended");
                            break;
                        }
                        Err(_) => {
                            warn!(
                                timeout_secs = self.config.block_stall_timeout.as_secs(),
                                "No block header received within the stall timeout; reconnecting"
                            );
                            break;
                        }
                    }
                }
                _ = cache_refresh.tick() => {
                    if let Err(e) = self.refresh_cache().await {
                        warn!(error = %e, "Cache refresh failed");
                    }
                    // Periodic crash-recovery sweep: resolve stale RESERVED reservations
                    // (nonces handed out but never signed) against the chain.
                    if let Err(e) = self.recover_stale_reservations(&provider).await {
                        warn!(error = %e, "Stale reservation recovery failed");
                    }
                }
            }
        }

        Ok(())
    }

    /// Process a new block: check for reorgs, rebroadcast signed txs, then check pending.
    /// Fetch and process blocks `from..=to` in order. Each fetch is retried a few times;
    /// a block that still cannot be fetched is logged at error and skipped so one flaky
    /// RPC response cannot stall the watcher indefinitely (pending receipts are still
    /// checked on every later block, so only reorg-tracking fidelity is at stake).
    async fn backfill_blocks<P: Provider>(&self, provider: &P, from: u64, to: u64) {
        for block_num in from..=to {
            let mut fetched = None;
            for attempt in 1..=CATCH_UP_FETCH_ATTEMPTS {
                match provider
                    .get_block_by_number(BlockNumberOrTag::Number(block_num))
                    .await
                {
                    Ok(Some(block)) => {
                        fetched = Some(block);
                        break;
                    }
                    Ok(None) => {
                        debug!(
                            block = block_num,
                            attempt, "Catch-up block not yet available"
                        );
                    }
                    Err(e) => {
                        warn!(block = block_num, attempt, error = %e, "Catch-up block fetch failed");
                    }
                }
                sleep(std::time::Duration::from_millis(250 * attempt as u64)).await;
            }
            let Some(block) = fetched else {
                error!(
                    block = block_num,
                    "Giving up on catch-up block; reorg tracking has a hole here"
                );
                continue;
            };
            let block_info = BlockInfo {
                number: block.header.number,
                hash: block.header.hash,
                parent_hash: block.header.parent_hash,
            };
            if let Err(e) = self
                .process_block(provider, block_info, block.header.timestamp)
                .await
            {
                error!(block = block_num, error = %e, "Failed to process catch-up block");
            }
        }
    }

    async fn process_block<P: Provider>(
        &self,
        provider: &P,
        block_info: BlockInfo,
        block_timestamp: u64,
    ) -> Result<()> {
        let block_number = block_info.number;
        let block_hash = block_info.hash;

        debug!(
            block = block_number,
            hash = ?block_hash,
            parent = ?block_info.parent_hash,
            "Processing block"
        );

        // Check for reorgs first
        let reorg_result = {
            let mut detector = self.reorg_detector.write().await;
            detector.process_block(block_info.clone())
        };

        // Handle any reorged transactions
        if reorg_result.reorg_depth > 0 {
            self.handle_reorg(&reorg_result).await?;
        }

        // Rebroadcast any SIGNED transactions (durably signed but not yet confirmed
        // broadcast, or reset to SIGNED by a reorg) using their exact bytes.
        self.rebroadcast_signed_transactions(provider).await?;

        // Replacement enqueueing is policy- and block-cadence-driven. DynamoDB's leased
        // conditional claim is the authority; the worker re-checks receipt and nonce
        // immediately before signing.
        self.enqueue_due_replacements(block_number).await;

        // Check pending transactions for inclusion in this block
        self.check_pending_transactions(provider, block_number, block_hash)
            .await?;

        // Update confirmations for mined transactions
        self.update_confirmations(provider, block_number).await?;

        // Finalize transactions that have reached required confirmations
        self.finalize_confirmed_transactions(block_number).await?;

        // Track last successfully processed block for catch-up on reconnect, in memory
        // and durably (best effort: a failed cursor write only costs catch-up fidelity
        // after a restart).
        {
            let mut last = self.last_processed_block.write().await;
            *last = Some(block_number);
        }
        if let Err(e) = self
            .store
            .save_cursor(self.config.chain_id, block_number)
            .await
        {
            warn!(block = block_number, error = %e, "Failed to persist watcher cursor");
        }

        // Liveness: heartbeat file for the ECS health check, and an EMF progress metric
        // whose *absence* alarms. Both happen only after a block was fully processed, so
        // a watcher stuck inside this function goes stale exactly like a dead one.
        self.record_progress(block_number, block_timestamp).await;

        Ok(())
    }

    /// Write the current epoch second to the heartbeat file (read by the ECS health
    /// check). Returns the timestamp written.
    fn write_heartbeat(&self) -> i64 {
        let now = Utc::now().timestamp();
        if let Err(e) = std::fs::write(&self.config.heartbeat_path, now.to_string()) {
            warn!(path = %self.config.heartbeat_path, error = %e, "Failed to write heartbeat file");
        }
        now
    }

    /// Write the heartbeat file and emit the per-block EMF progress document.
    async fn record_progress(&self, block_number: u64, block_timestamp: u64) {
        let now = self.write_heartbeat();
        let active_transactions = self.cache.read().await.len();
        crate::metrics::emit(&crate::metrics::BlockProgress {
            chain_id: self.config.chain_id,
            block_number,
            block_lag_secs: (now.max(0) as u64).saturating_sub(block_timestamp),
            active_transactions,
        });
    }

    async fn mark_rebroadcast_pending(&self, wallet: Address, nonce: u64, tx_hash: B256) -> bool {
        if let Err(e) = self
            .nonce_manager
            .mark_broadcast(wallet, nonce, tx_hash)
            .await
        {
            warn!(
                tx_hash = %tx_hash,
                nonce,
                error = %e,
                "Rebroadcast accepted but mark_broadcast failed; leaving SIGNED to retry"
            );
            return false;
        }

        let mut cache = self.cache.write().await;
        if let Some(cached) = cache.get_mut(&tx_hash) {
            cached.status = TxStatus::Pending;
        }
        info!(
            tx_hash = %tx_hash,
            nonce,
            "SIGNED transaction rebroadcast and marked PENDING"
        );
        true
    }

    /// Resolve a SIGNED row whose rebroadcast said `nonce too low` but whose exact hash
    /// has no receipt (N-H2). Fail closed at every step: a fresh `latest` nonce must be
    /// past this nonce, the row must be older than `stuck_threshold_secs`, and a second
    /// receipt lookup must still be empty. Only then is the nonce finalized as consumed
    /// (never released — a different transaction spent it) and the tracker marked
    /// DROPPED, in that order, so a failure leaves the row active for a later pass.
    async fn resolve_signed_consumed_by_other<P: Provider>(
        &self,
        provider: &P,
        tx: &CachedTx,
        wallet: Address,
        expected_hash: B256,
    ) {
        let latest = match provider
            .get_transaction_count(wallet)
            .block_id(BlockNumberOrTag::Latest.into())
            .await
        {
            Ok(n) => n,
            Err(e) => {
                warn!(tx_hash = %tx.tx_hash, nonce = tx.nonce, error = %e, "Failed to fetch latest nonce for SIGNED row; leaving SIGNED");
                return;
            }
        };
        let age_secs = Utc::now()
            .signed_duration_since(tx.submitted_at)
            .num_seconds();
        if !signed_nonce_consumed_by_other(
            latest,
            tx.nonce,
            age_secs,
            self.config.stuck_threshold_secs,
        ) {
            debug!(
                tx_hash = %tx.tx_hash,
                nonce = tx.nonce,
                latest,
                age_secs,
                "SIGNED nonce reported consumed but not yet past the fail-closed gate; leaving SIGNED"
            );
            return;
        }
        // One more receipt lookup right before acting, so a receipt that lagged on a
        // load-balanced endpoint is caught and routed to the normal PENDING path.
        match provider.get_transaction_receipt(expected_hash).await {
            Ok(Some(_)) => {
                info!(tx_hash = %tx.tx_hash, nonce = tx.nonce, "Receipt appeared on re-check; advancing to PENDING");
                self.mark_rebroadcast_pending(wallet, tx.nonce, expected_hash)
                    .await;
                return;
            }
            Ok(None) => {}
            Err(e) => {
                warn!(tx_hash = %tx.tx_hash, nonce = tx.nonce, error = %e, "Receipt re-check failed; leaving SIGNED");
                return;
            }
        }

        warn!(
            tx_hash = %tx.tx_hash,
            wallet = %tx.wallet,
            nonce = tx.nonce,
            latest,
            age_secs,
            "SIGNED nonce consumed on-chain by a different transaction; finalizing nonce and marking DROPPED"
        );
        if let Err(e) = self.finalize_nonce(&tx.wallet, tx.nonce).await {
            warn!(tx_hash = %tx.tx_hash, error = %e, "Nonce finalization failed for consumed SIGNED row; leaving SIGNED to retry");
            return;
        }
        if let Err(e) = self.complete_family(tx, "CONSUMED").await {
            warn!(tx_hash = %tx.tx_hash, error = %e, "Nonce finalized but family completion failed; leaving active to retry");
            return;
        }
        if let Err(e) = self.store.mark_dropped(&tx.wallet, &tx.tx_hash).await {
            warn!(tx_hash = %tx.tx_hash, error = %e, "Nonce finalized but marking DROPPED failed; leaving active to retry");
            return;
        }
        let mut cache = self.cache.write().await;
        if let Some(cached) = cache.get_mut(&expected_hash) {
            cached.status = TxStatus::Dropped;
        }
    }

    /// Rebroadcast SIGNED transactions verbatim.
    ///
    /// For each cached SIGNED row: require its exact signed bytes, recompute
    /// `keccak256(bytes)` and confirm it equals the stored tx hash, then
    /// `send_raw_transaction` with the identical bytes only. On the expected hash or a
    /// node "already known", advance the tracker to PENDING via
    /// [`DynamoNonceManager::mark_broadcast`] (atomic tracker→PENDING /
    /// reservation→BROADCAST) and update the cache. On a timeout or other error, leave
    /// the row SIGNED so a later pass rebroadcasts the same bytes. Never rebuild,
    /// re-sign, or allocate a new nonce.
    async fn rebroadcast_signed_transactions<P: Provider>(&self, provider: &P) -> Result<()> {
        let signed_txs: Vec<CachedTx> = {
            let cache = self.cache.read().await;
            cache
                .values()
                .filter(|tx| tx.status == TxStatus::Signed && tx.replacement_active)
                .cloned()
                .collect()
        };

        if signed_txs.is_empty() {
            return Ok(());
        }

        debug!(
            count = signed_txs.len(),
            "Rebroadcasting SIGNED transactions"
        );

        for tx in signed_txs {
            let Ok(expected_hash) = tx.tx_hash.parse::<B256>() else {
                warn!(tx_hash = %tx.tx_hash, "SIGNED row has unparseable tx_hash; skipping");
                continue;
            };
            let Some(bytes) = tx.signed_raw_tx.as_ref() else {
                warn!(
                    tx_hash = %tx.tx_hash,
                    "SIGNED row is missing signed_raw_tx; cannot rebroadcast — leaving SIGNED"
                );
                continue;
            };
            // Exact-byte integrity: the bytes must hash to the stored tx hash. A mismatch
            // means the row is corrupt; refuse to broadcast rather than send wrong bytes.
            if !signed_bytes_match(bytes, expected_hash) {
                error!(
                    tx_hash = %tx.tx_hash,
                    "signed_raw_tx keccak does not match stored tx_hash; refusing to broadcast"
                );
                continue;
            }
            let Ok(wallet) = tx.wallet.parse::<Address>() else {
                warn!(wallet = %tx.wallet, "SIGNED row has unparseable wallet; skipping");
                continue;
            };

            let send_result: std::result::Result<B256, String> = provider
                .send_raw_transaction(bytes)
                .await
                .map(|pending| *pending.tx_hash())
                .map_err(|e| e.to_string());

            match classify_rebroadcast(expected_hash, &send_result) {
                RebroadcastDisposition::MarkBroadcast => {
                    self.mark_rebroadcast_pending(wallet, tx.nonce, expected_hash)
                        .await;
                }
                RebroadcastDisposition::CheckReceipt => {
                    // `nonce too low` alone is ambiguous: either these exact bytes mined,
                    // or another transaction consumed the nonce. Advance only when the
                    // expected stored hash itself has an on-chain receipt.
                    match provider.get_transaction_receipt(expected_hash).await {
                        Ok(Some(_)) => {
                            info!(
                                tx_hash = %tx.tx_hash,
                                nonce = tx.nonce,
                                "Rebroadcast nonce already consumed by the expected transaction"
                            );
                            self.mark_rebroadcast_pending(wallet, tx.nonce, expected_hash)
                                .await;
                        }
                        Ok(None) => {
                            // Our exact bytes have no receipt. If the wallet's latest nonce is
                            // provably past this nonce and the row is old enough, a different
                            // transaction consumed it: finalize the nonce as consumed and mark
                            // DROPPED so the row stops leaking a pending slot and stops costing
                            // two RPCs per block forever (N-H2). Otherwise leave SIGNED.
                            self.resolve_signed_consumed_by_other(
                                provider,
                                &tx,
                                wallet,
                                expected_hash,
                            )
                            .await;
                        }
                        Err(_) => {
                            warn!(
                                tx_hash = %tx.tx_hash,
                                nonce = tx.nonce,
                                "Receipt lookup after nonce-too-low failed; leaving SIGNED"
                            );
                        }
                    }
                }
                RebroadcastDisposition::HashMismatch { node_hash } => {
                    error!(
                        tx_hash = %tx.tx_hash,
                        node = ?node_hash,
                        "Node returned a tx hash that disagrees with the signed bytes; leaving SIGNED"
                    );
                }
                RebroadcastDisposition::Refused => {
                    if let Err(e) = &send_result {
                        warn!(
                            tx_hash = %tx.tx_hash,
                            nonce = tx.nonce,
                            error = %e,
                            "Node definitively refused rebroadcast of SIGNED bytes; leaving SIGNED \
                             (not recycled: an earlier send may still be gossiping)"
                        );
                    }
                }
                RebroadcastDisposition::LeaveSigned => {
                    if let Err(e) = &send_result {
                        debug!(
                            tx_hash = %tx.tx_hash,
                            error = %e,
                            "Rebroadcast not confirmed; leaving SIGNED to retry on a later pass"
                        );
                    }
                }
            }
        }

        Ok(())
    }

    /// Resolve stale `RESERVED` reservations against the chain (crash recovery).
    ///
    /// A `RESERVED` reservation is a nonce handed out but never signed. These are
    /// globally discoverable via the `status-chain-index` GSI. For each stale row, query
    /// the wallet's latest and pending nonce and decide (see [`classify_stale_reservation`]):
    /// finalize a consumed nonce, leave a slot that is occupied-but-not-mined RESERVED
    /// (fail closed), or release a truly unused nonce back to the gap pool.
    async fn recover_stale_reservations<P: Provider>(&self, provider: &P) -> Result<()> {
        let stale = self.nonce_manager.find_stale_reservations().await?;
        if stale.is_empty() {
            return Ok(());
        }

        info!(count = stale.len(), "Resolving stale RESERVED reservations");

        for reservation in stale {
            let address = reservation.wallet;
            let nonce = reservation.nonce;

            let latest = match provider
                .get_transaction_count(address)
                .block_id(BlockNumberOrTag::Latest.into())
                .await
            {
                Ok(n) => n,
                Err(e) => {
                    warn!(wallet = ?address, nonce, error = %e, "Failed to fetch latest nonce; skipping stale reservation");
                    continue;
                }
            };
            let pending = match provider
                .get_transaction_count(address)
                .block_id(BlockNumberOrTag::Pending.into())
                .await
            {
                Ok(n) => n,
                Err(e) => {
                    warn!(wallet = ?address, nonce, error = %e, "Failed to fetch pending nonce; skipping stale reservation");
                    continue;
                }
            };

            match classify_stale_reservation(latest, pending, nonce) {
                StaleDisposition::Confirm => {
                    match self.nonce_manager.confirm_transaction(address, nonce).await {
                        Ok(()) => info!(
                            wallet = ?address, nonce, latest,
                            "Stale reservation nonce already consumed on-chain; confirmed"
                        ),
                        Err(e) => {
                            warn!(wallet = ?address, nonce, error = %e, "Failed to confirm consumed stale reservation")
                        }
                    }
                }
                StaleDisposition::LeaveReserved => {
                    info!(
                        wallet = ?address, nonce, latest, pending,
                        "Stale reservation slot occupied in mempool but not mined; leaving RESERVED (fail closed)"
                    );
                }
                StaleDisposition::Release => {
                    match self.nonce_manager.release_nonce(address, nonce).await {
                        Ok(true) => {
                            info!(wallet = ?address, nonce, "Stale reservation released to gap pool")
                        }
                        Ok(false) => {
                            debug!(wallet = ?address, nonce, "Stale reservation no longer RESERVED; nothing released")
                        }
                        Err(e) => {
                            warn!(wallet = ?address, nonce, error = %e, "Failed to release stale reservation")
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Handle reorged transactions
    async fn handle_reorg(&self, reorg_result: &crate::reorg::ReorgCheckResult) -> Result<()> {
        info!(
            reorg_depth = reorg_result.reorg_depth,
            affected_txs = reorg_result.affected_tx_hashes.len(),
            "Handling chain reorganization"
        );

        let cache = self.cache.read().await;

        for tx_hash in &reorg_result.affected_tx_hashes {
            if let Some(cached_tx) = cache.get(tx_hash) {
                // If the row carries its exact signed bytes, reset it to SIGNED so those
                // bytes are rebroadcast verbatim; otherwise reset to PENDING.
                let to_signed = cached_tx.signed_raw_tx.is_some();
                info!(
                    tx_hash = %cached_tx.tx_hash,
                    wallet = %cached_tx.wallet,
                    nonce = cached_tx.nonce,
                    to_signed,
                    "Resetting reorged transaction to active state (atomic)"
                );

                // Single atomic UpdateItem: status → SIGNED/PENDING, block fields and any
                // terminal TTL removed. A ConditionExpression prevents reverting rows that
                // are not MINED/CONFIRMED and makes the operation idempotent. Retry once
                // on transient failures; a ConditionalCheckFailedException on the first
                // attempt is benign (tx was already in a non-eligible state).
                let mut reorg_ok = false;
                for attempt in 0..2 {
                    match self
                        .store
                        .reorg_reset(&cached_tx.wallet, &cached_tx.tx_hash, to_signed)
                        .await
                    {
                        Ok(()) => {
                            reorg_ok = true;
                            break;
                        }
                        Err(e) => {
                            if attempt == 0 {
                                warn!(tx_hash = %cached_tx.tx_hash, error = %e, "reorg_reset failed, retrying");
                            } else {
                                warn!(tx_hash = %cached_tx.tx_hash, error = %e, "reorg_reset failed after retry; skipping");
                            }
                        }
                    }
                }
                let _ = reorg_ok; // outcome already logged above
            }
        }

        // Refresh cache after handling reorg so the watcher sees the reset statuses
        // (SIGNED/PENDING) and any SIGNED rows are picked up for rebroadcast.
        drop(cache);
        self.refresh_cache().await?;

        Ok(())
    }

    async fn enqueue_due_replacements(&self, current_block: u64) {
        let Some(queue_url) = self.config.replacement_queue_url.as_deref() else {
            return;
        };
        let candidates: Vec<CachedTx> = {
            let cache = self.cache.read().await;
            cache
                .values()
                .filter(|tx| matches!(tx.status, TxStatus::Signed | TxStatus::Pending))
                .filter(|tx| tx.family_nonce.is_some() && tx.replacement_active)
                .filter(|tx| replacement_decision(tx, current_block) != ReplacementDecision::None)
                .cloned()
                .collect()
        };

        for tx in candidates {
            let decision = replacement_decision(&tx, current_block);
            let (Some(nonce), Some(generation)) = (tx.family_nonce, tx.replacement_generation)
            else {
                continue;
            };
            let Ok(wallet) = tx.wallet.parse::<Address>() else {
                warn!(wallet=%tx.wallet, "Invalid family wallet; replacement not enqueued");
                continue;
            };
            let expected_generation = generation.saturating_add(1);
            match self
                .nonce_manager
                .claim_replacement(wallet, nonce, generation, current_block, 3)
                .await
            {
                Ok(true) => {}
                Ok(false) => continue,
                Err(e) => {
                    warn!(nonce, generation, error=%e, "Replacement claim failed");
                    continue;
                }
            }
            let action = match decision {
                ReplacementDecision::SpeedUp => "speedUp",
                ReplacementDecision::Cancel => "cancel",
                ReplacementDecision::Exhaust => "exhaust",
                ReplacementDecision::None => continue,
            };
            let body = serde_json::to_string(&ReplacementQueueMessage {
                wallet: tx.wallet.clone(),
                nonce,
                expected_generation,
                action,
            })
            .expect("replacement queue message is serializable");
            if let Err(e) = self
                .replacement_sqs
                .send_message()
                .queue_url(queue_url)
                .message_body(body)
                .send()
                .await
            {
                warn!(nonce, generation, error=%e, "Replacement queue send failed; releasing claim");
                if let Err(release_error) = self
                    .nonce_manager
                    .release_replacement_claim(wallet, nonce, expected_generation)
                    .await
                {
                    warn!(nonce, error=%release_error, "Failed to release replacement enqueue claim");
                }
                continue;
            }
            info!(
                nonce,
                expected_generation, action, "Replacement request enqueued"
            );
            println!(
                "{}",
                serde_json::json!({
                    "_aws": {
                        "Timestamp": Utc::now().timestamp_millis(),
                        "CloudWatchMetrics": [{
                            "Namespace": "TxManager/Replacement",
                            "Dimensions": [["ChainId"]],
                            "Metrics": [{"Name": "ReplacementRequested", "Unit": "Count"}]
                        }]
                    },
                    "ChainId": self.config.chain_id.to_string(),
                    "Action": action,
                    "Generation": expected_generation,
                    "ReplacementRequested": 1
                })
            );
        }
    }

    /// Check pending transactions for inclusion
    async fn check_pending_transactions<P: Provider>(
        &self,
        provider: &P,
        block_number: u64,
        block_hash: B256,
    ) -> Result<()> {
        let pending_txs: Vec<CachedTx> = {
            let cache = self.cache.read().await;
            cache
                .values()
                .filter(|tx| {
                    tx.status == TxStatus::Pending
                        || (tx.status == TxStatus::Signed && !tx.replacement_active)
                })
                .cloned()
                .collect()
        };

        if pending_txs.is_empty() {
            return Ok(());
        }

        debug!(count = pending_txs.len(), "Checking pending transactions");

        // Fetch receipts in parallel with bounded concurrency
        let results: Vec<_> = stream::iter(pending_txs.iter())
            .map(|tx| {
                let tx = tx.clone();
                async move {
                    let tx_hash: B256 = tx.tx_hash.parse().unwrap_or_default();
                    let result = self
                        .check_transaction(provider, tx_hash, block_number)
                        .await;
                    (tx, result)
                }
            })
            .buffer_unordered(10)
            .collect()
            .await;

        // Process results
        for (tx, result) in results {
            match result {
                Ok(Some(check_result)) => {
                    let mined_block = check_result.mined_block.unwrap_or(block_number);
                    let tx_block_hash = check_result.block_hash.unwrap_or(block_hash);

                    if !check_result.success {
                        // Transaction reverted on-chain — it should become FAILED.
                        //
                        // Ordering invariant (state recovery): finalize the consumed
                        // nonce FIRST, and only mark DynamoDB FAILED / update the cache
                        // after finalization succeeds. The tx stays PENDING until then,
                        // so a one-time failure is retried on a later block instead of
                        // becoming a permanent un-finalized nonce.
                        //
                        // The nonce is CONSUMED, not released: a revert means the tx was
                        // mined, so the chain spent this nonce exactly as it would for a
                        // success. Returning it to the gap pool would hand out a dead
                        // nonce the node rejects (`nonce too low`); since that rejection
                        // routes back to the same gap pool, the wallet would livelock,
                        // unable to broadcast again. Same reasoning as dropped-tx
                        // detection in `check_if_dropped`.
                        warn!(
                            tx_hash = %tx.tx_hash,
                            block = mined_block,
                            "Transaction reverted on-chain, finalizing nonce before marking FAILED"
                        );

                        if let Err(e) = self.finalize_nonce(&tx.wallet, tx.nonce).await {
                            warn!(
                                tx_hash = %tx.tx_hash,
                                error = %e,
                                "Nonce finalization failed for reverted tx; leaving PENDING to retry on a later block"
                            );
                            continue;
                        }

                        // Nonce finalized (idempotent on repeat). Now write the terminal
                        // state. If this DDB update fails, leave the cache active: the tx
                        // is still PENDING in DynamoDB, so the next pass re-finalizes
                        // (idempotent) and retries the mark.
                        if let Err(e) = self.complete_family(&tx, "FAILED").await {
                            warn!(tx_hash = %tx.tx_hash, error = %e, "Nonce finalized but family completion failed; leaving active to retry");
                            continue;
                        }
                        if let Err(e) = self.store.mark_failed(&tx.wallet, &tx.tx_hash).await {
                            warn!(
                                tx_hash = %tx.tx_hash,
                                error = %e,
                                "Nonce finalized but marking FAILED failed; leaving active to retry"
                            );
                            continue;
                        }

                        // Update cache only after the terminal write succeeded.
                        {
                            let mut cache = self.cache.write().await;
                            let parsed_hash: B256 = tx.tx_hash.parse().unwrap_or_default();
                            if let Some(cached) = cache.get_mut(&parsed_hash) {
                                cached.status = TxStatus::Failed;
                            }
                        }

                        continue;
                    }

                    info!(
                        tx_hash = %tx.tx_hash,
                        block = mined_block,
                        confirmations = check_result.confirmations,
                        "Transaction mined"
                    );

                    // Update DynamoDB
                    self.store
                        .update_mined(
                            &tx.wallet,
                            &tx.tx_hash,
                            mined_block,
                            &format!("{:?}", tx_block_hash),
                            check_result.success,
                            check_result.confirmations,
                        )
                        .await?;

                    // Record in reorg detector for tracking
                    {
                        let mut detector = self.reorg_detector.write().await;
                        detector.record_confirmed_tx(ConfirmedTx {
                            tx_hash: tx.tx_hash.parse().unwrap_or_default(),
                            wallet: tx.wallet.clone(),
                            nonce: tx.nonce,
                            block_number: mined_block,
                            block_hash: tx_block_hash,
                            confirmed_at_block: block_number,
                        });
                    }

                    // Update cache
                    {
                        let mut cache = self.cache.write().await;
                        let parsed_hash: B256 = tx.tx_hash.parse().unwrap_or_default();
                        if let Some(cached) = cache.get_mut(&parsed_hash) {
                            cached.status = TxStatus::Mined;
                            cached.block_number = Some(mined_block);
                            cached.block_hash = Some(format!("{:?}", tx_block_hash));
                        }
                    }
                }
                Ok(None) => {
                    // No receipt yet — check whether it was dropped from the mempool
                    self.check_if_dropped(provider, &tx).await;
                }
                Err(e) => {
                    warn!(tx_hash = %tx.tx_hash, error = %e, "Failed to check transaction");
                }
            }
        }

        Ok(())
    }

    /// Check whether a pending transaction with no receipt has been dropped from
    /// the mempool, and if so finalize its nonce and then mark it DROPPED.
    ///
    /// A transaction is treated as dropped only when BOTH hold:
    /// 1. It has been pending longer than `stuck_threshold_secs` — avoids racing
    ///    a transaction that simply has not been mined yet.
    /// 2. The wallet's on-chain nonce (at the latest block) has already advanced
    ///    past this transaction's nonce — proving a *different* transaction
    ///    consumed the nonce, so this one can never be mined.
    ///
    /// The nonce is finalized as consumed (not released for reuse): it is already
    /// spent on-chain, so returning it to the reuse pool would make the next
    /// reservation collide with an already-mined nonce ("nonce too low").
    /// Re-inject a stale PENDING transaction's exact signed bytes (N-H3, first half).
    ///
    /// Same-hash rebroadcast is always safe: the node either already has the bytes
    /// (`already known`), accepts them again, or reports the nonce consumed (handled on
    /// the next block by the receipt / drop checks). A definitive refusal means the bytes
    /// are no longer admissible at current network conditions (for example the max fee is
    /// below the base fee) — that transaction needs a fee-bumped replacement, which this
    /// system does not yet produce, so it is logged at warn for operators.
    ///
    /// Rate-limited to once per `stuck_threshold_secs` per transaction via the in-memory
    /// `last_rebroadcast` timestamp.
    async fn rebroadcast_stale_pending<P: Provider>(
        &self,
        provider: &P,
        tx: &CachedTx,
        age_secs: i64,
    ) {
        let now = Utc::now();
        if !reinject_due(tx.last_rebroadcast, now, self.config.stuck_threshold_secs) {
            return;
        }
        let Ok(expected_hash) = tx.tx_hash.parse::<B256>() else {
            return;
        };
        let Some(bytes) = tx.signed_raw_tx.as_ref() else {
            debug!(tx_hash = %tx.tx_hash, "Stale PENDING row has no signed_raw_tx; cannot re-inject");
            return;
        };
        if !signed_bytes_match(bytes, expected_hash) {
            error!(
                tx_hash = %tx.tx_hash,
                "PENDING row signed_raw_tx keccak does not match stored tx_hash; refusing to re-inject"
            );
            return;
        }

        // Record the attempt before sending so a slow/failed send cannot cause a burst.
        {
            let mut cache = self.cache.write().await;
            if let Some(cached) = cache.get_mut(&expected_hash) {
                cached.last_rebroadcast = Some(now);
            }
        }

        let send_result: std::result::Result<B256, String> = provider
            .send_raw_transaction(bytes)
            .await
            .map(|pending| *pending.tx_hash())
            .map_err(|e| e.to_string());

        match classify_rebroadcast(expected_hash, &send_result) {
            RebroadcastDisposition::MarkBroadcast => info!(
                tx_hash = %tx.tx_hash,
                nonce = tx.nonce,
                age_secs,
                "Re-injected stale PENDING transaction (identical bytes)"
            ),
            RebroadcastDisposition::CheckReceipt => debug!(
                tx_hash = %tx.tx_hash,
                nonce = tx.nonce,
                "Stale PENDING re-inject reports nonce consumed; receipt/drop checks will resolve it"
            ),
            RebroadcastDisposition::Refused => warn!(
                tx_hash = %tx.tx_hash,
                nonce = tx.nonce,
                age_secs,
                error = %send_result.as_ref().err().map(String::as_str).unwrap_or_default(),
                "Stale PENDING transaction is no longer admissible; it needs a fee-bumped \
                 replacement at the same nonce (not yet automated)"
            ),
            RebroadcastDisposition::HashMismatch { node_hash } => error!(
                tx_hash = %tx.tx_hash,
                node = ?node_hash,
                "Node returned a different hash for identical PENDING bytes"
            ),
            RebroadcastDisposition::LeaveSigned => debug!(
                tx_hash = %tx.tx_hash,
                nonce = tx.nonce,
                error = %send_result.as_ref().err().map(String::as_str).unwrap_or_default(),
                "Stale PENDING re-inject inconclusive; will retry after the interval"
            ),
        }
    }

    async fn check_if_dropped<P: Provider>(&self, provider: &P, tx: &CachedTx) {
        let age_secs = Utc::now()
            .signed_duration_since(tx.submitted_at)
            .num_seconds();
        if age_secs < self.config.stuck_threshold_secs as i64 {
            return;
        }

        let Ok(address) = tx.wallet.parse::<Address>() else {
            warn!(wallet = %tx.wallet, "Could not parse wallet for drop detection");
            return;
        };

        let chain_nonce = match provider
            .get_transaction_count(address)
            .block_id(BlockNumberOrTag::Latest.into())
            .await
        {
            Ok(n) => n,
            Err(e) => {
                warn!(tx_hash = %tx.tx_hash, error = %e, "Failed to fetch chain nonce for drop detection");
                return;
            }
        };

        // Nonce not yet consumed on-chain — the transaction is still legitimately pending,
        // but it has had no receipt for longer than the stuck threshold. It may have been
        // evicted from the mempool (fee spike, node restart, pool pressure); if so nothing
        // else will ever re-inject it and every later nonce queues behind the hole. Re-send
        // the identical bytes (same hash, so this can never double-spend), rate-limited.
        if chain_nonce <= tx.nonce {
            if tx.replacement_active {
                self.rebroadcast_stale_pending(provider, tx, age_secs).await;
            }
            return;
        }

        // The receipt query that brought us here and the nonce query above are not
        // atomic; behind a load-balanced endpoint one node may already show the nonce
        // consumed while another has not indexed the receipt for THIS transaction yet.
        // Re-check once before declaring it dropped so a just-mined tx is not misfiled.
        if let Ok(tx_hash) = tx.tx_hash.parse::<B256>() {
            match provider.get_transaction_receipt(tx_hash).await {
                Ok(Some(_)) => {
                    info!(
                        tx_hash = %tx.tx_hash,
                        nonce = tx.nonce,
                        "Receipt appeared on re-check; the nonce was consumed by this tx, not dropped"
                    );
                    return;
                }
                Ok(None) => {}
                Err(e) => {
                    warn!(tx_hash = %tx.tx_hash, error = %e, "Receipt re-check failed; deferring drop decision");
                    return;
                }
            }
        }

        warn!(
            tx_hash = %tx.tx_hash,
            wallet = %tx.wallet,
            nonce = tx.nonce,
            chain_nonce,
            age_secs,
            "Pending transaction dropped from mempool (nonce consumed on-chain), finalizing nonce before marking DROPPED"
        );

        // Ordering invariant (state recovery): finalize the consumed nonce FIRST, then
        // mark DROPPED and update the cache. The nonce is spent on-chain (a different tx
        // consumed it), so it is finalized as consumed via confirm — NOT released for
        // reuse. On any failure, leave the tx active (PENDING) so a later pass retries;
        // re-finalization is idempotent.
        if let Err(e) = self.finalize_nonce(&tx.wallet, tx.nonce).await {
            warn!(
                tx_hash = %tx.tx_hash,
                error = %e,
                "Nonce finalization failed for dropped tx; leaving PENDING to retry on a later block"
            );
            return;
        }

        if let Err(e) = self.complete_family(tx, "CONSUMED").await {
            warn!(tx_hash = %tx.tx_hash, error = %e, "Nonce finalized but family completion failed; leaving active to retry");
            return;
        }
        if let Err(e) = self.store.mark_dropped(&tx.wallet, &tx.tx_hash).await {
            warn!(
                tx_hash = %tx.tx_hash,
                error = %e,
                "Nonce finalized but marking DROPPED failed; leaving active to retry"
            );
            return;
        }

        // Update cache only after the terminal write succeeded, so this tx is not
        // re-evaluated before the next refresh.
        {
            let mut cache = self.cache.write().await;
            let parsed_hash: B256 = tx.tx_hash.parse().unwrap_or_default();
            if let Some(cached) = cache.get_mut(&parsed_hash) {
                cached.status = TxStatus::Dropped;
            }
        }
    }

    /// Check a single transaction for receipt
    async fn check_transaction<P: Provider>(
        &self,
        provider: &P,
        tx_hash: B256,
        current_block: u64,
    ) -> Result<Option<TxCheckResult>> {
        let receipt: Option<TransactionReceipt> = provider
            .get_transaction_receipt(tx_hash)
            .await
            .map_err(WatcherError::Rpc)?;

        match receipt {
            Some(receipt) => {
                let mined_block = receipt.block_number.unwrap_or(current_block);
                let block_hash = receipt.block_hash;
                let success = receipt.status();
                let confirmations = current_block.saturating_sub(mined_block) + 1;

                Ok(Some(TxCheckResult {
                    mined_block: Some(mined_block),
                    block_hash,
                    success,
                    confirmations,
                }))
            }
            None => Ok(None),
        }
    }

    /// Update confirmations for mined transactions
    async fn update_confirmations<P: Provider>(
        &self,
        provider: &P,
        current_block: u64,
    ) -> Result<()> {
        let mined_txs: Vec<CachedTx> = {
            let cache = self.cache.read().await;
            cache
                .values()
                .filter(|tx| tx.status == TxStatus::Mined)
                .cloned()
                .collect()
        };

        for tx in mined_txs {
            if let Some(cached_block) = tx.block_number {
                // Cheap pre-filter on the cached block; the authoritative count below uses
                // the receipt's block so a shallow re-mine cannot over-count.
                if current_block.saturating_sub(cached_block) + 1
                    < self.config.required_confirmations
                {
                    continue;
                }
                let Ok(tx_hash) = tx.tx_hash.parse::<B256>() else {
                    continue;
                };
                let receipt = match provider.get_transaction_receipt(tx_hash).await {
                    Ok(Some(r)) => r,
                    Ok(None) => {
                        // Receipt vanished: the block was orphaned and the reorg path
                        // (or the next pending check) will reset it. Do not confirm.
                        debug!(tx_hash = %tx.tx_hash, "MINED tx has no receipt now; awaiting reorg reset");
                        continue;
                    }
                    Err(e) => {
                        warn!(tx_hash = %tx.tx_hash, error = %e, "Receipt lookup failed at confirmation");
                        continue;
                    }
                };
                let Some(receipt_block) = receipt.block_number else {
                    continue;
                };
                // Tracked canonical hash for the receipt's block, if we have that height.
                let tracked_hash = {
                    let detector = self.reorg_detector.read().await;
                    detector.get_block(receipt_block).map(|b| b.hash)
                };
                let Some(canonical) = canonical_confirmations(
                    receipt_block,
                    receipt.block_hash,
                    current_block,
                    tracked_hash,
                ) else {
                    warn!(
                        tx_hash = %tx.tx_hash,
                        receipt_block,
                        "Receipt block hash disagrees with the tracked canonical chain; not confirming"
                    );
                    continue;
                };
                if receipt_block != cached_block {
                    info!(
                        tx_hash = %tx.tx_hash,
                        cached_block,
                        receipt_block,
                        "Mined block changed since caching (shallow re-mine); using receipt block"
                    );
                    let mut cache = self.cache.write().await;
                    if let Some(cached) = cache.get_mut(&tx_hash) {
                        cached.block_number = Some(receipt_block);
                        cached.block_hash = receipt.block_hash.map(|h| format!("{h:?}"));
                    }
                }
                let confirmations = canonical;

                if confirmations < self.config.required_confirmations {
                    continue;
                }
                info!(tx_hash = %tx.tx_hash, confirmations, "Transaction confirmed");

                // Ordering invariant (state recovery): finalize the nonce FIRST. Only after
                // finalization succeeds do we mark CONFIRMED and cache the state. If
                // finalization fails, keep the tx MINED so the next block retries;
                // re-finalization is idempotent.
                if let Err(e) = self.finalize_nonce(&tx.wallet, tx.nonce).await {
                    warn!(
                        tx_hash = %tx.tx_hash,
                        error = %e,
                        "Nonce finalization failed at confirmation; keeping MINED to retry on the next block"
                    );
                    continue;
                }

                self.store
                    .mark_confirmed(&tx.wallet, &tx.tx_hash, confirmations)
                    .await?;

                {
                    let mut cache = self.cache.write().await;
                    if let Some(cached) = cache.get_mut(&tx_hash) {
                        cached.status = TxStatus::Confirmed;
                    }
                }

                // Deliberately NOT removed from the reorg detector here. CONFIRMED is not
                // final: the detector keeps tracking the tx until `finality_blocks`
                // (required_confirmations + buffer) so a reorg deeper than
                // required_confirmations still resets it. Removal happens in
                // `finalize_confirmed_transactions`.
            }
        }

        Ok(())
    }

    /// Finalize transactions that have reached required confirmations
    async fn finalize_confirmed_transactions(&self, current_block: u64) -> Result<()> {
        // Get transactions that have reached finality from reorg detector
        let finalized = {
            let detector = self.reorg_detector.read().await;
            detector.get_finalized_txs(current_block)
        };

        for tx in finalized {
            debug!(
                tx_hash = ?tx.tx_hash,
                block = tx.block_number,
                "Transaction reached finality, removing from reorg tracking"
            );

            // Family rows remain ACTIVE through the reorg window. The periodic cache
            // refresh deliberately loads active statuses only and therefore drops a
            // CONFIRMED winner before this +20-block boundary. Use the reorg detector's
            // durable identity (wallet/nonce/hash), not the refreshable cache.
            let wallet = parse_finalize_wallet(&tx.wallet)?;
            let ttl = Utc::now().timestamp() + self.config.ttl_days * 86_400;
            if let Err(e) = self
                .nonce_manager
                .complete_replacement_family(wallet, tx.nonce, tx.tx_hash, "CONFIRMED", ttl)
                .await
            {
                warn!(tx_hash=?tx.tx_hash, error=%e, "Family finalization failed; retaining reorg tracking to retry");
                continue;
            }
            let winner_hash = format!("{:?}", tx.tx_hash).to_lowercase();
            if let Err(e) = self
                .store
                .mark_family_siblings_replaced(&tx.wallet, tx.nonce, &winner_hash)
                .await
            {
                warn!(tx_hash=?tx.tx_hash, error=%e, "Sibling terminalization failed; retaining reorg tracking to retry");
                continue;
            }

            // Remove from reorg detector
            {
                let mut detector = self.reorg_detector.write().await;
                detector.remove_tx(&tx.tx_hash);
            }

            // Remove every same-wallet/same-nonce candidate from cache (legacy txs
            // have exactly one; replacement families may have several).
            {
                let mut cache = self.cache.write().await;
                cache.retain(|_, candidate| {
                    !(candidate.wallet.eq_ignore_ascii_case(&tx.wallet)
                        && candidate.nonce == tx.nonce)
                });
            }
        }

        Ok(())
    }

    /// Refresh the transaction cache from DynamoDB
    async fn refresh_cache(&self) -> Result<()> {
        let records = self
            .store
            .get_active_transactions(self.config.chain_id)
            .await?;

        let mut cache = self.cache.write().await;
        // Preserve the in-memory re-injection timestamps across the rebuild so a refresh
        // cannot reset the per-transaction rebroadcast rate limit.
        let last_rebroadcasts: HashMap<B256, DateTime<Utc>> = cache
            .iter()
            .filter_map(|(h, tx)| tx.last_rebroadcast.map(|t| (*h, t)))
            .collect();
        cache.clear();

        for record in records {
            if let Ok(tx_hash) = record.tx_hash.parse::<B256>() {
                cache.insert(
                    tx_hash,
                    CachedTx {
                        wallet: record.wallet,
                        tx_hash: record.tx_hash,
                        nonce: record.nonce,
                        status: record.status,
                        block_number: record.block_number,
                        block_hash: record.block_hash,
                        signed_raw_tx: record.signed_raw_tx,
                        submitted_at: record.submitted_at,
                        family_nonce: record.family_nonce,
                        replacement_generation: record.replacement_generation,
                        replacement_active: record.replacement_active.unwrap_or(true),
                        next_eligible_replacement_block: record.next_eligible_replacement_block,
                        replacement_max_bumps: record.replacement_max_bumps,
                        replacement_on_exhaust: record.replacement_on_exhaust,
                        replacement_action: record.replacement_action,
                        replacement_exhausted: record.replacement_exhausted.unwrap_or(false),
                        last_rebroadcast: last_rebroadcasts.get(&tx_hash).copied(),
                    },
                );
            }
        }

        debug!(count = cache.len(), "Cache refreshed");
        Ok(())
    }

    async fn complete_family(&self, tx: &CachedTx, outcome: &str) -> Result<()> {
        let Some(nonce) = tx.family_nonce else {
            return Ok(());
        };
        let wallet = parse_finalize_wallet(&tx.wallet)?;
        let hash = tx
            .tx_hash
            .parse::<B256>()
            .map_err(|_| WatcherError::Store("invalid family candidate hash".into()))?;
        let ttl = Utc::now().timestamp() + self.config.ttl_days * 86_400;
        self.nonce_manager
            .complete_replacement_family(wallet, nonce, hash, outcome, ttl)
            .await?;
        Ok(())
    }

    /// Finalize a nonce after on-chain confirmation, revert, or drop.
    ///
    /// # Ordering invariant (state recovery)
    ///
    /// A transaction must remain in an active DynamoDB status (PENDING / MINED) and in
    /// the in-memory cache until finalization here returns `Ok(())`. Every caller MUST
    /// finalize the nonce and observe success *before* writing a terminal status
    /// (FAILED / DROPPED / CONFIRMED) or evicting the transaction from the cache. This
    /// makes a one-time failure recoverable: the transaction stays active and a later
    /// block/cache pass retries, instead of the failure becoming permanent. Repeat
    /// finalization of the same nonce is idempotent.
    ///
    /// Finalization is **always** `confirm_transaction`: every terminal watcher outcome
    /// (mined-and-confirmed, mined-but-reverted, dropped-with-nonce-consumed) means the
    /// nonce was spent on-chain, so it is consumed and the confirmed watermark advances.
    /// `mark_failed` (which recycles a RESERVED nonce to the gap pool) is deliberately
    /// NOT used here: recycling a consumed nonce would hand out a dead nonce and wedge
    /// the wallet.
    ///
    /// Returns `Err` on an invalid wallet address or any nonce-manager failure — these
    /// are not swallowed. Draining the pending set here also keeps it bounded.
    async fn finalize_nonce(&self, wallet: &str, nonce: u64) -> Result<()> {
        let address = parse_finalize_wallet(wallet)?;
        self.nonce_manager
            .confirm_transaction(address, nonce)
            .await?;
        debug!(wallet, nonce, "Nonce finalized (confirmed)");
        Ok(())
    }
}

/// Parse a wallet address for nonce finalization, mapping a parse failure to a hard
/// error instead of a swallowed log. Finalization must fail closed on a bad address:
/// see the ordering invariant on [`TransactionWatcher::finalize_nonce`].
fn parse_finalize_wallet(wallet: &str) -> Result<Address> {
    wallet.parse::<Address>().map_err(|_| {
        WatcherError::NonceManager(nonce_manager::NonceError::InvalidAddress(
            wallet.to_string(),
        ))
    })
}

/// Classify a SIGNED-row rebroadcast outcome against the expected (locally stored) hash.
/// Pure so the exact-byte recovery disposition is testable without a node. Error text is
/// classified by the shared [`classify_send_error`] table so the watcher and the
/// broadcaster never disagree about what a node message means.
fn replacement_decision(tx: &CachedTx, current_block: u64) -> ReplacementDecision {
    if !tx.replacement_active
        || tx.replacement_exhausted
        || tx.replacement_action.as_deref() == Some("cancel")
    {
        return ReplacementDecision::None;
    }
    let (Some(generation), Some(max_bumps), Some(eligible)) = (
        tx.replacement_generation,
        tx.replacement_max_bumps,
        tx.next_eligible_replacement_block,
    ) else {
        return ReplacementDecision::None;
    };
    if current_block < eligible {
        return ReplacementDecision::None;
    }
    if generation < max_bumps {
        return ReplacementDecision::SpeedUp;
    }
    match tx.replacement_on_exhaust.as_deref() {
        Some("cancel") => ReplacementDecision::Cancel,
        Some("hold") => ReplacementDecision::Exhaust,
        _ => ReplacementDecision::None,
    }
}

fn classify_rebroadcast(
    expected: B256,
    result: &std::result::Result<B256, String>,
) -> RebroadcastDisposition {
    match result {
        Ok(node_hash) if *node_hash == expected => RebroadcastDisposition::MarkBroadcast,
        Ok(node_hash) => RebroadcastDisposition::HashMismatch {
            node_hash: *node_hash,
        },
        Err(e) => match classify_send_error(e) {
            SendRejection::AlreadyKnown => RebroadcastDisposition::MarkBroadcast,
            SendRejection::NonceTooLow => RebroadcastDisposition::CheckReceipt,
            SendRejection::Definitive => RebroadcastDisposition::Refused,
            SendRejection::Ambiguous => RebroadcastDisposition::LeaveSigned,
        },
    }
}

/// Decide whether a SIGNED row whose rebroadcast returned `nonce too low`, and whose
/// stored hash has **no** receipt, should be finalized as DROPPED.
///
/// `nonce too low` proves the nonce is consumed at the queried node; a missing receipt
/// for our exact hash means something else consumed it (out-of-band send, replacement,
/// or an operator unsticking the wallet). Two guards keep this fail-closed:
/// * `latest_nonce > nonce` must hold from a fresh `eth_getTransactionCount(latest)` —
///   the send error alone is not trusted;
/// * the row must be older than `stuck_threshold`, so a just-mined transaction whose
///   receipt lags on a load-balanced endpoint is not misfiled as dropped.
///
/// The caller additionally re-queries the receipt once more before acting.
fn signed_nonce_consumed_by_other(
    latest_nonce: u64,
    nonce: u64,
    age_secs: i64,
    stuck_threshold_secs: u64,
) -> bool {
    latest_nonce > nonce && age_secs >= stuck_threshold_secs as i64
}

/// Whether a stale PENDING row is due for another identical-byte re-injection: never
/// re-injected yet, or at least `interval_secs` since the last attempt. Pure for testing.
fn reinject_due(last: Option<DateTime<Utc>>, now: DateTime<Utc>, interval_secs: u64) -> bool {
    match last {
        None => true,
        Some(t) => now.signed_duration_since(t).num_seconds() >= interval_secs as i64,
    }
}

/// Compute confirmations for a mined transaction from its **receipt's** block, refusing
/// when the receipt's block hash disagrees with the tracked canonical hash at that height.
///
/// `tracked_hash` is the canonical block hash the reorg detector holds for the receipt's
/// height, or `None` if that height is not tracked (older than the history window, or not
/// yet seen). Untracked heights are accepted on the receipt alone. Returns `None` when the
/// receipt is on a block we consider orphaned — the caller must not confirm.
fn canonical_confirmations(
    receipt_block: u64,
    receipt_block_hash: Option<B256>,
    current_block: u64,
    tracked_hash: Option<B256>,
) -> Option<u64> {
    if let (Some(rh), Some(th)) = (receipt_block_hash, tracked_hash)
        && rh != th
    {
        return None;
    }
    Some(current_block.saturating_sub(receipt_block) + 1)
}

/// Upper bound on blocks backfilled in one catch-up. Matches the reorg detector's history
/// window: blocks older than that cannot participate in reorg detection anyway, and every
/// pending transaction is receipt-checked on each live block regardless.
const MAX_CATCH_UP_BLOCKS: u64 = 256;

/// Fetch attempts per catch-up block before it is skipped.
const CATCH_UP_FETCH_ATTEMPTS: u32 = 3;

/// Inclusive range of blocks to backfill between the last processed block and `head`,
/// or `None` when nothing is missing. Bounded to the most recent `max_blocks` so a long
/// outage does not replay the whole gap. Pure for testing.
fn catch_up_range(last_processed: u64, head: u64, max_blocks: u64) -> Option<(u64, u64)> {
    if head <= last_processed {
        return None;
    }
    let from = (last_processed + 1).max(head.saturating_sub(max_blocks.saturating_sub(1)));
    Some((from, head))
}

/// Whether the signed bytes hash (keccak256) to the expected stored tx hash. The exact
/// bytes are rebroadcast verbatim, so this integrity check must pass before any send.
fn signed_bytes_match(bytes: &[u8], expected: B256) -> bool {
    keccak256(bytes) == expected
}

/// Decide how to resolve a stale `RESERVED` reservation from the wallet's chain nonces.
/// Pure so the fail-closed decision table is testable without a node (requirement 4):
/// * `latest > nonce`          → consumed on-chain → Confirm
/// * `latest <= nonce < pending` → occupied in mempool, not mined → LeaveReserved
/// * otherwise                 → truly unused → Release
fn classify_stale_reservation(
    latest_nonce: u64,
    pending_nonce: u64,
    reserved_nonce: u64,
) -> StaleDisposition {
    if latest_nonce > reserved_nonce {
        StaleDisposition::Confirm
    } else if pending_nonce > reserved_nonce {
        StaleDisposition::LeaveReserved
    } else {
        StaleDisposition::Release
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn replacement_tx(generation: u32, max_bumps: u32, eligible: u64) -> CachedTx {
        CachedTx {
            wallet: format!("{:?}", Address::repeat_byte(1)),
            tx_hash: format!("{:?}", B256::repeat_byte(2)),
            nonce: 7,
            status: TxStatus::Pending,
            block_number: None,
            block_hash: None,
            signed_raw_tx: Some(vec![0x02]),
            submitted_at: Utc::now(),
            family_nonce: Some(7),
            replacement_generation: Some(generation),
            replacement_active: true,
            next_eligible_replacement_block: Some(eligible),
            replacement_max_bumps: Some(max_bumps),
            replacement_on_exhaust: Some("hold".into()),
            replacement_action: Some("original".into()),
            replacement_exhausted: false,
            last_rebroadcast: None,
        }
    }

    #[test]
    fn replacement_is_block_cadenced_and_generation_bounded() {
        let tx = replacement_tx(0, 3, 100);
        assert_eq!(replacement_decision(&tx, 99), ReplacementDecision::None);
        assert_eq!(replacement_decision(&tx, 100), ReplacementDecision::SpeedUp);
        let mut exhausted = replacement_tx(3, 3, 100);
        assert_eq!(
            replacement_decision(&exhausted, 100),
            ReplacementDecision::Exhaust
        );
        exhausted.replacement_on_exhaust = Some("cancel".into());
        assert_eq!(
            replacement_decision(&exhausted, 100),
            ReplacementDecision::Cancel
        );
    }

    #[test]
    fn inactive_or_cancel_candidate_never_requests_another_replacement() {
        let mut tx = replacement_tx(0, 3, 100);
        tx.replacement_active = false;
        assert_eq!(replacement_decision(&tx, 100), ReplacementDecision::None);
        tx.replacement_active = true;
        tx.replacement_action = Some("cancel".into());
        assert_eq!(replacement_decision(&tx, 100), ReplacementDecision::None);
    }
    #[test]
    fn parse_finalize_wallet_accepts_valid_address() {
        let wallet = "0x000000000000000000000000000000000000dead";
        let addr = parse_finalize_wallet(wallet).expect("valid address must parse");
        assert_eq!(addr, wallet.parse::<Address>().unwrap());
    }

    #[test]
    fn parse_finalize_wallet_rejects_invalid_address_as_error() {
        // The invariant depends on finalization failing (not swallowing) on a bad
        // wallet, so the caller keeps the tx active and retries rather than writing a
        // terminal status with an un-finalized nonce.
        let err = parse_finalize_wallet("not-an-address").unwrap_err();
        match err {
            WatcherError::NonceManager(nonce_manager::NonceError::InvalidAddress(w)) => {
                assert_eq!(w, "not-an-address");
            }
            other => panic!("expected InvalidAddress error, got {other:?}"),
        }
    }

    #[test]
    fn parse_finalize_wallet_rejects_empty_as_error() {
        assert!(matches!(
            parse_finalize_wallet(""),
            Err(WatcherError::NonceManager(
                nonce_manager::NonceError::InvalidAddress(_)
            ))
        ));
    }

    // ---- rebroadcast disposition ----

    #[test]
    fn rebroadcast_expected_hash_marks_broadcast() {
        let expected = B256::from([0x11; 32]);
        let result = Ok(expected);
        assert_eq!(
            classify_rebroadcast(expected, &result),
            RebroadcastDisposition::MarkBroadcast
        );
    }

    #[test]
    fn rebroadcast_already_known_marks_broadcast() {
        let expected = B256::from([0x22; 32]);
        // A node that already has the identical bytes reports "already known".
        for msg in [
            "already known",
            "ALREADY KNOWN",
            "err: already imported",
            "known transaction: 0xabc",
        ] {
            let result: std::result::Result<B256, String> = Err(msg.to_string());
            assert_eq!(
                classify_rebroadcast(expected, &result),
                RebroadcastDisposition::MarkBroadcast,
                "message {msg:?} should be treated as already-known"
            );
        }
    }

    #[test]
    fn rebroadcast_nonce_too_low_requires_receipt_check() {
        let expected = B256::from([0x33; 32]);
        for msg in ["nonce too low", "Nonce Too Low: next nonce 4"] {
            let result: std::result::Result<B256, String> = Err(msg.to_string());
            assert_eq!(
                classify_rebroadcast(expected, &result),
                RebroadcastDisposition::CheckReceipt,
                "message {msg:?} must require exact-hash receipt proof"
            );
        }
    }

    #[test]
    fn rebroadcast_timeout_or_other_error_leaves_signed() {
        let expected = B256::from([0x34; 32]);
        for msg in ["request timed out", "connection refused"] {
            let result: std::result::Result<B256, String> = Err(msg.to_string());
            assert_eq!(
                classify_rebroadcast(expected, &result),
                RebroadcastDisposition::LeaveSigned,
                "message {msg:?} should leave the row SIGNED"
            );
        }
    }

    #[test]
    fn rebroadcast_definitive_refusal_is_refused_not_left_signed_silently() {
        // A refusal intrinsic to the bytes is surfaced (warn) but the nonce is never
        // recycled from the watcher: an earlier ambiguous send may still be gossiping.
        let expected = B256::repeat_byte(0x5a);
        for msg in [
            "insufficient funds for gas * price + value",
            "max fee per gas less than block base fee",
            "intrinsic gas too low",
        ] {
            assert_eq!(
                classify_rebroadcast(expected, &Err(msg.to_string())),
                RebroadcastDisposition::Refused,
                "{msg}"
            );
        }
    }

    #[test]
    fn signed_nonce_consumed_by_other_requires_fresh_nonce_and_age() {
        // N-H2 gate: both conditions must hold.
        assert!(signed_nonce_consumed_by_other(6, 5, 400, 300));
        assert!(
            signed_nonce_consumed_by_other(6, 5, 300, 300),
            "age equal to threshold counts"
        );
        // latest == nonce: not consumed.
        assert!(!signed_nonce_consumed_by_other(5, 5, 400, 300));
        // latest behind: not consumed.
        assert!(!signed_nonce_consumed_by_other(4, 5, 400, 300));
        // consumed but too young: wait (receipt may lag).
        assert!(!signed_nonce_consumed_by_other(6, 5, 299, 300));
        assert!(
            !signed_nonce_consumed_by_other(6, 5, -5, 300),
            "clock skew never triggers"
        );
    }

    #[test]
    fn reinject_rate_limit_is_once_per_interval() {
        let now = Utc::now();
        assert!(
            reinject_due(None, now, 300),
            "first re-injection is always due"
        );
        assert!(!reinject_due(Some(now), now, 300), "just re-injected");
        assert!(!reinject_due(
            Some(now - chrono::Duration::seconds(299)),
            now,
            300
        ));
        assert!(reinject_due(
            Some(now - chrono::Duration::seconds(300)),
            now,
            300
        ));
        assert!(reinject_due(
            Some(now - chrono::Duration::seconds(10_000)),
            now,
            300
        ));
    }

    #[test]
    fn catch_up_range_is_inclusive_and_bounded() {
        // Nothing missing.
        assert_eq!(catch_up_range(10, 10, 256), None);
        assert_eq!(catch_up_range(10, 9, 256), None);
        // Contiguous next block: nothing to backfill before it.
        assert_eq!(catch_up_range(10, 11, 256), Some((11, 11)));
        // Small gap: everything from last+1 through head, head inclusive.
        assert_eq!(catch_up_range(10, 15, 256), Some((11, 15)));
        // Long outage: only the most recent `max_blocks`.
        assert_eq!(catch_up_range(0, 10_000, 256), Some((9_745, 10_000)));
        assert_eq!(catch_up_range(0, 10_000, 1), Some((10_000, 10_000)));
    }

    #[test]
    fn canonical_confirmations_uses_receipt_block_and_refuses_orphaned_hash() {
        let a = B256::repeat_byte(0xa1);
        let b = B256::repeat_byte(0xb2);
        // Receipt block tracked with the same hash: count from the receipt's block.
        assert_eq!(
            canonical_confirmations(100, Some(a), 111, Some(a)),
            Some(12)
        );
        // Height not tracked (older than history): accept on the receipt alone.
        assert_eq!(canonical_confirmations(100, Some(a), 111, None), Some(12));
        // Receipt without a block hash: cannot compare; accept.
        assert_eq!(canonical_confirmations(100, None, 111, Some(a)), Some(12));
        // Receipt on a block we consider orphaned: refuse.
        assert_eq!(canonical_confirmations(100, Some(a), 111, Some(b)), None);
        // Same block as head: one confirmation.
        assert_eq!(canonical_confirmations(111, Some(a), 111, Some(a)), Some(1));
    }

    #[test]
    fn rebroadcast_hash_mismatch_is_flagged() {
        let expected = B256::from([0x44; 32]);
        let node_hash = B256::from([0x55; 32]);
        assert_eq!(
            classify_rebroadcast(expected, &Ok(node_hash)),
            RebroadcastDisposition::HashMismatch { node_hash }
        );
    }

    // ---- exact-byte integrity ----

    #[test]
    fn signed_bytes_match_only_on_exact_keccak() {
        let bytes = [0x02u8, 0xf8, 0x01, 0x02, 0x03];
        let expected = keccak256(bytes);
        assert!(signed_bytes_match(&bytes, expected));
        // Any different bytes fail the check.
        assert!(!signed_bytes_match(
            &[0x02u8, 0xf8, 0x01, 0x02, 0x04],
            expected
        ));
        // A wrong expected hash fails.
        assert!(!signed_bytes_match(&bytes, B256::from([0x00; 32])));
    }

    // ---- stale reservation chain decision ----

    #[test]
    fn stale_reservation_confirm_when_latest_past_nonce() {
        // latest advanced past the nonce → consumed on-chain → confirm.
        assert_eq!(
            classify_stale_reservation(11, 11, 10),
            StaleDisposition::Confirm
        );
        assert_eq!(
            classify_stale_reservation(50, 60, 10),
            StaleDisposition::Confirm
        );
    }

    #[test]
    fn stale_reservation_leaves_reserved_when_occupied_but_not_mined() {
        // latest == nonce (not yet mined) but pending is ahead → slot occupied → leave.
        assert_eq!(
            classify_stale_reservation(10, 12, 10),
            StaleDisposition::LeaveReserved
        );
        // latest below nonce, pending just past it.
        assert_eq!(
            classify_stale_reservation(5, 11, 10),
            StaleDisposition::LeaveReserved
        );
    }

    #[test]
    fn stale_reservation_releases_when_truly_unused() {
        // Neither latest nor pending reached the nonce → safe to release.
        assert_eq!(
            classify_stale_reservation(10, 10, 10),
            StaleDisposition::Release
        );
        assert_eq!(
            classify_stale_reservation(5, 8, 10),
            StaleDisposition::Release
        );
    }
}
