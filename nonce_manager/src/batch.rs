//! Batch transaction execution for high-throughput scenarios
//!
//! Safely executes multiple transactions concurrently from the same wallet

use crate::manager::DynamoNonceManager;
use crate::retry::{ConcurrentExecutor, FailureType, RetryConfig};
use alloy::primitives::{Address, B256, U256};
use alloy::providers::Provider;
use std::sync::Arc;
use tokio::sync::Semaphore;
use tracing::info;

/// Result of a batch transaction
#[derive(Debug)]
pub struct BatchTxResult {
    pub index: usize,
    pub result: std::result::Result<(u64, B256), String>,
}

/// Batch executor for concurrent transaction submission
pub struct BatchExecutor<P>
where
    P: Provider + Clone,
{
    executor: Arc<ConcurrentExecutor<P>>,
    max_concurrency: usize,
}

impl<P> BatchExecutor<P>
where
    P: Provider + Clone + Send + Sync + 'static,
{
    pub fn new(
        manager: DynamoNonceManager<P>,
        retry_config: RetryConfig,
        max_concurrency: usize,
    ) -> Self {
        Self {
            executor: Arc::new(ConcurrentExecutor::new(manager, retry_config)),
            max_concurrency,
        }
    }

    /// Get Arc reference to underlying executor for single transactions
    pub fn executor(&self) -> Arc<ConcurrentExecutor<P>> {
        self.executor.clone()
    }

    /// Execute multiple transactions concurrently
    ///
    /// Each transaction gets its own nonce atomically. Safe for concurrent execution.
    pub async fn execute_batch<S, B, C, SF, BF>(
        &self,
        address: Address,
        count: usize,
        simulate: S,
        broadcast: B,
        classify: C,
    ) -> Vec<BatchTxResult>
    where
        S: Fn(u64) -> SF + Clone + Send + Sync + 'static,
        SF: std::future::Future<Output = Result<(), String>> + Send + 'static,
        B: Fn(u64) -> BF + Clone + Send + Sync + 'static,
        BF: std::future::Future<Output = Result<(B256, Vec<u8>, U256), String>> + Send + 'static,
        C: Fn(&str) -> FailureType + Clone + Send + Sync + 'static,
    {
        let semaphore = Arc::new(Semaphore::new(self.max_concurrency));
        let mut handles = Vec::with_capacity(count);

        for index in 0..count {
            let permit = semaphore.clone().acquire_owned().await.unwrap();
            let exec = self.executor.clone();
            let sim = simulate.clone();
            let bc = broadcast.clone();
            let cls = classify.clone();

            let handle = tokio::spawn(async move {
                let _permit = permit;

                let result = exec
                    .execute_with_retry::<S, B, C, SF, BF>(address, sim, bc, cls)
                    .await;

                BatchTxResult {
                    index,
                    result: result.map_err(|e| e.to_string()),
                }
            });

            handles.push(handle);
        }

        let mut results = Vec::with_capacity(count);
        for handle in handles {
            match handle.await {
                Ok(result) => results.push(result),
                Err(e) => results.push(BatchTxResult {
                    index: results.len(),
                    result: Err(format!("Task panicked: {}", e)),
                }),
            }
        }

        results.sort_by_key(|r| r.index);

        info!(
            total = results.len(),
            succeeded = results.iter().filter(|r| r.result.is_ok()).count(),
            "Batch execution complete"
        );

        results
    }
}
