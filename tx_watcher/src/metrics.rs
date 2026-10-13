//! Watcher progress metrics via CloudWatch Embedded Metric Format (EMF).
//!
//! The ECS `awslogs` driver ships stdout to CloudWatch Logs, which extracts metrics
//! from any line that is a valid EMF JSON document. This gives the watcher a real
//! liveness signal (`BlocksProcessed`) and a data-freshness signal (`BlockLagSeconds`)
//! with no CloudWatch SDK, no IAM permission, and no background flusher. Alarms in the
//! CDK stack treat *missing* `BlocksProcessed` data as breaching, so a watcher that is
//! running but not making progress pages exactly like one that is dead.
//!
//! One document per processed block. Written with `println!` rather than `tracing` so
//! the top-level `_aws` key lands exactly where the EMF parser requires it (the JSON
//! tracing layer would nest it under `fields`).

use serde_json::json;

/// CloudWatch namespace for watcher metrics.
pub const NAMESPACE: &str = "TxManager/Watcher";

/// Progress snapshot emitted after each processed block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockProgress {
    pub chain_id: u64,
    pub block_number: u64,
    /// `now - block.timestamp`, clamped at zero. Large values mean the provider is
    /// feeding stale blocks even though headers are arriving.
    pub block_lag_secs: u64,
    /// Number of SIGNED/PENDING/MINED rows currently tracked.
    pub active_transactions: usize,
}

/// Render the EMF document for one processed block. Pure so the shape is testable.
pub fn render(progress: &BlockProgress, timestamp_ms: i64) -> String {
    json!({
        "_aws": {
            "Timestamp": timestamp_ms,
            "CloudWatchMetrics": [{
                "Namespace": NAMESPACE,
                "Dimensions": [["ChainId"]],
                "Metrics": [
                    { "Name": "BlocksProcessed", "Unit": "Count" },
                    { "Name": "BlockLagSeconds", "Unit": "Seconds" },
                    { "Name": "ActiveTransactions", "Unit": "Count" }
                ]
            }]
        },
        "ChainId": progress.chain_id.to_string(),
        "BlocksProcessed": 1,
        "BlockLagSeconds": progress.block_lag_secs,
        "ActiveTransactions": progress.active_transactions,
        "BlockNumber": progress.block_number,
    })
    .to_string()
}

/// Emit one EMF document to stdout.
pub fn emit(progress: &BlockProgress) {
    println!(
        "{}",
        render(progress, chrono::Utc::now().timestamp_millis())
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emf_document_has_required_shape() {
        let doc = render(
            &BlockProgress {
                chain_id: 11155111,
                block_number: 42,
                block_lag_secs: 7,
                active_transactions: 3,
            },
            1_700_000_000_000,
        );
        let v: serde_json::Value = serde_json::from_str(&doc).expect("valid JSON");
        assert_eq!(v["_aws"]["Timestamp"], 1_700_000_000_000i64);
        let cw = &v["_aws"]["CloudWatchMetrics"][0];
        assert_eq!(cw["Namespace"], NAMESPACE);
        assert_eq!(cw["Dimensions"][0][0], "ChainId");
        let names: Vec<&str> = cw["Metrics"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| m["Name"].as_str().unwrap())
            .collect();
        assert_eq!(
            names,
            ["BlocksProcessed", "BlockLagSeconds", "ActiveTransactions"]
        );
        // Dimension value and every metric value are top-level members.
        assert_eq!(v["ChainId"], "11155111");
        assert_eq!(v["BlocksProcessed"], 1);
        assert_eq!(v["BlockLagSeconds"], 7);
        assert_eq!(v["ActiveTransactions"], 3);
        assert_eq!(v["BlockNumber"], 42);
        // Single line: the awslogs driver treats each line as one event.
        assert!(!doc.contains('\n'));
    }
}
