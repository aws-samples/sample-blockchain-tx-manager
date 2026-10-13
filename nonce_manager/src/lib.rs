//! DynamoDB-backed Nonce Manager for Ethereum Transaction Management
//!
//! High-performance Rust implementation for managing Ethereum nonces with DynamoDB as
//! the sole nonce authority. Supports concurrent transactions, atomic reservation via
//! conditional `TransactWriteItems`, crash recovery via a status GSI, and multi-chain
//! deployments.
//!
//! # Multi-Chain Support
//!
//! Each `DynamoNonceManager` instance is bound to a specific chain_id and a per-chain
//! tracker table, ensuring nonce isolation across different EVM networks.
//!
//! # Features
//!
//! - Single-store state machine: nonce state and durable tracker rows in one table
//! - Atomic nonce reservation via conditional `TransactWriteItems`
//! - Concurrent transaction support (thread-safe)
//! - Gap detection and reuse
//! - Crash recovery: `RESERVED` rows are discoverable via the `status-chain-index` GSI
//!
//! # Example
//!
//! ```ignore
//! use nonce_manager::{DynamoNonceManager, ConcurrentExecutor, RetryConfig, FailureType};
//!
//! // Create manager for Ethereum mainnet (chain_id = 1)
//! let manager = DynamoNonceManager::with_defaults(ddb_client, table, provider, 1);
//! let executor = ConcurrentExecutor::new(manager, RetryConfig::default());
//! ```

pub mod batch;
pub mod error;
pub mod flow;
pub mod lambda;
pub mod manager;
pub mod retry;
pub mod rpc_secret;
pub mod send_error;
pub mod types;

pub use batch::{BatchExecutor, BatchTxResult};
pub use error::{NonceError, Result};
pub use flow::TransactionFlow;
pub use lambda::{LambdaExecutor, LambdaSubmitResult, PendingTxQuery};
pub use manager::DynamoNonceManager;
pub use retry::{ConcurrentExecutor, FailureType, RetryConfig, TxAttemptResult};
pub use rpc_secret::{RpcEndpoints, load_rpc_endpoints};
pub use send_error::{SendRejection, classify_send_error};
pub use types::{
    ExhaustionAction, FeeSpeed, NonceManagerConfig, PendingTransaction, ReplacementFamily,
    ReplacementFamilyInit, ReservationState, ResolvedReplacementPolicy, StaleReservation, TxStatus,
    WalletState,
};
