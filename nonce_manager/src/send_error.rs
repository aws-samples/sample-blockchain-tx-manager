//! Classification of `eth_sendRawTransaction` errors.
//!
//! A send error is **not** one state. The nonce authority must distinguish:
//!
//! * [`SendRejection::AlreadyKnown`] — the node already holds these exact bytes. For a
//!   rebroadcast this is success; for a first send it means an earlier attempt landed.
//! * [`SendRejection::NonceTooLow`] — the nonce is consumed on-chain. Either these bytes
//!   mined or a different transaction spent the nonce; only a receipt lookup for the
//!   stored hash can tell. Never recycle.
//! * [`SendRejection::Definitive`] — the node refused admission for a reason intrinsic to
//!   the signed bytes or the account (fees, funds, gas, encoding). The transaction was
//!   never accepted into any mempool by this call, so a *first* send may retire the
//!   reservation and recycle the nonce. A rebroadcast of bytes that may already have
//!   left the process must **not** recycle on this outcome (an earlier ambiguous send
//!   could still be gossiping).
//! * [`SendRejection::Ambiguous`] — anything else: transport failures, timeouts,
//!   `txpool is full`, `nonce too high`, `replacement transaction underpriced`, and
//!   unrecognised messages. Fail closed: keep the durable SIGNED row and let the watcher
//!   rebroadcast the identical bytes.
//!
//! The definitive set is a deliberate allowlist of well-known geth/reth/erigon/nethermind
//! admission errors. Anything not on it is ambiguous. Pure and side-effect free so both
//! the broadcast Lambda and the watcher classify identically and the table is testable
//! without a node.

/// Outcome class of an `eth_sendRawTransaction` error string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendRejection {
    /// Node already has these bytes (`already known`, `known transaction`, …).
    AlreadyKnown,
    /// Nonce consumed on-chain (`nonce too low`).
    NonceTooLow,
    /// Admission refused for a reason intrinsic to the bytes/account; never entered a pool.
    Definitive,
    /// Unknown, transient, or occupancy-related; the bytes may or may not be in a pool.
    Ambiguous,
}

/// Messages meaning the node already holds the transaction.
const ALREADY_KNOWN: &[&str] = &["already known", "already imported", "known transaction"];

/// Admission errors intrinsic to the signed bytes or the sending account. Lowercase
/// substrings; matched against the lowercased error text.
const DEFINITIVE: &[&str] = &[
    // balance
    "insufficient funds",
    // gas limit
    "intrinsic gas too low",
    "exceeds block gas limit",
    "gas limit too high",
    "gas uint64 overflow",
    // EIP-1559 fee shape
    "max fee per gas less than block base fee",
    "fee cap less than block base fee",
    "max priority fee per gas higher than max fee per gas",
    "tip higher than fee cap",
    "fee cap higher than 2^256-1",
    "tip higher than 2^256-1",
    // encoding / signature / chain
    "invalid sender",
    "invalid signature",
    "invalid chain id",
    "chain id mismatch",
    "transaction type not supported",
    "oversized data",
    "rlp:",
];

/// Classify an `eth_sendRawTransaction` error string.
pub fn classify_send_error(err: &str) -> SendRejection {
    let e = err.to_lowercase();
    if ALREADY_KNOWN.iter().any(|m| e.contains(m)) {
        return SendRejection::AlreadyKnown;
    }
    if e.contains("nonce too low") {
        return SendRejection::NonceTooLow;
    }
    // Occupancy / capacity errors are checked before the definitive allowlist so that a
    // message containing both (e.g. "replacement transaction underpriced") stays ambiguous.
    if e.contains("replacement transaction underpriced")
        || e.contains("txpool is full")
        || e.contains("nonce too high")
    {
        return SendRejection::Ambiguous;
    }
    if DEFINITIVE.iter().any(|m| e.contains(m)) {
        return SendRejection::Definitive;
    }
    SendRejection::Ambiguous
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn already_known_variants() {
        for m in [
            "already known",
            "ALREADY KNOWN",
            "server returned an error response: error code -32000: already known",
            "known transaction: 0xabc",
            "transaction already imported",
        ] {
            assert_eq!(classify_send_error(m), SendRejection::AlreadyKnown, "{m}");
        }
    }

    #[test]
    fn nonce_too_low_is_not_definitive() {
        assert_eq!(
            classify_send_error("error code -32000: nonce too low: next nonce 5, tx nonce 3"),
            SendRejection::NonceTooLow
        );
    }

    #[test]
    fn definitive_admission_errors() {
        for m in [
            "insufficient funds for gas * price + value: have 0 want 21000",
            "insufficient funds for transfer",
            "intrinsic gas too low: have 20000, want 21000",
            "exceeds block gas limit",
            "max fee per gas less than block base fee: address 0x.. maxFeePerGas: 1 baseFee: 7",
            "fee cap less than block base fee",
            "max priority fee per gas higher than max fee per gas",
            "invalid sender",
            "invalid chain id for signer",
            "oversized data: transaction size 200000, limit 131072",
            "rlp: expected input list for types.DynamicFeeTx",
        ] {
            assert_eq!(classify_send_error(m), SendRejection::Definitive, "{m}");
        }
    }

    #[test]
    fn ambiguous_by_default_and_for_occupancy() {
        for m in [
            "",
            "connection reset by peer",
            "operation timed out",
            "error sending request for url",
            "replacement transaction underpriced",
            "transaction underpriced",
            "txpool is full",
            "nonce too high",
            "some brand new node error nobody has seen",
        ] {
            assert_eq!(classify_send_error(m), SendRejection::Ambiguous, "{m}");
        }
    }
}
