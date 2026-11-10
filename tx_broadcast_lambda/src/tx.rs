//! Transaction building and signing utilities
//!
//! Supports both local signing (via Alloy wallet) and remote signing (via Nitro Enclave).

use alloy::consensus::{SignableTransaction, TxEip1559};
use alloy::primitives::{Address, B256, Bytes, Signature, TxKind, U256};

/// Parameters for building an EIP-1559 transaction
#[derive(Debug, Clone)]
pub struct TxParams {
    pub chain_id: u64,
    pub nonce: u64,
    pub to: Address,
    pub value: U256,
    pub data: Bytes,
    pub gas_limit: u64,
    pub max_fee_per_gas: u128,
    pub max_priority_fee_per_gas: u128,
}

/// Build an unsigned EIP-1559 transaction
pub fn build_unsigned_tx(params: &TxParams) -> TxEip1559 {
    TxEip1559 {
        chain_id: params.chain_id,
        nonce: params.nonce,
        gas_limit: params.gas_limit,
        max_fee_per_gas: params.max_fee_per_gas,
        max_priority_fee_per_gas: params.max_priority_fee_per_gas,
        to: TxKind::Call(params.to),
        value: params.value,
        access_list: Default::default(),
        input: params.data.clone(),
    }
}

/// Get the signing hash for an EIP-1559 transaction
pub fn get_signing_hash(tx: &TxEip1559) -> B256 {
    tx.signature_hash()
}

/// Compute the canonical transaction hash from the exact EIP-2718 signed bytes.
///
/// For a typed (EIP-1559) transaction the on-chain hash is
/// `keccak256(type_byte || rlp(payload))` — i.e. keccak256 over the *entire* EIP-2718
/// envelope, including the leading `0x02` type byte. Broadcasting the raw transaction
/// and hashing those same bytes therefore yields the identical hash the node computes.
///
/// Hashing the exact bytes we hand to `send_raw_transaction` (rather than re-deriving
/// the hash from the parsed transaction) guarantees the recorded hash matches what is
/// broadcast: the durable record and the mempool submission are byte-identical by
/// construction, which is the invariant the SIGNED-state recovery relies on.
pub fn compute_local_tx_hash(signed_tx_bytes: &[u8]) -> B256 {
    alloy::primitives::keccak256(signed_tx_bytes)
}

/// Encode a signed EIP-1559 transaction for broadcast using Alloy's built-in encoding
pub fn encode_signed_tx(tx: &TxEip1559, signature: &alloy::signers::Signature) -> Bytes {
    use alloy::eips::eip2718::Encodable2718;

    // Convert alloy::signers::Signature to alloy::primitives::Signature
    let prim_sig = Signature::new(signature.r(), signature.s(), signature.v());

    // Use into_signed which properly computes the transaction hash
    let signed = tx.clone().into_signed(prim_sig);

    // Use Alloy's built-in EIP-2718 encoding
    let mut buf = Vec::with_capacity(signed.eip2718_encoded_length());
    signed.encode_2718(&mut buf);

    Bytes::from(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::signers::Signature;

    fn test_params() -> TxParams {
        TxParams {
            chain_id: 11155111, // Sepolia
            nonce: 0,
            to: Address::ZERO,
            value: U256::ZERO,
            data: Bytes::new(),
            gas_limit: 21000,
            max_fee_per_gas: 1_000_000_000,
            max_priority_fee_per_gas: 1_000_000_000,
        }
    }

    #[test]
    fn test_build_unsigned_tx() {
        let params = TxParams {
            chain_id: 1,
            nonce: 0,
            to: Address::ZERO,
            value: U256::ZERO,
            data: Bytes::new(),
            gas_limit: 21000,
            max_fee_per_gas: 1_000_000_000,
            max_priority_fee_per_gas: 1_000_000_000,
        };
        let tx = build_unsigned_tx(&params);
        assert_eq!(tx.chain_id, 1);
        assert_eq!(tx.nonce, 0);
    }

    #[test]
    fn test_build_unsigned_tx_all_fields() {
        let to_addr: Address = "0x742d35Cc6634C0532925a3b844Bc9e7595f1dE3B"
            .parse()
            .unwrap();
        let params = TxParams {
            chain_id: 11155111,
            nonce: 42,
            to: to_addr,
            value: U256::from(1_000_000_000_000_000_000u128), // 1 ETH
            data: Bytes::from(vec![0x12, 0x34, 0x56]),
            gas_limit: 100_000,
            max_fee_per_gas: 50_000_000_000,
            max_priority_fee_per_gas: 2_000_000_000,
        };

        let tx = build_unsigned_tx(&params);

        assert_eq!(tx.chain_id, 11155111);
        assert_eq!(tx.nonce, 42);
        assert_eq!(tx.gas_limit, 100_000);
        assert_eq!(tx.max_fee_per_gas, 50_000_000_000);
        assert_eq!(tx.max_priority_fee_per_gas, 2_000_000_000);
        assert_eq!(tx.value, U256::from(1_000_000_000_000_000_000u128));
        assert_eq!(tx.input, Bytes::from(vec![0x12, 0x34, 0x56]));

        // Verify to address
        match tx.to {
            TxKind::Call(addr) => assert_eq!(addr, to_addr),
            _ => panic!("Expected Call transaction"),
        }
    }

    #[test]
    fn test_signing_hash_deterministic() {
        let tx = build_unsigned_tx(&test_params());
        let hash1 = get_signing_hash(&tx);
        let hash2 = get_signing_hash(&tx);
        assert_eq!(hash1, hash2, "Signing hash should be deterministic");
    }

    #[test]
    fn test_signing_hash_changes_with_nonce() {
        let mut params = test_params();
        let tx1 = build_unsigned_tx(&params);
        let hash1 = get_signing_hash(&tx1);

        params.nonce = 1;
        let tx2 = build_unsigned_tx(&params);
        let hash2 = get_signing_hash(&tx2);

        assert_ne!(
            hash1, hash2,
            "Different nonces should produce different hashes"
        );
    }

    #[test]
    fn test_signing_hash_changes_with_chain_id() {
        let mut params = test_params();
        params.chain_id = 1; // Mainnet
        let tx1 = build_unsigned_tx(&params);
        let hash1 = get_signing_hash(&tx1);

        params.chain_id = 11155111; // Sepolia
        let tx2 = build_unsigned_tx(&params);
        let hash2 = get_signing_hash(&tx2);

        assert_ne!(
            hash1, hash2,
            "Different chain IDs should produce different hashes"
        );
    }

    #[test]
    fn test_signing_hash_changes_with_value() {
        let mut params = test_params();
        let tx1 = build_unsigned_tx(&params);
        let hash1 = get_signing_hash(&tx1);

        params.value = U256::from(1000u64);
        let tx2 = build_unsigned_tx(&params);
        let hash2 = get_signing_hash(&tx2);

        assert_ne!(
            hash1, hash2,
            "Different values should produce different hashes"
        );
    }

    #[test]
    fn test_nitro_signature_recovery() {
        // Signature over hash 0x0...01 from a throwaway test key: the private key is
        // keccak256("sample-blockchain-tx-manager test vector (not a real wallet)"),
        // address 0xD764672D0bF0Cf30d2D3D665Bb5edd919Aa86384. It is public by
        // construction and must never hold funds.
        let r = U256::from_str_radix(
            "63b0e704a223cde8b5ddd4eacd25b86cfb1d3edd8c713aecd03944fa4962927d",
            16,
        )
        .unwrap();
        let s = U256::from_str_radix(
            "5533afe99d68aac0a1f7021d7fad22ba105c78b7edc393f6a76e867184e366ed",
            16,
        )
        .unwrap();
        let v = 28u64;

        // v=28 means parity=1 (true)
        let parity = v != 27;
        let sig = Signature::new(r, s, parity);

        // Hash that was signed (0x0...01)
        let hash = B256::left_padding_from(&[1u8]);

        // Recover address
        let recovered = sig
            .recover_address_from_prehash(&hash)
            .expect("recovery should work");
        let expected: Address = "0xD764672D0bF0Cf30d2D3D665Bb5edd919Aa86384"
            .parse()
            .unwrap();

        assert_eq!(
            recovered, expected,
            "Recovered address should match expected"
        );
    }

    #[test]
    fn test_nitro_signature_v27_parity() {
        // v=27 should convert to parity=false (0)
        let v = 27u64;
        let parity = v != 27;
        assert!(!parity, "v=27 should be parity false");
    }

    #[test]
    fn test_nitro_signature_v28_parity() {
        // v=28 should convert to parity=true (1)
        let v = 28u64;
        let parity = v != 27;
        assert!(parity, "v=28 should be parity true");
    }

    #[test]
    fn test_encode_signed_tx_eip2718_format() {
        use alloy::network::TxSignerSync;
        use alloy::signers::local::PrivateKeySigner;

        // Create a test signer
        let signer = PrivateKeySigner::random();

        let params = test_params();
        let mut tx = build_unsigned_tx(&params);

        // Sign the transaction
        let sig = signer.sign_transaction_sync(&mut tx).unwrap();

        // Encode
        let encoded = encode_signed_tx(&tx, &sig);

        // EIP-1559 transactions start with 0x02
        assert_eq!(
            encoded[0], 0x02,
            "EIP-1559 tx should start with type byte 0x02"
        );
    }

    #[test]
    fn test_encode_signed_tx_recoverable() {
        use alloy::consensus::TxEnvelope;
        use alloy::consensus::transaction::SignerRecoverable;
        use alloy::eips::eip2718::Decodable2718;
        use alloy::network::TxSignerSync;
        use alloy::signers::local::PrivateKeySigner;

        let signer = PrivateKeySigner::random();
        let signer_addr = signer.address();

        let params = test_params();
        let mut tx = build_unsigned_tx(&params);

        let sig = signer.sign_transaction_sync(&mut tx).unwrap();
        let encoded = encode_signed_tx(&tx, &sig);

        // Decode the transaction
        let decoded = TxEnvelope::decode_2718(&mut encoded.as_ref()).unwrap();

        // Verify we can recover the signer
        let recovered = decoded.recover_signer().unwrap();
        assert_eq!(recovered, signer_addr, "Should recover original signer");
    }

    #[test]
    fn test_tx_hash_computation() {
        use alloy::network::TxSignerSync;
        use alloy::signers::local::PrivateKeySigner;

        let signer = PrivateKeySigner::random();

        let params = test_params();
        let mut tx = build_unsigned_tx(&params);

        let sig = signer.sign_transaction_sync(&mut tx).unwrap();

        // Convert to primitives signature and use into_signed
        let prim_sig = Signature::new(sig.r(), sig.s(), sig.v());
        let signed = tx.clone().into_signed(prim_sig);

        // The hash from into_signed should be valid
        let tx_hash = *signed.hash();
        assert_ne!(tx_hash, B256::ZERO, "Transaction hash should not be zero");
    }

    #[test]
    fn compute_local_tx_hash_equals_keccak_of_exact_bytes() {
        // The local hash is defined as keccak256 over the exact EIP-2718 bytes we
        // broadcast — nothing more. Pin that so the definition cannot drift.
        let bytes = [0x02u8, 0xde, 0xad, 0xbe, 0xef];
        assert_eq!(
            compute_local_tx_hash(&bytes),
            alloy::primitives::keccak256(bytes),
            "local hash must be keccak256 of the exact signed bytes"
        );
    }

    #[test]
    fn compute_local_tx_hash_matches_node_hash_for_eip1559() {
        // The node computes an EIP-1559 tx hash as keccak256 of the full EIP-2718
        // envelope. Our local hash (keccak of the encoded bytes) must equal alloy's
        // canonical `signed.hash()` — the value a node returns from eth_sendRawTransaction.
        use alloy::network::TxSignerSync;
        use alloy::signers::local::PrivateKeySigner;

        let signer = PrivateKeySigner::random();
        let params = test_params();
        let mut tx = build_unsigned_tx(&params);

        let sig = signer.sign_transaction_sync(&mut tx).unwrap();
        let encoded = encode_signed_tx(&tx, &sig);

        let prim_sig = Signature::new(sig.r(), sig.s(), sig.v());
        let canonical_hash = *tx.clone().into_signed(prim_sig).hash();

        assert_eq!(
            compute_local_tx_hash(&encoded),
            canonical_hash,
            "local hash over broadcast bytes must equal the node/canonical tx hash"
        );
    }
}
