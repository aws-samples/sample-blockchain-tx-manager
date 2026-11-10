//! Non-vacuous DynamoDB Local integration tests for the nonce authority.
//!
//! These tests drive the **real** `DynamoNonceManager` transaction/expression logic
//! against a live DynamoDB Local instance (the AWS-provided
//! `public.ecr.aws/aws-dynamodb-local/aws-dynamodb-local` image, or a local
//! `DynamoDBLocal.jar` run under Java 17). Every test creates a uniquely named real
//! table (wallet PK / tx_hash SK + a `status-chain-index` GSI), waits for it to become
//! `ACTIVE`, exercises the manager, and deletes the table on the way out.
//!
//! # Not vacuous, never silently skipped
//!
//! The whole module is behind the `dynamodb-local-tests` Cargo feature so ordinary
//! `cargo test` (unit tests) needs no server. When the feature *is* enabled, a missing
//! endpoint is a hard, actionable **panic** — not a skip — so a green run always means
//! the assertions actually executed against DynamoDB.
//!
//! Run locally:
//! ```bash
//! DYNAMODB_LOCAL_ENDPOINT=http://127.0.0.1:8000 \
//!   cargo test -p nonce_manager --features dynamodb-local-tests -- --nocapture
//! ```
#![cfg(feature = "dynamodb-local-tests")]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use alloy::primitives::{Address, B256, Bytes, U256};
use alloy::providers::mock::Asserter;
use alloy::providers::{Provider, ProviderBuilder};
use aws_sdk_dynamodb::Client;
use aws_sdk_dynamodb::config::{BehaviorVersion, Credentials, Region};
use aws_sdk_dynamodb::types::{
    AttributeDefinition, AttributeValue, GlobalSecondaryIndex, KeySchemaElement, KeyType,
    Projection, ProjectionType, ScalarAttributeType,
};

use nonce_manager::{
    DynamoNonceManager, ExhaustionAction, FeeSpeed, NonceError, NonceManagerConfig,
    ReplacementFamilyInit, ResolvedReplacementPolicy,
};

const STATUS_CHAIN_INDEX: &str = "status-chain-index";
const CHAIN_ID: u64 = 11155111; // Sepolia — arbitrary, isolates GSI rows by chain.

// ---------------------------------------------------------------------------
// Endpoint + client
// ---------------------------------------------------------------------------

/// Resolve the DynamoDB Local endpoint. With the feature enabled a missing endpoint is
/// a hard, actionable failure — never a silent skip.
fn endpoint() -> String {
    match std::env::var("DYNAMODB_LOCAL_ENDPOINT") {
        Ok(v) if !v.trim().is_empty() => v,
        _ => panic!(
            "DYNAMODB_LOCAL_ENDPOINT is not set but the `dynamodb-local-tests` feature is \
             enabled. These tests require a running DynamoDB Local. Start one, e.g.:\n\
             \n  docker run -p 8000:8000 public.ecr.aws/aws-dynamodb-local/aws-dynamodb-local\n\
             or run the JAR under Java 17, then:\n\
             \n  export DYNAMODB_LOCAL_ENDPOINT=http://127.0.0.1:8000\n\
             \nSee scripts/run-tests.sh for the supported launch paths."
        ),
    }
}

/// Build a DynamoDB client pointed at DynamoDB Local: static dummy `for_tests`
/// credentials, `us-east-1`, an explicit `endpoint_url`, and the latest behavior
/// version. DynamoDB Local ignores the region/credentials but the SDK still requires
/// them to be present.
fn make_client(endpoint: &str) -> Client {
    let conf = aws_sdk_dynamodb::config::Builder::default()
        .behavior_version(BehaviorVersion::latest())
        .region(Region::new("us-east-1"))
        .credentials_provider(Credentials::for_tests())
        .endpoint_url(endpoint)
        .build();
    Client::from_conf(conf)
}

// ---------------------------------------------------------------------------
// Unique, self-cleaning test table
// ---------------------------------------------------------------------------

static TABLE_SEQ: AtomicU64 = AtomicU64::new(0);

fn unique_table_name() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let seq = TABLE_SEQ.fetch_add(1, Ordering::Relaxed);
    format!("nonce_it_{}_{}_{}", std::process::id(), nanos, seq)
}

/// Owns a real DynamoDB Local table for the lifetime of a test and deletes it on drop
/// (best effort, panic-safe). Deletion runs on a dedicated OS thread with its own
/// runtime so it works whether the test runtime is current-thread or multi-thread.
struct TestTable {
    client: Client,
    name: String,
}

impl TestTable {
    async fn create(client: Client) -> Self {
        let name = unique_table_name();
        let sk = |attr: &str, kt: KeyType| {
            KeySchemaElement::builder()
                .attribute_name(attr)
                .key_type(kt)
                .build()
                .expect("key schema element")
        };
        let attr = |name: &str, ty: ScalarAttributeType| {
            AttributeDefinition::builder()
                .attribute_name(name)
                .attribute_type(ty)
                .build()
                .expect("attribute definition")
        };

        let gsi = GlobalSecondaryIndex::builder()
            .index_name(STATUS_CHAIN_INDEX)
            .key_schema(sk("status", KeyType::Hash))
            .key_schema(sk("chain_id", KeyType::Range))
            .projection(
                Projection::builder()
                    .projection_type(ProjectionType::All)
                    .build(),
            )
            .build()
            .expect("gsi");

        client
            .create_table()
            .table_name(&name)
            .billing_mode(aws_sdk_dynamodb::types::BillingMode::PayPerRequest)
            .attribute_definitions(attr("wallet", ScalarAttributeType::S))
            .attribute_definitions(attr("tx_hash", ScalarAttributeType::S))
            .attribute_definitions(attr("status", ScalarAttributeType::S))
            .attribute_definitions(attr("chain_id", ScalarAttributeType::N))
            .key_schema(sk("wallet", KeyType::Hash))
            .key_schema(sk("tx_hash", KeyType::Range))
            .global_secondary_indexes(gsi)
            .send()
            .await
            .expect("create_table");

        // Wait until the table (and its GSI) reports ACTIVE.
        let mut waited = Duration::ZERO;
        loop {
            let out = client
                .describe_table()
                .table_name(&name)
                .send()
                .await
                .expect("describe_table");
            let desc = out.table().expect("table description");
            let table_active =
                desc.table_status() == Some(&aws_sdk_dynamodb::types::TableStatus::Active);
            let gsis_active = desc
                .global_secondary_indexes()
                .iter()
                .all(|g| g.index_status() == Some(&aws_sdk_dynamodb::types::IndexStatus::Active));
            if table_active && gsis_active {
                break;
            }
            assert!(
                waited < Duration::from_secs(30),
                "table {name} did not become ACTIVE within 30s"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
            waited += Duration::from_millis(100);
        }

        TestTable { client, name }
    }
}

impl Drop for TestTable {
    fn drop(&mut self) {
        let client = self.client.clone();
        let name = self.name.clone();
        // Delete on a separate OS thread so we never create a runtime inside the
        // (possibly multi-thread) test runtime.
        let _ = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("cleanup runtime");
            rt.block_on(async {
                let _ = client.delete_table().table_name(&name).send().await;
            });
        })
        .join();
    }
}

// ---------------------------------------------------------------------------
// Manager + attribute helpers
// ---------------------------------------------------------------------------

/// Build a manager over a mocked alloy provider. Tests that pre-seed the nonce-state
/// row never touch the provider (an empty asserter would panic if they did, surfacing
/// an unexpected RPC). Tests that exercise `force_sync` push responses into `asserter`.
fn manager(
    client: Client,
    table: String,
    cfg: NonceManagerConfig,
    asserter: Asserter,
) -> DynamoNonceManager<impl Provider + Clone> {
    let provider = ProviderBuilder::new().connect_mocked_client(asserter);
    DynamoNonceManager::new(client, table, Arc::new(provider), CHAIN_ID, cfg)
}

fn test_wallet() -> Address {
    "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
        .parse()
        .unwrap()
}

/// Partition key derivation identical to the production `model::wallet_pk`.
fn wallet_pk(addr: &Address) -> String {
    format!("{addr:?}").to_lowercase()
}

fn pad(nonce: u64) -> String {
    format!("{nonce:020}")
}

fn s(v: impl Into<String>) -> AttributeValue {
    AttributeValue::S(v.into())
}
fn n(v: impl ToString) -> AttributeValue {
    AttributeValue::N(v.to_string())
}

async fn seed_nonce_state(
    client: &Client,
    table: &str,
    addr: &Address,
    next: u64,
    confirmed: u64,
    pending: u64,
) {
    client
        .put_item()
        .table_name(table)
        .item("wallet", s(wallet_pk(addr)))
        .item("tx_hash", s("nonce-state"))
        .item("next_nonce", n(next))
        .item("confirmed_nonce", n(confirmed))
        .item("pending_count", n(pending))
        .item("updated_at", s(chrono::Utc::now().to_rfc3339()))
        .send()
        .await
        .expect("seed nonce-state");
}

async fn seed_reservation(client: &Client, table: &str, addr: &Address, nonce: u64) {
    client
        .put_item()
        .table_name(table)
        .item("wallet", s(wallet_pk(addr)))
        .item("tx_hash", s(format!("reservation#{}", pad(nonce))))
        .item("nonce", n(nonce))
        .item("state", s("RESERVED"))
        .item("status", s("RESERVED"))
        .item("chain_id", n(CHAIN_ID))
        .item("reserved_at", s(chrono::Utc::now().to_rfc3339()))
        .send()
        .await
        .expect("seed reservation");
}

async fn seed_gap(client: &Client, table: &str, addr: &Address, nonce: u64) {
    client
        .put_item()
        .table_name(table)
        .item("wallet", s(wallet_pk(addr)))
        .item("tx_hash", s(format!("gap#{}", pad(nonce))))
        .item("nonce", n(nonce))
        .send()
        .await
        .expect("seed gap");
}

async fn get_item(
    client: &Client,
    table: &str,
    addr: &Address,
    sk: &str,
) -> Option<std::collections::HashMap<String, AttributeValue>> {
    client
        .get_item()
        .table_name(table)
        .key("wallet", s(wallet_pk(addr)))
        .key("tx_hash", s(sk))
        .consistent_read(true)
        .send()
        .await
        .expect("get_item")
        .item
}

fn get_num(item: &std::collections::HashMap<String, AttributeValue>, key: &str) -> u64 {
    item.get(key)
        .and_then(|v| v.as_n().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or_else(|| panic!("missing numeric attribute {key}"))
}

fn get_str<'a>(item: &'a std::collections::HashMap<String, AttributeValue>, key: &str) -> &'a str {
    item.get(key)
        .and_then(|v| v.as_s().ok())
        .map(|s| s.as_str())
        .unwrap_or_else(|| panic!("missing string attribute {key}"))
}

/// Count reservation rows for a wallet (consistent scan of the wallet partition).
async fn query_prefix_count(client: &Client, table: &str, addr: &Address, prefix: &str) -> usize {
    client
        .query()
        .table_name(table)
        .key_condition_expression("wallet = :w AND begins_with(tx_hash, :p)")
        .expression_attribute_values(":w", s(wallet_pk(addr)))
        .expression_attribute_values(":p", s(prefix))
        .consistent_read(true)
        .send()
        .await
        .expect("query prefix")
        .items
        .map(|v| v.len())
        .unwrap_or(0)
}

/// Count rows in the `status-chain-index` GSI matching (status, chain_id).
async fn gsi_count(client: &Client, table: &str, status: &str, chain_id: u64) -> usize {
    client
        .query()
        .table_name(table)
        .index_name(STATUS_CHAIN_INDEX)
        .key_condition_expression("#st = :s AND chain_id = :c")
        .expression_attribute_names("#st", "status")
        .expression_attribute_values(":s", s(status))
        .expression_attribute_values(":c", n(chain_id))
        .send()
        .await
        .expect("gsi query")
        .items
        .map(|v| v.len())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_reserves_are_contiguous_unique_and_durable() {
    let client = make_client(&endpoint());
    let table = TestTable::create(client.clone()).await;
    let addr = test_wallet();

    // Seed a fresh wallet at nonce 0 so all 50 reservations allocate sequentially.
    seed_nonce_state(&client, &table.name, &addr, 0, 0, 0).await;

    let mgr = manager(
        client.clone(),
        table.name.clone(),
        NonceManagerConfig::default(),
        Asserter::new(),
    );

    let mut handles = Vec::new();
    for _ in 0..50 {
        let m = mgr.clone();
        handles.push(tokio::spawn(async move { m.reserve_nonce(addr).await }));
    }

    let mut nonces = Vec::new();
    for h in handles {
        nonces.push(h.await.expect("join").expect("reserve_nonce succeeded"));
    }
    nonces.sort_unstable();

    // Exactly contiguous and unique: {0, 1, ..., 49}.
    assert_eq!(
        nonces,
        (0..50).collect::<Vec<_>>(),
        "50 concurrent reserves must yield contiguous unique nonces 0..49"
    );

    // 50 durable reservation rows, all RESERVED.
    let reservations = client
        .query()
        .table_name(&table.name)
        .key_condition_expression("wallet = :w AND begins_with(tx_hash, :p)")
        .expression_attribute_values(":w", s(wallet_pk(&addr)))
        .expression_attribute_values(":p", s("reservation#"))
        .consistent_read(true)
        .send()
        .await
        .expect("query reservations")
        .items
        .unwrap_or_default();
    assert_eq!(
        reservations.len(),
        50,
        "expected 50 durable reservation rows"
    );
    for item in &reservations {
        assert_eq!(get_str(item, "state"), "RESERVED");
    }

    // All 50 are discoverable via the crash-recovery GSI while RESERVED.
    assert_eq!(
        gsi_count(&client, &table.name, "RESERVED", CHAIN_ID).await,
        50,
        "all 50 RESERVED reservations must be visible in status-chain-index"
    );

    // next_nonce advanced to exactly 50; pending_count == 50.
    let state = get_item(&client, &table.name, &addr, "nonce-state")
        .await
        .expect("nonce-state");
    assert_eq!(get_num(&state, "next_nonce"), 50);
    assert_eq!(get_num(&state, "pending_count"), 50);
}

#[tokio::test]
async fn max_pending_blocks_further_reservations() {
    let client = make_client(&endpoint());
    let table = TestTable::create(client.clone()).await;
    let addr = test_wallet();
    seed_nonce_state(&client, &table.name, &addr, 0, 0, 0).await;

    let cfg = NonceManagerConfig {
        max_pending_per_wallet: 3,
        ..Default::default()
    };
    let mgr = manager(client.clone(), table.name.clone(), cfg, Asserter::new());

    for expected in 0..3 {
        assert_eq!(mgr.reserve_nonce(addr).await.unwrap(), expected);
    }
    let err = mgr.reserve_nonce(addr).await.unwrap_err();
    assert!(
        matches!(err, NonceError::MaxPendingExceeded { count, max, .. } if count >= 3 && max == 3),
        "expected MaxPendingExceeded, got {err:?}"
    );
}

#[tokio::test]
async fn release_recycles_nonce_and_gap_is_reused_lowest_first() {
    let client = make_client(&endpoint());
    let table = TestTable::create(client.clone()).await;
    let addr = test_wallet();
    seed_nonce_state(&client, &table.name, &addr, 0, 0, 0).await;

    let mgr = manager(
        client.clone(),
        table.name.clone(),
        NonceManagerConfig::default(),
        Asserter::new(),
    );

    assert_eq!(mgr.reserve_nonce(addr).await.unwrap(), 0);
    assert_eq!(mgr.reserve_nonce(addr).await.unwrap(), 1);
    assert_eq!(mgr.reserve_nonce(addr).await.unwrap(), 2);

    // Release the middle nonce; it becomes the lowest gap.
    assert!(mgr.release_nonce(addr, 1).await.unwrap());
    assert_eq!(mgr.get_available_gaps(addr).await.unwrap(), vec![1]);

    // Next reservation reuses the gap (1), not a fresh sequential nonce (3).
    assert_eq!(
        mgr.reserve_nonce(addr).await.unwrap(),
        1,
        "gap must be reused lowest-first"
    );
    assert!(mgr.get_available_gaps(addr).await.unwrap().is_empty());

    // Releasing a signed nonce is refused (Ok(false)); here nonce 1 is RESERVED again.
    // Releasing a nonce with no reservation is also a no-op false.
    assert!(!mgr.release_nonce(addr, 999).await.unwrap());
}

#[tokio::test]
async fn stale_gap_below_confirmed_is_discarded_before_reuse() {
    let client = make_client(&endpoint());
    let table = TestTable::create(client.clone()).await;
    let addr = test_wallet();
    seed_nonce_state(&client, &table.name, &addr, 10, 8, 0).await;

    // Nonce 5 is already consumed according to confirmed_nonce=8. Nonce 9 is the
    // lowest genuinely reusable gap. The allocator must delete 5 and return 9.
    seed_gap(&client, &table.name, &addr, 5).await;
    seed_gap(&client, &table.name, &addr, 9).await;

    let mgr = manager(
        client.clone(),
        table.name.clone(),
        NonceManagerConfig::default(),
        Asserter::new(),
    );

    assert_eq!(
        mgr.reserve_nonce(addr).await.unwrap(),
        9,
        "allocator must skip a gap below the confirmed watermark"
    );
    assert_eq!(
        mgr.get_available_gaps(addr).await.unwrap(),
        Vec::<u64>::new(),
        "stale gap must be removed and valid gap must be claimed"
    );

    let stale = get_item(&client, &table.name, &addr, &format!("gap#{}", pad(5))).await;
    assert!(stale.is_none(), "confirmed stale gap must be deleted");
}

#[tokio::test]
async fn record_signed_removes_gsi_marker_and_writes_signed_tracker_without_ttl() {
    let client = make_client(&endpoint());
    let table = TestTable::create(client.clone()).await;
    let addr = test_wallet();
    seed_nonce_state(&client, &table.name, &addr, 0, 0, 0).await;

    let mgr = manager(
        client.clone(),
        table.name.clone(),
        NonceManagerConfig::default(),
        Asserter::new(),
    );

    let nonce = mgr.reserve_nonce(addr).await.unwrap();
    assert_eq!(nonce, 0);
    assert_eq!(
        gsi_count(&client, &table.name, "RESERVED", CHAIN_ID).await,
        1
    );

    let raw = [0x02u8, 0xf8, 0x01, 0x80, 0x0a, 0xde, 0xad, 0xbe, 0xef];
    let tx_hash = B256::from([0x11u8; 32]);
    mgr.record_signed(
        addr,
        nonce,
        tx_hash,
        &raw,
        Some(U256::from(7u64)),
        None,
        None,
    )
    .await
    .expect("record_signed");

    // Reservation advanced to SIGNED and the GSI recovery marker is gone.
    let resv = get_item(
        &client,
        &table.name,
        &addr,
        &format!("reservation#{}", pad(nonce)),
    )
    .await
    .expect("reservation row");
    assert_eq!(get_str(&resv, "state"), "SIGNED");
    assert!(
        !resv.contains_key("status"),
        "SIGNED reservation must not keep the status marker"
    );
    assert!(
        !resv.contains_key("chain_id"),
        "SIGNED reservation must not keep the chain_id marker"
    );
    assert_eq!(
        gsi_count(&client, &table.name, "RESERVED", CHAIN_ID).await,
        0,
        "record_signed must remove the reservation from the RESERVED GSI"
    );

    // Durable tracker row keyed by the real hash, with exact raw hex and no TTL.
    let hash_hex = format!("{tx_hash:?}").to_lowercase();
    let tracker = get_item(&client, &table.name, &addr, &hash_hex)
        .await
        .expect("tracker row");
    assert_eq!(get_str(&tracker, "status"), "SIGNED");
    assert_eq!(get_num(&tracker, "chain_id"), CHAIN_ID);
    assert_eq!(get_num(&tracker, "nonce"), nonce);
    assert_eq!(
        get_str(&tracker, "signed_raw_tx"),
        format!("0x{}", alloy::hex::encode(raw)),
        "signed_raw_tx must be the exact raw bytes as lowercase hex"
    );
    assert!(
        !tracker.contains_key("ttl"),
        "unresolved tracker row must not carry a TTL"
    );
    // The tracker is discoverable by the watcher under SIGNED.
    assert_eq!(gsi_count(&client, &table.name, "SIGNED", CHAIN_ID).await, 1);
}

#[tokio::test]
async fn replacement_family_claim_and_activation_are_atomic_and_idempotent() {
    let client = make_client(&endpoint());
    let table = TestTable::create(client.clone()).await;
    let addr = test_wallet();
    seed_nonce_state(&client, &table.name, &addr, 0, 0, 0).await;
    let mgr = manager(
        client.clone(),
        table.name.clone(),
        NonceManagerConfig::default(),
        Asserter::new(),
    );
    let nonce = mgr.reserve_nonce(addr).await.unwrap();
    let original_hash = B256::repeat_byte(0x31);
    let family_init = ReplacementFamilyInit {
        to: Address::repeat_byte(0x44),
        value: U256::from(5u64),
        data: Bytes::from(vec![0xaa, 0xbb]),
        gas_limit: 50_000,
        policy: ResolvedReplacementPolicy {
            fee_speed: FeeSpeed::Standard,
            bump_every_blocks: 5,
            max_bumps: 3,
            on_exhaust: ExhaustionAction::Hold,
            max_fee_per_gas_wei: 1_000,
            max_total_fee_wei: U256::from(50_000_000u64),
        },
        current_block: 100,
        max_fee_per_gas: 100,
        max_priority_fee_per_gas: 10,
    };
    mgr.record_signed_with_family(
        addr,
        nonce,
        original_hash,
        &[0x02, 0x01],
        U256::from(100),
        U256::from(10),
        &family_init,
    )
    .await
    .expect("family signed handoff");
    mgr.mark_broadcast(addr, nonce, original_hash)
        .await
        .unwrap();

    let family = mgr
        .get_replacement_family(addr, nonce)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(family.active_generation, 0);
    assert_eq!(family.active_hash, original_hash);
    assert_eq!(family.next_eligible_block, 105);
    assert!(!mgr.claim_replacement(addr, nonce, 0, 104, 3).await.unwrap());
    assert!(mgr.claim_replacement(addr, nonce, 0, 105, 3).await.unwrap());
    assert!(!mgr.claim_replacement(addr, nonce, 0, 105, 3).await.unwrap());

    let new_hash = B256::repeat_byte(0x32);
    assert!(
        mgr.activate_replacement(&family, new_hash, &[0x02, 0x02], 130, 12, 105, "speedUp")
            .await
            .unwrap()
    );
    assert!(
        !mgr.activate_replacement(
            &family,
            B256::repeat_byte(0x33),
            &[0x02, 0x03],
            170,
            14,
            106,
            "speedUp"
        )
        .await
        .unwrap()
    );

    let updated = mgr
        .get_replacement_family(addr, nonce)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(updated.active_generation, 1);
    assert_eq!(updated.active_hash, new_hash);
    assert_eq!(updated.active_max_fee_per_gas, 130);
    assert_eq!(updated.next_eligible_block, 110);
    let original = get_item(
        &client,
        &table.name,
        &addr,
        &format!("{original_hash:?}").to_lowercase(),
    )
    .await
    .unwrap();
    assert_eq!(
        original
            .get("replacement_active")
            .unwrap()
            .as_bool()
            .unwrap(),
        &false
    );
    assert_eq!(
        get_str(&original, "status"),
        "PENDING",
        "inactive sibling remains receipt-tracked"
    );
    let replacement = get_item(
        &client,
        &table.name,
        &addr,
        &format!("{new_hash:?}").to_lowercase(),
    )
    .await
    .unwrap();
    assert_eq!(
        replacement
            .get("replacement_active")
            .unwrap()
            .as_bool()
            .unwrap(),
        &true
    );
    assert_eq!(get_num(&replacement, "replacement_generation"), 1);
    assert_eq!(get_str(&replacement, "status"), "SIGNED");
}

#[tokio::test]
async fn rejected_family_is_deleted_before_nonce_reuse() {
    let client = make_client(&endpoint());
    let table = TestTable::create(client.clone()).await;
    let addr = test_wallet();
    seed_nonce_state(&client, &table.name, &addr, 0, 0, 0).await;
    let mgr = manager(
        client.clone(),
        table.name.clone(),
        NonceManagerConfig::default(),
        Asserter::new(),
    );
    let policy = ResolvedReplacementPolicy {
        fee_speed: FeeSpeed::Standard,
        bump_every_blocks: 5,
        max_bumps: 3,
        on_exhaust: ExhaustionAction::Hold,
        max_fee_per_gas_wei: 1_000,
        max_total_fee_wei: U256::from(50_000_000u64),
    };
    let nonce = mgr.reserve_nonce(addr).await.unwrap();
    let hash1 = B256::repeat_byte(0x41);
    let init = ReplacementFamilyInit {
        to: Address::repeat_byte(0x44),
        value: U256::ZERO,
        data: Bytes::new(),
        gas_limit: 21_000,
        policy: policy.clone(),
        current_block: 100,
        max_fee_per_gas: 100,
        max_priority_fee_per_gas: 10,
    };
    mgr.record_signed_with_family(
        addr,
        nonce,
        hash1,
        &[0x02, 0x11],
        U256::from(100),
        U256::from(10),
        &init,
    )
    .await
    .unwrap();
    assert!(
        mgr.reject_signed(addr, nonce, hash1, "max fee below base fee", 9999999999)
            .await
            .unwrap()
    );
    assert!(
        get_item(
            &client,
            &table.name,
            &addr,
            &format!("family#{}", pad(nonce))
        )
        .await
        .is_none()
    );

    let reused = mgr.reserve_nonce(addr).await.unwrap();
    assert_eq!(reused, nonce, "rejected nonce must be reusable");
    let hash2 = B256::repeat_byte(0x42);
    let init2 = ReplacementFamilyInit {
        current_block: 101,
        policy,
        ..init
    };
    mgr.record_signed_with_family(
        addr,
        reused,
        hash2,
        &[0x02, 0x12],
        U256::from(100),
        U256::from(10),
        &init2,
    )
    .await
    .expect("reused nonce must accept a fresh family row");
}

#[tokio::test]
async fn mark_broadcast_succeeds_is_idempotent_and_ambiguous_stays_signed() {
    let client = make_client(&endpoint());
    let table = TestTable::create(client.clone()).await;
    let addr = test_wallet();
    seed_nonce_state(&client, &table.name, &addr, 0, 0, 0).await;

    let mgr = manager(
        client.clone(),
        table.name.clone(),
        NonceManagerConfig::default(),
        Asserter::new(),
    );

    let nonce = mgr.reserve_nonce(addr).await.unwrap();
    let raw = [0x02u8, 0xf8, 0x01, 0x02, 0x03];
    let tx_hash = B256::from([0x22u8; 32]);
    mgr.record_signed(
        addr,
        nonce,
        tx_hash,
        &raw,
        None,
        Some(U256::from(1u64)),
        None,
    )
    .await
    .expect("record_signed");

    let hash_hex = format!("{tx_hash:?}").to_lowercase();

    // --- Ambiguous broadcast: no mark_broadcast is issued, state must remain SIGNED. ---
    let resv = get_item(
        &client,
        &table.name,
        &addr,
        &format!("reservation#{}", pad(nonce)),
    )
    .await
    .unwrap();
    assert_eq!(
        get_str(&resv, "state"),
        "SIGNED",
        "ambiguous outcome (no mark_broadcast) must leave the reservation SIGNED"
    );
    let tracker = get_item(&client, &table.name, &addr, &hash_hex)
        .await
        .unwrap();
    assert_eq!(get_str(&tracker, "status"), "SIGNED");
    // A second record_signed is rejected — we never double-record after an ambiguous send.
    assert!(
        mgr.record_signed(
            addr,
            nonce,
            tx_hash,
            &raw,
            None,
            Some(U256::from(1u64)),
            None
        )
        .await
        .is_err(),
        "record_signed must be RESERVED-only; a replay after SIGNED must fail closed"
    );

    // --- Now broadcast: tracker -> PENDING, reservation -> BROADCAST. ---
    mgr.mark_broadcast(addr, nonce, tx_hash)
        .await
        .expect("mark_broadcast");
    let resv = get_item(
        &client,
        &table.name,
        &addr,
        &format!("reservation#{}", pad(nonce)),
    )
    .await
    .unwrap();
    assert_eq!(get_str(&resv, "state"), "BROADCAST");
    let tracker = get_item(&client, &table.name, &addr, &hash_hex)
        .await
        .unwrap();
    assert_eq!(get_str(&tracker, "status"), "PENDING");

    // --- Idempotent replay: a second mark_broadcast still succeeds and is a no-op. ---
    mgr.mark_broadcast(addr, nonce, tx_hash)
        .await
        .expect("mark_broadcast replay is idempotent");
    let resv = get_item(
        &client,
        &table.name,
        &addr,
        &format!("reservation#{}", pad(nonce)),
    )
    .await
    .unwrap();
    assert_eq!(get_str(&resv, "state"), "BROADCAST");
    let tracker = get_item(&client, &table.name, &addr, &hash_hex)
        .await
        .unwrap();
    assert_eq!(get_str(&tracker, "status"), "PENDING");
    // pending_count was never touched by mark_broadcast.
    let state = get_item(&client, &table.name, &addr, "nonce-state")
        .await
        .unwrap();
    assert_eq!(get_num(&state, "pending_count"), 1);
}

#[tokio::test]
async fn find_stale_reservations_surfaces_reserved_only() {
    let client = make_client(&endpoint());
    let table = TestTable::create(client.clone()).await;
    let addr = test_wallet();
    seed_nonce_state(&client, &table.name, &addr, 0, 0, 0).await;

    // Threshold of zero makes every existing reservation immediately "stale".
    let cfg = NonceManagerConfig {
        reservation_stale_threshold: Duration::ZERO,
        ..Default::default()
    };
    let mgr = manager(client.clone(), table.name.clone(), cfg, Asserter::new());

    // Two reservations: one stays RESERVED (should be surfaced), one advances to SIGNED
    // (its GSI marker is removed, so it must NOT be surfaced).
    let stale_nonce = mgr.reserve_nonce(addr).await.unwrap();
    let signed_nonce = mgr.reserve_nonce(addr).await.unwrap();
    mgr.record_signed(
        addr,
        signed_nonce,
        B256::from([0x33u8; 32]),
        &[0x02u8, 0x01, 0x02],
        None,
        None,
        None,
    )
    .await
    .expect("record_signed");

    // Small delay so reserved_at is strictly in the past relative to the cutoff.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let stale = mgr.find_stale_reservations().await.expect("find_stale");
    assert_eq!(stale.len(), 1, "exactly the RESERVED reservation is stale");
    assert_eq!(stale[0].nonce, stale_nonce);
    assert_eq!(stale[0].wallet, addr);
    assert_eq!(stale[0].chain_id, CHAIN_ID);
}

#[tokio::test]
async fn out_of_order_confirms_drain_watermark_and_decrement_pending_once_each() {
    let client = make_client(&endpoint());
    let table = TestTable::create(client.clone()).await;
    let addr = test_wallet();

    // Wallet with three in-flight nonces (5,6,7); confirmed watermark at 5.
    seed_nonce_state(&client, &table.name, &addr, 8, 5, 3).await;
    for nonce in [5u64, 6, 7] {
        seed_reservation(&client, &table.name, &addr, nonce).await;
    }

    let mgr = manager(
        client.clone(),
        table.name.clone(),
        NonceManagerConfig::default(),
        Asserter::new(),
    );

    // Confirm out of order: 5 (in-order), 7 (ahead -> marker), 6 (drains 6 and 7).
    mgr.confirm_transaction(addr, 5).await.expect("confirm 5");
    mgr.confirm_transaction(addr, 7).await.expect("confirm 7");
    mgr.confirm_transaction(addr, 6).await.expect("confirm 6");

    let state = get_item(&client, &table.name, &addr, "nonce-state")
        .await
        .expect("nonce-state");
    assert_eq!(
        get_num(&state, "confirmed_nonce"),
        8,
        "watermark must drain to 8 after 5,7,6"
    );
    assert_eq!(
        get_num(&state, "pending_count"),
        0,
        "each of 5,6,7 decrements pending exactly once"
    );

    // Reservations retired; no residual confirmed markers.
    assert_eq!(
        query_prefix_count(&client, &table.name, &addr, "reservation#").await,
        0
    );
    assert_eq!(
        query_prefix_count(&client, &table.name, &addr, "confirmed#").await,
        0
    );

    // Repeated confirms are idempotent: watermark and pending stay put.
    mgr.confirm_transaction(addr, 5)
        .await
        .expect("confirm 5 again");
    mgr.confirm_transaction(addr, 6)
        .await
        .expect("confirm 6 again");
    mgr.confirm_transaction(addr, 7)
        .await
        .expect("confirm 7 again");
    let state = get_item(&client, &table.name, &addr, "nonce-state")
        .await
        .unwrap();
    assert_eq!(get_num(&state, "confirmed_nonce"), 8);
    assert_eq!(get_num(&state, "pending_count"), 0);
}

#[tokio::test]
async fn force_sync_is_monotonic_and_non_destructive() {
    let client = make_client(&endpoint());
    let table = TestTable::create(client.clone()).await;
    let addr = test_wallet();

    // Ahead-of-chain in-flight state: next=10, confirmed=5, pending=3, plus a live
    // reservation (#6) and a gap (#4) that must never be deleted or lowered.
    seed_nonce_state(&client, &table.name, &addr, 10, 5, 3).await;
    seed_reservation(&client, &table.name, &addr, 6).await;
    seed_gap(&client, &table.name, &addr, 4).await;

    // --- Case 1: chain is BEHIND stored state -> nothing lowered, nothing deleted. ---
    let behind = Asserter::new();
    behind.push_success(&2u64); // chain_pending  (Pending)
    behind.push_success(&1u64); // chain_confirmed (Latest)
    let mgr = manager(
        client.clone(),
        table.name.clone(),
        NonceManagerConfig::default(),
        behind,
    );
    let (old, new) = mgr.force_sync(addr).await.expect("force_sync (behind)");
    assert_eq!((old, new), (10, 10), "force_sync must not lower next_nonce");

    let state = get_item(&client, &table.name, &addr, "nonce-state")
        .await
        .unwrap();
    assert_eq!(get_num(&state, "next_nonce"), 10);
    assert_eq!(get_num(&state, "confirmed_nonce"), 5);
    assert_eq!(get_num(&state, "pending_count"), 3);
    assert!(
        get_item(
            &client,
            &table.name,
            &addr,
            "reservation#00000000000000000006"
        )
        .await
        .is_some(),
        "in-flight reservation must be preserved"
    );
    assert!(
        get_item(&client, &table.name, &addr, "gap#00000000000000000004")
            .await
            .is_some(),
        "gap entry must be preserved"
    );

    // --- Case 2: chain is AHEAD -> counters raised monotonically, rows still intact. ---
    let ahead = Asserter::new();
    ahead.push_success(&20u64); // chain_pending
    ahead.push_success(&15u64); // chain_confirmed
    let mgr = manager(
        client.clone(),
        table.name.clone(),
        NonceManagerConfig::default(),
        ahead,
    );
    let (old, new) = mgr.force_sync(addr).await.expect("force_sync (ahead)");
    assert_eq!(old, 10);
    assert_eq!(new, 20, "force_sync must raise next_nonce toward the chain");

    let state = get_item(&client, &table.name, &addr, "nonce-state")
        .await
        .unwrap();
    assert_eq!(get_num(&state, "next_nonce"), 20);
    assert_eq!(get_num(&state, "confirmed_nonce"), 15);
    assert_eq!(
        get_num(&state, "pending_count"),
        3,
        "pending_count is never rewritten by reconciliation"
    );
    assert!(
        get_item(
            &client,
            &table.name,
            &addr,
            "reservation#00000000000000000006"
        )
        .await
        .is_some(),
        "reconciliation must not delete reservations"
    );
    assert!(
        get_item(&client, &table.name, &addr, "gap#00000000000000000004")
            .await
            .is_some(),
        "reconciliation must not delete gap entries"
    );
}

/// Regression: reconciliation raised `confirmed_nonce` past a still-live
/// reservation before the watcher confirmed it. The later confirm lands below the
/// watermark and must still retire the reservation **and** release its pending slot;
/// previously it deleted the reservation and left `pending_count` permanently inflated
/// (one leaked slot per event, wedging the wallet at `max_pending_per_wallet`).
#[tokio::test]
async fn confirm_below_watermark_retires_reservation_and_releases_pending_slot() {
    let client = make_client(&endpoint());
    let table = TestTable::create(client.clone()).await;
    let addr = test_wallet();

    // Nonce 0 reserved and broadcast: next=1, confirmed=0, pending=1, live reservation#0.
    seed_nonce_state(&client, &table.name, &addr, 1, 0, 1).await;
    seed_reservation(&client, &table.name, &addr, 0).await;

    // Nonce 0 has mined (latest=1). A reconcile runs before the watcher confirms it.
    let asserter = Asserter::new();
    asserter.push_success(&1u64); // chain_pending
    asserter.push_success(&1u64); // chain_confirmed (Latest)
    let mgr = manager(
        client.clone(),
        table.name.clone(),
        NonceManagerConfig::default(),
        asserter,
    );
    mgr.initialize_wallet(addr)
        .await
        .expect("initialize_wallet");

    let state = get_item(&client, &table.name, &addr, "nonce-state")
        .await
        .unwrap();
    assert_eq!(
        get_num(&state, "confirmed_nonce"),
        1,
        "reconcile raised the watermark"
    );
    assert_eq!(
        get_num(&state, "pending_count"),
        1,
        "reconcile never touches pending_count"
    );

    // Watcher now confirms nonce 0 — below the watermark.
    mgr.confirm_transaction(addr, 0)
        .await
        .expect("confirm below watermark");

    let state = get_item(&client, &table.name, &addr, "nonce-state")
        .await
        .unwrap();
    assert_eq!(
        get_num(&state, "confirmed_nonce"),
        1,
        "watermark is monotonic"
    );
    assert_eq!(
        get_num(&state, "pending_count"),
        0,
        "the only in-flight reservation was retired, so its pending slot must be released"
    );
    assert!(
        get_item(
            &client,
            &table.name,
            &addr,
            &format!("reservation#{}", pad(0))
        )
        .await
        .is_none(),
        "reservation row retired"
    );

    // Replay is a no-op: no reservation left, so no second decrement.
    mgr.confirm_transaction(addr, 0)
        .await
        .expect("replayed confirm");
    let state = get_item(&client, &table.name, &addr, "nonce-state")
        .await
        .unwrap();
    assert_eq!(
        get_num(&state, "pending_count"),
        0,
        "replay must not double-decrement"
    );

    // A below-watermark confirm for a nonce that never had a reservation is also a
    // pure no-op on the counter.
    seed_nonce_state(&client, &table.name, &addr, 5, 4, 2).await;
    mgr.confirm_transaction(addr, 1)
        .await
        .expect("confirm with no reservation");
    let state = get_item(&client, &table.name, &addr, "nonce-state")
        .await
        .unwrap();
    assert_eq!(
        get_num(&state, "pending_count"),
        2,
        "no reservation, no decrement"
    );
    assert_eq!(get_num(&state, "confirmed_nonce"), 4);
}

/// N-H1: a definitive node rejection of the *first* send retires the SIGNED reservation,
/// recycles the nonce into the gap pool, releases the pending slot, and moves the
/// tracker to REJECTED with a terminal TTL — all atomically. Replays and post-broadcast
/// calls are no-ops.
#[tokio::test]
async fn reject_signed_retires_reservation_recycles_nonce_and_is_noop_after_broadcast() {
    let client = make_client(&endpoint());
    let table = TestTable::create(client.clone()).await;
    let addr = test_wallet();
    seed_nonce_state(&client, &table.name, &addr, 0, 0, 0).await;

    let mgr = manager(
        client.clone(),
        table.name.clone(),
        NonceManagerConfig::default(),
        Asserter::new(),
    );

    let raw = [0x02u8, 0xf8, 0x01, 0x80, 0x0a, 0xde, 0xad, 0xbe, 0xef];

    // --- First send definitively rejected: retire + recycle. ---
    let nonce = mgr.reserve_nonce(addr).await.unwrap();
    assert_eq!(nonce, 0);
    let tx_hash = B256::from([0x21u8; 32]);
    mgr.record_signed(addr, nonce, tx_hash, &raw, None, None, None)
        .await
        .expect("record_signed");

    let ttl = 1_900_000_000i64;
    let retired = mgr
        .reject_signed(
            addr,
            nonce,
            tx_hash,
            "insufficient funds for gas * price + value",
            ttl,
        )
        .await
        .expect("reject_signed");
    assert!(
        retired,
        "first definitive rejection must retire the reservation"
    );

    assert!(
        get_item(
            &client,
            &table.name,
            &addr,
            &format!("reservation#{}", pad(nonce))
        )
        .await
        .is_none(),
        "reservation row must be deleted"
    );
    assert!(
        get_item(&client, &table.name, &addr, &format!("gap#{}", pad(nonce)))
            .await
            .is_some(),
        "the never-broadcast nonce must be recycled into the gap pool"
    );
    let state = get_item(&client, &table.name, &addr, "nonce-state")
        .await
        .unwrap();
    assert_eq!(get_num(&state, "pending_count"), 0, "pending slot released");
    assert_eq!(
        get_num(&state, "next_nonce"),
        1,
        "next_nonce is never lowered"
    );

    let hash_hex = format!("{tx_hash:?}").to_lowercase();
    let tracker = get_item(&client, &table.name, &addr, &hash_hex)
        .await
        .expect("tracker row");
    assert_eq!(get_str(&tracker, "status"), "REJECTED");
    assert_eq!(
        get_str(&tracker, "error"),
        "insufficient funds for gas * price + value"
    );
    assert_eq!(get_num(&tracker, "ttl") as i64, ttl, "terminal TTL applied");
    assert_eq!(
        gsi_count(&client, &table.name, "SIGNED", CHAIN_ID).await,
        0,
        "rejected tracker must leave the SIGNED GSI partition"
    );

    // Replay is a no-op.
    let again = mgr
        .reject_signed(addr, nonce, tx_hash, "insufficient funds", ttl)
        .await
        .expect("replayed reject_signed");
    assert!(!again, "replay must report nothing retired");
    let state = get_item(&client, &table.name, &addr, "nonce-state")
        .await
        .unwrap();
    assert_eq!(get_num(&state, "pending_count"), 0, "no double decrement");

    // The recycled nonce is handed out again (lowest gap first).
    let reused = mgr.reserve_nonce(addr).await.unwrap();
    assert_eq!(reused, 0, "recycled nonce must be reusable");
    let state = get_item(&client, &table.name, &addr, "nonce-state")
        .await
        .unwrap();
    assert_eq!(get_num(&state, "pending_count"), 1);

    // --- After a successful broadcast, reject_signed must refuse to touch anything. ---
    let tx_hash2 = B256::from([0x22u8; 32]);
    mgr.record_signed(addr, reused, tx_hash2, &raw, None, None, None)
        .await
        .expect("record_signed #2");
    mgr.mark_broadcast(addr, reused, tx_hash2)
        .await
        .expect("mark_broadcast");
    let refused = mgr
        .reject_signed(addr, reused, tx_hash2, "insufficient funds", ttl)
        .await
        .expect("reject_signed after broadcast");
    assert!(
        !refused,
        "a BROADCAST reservation must never be retired by reject_signed"
    );
    let resv = get_item(
        &client,
        &table.name,
        &addr,
        &format!("reservation#{}", pad(reused)),
    )
    .await
    .expect("reservation still present");
    assert_eq!(get_str(&resv, "state"), "BROADCAST");
    let tracker2 = get_item(
        &client,
        &table.name,
        &addr,
        &format!("{tx_hash2:?}").to_lowercase(),
    )
    .await
    .expect("tracker #2");
    assert_eq!(get_str(&tracker2, "status"), "PENDING");
    assert!(
        !tracker2.contains_key("ttl"),
        "active row must not gain a TTL"
    );
    let state = get_item(&client, &table.name, &addr, "nonce-state")
        .await
        .unwrap();
    assert_eq!(get_num(&state, "pending_count"), 1, "pending untouched");
    assert!(
        get_item(&client, &table.name, &addr, &format!("gap#{}", pad(reused)))
            .await
            .is_none(),
        "no gap may be created for a broadcast nonce"
    );
}
