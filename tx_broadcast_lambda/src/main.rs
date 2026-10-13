//! AWS Lambda function for Ethereum transaction broadcast
//!
//! This Lambda:
//! 1. Receives transaction request (to, value, data, etc.)
//! 2. Resolves wallet credentials from user mapping (multi-tenant)
//! 3. Reserves a nonce from the DynamoDB nonce authority
//! 4. Simulates transaction (eth_call)
//! 5. Signs, durably records (SIGNED), then broadcasts the raw transaction
//! 6. Returns immediately (watcher handles confirmation and rebroadcast)

mod config;
mod eip712;
mod error;
mod fees;
mod handler;
mod idempotency;
mod replacement;
mod signing;
mod tx;
mod types;

use lambda_runtime::{Error, LambdaEvent, service_fn};
use tracing::{error, info};

use crate::types::{SignHashRequest, SignHashResponse, TxRequest, TxResponse};

#[tokio::main]
async fn main() -> Result<(), Error> {
    // Initialize rustls crypto provider
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("tx_broadcast_lambda=info".parse().unwrap())
                .add_directive("nonce_manager=info".parse().unwrap()),
        )
        .json()
        .without_time() // Lambda adds timestamps
        .init();

    info!("Lambda cold start - initializing");

    // Run the Lambda handler
    lambda_runtime::run(service_fn(handler)).await
}

async fn handler(event: LambdaEvent<serde_json::Value>) -> Result<serde_json::Value, Error> {
    let (payload, _context) = event.into_parts();

    // The same pinned image serves a separately permissioned replacement function.
    // Its role/queue are isolated in CDK; mode is deployment-owned, never payload-owned.
    if std::env::var("FUNCTION_MODE").as_deref() == Ok("replacement") {
        return crate::replacement::handle_sqs_event(&payload).await;
    }

    // Parse request from different event sources:
    // 1. SQS: {"Records": [{"body": "{...}"}]}
    //    - batchSize is 1; only the first record is processed (CDK enforces this)
    // 2. Direct invocation: {"from": "0x...", ...}
    //    - Sign-hash if payload has `hash`, `typedData`, or `domainSeparator` AND no `to`
    //    - Broadcast otherwise
    if let Some(records) = payload.get("Records").and_then(|r| r.as_array()) {
        // SQS event. The event source is configured with batchSize=1 and this handler
        // does not implement partial-batch failure reporting, so a batch with more than
        // one record would silently ack (drop) every record after the first. Refuse the
        // whole batch instead; an Err returns every record to the queue for redelivery
        // and surfaces the misconfiguration loudly rather than losing transactions.
        if records.len() != 1 {
            return Err(Error::from(format!(
                "SQS event has {} records; this handler requires batchSize=1",
                records.len()
            )));
        }
        let record = &records[0];
        let body_str = record
            .get("body")
            .and_then(|b| b.as_str())
            .ok_or_else(|| Error::from("SQS record has no body"))?;
        let mut tx_request: TxRequest = serde_json::from_str(body_str)
            .map_err(|e| Error::from(format!("Invalid SQS message body: {}", e)))?;

        // Fall back to the SQS messageId as the idempotency key when the request omits
        // one or supplies a blank/whitespace-only key, so at-least-once redelivery of a
        // message without a usable key still dedups and cannot double-broadcast.
        tx_request.idempotency_key = crate::handler::sqs_idempotency_key(
            tx_request.idempotency_key.as_deref(),
            record.get("messageId").and_then(|id| id.as_str()),
        );

        let response = match crate::handler::handle_request_with_context(tx_request, None).await {
            Ok(resp) => resp,
            Err(e) => {
                error!(error = %e, "Transaction request failed");
                TxResponse::error(e.to_string())
            }
        };
        if !response.success {
            error!(error = ?response.error, code = ?response.error_code, "TX failed");
            // Return Err for retryable failures so SQS re-enqueues the message and routes
            // it to the DLQ after maxReceiveCount exhausted. Non-retryable failures (e.g.
            // simulation revert) return Ok to acknowledge and discard the message.
            if response.retryable {
                return Err(Error::from(
                    response.error.unwrap_or_else(|| "TX failed".to_string()),
                ));
            }
        }
        return serde_json::to_value(response)
            .map_err(|e| Error::from(format!("Failed to serialize SQS response: {e}")));
    }

    // Direct Lambda invocation — route by payload shape.
    // Sign-hash requests are identified by the absence of `to` AND the presence of at
    // least one signing field (`hash`, `typedData`, or `domainSeparator`).
    // A payload that contains BOTH `to` and a signing field is treated as a broadcast;
    // callers must omit `to` when signing.
    if payload.get("to").is_none()
        && (payload.get("hash").is_some()
            || payload.get("typedData").is_some()
            || payload.get("domainSeparator").is_some())
    {
        let req: SignHashRequest = serde_json::from_value(payload)
            .map_err(|e| Error::from(format!("Invalid sign-hash request: {}", e)))?;
        let response = match crate::handler::handle_sign_hash(req, None).await {
            Ok(resp) => resp,
            Err(e) => {
                error!(error = %e, "Sign-hash request failed");
                SignHashResponse {
                    success: false,
                    error: Some(e.to_string()),
                    error_code: Some("SIGNER_ERROR".to_string()),
                    ..Default::default()
                }
            }
        };
        return serde_json::to_value(response)
            .map_err(|e| Error::from(format!("Failed to serialize sign-hash response: {e}")));
    }

    // Broadcast path
    let tx_request: TxRequest = serde_json::from_value(payload)
        .map_err(|e| Error::from(format!("Invalid request: {}", e)))?;

    let response = match crate::handler::handle_request_with_context(tx_request, None).await {
        Ok(resp) => resp,
        Err(e) => {
            error!(error = %e, "Transaction request failed");
            TxResponse::error(e.to_string())
        }
    };

    if !response.success {
        error!(error = ?response.error, code = ?response.error_code, "TX failed");
    }

    serde_json::to_value(response)
        .map_err(|e| Error::from(format!("Failed to serialize response: {e}")))
}
