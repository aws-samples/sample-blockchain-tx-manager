#!/usr/bin/env bash
#
# Run the full test suite locally, matching what CI runs.
#
# The nonce_manager crate has two test layers:
#   * pure key/model/state-machine unit tests (no server, no AWS calls); and
#   * DynamoDB Local integration tests behind the `dynamodb-local-tests` Cargo feature,
#     which drive the real reservation/confirm/record_signed transaction logic against
#     a live DynamoDB Local instance.
#
# This script runs the integration layer too. It prefers an already-running endpoint
# (DYNAMODB_LOCAL_ENDPOINT, or http://127.0.0.1:8000) and otherwise launches
# DynamoDBLocal.jar under Java 17 — no Docker/Finch. When it starts the JAR itself it
# cleans up only that process on exit; an endpoint you supplied is left untouched.
#
# Usage:
#   scripts/run-tests.sh            # everything
#   scripts/run-tests.sh rust       # Rust crates only
#   scripts/run-tests.sh python     # Python signer only
#
# Integration-test environment:
#   DYNAMODB_LOCAL_ENDPOINT   use this already-running endpoint (skip launching a JAR)
#   DYNAMODB_LOCAL_JAR        path to DynamoDBLocal.jar to launch when no endpoint is up
#   DYNAMODB_LOCAL_PORT       port for a launched JAR (default 8000)
#   JAVA17_HOME               JDK 17 home used to launch the JAR (macOS: auto-detected
#                             via /usr/libexec/java_home -v 17)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

log() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
die() { printf '\n\033[31merror: %s\033[0m\n' "$*" >&2; exit 1; }

# ---- DynamoDB Local integration support (nonce_manager) --------------------

# PID of a DynamoDB Local JAR this script launched (empty when we reuse an endpoint).
NONCE_DDB_PID=""

# Kill only the DynamoDB Local process we started ourselves; never touch a
# pre-existing endpoint the caller supplied.
cleanup_ddb() {
    if [ -n "$NONCE_DDB_PID" ]; then
        kill "$NONCE_DDB_PID" 2>/dev/null || true
        wait "$NONCE_DDB_PID" 2>/dev/null || true
        NONCE_DDB_PID=""
    fi
}

# Ready when a bare GET completes (DynamoDB Local answers HTTP 400); curl exits 0 on any
# completed connection and non-zero only when the port is refused.
ddb_ready() { curl -s -o /dev/null "$1"; }

# Resolve a Java 17 launcher, honoring JAVA17_HOME, then macOS java_home, then a `java`
# on PATH that reports version 17. Prints the launcher path/name or nothing.
resolve_java17() {
    if [ -n "${JAVA17_HOME:-}" ] && [ -x "$JAVA17_HOME/bin/java" ] \
        && "$JAVA17_HOME/bin/java" -version 2>&1 | grep -q 'version "17'; then
        echo "$JAVA17_HOME/bin/java"; return 0
    fi
    local home
    home="$(/usr/libexec/java_home -v 17 2>/dev/null || true)"
    if [ -n "$home" ] && [ -x "$home/bin/java" ] \
        && "$home/bin/java" -version 2>&1 | grep -q 'version "17'; then
        echo "$home/bin/java"; return 0
    fi
    # Homebrew versioned JDKs are keg-only and are not visible to java_home unless the
    # user creates a system symlink. Use the formula prefix directly instead.
    if command -v brew >/dev/null 2>&1; then
        home="$(brew --prefix openjdk@17 2>/dev/null || true)"
        if [ -n "$home" ] && [ -x "$home/bin/java" ]; then
            echo "$home/bin/java"; return 0
        fi
    fi
    if command -v java >/dev/null 2>&1 && java -version 2>&1 | grep -q 'version "17'; then
        echo "java"; return 0
    fi
    return 1
}

# Ensure a DynamoDB Local endpoint is available and run the feature-gated integration
# tests against it. Prefers an existing endpoint; otherwise launches DynamoDBLocal.jar
# under Java 17 (no Docker/Finch) and tears down only that process afterward.
run_nonce_integration() {
    local endpoint="${DYNAMODB_LOCAL_ENDPOINT:-http://127.0.0.1:8000}"
    local started=0

    if ddb_ready "$endpoint"; then
        log "DynamoDB Local reachable at $endpoint (reusing it; will not manage its lifecycle)"
    else
        local jar="${DYNAMODB_LOCAL_JAR:-}"
        # Homebrew's dynamodb-local cask installs the JAR outside PATH and exposes only
        # a command wrapper. Discover the actual JAR so the script can still control the
        # exact process lifecycle and Java 17 launcher without requiring manual env vars.
        if [ -z "$jar" ] && command -v brew >/dev/null 2>&1; then
            jar="$(brew list --cask dynamodb-local 2>/dev/null \
                | grep '/DynamoDBLocal.jar$' | head -1 || true)"
        fi
        [ -n "$jar" ] && [ -f "$jar" ] || die \
"DynamoDB Local is not running at $endpoint and no DynamoDBLocal.jar was found.
Install the Homebrew dynamodb-local cask, start an endpoint and export
DYNAMODB_LOCAL_ENDPOINT, or set DYNAMODB_LOCAL_JAR explicitly. Official download:
  https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/DynamoDBLocal.DownloadingAndRunning.html"

        local java17
        java17="$(resolve_java17)" || die \
"Java 17 is required to launch DynamoDB Local. Install a JDK 17 and set JAVA17_HOME,
or start DynamoDB Local yourself and export DYNAMODB_LOCAL_ENDPOINT."

        local jar_dir port
        jar_dir="$(cd "$(dirname "$jar")" && pwd)"
        port="${DYNAMODB_LOCAL_PORT:-8000}"
        endpoint="http://127.0.0.1:$port"

        log "Starting DynamoDB Local under Java 17 on $endpoint"
        "$java17" -Djava.library.path="$jar_dir/DynamoDBLocal_lib" \
            -jar "$jar" -inMemory -port "$port" >/tmp/dynamodb-local.log 2>&1 &
        NONCE_DDB_PID=$!
        started=1
        trap cleanup_ddb EXIT INT TERM

        local _i
        for _i in $(seq 1 30); do
            ddb_ready "$endpoint" && break
            kill -0 "$NONCE_DDB_PID" 2>/dev/null \
                || die "DynamoDB Local exited during startup; see /tmp/dynamodb-local.log"
            sleep 1
        done
        ddb_ready "$endpoint" || die "DynamoDB Local did not become ready on $endpoint"
    fi

    log "cargo test (nonce_manager DynamoDB Local integration)"
    (cd nonce_manager && DYNAMODB_LOCAL_ENDPOINT="$endpoint" \
        cargo test --features dynamodb-local-tests --test dynamodb_local -- --test-threads=4)

    if [ "$started" = "1" ]; then
        cleanup_ddb
        trap - EXIT INT TERM
    fi
}

run_rust() {
    log "cargo fmt --check"
    for crate in nonce_manager tx_broadcast_lambda tx_watcher; do
        (cd "$crate" && cargo fmt --check) || die "$crate is not formatted (run: cd $crate && cargo fmt)"
    done

    # tx_broadcast_lambda's signer backends are feature-gated, so a single build proves
    # nothing about the others; clippy must see every combination that ships.
    log "cargo clippy -D warnings (all feature combos)"
    (cd nonce_manager && cargo clippy --all-targets -- -D warnings)
    (cd tx_watcher && cargo clippy --all-targets -- -D warnings)
    (cd tx_broadcast_lambda && for feats in "" "nitro" "coinbase" "nitro,coinbase"; do
        if [ -z "$feats" ]; then
            echo "--- features: <none> ---"
            cargo clippy --all-targets --no-default-features -- -D warnings
        else
            echo "--- features: $feats ---"
            cargo clippy --all-targets --no-default-features --features "$feats" -- -D warnings
        fi
    done)

    log "cargo test"
    (cd nonce_manager && cargo test)
    (cd tx_watcher && cargo test)
    (cd tx_broadcast_lambda && for feats in "" "nitro" "coinbase" "nitro,coinbase"; do
        if [ -z "$feats" ]; then
            echo "--- features: <none> ---"
            cargo test --no-default-features
        else
            echo "--- features: $feats ---"
            cargo test --no-default-features --features "$feats"
        fi
    done)

    # Real-DynamoDB integration layer for the nonce authority (feature-gated). Runs
    # against an existing endpoint or a Java-17-launched JAR; see the header for env vars.
    run_nonce_integration
}

run_python() {
    log "pytest (nitro_enclave_signer)"
    cd "$REPO_ROOT/nitro_enclave_signer"
    local python=".venv/bin/python"
    [ -x "$python" ] || die \
"nitro_enclave_signer/.venv is missing. Create it and install the pinned test dependencies:
  cd nitro_enclave_signer
  python3 -m venv .venv
  .venv/bin/pip install \
    -r requirements.txt \
    -r requirements-dev.txt \
    -r application/eth1/enclave/requirements.txt \
    -r application/eth1/lambda/requirements.txt \
    -r application/eth1/server/requirements.txt"
    "$python" -m pytest --version >/dev/null 2>&1 \
        || die "pytest is not installed in nitro_enclave_signer/.venv"
    PYTHONPATH="application/eth1/server:application/eth1/enclave:application/eth1/lambda" \
        "$python" -m pytest -q
}

case "${1:-all}" in
    all)         run_rust; run_python; log "All tests passed" ;;
    rust)        run_rust ;;
    python)      run_python ;;
    *)           die "Unknown target '$1' (expected: all|rust|python)" ;;
esac
