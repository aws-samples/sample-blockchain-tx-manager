#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

import base64
import json
import os
import re
import socket

# The enclave's only route to KMS is the `kmstool_enclave_cli` binary, which speaks the
# attestation protocol over the vsock proxy. Every call below passes a fixed argument
# list to a fixed absolute path with no shell, so caller input cannot become a command.
import subprocess  # nosec B404

from eth_keys import keys as eth_keys

# Bounds on a single vsock request. Requests come from the parent's HTTP handler, which
# applies its own cap, but the enclave does not trust the parent — in the Nitro threat
# model any local process can open a vsock to it.
MAX_REQUEST_BYTES = 16 * 1024
REQUEST_TIMEOUT_SECONDS = 10

# Bounds a KMS call made through the vsock proxy. `communicate()` without a timeout blocks
# the accept loop indefinitely if the proxy or KMS stops answering.
KMSTOOL_TIMEOUT_SECONDS = 15


# Every value below is interpolated into a `kmstool_enclave_cli` argument list, and all of
# them arrive in the request payload. A value beginning with "-" would be read as a flag
# rather than a value, so the charsets are anchored and none of them admit a leading dash.
#
# The tail anchor is `\Z`, not `$`: `$` also matches immediately before a trailing newline,
# so "us-east-1\n" would satisfy a `$`-anchored pattern.
_ARG_PATTERNS = {
    # The leading character is anchored separately from the rest: "-" is legal inside a
    # region name but must not be able to start one, or the value becomes a flag.
    "region": re.compile(r"\A[a-z][a-z0-9-]{1,31}\Z"),
    # A key id, key ARN, alias name, or alias ARN.
    "key_id": re.compile(r"\A[A-Za-z0-9][A-Za-z0-9:/_-]{0,2047}\Z"),
    # Base64: ciphertext blobs and session tokens.
    "base64": re.compile(r"\A[A-Za-z0-9+/=]{1,16384}\Z"),
    "access_key_id": re.compile(r"\A[A-Z0-9]{16,128}\Z"),
    "secret_access_key": re.compile(r"\A[A-Za-z0-9+/=]{1,128}\Z"),
}


def _checked_arg(kind, name, value):
    """Return `value` if it is safe to pass as a CLI argument value.

    Args:
        kind: Key into `_ARG_PATTERNS` selecting the permitted charset.
        name: Field name, used in the error message.
        value: The caller-supplied value.

    Returns:
        The value unchanged.

    Raises:
        ValueError: The value is not a string or contains characters outside the
            permitted charset for `kind`.
    """
    if not isinstance(value, str) or not _ARG_PATTERNS[kind].match(value):
        raise ValueError(f"{name} is not a well-formed {kind}")
    return value


def _credential_args(credential):
    """Build the validated credential portion of a `kmstool_enclave_cli` argument list.

    Raises:
        ValueError: The credential is missing a field or a field is malformed.
    """
    if not isinstance(credential, dict):
        raise ValueError("credential must be a JSON object")
    try:
        key_id = credential["access_key_id"]
        secret = credential["secret_access_key"]
        token = credential["token"]
    except KeyError as exc:
        raise ValueError(f"credential is missing {exc.args[0]}")

    return [
        "--aws-access-key-id",
        _checked_arg("access_key_id", "access_key_id", key_id),
        "--aws-secret-access-key",
        _checked_arg("secret_access_key", "secret_access_key", secret),
        "--aws-session-token",
        _checked_arg("base64", "token", token),
    ]


def _run_kmstool(subprocess_args, operation):
    """Run `kmstool_enclave_cli` and return its stdout.

    Raises:
        Exception: The tool exited non-zero or did not finish within its timeout.
    """
    print(f"Calling kmstool_enclave_cli {operation}")
    # A fixed absolute path and a fixed argument list, with no shell. Every interpolated
    # value has been charset-validated above, so none can become a flag or a command.
    proc = subprocess.Popen(  # nosec B603
        subprocess_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    try:
        stdout, stderr = proc.communicate(timeout=KMSTOOL_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        # Without this the single-threaded accept loop would block on a wedged KMS call.
        proc.kill()
        proc.communicate()
        raise Exception(f"KMS {operation} timed out after {KMSTOOL_TIMEOUT_SECONDS}s")

    if proc.returncode != 0:
        raise Exception(f"KMS {operation} failed: {stderr.decode()}")
    return stdout.decode()


def kms_decrypt(credential, ciphertext, region=None):
    """Decrypt ciphertext using KMS via attestation."""
    region = region or os.getenv("REGION", "us-east-1")
    subprocess_args = [
        "/app/kmstool_enclave_cli",
        "decrypt",
        "--region",
        _checked_arg("region", "region", region),
        "--proxy-port",
        "8000",
        *_credential_args(credential),
        "--ciphertext",
        _checked_arg("base64", "encrypted_key", ciphertext),
    ]

    result = _run_kmstool(subprocess_args, "decrypt")

    # Output is "PLAINTEXT: <b64>". Anything else must not be treated as a key: silently
    # returning a mis-parsed fragment would produce signatures under the wrong key.
    prefix = "PLAINTEXT:"
    if not result.startswith(prefix):
        raise Exception("Unexpected decrypt output")
    return result[len(prefix) :].strip()


def kms_generate_random(credential, key_id, region=None):
    """Generate random bytes using KMS via attestation.

    Uses GenerateDataKey which returns both plaintext (for use in enclave)
    and ciphertext (for storage) encrypted under the specified KMS key.
    """
    region = region or os.getenv("REGION", "us-east-1")
    subprocess_args = [
        "/app/kmstool_enclave_cli",
        "genkey",
        "--region",
        _checked_arg("region", "region", region),
        "--proxy-port",
        "8000",
        *_credential_args(credential),
        "--key-id",
        _checked_arg("key_id", "key_id", key_id),
        "--key-spec",
        "AES-256",
    ]

    result = _run_kmstool(subprocess_args, "genkey")

    plaintext_b64 = None
    ciphertext_b64 = None
    for line in result.strip().split("\n"):
        if line.startswith("PLAINTEXT:"):
            plaintext_b64 = line.split(":", 1)[1].strip()
        elif line.startswith("CIPHERTEXT:"):
            ciphertext_b64 = line.split(":", 1)[1].strip()

    if not plaintext_b64 or not ciphertext_b64:
        # Deliberately does not echo the output: it would contain the plaintext key.
        raise Exception("Unexpected genkey output")

    return plaintext_b64, ciphertext_b64


def generate_key(credential, key_id, region=None):
    """Generate a new Ethereum key pair inside the enclave.

    Uses KMS GenerateDataKey to get random bytes that are:
    1. Returned as plaintext to the enclave (for deriving address)
    2. Returned as ciphertext (for storage in Secrets Manager)

    The plaintext key never leaves the enclave.
    """
    # Get random bytes from KMS - returns both plaintext and encrypted versions
    plaintext_b64, ciphertext_b64 = kms_generate_random(credential, key_id, region)

    # Decode the plaintext to get the raw bytes (32 bytes from AES_256)
    private_key_bytes = base64.standard_b64decode(plaintext_b64)

    # Validate the key is within secp256k1 curve order
    SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    key_int = int.from_bytes(private_key_bytes, "big")

    if key_int == 0 or key_int >= SECP256K1_ORDER:
        raise Exception("Generated key outside valid range, retry required")

    # Derive the Ethereum address
    private_key = eth_keys.PrivateKey(private_key_bytes)
    address = private_key.public_key.to_checksum_address()

    # Drop our references to the plaintext key. This is NOT zeroization: Python `bytes`
    # are immutable and `del` only unbinds names, so the material lives until the
    # garbage collector reclaims it. The actual control is the enclave boundary — no
    # process outside the enclave can read this memory — not scrubbing.
    del private_key_bytes
    del private_key
    del plaintext_b64

    return {
        "address": address,
        "encrypted_key": ciphertext_b64,
    }


def sign_hash(key_bytes, hash_hex):
    """Sign a raw 32-byte hash and return r, s, v signature components.

    SECURITY NOTE: a raw hash carries no information about what it authorizes, so this
    function grants unconstrained signing authority over the wallet by design. Callers
    are constrained outside the enclave, not here: the parent service authenticates every
    request against an IAM principal allowlist (SigV4 via STS) or a client certificate
    (mTLS), the security group admits only the broadcast Lambda, and the Lambda's
    ecrecover check rejects malformed responses. This function itself validates nothing
    beyond hash length, and must not be exposed to any caller that is not already trusted
    with the wallet. Reconstructing hashes from transaction pre-images inside the enclave
    would remove the trust assumption; that is not what this does.

    Raises:
        ValueError: `hash_hex` is not exactly 32 bytes of hex.
    """
    hash_clean = hash_hex.removeprefix("0x")
    hash_bytes = bytes.fromhex(hash_clean)

    # `sign_msg_hash` accepts any length, so without this the enclave would sign
    # arbitrary-length digests. The parent checks too, but the enclave does not trust the
    # parent: in the Nitro threat model any local process can open a vsock to it.
    if len(hash_bytes) != 32:
        raise ValueError(f"hash must be exactly 32 bytes, got {len(hash_bytes)}")

    private_key = eth_keys.PrivateKey(key_bytes)
    signature = private_key.sign_msg_hash(hash_bytes)

    return {
        "r": f"0x{signature.r:064x}",
        "s": f"0x{signature.s:064x}",
        "v": signature.v + 27,
    }


def _recv_request(c):
    """Read one complete request from a vsock connection.

    The peer signals end-of-request by shutting down its write side. A peer that never
    does so must not be able to block the enclave forever: this is a single-threaded
    accept loop, so one stalled connection stops *every* wallet from signing until the
    enclave is manually restarted. The timeout and size cap bound both cases.

    Args:
        c: An accepted vsock connection.

    Returns:
        The decoded request as a dict.

    Raises:
        ValueError: The peer stalled, sent nothing, exceeded the size cap, or sent
            something that is not a JSON object.
    """
    c.settimeout(REQUEST_TIMEOUT_SECONDS)

    chunks = []
    total = 0
    while True:
        try:
            chunk = c.recv(4096)
        except socket.timeout:
            raise ValueError(f"peer stalled for more than {REQUEST_TIMEOUT_SECONDS}s")
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > MAX_REQUEST_BYTES:
            raise ValueError(f"request exceeded {MAX_REQUEST_BYTES} bytes")

    if not chunks:
        raise ValueError("peer closed the connection without sending a request")

    payload = json.loads(b"".join(chunks).decode())
    if not isinstance(payload, dict):
        # `main` calls .get() on this. A list or scalar would raise AttributeError, which
        # is outside the caller's except clause and would stop the accept loop for good.
        raise ValueError(f"request must be a JSON object, got {type(payload).__name__}")
    return payload


def _respond(c, response):
    """Send a complete JSON response and close the connection.

    `sendall` rather than `send`: a short write would leave the parent parsing a truncated
    body, and closing without shutting down the write side leaves it waiting for EOF.
    """
    try:
        c.sendall(str.encode(json.dumps(response)))
        c.shutdown(socket.SHUT_WR)
    except OSError as e:
        print(f"Could not send response: {e}")
    finally:
        c.close()


def _dispatch(payload_json):
    """Execute one well-formed request and return the response object.

    Kept separate from the accept loop so the operation table is unit-testable. Every
    exception is converted into an `{"error": ...}` response here; nothing propagates to
    the loop.
    """
    # No default operation: a request must say what it wants. (The historical default,
    # `sign_transaction`, built and signed a full transaction inside the enclave,
    # reinterpreting `value` as ether and bypassing the nonce authority, simulation, and
    # the broadcaster's ecrecover. It has been removed; this enclave signs 32-byte hashes.)
    operation = payload_json.get("operation")
    print(f"Received {operation} request")

    credential = payload_json.get("credential")
    region = payload_json.get("region")

    try:
        if operation == "ping":
            # Liveness probe from the parent's health endpoint. Touches no credential,
            # no KMS, and no key material: it only proves the accept loop is alive and
            # answering well-formed requests.
            return {"status": "ok"}

        if operation == "generate_key":
            # Generate new key - no existing encrypted_key needed
            key_id = payload_json["key_id"]
            return generate_key(credential, key_id, region)

        if operation != "sign_hash":
            # Refuse before touching KMS or any key material.
            return {"error": f"Unknown operation: {operation}"}

        # sign_hash needs to decrypt the existing key first
        key_encrypted = payload_json["encrypted_key"]
        key_b64 = kms_decrypt(credential, key_encrypted, region)
        # KMS returns raw bytes as base64, decode to get the 32-byte key
        key_bytes = base64.standard_b64decode(key_b64)

        try:
            if operation == "sign_hash":
                hash_to_sign = payload_json["hash"]
                signature = sign_hash(key_bytes, hash_to_sign)
                return {"signature": signature}

            return {"error": f"Unknown operation: {operation}"}
        finally:
            del key_bytes

    except Exception as e:  # noqa: BLE001 - the loop must survive anything
        # Detail stays inside the enclave (console). Exception text from code that held
        # plaintext key bytes must never cross the vsock: only the operation and the
        # exception class name are relayed, neither of which can carry key material.
        print(f"exception during {operation}: {type(e).__name__}: {e}")
        return {"error": f"{operation} failed: {type(e).__name__}"}


def main():
    print("Starting server...")

    s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    cid = socket.VMADDR_CID_ANY
    port = 5000
    s.bind((cid, port))
    s.listen()

    while True:
        c, addr = s.accept()

        try:
            payload_json = _recv_request(c)
        except (ValueError, json.JSONDecodeError, OSError) as e:
            # Never let one bad peer take down the loop; answer and move on.
            print(f"Rejected malformed request: {e}")
            _respond(c, {"error": "malformed request"})
            continue

        response_plaintext = _dispatch(payload_json)

        if "error" in response_plaintext:
            print(f"Request failed: {response_plaintext['error']}")
        else:
            print("Request succeeded")

        _respond(c, response_plaintext)


if __name__ == "__main__":
    main()
