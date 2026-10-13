#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

import json
import logging
import os
import re
import ssl
from http import client

import boto3
from eth_keys import keys as eth_keys

import nitro_client_auth

AWS_REGION = os.getenv("AWS_REGION", "us-east-1")

# Signing keys live under a single namespace, which is also the only prefix the
# instance and Lambda roles are granted access to (see nitro_wallet_stack.py). Validating
# here keeps a malformed name from reaching the enclave at all, and keeps the stored name
# aligned with what the IAM policy actually scopes.
SECRET_NAME_PATTERN = re.compile(r"^nitro-wallet/[a-zA-Z0-9_-]{1,64}$")


def _build_ssl_context(ca_cert_path=None, ca_cert_pem=None, skip_tls_verify=False):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if ca_cert_path:
        context.load_verify_locations(ca_cert_path)
        context.verify_mode = ssl.CERT_REQUIRED
    elif ca_cert_pem:
        context.load_verify_locations(cadata=ca_cert_pem)
        context.verify_mode = ssl.CERT_REQUIRED
    elif skip_tls_verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    else:
        context.load_default_certs()
        context.verify_mode = ssl.CERT_REQUIRED
    return context


ssl_context = _build_ssl_context(
    os.getenv("NITRO_CA_CERT_PATH"),
    os.getenv("NITRO_CA_CERT_PEM"),
    os.getenv("NITRO_SKIP_TLS_VERIFY", "").lower() in ("true", "1"),
)


LOG_LEVEL = os.getenv("LOG_LEVEL", "WARNING")
LOG_FORMAT = "%(levelname)s:%(lineno)s:%(message)s"
handler = logging.StreamHandler()

_logger = logging.getLogger("tx_manager_controller")
_logger.setLevel(LOG_LEVEL)
_logger.addHandler(handler)
_logger.propagate = False

client_secrets_manager = boto3.client("secretsmanager")


def _validate_hash(hash_value):
    """Validate that hash_value is exactly 32 bytes of hex."""
    if not hash_value:
        raise ValueError("sign_hash requires a 'hash' field")
    hash_clean = hash_value.replace("0x", "")
    if len(hash_clean) != 64:
        raise ValueError(
            "Hash must be exactly 32 bytes (64 hex chars), got {} chars".format(len(hash_clean))
        )
    try:
        bytes.fromhex(hash_clean)
    except ValueError:
        raise ValueError("Hash contains invalid hex characters")
    return hash_clean


def _validate_secret_name(secret_name):
    """Validate a target secret name for key generation.

    Args:
        secret_name: The caller-supplied name for the new wallet's secret.

    Returns:
        The validated name.

    Raises:
        ValueError: The name is missing or outside the `nitro-wallet/` namespace.
    """
    if not secret_name:
        raise ValueError("generate_key requires secret_name")
    if not isinstance(secret_name, str) or not SECRET_NAME_PATTERN.match(secret_name):
        raise ValueError(
            "secret_name must match nitro-wallet/<1-64 chars of A-Z a-z 0-9 _ ->, got {!r}".format(
                secret_name
            )
        )
    return secret_name


def _verify_recovered_address(hash_hex, signature, expected_address):
    """Verify that the signature recovers to the expected address.

    Provides defense-in-depth against forged or malformed signatures
    on the Python Lambda invocation path (mirrors the Rust NitroSigner's
    ecrecover check).
    """
    hash_clean = hash_hex.replace("0x", "")
    hash_bytes = bytes.fromhex(hash_clean)

    r = int(signature["r"], 16)
    s = int(signature["s"], 16)
    # eth_keys uses v as 0 or 1 (not 27/28)
    v_normalized = signature["v"] - 27

    sig = eth_keys.Signature(vrs=(v_normalized, r, s))
    recovered_key = sig.recover_public_key_from_msg_hash(hash_bytes)
    recovered_address = recovered_key.to_checksum_address()

    if recovered_address.lower() != expected_address.lower():
        raise Exception(
            "Signature verification failed: recovered {} but expected {}".format(
                recovered_address, expected_address
            )
        )


def _post_to_signer(host, path, payload):
    """POST an authenticated request to the parent signing service.

    The service refuses requests it cannot attribute to an allowed IAM principal, so
    every call carries a SigV4 identity proof bound to this exact body.

    Args:
        host: The signing service's DNS name (the NLB).
        path: Request path, e.g. `/sign_hash`.
        payload: JSON-serializable request body.

    Returns:
        The parsed JSON response.

    Raises:
        Exception: The service was unreachable, rejected the request, or returned a body
            that is not JSON.
    """
    body = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    headers.update(nitro_client_auth.build_auth_headers(body, AWS_REGION))

    connection = client.HTTPSConnection("{}:{}".format(host, 443), context=ssl_context)
    try:
        connection.request("POST", path, body=body, headers=headers)
        response = connection.getresponse()
        response_raw = response.read()
        status = response.status
    except Exception as e:
        raise Exception("exception happened calling Nitro Enclave {}: {}".format(path, e))
    finally:
        connection.close()

    _logger.debug("response: {}".format(status))

    try:
        parsed = json.loads(response_raw)
    except json.JSONDecodeError:
        raise Exception(
            "Nitro Enclave {} returned HTTP {} with a non-JSON body".format(path, status)
        )

    if status != 200:
        raise Exception(
            "Nitro Enclave {} returned HTTP {}: {}".format(
                path, status, parsed.get("error", parsed)
            )
        )

    if "error" in parsed:
        raise Exception("Enclave error: {}".format(parsed["error"]))

    return parsed


def lambda_handler(event, context):
    """
    example requests:

    Sign a raw hash (e.g. EIP-712 typed data):
    {
      "operation": "sign_hash",
      "hash": "0x<64 hex chars>"
    }

    """
    nitro_instance_private_dns = os.getenv("NITRO_INSTANCE_PRIVATE_DNS")
    key_id = os.getenv("KEY_ARN")

    # SECRET_ARN is deliberately not read here: which wallet signs is the signing
    # service's decision, configured on the instance, not something this caller passes.
    if not (nitro_instance_private_dns and key_id):
        raise ValueError(
            "NITRO_INSTANCE_PRIVATE_DNS and KEY_ARN environment variables need to be set"
        )

    operation = event.get("operation")
    if not operation:
        raise ValueError("request needs to define operation")

    if operation == "generate_key":
        # Secure key generation - key is created inside the enclave
        # and never exists in plaintext outside of it
        secret_name = _validate_secret_name(event.get("secret_name"))

        response_parsed = _post_to_signer(
            nitro_instance_private_dns, "/generate_key", {"key_id": key_id}
        )

        # Store the encrypted key in Secrets Manager
        encrypted_key = response_parsed["encrypted_key"]
        address = response_parsed["address"]

        # Create only — never update. If the name is already taken it may hold a funded
        # wallet's only ciphertext, and overwriting it would make those funds permanently
        # inaccessible. A name collision is a hard error the caller must resolve by
        # choosing a different name; there is deliberately no rotate-in-place path.
        try:
            client_secrets_manager.create_secret(
                Name=secret_name,
                SecretString=encrypted_key,
                Description=f"Encrypted Ethereum key for {address}",
            )
        except client_secrets_manager.exceptions.ResourceExistsException:
            raise Exception(
                "secret_name '{}' already exists. Refusing to overwrite it: it may hold "
                "the only copy of a funded wallet's encrypted key. Choose a different "
                "name.".format(secret_name)
            )

        return {
            "address": address,
            "secret_name": secret_name,
        }

    elif operation == "sign_hash":
        hash_value = event.get("hash")
        _validate_hash(hash_value)

        response_parsed = _post_to_signer(
            nitro_instance_private_dns, "/sign_hash", {"hash": hash_value}
        )

        # Verify the signature recovers to the wallet address if the address
        # is available. The address is obtained by calling generate_key or
        # looked up from Secrets Manager metadata — pass it via the event
        # payload as "expected_address" for defense-in-depth verification.
        expected_address = event.get("expected_address")
        if expected_address and "signature" in response_parsed:
            _verify_recovered_address(hash_value, response_parsed["signature"], expected_address)

        return response_parsed

    else:
        raise ValueError("operation: {} not supported right now".format(operation))
