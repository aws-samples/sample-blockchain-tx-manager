"""Tests for lambda_function.py sign_hash operation and helpers."""

import hashlib
import json
import os
import unittest
from unittest.mock import patch, MagicMock

# Set required env vars before importing lambda_function
os.environ["NITRO_INSTANCE_PRIVATE_DNS"] = "test-host"
os.environ["KEY_ARN"] = "arn:aws:kms:us-east-1:123456789:key/test-key-id"
os.environ["NITRO_SKIP_TLS_VERIFY"] = "true"
# Signing an identity proof needs credentials; supply static ones so the suite does not
# depend on the ambient AWS environment.
os.environ.setdefault("AWS_ACCESS_KEY_ID", "AKIDEXAMPLE")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

import nitro_client_auth
from lambda_function import (
    _build_ssl_context,
    _validate_hash,
    _validate_secret_name,
    _verify_recovered_address,
    lambda_handler,
)


class TestTlsContext(unittest.TestCase):
    def test_inline_ca_uses_cadata_and_keeps_verification(self):
        with patch("ssl.SSLContext.load_verify_locations") as load:
            context = _build_ssl_context(ca_cert_pem="PUBLIC-CA-PEM")
        load.assert_called_once_with(cadata="PUBLIC-CA-PEM")
        self.assertEqual(context.verify_mode, __import__("ssl").CERT_REQUIRED)
        self.assertTrue(context.check_hostname)


class TestValidateHash(unittest.TestCase):
    def test_valid_hash_with_0x(self):
        result = _validate_hash("0x" + "ab" * 32)
        self.assertEqual(len(result), 64)

    def test_valid_hash_without_0x(self):
        result = _validate_hash("ab" * 32)
        self.assertEqual(result, "ab" * 32)

    def test_missing_hash(self):
        with self.assertRaises(ValueError) as ctx:
            _validate_hash(None)
        self.assertIn("requires", str(ctx.exception))

    def test_empty_hash(self):
        with self.assertRaises(ValueError) as ctx:
            _validate_hash("")
        self.assertIn("requires", str(ctx.exception))

    def test_too_short(self):
        with self.assertRaises(ValueError) as ctx:
            _validate_hash("0x" + "ab" * 31)
        self.assertIn("64 hex chars", str(ctx.exception))

    def test_too_long(self):
        with self.assertRaises(ValueError) as ctx:
            _validate_hash("0x" + "ab" * 33)
        self.assertIn("64 hex chars", str(ctx.exception))

    def test_invalid_hex(self):
        with self.assertRaises(ValueError) as ctx:
            _validate_hash("0x" + "zz" * 32)
        self.assertIn("invalid hex", str(ctx.exception))


class TestValidateSecretName(unittest.TestCase):
    """A caller-chosen secret name must stay inside the namespace IAM actually scopes."""

    def test_valid_name(self):
        self.assertEqual(
            _validate_secret_name("nitro-wallet/treasury-1"), "nitro-wallet/treasury-1"
        )

    def test_missing_name(self):
        with self.assertRaises(ValueError) as ctx:
            _validate_secret_name(None)
        self.assertIn("requires secret_name", str(ctx.exception))

    def test_rejects_other_namespace(self):
        with self.assertRaises(ValueError):
            _validate_secret_name("prod/database-password")

    def test_rejects_path_traversal(self):
        # `nitro-wallet/../prod/x` matches the prefix but escapes the namespace.
        with self.assertRaises(ValueError):
            _validate_secret_name("nitro-wallet/../prod/x")

    def test_rejects_nested_path(self):
        with self.assertRaises(ValueError):
            _validate_secret_name("nitro-wallet/a/b")

    def test_rejects_wildcard(self):
        with self.assertRaises(ValueError):
            _validate_secret_name("nitro-wallet/*")

    def test_rejects_non_string(self):
        with self.assertRaises(ValueError):
            _validate_secret_name(["nitro-wallet/x"])


class TestVerifyRecoveredAddress(unittest.TestCase):
    """Test ecrecover verification using a known signature."""

    # Known test vector: private key 0x01 signs hash 0x01...00
    # These values are generated from eth_keys directly
    KNOWN_HASH = "0x0000000000000000000000000000000000000000000000000000000000000001"

    def test_valid_recovery(self):
        """Use eth_keys to generate a real signature, then verify it recovers."""
        from eth_keys import keys as ek

        private_key = ek.PrivateKey(b"\x01" * 32)
        address = private_key.public_key.to_checksum_address()
        hash_bytes = bytes.fromhex(self.KNOWN_HASH.replace("0x", ""))
        sig = private_key.sign_msg_hash(hash_bytes)

        signature = {
            "r": hex(sig.r),
            "s": hex(sig.s),
            "v": sig.v + 27,
        }

        # Should not raise
        _verify_recovered_address(self.KNOWN_HASH, signature, address)

    def test_wrong_address_raises(self):
        from eth_keys import keys as ek

        private_key = ek.PrivateKey(b"\x01" * 32)
        hash_bytes = bytes.fromhex(self.KNOWN_HASH.replace("0x", ""))
        sig = private_key.sign_msg_hash(hash_bytes)

        signature = {
            "r": hex(sig.r),
            "s": hex(sig.s),
            "v": sig.v + 27,
        }

        with self.assertRaises(Exception) as ctx:
            _verify_recovered_address(
                self.KNOWN_HASH, signature, "0x0000000000000000000000000000000000000000"
            )
        self.assertIn("verification failed", str(ctx.exception))


class TestSignHashLambdaHandler(unittest.TestCase):
    """Test the sign_hash operation in the Lambda handler."""

    def _mock_https_response(self, body_dict, status=200):
        mock_response = MagicMock()
        mock_response.status = status
        mock_response.reason = "OK"
        mock_response.read.return_value = json.dumps(body_dict).encode()
        return mock_response

    @patch("lambda_function.client.HTTPSConnection")
    def test_sign_hash_success(self, mock_conn_cls):
        mock_conn = MagicMock()
        mock_conn_cls.return_value = mock_conn
        mock_conn.getresponse.return_value = self._mock_https_response(
            {"signature": {"r": "0x" + "ab" * 32, "s": "0x" + "cd" * 32, "v": 27}}
        )

        event = {"operation": "sign_hash", "hash": "0x" + "ff" * 32}
        result = lambda_handler(event, None)

        self.assertIn("signature", result)
        self.assertEqual(result["signature"]["v"], 27)
        mock_conn.request.assert_called_once()
        call_args = mock_conn.request.call_args
        self.assertEqual(call_args[0][1], "/sign_hash")

    @patch("lambda_function.client.HTTPSConnection")
    def test_request_carries_a_bound_identity_proof(self, mock_conn_cls):
        """The service rejects requests it cannot attribute, so every call must be signed."""
        mock_conn = MagicMock()
        mock_conn_cls.return_value = mock_conn
        mock_conn.getresponse.return_value = self._mock_https_response(
            {"signature": {"r": "0x" + "ab" * 32, "s": "0x" + "cd" * 32, "v": 27}}
        )

        lambda_handler({"operation": "sign_hash", "hash": "0x" + "ff" * 32}, None)

        headers = mock_conn.request.call_args.kwargs["headers"]
        body = mock_conn.request.call_args.kwargs["body"]

        self.assertIn(nitro_client_auth.AUTHORIZATION_HEADER, headers)
        self.assertIn(nitro_client_auth.DATE_HEADER, headers)
        # The digest must cover the bytes actually sent, or the service rejects the body.
        self.assertEqual(headers[nitro_client_auth.DIGEST_HEADER], hashlib.sha256(body).hexdigest())
        # And the digest header has to be inside the signed set, otherwise the signature
        # says nothing about the body and the proof is replayable against any payload.
        authorization = headers[nitro_client_auth.AUTHORIZATION_HEADER]
        signed_headers = authorization.split("SignedHeaders=")[1].split(",")[0]
        self.assertIn(nitro_client_auth.DIGEST_HEADER.lower(), signed_headers.split(";"))

    @patch("lambda_function.client.HTTPSConnection")
    def test_non_json_error_body_is_not_masked(self, mock_conn_cls):
        """A gateway returning HTML on 502 must not surface as a JSON parse error."""
        mock_conn = MagicMock()
        mock_conn_cls.return_value = mock_conn
        response = MagicMock()
        response.status = 502
        response.reason = "Bad Gateway"
        response.read.return_value = b"<html>502 Bad Gateway</html>"
        mock_conn.getresponse.return_value = response

        with self.assertRaises(Exception) as ctx:
            lambda_handler({"operation": "sign_hash", "hash": "0x" + "ff" * 32}, None)
        self.assertIn("502", str(ctx.exception))
        self.assertIn("non-JSON", str(ctx.exception))

    @patch("lambda_function.client.HTTPSConnection")
    def test_unauthorized_status_is_surfaced(self, mock_conn_cls):
        """403 from the allowlist check must reach the caller, not look like a fault."""
        mock_conn = MagicMock()
        mock_conn_cls.return_value = mock_conn
        mock_conn.getresponse.return_value = self._mock_https_response(
            {"error": "Caller is not authorized to use this signing service"}, status=403
        )

        with self.assertRaises(Exception) as ctx:
            lambda_handler({"operation": "sign_hash", "hash": "0x" + "ff" * 32}, None)
        self.assertIn("403", str(ctx.exception))
        self.assertIn("not authorized", str(ctx.exception))

    @patch("lambda_function.client.HTTPSConnection")
    def test_sign_hash_enclave_error(self, mock_conn_cls):
        mock_conn = MagicMock()
        mock_conn_cls.return_value = mock_conn
        mock_conn.getresponse.return_value = self._mock_https_response(
            {"error": "KMS decrypt failed"}
        )

        event = {"operation": "sign_hash", "hash": "0x" + "ff" * 32}
        with self.assertRaises(Exception) as ctx:
            lambda_handler(event, None)
        self.assertIn("KMS decrypt failed", str(ctx.exception))

    def test_sign_hash_missing_hash(self):
        event = {"operation": "sign_hash"}
        with self.assertRaises(ValueError) as ctx:
            lambda_handler(event, None)
        self.assertIn("requires", str(ctx.exception))

    def test_sign_hash_invalid_hash(self):
        event = {"operation": "sign_hash", "hash": "0xtooshort"}
        with self.assertRaises(ValueError):
            lambda_handler(event, None)

    @patch("lambda_function.client.HTTPSConnection")
    def test_sign_hash_network_error(self, mock_conn_cls):
        mock_conn = MagicMock()
        mock_conn_cls.return_value = mock_conn
        mock_conn.request.side_effect = ConnectionError("connection refused")

        event = {"operation": "sign_hash", "hash": "0x" + "ff" * 32}
        with self.assertRaises(Exception) as ctx:
            lambda_handler(event, None)
        self.assertIn("exception happened calling Nitro Enclave /sign_hash", str(ctx.exception))

    @patch("lambda_function.client.HTTPSConnection")
    def test_sign_hash_with_ecrecover(self, mock_conn_cls):
        """Test that ecrecover runs when expected_address is provided."""
        from eth_keys import keys as ek

        private_key = ek.PrivateKey(b"\x02" * 32)
        address = private_key.public_key.to_checksum_address()
        hash_hex = "0x" + "aa" * 32
        hash_bytes = bytes.fromhex("aa" * 32)
        sig = private_key.sign_msg_hash(hash_bytes)

        mock_conn = MagicMock()
        mock_conn_cls.return_value = mock_conn
        mock_conn.getresponse.return_value = self._mock_https_response(
            {
                "signature": {
                    "r": hex(sig.r),
                    "s": hex(sig.s),
                    "v": sig.v + 27,
                }
            }
        )

        event = {
            "operation": "sign_hash",
            "hash": hash_hex,
            "expected_address": address,
        }
        result = lambda_handler(event, None)
        self.assertIn("signature", result)

    @patch("lambda_function.client.HTTPSConnection")
    def test_sign_hash_ecrecover_wrong_address(self, mock_conn_cls):
        """Test that ecrecover rejects wrong expected_address."""
        from eth_keys import keys as ek

        private_key = ek.PrivateKey(b"\x02" * 32)
        hash_hex = "0x" + "aa" * 32
        hash_bytes = bytes.fromhex("aa" * 32)
        sig = private_key.sign_msg_hash(hash_bytes)

        mock_conn = MagicMock()
        mock_conn_cls.return_value = mock_conn
        mock_conn.getresponse.return_value = self._mock_https_response(
            {
                "signature": {
                    "r": hex(sig.r),
                    "s": hex(sig.s),
                    "v": sig.v + 27,
                }
            }
        )

        event = {
            "operation": "sign_hash",
            "hash": hash_hex,
            "expected_address": "0x0000000000000000000000000000000000000000",
        }
        with self.assertRaises(Exception) as ctx:
            lambda_handler(event, None)
        self.assertIn("verification failed", str(ctx.exception))

    def test_unsupported_operation(self):
        event = {"operation": "unknown_op"}
        with self.assertRaises(ValueError) as ctx:
            lambda_handler(event, None)
        self.assertIn("not supported", str(ctx.exception))

    def test_missing_operation(self):
        event = {}
        with self.assertRaises(ValueError) as ctx:
            lambda_handler(event, None)
        self.assertIn("needs to define operation", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
