#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0
"""Tests for the enclave's vsock request handling.

The accept loop is single threaded, so any request that can stall it or raise outside its
except clause stops *every* wallet from signing until the enclave is manually restarted.
These tests pin the framing behaviour that prevents that. KMS and signing are not
exercised: they need `kmstool_enclave_cli` and a decrypted key.
"""

import base64
import json
import socket
import sys
import unittest
from unittest.mock import MagicMock, patch

import server  # noqa: E402


def _connection(chunks=(), recv_side_effect=None):
    conn = MagicMock()
    if recv_side_effect is not None:
        conn.recv.side_effect = recv_side_effect
    else:
        conn.recv.side_effect = list(chunks) + [b""]
    return conn


class TestRecvRequest(unittest.TestCase):
    def test_reads_a_complete_request(self):
        payload = {"operation": "sign_hash", "hash": "0x01"}
        conn = _connection([json.dumps(payload).encode()])
        self.assertEqual(server._recv_request(conn), payload)

    def test_reassembles_a_chunked_request(self):
        payload = {"operation": "sign_hash", "hash": "0x" + "ab" * 32}
        raw = json.dumps(payload).encode()
        conn = _connection([raw[:5], raw[5:20], raw[20:]])
        self.assertEqual(server._recv_request(conn), payload)

    def test_a_read_timeout_is_configured(self):
        conn = _connection([b"{}"])
        server._recv_request(conn)
        conn.settimeout.assert_called_once_with(server.REQUEST_TIMEOUT_SECONDS)

    def test_stalled_peer_raises(self):
        """A peer that opens a connection and never shuts down its write side.

        Without the timeout this blocks the accept loop indefinitely.
        """
        conn = _connection(recv_side_effect=[b'{"oper', socket.timeout()])
        with self.assertRaises(ValueError) as ctx:
            server._recv_request(conn)
        self.assertIn("stalled", str(ctx.exception))

    def test_empty_request_raises(self):
        with self.assertRaises(ValueError) as ctx:
            server._recv_request(_connection([]))
        self.assertIn("without sending a request", str(ctx.exception))

    def test_oversize_request_raises(self):
        oversize = [b"a" * 4096] * (server.MAX_REQUEST_BYTES // 4096 + 2)
        with self.assertRaises(ValueError) as ctx:
            server._recv_request(_connection(oversize))
        self.assertIn("exceeded", str(ctx.exception))

    def test_malformed_json_raises(self):
        with self.assertRaises(json.JSONDecodeError):
            server._recv_request(_connection([b"{not json"]))

    def test_json_array_is_rejected(self):
        """`main` calls .get() on the result; a list would raise AttributeError.

        That exception is outside main's except clause, so it would propagate and stop the
        accept loop permanently.
        """
        with self.assertRaises(ValueError) as ctx:
            server._recv_request(_connection([b"[1,2,3]"]))
        self.assertIn("JSON object", str(ctx.exception))

    def test_json_scalar_is_rejected(self):
        for raw in (b"42", b'"a string"', b"null", b"true"):
            with self.subTest(raw=raw):
                with self.assertRaises(ValueError):
                    server._recv_request(_connection([raw]))

    def test_request_at_the_cap_is_accepted(self):
        filler = "a" * (server.MAX_REQUEST_BYTES - 20)
        raw = json.dumps({"h": filler}).encode()
        self.assertLessEqual(len(raw), server.MAX_REQUEST_BYTES)
        self.assertEqual(server._recv_request(_connection([raw]))["h"], filler)


class TestRespond(unittest.TestCase):
    def test_sends_the_whole_body_and_signals_eof(self):
        conn = MagicMock()
        server._respond(conn, {"signature": {"v": 27}})
        # sendall, not send: a short write would truncate the parent's response body.
        conn.sendall.assert_called_once_with(b'{"signature": {"v": 27}}')
        conn.shutdown.assert_called_once_with(socket.SHUT_WR)
        conn.close.assert_called_once()

    def test_closes_the_connection_even_when_sending_fails(self):
        # Leaking the descriptor on every failed send would eventually exhaust them.
        conn = MagicMock()
        conn.sendall.side_effect = OSError("broken pipe")
        server._respond(conn, {"error": "x"})
        conn.close.assert_called_once()

    def test_send_failure_does_not_propagate(self):
        conn = MagicMock()
        conn.shutdown.side_effect = OSError("not connected")
        server._respond(conn, {"error": "x"})
        conn.close.assert_called_once()


CREDENTIAL = {
    "access_key_id": "ASIAIOSFODNN7EXAMPLE",
    "secret_access_key": "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY",
    "token": "IQoJb3JpZ2luX2VjEExampleToken==",
}


class TestKmstoolArgumentValidation(unittest.TestCase):
    """Caller-supplied values become `kmstool_enclave_cli` arguments.

    The tool parses anything starting with "-" as a flag, so an unvalidated value could
    redirect the call — for example at a different `--proxy-port` or `--region`.
    """

    _UNSET = object()

    def _decrypt(self, credential=_UNSET, ciphertext="Q2lwaGVydGV4dA==", region="us-east-1"):
        if credential is self._UNSET:
            credential = CREDENTIAL
        with patch.object(server, "_run_kmstool", return_value="PLAINTEXT: a2V5") as run:
            server.kms_decrypt(credential, ciphertext, region)
        return run.call_args[0][0]

    def test_a_well_formed_call_is_passed_through(self):
        args = self._decrypt()
        self.assertEqual(args[0], "/app/kmstool_enclave_cli")
        self.assertIn("--ciphertext", args)
        self.assertIn(CREDENTIAL["token"], args)

    def test_region_cannot_be_turned_into_a_flag(self):
        # "--proxy-port" appears later in the list; a dash-leading region would let the
        # caller inject an earlier occurrence and win the argument parse.
        for region in ("--proxy-port", "-r", "us-east-1 --proxy-port=9999"):
            with self.subTest(region=region):
                with self.assertRaises(ValueError) as ctx:
                    self._decrypt(region=region)
                self.assertIn("region", str(ctx.exception))

    def test_ciphertext_charset_is_enforced(self):
        for ciphertext in ("--key-id", "not base64!", "a b", ""):
            with self.subTest(ciphertext=ciphertext):
                with self.assertRaises(ValueError):
                    self._decrypt(ciphertext=ciphertext)

    def test_a_trailing_newline_is_rejected(self):
        """`$` matches before a trailing newline, so the patterns must anchor with `\\Z`.

        A value is not required to be newline-free by the charset alone: "us-east-1\\n"
        satisfies a `$`-anchored pattern but is not the region the operator configured.
        """
        with self.assertRaises(ValueError):
            self._decrypt(region="us-east-1\n")
        with self.assertRaises(ValueError):
            self._decrypt(ciphertext="Q2lwaGVy\n")

    def test_non_string_values_are_rejected(self):
        for ciphertext in (None, 42, {"a": 1}, ["a"]):
            with self.subTest(ciphertext=ciphertext):
                with self.assertRaises(ValueError):
                    self._decrypt(ciphertext=ciphertext)

    def test_each_credential_field_is_required(self):
        for field in CREDENTIAL:
            with self.subTest(field=field):
                partial = {k: v for k, v in CREDENTIAL.items() if k != field}
                with self.assertRaises(ValueError) as ctx:
                    self._decrypt(credential=partial)
                self.assertIn(field, str(ctx.exception))

    def test_non_dict_credential_is_rejected(self):
        # `main` forwards whatever was in the payload, including None.
        for credential in (None, "creds", ["a"]):
            with self.subTest(credential=credential):
                with self.assertRaises(ValueError):
                    self._decrypt(credential=credential)

    def test_credential_fields_cannot_be_turned_into_flags(self):
        for field in CREDENTIAL:
            with self.subTest(field=field):
                hostile = dict(CREDENTIAL, **{field: "--proxy-port"})
                with self.assertRaises(ValueError):
                    self._decrypt(credential=hostile)

    def test_key_id_charset_is_enforced(self):
        for key_id in ("--region", "", "key id with spaces", "key\nid"):
            with self.subTest(key_id=key_id):
                with patch.object(server, "_run_kmstool"):
                    with self.assertRaises(ValueError):
                        server.kms_generate_random(CREDENTIAL, key_id, "us-east-1")

    def test_key_arn_is_accepted(self):
        arn = "arn:aws:kms:us-east-1:123456789012:key/abcd-1234"
        with patch.object(
            server, "_run_kmstool", return_value="PLAINTEXT: a2V5\nCIPHERTEXT: Yw=="
        ) as run:
            server.kms_generate_random(CREDENTIAL, arn, "us-east-1")
        self.assertIn(arn, run.call_args[0][0])


class TestDecryptOutputParsing(unittest.TestCase):
    def test_plaintext_is_extracted(self):
        with patch.object(server, "_run_kmstool", return_value="PLAINTEXT: a2V5\n"):
            self.assertEqual(server.kms_decrypt(CREDENTIAL, "Yw==", "us-east-1"), "a2V5")

    def test_the_whole_remainder_is_returned_not_the_first_colon_field(self):
        """The old parser was `split(":")[1]`, which truncates at any later colon.

        Base64 never contains a colon, so this cannot happen with a well-behaved tool —
        but truncating a key rather than failing is the worst available outcome, since it
        yields a valid-looking signature under the wrong key.
        """
        with patch.object(server, "_run_kmstool", return_value="PLAINTEXT: a2V5:extra"):
            self.assertEqual(server.kms_decrypt(CREDENTIAL, "Yw==", "us-east-1"), "a2V5:extra")

    def test_unexpected_output_is_not_treated_as_a_key(self):
        """The old parser split on ":" and returned field 1 of whatever it got.

        An error line would yield a fragment that is not a key, and signing would proceed
        with it rather than failing.
        """
        for output in ("ERROR: something failed", "", "a2V5", "CIPHERTEXT: Yw=="):
            with self.subTest(output=output):
                with patch.object(server, "_run_kmstool", return_value=output):
                    with self.assertRaises(Exception) as ctx:
                        server.kms_decrypt(CREDENTIAL, "Yw==", "us-east-1")
                    self.assertIn("Unexpected decrypt output", str(ctx.exception))


class TestRunKmstool(unittest.TestCase):
    def _proc(self, returncode=0, stdout=b"PLAINTEXT: a2V5", stderr=b"", timeout=False):
        proc = MagicMock()
        proc.returncode = returncode
        if timeout:
            proc.communicate.side_effect = [
                server.subprocess.TimeoutExpired(cmd="kmstool", timeout=1),
                (stdout, stderr),
            ]
        else:
            proc.communicate.return_value = (stdout, stderr)
        return proc

    def test_a_timeout_is_bounded_and_the_process_killed(self):
        """A wedged KMS call would otherwise block the accept loop forever."""
        proc = self._proc(timeout=True)
        with patch.object(server.subprocess, "Popen", return_value=proc):
            with self.assertRaises(Exception) as ctx:
                server._run_kmstool(["/app/kmstool_enclave_cli"], "decrypt")
        self.assertIn("timed out", str(ctx.exception))
        proc.kill.assert_called_once()

    def test_a_timeout_is_actually_passed_to_communicate(self):
        proc = self._proc()
        with patch.object(server.subprocess, "Popen", return_value=proc):
            server._run_kmstool(["/app/kmstool_enclave_cli"], "decrypt")
        self.assertEqual(
            proc.communicate.call_args.kwargs["timeout"], server.KMSTOOL_TIMEOUT_SECONDS
        )

    def test_no_shell_is_used(self):
        proc = self._proc()
        with patch.object(server.subprocess, "Popen", return_value=proc) as popen:
            server._run_kmstool(["/app/kmstool_enclave_cli", "decrypt"], "decrypt")
        self.assertNotIn("shell", popen.call_args.kwargs)
        self.assertIsInstance(popen.call_args[0][0], list)

    def test_nonzero_exit_raises(self):
        proc = self._proc(returncode=1, stderr=b"access denied")
        with patch.object(server.subprocess, "Popen", return_value=proc):
            with self.assertRaises(Exception) as ctx:
                server._run_kmstool(["/app/kmstool_enclave_cli"], "genkey")
        self.assertIn("access denied", str(ctx.exception))


class TestGenerateKeyValidation(unittest.TestCase):
    """A key outside the curve order must be rejected, not used."""

    ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

    def _generate(self, key_int):
        key_bytes = key_int.to_bytes(32, "big")
        plaintext = base64.standard_b64encode(key_bytes).decode()
        with patch.object(
            server, "kms_generate_random", return_value=(plaintext, "ciphertext-b64")
        ):
            return server.generate_key(CREDENTIAL, "key-id")

    def test_zero_key_is_rejected(self):
        with self.assertRaises(Exception) as ctx:
            self._generate(0)
        self.assertIn("outside valid range", str(ctx.exception))

    def test_key_at_the_curve_order_is_rejected(self):
        with self.assertRaises(Exception) as ctx:
            self._generate(self.ORDER)
        self.assertIn("outside valid range", str(ctx.exception))

    def test_key_above_the_curve_order_is_rejected(self):
        with self.assertRaises(Exception):
            self._generate(self.ORDER + 1)

    def test_valid_key_yields_an_address_and_ciphertext(self):
        result = self._generate(1)
        self.assertEqual(result["encrypted_key"], "ciphertext-b64")
        self.assertTrue(result["address"].startswith("0x"))
        self.assertEqual(len(result["address"]), 42)

    def test_plaintext_key_is_not_returned(self):
        """The whole point of generating in-enclave: plaintext must not leave."""
        result = self._generate(1)
        self.assertEqual(set(result), {"address", "encrypted_key"})

    def test_key_just_below_the_curve_order_is_accepted(self):
        result = self._generate(self.ORDER - 1)
        self.assertTrue(result["address"].startswith("0x"))


class TestSignHash(unittest.TestCase):
    def test_produces_a_recoverable_signature(self):
        from eth_keys import keys as eth_keys

        key_bytes = b"\x02" * 32
        hash_hex = "0x" + "aa" * 32
        signature = server.sign_hash(key_bytes, hash_hex)

        recovered = eth_keys.Signature(
            vrs=(signature["v"] - 27, int(signature["r"], 16), int(signature["s"], 16))
        ).recover_public_key_from_msg_hash(bytes.fromhex("aa" * 32))

        expected = eth_keys.PrivateKey(key_bytes).public_key.to_checksum_address()
        self.assertEqual(recovered.to_checksum_address(), expected)

    def test_accepts_a_hash_without_the_0x_prefix(self):
        with_prefix = server.sign_hash(b"\x02" * 32, "0x" + "aa" * 32)
        without_prefix = server.sign_hash(b"\x02" * 32, "aa" * 32)
        self.assertEqual(with_prefix, without_prefix)

    def test_r_and_s_are_zero_padded_to_32_bytes(self):
        """An unpadded value parses as the right integer but is the wrong length on wire.

        This vector is chosen because its `s` has a leading zero byte, so unpadded
        formatting would produce 63 hex chars instead of 64. A vector whose components
        both happen to be full length would not detect missing padding at all.
        """
        signature = server.sign_hash((12).to_bytes(32, "big"), "0x" + f"{12:064x}")
        self.assertEqual(len(signature["s"]), 66, signature["s"])
        self.assertEqual(len(signature["r"]), 66, signature["r"])
        self.assertTrue(signature["s"].startswith("0x0"))

    def test_v_is_in_ethereum_form(self):
        signature = server.sign_hash(b"\x02" * 32, "0x" + "aa" * 32)
        self.assertIn(signature["v"], (27, 28))

    def test_signing_is_deterministic(self):
        """RFC 6979. This is why replaying an identical request is harmless."""
        first = server.sign_hash(b"\x02" * 32, "0x" + "aa" * 32)
        second = server.sign_hash(b"\x02" * 32, "0x" + "aa" * 32)
        self.assertEqual(first, second)

    def test_non_hex_hash_raises(self):
        with self.assertRaises(ValueError):
            server.sign_hash(b"\x02" * 32, "0x" + "zz" * 32)

    def test_wrong_length_hash_raises(self):
        """`eth_keys.sign_msg_hash` happily signs any length, so this must be checked.

        The parent validates too, but the enclave does not trust the parent.
        """
        for byte_count in (0, 16, 31, 33, 64):
            with self.subTest(byte_count=byte_count):
                with self.assertRaises(ValueError) as ctx:
                    server.sign_hash(b"\x02" * 32, "0x" + "aa" * byte_count)
                self.assertIn("exactly 32 bytes", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()


class TestDispatch(unittest.TestCase):
    def test_ping_touches_no_kms_and_needs_no_credential(self):
        with (
            patch.object(server, "kms_decrypt") as decrypt,
            patch.object(server, "generate_key") as gen,
        ):
            self.assertEqual(server._dispatch({"operation": "ping"}), {"status": "ok"})
        decrypt.assert_not_called()
        gen.assert_not_called()

    def test_unknown_operation_is_refused_before_any_decrypt(self):
        with patch.object(server, "kms_decrypt") as decrypt:
            resp = server._dispatch(
                {"operation": "bogus", "credential": {}, "encrypted_key": "x", "region": "r"}
            )
        self.assertEqual(resp, {"error": "Unknown operation: bogus"})
        decrypt.assert_not_called()

    def test_sign_transaction_no_longer_exists(self):
        # M37: the enclave must not build or sign transactions (value-as-ether, bypassing
        # the nonce authority). No default operation either.
        with patch.object(server, "kms_decrypt") as decrypt:
            gone = server._dispatch({"operation": "sign_transaction", "transaction_payload": {}})
            no_default = server._dispatch({"transaction_payload": {}})
        self.assertEqual(gone, {"error": "Unknown operation: sign_transaction"})
        self.assertEqual(no_default, {"error": "Unknown operation: None"})
        decrypt.assert_not_called()
        self.assertFalse(hasattr(server, "sign_transaction"))

    def test_exception_text_does_not_cross_the_vsock(self):
        # M34: only the operation and exception class are relayed, never the message.
        secret = "PLAINTEXT-KEY-MATERIAL-0xdeadbeef"
        with patch.object(server, "kms_decrypt", side_effect=RuntimeError(secret)):
            resp = server._dispatch(
                {
                    "operation": "sign_hash",
                    "hash": "00" * 32,
                    "credential": {},
                    "encrypted_key": "x",
                    "region": "r",
                }
            )
        self.assertEqual(resp, {"error": "sign_hash failed: RuntimeError"})
        self.assertNotIn(secret, json.dumps(resp))

    def test_missing_encrypted_key_becomes_error_response_not_exception(self):
        # Nothing may propagate out of dispatch: the accept loop must survive.
        resp = server._dispatch({"operation": "sign_hash", "hash": "00" * 32})
        self.assertIn("error", resp)
