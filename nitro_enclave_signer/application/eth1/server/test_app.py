#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0
"""Tests for the signing service's request handling.

Covers the paths an unauthenticated client can reach: body framing, the enclave read
loop, and the startup configuration check. Each of these was previously a way to make the
service hang, crash, or answer 200 with garbage.

`boto3` is stubbed before import because the module builds a Secrets Manager client at
import time and these tests never reach it.
"""

import io
import json
import os
import socket
import sys
import unittest
import unittest.mock
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.modules.setdefault("boto3", MagicMock())

import app  # noqa: E402


class _FakeHandler(app.S):
    """An `S` instance with the socket layers replaced by in-memory buffers.

    `BaseHTTPRequestHandler.__init__` reads and dispatches a request, so it is bypassed;
    the fields the methods under test touch are set directly.
    """

    def __init__(self, body=b"", headers=None, path="/sign_hash"):
        self.rfile = io.BytesIO(body)
        self.wfile = io.BytesIO()
        self.headers = headers if headers is not None else {}
        self.path = path
        self.requestline = f"POST {path} HTTP/1.1"
        self.request_version = "HTTP/1.1"
        self.command = "POST"
        self.client_address = ("10.0.0.1", 40000)
        self.responses_sent = []

    def _send_json_response(self, data, http_status=200):
        self.responses_sent.append((http_status, data))

    def address_string(self):
        return "10.0.0.1"


class TestReadBody(unittest.TestCase):
    """Body framing. A client must not be able to stall or overrun a worker."""

    def test_reads_a_well_formed_body(self):
        body = b'{"hash":"0x01"}'
        handler = _FakeHandler(body, {"Content-Length": str(len(body))})
        self.assertEqual(handler._read_body(), body)
        self.assertEqual(handler.responses_sent, [])

    def test_missing_content_length_is_411(self):
        # Without this the old code raised KeyError inside the handler.
        handler = _FakeHandler(b"{}", {})
        self.assertIsNone(handler._read_body())
        self.assertEqual(handler.responses_sent[0][0], 411)

    def test_non_integer_content_length_is_400(self):
        # `int("abc")` used to propagate as an unhandled ValueError.
        handler = _FakeHandler(b"{}", {"Content-Length": "abc"})
        self.assertIsNone(handler._read_body())
        self.assertEqual(handler.responses_sent[0][0], 400)

    def test_negative_content_length_is_400(self):
        # A negative length makes `rfile.read(-1)` read until EOF, ignoring the cap.
        handler = _FakeHandler(b"{}", {"Content-Length": "-1"})
        self.assertIsNone(handler._read_body())
        self.assertEqual(handler.responses_sent[0][0], 400)

    def test_oversize_content_length_is_413_without_reading(self):
        declared = app.MAX_BODY_BYTES + 1
        handler = _FakeHandler(b"", {"Content-Length": str(declared)})
        self.assertIsNone(handler._read_body())
        self.assertEqual(handler.responses_sent[0][0], 413)
        # The cap must be enforced from the header, not after buffering the body.
        self.assertEqual(handler.rfile.tell(), 0)

    def test_body_at_the_cap_is_accepted(self):
        body = b"a" * app.MAX_BODY_BYTES
        handler = _FakeHandler(body, {"Content-Length": str(len(body))})
        self.assertEqual(handler._read_body(), body)

    def test_truncated_body_is_400(self):
        # A client that declares more than it sends must not have the short read acted on.
        handler = _FakeHandler(b"{}", {"Content-Length": "100"})
        self.assertIsNone(handler._read_body())
        self.assertEqual(handler.responses_sent[0][0], 400)
        self.assertIn("truncated", handler.responses_sent[0][1]["error"])

    def test_zero_length_body_is_read_as_empty(self):
        handler = _FakeHandler(b"", {"Content-Length": "0"})
        self.assertEqual(handler._read_body(), b"")


class TestDoPost(unittest.TestCase):
    """Dispatch order: nothing is parsed or routed before the caller is authenticated."""

    def _post(self, body, path="/sign_hash", auth_returns="arn:aws:iam::1:role/R"):
        handler = _FakeHandler(body, {"Content-Length": str(len(body))}, path=path)
        with patch.object(_FakeHandler, "_authenticate", return_value=auth_returns):
            handler.do_POST()
        return handler

    def test_unauthenticated_request_is_not_parsed_or_routed(self):
        handler = _FakeHandler(b'{"hash":"0x01"}', {"Content-Length": "15"})
        with (
            patch.object(_FakeHandler, "_authenticate", return_value=None) as auth,
            patch.object(_FakeHandler, "_handle_sign_hash") as route,
        ):
            handler.do_POST()
        auth.assert_called_once()
        route.assert_not_called()

    def test_authentication_sees_the_raw_body(self):
        """The digest binding is over raw bytes, so auth is handed the body verbatim."""
        body = b'{"hash":"0x01"}'
        handler = _FakeHandler(body, {"Content-Length": str(len(body))})
        with patch.object(_FakeHandler, "_authenticate", return_value="caller") as auth:
            with patch.object(_FakeHandler, "_handle_sign_hash"):
                handler.do_POST()
        self.assertEqual(auth.call_args[0][0], body)

    def test_nothing_parses_the_body_before_authentication(self):
        """The JSON parser must not run on input from an unattributed caller.

        Ordering is the property, not just the outcome: a handler that parses first and
        authenticates second still refuses the request, but has already exposed the parser
        to anything that can reach port 443.
        """
        order = []
        body = b'{"hash":"0x01"}'
        handler = _FakeHandler(body, {"Content-Length": str(len(body))})

        def _auth(_self, _body):
            order.append("authenticate")
            return "caller"

        def _loads(*args, **kwargs):
            order.append("json.loads")
            return {"hash": "0x01"}

        with (
            patch.object(_FakeHandler, "_authenticate", _auth),
            patch.object(app.json, "loads", _loads),
            patch.object(_FakeHandler, "_handle_sign_hash"),
        ):
            handler.do_POST()

        self.assertEqual(order, ["authenticate", "json.loads"])

    def test_malformed_json_is_400(self):
        handler = self._post(b"{not json")
        self.assertEqual(handler.responses_sent[0][0], 400)
        self.assertIn("not valid JSON", handler.responses_sent[0][1]["error"])

    def test_invalid_utf8_is_400(self):
        handler = self._post(b"\xff\xfe")
        self.assertEqual(handler.responses_sent[0][0], 400)

    def test_json_array_is_rejected(self):
        # `payload.get(...)` on a list would be an AttributeError, i.e. a 500.
        handler = self._post(b"[1,2,3]")
        self.assertEqual(handler.responses_sent[0][0], 400)
        self.assertIn("JSON object", handler.responses_sent[0][1]["error"])

    def test_json_scalar_is_rejected(self):
        handler = self._post(b'"just-a-string"')
        self.assertEqual(handler.responses_sent[0][0], 400)

    def test_json_null_is_rejected(self):
        handler = self._post(b"null")
        self.assertEqual(handler.responses_sent[0][0], 400)

    def test_unknown_path_is_404(self):
        handler = self._post(b"{}", path="/etc/passwd")
        self.assertEqual(handler.responses_sent[0][0], 404)


class TestSignHashValidation(unittest.TestCase):
    """The enclave validates nothing beyond hash length, so this is the only check."""

    # A Secrets Manager identifier, not a credential.
    def _sign_hash(self, payload, secret_id="nitro-wallet/test"):  # nosec B107
        handler = _FakeHandler()
        with patch.object(app, "SECRET_ID", secret_id):
            with patch.object(_FakeHandler, "_call_enclave") as call:
                handler._handle_sign_hash(payload)
        return handler, call

    def test_valid_hash_reaches_the_enclave(self):
        handler, call = self._sign_hash({"hash": "0x" + "ab" * 32})
        call.assert_called_once()
        self.assertEqual(handler.responses_sent, [])

    def test_missing_hash_is_400(self):
        handler, call = self._sign_hash({})
        self.assertEqual(handler.responses_sent[0][0], 400)
        call.assert_not_called()

    def test_short_hash_is_400(self):
        handler, call = self._sign_hash({"hash": "0x" + "ab" * 31})
        self.assertEqual(handler.responses_sent[0][0], 400)
        call.assert_not_called()

    def test_non_hex_hash_is_400(self):
        # Length alone is not enough: "zz"*32 is 64 chars and not hex.
        handler, call = self._sign_hash({"hash": "0x" + "zz" * 32})
        self.assertEqual(handler.responses_sent[0][0], 400)
        self.assertIn("hex", handler.responses_sent[0][1]["error"])
        call.assert_not_called()

    def test_unset_secret_id_is_503(self):
        # The empty string is the condition under test, not a credential.
        handler, call = self._sign_hash({"hash": "0x" + "ab" * 32}, secret_id="")  # nosec B106
        self.assertEqual(handler.responses_sent[0][0], 503)
        call.assert_not_called()

    def test_caller_cannot_choose_the_wallet(self):
        """A caller-supplied secret_id must be ignored, not honoured."""
        handler = _FakeHandler()
        with patch.object(app, "SECRET_ID", "nitro-wallet/configured"):
            with patch.object(_FakeHandler, "_call_enclave") as call:
                handler._handle_sign_hash(
                    {"hash": "0x" + "ab" * 32, "secret_id": "nitro-wallet/attacker-choice"}
                )
        self.assertEqual(call.call_args[0][1]["secret_id"], "nitro-wallet/configured")

    def test_sign_transaction_route_is_gone(self):
        # M37: no transaction-building path through the parent; both the legacy `/` and
        # `/sign_transaction` routes are unknown endpoints even for an authenticated caller.
        body = b'{"transaction_payload": {"to": "0x0"}}'
        for path in ("/sign_transaction", "/"):
            handler = _FakeHandler(body, {"Content-Length": str(len(body))}, path=path)
            with (
                patch.object(_FakeHandler, "_authenticate", return_value="caller"),
                patch.object(app, "SECRET_ID", "nitro-wallet/configured"),
                patch.object(_FakeHandler, "_call_enclave") as call,
            ):
                handler.do_POST()
            self.assertEqual(handler.responses_sent[-1][0], 404, path)
            call.assert_not_called()
        self.assertFalse(hasattr(app.S, "_handle_sign_transaction"))


class TestSendToEnclave(unittest.TestCase):
    """A short or stalled enclave read must not be relayed as a successful response."""

    def _socket(self, chunks=(), recv_side_effect=None):
        sock = MagicMock()
        if recv_side_effect is not None:
            sock.recv.side_effect = recv_side_effect
        else:
            sock.recv.side_effect = list(chunks) + [b""]
        return sock

    def _send(self, sock):
        # AF_VSOCK only exists on Linux; the address family is irrelevant to the read loop
        # under test, so it is created here to let the suite run off-instance.
        with patch.object(socket, "AF_VSOCK", 40, create=True):
            with patch("socket.socket", return_value=sock):
                return app._send_to_enclave(16, 5000, {"operation": "sign_hash"})

    def test_reassembles_a_chunked_response(self):
        response = json.dumps({"signature": {"r": "0x1", "s": "0x2", "v": 27}})
        chunks = [response[:10].encode(), response[10:].encode()]
        self.assertEqual(self._send(self._socket(chunks)), response)

    def test_timeout_raises_instead_of_returning_a_partial_body(self):
        """The old loop broke on timeout and returned a partial body with HTTP 200.

        The caller then saw a JSON parse error rather than a retryable timeout.
        """
        sock = self._socket(recv_side_effect=[b'{"signat', socket.timeout()])
        with self.assertRaises(app.EnclaveError) as ctx:
            self._send(sock)
        self.assertIn("did not respond", str(ctx.exception))

    def test_empty_response_raises(self):
        with self.assertRaises(app.EnclaveError) as ctx:
            self._send(self._socket([]))
        self.assertIn("without responding", str(ctx.exception))

    def test_oversize_response_raises(self):
        oversize = [b"a" * 4096] * (app.MAX_BODY_BYTES // 4096 + 2)
        with self.assertRaises(app.EnclaveError) as ctx:
            self._send(self._socket(oversize))
        self.assertIn("maximum size", str(ctx.exception))

    def test_socket_is_closed_on_failure(self):
        sock = self._socket([])
        with self.assertRaises(app.EnclaveError):
            self._send(sock)
        sock.close.assert_called_once()

    def test_a_read_timeout_is_configured(self):
        # Without a timeout, a wedged enclave holds the worker thread forever.
        sock = self._socket([b"{}"])
        self._send(sock)
        sock.settimeout.assert_called_once_with(5)


class TestValidateConfig(unittest.TestCase):
    """Starting unauthenticated is worse than not starting."""

    def _validate(self, **overrides):
        defaults = {
            "AUTH_MODE": "sigv4",
            "ALLOWED_PRINCIPALS": ("arn:aws:iam::1:role/R",),
            "ALLOWED_CLIENTS": (),
            "CLIENT_CA_PATH": "",
            "SECRET_ID": "nitro-wallet/test",
        }
        defaults.update(overrides)
        with patch.multiple(app, **defaults):
            app._validate_config()

    def test_valid_sigv4_config_starts(self):
        self._validate()

    def test_valid_mtls_config_starts(self):
        self._validate(
            AUTH_MODE="mtls",
            CLIENT_CA_PATH="/etc/pki/ca.crt",
            ALLOWED_CLIENTS=("tx-broadcast-lambda",),
        )

    def test_unknown_auth_mode_refuses_to_start(self):
        with self.assertRaises(SystemExit):
            self._validate(AUTH_MODE="basic")

    def test_there_is_no_unauthenticated_mode(self):
        for mode in ("none", "off", "", "disabled"):
            with self.subTest(mode=mode):
                with self.assertRaises(SystemExit):
                    self._validate(AUTH_MODE=mode)

    def test_sigv4_without_an_allowlist_refuses_to_start(self):
        with self.assertRaises(SystemExit) as ctx:
            self._validate(ALLOWED_PRINCIPALS=())
        self.assertIn("NITRO_ALLOWED_PRINCIPALS", str(ctx.exception))

    def test_mtls_without_a_ca_refuses_to_start(self):
        with self.assertRaises(SystemExit) as ctx:
            self._validate(AUTH_MODE="mtls", ALLOWED_CLIENTS=("c",), CLIENT_CA_PATH="")
        self.assertIn("NITRO_CLIENT_CA_PATH", str(ctx.exception))

    def test_mtls_without_an_allowlist_refuses_to_start(self):
        with self.assertRaises(SystemExit) as ctx:
            self._validate(AUTH_MODE="mtls", CLIENT_CA_PATH="/etc/pki/ca.crt")
        self.assertIn("NITRO_ALLOWED_CLIENTS", str(ctx.exception))

    def test_missing_secret_id_warns_but_starts(self):
        # Deferred to request time as a 503: the service is still useful for health
        # checks, and this is an operator error rather than a security hole.
        with self.assertLogs(level="WARNING"):
            # The empty string is the unset case under test, not a credential.
            self._validate(SECRET_ID="")  # nosec B106


class TestBuildSslContext(unittest.TestCase):
    """The listener's TLS context must match the configured auth mode.

    In mTLS mode the context is the only thing that requires a client certificate at all;
    a context built by the sigv4 branch would accept every anonymous client and leave
    `mtls_auth.authenticate` inspecting a peer certificate that is always `None`.
    """

    def test_mtls_mode_builds_a_client_verifying_context(self):
        with patch.multiple(
            app,
            AUTH_MODE="mtls",
            SERVER_CERT_PATH="/etc/pki/server.crt",
            CLIENT_CA_PATH="/etc/pki/ca.crt",
            CLIENT_CRL_PATH="",
        ):
            with patch.object(app.mtls_auth, "build_client_verifying_context") as build:
                self.assertIs(app._build_ssl_context(), build.return_value)
        build.assert_called_once_with("/etc/pki/server.crt", "/etc/pki/ca.crt", None)

    def test_configured_crl_reaches_the_context(self):
        # A CRL that is read but never applied leaves revoked clients accepted.
        with patch.multiple(
            app,
            AUTH_MODE="mtls",
            SERVER_CERT_PATH="/etc/pki/server.crt",
            CLIENT_CA_PATH="/etc/pki/ca.crt",
            CLIENT_CRL_PATH="/etc/pki/clients.crl",
        ):
            with patch.object(app.mtls_auth, "build_client_verifying_context") as build:
                app._build_ssl_context()
        build.assert_called_once_with(
            "/etc/pki/server.crt", "/etc/pki/ca.crt", "/etc/pki/clients.crl"
        )

    def test_sigv4_mode_does_not_request_a_client_certificate(self):
        with patch.multiple(app, AUTH_MODE="sigv4", SERVER_CERT_PATH="/etc/pki/server.crt"):
            with patch.object(app.mtls_auth, "build_client_verifying_context") as build:
                with patch.object(app.ssl, "SSLContext") as ssl_context_cls:
                    context = app._build_ssl_context()

        build.assert_not_called()
        self.assertIs(context, ssl_context_cls.return_value)
        self.assertEqual(context.minimum_version, app.ssl.TLSVersion.TLSv1_2)
        context.load_cert_chain.assert_called_once_with(certfile="/etc/pki/server.crt")


class TestHealthEndpoint(unittest.TestCase):
    def test_health_is_unauthenticated_and_pings_enclave_without_keys(self):
        handler = _FakeHandler(path="/health")
        with (
            patch.object(app, "ping_enclave", return_value={"status": "ok"}) as ping,
            patch.object(app, "call_enclave") as call,
            patch.object(app, "get_encrypted_key") as get_key,
        ):
            handler.do_GET()
        status, body = handler.responses_sent[0][0], handler.responses_sent[0][1]
        self.assertEqual(status, 200)
        self.assertEqual(body["enclave"], "ok")
        ping.assert_called_once_with(app.ENCLAVE_CID, app.ENCLAVE_PORT)
        # The health path must never touch the signing path or any secret.
        call.assert_not_called()
        get_key.assert_not_called()

    def test_health_is_503_when_enclave_is_unreachable(self):
        handler = _FakeHandler(path="/health")
        with patch.object(app, "ping_enclave", side_effect=app.EnclaveError("no enclave")):
            handler.do_GET()
        self.assertEqual(handler.responses_sent[0][0], 503)
        self.assertEqual(handler.responses_sent[0][1]["status"], "unhealthy")

    def test_health_is_503_when_enclave_answers_with_error(self):
        handler = _FakeHandler(path="/health")
        with patch.object(app, "ping_enclave", return_value={"error": "boom"}):
            handler.do_GET()
        self.assertEqual(handler.responses_sent[0][0], 503)

    def test_ping_payload_carries_no_credential_or_key(self):
        # _send_to_enclave returns the raw response TEXT (as in production); ping_enclave
        # must parse it. A prior version assumed a dict and crashed the health endpoint.
        with patch.object(app, "_send_to_enclave", return_value='{"status": "ok"}') as send:
            result = app.ping_enclave(16, 5000)
        send.assert_called_once_with(16, 5000, {"operation": "ping"})
        self.assertEqual(result, {"status": "ok"})

    def test_ping_rejects_non_json_and_non_object_responses(self):
        with patch.object(app, "_send_to_enclave", return_value="not json"):
            with self.assertRaises(app.EnclaveError):
                app.ping_enclave(16, 5000)
        with patch.object(app, "_send_to_enclave", return_value='"just a string"'):
            with self.assertRaises(app.EnclaveError):
                app.ping_enclave(16, 5000)

    def test_other_get_paths_are_404(self):
        handler = _FakeHandler(path="/sign_hash")
        handler.do_GET()
        self.assertEqual(handler.responses_sent[0][0], 404)


class TestServerHardening(unittest.TestCase):
    def test_version_banner_is_suppressed(self):
        # Do not tell unauthenticated callers the Python and OpenSSL versions.
        self.assertEqual(app.S.sys_version, "")
        self.assertNotIn("Python", app.S.server_version)

    def test_handler_has_a_request_timeout(self):
        self.assertEqual(app.S.timeout, app.REQUEST_TIMEOUT_SECONDS)

    def test_tls_handshake_is_deferred_off_the_accept_loop(self):
        """Handshaking in `accept()` lets one stalled client wedge every request."""
        context = MagicMock()
        server = MagicMock(spec=app.DeferredTlsThreadingHTTPServer)
        server.ssl_context = context
        raw_socket = MagicMock()

        with patch(
            "http.server.ThreadingHTTPServer.get_request",
            return_value=(raw_socket, ("10.0.0.1", 40000)),
        ):
            app.DeferredTlsThreadingHTTPServer.get_request(server)

        raw_socket.settimeout.assert_called_once_with(app.REQUEST_TIMEOUT_SECONDS)
        self.assertIs(context.wrap_socket.call_args.kwargs["do_handshake_on_connect"], False)
        self.assertIs(context.wrap_socket.call_args.kwargs["server_side"], True)

    def test_connection_level_errors_do_not_dump_tracebacks(self):
        server = MagicMock(spec=app.DeferredTlsThreadingHTTPServer)
        for exc in (app.ssl.SSLError("bad handshake"), socket.timeout(), ConnectionResetError()):
            with self.subTest(exc=type(exc).__name__):
                try:
                    raise exc
                except Exception:
                    with self.assertLogs(level="WARNING"):
                        app.DeferredTlsThreadingHTTPServer.handle_error(
                            server, MagicMock(), ("10.0.0.1", 40000)
                        )


class ServerPortTests(unittest.TestCase):
    """run() binds NITRO_SERVER_PORT (default 8443 — unprivileged, for the non-root user)."""

    def _captured_run_port(self):
        bound = {}

        class FakeServer:
            def __init__(self, server_address, handler_class, ssl_context):
                bound["port"] = server_address[1]

            def serve_forever(self):
                raise KeyboardInterrupt

            def server_close(self):
                pass

        with (
            unittest.mock.patch.object(app, "_build_ssl_context", return_value=None),
            unittest.mock.patch.object(app, "_validate_config"),
        ):
            app.run(server_class=FakeServer)
        return bound["port"]

    def test_default_port_is_unprivileged(self):
        with unittest.mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("NITRO_SERVER_PORT", None)
            self.assertEqual(self._captured_run_port(), 8443)

    def test_port_env_override(self):
        with unittest.mock.patch.dict(os.environ, {"NITRO_SERVER_PORT": "9443"}):
            self.assertEqual(self._captured_run_port(), 9443)


class ContainerPackagingTests(unittest.TestCase):
    """The deployed parent image must contain modules imported by app.py."""

    def test_dockerfile_copies_authentication_modules(self):
        dockerfile = Path(__file__).with_name("Dockerfile").read_text()
        self.assertIn("mtls_auth.py", dockerfile)
        self.assertIn("sigv4_auth.py", dockerfile)

    def test_dockerfile_drops_root(self):
        """The signing server must not run as uid 0; user_data chowns the TLS material
        to this exact uid, so the two files must agree on it."""
        dockerfile = Path(__file__).with_name("Dockerfile").read_text()
        self.assertIn("USER 10001:10001", dockerfile)
        user_data = (Path(__file__).parents[1] / "user_data" / "user_data.sh").read_text()
        self.assertIn('chown 10001:10001 "$CERT_DIR/localhost.crt"', user_data)
        # Non-root cannot bind 443 in-container: the run line must publish 443 -> 8443
        # and mount the certs read-only.
        self.assertIn("-p 443:8443", user_data)
        self.assertIn("/etc/pki/tls/certs/:ro", user_data)

    def test_ca_private_key_handling_disables_xtrace(self):
        """CA JSON/key operations stay between xtrace-off and cleanup boundaries."""
        user_data = (Path(__file__).parents[1] / "user_data" / "user_data.sh").read_text()
        sensitive_start = user_data.index("CA_JSON=$(aws secretsmanager")
        sensitive_end = user_data.index("{ set -x; } 2>/dev/null", sensitive_start)
        block = user_data[sensitive_start:sensitive_end]
        trace_off = user_data.rfind("{ set +x; } 2>/dev/null", 0, sensitive_start)

        self.assertGreater(trace_off, user_data.index('if [ -n "$TLS_CA_SECRET_NAME" ]'))
        self.assertIn("unset CA_JSON", block)
        self.assertLess(block.index("unset CA_JSON"), block.index('shred -u "$CERT_DIR/ca.key"'))
        self.assertIn('rm -f "$CERT_DIR/server.csr" "$CERT_DIR/ca.srl"', block)

    def test_dockerignore_allows_only_runtime_files(self):
        rules = Path(__file__).with_name(".dockerignore").read_text().splitlines()
        self.assertEqual(
            rules,
            [
                "*",
                "!Dockerfile",
                "!requirements.txt",
                "!app.py",
                "!mtls_auth.py",
                "!sigv4_auth.py",
            ],
        )


if __name__ == "__main__":
    unittest.main()
