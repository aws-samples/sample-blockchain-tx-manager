#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

import json
import logging
import os
import socket
import ssl
import sys
from http import client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import boto3

import mtls_auth
import sigv4_auth

AWS_REGION = os.getenv("REGION", "us-east-1")

secrets_manager_client = boto3.client(service_name="secretsmanager", region_name=AWS_REGION)

# Which wallet this service is permitted to sign with. The caller does not get to
# choose: a caller-supplied secret id would let any authorized client name any other
# wallet in the nitro-wallet/ namespace, since the instance role can read all of them.
SECRET_ID = os.getenv("SECRET_ID", "").strip()

# "sigv4" (default) verifies the caller's IAM identity via STS; "mtls" requires a client
# certificate issued by NITRO_CLIENT_CA_PATH. There is deliberately no "none".
AUTH_MODE = os.getenv("NITRO_AUTH_MODE", "sigv4").strip().lower()

SERVER_CERT_PATH = os.getenv("NITRO_SERVER_CERT_PATH", "/etc/pki/tls/certs/localhost.crt")
CLIENT_CA_PATH = os.getenv("NITRO_CLIENT_CA_PATH", "").strip()
CLIENT_CRL_PATH = os.getenv("NITRO_CLIENT_CRL_PATH", "").strip()

# A signing request is a small JSON object; the largest legitimate one is a transaction
# payload well under 1 KiB. Anything approaching this cap is malformed or hostile.
MAX_BODY_BYTES = 16 * 1024

# Bounds how long a single client can hold a worker thread while dribbling out a body.
# Without this, `rfile.read(content_length)` blocks indefinitely.
REQUEST_TIMEOUT_SECONDS = 10

ENCLAVE_CID = 16
ENCLAVE_PORT = 5000

ALLOWED_PRINCIPALS = sigv4_auth.load_allowed_principals(os.getenv("NITRO_ALLOWED_PRINCIPALS"))
ALLOWED_CLIENTS = sigv4_auth.load_allowed_principals(os.getenv("NITRO_ALLOWED_CLIENTS"))


class EnclaveError(Exception):
    """The enclave could not be reached, or returned a truncated response."""


class DeferredTlsThreadingHTTPServer(ThreadingHTTPServer):
    """A threaded HTTPS server that performs TLS handshakes in worker threads.

    Wrapping the *listening* socket is the usual shorthand for TLS here, but it makes
    `accept()` complete the handshake — putting it back in the single accept loop, where
    one client that connects and then stalls mid-handshake blocks every other request.
    That is the same wedge threading is meant to prevent, so the handshake is deferred to
    the per-connection worker instead (see `_TlsHandshakeMixin.setup`).
    """

    def __init__(self, server_address, handler_class, ssl_context):
        self.ssl_context = ssl_context
        super().__init__(server_address, handler_class)

    def get_request(self):
        sock, addr = super().get_request()
        sock.settimeout(REQUEST_TIMEOUT_SECONDS)
        return (
            self.ssl_context.wrap_socket(sock, server_side=True, do_handshake_on_connect=False),
            addr,
        )

    def handle_error(self, request, client_address):
        """Log connection-level failures without dumping a traceback per bad client.

        Unauthenticated clients can trigger these at will (failed handshakes, stalled
        bodies), so they are operational noise rather than server faults.
        """
        exc = sys.exc_info()[1]
        if isinstance(exc, (ssl.SSLError, socket.timeout, ConnectionError)):
            logging.warning("Dropped connection from %s: %s", client_address[0], exc)
            return
        super().handle_error(request, client_address)


class _TlsHandshakeMixin:
    """Completes the deferred TLS handshake inside the worker thread."""

    def setup(self):
        # Runs in the worker thread, so a slow or hostile handshake costs one thread
        # instead of the whole accept loop. The socket timeout set in `get_request`
        # bounds it.
        self.request.do_handshake()
        super().setup()


class S(_TlsHandshakeMixin, BaseHTTPRequestHandler):
    # Cap how long a worker waits on a stalled client. BaseHTTPRequestHandler applies
    # this to the connection socket, so it covers both the request line and the body.
    timeout = REQUEST_TIMEOUT_SECONDS

    # Do not advertise the Python and OpenSSL versions to unauthenticated callers.
    server_version = "NitroSigner"
    sys_version = ""

    def _send_json_response(self, data, http_status=200):
        """Send a JSON response with proper Content-Length for TLS compatibility"""
        body = json.dumps(data).encode("utf-8") if isinstance(data, dict) else data.encode("utf-8")
        self.send_response(http_status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()

    def log_message(self, format, *args):
        """Route access logs through logging instead of stderr, without request bodies."""
        logging.info("%s %s", self.address_string(), format % args)

    def do_GET(self):
        """Health check endpoint.

        Left unauthenticated on purpose: the NLB health check cannot present an identity
        proof, and the response discloses nothing but liveness. It pings the enclave over
        vsock with a credential-free `ping` operation so a parent whose enclave has died
        (or is wedged) reports unhealthy and is taken out of the NLB target group; the
        ping cannot reach key material because the enclave answers it before any decrypt.
        """
        if self.path != "/health":
            self._send_json_response({"error": "Not found"}, 404)
            return
        try:
            result = ping_enclave(ENCLAVE_CID, ENCLAVE_PORT)
        except Exception as e:  # noqa: BLE001 - any enclave failure is "unhealthy"
            logging.warning("health: enclave ping failed: %s", e)
            self._send_json_response({"status": "unhealthy", "enclave": "unreachable"}, 503)
            return
        if result.get("status") != "ok":
            logging.warning("health: enclave ping returned %s", result)
            self._send_json_response({"status": "unhealthy", "enclave": "error"}, 503)
            return
        self._send_json_response({"status": "healthy", "enclave": "ok"})

    def _read_body(self):
        """Read and bound the request body.

        Returns:
            Raw body bytes, or None if a response has already been sent.
        """
        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            self._send_json_response({"error": "Content-Length is required"}, 411)
            return None

        try:
            content_length = int(raw_length)
        except ValueError:
            self._send_json_response({"error": "Content-Length is not an integer"}, 400)
            return None

        if content_length < 0:
            self._send_json_response({"error": "Content-Length is negative"}, 400)
            return None

        if content_length > MAX_BODY_BYTES:
            self._send_json_response({"error": f"Request body exceeds {MAX_BODY_BYTES} bytes"}, 413)
            return None

        body = self.rfile.read(content_length)
        if len(body) != content_length:
            # Client disconnected or lied about the length; do not act on a partial body.
            self._send_json_response({"error": "Request body was truncated"}, 400)
            return None
        return body

    def _authenticate(self, body):
        """Attribute the request to an allowed caller.

        Returns:
            The authenticated caller identity, or None if a response has already been
            sent.
        """
        if AUTH_MODE == "mtls":
            try:
                return mtls_auth.authenticate(self.connection.getpeercert(), ALLOWED_CLIENTS)
            except mtls_auth.MtlsConfigError as exc:
                logging.error("mTLS misconfiguration: %s", exc)
                self._send_json_response({"error": "Signing service is misconfigured"}, 503)
                return None
            except PermissionError as exc:
                logging.warning("Rejected signing request: %s", exc)
                self._send_json_response({"error": str(exc)}, 403)
                return None

        try:
            return sigv4_auth.authenticate(self.headers, body, ALLOWED_PRINCIPALS, AWS_REGION)
        except sigv4_auth.AuthError as exc:
            logging.warning("Rejected signing request: %s", exc)
            self._send_json_response({"error": str(exc)}, exc.http_status)
            return None

    def do_POST(self):
        body = self._read_body()
        if body is None:
            return

        # Log path only, not body contents
        logging.info("POST request to %s", str(self.path))

        caller = self._authenticate(body)
        if caller is None:
            return

        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            self._send_json_response({"error": f"Request body is not valid JSON: {exc}"}, 400)
            return

        if not isinstance(payload, dict):
            self._send_json_response({"error": "Request body must be a JSON object"}, 400)
            return

        logging.info("Authenticated %s for %s", caller, self.path)

        # Route based on path
        if self.path == "/sign_hash":
            self._handle_sign_hash(payload)
        elif self.path == "/generate_key":
            self._handle_generate_key(payload)
        else:
            self._send_json_response({"error": "Unknown endpoint"}, 404)

    def _configured_secret_id(self):
        """Return the wallet this service signs with, or None if unconfigured."""
        if not SECRET_ID:
            logging.error("SECRET_ID is not set; refusing to sign")
            self._send_json_response({"error": "Signing service is misconfigured"}, 503)
            return None
        return SECRET_ID

    def _call_enclave(self, operation, enclave_payload):
        """Invoke the enclave and relay its response, mapping failures to 502."""
        try:
            if operation == "generate_key":
                result = call_enclave_generate(ENCLAVE_CID, ENCLAVE_PORT, enclave_payload)
            else:
                result = call_enclave(ENCLAVE_CID, ENCLAVE_PORT, enclave_payload)
        except Exception as e:
            logging.error("%s enclave call failed: %s", operation, e)
            self._send_json_response({"error": f"Enclave communication failed: {e}"}, 502)
            return
        self._send_json_response(result)

    def _handle_sign_hash(self, payload):
        """Handle raw hash signing requests"""
        if not payload.get("hash"):
            self._send_json_response({"error": "Missing 'hash' field"}, 400)
            return

        # Validate hash is 32 bytes (64 hex chars)
        hash_clean = payload["hash"].replace("0x", "")
        if len(hash_clean) != 64:
            self._send_json_response({"error": "Hash must be 32 bytes (64 hex chars)"}, 400)
            return

        try:
            bytes.fromhex(hash_clean)
        except ValueError:
            self._send_json_response({"error": "Hash contains invalid hex characters"}, 400)
            return

        secret_id = self._configured_secret_id()
        if secret_id is None:
            return

        self._call_enclave(
            "sign_hash",
            {"operation": "sign_hash", "hash": payload["hash"], "secret_id": secret_id},
        )

    def _handle_generate_key(self, payload):
        """Handle key generation requests - key is generated inside enclave"""
        key_id = payload.get("key_id")
        if not key_id:
            self._send_json_response({"error": "Missing 'key_id' field"}, 400)
            return

        self._call_enclave("generate_key", {"operation": "generate_key", "key_id": key_id})


def get_encrypted_key(secret_id):
    encrypted_key = secrets_manager_client.get_secret_value(SecretId=secret_id)
    return encrypted_key["SecretString"]


def get_imds_token():
    http_ec2_client = client.HTTPConnection("169.254.169.254", timeout=2)
    try:
        headers = {"X-aws-ec2-metadata-token-ttl-seconds": "21600"}  # Token valid for 6 hours
        http_ec2_client.request("PUT", "/latest/api/token", headers=headers)
        token_response = http_ec2_client.getresponse()
        return token_response.read().decode()
    finally:
        http_ec2_client.close()


def get_aws_session_token():
    http_ec2_client = None
    try:
        token = get_imds_token()

        http_ec2_client = client.HTTPConnection("169.254.169.254", timeout=2)
        headers = {"X-aws-ec2-metadata-token": token}

        # Get instance profile name
        http_ec2_client.request(
            "GET", "/latest/meta-data/iam/security-credentials/", headers=headers
        )
        r = http_ec2_client.getresponse()
        instance_profile_name = r.read().decode()

        # Get credentials
        http_ec2_client.request(
            "GET",
            f"/latest/meta-data/iam/security-credentials/{instance_profile_name}",
            headers=headers,
        )
        r = http_ec2_client.getresponse()
        response = json.loads(r.read())
        return {
            "access_key_id": response["AccessKeyId"],
            "secret_access_key": response["SecretAccessKey"],
            "token": response["Token"],
        }

    except Exception as e:
        raise Exception(f"Failed to retrieve instance credentials: {str(e)}")
    finally:
        if http_ec2_client is not None:
            http_ec2_client.close()


def call_enclave(cid, port, enclave_payload):
    secret_id = enclave_payload["secret_id"]
    encrypted_key = get_encrypted_key(secret_id)

    payload = {
        "credential": get_aws_session_token(),
        "encrypted_key": encrypted_key,
        "operation": enclave_payload["operation"],
        "region": AWS_REGION,
    }

    # Pass operation-specific fields. The enclave signs 32-byte hashes only; there is no
    # transaction-building path (removed: it reinterpreted `value` as ether and bypassed
    # the nonce authority, simulation, and the broadcaster's ecrecover).
    if enclave_payload.get("hash"):
        payload["hash"] = enclave_payload["hash"]

    return _send_to_enclave(cid, port, payload)


def ping_enclave(cid, port):
    """Credential-free liveness probe of the enclave accept loop.

    Returns:
        The enclave's response as a dict. `_send_to_enclave` returns the raw response
        text (signing callers relay it opaquely); the health path is the one caller
        that inspects it, so it parses here.

    Raises:
        EnclaveError: The enclave is unreachable or answered with something other
        than a JSON object.
    """
    raw = _send_to_enclave(cid, port, {"operation": "ping"})
    try:
        result = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise EnclaveError(f"Enclave ping returned non-JSON: {exc}") from exc
    if not isinstance(result, dict):
        raise EnclaveError("Enclave ping returned a non-object response")
    return result


def call_enclave_generate(cid, port, enclave_payload):
    """Call enclave for key generation - no existing secret needed."""
    payload = {
        "credential": get_aws_session_token(),
        "operation": "generate_key",
        "key_id": enclave_payload["key_id"],
        "region": AWS_REGION,
    }

    return _send_to_enclave(cid, port, payload)


def _send_to_enclave(cid, port, payload):
    """Send payload to enclave via vsock and return its complete response.

    A timeout is a failure, not a short read. The previous implementation broke out of
    the receive loop on `socket.timeout` and returned whatever bytes had arrived with a
    200, so the caller got a JSON parse error instead of a retryable timeout.

    Raises:
        EnclaveError: The enclave stalled, closed early, or sent nothing.
    """
    s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    s.settimeout(5)

    try:
        s.connect((cid, port))
        s.sendall(str.encode(json.dumps(payload)))
        s.shutdown(socket.SHUT_WR)

        chunks = []
        total = 0
        while True:
            try:
                chunk = s.recv(4096)
            except socket.timeout:
                raise EnclaveError("Enclave did not respond within 5s")
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_BODY_BYTES:
                raise EnclaveError("Enclave response exceeded the maximum size")
    finally:
        s.close()

    if not chunks:
        raise EnclaveError("Enclave closed the connection without responding")

    return b"".join(chunks).decode()


def _build_ssl_context():
    """Build the listener's TLS context for the configured auth mode.

    Returns:
        A configured `ssl.SSLContext`.

    Raises:
        mtls_auth.MtlsConfigError: mTLS was selected but cannot be configured.
    """
    if AUTH_MODE == "mtls":
        return mtls_auth.build_client_verifying_context(
            SERVER_CERT_PATH, CLIENT_CA_PATH, CLIENT_CRL_PATH or None
        )

    # Use SSLContext with TLS 1.2+ and rustls-compatible ciphers
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
    # Set ciphers compatible with rustls (ECDHE + AES-GCM)
    ssl_context.set_ciphers("ECDHE+AESGCM:DHE+AESGCM:ECDHE+CHACHA20:DHE+CHACHA20")
    ssl_context.load_cert_chain(certfile=SERVER_CERT_PATH)
    return ssl_context


def _validate_config():
    """Fail fast on a configuration that cannot authenticate callers.

    Starting an unauthenticated signing service is worse than not starting at all: it
    would serve signatures over arbitrary hashes to anything that can reach port 443.

    Raises:
        SystemExit: The configuration is unusable.
    """
    if AUTH_MODE not in ("sigv4", "mtls"):
        raise SystemExit(
            f"NITRO_AUTH_MODE must be 'sigv4' or 'mtls', got '{AUTH_MODE}'. "
            "There is no unauthenticated mode."
        )

    if AUTH_MODE == "sigv4" and not ALLOWED_PRINCIPALS:
        raise SystemExit(
            "NITRO_AUTH_MODE=sigv4 requires NITRO_ALLOWED_PRINCIPALS (JSON array or "
            "comma-separated list of IAM role/user ARNs permitted to request signatures)."
        )

    if AUTH_MODE == "mtls":
        if not CLIENT_CA_PATH:
            raise SystemExit("NITRO_AUTH_MODE=mtls requires NITRO_CLIENT_CA_PATH.")
        if not ALLOWED_CLIENTS:
            raise SystemExit(
                "NITRO_AUTH_MODE=mtls requires NITRO_ALLOWED_CLIENTS (comma-separated "
                "client certificate CN or DNS SAN values permitted to request signatures)."
            )

    if not SECRET_ID:
        logging.warning(
            "SECRET_ID is not set; signing requests will be refused with HTTP 503 until it is."
        )


def run(server_class=DeferredTlsThreadingHTTPServer, handler_class=S, port=None):
    if port is None:
        # 8443 by default: the container runs as a non-root user, which cannot bind
        # ports below 1024. dockerd publishes host 443 -> container 8443, so the NLB
        # listener, target group, and security groups are unaffected.
        port = int(os.getenv("NITRO_SERVER_PORT", "8443"))
    logging.basicConfig(level=logging.INFO)
    _validate_config()

    try:
        ssl_context = _build_ssl_context()
    except mtls_auth.MtlsConfigError as exc:
        raise SystemExit(f"Cannot start signing service: {exc}")

    # Binding all interfaces is required: this listens inside a container whose published
    # port the NLB targets, and the container's address is not known ahead of time.
    # Reachability is constrained by the instance security group, and every request is
    # authenticated regardless of which interface it arrives on.
    server_address = ("0.0.0.0", port)  # nosec B104
    httpd = server_class(server_address, handler_class, ssl_context)
    logging.info("Starting httpd with %s authentication...", AUTH_MODE)

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    logging.info("Stopping httpd...\n")


if __name__ == "__main__":
    sys.exit(run())
