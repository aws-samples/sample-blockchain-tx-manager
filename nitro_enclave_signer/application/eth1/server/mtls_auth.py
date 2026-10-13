#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0
"""Mutual-TLS caller authentication for the parent signing service.

An alternative to `sigv4_auth` for deployments that already operate a private CA. It is
the cheaper of the two at request time — no STS round trip — and it authenticates the
transport rather than the payload, so there is nothing to bind and nothing to replay.

The division of labour matters. The TLS layer does the verification: `CERT_REQUIRED`
plus the configured CA bundle means a connection cannot reach the handler at all unless
the client presented a certificate that chains to that CA. This module only reads the
already-verified peer certificate and decides whether that identity is allowed to sign.
It performs no signature or chain checking of its own, because by the time it runs those
questions are settled.

Certificate issuance and revocation are the operator's responsibility. Python's `ssl`
module does not check CRLs or OCSP by default; a deployment that needs revocation to
take effect should either enable `VERIFY_CRL_CHECK_CHAIN` with a maintained CRL (see
`build_client_verifying_context`) or issue short-lived certificates.
"""

import hmac
import ssl


class MtlsConfigError(Exception):
    """The mTLS mode was selected but cannot be configured safely."""


def _common_names(peer_cert):
    """Return every CN in the peer certificate's subject."""
    names = set()
    for rdn in peer_cert.get("subject", ()):
        for attribute, value in rdn:
            if attribute == "commonName" and value:
                names.add(value)
    return names


def _dns_sans(peer_cert):
    """Return every DNS subjectAltName in the peer certificate."""
    return {
        value
        for san_type, value in peer_cert.get("subjectAltName", ())
        if san_type == "DNS" and value
    }


def peer_identities(peer_cert):
    """Return the identifiers a peer certificate asserts.

    Both CN and DNS SANs are collected so an allowlist can be written against whichever
    field the operator's CA populates. Callers must not treat these as verified beyond
    what TLS already established: they are only meaningful because the chain validated.

    Args:
        peer_cert: The dict returned by `SSLSocket.getpeercert()`.

    Returns:
        Set of asserted identity strings.
    """
    return _common_names(peer_cert) | _dns_sans(peer_cert)


def authenticate(peer_cert, allowed_clients):
    """Authorize an already-TLS-verified peer against an allowlist.

    Args:
        peer_cert: The dict returned by `SSLSocket.getpeercert()`, or None/empty when no
            client certificate was presented.
        allowed_clients: Non-empty collection of permitted CN or DNS SAN values.

    Returns:
        The matched client identity.

    Raises:
        MtlsConfigError: No allowlist is configured, so nothing can be authorized.
        PermissionError: No certificate was presented, or none of the identities it
            asserts appears in the allowlist.
    """
    if not allowed_clients:
        raise MtlsConfigError("mTLS mode requires NITRO_ALLOWED_CLIENTS; refusing all requests")

    if not peer_cert:
        # Unreachable while the listener uses CERT_REQUIRED, but checked anyway so this
        # function is safe to call from any context.
        raise PermissionError("No client certificate presented")

    identities = peer_identities(peer_cert)
    for allowed in allowed_clients:
        for identity in identities:
            if hmac.compare_digest(identity, allowed):
                return identity

    raise PermissionError("Client certificate identity is not authorized to sign")


def build_client_verifying_context(server_cert_path, client_ca_path, crl_path=None):
    """Build a TLS context that requires and verifies client certificates.

    Args:
        server_cert_path: PEM file holding the server certificate and its private key.
        client_ca_path: PEM bundle of CA certificates that may issue client
            certificates. Only these are trusted; the system store is not loaded, so an
            unrelated public CA cannot mint a client identity.
        crl_path: Optional PEM/DER certificate revocation list. When supplied, the whole
            chain is checked against it and a revoked client is rejected at handshake.

    Returns:
        A configured `ssl.SSLContext` for `wrap_socket(server_side=True)`.

    Raises:
        MtlsConfigError: The CA bundle is missing or unreadable.
    """
    if not client_ca_path:
        raise MtlsConfigError("mTLS mode requires NITRO_CLIENT_CA_PATH")

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_ciphers("ECDHE+AESGCM:DHE+AESGCM:ECDHE+CHACHA20:DHE+CHACHA20")
    context.load_cert_chain(certfile=server_cert_path)

    try:
        context.load_verify_locations(cafile=client_ca_path)
    except OSError as exc:
        raise MtlsConfigError(f"Could not load client CA bundle '{client_ca_path}': {exc}")

    context.verify_mode = ssl.CERT_REQUIRED

    if crl_path:
        try:
            context.load_verify_locations(cafile=crl_path)
        except OSError as exc:
            raise MtlsConfigError(f"Could not load CRL '{crl_path}': {exc}")
        context.verify_flags |= ssl.VERIFY_CRL_CHECK_CHAIN

    return context
