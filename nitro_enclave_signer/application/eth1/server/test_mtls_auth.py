#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0
"""Tests for the signing service's mutual-TLS caller authorization.

Chain validation is the TLS layer's job and is not re-tested here. What is tested is the
authorization decision made over an already-verified peer certificate, and that the
listener context is built so that TLS actually performs that verification — a context
built with the wrong `verify_mode` would let any client through with the allowlist never
seeing a certificate at all.
"""

import ssl
import unittest
from unittest.mock import patch

import mtls_auth
from mtls_auth import MtlsConfigError

ALLOWED = ("tx-broadcast-lambda", "tx-watcher")


def _cert(common_name=None, dns_sans=()):
    """Build a `getpeercert()`-shaped dict."""
    cert = {}
    if common_name is not None:
        cert["subject"] = ((("commonName", common_name),),)
    if dns_sans:
        cert["subjectAltName"] = tuple(("DNS", name) for name in dns_sans)
    return cert


class TestPeerIdentities(unittest.TestCase):
    def test_collects_common_name(self):
        self.assertEqual(mtls_auth.peer_identities(_cert("client-a")), {"client-a"})

    def test_collects_dns_sans(self):
        cert = _cert(dns_sans=("a.example.com", "b.example.com"))
        self.assertEqual(mtls_auth.peer_identities(cert), {"a.example.com", "b.example.com"})

    def test_unions_cn_and_sans(self):
        cert = _cert("client-a", dns_sans=("a.example.com",))
        self.assertEqual(mtls_auth.peer_identities(cert), {"client-a", "a.example.com"})

    def test_ignores_non_dns_sans(self):
        # An IP or email SAN must not be usable as an allowlist identity.
        cert = {"subjectAltName": (("IP Address", "10.0.0.5"), ("email", "a@b.c"))}
        self.assertEqual(mtls_auth.peer_identities(cert), set())

    def test_ignores_other_subject_attributes(self):
        cert = {"subject": ((("organizationName", "tx-broadcast-lambda"),),)}
        self.assertEqual(mtls_auth.peer_identities(cert), set())

    def test_empty_certificate_asserts_nothing(self):
        self.assertEqual(mtls_auth.peer_identities({}), set())


class TestAuthenticate(unittest.TestCase):
    def test_allows_a_listed_common_name(self):
        self.assertEqual(
            mtls_auth.authenticate(_cert("tx-broadcast-lambda"), ALLOWED),
            "tx-broadcast-lambda",
        )

    def test_allows_a_listed_dns_san(self):
        cert = _cert("some-cn", dns_sans=("tx-watcher",))
        self.assertEqual(mtls_auth.authenticate(cert, ALLOWED), "tx-watcher")

    def test_rejects_an_unlisted_identity(self):
        with self.assertRaises(PermissionError) as ctx:
            mtls_auth.authenticate(_cert("attacker"), ALLOWED)
        self.assertIn("not authorized", str(ctx.exception))

    def test_rejects_a_missing_certificate(self):
        for peer_cert in (None, {}):
            with self.subTest(peer_cert=peer_cert):
                with self.assertRaises(PermissionError) as ctx:
                    mtls_auth.authenticate(peer_cert, ALLOWED)
                self.assertIn("No client certificate", str(ctx.exception))

    def test_empty_allowlist_fails_closed(self):
        """A missing allowlist is a misconfiguration, never 'permit all'."""
        with self.assertRaises(MtlsConfigError):
            mtls_auth.authenticate(_cert("tx-broadcast-lambda"), ())

    def test_empty_allowlist_is_checked_before_the_certificate(self):
        # Otherwise a missing allowlist would surface as a client error and be
        # misdiagnosed as the caller's problem.
        with self.assertRaises(MtlsConfigError):
            mtls_auth.authenticate(None, ())

    def test_match_is_exact_not_prefix(self):
        with self.assertRaises(PermissionError):
            mtls_auth.authenticate(_cert("tx-broadcast-lambda-evil"), ALLOWED)

    def test_match_is_case_sensitive(self):
        # CN comparison is byte-exact; an operator writing the wrong case should find out
        # at deploy time rather than get a looser match than they wrote.
        with self.assertRaises(PermissionError):
            mtls_auth.authenticate(_cert("TX-Broadcast-Lambda"), ALLOWED)


class TestBuildClientVerifyingContext(unittest.TestCase):
    """The context must actually require client certificates."""

    SERVER_CERT = "/etc/pki/tls/certs/localhost.crt"
    CLIENT_CA = "/etc/pki/tls/certs/client-ca.crt"

    def _context(self, **kwargs):
        # Real cert loading needs real files; the properties under test are the flags set
        # around it, so only the loaders are stubbed.
        with (
            patch.object(ssl.SSLContext, "load_cert_chain"),
            patch.object(ssl.SSLContext, "load_verify_locations") as load_verify,
            patch.object(ssl.SSLContext, "load_default_certs") as load_default,
        ):
            context = mtls_auth.build_client_verifying_context(
                self.SERVER_CERT, self.CLIENT_CA, **kwargs
            )
        return context, load_verify, load_default

    def test_requires_a_client_certificate(self):
        context, _, _ = self._context()
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)

    def test_requires_tls_1_2_minimum(self):
        context, _, _ = self._context()
        self.assertEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)

    def test_loads_only_the_configured_ca(self):
        """The system store must not be loaded, or a public CA could mint a client."""
        _, load_verify, load_default = self._context()
        load_verify.assert_called_once_with(cafile=self.CLIENT_CA)
        load_default.assert_not_called()

    def test_crl_checking_is_off_unless_a_crl_is_supplied(self):
        context, _, _ = self._context()
        self.assertFalse(context.verify_flags & ssl.VERIFY_CRL_CHECK_CHAIN)

    def test_crl_enables_chain_checking(self):
        context, load_verify, load_default = self._context(crl_path="/etc/pki/tls/crl/clients.crl")
        self.assertTrue(context.verify_flags & ssl.VERIFY_CRL_CHECK_CHAIN)
        self.assertEqual(load_verify.call_count, 2)
        load_default.assert_not_called()

    def test_missing_ca_path_is_a_config_error(self):
        with self.assertRaises(MtlsConfigError) as ctx:
            mtls_auth.build_client_verifying_context(self.SERVER_CERT, "")
        self.assertIn("NITRO_CLIENT_CA_PATH", str(ctx.exception))

    def test_unreadable_ca_bundle_is_a_config_error(self):
        with (
            patch.object(ssl.SSLContext, "load_cert_chain"),
            patch.object(
                ssl.SSLContext, "load_verify_locations", side_effect=OSError("no such file")
            ),
        ):
            with self.assertRaises(MtlsConfigError) as ctx:
                mtls_auth.build_client_verifying_context(self.SERVER_CERT, self.CLIENT_CA)
        self.assertIn("client CA bundle", str(ctx.exception))

    def test_unreadable_crl_is_a_config_error(self):
        # Silently continuing without the CRL would leave revoked clients accepted.
        calls = []

        def _load(cafile=None, **kwargs):
            calls.append(cafile)
            if len(calls) == 2:
                raise OSError("no such file")

        with (
            patch.object(ssl.SSLContext, "load_cert_chain"),
            patch.object(ssl.SSLContext, "load_verify_locations", side_effect=_load),
        ):
            with self.assertRaises(MtlsConfigError) as ctx:
                mtls_auth.build_client_verifying_context(
                    self.SERVER_CERT, self.CLIENT_CA, "/missing.crl"
                )
        self.assertIn("CRL", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
