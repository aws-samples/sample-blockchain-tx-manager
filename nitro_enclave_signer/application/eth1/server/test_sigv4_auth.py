#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0
"""Tests for the signing service's SigV4 caller authentication.

The property under test is that a captured identity proof cannot be turned into a
signature over a different hash. STS itself is mocked — its job is validating the
signature, which is not this module's responsibility — so these tests cover the checks
that run before and after that call, which are the ones an attacker would try to skip.
"""

import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import sigv4_auth
from sigv4_auth import AuthError

ALLOWED_ROLE = "arn:aws:iam::123456789012:role/TxBroadcastLambdaRole"
STS_ARN = "arn:aws:sts::123456789012:assumed-role/TxBroadcastLambdaRole/session-1"

STS_RESPONSE = (
    '<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">'
    "<GetCallerIdentityResult>"
    "<Arn>{arn}</Arn>"
    "<UserId>AROAEXAMPLE:session-1</UserId>"
    "<Account>123456789012</Account>"
    "</GetCallerIdentityResult>"
    "</GetCallerIdentityResponse>"
)


def _amz_date(offset_seconds=0):
    stamp = datetime.now(timezone.utc) + timedelta(seconds=offset_seconds)
    return stamp.strftime("%Y%m%dT%H%M%SZ")


def _authorization(signed_headers="content-type;host;x-amz-date;x-nitro-request-digest"):
    return (
        "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260729/us-east-1/sts/aws4_request, "
        f"SignedHeaders={signed_headers}, Signature=" + "a" * 64
    )


def _headers(body, **overrides):
    headers = {
        sigv4_auth.AUTHORIZATION_HEADER: _authorization(),
        sigv4_auth.DATE_HEADER: _amz_date(),
        sigv4_auth.DIGEST_HEADER: sigv4_auth.body_digest(body),
        sigv4_auth.TOKEN_HEADER: "session-token",
    }
    headers.update(overrides)
    return {k: v for k, v in headers.items() if v is not None}


class _StsPatch:
    """Patch the STS round trip, returning `arn` (or a given HTTP status)."""

    def __init__(self, arn=STS_ARN, status=200, body=None):
        self.arn = arn
        self.status = status
        self.body = body
        self.request_calls = []

    def __enter__(self):
        response = MagicMock()
        response.status = self.status
        response.read.return_value = (
            self.body if self.body is not None else STS_RESPONSE.format(arn=self.arn).encode()
        )
        connection = MagicMock()
        connection.getresponse.return_value = response
        connection.request.side_effect = lambda *a, **kw: self.request_calls.append((a, kw))

        self._patcher = patch("http.client.HTTPSConnection", return_value=connection)
        self.factory = self._patcher.start()
        return self

    def __exit__(self, *exc_info):
        self._patcher.stop()
        return False


class TestBodyBinding(unittest.TestCase):
    """A proof must only authorize the exact body it was signed over."""

    def test_authenticates_a_well_formed_request(self):
        body = b'{"hash":"0x01"}'
        with _StsPatch():
            arn = sigv4_auth.authenticate(_headers(body), body, (ALLOWED_ROLE,), "us-east-1")
        self.assertEqual(arn, STS_ARN)

    def test_swapped_body_is_rejected(self):
        # The core attack: capture a proof for one hash, replay it with another.
        original = b'{"hash":"0x01"}'
        attacker_body = b'{"hash":"0x02"}'
        with _StsPatch() as sts:
            with self.assertRaises(AuthError) as ctx:
                sigv4_auth.authenticate(
                    _headers(original), attacker_body, (ALLOWED_ROLE,), "us-east-1"
                )
        self.assertIn("does not match the digest", str(ctx.exception))
        # Rejected before spending an STS call.
        self.assertEqual(sts.request_calls, [])

    def test_proof_not_covering_the_digest_is_rejected(self):
        """Dropping the digest from SignedHeaders keeps the signature valid but unbinds it.

        Without this check an attacker signs without the digest header, then supplies any
        digest and body they like — the signature still verifies at STS.
        """
        body = b'{"hash":"0x01"}'
        headers = _headers(
            body,
            **{
                sigv4_auth.AUTHORIZATION_HEADER: _authorization(
                    signed_headers="content-type;host;x-amz-date"
                )
            },
        )
        with _StsPatch() as sts:
            with self.assertRaises(AuthError) as ctx:
                sigv4_auth.authenticate(headers, body, (ALLOWED_ROLE,), "us-east-1")
        self.assertIn("does not cover", str(ctx.exception))
        self.assertEqual(sts.request_calls, [])

    def test_proof_not_covering_host_is_rejected(self):
        body = b'{"hash":"0x01"}'
        headers = _headers(
            body,
            **{
                sigv4_auth.AUTHORIZATION_HEADER: _authorization(
                    signed_headers="content-type;x-amz-date;x-nitro-request-digest"
                )
            },
        )
        with _StsPatch():
            with self.assertRaises(AuthError) as ctx:
                sigv4_auth.authenticate(headers, body, (ALLOWED_ROLE,), "us-east-1")
        self.assertIn("'host'", str(ctx.exception))

    def test_empty_body_still_binds(self):
        body = b""
        with _StsPatch():
            arn = sigv4_auth.authenticate(_headers(body), body, (ALLOWED_ROLE,), "us-east-1")
        self.assertEqual(arn, STS_ARN)


class TestMissingAndMalformedProofs(unittest.TestCase):
    def test_no_headers_at_all_is_401(self):
        with self.assertRaises(AuthError) as ctx:
            sigv4_auth.authenticate({}, b"{}", (ALLOWED_ROLE,), "us-east-1")
        self.assertEqual(ctx.exception.http_status, 401)

    def test_each_required_header_is_individually_required(self):
        body = b"{}"
        for header in (
            sigv4_auth.AUTHORIZATION_HEADER,
            sigv4_auth.DATE_HEADER,
            sigv4_auth.DIGEST_HEADER,
        ):
            with self.subTest(header=header):
                headers = _headers(body, **{header: None})
                with self.assertRaises(AuthError) as ctx:
                    sigv4_auth.authenticate(headers, body, (ALLOWED_ROLE,), "us-east-1")
                self.assertEqual(ctx.exception.http_status, 401)
                self.assertIn(header, str(ctx.exception))

    def test_session_token_is_optional(self):
        """Long-term credentials sign without a session token."""
        body = b"{}"
        headers = _headers(body, **{sigv4_auth.TOKEN_HEADER: None})
        with _StsPatch():
            arn = sigv4_auth.authenticate(headers, body, (ALLOWED_ROLE,), "us-east-1")
        self.assertEqual(arn, STS_ARN)

    def test_authorization_without_signed_headers_is_rejected(self):
        body = b"{}"
        headers = _headers(body, **{sigv4_auth.AUTHORIZATION_HEADER: "AWS4-HMAC-SHA256 junk"})
        with self.assertRaises(AuthError) as ctx:
            sigv4_auth.authenticate(headers, body, (ALLOWED_ROLE,), "us-east-1")
        self.assertIn("SignedHeaders", str(ctx.exception))

    def test_unparseable_date_is_rejected(self):
        body = b"{}"
        headers = _headers(body, **{sigv4_auth.DATE_HEADER: "2026-07-29T00:00:00Z"})
        with self.assertRaises(AuthError) as ctx:
            sigv4_auth.authenticate(headers, body, (ALLOWED_ROLE,), "us-east-1")
        self.assertIn("ISO8601", str(ctx.exception))


class TestFreshness(unittest.TestCase):
    def test_stale_proof_is_rejected(self):
        body = b"{}"
        headers = _headers(body, **{sigv4_auth.DATE_HEADER: _amz_date(offset_seconds=-600)})
        with _StsPatch() as sts:
            with self.assertRaises(AuthError) as ctx:
                sigv4_auth.authenticate(headers, body, (ALLOWED_ROLE,), "us-east-1")
        self.assertIn("freshness window", str(ctx.exception))
        self.assertEqual(sts.request_calls, [])

    def test_future_dated_proof_is_rejected(self):
        # A clock-skewed or hand-crafted future timestamp would otherwise extend the
        # window a captured proof stays usable.
        body = b"{}"
        headers = _headers(body, **{sigv4_auth.DATE_HEADER: _amz_date(offset_seconds=600)})
        with _StsPatch():
            with self.assertRaises(AuthError) as ctx:
                sigv4_auth.authenticate(headers, body, (ALLOWED_ROLE,), "us-east-1")
        self.assertIn("freshness window", str(ctx.exception))

    def test_proof_inside_the_window_is_accepted(self):
        body = b"{}"
        headers = _headers(body, **{sigv4_auth.DATE_HEADER: _amz_date(offset_seconds=-30)})
        with _StsPatch():
            self.assertEqual(
                sigv4_auth.authenticate(headers, body, (ALLOWED_ROLE,), "us-east-1"), STS_ARN
            )


class TestAllowlist(unittest.TestCase):
    def test_empty_allowlist_fails_closed(self):
        """A misconfigured allowlist must never mean 'permit all'."""
        body = b"{}"
        with self.assertRaises(AuthError) as ctx:
            sigv4_auth.authenticate(_headers(body), body, (), "us-east-1")
        self.assertEqual(ctx.exception.http_status, 503)

    def test_principal_not_on_allowlist_is_rejected(self):
        body = b"{}"
        with _StsPatch(arn="arn:aws:sts::123456789012:assumed-role/SomeOtherRole/s"):
            with self.assertRaises(AuthError) as ctx:
                sigv4_auth.authenticate(_headers(body), body, (ALLOWED_ROLE,), "us-east-1")
        self.assertEqual(ctx.exception.http_status, 403)
        self.assertIn("not authorized", str(ctx.exception))

    def test_assumed_role_arn_matches_a_role_arn_entry(self):
        """Operators configure the role; STS reports the session. Both must match."""
        forms = sigv4_auth.canonical_principals(STS_ARN)
        self.assertIn(STS_ARN, forms)
        self.assertIn(ALLOWED_ROLE, forms)

    def test_assumed_role_arn_matches_its_own_form(self):
        body = b"{}"
        with _StsPatch():
            arn = sigv4_auth.authenticate(_headers(body), body, (STS_ARN,), "us-east-1")
        self.assertEqual(arn, STS_ARN)

    def test_iam_user_arn_has_no_derived_form(self):
        user = "arn:aws:iam::123456789012:user/alice"
        self.assertEqual(sigv4_auth.canonical_principals(user), {user})

    def test_role_name_is_not_matched_across_accounts(self):
        # Same role name, different account: must not match.
        other_account = "arn:aws:sts::999999999999:assumed-role/TxBroadcastLambdaRole/s"
        self.assertNotIn(ALLOWED_ROLE, sigv4_auth.canonical_principals(other_account))

    def test_partition_is_preserved(self):
        gov = "arn:aws-us-gov:sts::123456789012:assumed-role/TxBroadcastLambdaRole/s"
        self.assertIn(
            "arn:aws-us-gov:iam::123456789012:role/TxBroadcastLambdaRole",
            sigv4_auth.canonical_principals(gov),
        )


class TestStsInteraction(unittest.TestCase):
    def test_sts_host_comes_from_configured_region(self):
        """A caller must not be able to steer the verification call at its own endpoint."""
        body = b"{}"
        with _StsPatch() as sts:
            sigv4_auth.authenticate(_headers(body), body, (ALLOWED_ROLE,), "eu-west-2")
        sts.factory.assert_called_once()
        self.assertEqual(sts.factory.call_args[0][0], "sts.eu-west-2.amazonaws.com")

    def test_sts_403_is_reported_as_a_caller_error(self):
        body = b"{}"
        with _StsPatch(status=403, body=b"<Error/>"):
            with self.assertRaises(AuthError) as ctx:
                sigv4_auth.authenticate(_headers(body), body, (ALLOWED_ROLE,), "us-east-1")
        self.assertEqual(ctx.exception.http_status, 403)

    def test_sts_500_is_reported_as_a_server_error(self):
        # Not the caller's fault; a 403 here would tell them to stop retrying.
        body = b"{}"
        with _StsPatch(status=500, body=b"<Error/>"):
            with self.assertRaises(AuthError) as ctx:
                sigv4_auth.authenticate(_headers(body), body, (ALLOWED_ROLE,), "us-east-1")
        self.assertEqual(ctx.exception.http_status, 502)

    def test_unreachable_sts_is_a_502(self):
        body = b"{}"
        connection = MagicMock()
        connection.request.side_effect = OSError("no route to host")
        with patch("http.client.HTTPSConnection", return_value=connection):
            with self.assertRaises(AuthError) as ctx:
                sigv4_auth.authenticate(_headers(body), body, (ALLOWED_ROLE,), "us-east-1")
        self.assertEqual(ctx.exception.http_status, 502)

    def test_unparseable_sts_response_is_a_502(self):
        body = b"{}"
        with _StsPatch(body=b"not xml at all <"):
            with self.assertRaises(AuthError) as ctx:
                sigv4_auth.authenticate(_headers(body), body, (ALLOWED_ROLE,), "us-east-1")
        self.assertEqual(ctx.exception.http_status, 502)

    def test_sts_response_without_an_arn_is_a_502(self):
        body = b"{}"
        with _StsPatch(body=b"<GetCallerIdentityResponse><Result/></GetCallerIdentityResponse>"):
            with self.assertRaises(AuthError) as ctx:
                sigv4_auth.authenticate(_headers(body), body, (ALLOWED_ROLE,), "us-east-1")
        self.assertEqual(ctx.exception.http_status, 502)

    def test_a_dtd_in_the_response_is_rejected(self):
        """ElementTree expands internally declared entities.

        STS never sends a DTD, so refusing one removes the expansion hazard rather than
        relying on the response always being well behaved.
        """
        bomb = (
            b'<!DOCTYPE r [<!ENTITY a "aaaaaaaaaa">'
            b'<!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">'
            b'<!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">]>'
            b"<r><Arn>&c;</Arn></r>"
        )
        body = b"{}"
        with _StsPatch(body=bomb):
            with self.assertRaises(AuthError) as ctx:
                sigv4_auth.authenticate(_headers(body), body, (ALLOWED_ROLE,), "us-east-1")
        self.assertEqual(ctx.exception.http_status, 502)
        self.assertIn("DTD", str(ctx.exception))

    def test_a_namespaced_response_is_still_parsed(self):
        # The DTD guard must not break the ordinary case: STS namespaces its responses.
        arn = sigv4_auth._extract_arn(STS_RESPONSE.format(arn=STS_ARN).encode())
        self.assertEqual(arn, STS_ARN)

    def test_replayed_headers_are_forwarded_verbatim(self):
        """STS recomputes the signature, so every signed header must be passed through."""
        body = b'{"hash":"0x01"}'
        headers = _headers(body)
        with _StsPatch() as sts:
            sigv4_auth.authenticate(headers, body, (ALLOWED_ROLE,), "us-east-1")

        _, kwargs = sts.request_calls[0]
        forwarded = kwargs["headers"]
        self.assertEqual(forwarded["Authorization"], headers[sigv4_auth.AUTHORIZATION_HEADER])
        self.assertEqual(forwarded["X-Amz-Date"], headers[sigv4_auth.DATE_HEADER])
        self.assertEqual(forwarded[sigv4_auth.DIGEST_HEADER], headers[sigv4_auth.DIGEST_HEADER])
        self.assertEqual(forwarded["X-Amz-Security-Token"], "session-token")


class TestLoadAllowedPrincipals(unittest.TestCase):
    def test_empty_and_blank_yield_nothing(self):
        for raw in (None, "", "   "):
            with self.subTest(raw=raw):
                self.assertEqual(sigv4_auth.load_allowed_principals(raw), ())

    def test_json_array(self):
        self.assertEqual(
            sigv4_auth.load_allowed_principals(f'["{ALLOWED_ROLE}", "arn:aws:iam::1:role/B"]'),
            (ALLOWED_ROLE, "arn:aws:iam::1:role/B"),
        )

    def test_comma_separated(self):
        self.assertEqual(
            sigv4_auth.load_allowed_principals(f" {ALLOWED_ROLE} , arn:aws:iam::1:role/B "),
            (ALLOWED_ROLE, "arn:aws:iam::1:role/B"),
        )

    def test_single_entry(self):
        self.assertEqual(sigv4_auth.load_allowed_principals(ALLOWED_ROLE), (ALLOWED_ROLE,))

    def test_blank_entries_are_dropped(self):
        self.assertEqual(
            sigv4_auth.load_allowed_principals(f"{ALLOWED_ROLE},,  ,"), (ALLOWED_ROLE,)
        )

    def test_invalid_json_raises(self):
        with self.assertRaises(ValueError) as ctx:
            sigv4_auth.load_allowed_principals('["unterminated')
        self.assertIn("not valid JSON", str(ctx.exception))

    def test_json_object_is_rejected(self):
        with self.assertRaises(ValueError):
            sigv4_auth.load_allowed_principals('[{"arn": "x"}]')

    def test_json_non_array_is_rejected(self):
        # A misconfiguration that silently produced an empty allowlist would fail closed,
        # but loudly is better: it tells the operator what they got wrong.
        with self.assertRaises(ValueError) as ctx:
            sigv4_auth.load_allowed_principals('["a"] extra')
        self.assertIn("not valid JSON", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
