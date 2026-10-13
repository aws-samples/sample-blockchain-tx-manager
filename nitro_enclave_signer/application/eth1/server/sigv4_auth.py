#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0
"""Caller authentication for the parent signing service.

The signing service hands out ECDSA signatures over caller-supplied hashes. A hash
carries no information about what it authorizes, so possession of the endpoint is
equivalent to possession of the wallet. Network reachability is therefore not an
adequate control, and this module supplies the missing one: every request must prove
which IAM principal sent it.

There is no AWS API that answers "is this SigV4 signature valid for this principal",
so the signature cannot be checked locally. Instead the caller signs a
`sts:GetCallerIdentity` request and forwards the resulting SigV4 headers alongside its
signing request; this module replays those headers to STS, which validates the
signature and returns the caller's ARN. The ARN is then matched against an allowlist
supplied by the stack.

Replaying an identity proof to a different body is prevented by binding: the caller
includes a SHA-256 digest of the signing-request body as a *signed* header, so the
digest is covered by the signature STS validates. This module recomputes the digest
over the body it actually received, and — critically — rejects any proof whose
`SignedHeaders` list omits the digest header. Without that second check an attacker
could drop the digest from the signed set, keep a valid signature, and swap the body
freely.

Replaying the identical request within the signature's validity window is not
prevented, and does not need to be: `sign_hash` over the same hash with the same key
is deterministic (RFC 6979), so a replay returns bytes the caller already held.
"""

import hashlib
import hmac
import http.client
import json
import logging
import re

# STS speaks the `query` protocol, whose responses are XML. ElementTree does not resolve
# external entities, and `_extract_arn` rejects any response carrying a DTD, so the
# internal-entity expansion this import is flagged for cannot be reached. The response
# also arrives from STS over a certificate-verified TLS connection.
import xml.etree.ElementTree as ElementTree  # nosec B405
from datetime import datetime, timedelta, timezone

AUTHORIZATION_HEADER = "X-Nitro-Auth-Authorization"
DATE_HEADER = "X-Nitro-Auth-Date"
# A header name, not a credential.
TOKEN_HEADER = "X-Nitro-Auth-Token"  # nosec B105
DIGEST_HEADER = "X-Nitro-Request-Digest"

_STS_BODY = "Action=GetCallerIdentity&Version=2011-06-15"
_STS_CONTENT_TYPE = "application/x-www-form-urlencoded"
_STS_TIMEOUT_SECONDS = 5

# STS enforces its own 5-minute window on the signature. This bound is tighter and is
# applied before the network call, so a stale proof costs nothing to reject.
_MAX_CLOCK_SKEW = timedelta(minutes=2)

_AMZ_DATE_FORMAT = "%Y%m%dT%H%M%SZ"
_SIGNED_HEADERS_RE = re.compile(r"SignedHeaders=([^,\s]+)")
_ASSUMED_ROLE_ARN_RE = re.compile(
    r"^arn:(?P<partition>[^:]+):sts::(?P<account>\d+):assumed-role/(?P<role>[^/]+)/.+$"
)


class AuthError(Exception):
    """A request could not be attributed to an allowed IAM principal.

    Carries the HTTP status the caller should receive. Detail in the message is safe to
    return: it describes what was wrong with the *caller's own* proof and never
    discloses the allowlist or anything about the key material.
    """

    def __init__(self, message, http_status=403):
        super().__init__(message)
        self.http_status = http_status


def body_digest(body):
    """Return the lowercase hex SHA-256 of a request body.

    Args:
        body: Raw request body bytes.

    Returns:
        64-character lowercase hex digest.
    """
    return hashlib.sha256(body).hexdigest()


def parse_signed_headers(authorization):
    """Extract the `SignedHeaders` set from a SigV4 Authorization header value.

    Args:
        authorization: The full `Authorization` header value produced by SigV4.

    Returns:
        Set of lowercase header names the signature covers.

    Raises:
        AuthError: The header has no parseable `SignedHeaders` component.
    """
    match = _SIGNED_HEADERS_RE.search(authorization)
    if not match:
        raise AuthError("Authorization header has no SignedHeaders component")
    return {name.strip().lower() for name in match.group(1).split(";") if name.strip()}


def _check_freshness(amz_date):
    """Reject a proof whose signing timestamp is outside the accepted skew."""
    try:
        signed_at = datetime.strptime(amz_date, _AMZ_DATE_FORMAT).replace(tzinfo=timezone.utc)
    except ValueError:
        raise AuthError(f"{DATE_HEADER} must be an ISO8601 basic UTC timestamp")

    skew = abs(datetime.now(timezone.utc) - signed_at)
    if skew > _MAX_CLOCK_SKEW:
        raise AuthError(
            f"Identity proof is outside the {int(_MAX_CLOCK_SKEW.total_seconds())}s "
            f"freshness window (off by {int(skew.total_seconds())}s)"
        )


class _DtdRejectingTreeBuilder(ElementTree.TreeBuilder):
    """A tree builder that refuses any document carrying a document type declaration.

    STS never sends one. Refusing it removes the only ElementTree parsing hazard that
    applies here — expansion of internally declared entities, which can inflate a small
    response into an arbitrarily large one. External entities are not resolved by
    ElementTree at all, so a DTD has no legitimate use in this response.
    """

    def doctype(self, name, pubid, system):
        raise ElementTree.ParseError("response declares a DTD, which is not permitted")


def _extract_arn(xml_body):
    """Pull the caller ARN out of an STS GetCallerIdentity XML response."""
    try:
        # The DTD-rejecting target is what makes this safe; see the class docstring.
        parser = ElementTree.XMLParser(target=_DtdRejectingTreeBuilder())  # nosec B314
        root = ElementTree.fromstring(xml_body, parser=parser)  # nosec B314
    except ElementTree.ParseError as exc:
        raise AuthError(f"STS returned an unparseable response: {exc}", http_status=502)

    # The response is namespaced; match on the local tag name rather than hardcoding
    # the namespace URI, which is versioned.
    for element in root.iter():
        if element.tag.rsplit("}", 1)[-1] == "Arn" and element.text:
            return element.text.strip()
    raise AuthError("STS response contained no Arn", http_status=502)


def _call_sts(region, amz_date, authorization, session_token, digest):
    """Replay a caller's signed GetCallerIdentity request and return the caller ARN.

    The host is derived from the parent's own configured region, never from the request,
    so a caller cannot steer this call at an endpoint of its choosing.

    Args:
        region: The parent's configured AWS region.
        amz_date: The `x-amz-date` value the caller signed with.
        authorization: The caller's SigV4 Authorization header value.
        session_token: The caller's session token, or None for long-term credentials.
        digest: The signed body digest, echoed back as the header the caller signed.

    Returns:
        The caller's ARN as reported by STS.

    Raises:
        AuthError: STS rejected the signature, or was unreachable.
    """
    host = f"sts.{region}.amazonaws.com"
    headers = {
        "Host": host,
        "Content-Type": _STS_CONTENT_TYPE,
        "X-Amz-Date": amz_date,
        DIGEST_HEADER: digest,
        "Authorization": authorization,
    }
    if session_token:
        headers["X-Amz-Security-Token"] = session_token

    connection = http.client.HTTPSConnection(host, timeout=_STS_TIMEOUT_SECONDS)
    try:
        connection.request("POST", "/", body=_STS_BODY, headers=headers)
        response = connection.getresponse()
        payload = response.read()
    except OSError as exc:
        raise AuthError(f"Could not reach STS to verify caller identity: {exc}", http_status=502)
    finally:
        connection.close()

    if response.status != 200:
        # A 403 here means the caller's signature did not verify — their problem, not a
        # server fault. Anything else is STS itself failing.
        status = 403 if response.status == 403 else 502
        raise AuthError(
            f"STS rejected the identity proof (HTTP {response.status})", http_status=status
        )

    return _extract_arn(payload)


def canonical_principals(arn):
    """Return the forms of `arn` that an allowlist entry may legitimately match.

    `GetCallerIdentity` reports a role session as
    `arn:aws:sts::<account>:assumed-role/<RoleName>/<session>`, while stacks and
    operators configure the role itself as `arn:aws:iam::<account>:role/<RoleName>`.
    Both are accepted so an allowlist can be written in the form people actually have.

    Note: an assumed-role ARN does not carry the role's IAM path, so the derived role
    ARN is unqualified. A role created under a non-default path must be allowlisted by
    its `assumed-role` form.

    Args:
        arn: The ARN reported by STS.

    Returns:
        Set of equivalent principal identifiers.
    """
    forms = {arn}
    match = _ASSUMED_ROLE_ARN_RE.match(arn)
    if match:
        forms.add(
            "arn:{}:iam::{}:role/{}".format(
                match.group("partition"), match.group("account"), match.group("role")
            )
        )
    return forms


def _matches_allowlist(arn, allowed_principals):
    """Constant-time-per-candidate allowlist match on the caller's ARN."""
    candidates = canonical_principals(arn)
    for allowed in allowed_principals:
        for candidate in candidates:
            if hmac.compare_digest(candidate, allowed):
                return True
    return False


def authenticate(headers, body, allowed_principals, region):
    """Authenticate a request and authorize it against an allowlist of IAM principals.

    Args:
        headers: The inbound request's header mapping (case-insensitive lookup).
        body: The raw request body bytes, used to verify the signed digest binding.
        allowed_principals: Non-empty collection of permitted principal ARNs.
        region: The parent's configured AWS region; the caller must have signed for it.

    Returns:
        The authenticated caller's ARN.

    Raises:
        AuthError: The proof is missing, malformed, stale, unbound to this body,
            rejected by STS, or attributable to a principal that is not allowed.
    """
    if not allowed_principals:
        # Fail closed: an empty allowlist is a misconfiguration, not "permit all".
        raise AuthError(
            "Signing service has no allowed principals configured; refusing all requests",
            http_status=503,
        )

    authorization = headers.get(AUTHORIZATION_HEADER)
    amz_date = headers.get(DATE_HEADER)
    digest = headers.get(DIGEST_HEADER)
    session_token = headers.get(TOKEN_HEADER)

    missing = [
        name
        for name, value in (
            (AUTHORIZATION_HEADER, authorization),
            (DATE_HEADER, amz_date),
            (DIGEST_HEADER, digest),
        )
        if not value
    ]
    if missing:
        raise AuthError(f"Request is missing required auth headers: {', '.join(missing)}", 401)

    signed_headers = parse_signed_headers(authorization)
    # Without the digest in the signed set the signature says nothing about this body,
    # and the proof would be replayable against any payload the attacker chooses.
    for required in (DIGEST_HEADER.lower(), "host"):
        if required not in signed_headers:
            raise AuthError(f"Identity proof does not cover the '{required}' header")

    expected_digest = body_digest(body)
    if not hmac.compare_digest(digest.lower(), expected_digest):
        raise AuthError("Request body does not match the digest covered by the identity proof")

    _check_freshness(amz_date)

    arn = _call_sts(region, amz_date, authorization, session_token, digest)

    if not _matches_allowlist(arn, allowed_principals):
        logging.warning("Rejected signing request from unauthorized principal %s", arn)
        raise AuthError("Caller is not authorized to use this signing service")

    return arn


def load_allowed_principals(raw):
    """Parse an allowlist from its environment-variable form.

    Accepts a JSON array or a comma-separated list, so the value can be produced
    conveniently by either CDK or a shell.

    Args:
        raw: The environment variable value, possibly None or empty.

    Returns:
        Tuple of principal ARNs, empty if nothing was configured.
    """
    if not raw or not raw.strip():
        return ()

    stripped = raw.strip()
    if stripped.startswith("["):
        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Principal allowlist is not valid JSON: {exc}")
        if not isinstance(parsed, list):
            raise ValueError("Principal allowlist JSON must be an array of ARN strings")
        entries = parsed
    else:
        entries = stripped.split(",")

    principals = []
    for entry in entries:
        if not isinstance(entry, str):
            raise ValueError("Principal allowlist entries must be strings")
        cleaned = entry.strip()
        if cleaned:
            principals.append(cleaned)
    return tuple(principals)
