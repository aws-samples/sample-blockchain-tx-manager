#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0
"""Builds the identity proof the parent signing service requires.

The signing service will not act on a request it cannot attribute to an allowed IAM
principal. Since no AWS API can validate a SigV4 signature on the service's behalf, the
proof takes the form of a signed `sts:GetCallerIdentity` request that the service replays
to STS (see `server/sigv4_auth.py` for the verifying half).

The proof is bound to the request body by signing a SHA-256 digest of that body as a
covered header, so a captured proof cannot be reused with a different payload.
"""

import hashlib

import boto3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest

AUTHORIZATION_HEADER = "X-Nitro-Auth-Authorization"
DATE_HEADER = "X-Nitro-Auth-Date"
# A header name, not a credential.
TOKEN_HEADER = "X-Nitro-Auth-Token"  # nosec B105
DIGEST_HEADER = "X-Nitro-Request-Digest"

_STS_BODY = "Action=GetCallerIdentity&Version=2011-06-15"
_STS_CONTENT_TYPE = "application/x-www-form-urlencoded"

_session = boto3.session.Session()


def build_auth_headers(body, region):
    """Sign a GetCallerIdentity request bound to `body` and return proof headers.

    Args:
        body: The exact request body bytes that will be sent to the signing service.
        region: The region whose STS endpoint the signing service will replay to. It must
            match the service's configured region or verification fails.

    Returns:
        Dict of headers to add to the signing request.

    Raises:
        RuntimeError: No AWS credentials are available to sign with.
    """
    credentials = _session.get_credentials()
    if credentials is None:
        raise RuntimeError("No AWS credentials available to build a Nitro signing identity proof")
    frozen = credentials.get_frozen_credentials()

    digest = hashlib.sha256(body).hexdigest()
    host = f"sts.{region}.amazonaws.com"

    # The digest header is included *before* signing so SigV4 covers it. The signing
    # service rejects any proof whose SignedHeaders list omits it.
    request = AWSRequest(
        method="POST",
        url=f"https://{host}/",
        data=_STS_BODY,
        headers={
            "Host": host,
            "Content-Type": _STS_CONTENT_TYPE,
            DIGEST_HEADER: digest,
        },
    )
    SigV4Auth(frozen, "sts", region).add_auth(request)

    headers = {
        AUTHORIZATION_HEADER: request.headers["Authorization"],
        DATE_HEADER: request.headers["X-Amz-Date"],
        DIGEST_HEADER: digest,
    }
    if frozen.token:
        headers[TOKEN_HEADER] = frozen.token
    return headers
