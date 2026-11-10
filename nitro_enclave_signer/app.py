#!/usr/bin/env python3

#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

import base64
import os
import re
import sys
from aws_cdk import App, Environment, Aspects

from nitro_wallet.nitro_wallet_stack import NitroWalletStack
import cdk_nag

app = App()

VALID_DEPLOYMENTS = ("dev", "staging", "prod")
deployment = app.node.try_get_context("deployment") or os.getenv("CDK_DEPLOYMENT")
if deployment not in VALID_DEPLOYMENTS:
    raise ValueError(
        f"'deployment' must be one of {VALID_DEPLOYMENTS}, got: {deployment!r}. "
        "Pass --context deployment=dev (or staging/prod) to cdk deploy, "
        "or set CDK_DEPLOYMENT env var."
    )
prefix = app.node.try_get_context("prefix") or os.getenv("CDK_PREFIX", deployment)

# PCR0 is the enclave image measurement (SHA384, 96 hex chars) that gates kms:Decrypt.
# It is optional on the first deploy only: the measurement does not exist until the
# enclave image has been built, so the bootstrap order is
#   deploy without pcr0 -> read PCR0 from the built EIF -> redeploy with pcr0.
# Until it is supplied, NO principal is granted kms:Decrypt on the signing key, so the
# enclave cannot sign. That is deliberate: an unmeasured deployment must not be able to
# decrypt key material. See docs/nitro-enclave-deployment.md.
#
# deployment=dev runs the enclave with --debug-mode, and a debug-mode enclave's attestation
# document reports PCR0 as 96 zeros regardless of the image. Enforcing that value therefore
# admits ANY debug-mode enclave the parent chooses to run, so it is accepted only for dev
# (with a warning) and refused everywhere else.
DEBUG_MODE_PCR0 = "0" * 96
pcr0 = app.node.try_get_context("pcr0") or os.getenv("CDK_ENCLAVE_PCR0")
if pcr0 is not None:
    pcr0 = pcr0.strip().lower()
    if not re.fullmatch(r"[0-9a-f]{96}", pcr0):
        raise ValueError(
            f"'pcr0' must be 96 hex characters (SHA384 enclave measurement), got: {pcr0!r}. "
            "Obtain it with `nitro-cli describe-eif --eif-path <path>` and pass it as "
            "--context pcr0=<value>, or set CDK_ENCLAVE_PCR0. For deployment=dev the "
            f"enclave runs in debug mode and the only value it can attest is {DEBUG_MODE_PCR0!r}."
        )
    if pcr0 == DEBUG_MODE_PCR0:
        if deployment != "dev":
            raise ValueError(
                f"'pcr0' is the debug-mode measurement (96 zeros), which is not permitted for "
                f"deployment={deployment}. Every debug-mode enclave attests this value, so "
                "enforcing it would let any enclave image decrypt the wallet key. Supply the "
                "measurement of your built EIF from `nitro-cli describe-eif`."
            )
        print(
            "WARNING: pcr0 is the debug-mode measurement (96 zeros). The key policy will "
            "admit ANY debug-mode enclave the parent instance runs; the enclave boundary "
            "is not enforced in this dev deployment.",
            file=sys.stderr,
        )

# The signing service hands out signatures over caller-supplied hashes, so it refuses to
# start without an authentication mode and a non-empty allowlist. The invoking Lambda's
# role is added to the allowlist by the stack; these context values are for additional
# principals (an operator break-glass role, a second service) and for the mTLS path.
auth_mode = (
    app.node.try_get_context("authMode") or os.getenv("NITRO_AUTH_MODE") or "sigv4"
).strip()
if auth_mode not in ("sigv4", "mtls"):
    raise ValueError(
        f"'authMode' must be 'sigv4' or 'mtls', got: {auth_mode!r}. There is no "
        "unauthenticated mode. Pass --context authMode=sigv4 (or mtls)."
    )


def _context_list(name, env_var):
    """Split a comma-separated context or environment value into a list of entries."""
    raw = app.node.try_get_context(name) or os.getenv(env_var) or ""
    return [entry.strip() for entry in raw.split(",") if entry.strip()]


allowed_principals = _context_list("allowedPrincipals", "NITRO_ALLOWED_PRINCIPALS")
allowed_clients = _context_list("allowedClients", "NITRO_ALLOWED_CLIENTS")
client_ca_path = (
    app.node.try_get_context("clientCaPath") or os.getenv("NITRO_CLIENT_CA_PATH") or ""
).strip()
# Optional. Supplying it turns on CRL checking for the whole chain, so a stale or missing
# CRL then fails every client handshake rather than silently accepting revoked certs.
client_crl_path = (
    app.node.try_get_context("clientCrlPath") or os.getenv("NITRO_CLIENT_CRL_PATH") or ""
).strip()

if auth_mode == "mtls" and not (allowed_clients and client_ca_path):
    raise ValueError(
        "authMode=mtls requires both 'allowedClients' (comma-separated client certificate "
        "CN or DNS SAN values) and 'clientCaPath' (path to the CA bundle on the instance, "
        "under /etc/pki/tls/certs which the container mounts). The signing service will "
        "refuse to start without them."
    )

# Explicitly permits the invoke Lambda to connect to the sample self-signed server
# certificate in dev/test environments. Verification remains the default, and production
# can never opt out. A private/public CA should replace this override outside canaries.
skip_tls_verify_raw = app.node.try_get_context("nitroSkipTlsVerify")
if skip_tls_verify_raw is None:
    skip_tls_verify_raw = os.getenv("NITRO_SKIP_TLS_VERIFY", "false")
skip_tls_verify_text = str(skip_tls_verify_raw).strip().lower()
if skip_tls_verify_text not in ("true", "false", "1", "0"):
    raise ValueError(f"'nitroSkipTlsVerify' must be true or false, got: {skip_tls_verify_raw!r}.")
skip_tls_verify = skip_tls_verify_text in ("true", "1")
if deployment == "prod" and skip_tls_verify:
    raise ValueError("nitroSkipTlsVerify is forbidden for production deployments")

# Which wallet the signing service may use. Deliberately not caller-supplied: the instance
# role can read every secret under nitro-wallet/, so a caller-chosen id would let any
# authorized client sign with any other wallet in that namespace.
secret_id = (app.node.try_get_context("secretId") or os.getenv("NITRO_SECRET_ID") or "").strip()

# Secrets Manager name of the deployment TLS CA (created out-of-band by
# deploy-nitro-stack.sh). When set, instances fetch the CA at boot and issue a per-instance
# server certificate whose SAN is the NLB DNS name, replacing the CN=localhost self-signed
# cert so clients can verify TLS. Required for prod unless nitroSkipTlsVerify is set (which
# is itself forbidden for prod), so a prod deploy fails closed without a real TLS story.
tls_ca_secret_name = (
    app.node.try_get_context("tlsCaSecretName") or os.getenv("NITRO_TLS_CA_SECRET_NAME") or ""
).strip()
tls_ca_cert_b64 = (
    app.node.try_get_context("tlsCaCertB64") or os.getenv("NITRO_TLS_CA_CERT_B64") or ""
).strip()
tls_ca_cert_pem = ""
if tls_ca_cert_b64:
    try:
        tls_ca_cert_pem = base64.b64decode(tls_ca_cert_b64, validate=True).decode("ascii")
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError("tlsCaCertB64 must be valid base64-encoded ASCII PEM") from exc
    if not (
        tls_ca_cert_pem.startswith("-----BEGIN CERTIFICATE-----")
        and "-----END CERTIFICATE-----" in tls_ca_cert_pem
    ):
        raise ValueError("tlsCaCertB64 does not decode to a complete PEM certificate")
if tls_ca_secret_name and not tls_ca_cert_pem:
    raise ValueError(
        "tlsCaSecretName requires tlsCaCertB64 so the invoke Lambda can verify the NLB certificate"
    )
if deployment == "prod" and not tls_ca_secret_name and not skip_tls_verify:
    raise ValueError(
        "production requires tlsCaSecretName (a deployment TLS CA): the server must present "
        "a certificate the client can verify against the NLB DNS name. Run deploy-nitro-stack.sh, "
        "which creates the CA, or pass --context tlsCaSecretName=<name>."
    )

NitroWalletStack(
    app,
    f"{prefix}NitroWalletEth",
    params={
        "deployment": deployment,
        "application_type": "eth1",
        "pcr0": pcr0,
        "auth_mode": auth_mode,
        "allowed_principals": allowed_principals,
        "allowed_clients": allowed_clients,
        "client_ca_path": client_ca_path,
        "client_crl_path": client_crl_path,
        "secret_id": secret_id,
        "skip_tls_verify": skip_tls_verify,
        "tls_ca_secret_name": tls_ca_secret_name,
        "tls_ca_cert_pem": tls_ca_cert_pem,
    },
    env=Environment(
        region=os.environ.get("CDK_DEPLOY_REGION"),
        account=os.environ.get("CDK_DEPLOY_ACCOUNT"),
    ),
)

Aspects.of(app).add(cdk_nag.AwsSolutionsChecks())
app.synth()
