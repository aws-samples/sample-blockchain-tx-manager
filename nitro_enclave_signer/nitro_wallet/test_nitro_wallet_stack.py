#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0
"""Synth assertions for the NitroSigningClientRole authentication wiring.

These prove, at the CloudFormation-template level, the contract the rest of the system
depends on:

  * a dedicated signing-client role exists and carries NO permission policies;
  * its trust is delegated to the account root (so per-caller sts:AssumeRole grants,
    not the role itself, decide who may assume it);
  * both the invoke Lambda's role (key generation) and the signing-client role are on
    the service's allowlist baked into the instance user data;
  * the stack exports SigningClientRoleArn so deploy-nitro-stack.sh can wire it into
    .nitro-config.

Synthesis runs with bundling disabled (`aws:cdk:bundling-stacks: []`), so it needs no
Docker and no AWS credentials.
"""

import json

import pytest
from aws_cdk import App, Aspects, Environment
from aws_cdk.assertions import Annotations, Match, Template
from cdk_nag import AwsSolutionsChecks

from nitro_wallet.nitro_wallet_stack import NitroWalletStack


def _build_stack(app, **overrides):
    params = {
        "deployment": "dev",
        "application_type": "eth1",
        "pcr0": None,
        "auth_mode": "sigv4",
        "allowed_principals": [],
        "allowed_clients": [],
        "client_ca_path": "",
        "client_crl_path": "",
        "secret_id": "nitro-wallet/dev",
        "skip_tls_verify": False,
        "tls_ca_secret_name": "",
        "tls_ca_cert_pem": "",
    }
    params.update(overrides)
    return NitroWalletStack(
        app,
        "devNitroWalletEth",
        params=params,
        env=Environment(account="123456789012", region="us-east-1"),
    )


def _kms_statements(template):
    keys = template.find_resources("AWS::KMS::Key")
    assert len(keys) == 1
    return next(iter(keys.values()))["Properties"]["KeyPolicy"]["Statement"]


def test_unmeasured_bootstrap_denies_decrypt_and_generate_data_key(template):
    denies = [s for s in _kms_statements(template) if s.get("Effect") == "Deny"]
    assert len(denies) == 1
    actions = (
        denies[0]["Action"] if isinstance(denies[0]["Action"], list) else [denies[0]["Action"]]
    )
    assert {"kms:Decrypt", "kms:GenerateDataKey"}.issubset(actions)
    assert "Condition" not in denies[0], "no-PCR bootstrap must deny everyone unconditionally"
    assert not any(
        s.get("Effect") == "Allow" and "kms:RecipientAttestation:ImageSha384" in json.dumps(s)
        for s in _kms_statements(template)
    )


def test_measured_policy_denies_nonmatching_and_allows_exact_attestation():
    pcr0 = "ab" * 48
    app = App(context={"aws:cdk:bundling-stacks": []})
    measured = Template.from_stack(_build_stack(app, pcr0=pcr0))
    statements = _kms_statements(measured)
    deny = next(s for s in statements if s.get("Effect") == "Deny")
    allow = next(
        s
        for s in statements
        if s.get("Effect") == "Allow"
        and s.get("Condition", {})
        .get("StringEqualsIgnoreCase", {})
        .get("kms:RecipientAttestation:ImageSha384")
        == pcr0
    )
    assert (
        deny["Condition"]["StringNotEqualsIfExists"]["kms:RecipientAttestation:ImageSha384"] == pcr0
    )
    assert "kms:Decrypt" in allow["Action"]


@pytest.fixture(scope="module")
def template():
    app = App(context={"aws:cdk:bundling-stacks": []})
    stack = _build_stack(app)
    return Template.from_stack(stack)


def _role_by_description(template, needle):
    """Return (logical_id, properties) for the single IAM role whose Description matches."""
    roles = template.find_resources(
        "AWS::IAM::Role",
        {"Properties": {"Description": Match.string_like_regexp(f".*{needle}.*")}},
    )
    assert len(roles) == 1, f"expected exactly one role matching {needle!r}, got {list(roles)}"
    (logical_id,) = roles.keys()
    return logical_id, roles[logical_id]["Properties"]


def test_signing_client_role_has_no_permissions(template):
    _, props = _role_by_description(template, "Zero-permission identity")
    # A permission policy of any shape would defeat the point: assuming this role must
    # confer only an allowlisted identity, never AWS API access.
    assert "ManagedPolicyArns" not in props, "signing-client role must have no managed policies"
    assert "Policies" not in props, "signing-client role must have no inline policies"


def test_signing_client_role_trusts_account_root(template):
    _, props = _role_by_description(template, "Zero-permission identity")
    statement = props["AssumeRolePolicyDocument"]["Statement"][0]
    assert statement["Action"] == "sts:AssumeRole"
    # AccountPrincipal(this.account) renders as arn:<partition>:iam::<account>:root — the
    # trust delegates the assume decision to IAM, it does not grant it.
    principal_join = statement["Principal"]["AWS"]["Fn::Join"][1]
    assert ":iam::123456789012:root" in "".join(
        part for part in principal_join if isinstance(part, str)
    )


def test_exports_signing_client_role_arn(template):
    outputs = template.find_outputs("SigningClientRoleArn")
    assert outputs, "stack must export SigningClientRoleArn for deploy-nitro-stack.sh"


def test_allowlist_contains_both_invoke_lambda_and_signing_client_roles(template):
    client_id, _ = _role_by_description(template, "Zero-permission identity")
    lambda_id, _ = _role_by_description(template, "Execution role for the Nitro signing invoke")

    launch_templates = template.find_resources("AWS::EC2::LaunchTemplate")
    assert launch_templates, "stack must define a launch template carrying the user data"
    user_data = json.dumps(
        [lt["Properties"]["LaunchTemplateData"]["UserData"] for lt in launch_templates.values()]
    )

    # The allowlist is Fn.join(",", allowed_principals) substituted into the user data.
    # Both roles' Arn GetAtts must appear, so the signing service admits the assumed
    # signing-client identity and the invoke Lambda (for key generation).
    assert client_id in user_data, "signing-client role ARN must be on the service allowlist"
    assert lambda_id in user_data, "invoke Lambda role ARN must remain on the service allowlist"


def test_no_unsuppressed_cdk_nag_findings():
    # The zero-permission signing-client role has no policies and no wildcards, so it
    # introduces no AwsSolutions finding and needs no suppression. Run the same pack
    # bin app.py applies and assert the stack is clean end to end.
    app = App(context={"aws:cdk:bundling-stacks": []})
    stack = _build_stack(app)
    Aspects.of(app).add(AwsSolutionsChecks(verbose=True))
    template = Template.from_stack(stack)  # forces synth so the aspect runs

    errors = Annotations.from_stack(stack).find_error(
        "*", Match.string_like_regexp(r"AwsSolutions-.*")
    )
    assert not errors, f"unexpected cdk-nag errors: {[e.entry.data for e in errors]}"


def test_tls_verification_is_enabled_by_default(template):
    functions = template.find_resources("AWS::Lambda::Function")
    assert len(functions) == 1
    environment = next(iter(functions.values()))["Properties"]["Environment"]["Variables"]
    assert "NITRO_SKIP_TLS_VERIFY" not in environment


def test_explicit_canary_tls_skip_reaches_invoke_lambda():
    app = App(context={"aws:cdk:bundling-stacks": []})
    stack = _build_stack(app, skip_tls_verify=True)
    rendered = Template.from_stack(stack)
    functions = rendered.find_resources("AWS::Lambda::Function")
    environment = next(iter(functions.values()))["Properties"]["Environment"]["Variables"]
    assert environment["NITRO_SKIP_TLS_VERIFY"] == "true"


def test_production_cannot_disable_tls_verification():
    app = App(context={"aws:cdk:bundling-stacks": []})
    with pytest.raises(ValueError, match="forbidden for production"):
        _build_stack(app, deployment="prod", skip_tls_verify=True)


@pytest.mark.parametrize("deployment", ["staging", "prod"])
def test_debug_mode_pcr0_is_rejected_outside_dev(deployment):
    # Every debug-mode enclave attests PCR0 as 96 zeros, so enforcing it would admit any
    # enclave image the parent runs. Only dev (which runs --debug-mode) may enforce it.
    app = App(context={"aws:cdk:bundling-stacks": []})
    with pytest.raises(ValueError, match="debug-mode measurement"):
        _build_stack(app, deployment=deployment, pcr0="0" * 96)


def test_debug_mode_pcr0_is_accepted_for_dev():
    app = App(context={"aws:cdk:bundling-stacks": []})
    stack = _build_stack(app, deployment="dev", pcr0="0" * 96)
    rendered = Template.from_stack(stack)
    rendered.has_resource_properties(
        "AWS::KMS::Key",
        {
            "KeyPolicy": {
                "Statement": Match.array_with(
                    [
                        Match.object_like(
                            {
                                "Sid": "AllowEnclaveAttestedDecrypt",
                                "Condition": {
                                    "StringEqualsIgnoreCase": {
                                        "kms:RecipientAttestation:ImageSha384": "0" * 96
                                    }
                                },
                            }
                        )
                    ]
                )
            }
        },
    )


def test_parent_container_gets_vsock_without_linux_capabilities(template):
    launch_templates = template.find_resources("AWS::EC2::LaunchTemplate")
    user_data = json.dumps(
        [lt["Properties"]["LaunchTemplateData"]["UserData"] for lt in launch_templates.values()]
    )
    assert "--security-opt no-new-privileges" in user_data
    assert "--security-opt seccomp=unconfined" in user_data
    assert "--cap-drop ALL" in user_data
    assert "--privileged" not in user_data


def test_nlb_health_check_is_application_level(template):
    """A TCP handshake proves only that the parent is listening; /health pings the enclave."""
    template.has_resource_properties(
        "AWS::ElasticLoadBalancingV2::TargetGroup",
        {
            "HealthCheckProtocol": "HTTPS",
            "HealthCheckPath": "/health",
            "Matcher": {"HttpCode": "200"},
            "HealthCheckIntervalSeconds": 30,
            "UnhealthyThresholdCount": 2,
        },
    )


def test_asg_replaces_instances_the_nlb_marks_unhealthy(template):
    """EC2 status checks pass for a parent whose signer never started; only the NLB's
    /health check sees that, so the ASG must use it (with room for the EIF build)."""
    template.has_resource_properties(
        "AWS::AutoScaling::AutoScalingGroup",
        {"HealthCheckType": "ELB", "HealthCheckGracePeriod": 1200},
    )


def test_asg_launches_only_after_image_pull_endpoints_exist(template):
    """Instances pull images at boot via the ECR interface endpoints and the S3 gateway;
    launching before them strands both parents without a signer."""
    endpoints = template.find_resources("AWS::EC2::VPCEndpoint")
    image_path = {
        logical_id
        for logical_id, e in endpoints.items()
        if any(s in str(e["Properties"]["ServiceName"]) for s in (".ecr.api", ".ecr.dkr", ".s3"))
    }
    assert len(image_path) == 3, image_path
    (asg,) = template.find_resources("AWS::AutoScaling::AutoScalingGroup").values()
    assert image_path <= set(asg.get("DependsOn", [])), asg.get("DependsOn")


def test_user_data_retries_ecr_login_and_image_pulls(template):
    (lt,) = template.find_resources("AWS::EC2::LaunchTemplate").values()
    user_data = json.dumps(lt["Properties"]["LaunchTemplateData"]["UserData"])
    assert "retry ecr_login" in user_data
    assert user_data.count("retry docker pull") == 2


def test_secrets_manager_arns_use_partition_token(template):
    rendered = template.to_json()
    text = str(rendered)
    assert "arn:aws:secretsmanager" not in text, "hardcoded partition in Secrets Manager ARN"


def test_shared_vpc_has_endpoints_for_the_chain_stacks_hot_path(template):
    """DynamoDB and SQS must not depend on the single NAT gateway."""
    endpoints = template.find_resources("AWS::EC2::VPCEndpoint")
    rendered = str(template.to_json())
    for suffix in ("dynamodb", "s3", "sqs", "logs", "ecr.dkr", "ecr.api", "sts", "kms"):
        assert f".{suffix}" in rendered, f"missing VPC endpoint for {suffix}"
    gateway = [e for e in endpoints.values() if e["Properties"].get("VpcEndpointType") == "Gateway"]
    assert len(gateway) == 2, "DynamoDB and S3 gateway endpoints expected"
    for e in gateway:
        assert e["Properties"].get("RouteTableIds"), (
            "gateway endpoint must be attached to route tables"
        )


def test_tls_ca_wiring_grants_read_and_issues_san_cert():
    """With a deployment CA configured, the instance role can read the CA and user_data
    issues a per-instance server cert whose SAN is the NLB DNS name (no CN=localhost)."""
    app = App(context={"aws:cdk:bundling-stacks": []})
    stack = _build_stack(
        app,
        tls_ca_secret_name="nitro-tls-ca/dev",
        tls_ca_cert_pem="-----BEGIN CERTIFICATE-----\nPUBLIC\n-----END CERTIFICATE-----\n",
    )
    template = Template.from_stack(stack)

    # Instance role has a scoped read grant on the nitro-tls-ca/ namespace.
    rendered = str(template.to_json())
    assert "secret:nitro-tls-ca/*" in rendered, "instance role must read the TLS CA namespace"

    # user_data references the CA secret and issues a SAN cert from it (base64 user data).
    import base64

    lt = template.find_resources("AWS::EC2::LaunchTemplate")
    ud_field = next(iter(lt.values()))["Properties"]["LaunchTemplateData"]["UserData"]
    # UserData is Fn::Base64 of an Fn::Sub; join the template parts and decode where literal.
    ud_text = str(ud_field)
    assert "nitro-tls-ca/dev" in ud_text, "user_data must name the CA secret"
    assert "subjectAltName=DNS" in ud_text, "user_data must issue a SAN cert"
    assert "NitroEC2NetworkLoadBalancer" in ud_text, "SAN must be the NLB DNS name (token ref)"

    # Invoke Lambda receives only the public cert inline; it is not granted the CA secret,
    # whose value also contains the private key.
    functions = template.find_resources("AWS::Lambda::Function")
    invoke_envs = [
        f["Properties"].get("Environment", {}).get("Variables", {})
        for f in functions.values()
        if "NITRO_INSTANCE_PRIVATE_DNS"
        in f["Properties"].get("Environment", {}).get("Variables", {})
    ]
    assert len(invoke_envs) == 1
    assert invoke_envs[0]["NITRO_CA_CERT_PEM"].startswith("-----BEGIN CERTIFICATE-----")


def test_ca_secret_without_public_cert_is_rejected():
    app = App(context={"aws:cdk:bundling-stacks": []})
    with pytest.raises(ValueError, match="tls_ca_cert_pem"):
        _build_stack(app, tls_ca_secret_name="nitro-tls-ca/dev")


def test_no_ca_falls_back_to_self_signed(template):
    """The default (no CA) path keeps the self-signed localhost cert and grants no
    nitro-tls-ca read."""
    rendered = str(template.to_json())
    assert "secret:nitro-tls-ca/*" not in rendered
    lt = template.find_resources("AWS::EC2::LaunchTemplate")
    ud_text = str(next(iter(lt.values()))["Properties"]["LaunchTemplateData"]["UserData"])
    assert "CN=localhost" in ud_text
