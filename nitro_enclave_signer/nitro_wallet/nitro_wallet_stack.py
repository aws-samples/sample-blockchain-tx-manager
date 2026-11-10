#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0
import aws_cdk
from aws_cdk import (
    Stack,
    Fn,
    Duration,
    CfnOutput,
    BundlingOptions,
    aws_ec2,
    aws_iam,
    aws_ecr_assets,
    aws_secretsmanager,
    aws_lambda,
    aws_autoscaling,
    aws_elasticloadbalancingv2,
    aws_kms,
)
from cdk_nag import NagSuppressions, NagPackSuppression
from constructs import Construct

ATTESTATION_KEY = "kms:RecipientAttestation:ImageSha384"

# PCR0 reported by any enclave started with --debug-mode, regardless of its image.
DEBUG_MODE_PCR0 = "0" * 96


class NitroWalletStack(Stack):
    def _grant_enclave_only_decrypt(self, encryption_key, role, pcr0) -> None:
        """Authorize `kms:Decrypt` for the measured enclave only, and deny it everywhere else.

        The parent EC2 instance is untrusted in the Nitro threat model: it holds the
        ciphertext and mints the IMDS credentials used to call KMS, so an identity-policy
        grant of `kms:Decrypt` to the instance role would let anyone with those
        credentials decrypt signing keys *outside* the enclave and make the enclave
        decorative. Only the attestation document produced by a measured enclave carries
        `kms:RecipientAttestation:ImageSha384`.

        Two statements are required, and the `Deny` is the load-bearing one. An `Allow`
        can only add authorization, never subtract it, so a conditioned `Allow` on its own
        would sit alongside CDK's default `kms:*` delegation to the account root and
        remove nothing. `StringNotEqualsIfExists` denies both the wrong measurement and
        any caller that presents no attestation at all.

        Args:
            encryption_key: The KMS key wrapping every stored signing key.
            role: The parent EC2 instance role that proxies enclave KMS calls.
            pcr0: The 96-hex-char enclave measurement, or None before the first build.
        """
        # Deny unattested decrypt for every principal, including the account root.
        # NotPrincipal is deliberately avoided: this denies the operation itself rather
        # than exempting a principal, so re-adding an identity grant cannot bypass it.
        #
        # With a measurement, `StringNotEqualsIfExists` alone is exactly right: an absent
        # attestation key evaluates the condition true (deny), and a present-but-mismatched
        # one also evaluates true (deny). Only an exact match falls through to the Allow.
        # Do not AND a `Null` check onto this — conditions within a statement are ANDed,
        # so adding one would narrow the Deny to the absent case and let a *mismatched*
        # measurement through.
        deny_conditions = (
            {"StringNotEqualsIfExists": {ATTESTATION_KEY: pcr0}} if pcr0 is not None else None
        )
        encryption_key.add_to_resource_policy(
            aws_iam.PolicyStatement(
                sid="DenyDecryptWithoutMatchingEnclaveAttestation",
                effect=aws_iam.Effect.DENY,
                principals=[aws_iam.AnyPrincipal()],
                actions=["kms:Decrypt", "kms:GenerateDataKey"],
                resources=["*"],
                conditions=deny_conditions,
            )
        )

        if pcr0 is None:
            # No measurement supplied yet (first deploy, before the EIF exists). The Deny
            # above is already in force, so signing stays unavailable until a redeploy
            # supplies --context pcr0=<value>. Granting nothing here is the safe default.
            return

        encryption_key.add_to_resource_policy(
            aws_iam.PolicyStatement(
                sid="AllowEnclaveAttestedDecrypt",
                effect=aws_iam.Effect.ALLOW,
                principals=[role.grant_principal],
                actions=["kms:Decrypt", "kms:GenerateDataKey"],
                resources=["*"],
                conditions={"StringEqualsIgnoreCase": {ATTESTATION_KEY: pcr0}},
            )
        )

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        params = kwargs.pop("params")
        if params["deployment"] == "prod" and params.get("skip_tls_verify", False):
            raise ValueError("skip_tls_verify is forbidden for production deployments")
        # A debug-mode enclave attests PCR0 as 96 zeros whatever image it runs, so enforcing
        # that value admits any debug enclave the parent starts. Only dev runs --debug-mode,
        # and only dev may enforce it. app.py warns when it does.
        if params.get("pcr0") == DEBUG_MODE_PCR0 and params["deployment"] != "dev":
            raise ValueError(
                "pcr0 is the debug-mode measurement (96 zeros); it is only permitted for "
                "deployment=dev because every debug-mode enclave attests that value"
            )
        if params.get("tls_ca_secret_name") and not params.get("tls_ca_cert_pem"):
            raise ValueError(
                "tls_ca_secret_name requires tls_ca_cert_pem for invoke-Lambda TLS verification"
            )
        super().__init__(scope, construct_id, **kwargs)

        application_type = params["application_type"]

        encrypted_key = aws_secretsmanager.Secret(self, "SecretsManager")

        # Retained for the same reason as the KMS key below: this secret holds the only
        # copy of a wallet's ciphertext. Retaining the key but letting the ciphertext be
        # deleted loses the wallet just as completely.
        encrypted_key.apply_removal_policy(aws_cdk.RemovalPolicy.RETAIN)

        # Key that encrypts stored private keys. Rotation is safe here because the key id is
        # encoded in the ciphertext metadata, so existing ciphertext stays decryptable.
        encryption_key = aws_kms.Key(self, "EncryptionKey", enable_key_rotation=True)

        # RETAIN is unconditional and must stay that way. Signing keys exist only as
        # ciphertext in Secrets Manager, and this key is the only thing that can decrypt
        # them. Because the key id is embedded in the ciphertext metadata (see above),
        # there is no re-wrap path: deleting this key permanently orphans every wallet
        # and any on-chain funds those wallets hold. `cdk destroy` and create-rollback
        # must not be able to schedule it for deletion. See docs/nitro-enclave-deployment.md
        # ("Teardown") for the manual, deliberate deletion procedure.
        encryption_key.apply_removal_policy(aws_cdk.RemovalPolicy.RETAIN)

        signing_server_image = aws_ecr_assets.DockerImageAsset(
            self,
            "EthereumSigningServerImage",
            directory="./application/{}/server".format(application_type),
            platform=aws_ecr_assets.Platform.LINUX_AMD64,
        )

        signing_enclave_image = aws_ecr_assets.DockerImageAsset(
            self,
            "EthereumSigningEnclaveImage",
            directory="./application/{}/enclave".format(application_type),
            platform=aws_ecr_assets.Platform.LINUX_AMD64,
        )

        # Preserve the existing two-AZ CloudFormation shape across CDK upgrades. Using
        # explicit Fn::GetAZs selections prevents newer CDK versions from resolving AZs
        # to account-specific literals, which would make CloudFormation replace every
        # live subnet solely because the synthesized expression changed.
        vpc = aws_ec2.Vpc(
            self,
            "VPC",
            availability_zones=[
                Fn.select(0, Fn.get_azs()),
                Fn.select(1, Fn.get_azs()),
            ],
            nat_gateways=1,
            subnet_configuration=[
                aws_ec2.SubnetConfiguration(name="public", subnet_type=aws_ec2.SubnetType.PUBLIC),
                aws_ec2.SubnetConfiguration(
                    name="private", subnet_type=aws_ec2.SubnetType.PRIVATE_WITH_EGRESS
                ),
            ],
            enable_dns_support=True,
            enable_dns_hostnames=True,
        )

        # Interface endpoints keep these API calls inside the VPC. STS is on the
        # authentication path: the signing service verifies caller identity by replaying
        # the caller's signed GetCallerIdentity request to STS, so without this endpoint
        # that call leaves through the NAT gateway and a NAT or route failure would fail
        # authentication closed for every signing request.
        # Keep service names tokenized exactly as the deployed template
        # (`com.amazonaws.${AWS::Region}.<service>`). Newer CDK versions resolve the
        # region to a literal during synth, which CloudFormation treats as a replacement
        # even when it resolves to the same endpoint service at deploy time.
        # The per-chain TX Manager stacks (Lambda + Fargate watcher) run in this VPC's
        # private subnets. Their hot path is DynamoDB (every nonce reservation) and SQS;
        # the watcher also ships logs and pulls its image. Without endpoints all of that
        # egresses through the single NAT gateway, making one NAT/AZ a dependency of the
        # entire broadcast path and billing NAT data processing on every nonce op.
        endpoint_services = {
            "KMSEndpoint": "kms",
            "SecretsManagerEndpoint": "secretsmanager",
            "SSMEndpoint": "ssm",
            "ECREndpoint": "ecr.api",
            "ECRDockerEndpoint": "ecr.dkr",
            "STSEndpoint": "sts",
            "SQSEndpoint": "sqs",
            "CloudWatchLogsEndpoint": "logs",
        }
        # The instances pull their images through these endpoints at boot, so the ASG
        # below depends on them; otherwise CloudFormation can launch instances first.
        interface_endpoints = []
        for endpoint_id, service_suffix in endpoint_services.items():
            endpoint_service = aws_ec2.InterfaceVpcEndpointService(
                Fn.join("", ["com.amazonaws.", aws_cdk.Aws.REGION, f".{service_suffix}"]),
                443,
            )
            endpoint = aws_ec2.InterfaceVpcEndpoint(
                self,
                endpoint_id,
                vpc=vpc,
                subnets=aws_ec2.SubnetSelection(subnet_type=aws_ec2.SubnetType.PRIVATE_WITH_EGRESS),
                service=endpoint_service,
                private_dns_enabled=True,
            )
            interface_endpoints.append(endpoint)
            # CDK generates each endpoint a security group whose sole ingress rule is 443
            # from `vpc.vpc_cidr_block` — an unresolved intrinsic at synth time. Given an
            # intrinsic, AwsSolutions-EC23 cannot return pass or fail and instead emits
            # CdkNagValidationFailure; suppressing EC23 does not silence that, only
            # suppressing the validation failure does. EC23 stays in force on every
            # resource where it can actually evaluate, including the instance SG below.
            NagSuppressions.add_resource_suppressions(
                construct=endpoint,
                suppressions=[
                    NagPackSuppression(
                        id="CdkNagValidationFailure",
                        reason=(
                            "The endpoint security group is CDK-generated and its only "
                            "ingress source is vpc.vpc_cidr_block, an intrinsic that "
                            "AwsSolutions-EC23 cannot resolve at synth time. The value is "
                            "a VPC CIDR by construction, never an open range."
                        ),
                    ),
                ],
                apply_to_children=True,
            )

        # Gateway endpoints are free and route-table based: DynamoDB for the nonce
        # authority, S3 for ECR image layers (and any SDK S3 use). Both private subnets'
        # route tables get the prefix-list routes.
        vpc.add_gateway_endpoint(
            "DynamoDBEndpoint",
            service=aws_ec2.GatewayVpcEndpointAwsService.DYNAMODB,
            subnets=[aws_ec2.SubnetSelection(subnet_type=aws_ec2.SubnetType.PRIVATE_WITH_EGRESS)],
        )
        s3_endpoint = vpc.add_gateway_endpoint(
            "S3Endpoint",
            service=aws_ec2.GatewayVpcEndpointAwsService.S3,
            subnets=[aws_ec2.SubnetSelection(subnet_type=aws_ec2.SubnetType.PRIVATE_WITH_EGRESS)],
        )

        nitro_instance_sg = aws_ec2.SecurityGroup(
            self,
            "Nitro",
            vpc=vpc,
            allow_all_outbound=True,
            description="Private SG for NitroWallet EC2 instance",
        )

        # Port 443 is the signing service. A caller that reaches it and holds a valid
        # identity proof gets a signature over any hash it likes, so the reachable set is
        # kept to exactly what has to reach it:
        #
        #   1. the NLB's own private addresses, for health checks;
        #   2. other members of this SG, so instances can reach each other;
        #   3. the broadcast Lambda, whose SG is added as an ingress source by the
        #      TX Manager stack (`nitroSecurityGroupId` in infra/lib/tx-manager-stack.ts).
        #
        # This previously admitted the entire VPC CIDR, which is far wider than the NLB:
        # every workload in every subnet — including anything later deployed into the
        # shared VPC — could open a connection to the signing service.
        #
        # The health-check source is the NLB's private IP, not the client IP: this is an
        # instance-type TCP target group, so client IP preservation is on and *client*
        # traffic arrives with the caller's own address (covered by rule 3), while health
        # checks originate from the load balancer's interfaces. The NLB here carries no
        # security group of its own, so the subnets it is attached to (one interface per
        # subnet) are the tightest source available for the health-check rule. Adopters
        # who want the signer port closed to every other workload in those subnets can
        # attach a security group to the NLB and reference it here instead of the CIDRs.
        for subnet in vpc.select_subnets(
            subnet_type=aws_ec2.SubnetType.PRIVATE_WITH_EGRESS
        ).subnets:
            nitro_instance_sg.add_ingress_rule(
                aws_ec2.Peer.ipv4(subnet.ipv4_cidr_block),
                aws_ec2.Port.tcp(443),
                description="NLB health check on the signing service port",
            )

        # all members of the sg can access each others https ports (443)
        nitro_instance_sg.add_ingress_rule(nitro_instance_sg, aws_ec2.Port.tcp(443))

        # AMI
        amzn_linux = aws_ec2.MachineImage.latest_amazon_linux2023()

        # Instance Role and SSM Managed Policy
        role = aws_iam.Role(
            self,
            "InstanceSSM",
            assumed_by=aws_iam.ServicePrincipal("ec2.amazonaws.com"),
        )
        role.add_managed_policy(
            aws_iam.ManagedPolicy.from_aws_managed_policy_name("AmazonSSMManagedInstanceCore")
        )

        block_device = aws_ec2.BlockDevice(
            device_name="/dev/xvda",
            volume=aws_ec2.BlockDeviceVolume(
                ebs_device=aws_ec2.EbsDeviceProps(
                    volume_size=32,
                    volume_type=aws_ec2.EbsDeviceVolumeType.GP2,
                    encrypted=True,
                    delete_on_termination=True if params.get("deployment") == "dev" else False,
                )
            ),
        )

        # The signing service refuses to start without an authentication mode and a
        # non-empty allowlist, so these are deploy-time inputs rather than optional
        # extras. `allowed_principals` is every IAM principal permitted to request a
        # signature; the invoking Lambda's role is appended below, once it exists.
        auth_mode = params.get("auth_mode", "sigv4")
        allowed_principals = list(params.get("allowed_principals") or [])

        # The invoking Lambda's role is created here rather than being generated by the
        # Function below, because its ARN has to appear in the signing service's allowlist
        # in the instance user data. Letting `aws_lambda.Function` create the role would
        # make user data depend on the Function, which depends on the NLB, which depends
        # on the ASG that consumes the user data — a dependency cycle. A role depends on
        # nothing, so creating it first breaks it.
        invoke_lambda_role = aws_iam.Role(
            self,
            "NitroInvokeLambdaRole",
            assumed_by=aws_iam.ServicePrincipal("lambda.amazonaws.com"),
            description="Execution role for the Nitro signing invoke Lambda",
        )
        invoke_lambda_role.add_managed_policy(
            aws_iam.ManagedPolicy.from_aws_managed_policy_name(
                "service-role/AWSLambdaVPCAccessExecutionRole"
            )
        )
        # The Nitro stack's own invoke Lambda stays allowlisted so it can generate keys
        # (generate-nitro-key.sh invokes it), independent of any TX Manager deployment.
        allowed_principals.append(invoke_lambda_role.role_arn)

        # Stable, zero-permission identity that authorized broadcast Lambdas assume to
        # authenticate to the signing service. This is what lets per-chain TX Manager
        # stacks come and go without ever editing the deployed allowlist: the allowlist
        # pins this one role ARN, and each broadcast Lambda reaches it by assuming this
        # role rather than by having its own freshly-generated role ARN added here (which
        # would require redeploying the signing service for every new chain).
        #
        # Trust is delegated to the account root via AccountPrincipal: the role does not
        # decide who may assume it, IAM does. Assumption is gated entirely by the caller
        # side — the TX Manager stack grants its broadcast Lambda `sts:AssumeRole` on
        # exactly this ARN and nothing else in the account is permitted to assume it
        # unless explicitly granted. The role carries NO permission policies of its own,
        # so assuming it confers only an assumed-role ARN the allowlist recognizes, never
        # any AWS API access. It is a pure identity, not a privilege.
        signing_client_role = aws_iam.Role(
            self,
            "NitroSigningClientRole",
            assumed_by=aws_iam.AccountPrincipal(self.account),
            description=(
                "Zero-permission identity that authorized broadcast Lambdas assume to "
                "authenticate to the Nitro signing service. Holds no permission policies; "
                "assumption is gated by per-caller sts:AssumeRole grants."
            ),
        )
        allowed_principals.append(signing_client_role.role_arn)

        nitro_nlb = aws_elasticloadbalancingv2.NetworkLoadBalancer(
            self,
            "NitroEC2NetworkLoadBalancer",
            internet_facing=False,
            vpc=vpc,
            vpc_subnets=aws_ec2.SubnetSelection(subnet_type=aws_ec2.SubnetType.PRIVATE_WITH_EGRESS),
        )

        mappings = {
            "__DEV_MODE__": params["deployment"],
            "__DEBUG_FLAG__": "--debug-mode" if params["deployment"] == "dev" else "",
            "__SIGNING_SERVER_IMAGE_URI__": signing_server_image.image_uri,
            "__SIGNING_ENCLAVE_IMAGE_URI__": signing_enclave_image.image_uri,
            "__REGION__": self.region,
            "__AUTH_MODE__": auth_mode,
            "__SECRET_ID__": params.get("secret_id", ""),
            # Fn.join rather than str.join: the Lambda role ARN is an unresolved token at
            # synth time. The service accepts a comma-separated list or a JSON array.
            "__ALLOWED_PRINCIPALS__": Fn.join(",", allowed_principals),
            # mTLS scaffold. Empty in sigv4 mode, which the service treats as unset. The
            # CA bundle itself is operator-supplied: drop it in /etc/pki/tls/certs, which
            # the container already mounts, and point NITRO_CLIENT_CA_PATH at it.
            "__ALLOWED_CLIENTS__": ",".join(params.get("allowed_clients") or []),
            "__CLIENT_CA_PATH__": params.get("client_ca_path", ""),
            "__CLIENT_CRL_PATH__": params.get("client_crl_path", ""),
            # Deployment TLS CA: the secret holding the CA key+cert, and the NLB DNS name
            # the per-instance server cert must carry as its SAN. Empty when no CA is
            # configured (dev with skip-verify), in which case user_data falls back to the
            # legacy self-signed localhost cert.
            "__TLS_CA_SECRET_NAME__": params.get("tls_ca_secret_name", ""),
            "__NLB_DNS_NAME__": nitro_nlb.load_balancer_dns_name,
        }

        with open("./application/{}/user_data/user_data.sh".format(application_type)) as f:
            user_data_raw = Fn.sub(f.read(), mappings)

        signing_enclave_image.repository.grant_pull(role)
        signing_server_image.repository.grant_pull(role)
        encrypted_key.grant_read(role)
        self._grant_enclave_only_decrypt(encryption_key, role, params.get("pcr0"))

        # Allow reading encrypted signing keys under the nitro-wallet/ prefix only.
        # All signing keys MUST be stored as: nitro-wallet/{name}
        # The trailing wildcard covers the 6-char random suffix Secrets Manager appends.
        role.add_to_policy(
            aws_iam.PolicyStatement(
                actions=["secretsmanager:GetSecretValue"],
                resources=[
                    f"arn:{aws_cdk.Aws.PARTITION}:secretsmanager:{self.region}:{self.account}:secret:nitro-wallet/*",
                ],
            )
        )

        # Read the deployment TLS CA (key + cert) so each instance can issue its own
        # SAN-matched server certificate at boot. Scoped to the nitro-tls-ca/ prefix,
        # separate from the wallet-key namespace above.
        tls_ca_secret_name = params.get("tls_ca_secret_name", "")
        if tls_ca_secret_name:
            role.add_to_policy(
                aws_iam.PolicyStatement(
                    actions=["secretsmanager:GetSecretValue"],
                    resources=[
                        f"arn:{aws_cdk.Aws.PARTITION}:secretsmanager:{self.region}:{self.account}:secret:nitro-tls-ca/*",
                    ],
                )
            )

        nitro_launch_template = aws_ec2.LaunchTemplate(
            self,
            "NitroEC2LauchTemplate",
            instance_type=aws_ec2.InstanceType("m6i.xlarge"),
            user_data=aws_ec2.UserData.custom(user_data_raw),
            nitro_enclave_enabled=True,
            machine_image=amzn_linux,
            block_devices=[block_device],
            role=role,
            security_group=nitro_instance_sg,
            require_imdsv2=True,
            http_put_response_hop_limit=3,
        )

        nitro_asg = aws_autoscaling.AutoScalingGroup(
            self,
            "NitroEC2AutoScalingGroup",
            max_capacity=2,
            min_capacity=2,
            launch_template=nitro_launch_template,
            vpc=vpc,
            vpc_subnets=aws_ec2.SubnetSelection(subnet_type=aws_ec2.SubnetType.PRIVATE_WITH_EGRESS),
            update_policy=aws_autoscaling.UpdatePolicy.rolling_update(),
            # Replace instances the NLB marks unhealthy (signer or enclave never came up,
            # or died), not just failed EC2 status checks. The grace period covers image
            # pull + on-instance EIF build + enclave start (~8 minutes observed) plus the
            # user_data retry window.
            health_checks=aws_autoscaling.HealthChecks.with_additional_checks(
                additional_types=[aws_autoscaling.AdditionalHealthCheckType.ELB],
                grace_period=Duration.minutes(20),
            ),
        )
        # Image pulls at boot go through the ECR interface endpoints and the S3 gateway.
        for endpoint in (*interface_endpoints, s3_endpoint):
            nitro_asg.node.add_dependency(endpoint)

        nitro_nlb.add_listener(
            "HTTPSListener",
            port=443,
            protocol=aws_elasticloadbalancingv2.Protocol.TCP,
            default_target_groups=[
                aws_elasticloadbalancingv2.NetworkTargetGroup(
                    self,
                    "NitroEC2AutoScalingGroupTarget",
                    targets=[nitro_asg],
                    protocol=aws_elasticloadbalancingv2.Protocol.TCP,
                    port=443,
                    vpc=vpc,
                    # Application-level health, not a TCP handshake: the parent's GET
                    # /health pings the enclave over vsock (credential-free) and returns
                    # 503 when the enclave is dead or wedged, so such a host is removed
                    # from rotation instead of receiving signing requests it cannot
                    # serve. NLB HTTPS health checks do not validate the certificate,
                    # so the instance's self-signed cert is fine here.
                    health_check=aws_elasticloadbalancingv2.HealthCheck(
                        protocol=aws_elasticloadbalancingv2.Protocol.HTTPS,
                        path="/health",
                        healthy_http_codes="200",
                        interval=Duration.seconds(30),
                        timeout=Duration.seconds(10),
                        healthy_threshold_count=2,
                        unhealthy_threshold_count=2,
                    ),
                )
            ],
        )

        lambda_environment = {
            "LOG_LEVEL": "DEBUG" if params["deployment"] == "dev" else "INFO",
            "NITRO_INSTANCE_PRIVATE_DNS": nitro_nlb.load_balancer_dns_name,
            "SECRET_ARN": encrypted_key.secret_full_arn,
            "KEY_ARN": encryption_key.key_arn,
        }
        if params.get("skip_tls_verify", False):
            lambda_environment["NITRO_SKIP_TLS_VERIFY"] = "true"
        elif params.get("tls_ca_cert_pem"):
            # Public certificate only. Never grant this Lambda read access to the CA
            # secret, which also contains the private key used by parent bootstrapping.
            lambda_environment["NITRO_CA_CERT_PEM"] = params["tls_ca_cert_pem"]

        lambda_path = "application/{}/lambda".format(params["application_type"])
        invoke_lambda = aws_lambda.Function(
            self,
            "NitroInvokeLambda",
            code=aws_lambda.Code.from_asset(
                path=lambda_path,
                bundling=BundlingOptions(
                    image=aws_lambda.Runtime.PYTHON_3_14.bundling_image,
                    # The function uses Lambda's default x86_64 architecture. Pin the
                    # bundling container too: otherwise an arm64 development host installs
                    # arm64 native wheels (for example pydantic_core) into an x86_64 zip.
                    platform="linux/amd64",
                    # Copies the handler modules only, rather than the whole directory.
                    # `cp -au .` shipped test_lambda_function.py, __pycache__ and
                    # .pytest_cache into the deployed package, and its archive mode also
                    # fails outright on container runtimes whose bind mount does not carry
                    # extended attributes ("preserving permissions: No data available"),
                    # which is what Finch does on macOS. `exclude` is not an option here:
                    # it has no effect on assets built with `bundling`.
                    command=[
                        "bash",
                        "-c",
                        "pip install -r requirements.txt -t /asset-output && "
                        "find . -maxdepth 1 -name '*.py' -not -name 'test_*' "
                        "-exec cp {} /asset-output \\;",
                    ],
                ),
            ),
            handler="lambda_function.lambda_handler",
            runtime=aws_lambda.Runtime.PYTHON_3_14,
            timeout=Duration.minutes(2),
            memory_size=256,
            role=invoke_lambda_role,
            environment=lambda_environment,
            vpc=vpc,
            vpc_subnets=aws_ec2.SubnetSelection(subnet_type=aws_ec2.SubnetType.PRIVATE_WITH_EGRESS),
            security_groups=[nitro_instance_sg],
        )

        encrypted_key.grant_write(invoke_lambda)
        # if productive case, lambda is just allowed to set the secret key value
        if params.get("deployment") == "dev":
            encrypted_key.grant_read(invoke_lambda)

        # Allow Lambda to create secrets for the generate_key operation. It only ever
        # creates (a name collision is an error, never an overwrite), so no UpdateSecret.
        # Secrets must be stored under the nitro-wallet/ prefix.
        invoke_lambda.add_to_role_policy(
            aws_iam.PolicyStatement(
                actions=["secretsmanager:CreateSecret"],
                resources=[
                    f"arn:{aws_cdk.Aws.PARTITION}:secretsmanager:{self.region}:{self.account}:secret:nitro-wallet/*",
                ],
            )
        )

        CfnOutput(
            self,
            "EC2 Instance Role ARN",
            value=role.role_arn,
            description="EC2 Instance Role ARN",
        )

        CfnOutput(
            self,
            "Lambda Execution Role ARN",
            value=invoke_lambda.role.role_arn,
            description="Lambda Execution Role ARN",
        )

        CfnOutput(
            self,
            "SigningClientRoleArn",
            value=signing_client_role.role_arn,
            description=(
                "ARN of the zero-permission role that authorized broadcast Lambdas assume "
                "to authenticate to the signing service. It is permanently on the service "
                "allowlist. Grant each broadcast Lambda sts:AssumeRole on exactly this ARN "
                "(the TX Manager stack does this via nitroAuthRoleArn); no redeploy of this "
                "stack is needed to onboard a new chain."
            ),
        )

        CfnOutput(
            self,
            "Lambda Function Name",
            value=invoke_lambda.function_name,
            description=(
                "Name of the Lambda that brokers signing requests. It is the only "
                "supported entry point: the signing service requires an authenticated "
                "caller and this Lambda's role is on the allowlist."
            ),
        )

        CfnOutput(
            self,
            "ASG Group Name",
            value=nitro_asg.auto_scaling_group_name,
            description="ASG Group Name",
        )

        CfnOutput(self, "KMS Key ID", value=encryption_key.key_id, description="KMS Key ID")

        CfnOutput(
            self,
            "NLB DNS",
            value=nitro_nlb.load_balancer_dns_name,
            description="Network Load Balancer DNS Name",
        )

        # cdk-nag suppressions are attached per resource, not stack-wide.
        #
        # These were previously one blanket block on the stack with
        # `apply_to_children=True`, which suppressed each rule everywhere it could ever
        # fire — including on resources added later, which would then never be reviewed.
        # AwsSolutions-EC23 (security group open to the world) was among them; that is
        # exactly the finding this stack must not be able to hide, so it is gone rather
        # than re-scoped, and the ingress rules above are narrowed to earn its silence.
        NagSuppressions.add_resource_suppressions(
            construct=vpc,
            suppressions=[
                NagPackSuppression(
                    id="AwsSolutions-VPC7",
                    reason=(
                        "Flow logs are an operator decision with a per-GB cost and no "
                        "bearing on the signing path. Enable them where network forensics "
                        "are required."
                    ),
                ),
            ],
        )

        NagSuppressions.add_resource_suppressions(
            construct=nitro_nlb,
            suppressions=[
                NagPackSuppression(
                    id="AwsSolutions-ELB2",
                    reason=(
                        "The NLB is a TCP passthrough to a TLS listener it cannot "
                        "terminate, so its access logs would record connection metadata "
                        "only. The signing service logs the authenticated caller ARN for "
                        "every request, which is the audit record that matters."
                    ),
                ),
            ],
        )

        NagSuppressions.add_resource_suppressions(
            construct=role,
            suppressions=[
                NagPackSuppression(
                    id="AwsSolutions-IAM4",
                    reason=(
                        "AmazonSSMManagedInstanceCore is the AWS-managed policy for "
                        "Session Manager access, which is how these instances are "
                        "administered in place of inbound SSH."
                    ),
                ),
                NagPackSuppression(
                    id="AwsSolutions-IAM5",
                    reason=(
                        "secretsmanager:GetSecretValue is scoped to the nitro-wallet/* "
                        "prefix. The wildcard covers the 6-character suffix Secrets "
                        "Manager appends to every secret name, which is not known at "
                        "synth time."
                    ),
                ),
            ],
            apply_to_children=True,
        )

        NagSuppressions.add_resource_suppressions(
            construct=invoke_lambda_role,
            suppressions=[
                NagPackSuppression(
                    id="AwsSolutions-IAM4",
                    reason=(
                        "AWSLambdaVPCAccessExecutionRole is the AWS-managed policy "
                        "granting the ENI permissions a VPC-attached Lambda requires."
                    ),
                ),
                NagPackSuppression(
                    id="AwsSolutions-IAM5",
                    reason=(
                        "Secrets Manager actions are scoped to the nitro-wallet/* prefix; "
                        "the wildcard covers the suffix Secrets Manager appends."
                    ),
                ),
            ],
            apply_to_children=True,
        )

        NagSuppressions.add_resource_suppressions(
            construct=nitro_asg,
            suppressions=[
                NagPackSuppression(
                    id="AwsSolutions-AS3",
                    reason=(
                        "Scaling notifications are an operator preference. Instance "
                        "health is already alarmed through the target group."
                    ),
                ),
            ],
            apply_to_children=True,
        )

        NagSuppressions.add_resource_suppressions(
            construct=encrypted_key,
            suppressions=[
                NagPackSuppression(
                    id="AwsSolutions-SMG4",
                    reason=(
                        "Rotation would mint a new value for a secret that holds a "
                        "KMS-wrapped signing key. The key is the wallet identity and its "
                        "address is on-chain, so it cannot be rotated without moving "
                        "funds; rotation here would destroy access to them."
                    ),
                ),
            ],
        )
