import * as cdk from 'aws-cdk-lib';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as sqs from 'aws-cdk-lib/aws-sqs';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as ecs from 'aws-cdk-lib/aws-ecs';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as lambdaEventSources from 'aws-cdk-lib/aws-lambda-event-sources';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as cloudwatch_actions from 'aws-cdk-lib/aws-cloudwatch-actions';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as sns from 'aws-cdk-lib/aws-sns';
import * as sns_subscriptions from 'aws-cdk-lib/aws-sns-subscriptions';
import { NagSuppressions } from 'cdk-nag';
import { Construct } from 'constructs';
import * as path from 'node:path';

export interface TxManagerStackProps extends cdk.StackProps {
  /**
   * VPC ID to deploy into — the Nitro Enclave signer VPC. Can also be provided
   * via --context vpcId=vpc-.... The stack looks the VPC up directly; it never
   * creates one.
   */
  vpcId?: string;

  /**
   * HTTP RPC URL (for Lambda broadcast)
   */
  rpcUrl?: string;

  /**
   * WebSocket RPC URL (for tx_watcher)
   */
  wsRpcUrl?: string;

  /**
   * Chain ID (default: 1 for mainnet)
   */
  chainId?: number;

  /**
   * TTL for DynamoDB records in days (default: 7)
   */
  ttlDays?: number;

  /**
   * Required confirmations for finality (default: 12)
   */
  requiredConfirmations?: number;

  /**
   * ECS task CPU (default: 256)
   */
  watcherCpu?: number;

  /**
   * ECS task memory (default: 512)
   */
  watcherMemory?: number;

  /**
   * Stuck transaction threshold in seconds (default: 300)
   */
  stuckThresholdSecs?: number;

  /**
   * If true, all resources will be destroyed on stack deletion.
   * Use for dev/test environments only. (default: false)
   */
  destroyOnRemoval?: boolean;

  /**
   * Resource name prefix for unique naming (default: 'eth-tx')
   */
  resourcePrefix?: string;

  /**
   * Nitro Enclave signing endpoint (NLB URL). If provided, enables Nitro signing.
   */
  nitroEndpoint?: string;

  /**
   * Secrets Manager secret ID for Nitro Enclave encrypted key
   */
  nitroSecretId?: string;

  /**
   * ARN of the Nitro stack's zero-permission signing-client role (its
   * `SigningClientRoleArn` output). When the Nitro backend is used, the broadcast
   * Lambda is granted `sts:AssumeRole` on exactly this ARN and assumes it to obtain an
   * identity the signing service's allowlist recognizes. Sourced from `.nitro-config`
   * (`NITRO_AUTH_ROLE_ARN`) by `deploy-chain.sh` and passed via
   * `--context nitroAuthRoleArn`.
   */
  nitroAuthRoleArn?: string;

  /**
   * Security group ID of the Nitro Enclave instances. When provided, the
   * Lambda security group is added as an ingress source on port 443 so the
   * broadcast Lambda can reach the Nitro signing NLB.
   */
  nitroSecurityGroupId?: string;

  /**
   * Signer backend for the broadcast Lambda. One of `nitro`, `secrets_manager`,
   * or `coinbase`. When omitted, defaults to `nitro` if `nitroEndpoint` is
   * set, otherwise requires an explicit value.
   */
  signerBackend?: string;

  /**
   * Skip TLS verification when the broadcast Lambda connects to the Nitro
   * signing NLB. Use only with self-signed certs in dev/test. (default: false)
   */
  nitroSkipTlsVerify?: boolean;

  /**
   * PEM of the deployment TLS CA that signed the Nitro NLB server certificate, passed to
   * the broadcast Lambda as NITRO_CA_CERT_PEM so it verifies TLS against exactly that CA
   * (and the NLB DNS name via the cert SAN). Produced by deploy-nitro-stack.sh and
   * carried in .nitro-config as NITRO_CA_CERT_B64. Required for a prod Nitro deployment
   * unless nitroSkipTlsVerify is set (which is itself forbidden for prod).
   */
  nitroCaCertPem?: string;

  /**
   * Email address subscribed to the alarm SNS topic. Alarms that notify a topic with no
   * subscribers are indistinguishable from no alarms. Required for `environment=prod`
   * unless `alarmTopicArn` is given; optional elsewhere (a synth warning is emitted).
   */
  alarmEmail?: string;

  /**
   * Existing SNS topic ARN (e.g. a PagerDuty/Chatbot-wired org topic) to notify instead
   * of the per-stack topic. When set, `alarmEmail` is not required.
   */
  alarmTopicArn?: string;

  /**
   * Secrets Manager secret holding the RPC endpoints as JSON
   * `{"rpcUrl": "https://...", "wsRpcUrl": "wss://..."}`. Provider RPC URLs embed the
   * provider API key, so they must not live in plaintext Lambda/ECS environment
   * variables (readable by anyone with lambda:GetFunctionConfiguration or
   * ecs:DescribeTaskDefinition). Required for `environment=prod`; when set, `rpcUrl` /
   * `wsRpcUrl` are ignored and both services read the secret at startup.
   */
  rpcSecretArn?: string;

  /**
   * Reserved concurrency for the broadcast Lambda. Bounds how many invocations can be
   * in flight so a queue backlog or invoke burst cannot consume the account's concurrency
   * pool or overrun the RPC provider's rate limit. Default 50.
   */
  lambdaReservedConcurrency?: number;

  /**
   * Maximum concurrent Lambda invocations the SQS event source may drive (2-1000).
   * Default 10: per-wallet reservations are serialized in DynamoDB anyway, so a small
   * consumer pool keeps RPC pressure predictable while direct invocations still have
   * the remaining reserved headroom.
   */
  sqsMaxConcurrency?: number;

  /**
   * Seconds without a processed block before the watcher is considered stalled. Drives
   * both the ECS container health check (task replaced) and the block-progress alarm.
   * Default 300 — well above any supported chain's block interval.
   */
  watcherStallSecs?: number;

  replacementEnabled?: boolean;
  defaultMaxFeePerGasWei?: string;
  hardMaxFeePerGasWei?: string;
  defaultMaxTotalFeeWei?: string;
  hardMaxTotalFeeWei?: string;
  maxReplacementAttempts?: number;
  feeTipFloorWei?: string;
  replacementReservedConcurrency?: number;

  /** Existing customer-managed KMS key ARN for DynamoDB table encryption. */
  dynamoDbKmsKeyArn?: string;

  /** Create a rotating stack-owned CMK for DynamoDB. Mutually exclusive with dynamoDbKmsKeyArn. */
  createDynamoDbKmsKey?: boolean;
}


export class TxManagerStack extends cdk.Stack {
  public readonly vpc: ec2.IVpc;
  public readonly txTrackerTable: dynamodb.Table;
  public readonly broadcastFunction: lambda.Function;
  public readonly replacementFunction: lambda.Function;
  public readonly watcherService: ecs.FargateService;
  public readonly txQueue: sqs.Queue;
  public readonly replacementQueue: sqs.Queue;

  constructor(scope: Construct, id: string, props: TxManagerStackProps) {
    super(scope, id, props);

    // Resolve the existing Nitro Enclave signer VPC. This stack never creates a VPC.
    //
    // Two paths:
    //  * synthMode (CI / TypeScript+CDK validation): import a deterministic VPC via
    //    fromVpcAttributes. This performs NO AWS lookup, so `cdk synth` is reproducible
    //    with no credentials, no context cache, and no account/region. It is never
    //    deployed — it exists only to let synth validate the rest of the stack.
    //  * deploy: fromLookup resolves the real VPC (deploy-chain.sh provides account,
    //    region, and vpcId).
    const vpcId = props.vpcId ?? this.node.tryGetContext('vpcId');
    const synthModeRaw = this.node.tryGetContext('synthMode') ?? false;
    const synthMode = synthModeRaw === true || synthModeRaw === 'true';

    if (synthMode) {
      this.vpc = ec2.Vpc.fromVpcAttributes(this, 'Vpc', {
        vpcId: vpcId ?? 'vpc-00000000000000000',
        availabilityZones: ['us-east-1a', 'us-east-1b'],
        // Two private-with-egress subnets so PRIVATE_WITH_EGRESS placement resolves
        // for the Lambda and the ECS watcher during synth validation.
        privateSubnetIds: ['subnet-00000000000000001', 'subnet-00000000000000002'],
        publicSubnetIds: ['subnet-00000000000000003', 'subnet-00000000000000004'],
      });
    } else {
      if (!vpcId) {
        throw new Error(
          'vpcId is required. Provide the Nitro Enclave signer VPC ID via props or ' +
          'context (--context vpcId=vpc-...), or pass --context synthMode=true for ' +
          'credential-free synth. This stack does not create a VPC.'
        );
      }
      this.vpc = ec2.Vpc.fromLookup(this, 'Vpc', { vpcId });
    }

    // Read from context or props
    const rpcUrl = props.rpcUrl ?? this.node.tryGetContext('rpcUrl');
    const wsRpcUrl = props.wsRpcUrl ?? this.node.tryGetContext('wsRpcUrl');
    const rpcSecretArn: string | undefined = props.rpcSecretArn ?? this.node.tryGetContext('rpcSecretArn');
    if (rpcSecretArn !== undefined && !/^arn:[a-z-]+:secretsmanager:[a-z0-9-]+:\d{12}:secret:.+$/.test(rpcSecretArn)) {
      throw new Error(`rpcSecretArn is not a Secrets Manager secret ARN: "${rpcSecretArn}"`);
    }
    const chainId = props.chainId ?? this.node.tryGetContext('chainId') ?? 1;
    const ttlDays = props.ttlDays ?? this.node.tryGetContext('ttlDays') ?? 7;
    const requiredConfirmations = props.requiredConfirmations ?? this.node.tryGetContext('requiredConfirmations') ?? 12;
    const watcherCpu = props.watcherCpu ?? this.node.tryGetContext('watcherCpu') ?? 256;
    const watcherMemory = props.watcherMemory ?? this.node.tryGetContext('watcherMemory') ?? 512;
    const stuckThresholdSecs = props.stuckThresholdSecs ?? this.node.tryGetContext('stuckThresholdSecs') ?? 300;
    const destroyOnRemovalRaw = props.destroyOnRemoval ?? this.node.tryGetContext('destroyOnRemoval') ?? false;
    const destroyOnRemoval = destroyOnRemovalRaw === true || destroyOnRemovalRaw === 'true';
    const resourcePrefix = props.resourcePrefix ?? this.node.tryGetContext('resourcePrefix') ?? 'eth-tx';
    const nitroEndpoint = props.nitroEndpoint ?? this.node.tryGetContext('nitroEndpoint');
    const nitroSecretId = props.nitroSecretId ?? this.node.tryGetContext('nitroSecretId');
    const nitroAuthRoleArn = props.nitroAuthRoleArn ?? this.node.tryGetContext('nitroAuthRoleArn');
    const signerBackendRaw = props.signerBackend ?? this.node.tryGetContext('signerBackend') ?? (nitroEndpoint ? 'nitro' : undefined);
    const nitroSecurityGroupId = props.nitroSecurityGroupId ?? this.node.tryGetContext('nitroSecurityGroupId');
    const nitroSkipTlsVerifyRaw = props.nitroSkipTlsVerify ?? this.node.tryGetContext('nitroSkipTlsVerify') ?? false;
    const nitroSkipTlsVerify = nitroSkipTlsVerifyRaw === true || nitroSkipTlsVerifyRaw === 'true';
    // The CA travels through CLI context base64-encoded: `cdk --context` does not
    // survive multi-line values (everything after the first newline is dropped).
    const nitroCaCertB64: string | undefined = this.node.tryGetContext('nitroCaCertB64');
    const nitroCaCertPem: string | undefined =
      props.nitroCaCertPem ??
      (nitroCaCertB64 ? Buffer.from(nitroCaCertB64, 'base64').toString('utf8') : undefined) ??
      this.node.tryGetContext('nitroCaCertPem');
    const environment = this.node.tryGetContext('environment') ?? 'prod';
    if (nitroSkipTlsVerify && environment === 'prod') {
      // Mirrors the Nitro stack's own guard. SigV4 still binds the body and the client
      // ecrecovers the signature, so a MITM cannot forge signatures — but it can read
      // and replay the caller's identity proof. Not acceptable for production.
      throw new Error(
        'nitroSkipTlsVerify=true is not allowed for environment=prod. Provision the ' +
          'deployment TLS CA (deploy-nitro-stack.sh) and pass nitroCaCertPem.',
      );
    }
    if (nitroCaCertPem && !/-----BEGIN CERTIFICATE-----[\s\S]+-----END CERTIFICATE-----/.test(nitroCaCertPem)) {
      throw new Error('nitroCaCertPem is not a complete PEM certificate (header and footer required)');
    }
    // A prod Nitro deployment must verify TLS: either pin the deployment CA, or (not for
    // prod) skip verification. Without one of those the client would fall back to the
    // system trust store and fail against the private CA — a broken deploy.
    if (environment === 'prod' && !synthMode && nitroEndpoint && !nitroCaCertPem && !nitroSkipTlsVerify) {
      throw new Error(
        'environment=prod with a Nitro endpoint requires nitroCaCertPem (the deployment ' +
          'TLS CA). Deploy the Nitro stack first; deploy-chain.sh sources it from .nitro-config.',
      );
    }
    const alarmEmail: string | undefined = props.alarmEmail ?? this.node.tryGetContext('alarmEmail');
    const alarmTopicArn: string | undefined = props.alarmTopicArn ?? this.node.tryGetContext('alarmTopicArn');
    const lambdaReservedConcurrency: number = Number(
      props.lambdaReservedConcurrency ?? this.node.tryGetContext('lambdaReservedConcurrency') ?? 50,
    );
    const sqsMaxConcurrency: number = Number(
      props.sqsMaxConcurrency ?? this.node.tryGetContext('sqsMaxConcurrency') ?? 10,
    );
    if (!Number.isInteger(lambdaReservedConcurrency) || lambdaReservedConcurrency < 2) {
      throw new Error(`lambdaReservedConcurrency must be an integer >= 2 (got ${lambdaReservedConcurrency})`);
    }
    if (!Number.isInteger(sqsMaxConcurrency) || sqsMaxConcurrency < 2 || sqsMaxConcurrency > lambdaReservedConcurrency) {
      throw new Error(
        `sqsMaxConcurrency must be an integer in [2, lambdaReservedConcurrency=${lambdaReservedConcurrency}] (got ${sqsMaxConcurrency})`,
      );
    }
    const replacementEnabledRaw = props.replacementEnabled ?? this.node.tryGetContext('replacementEnabled') ?? true;
    const replacementEnabled = replacementEnabledRaw === true || replacementEnabledRaw === 'true';
    const defaultMaxFeePerGasWei = String(props.defaultMaxFeePerGasWei ?? this.node.tryGetContext('defaultMaxFeePerGasWei') ?? '150000000000');
    const hardMaxFeePerGasWei = String(props.hardMaxFeePerGasWei ?? this.node.tryGetContext('hardMaxFeePerGasWei') ?? '500000000000');
    const defaultMaxTotalFeeWei = String(props.defaultMaxTotalFeeWei ?? this.node.tryGetContext('defaultMaxTotalFeeWei') ?? '20000000000000000');
    const hardMaxTotalFeeWei = String(props.hardMaxTotalFeeWei ?? this.node.tryGetContext('hardMaxTotalFeeWei') ?? '100000000000000000');
    const feeTipFloorWei = String(props.feeTipFloorWei ?? this.node.tryGetContext('feeTipFloorWei') ?? '100000000');
    const maxReplacementAttempts = Number(props.maxReplacementAttempts ?? this.node.tryGetContext('maxReplacementAttempts') ?? 3);
    const replacementReservedConcurrency = Number(props.replacementReservedConcurrency ?? this.node.tryGetContext('replacementReservedConcurrency') ?? 2);
    for (const [name, value] of Object.entries({ defaultMaxFeePerGasWei, hardMaxFeePerGasWei, defaultMaxTotalFeeWei, hardMaxTotalFeeWei, feeTipFloorWei })) {
      if (!/^[1-9][0-9]*$/.test(value)) throw new Error(`${name} must be a positive integer string`);
    }
    if (BigInt(defaultMaxFeePerGasWei) > BigInt(hardMaxFeePerGasWei) || BigInt(defaultMaxTotalFeeWei) > BigInt(hardMaxTotalFeeWei)) {
      throw new Error('replacement default fee limits must not exceed hard limits');
    }
    if (!Number.isInteger(maxReplacementAttempts) || maxReplacementAttempts < 1 || maxReplacementAttempts > 20) {
      throw new Error(`maxReplacementAttempts must be an integer in [1,20] (got ${maxReplacementAttempts})`);
    }
    if (!Number.isInteger(replacementReservedConcurrency) || replacementReservedConcurrency < 2) {
      throw new Error(`replacementReservedConcurrency must be an integer >= 2 (got ${replacementReservedConcurrency})`);
    }
    const dynamoDbKmsKeyArn: string | undefined = props.dynamoDbKmsKeyArn ?? this.node.tryGetContext('dynamoDbKmsKeyArn');
    const createDynamoDbKmsKeyRaw = props.createDynamoDbKmsKey ?? this.node.tryGetContext('createDynamoDbKmsKey') ?? false;
    const createDynamoDbKmsKey = createDynamoDbKmsKeyRaw === true || createDynamoDbKmsKeyRaw === 'true';
    if (dynamoDbKmsKeyArn && !/^arn:[a-z0-9-]+:kms:[a-z0-9-]+:\d{12}:key\/(mrk-)?[0-9a-f-]+$/i.test(dynamoDbKmsKeyArn)) {
      throw new Error(`dynamoDbKmsKeyArn is not a KMS key ARN: "${dynamoDbKmsKeyArn}"`);
    }
    if (dynamoDbKmsKeyArn && createDynamoDbKmsKey) {
      throw new Error('dynamoDbKmsKeyArn and createDynamoDbKmsKey=true are mutually exclusive');
    }
    const watcherStallSecs: number = Number(props.watcherStallSecs ?? this.node.tryGetContext('watcherStallSecs') ?? 300);
    if (!Number.isFinite(watcherStallSecs) || watcherStallSecs < 60) {
      throw new Error(`watcherStallSecs must be a number >= 60 (got ${watcherStallSecs})`);
    }

    // Fail fast: validate required RPC URLs before creating any resources
    // Only validate when stackName context is provided (i.e., during actual deploy, not bootstrap/synth)
    const stackNameContext = this.node.tryGetContext('stackName');
    if (stackNameContext) {
      if (rpcSecretArn) {
        // Secret-sourced RPC config: the URLs live in Secrets Manager, never in the template.
      } else {
        if (environment === 'prod' && !synthMode) {
          throw new Error(
            'environment=prod requires rpcSecretArn: RPC URLs carry the provider API key and ' +
              'must not be deployed as plaintext Lambda/ECS environment variables. Create a ' +
              'Secrets Manager secret {"rpcUrl": ..., "wsRpcUrl": ...} and pass --context rpcSecretArn=<arn>.',
          );
        }
        cdk.Annotations.of(this).addWarning(
          'RPC URLs are being deployed as plaintext environment variables (rpcUrl/wsRpcUrl). ' +
            'Use rpcSecretArn to keep the provider API key out of the task/function configuration.',
        );
        if (!rpcUrl || rpcUrl.includes('localhost')) {
          throw new Error(
            `Invalid rpcUrl: "${rpcUrl ?? 'undefined'}". ` +
            'You must provide a valid HTTP RPC URL via context (--context rpcUrl=...) or props, ' +
            'or an rpcSecretArn. Localhost URLs are not allowed in deployed stacks.'
          );
        }
        if (!wsRpcUrl || wsRpcUrl.includes('localhost')) {
          throw new Error(
            `Invalid wsRpcUrl: "${wsRpcUrl ?? 'undefined'}". ` +
            'You must provide a valid WebSocket RPC URL via context (--context wsRpcUrl=...) or props, ' +
            'or an rpcSecretArn. Localhost URLs are not allowed in deployed stacks.'
          );
        }
      }
      if (!signerBackendRaw) {
        throw new Error(
          'signerBackend is required when nitroEndpoint is not set. ' +
          'Pass --context signerBackend=secrets_manager (or coinbase) to explicitly opt into a non-Nitro signer, ' +
          'or provide nitroEndpoint to use the Nitro Enclave backend.'
        );
      }
      const validBackends = ['nitro', 'secrets_manager', 'coinbase'];
      if (!validBackends.includes(signerBackendRaw)) {
        throw new Error(
          `Invalid signerBackend: "${signerBackendRaw}". Must be one of: ${validBackends.join(', ')}.`
        );
      }
      if (signerBackendRaw === 'nitro' && !nitroEndpoint) {
        throw new Error(
          'signerBackend=nitro requires nitroEndpoint to be set. ' +
          'Either provide nitroEndpoint via --context nitroEndpoint=... (or source .nitro-config) ' +
          'or pick a different backend.'
        );
      }
      if (signerBackendRaw === 'nitro' && !nitroAuthRoleArn) {
        throw new Error(
          'signerBackend=nitro requires nitroAuthRoleArn: the ARN of the Nitro stack\'s ' +
          'SigningClientRoleArn output. deploy-chain.sh sources it from .nitro-config ' +
          '(NITRO_AUTH_ROLE_ARN) and passes --context nitroAuthRoleArn. The broadcast Lambda ' +
          'assumes this role to authenticate to the signing service; without it, signing ' +
          'requests are rejected as unauthenticated.'
        );
      }
    }
    const signerBackend = signerBackendRaw;

    // Effective signing-client role ARN the broadcast Lambda assumes for Nitro SigV4
    // auth. In synthMode there is no real Nitro stack to read an output from, so a
    // deterministic placeholder keeps `cdk synth` credential-free and reproducible; it
    // is never deployed. In a real deploy nitroAuthRoleArn is required (validated above)
    // whenever the Nitro backend is selected.
    const resolvedNitroAuthRoleArn: string | undefined =
      nitroAuthRoleArn ??
      (synthMode ? 'arn:aws:iam::111122223333:role/synthmode-nitro-signing-client' : undefined);

    // Determine removal policy based on destroyOnRemoval flag
    const dataRemovalPolicy = destroyOnRemoval ? cdk.RemovalPolicy.DESTROY : cdk.RemovalPolicy.RETAIN;

    // ========================================
    // Security Groups
    // ========================================
    const lambdaSg = new ec2.SecurityGroup(this, 'LambdaSg', {
      vpc: this.vpc,
      description: `Security group for ${resourcePrefix} TX broadcast Lambda`,
      allowAllOutbound: true,
    });

    const watcherSg = new ec2.SecurityGroup(this, 'WatcherSg', {
      vpc: this.vpc,
      description: `Security group for ${resourcePrefix} TX watcher ECS service`,
      allowAllOutbound: true,
    });

    // Allow Lambda to reach Nitro Enclave NLB on port 443
    if (nitroSecurityGroupId) {
      const nitroSg = ec2.SecurityGroup.fromSecurityGroupId(
        this, 'NitroSg', nitroSecurityGroupId,
      );
      nitroSg.addIngressRule(lambdaSg, ec2.Port.tcp(443), 'Lambda access to Nitro NLB');
    }

    // ========================================
    // DynamoDB Table
    // ========================================
    // DynamoDB is always encrypted at rest. The default uses an AWS-owned key (no
    // customer KMS charge/administration). Adopters may import an existing CMK to apply
    // organizational key policy, or ask this sample stack to create a rotating CMK.
    const dynamoDbEncryptionKey: kms.IKey | undefined = dynamoDbKmsKeyArn
      ? kms.Key.fromKeyArn(this, 'ImportedDynamoDbKey', dynamoDbKmsKeyArn)
      : createDynamoDbKmsKey
        ? new kms.Key(this, 'DynamoDbKey', {
            description: `Customer-managed encryption key for ${resourcePrefix}-tracker`,
            enableKeyRotation: true,
            removalPolicy: dataRemovalPolicy,
          })
        : undefined;
    const dynamoDbEncryption = dynamoDbEncryptionKey
      ? dynamodb.TableEncryption.CUSTOMER_MANAGED
      : dynamodb.TableEncryption.DEFAULT;

    this.txTrackerTable = new dynamodb.Table(this, 'TxTrackerTable', {
      tableName: `${resourcePrefix}-tracker`,
      partitionKey: { name: 'wallet', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'tx_hash', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      encryption: dynamoDbEncryption,
      ...(dynamoDbEncryptionKey && { encryptionKey: dynamoDbEncryptionKey }),
      timeToLiveAttribute: 'ttl',
      removalPolicy: dataRemovalPolicy,
      pointInTimeRecoverySpecification: {
        pointInTimeRecoveryEnabled: !destroyOnRemoval,
      },
      // The table is the sole nonce authority and the only record of in-flight signed
      // bytes. Outside destroyOnRemoval deployments a delete must be a deliberate
      // two-step (disable protection, then delete), never a side effect of a stack op.
      deletionProtection: !destroyOnRemoval,
    });

    this.txTrackerTable.addGlobalSecondaryIndex({
      indexName: 'status-chain-index',
      partitionKey: { name: 'status', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'chain_id', type: dynamodb.AttributeType.NUMBER },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // ========================================
    // Secrets Manager
    // ========================================
    // Only the plaintext secrets_manager backend needs a key secret. Creating it for a
    // Nitro deployment would leave a readable (placeholder) private-key secret and a
    // grant to it on the Lambda role — attack surface with no function.
    const privateKeysSecret: secretsmanager.Secret | undefined =
      signerBackend === 'secrets_manager'
        ? new secretsmanager.Secret(this, 'EthPrivateKeys', {
            secretName: `${resourcePrefix}-private-keys`,
            description: 'Ethereum private keys for transaction signing (JSON: {"0xAddress": "privateKey"})',
            generateSecretString: {
              secretStringTemplate: JSON.stringify({ placeholder: 'replace-with-actual-keys' }),
              generateStringKey: 'generated',
            },
            removalPolicy: dataRemovalPolicy,
          })
        : undefined;

    // ========================================
    // SQS Queues
    // ========================================
    // enforceSSL adds a queue policy denying any request without aws:SecureTransport.
    // Transaction requests carry the wallet address and calldata to be signed, so
    // plaintext delivery is not acceptable even inside the VPC.
    const deadLetterQueue = new sqs.Queue(this, 'TxDeadLetterQueue', {
      queueName: `${resourcePrefix}-dlq`,
      retentionPeriod: cdk.Duration.days(14),
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      encryption: sqs.QueueEncryption.SQS_MANAGED,
      enforceSSL: true,
    });

    this.txQueue = new sqs.Queue(this, 'TxQueue', {
      queueName: `${resourcePrefix}-queue`,
      visibilityTimeout: cdk.Duration.seconds(180),
      retentionPeriod: cdk.Duration.days(1),
      deadLetterQueue: { queue: deadLetterQueue, maxReceiveCount: 3 },
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      encryption: sqs.QueueEncryption.SQS_MANAGED,
      enforceSSL: true,
    });

    const replacementDeadLetterQueue = new sqs.Queue(this, 'ReplacementDeadLetterQueue', {
      queueName: `${resourcePrefix}-replacement-dlq`,
      retentionPeriod: cdk.Duration.days(14),
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      encryption: sqs.QueueEncryption.SQS_MANAGED,
      enforceSSL: true,
    });

    this.replacementQueue = new sqs.Queue(this, 'ReplacementQueue', {
      queueName: `${resourcePrefix}-replacement`,
      visibilityTimeout: cdk.Duration.seconds(180),
      retentionPeriod: cdk.Duration.days(1),
      deadLetterQueue: { queue: replacementDeadLetterQueue, maxReceiveCount: 3 },
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      encryption: sqs.QueueEncryption.SQS_MANAGED,
      enforceSSL: true,
    });


    // ========================================
    // Lambda Function (tx_broadcast_lambda)
    // ========================================
    // The log group is declared rather than using the deprecated `logRetention` prop.
    // `logRetention` provisions a custom-resource Lambda that calls PutRetentionPolicy at
    // deploy time, which needs logs:* on every log group in the account; declaring the
    // group directly removes that Lambda, its role, and its wildcard permissions.
    const broadcastLogGroup = new logs.LogGroup(this, 'BroadcastLogGroup', {
      logGroupName: `/aws/lambda/${resourcePrefix}-broadcast`,
      retention: logs.RetentionDays.TWO_WEEKS,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    this.broadcastFunction = new lambda.DockerImageFunction(this, 'TxBroadcastFunction', {
      functionName: `${resourcePrefix}-broadcast`,
      description: 'Broadcasts Ethereum transactions with atomic nonce management',
      code: lambda.DockerImageCode.fromImageAsset(
        path.join(__dirname, '../..'),
        {
          file: 'tx_broadcast_lambda/Dockerfile',
          platform: cdk.aws_ecr_assets.Platform.LINUX_ARM64,
        }
      ),
      architecture: lambda.Architecture.ARM_64,
      memorySize: 256,
      timeout: cdk.Duration.seconds(30),
      reservedConcurrentExecutions: lambdaReservedConcurrency,
      vpc: this.vpc,
      vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
      securityGroups: [lambdaSg],
      environment: {
        ...(rpcSecretArn ? { RPC_SECRET_ARN: rpcSecretArn } : { RPC_URL: rpcUrl }),
        CHAIN_ID: chainId.toString(),
        ...(privateKeysSecret && { SECRETS_NAME: privateKeysSecret.secretName }),
        DYNAMODB_TABLE: this.txTrackerTable.tableName,
        TTL_DAYS: ttlDays.toString(),
        REPLACEMENT_ENABLED: replacementEnabled.toString(),
        DEFAULT_MAX_FEE_PER_GAS_WEI: defaultMaxFeePerGasWei,
        HARD_MAX_FEE_PER_GAS_WEI: hardMaxFeePerGasWei,
        DEFAULT_MAX_TOTAL_FEE_WEI: defaultMaxTotalFeeWei,
        HARD_MAX_TOTAL_FEE_WEI: hardMaxTotalFeeWei,
        MAX_REPLACEMENT_ATTEMPTS: maxReplacementAttempts.toString(),
        FEE_TIP_FLOOR_WEI: feeTipFloorWei,
        RUST_LOG: 'info',
        // Nitro Enclave config (optional)
        ...(nitroEndpoint && { NITRO_ENDPOINT: nitroEndpoint }),
        ...(nitroSecretId && { NITRO_SECRET_ID: nitroSecretId }),
        ...(nitroEndpoint && resolvedNitroAuthRoleArn && { NITRO_AUTH_ROLE_ARN: resolvedNitroAuthRoleArn }),
        ...(signerBackend && { SIGNER_BACKEND: signerBackend }),
        ...(nitroEndpoint && nitroCaCertPem && { NITRO_CA_CERT_PEM: nitroCaCertPem }),
        ...(nitroEndpoint && nitroSkipTlsVerify && { NITRO_SKIP_TLS_VERIFY: 'true' }),
      },
      logGroup: broadcastLogGroup,
    });

    this.txTrackerTable.grantReadWriteData(this.broadcastFunction);
    privateKeysSecret?.grantRead(this.broadcastFunction);
    const rpcSecret = rpcSecretArn
      ? secretsmanager.Secret.fromSecretCompleteArn(this, 'RpcSecret', rpcSecretArn)
      : undefined;
    rpcSecret?.grantRead(this.broadcastFunction);

    // Nitro SigV4 auth: the broadcast Lambda assumes the Nitro stack's dedicated,
    // zero-permission signing-client role to obtain an identity the service's allowlist
    // pins. The grant is `sts:AssumeRole` on exactly that one role ARN — a single literal
    // resource, no wildcard and no other action — so the Lambda can mint that identity
    // and nothing more. The assumed role itself carries no permissions, so this confers
    // no access beyond being recognized by the allowlist. Least privilege: this is the
    // narrowest grant that authenticates the caller.
    if (nitroEndpoint && resolvedNitroAuthRoleArn) {
      this.broadcastFunction.addToRolePolicy(
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: ['sts:AssumeRole'],
          resources: [resolvedNitroAuthRoleArn],
        }),
      );
    }

    // batchSize 1 is load-bearing: the handler processes exactly one record and refuses
    // larger batches (no partial-batch failure reporting). maxConcurrency caps how many
    // consumers SQS drives at once.
    this.broadcastFunction.addEventSource(
      new lambdaEventSources.SqsEventSource(this.txQueue, {
        batchSize: 1,
        maxConcurrency: sqsMaxConcurrency,
      }),
    );

    const replacementLogGroup = new logs.LogGroup(this, 'ReplacementLogGroup', {
      logGroupName: `/aws/lambda/${resourcePrefix}-replacement`,
      retention: logs.RetentionDays.TWO_WEEKS,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    this.replacementFunction = new lambda.DockerImageFunction(this, 'TxReplacementFunction', {
      functionName: `${resourcePrefix}-replacement`,
      description: 'Creates policy-bounded same-nonce EIP-1559 replacements',
      code: lambda.DockerImageCode.fromImageAsset(path.join(__dirname, '../..'), {
        file: 'tx_broadcast_lambda/Dockerfile',
        platform: cdk.aws_ecr_assets.Platform.LINUX_ARM64,
      }),
      architecture: lambda.Architecture.ARM_64,
      memorySize: 256,
      timeout: cdk.Duration.seconds(30),
      reservedConcurrentExecutions: replacementReservedConcurrency,
      vpc: this.vpc,
      vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
      securityGroups: [lambdaSg],
      environment: {
        FUNCTION_MODE: 'replacement',
        ...(rpcSecretArn ? { RPC_SECRET_ARN: rpcSecretArn } : { RPC_URL: rpcUrl }),
        CHAIN_ID: chainId.toString(),
        DYNAMODB_TABLE: this.txTrackerTable.tableName,
        TTL_DAYS: ttlDays.toString(),
        REPLACEMENT_ENABLED: replacementEnabled.toString(),
        DEFAULT_MAX_FEE_PER_GAS_WEI: defaultMaxFeePerGasWei,
        HARD_MAX_FEE_PER_GAS_WEI: hardMaxFeePerGasWei,
        DEFAULT_MAX_TOTAL_FEE_WEI: defaultMaxTotalFeeWei,
        HARD_MAX_TOTAL_FEE_WEI: hardMaxTotalFeeWei,
        MAX_REPLACEMENT_ATTEMPTS: maxReplacementAttempts.toString(),
        FEE_TIP_FLOOR_WEI: feeTipFloorWei,
        RUST_LOG: 'info',
        ...(nitroEndpoint && { NITRO_ENDPOINT: nitroEndpoint }),
        ...(nitroSecretId && { NITRO_SECRET_ID: nitroSecretId }),
        ...(nitroEndpoint && resolvedNitroAuthRoleArn && { NITRO_AUTH_ROLE_ARN: resolvedNitroAuthRoleArn }),
        ...(signerBackend && { SIGNER_BACKEND: signerBackend }),
        ...(nitroEndpoint && nitroCaCertPem && { NITRO_CA_CERT_PEM: nitroCaCertPem }),
        ...(nitroEndpoint && nitroSkipTlsVerify && { NITRO_SKIP_TLS_VERIFY: 'true' }),
      },
      logGroup: replacementLogGroup,
    });
    this.txTrackerTable.grantReadWriteData(this.replacementFunction);
    privateKeysSecret?.grantRead(this.replacementFunction);
    rpcSecret?.grantRead(this.replacementFunction);
    if (nitroEndpoint && resolvedNitroAuthRoleArn) {
      this.replacementFunction.addToRolePolicy(
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: ['sts:AssumeRole'],
          resources: [resolvedNitroAuthRoleArn],
        }),
      );
    }
    this.replacementFunction.addEventSource(
      new lambdaEventSources.SqsEventSource(this.replacementQueue, {
        batchSize: 1,
        maxConcurrency: replacementReservedConcurrency,
      }),
    );

    // ========================================
    // ECS Cluster & Fargate Service (tx_watcher)
    // ========================================
    const cluster = new ecs.Cluster(this, 'TxManagerCluster', {
      vpc: this.vpc,
      clusterName: `${resourcePrefix}-cluster`,
      containerInsightsV2: ecs.ContainerInsights.ENABLED,
    });

    const watcherLogGroup = new logs.LogGroup(this, 'WatcherLogGroup', {
      logGroupName: `/ecs/${resourcePrefix}-watcher`,
      retention: logs.RetentionDays.TWO_WEEKS,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    const watcherTaskDef = new ecs.FargateTaskDefinition(this, 'WatcherTaskDef', {
      memoryLimitMiB: watcherMemory,
      cpu: watcherCpu,
      runtimePlatform: {
        cpuArchitecture: ecs.CpuArchitecture.ARM64,
        operatingSystemFamily: ecs.OperatingSystemFamily.LINUX,
      },
    });

    watcherTaskDef.addContainer('TxWatcher', {
      image: ecs.ContainerImage.fromAsset(path.join(__dirname, '../..'), {
        file: 'tx_watcher/Dockerfile',
        platform: cdk.aws_ecr_assets.Platform.LINUX_ARM64,
      }),
      logging: ecs.LogDrivers.awsLogs({
        streamPrefix: 'tx-watcher',
        logGroup: watcherLogGroup,
      }),
      environment: {
        ...(rpcSecretArn ? { RPC_SECRET_ARN: rpcSecretArn } : { WS_RPC_URL: wsRpcUrl, HTTP_RPC_URL: rpcUrl }),
        DYNAMODB_TABLE: this.txTrackerTable.tableName,
        CHAIN_ID: chainId.toString(),
        REQUIRED_CONFIRMATIONS: requiredConfirmations.toString(),
        STUCK_THRESHOLD_SECS: stuckThresholdSecs.toString(),
        // The watcher stamps the TTL on terminal rows; without this it silently uses its
        // compiled default and the ttlDays context has no effect on tracker rows.
        TTL_DAYS: ttlDays.toString(),
        HEARTBEAT_PATH: '/tmp/tx_watcher_heartbeat',
        ...(replacementEnabled && { REPLACEMENT_QUEUE_URL: this.replacementQueue.queueUrl }),
        RUST_LOG: 'info',
      },
      // Progress health check, not just liveness: the watcher rewrites the heartbeat
      // file after every fully processed block. If it goes stale for watcherStallSecs
      // the task is unhealthy and ECS replaces it — a hung-but-running watcher (silent
      // WebSocket stall, wedged loop) is otherwise invisible to RunningTaskCount.
      healthCheck: {
        command: [
          'CMD-SHELL',
          `test -f /tmp/tx_watcher_heartbeat && [ $(( $(date +%s) - $(cat /tmp/tx_watcher_heartbeat) )) -lt ${watcherStallSecs} ]`,
        ],
        interval: cdk.Duration.seconds(60),
        timeout: cdk.Duration.seconds(5),
        retries: 3,
        // Covers image start, WebSocket connect, and reconnect catch-up before the first
        // block-driven heartbeat (a baseline heartbeat is written at startup).
        startPeriod: cdk.Duration.seconds(120),
      },
    });

    this.txTrackerTable.grantReadWriteData(watcherTaskDef.taskRole);
    if (replacementEnabled) this.replacementQueue.grantSendMessages(watcherTaskDef.taskRole);
    rpcSecret?.grantRead(watcherTaskDef.taskRole);

    this.watcherService = new ecs.FargateService(this, 'WatcherService', {
      cluster,
      taskDefinition: watcherTaskDef,
      desiredCount: 1,
      serviceName: `${resourcePrefix}-watcher`,
      vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
      securityGroups: [watcherSg],
      circuitBreaker: { rollback: true },
      minHealthyPercent: 0,  // Allow full replacement for single-task service
      maxHealthyPercent: 100,
    });


    // ========================================
    // CloudWatch Alarms
    // ========================================
    if (!alarmEmail && !alarmTopicArn) {
      const msg =
        'No alarm subscriber configured (alarmEmail or alarmTopicArn). Alarms will publish ' +
        'to an SNS topic nobody receives.';
      if (environment === 'prod' && !synthMode) {
        throw new Error(`${msg} This is required for environment=prod.`);
      }
      cdk.Annotations.of(this).addWarning(msg);
    }
    // The topic is encrypted with a customer-managed key, not the AWS-managed SNS key:
    // CloudWatch alarms publish with the *service principal*, and the AWS-managed key's
    // policy does not admit it — alarms would be silently dropped at the KMS boundary.
    // The key policy below is what makes the alarm → topic delivery work at all.
    let alarmTopic: sns.ITopic;
    if (alarmTopicArn) {
      alarmTopic = sns.Topic.fromTopicArn(this, 'AlarmTopic', alarmTopicArn);
    } else {
      const alarmTopicKey = new kms.Key(this, 'AlarmTopicKey', {
        description: `SSE for ${resourcePrefix}-alarms (policy admits CloudWatch alarms)`,
        enableKeyRotation: true,
        removalPolicy: dataRemovalPolicy,
      });
      alarmTopicKey.addToResourcePolicy(
        new iam.PolicyStatement({
          sid: 'AllowCloudWatchAlarmsToPublishEncrypted',
          principals: [new iam.ServicePrincipal('cloudwatch.amazonaws.com')],
          actions: ['kms:Decrypt', 'kms:GenerateDataKey*'],
          resources: ['*'],
          conditions: {
            StringEquals: { 'aws:SourceAccount': cdk.Stack.of(this).account },
            ArnLike: {
              'aws:SourceArn': cdk.Stack.of(this).formatArn({
                service: 'cloudwatch',
                resource: 'alarm',
                resourceName: '*',
                arnFormat: cdk.ArnFormat.COLON_RESOURCE_NAME,
              }),
            },
          },
        })
      );
      alarmTopic = new sns.Topic(this, 'AlarmTopic', {
        topicName: `${resourcePrefix}-alarms`,
        displayName: `TX Manager Alarms (${resourcePrefix})`,
        enforceSSL: true,
        masterKey: alarmTopicKey,
      });
      // enforceSSL materializes a topic policy, and a topic with a resource policy only
      // authorizes what that policy allows: without this statement the CloudWatch
      // alarms principal cannot publish at all ("CloudWatch Alarms is not authorized to
      // perform: SNS:Publish"), and every alarm fails silently. Found live: this was
      // latent before the CMK change too.
      alarmTopic.addToResourcePolicy(
        new iam.PolicyStatement({
          sid: 'AllowCloudWatchAlarmsPublish',
          principals: [new iam.ServicePrincipal('cloudwatch.amazonaws.com')],
          actions: ['sns:Publish'],
          resources: [alarmTopic.topicArn],
          conditions: {
            StringEquals: { 'aws:SourceAccount': cdk.Stack.of(this).account },
            ArnLike: {
              'aws:SourceArn': cdk.Stack.of(this).formatArn({
                service: 'cloudwatch',
                resource: 'alarm',
                resourceName: '*',
                arnFormat: cdk.ArnFormat.COLON_RESOURCE_NAME,
              }),
            },
          },
        })
      );
    }
    if (alarmEmail && !alarmTopicArn) {
      alarmTopic.addSubscription(new sns_subscriptions.EmailSubscription(alarmEmail));
    }

    const lambdaErrors = this.broadcastFunction.metricErrors({ period: cdk.Duration.minutes(5) });
    const lambdaDuration = this.broadcastFunction.metricDuration({ period: cdk.Duration.minutes(5), statistic: 'p99' });
    const alarmAction = new cloudwatch_actions.SnsAction(alarmTopic);

    const lambdaErrorAlarm = new cloudwatch.Alarm(this, 'LambdaErrorAlarm', {
      metric: lambdaErrors,
      threshold: 1,
      evaluationPeriods: 2,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
      alarmDescription: 'TX Broadcast Lambda error rate',
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
    lambdaErrorAlarm.addAlarmAction(alarmAction);

    const lambdaDurationAlarm = new cloudwatch.Alarm(this, 'LambdaDurationAlarm', {
      metric: lambdaDuration,
      threshold: 25000,
      evaluationPeriods: 2,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
      alarmDescription: 'TX Broadcast Lambda p99 duration exceeds 25s',
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
    lambdaDurationAlarm.addAlarmAction(alarmAction);

    const replacementErrorAlarm = new cloudwatch.Alarm(this, 'ReplacementLambdaErrorAlarm', {
      metric: this.replacementFunction.metricErrors({ period: cdk.Duration.minutes(5) }),
      threshold: 0,
      evaluationPeriods: 1,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
      alarmDescription: 'Dynamic replacement Lambda errors',
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
    replacementErrorAlarm.addAlarmAction(alarmAction);

    const replacementDlqAlarm = new cloudwatch.Alarm(this, 'ReplacementDlqMessageAlarm', {
      metric: replacementDeadLetterQueue.metricApproximateNumberOfMessagesVisible({ period: cdk.Duration.minutes(5) }),
      threshold: 0,
      evaluationPeriods: 1,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
      alarmDescription: 'Messages in replacement dead letter queue',
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
    replacementDlqAlarm.addAlarmAction(alarmAction);

    const replacementAgeAlarm = new cloudwatch.Alarm(this, 'ReplacementQueueAgeAlarm', {
      metric: this.replacementQueue.metricApproximateAgeOfOldestMessage({ period: cdk.Duration.minutes(5), statistic: 'Maximum' }),
      threshold: 300,
      evaluationPeriods: 2,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
      alarmDescription: 'Oldest dynamic replacement request is older than 5 minutes',
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
    replacementAgeAlarm.addAlarmAction(alarmAction);

    const replacementExhaustedAlarm = new cloudwatch.Alarm(this, 'ReplacementPolicyExhaustedAlarm', {
      metric: new cloudwatch.Metric({
        namespace: 'TxManager/Replacement',
        metricName: 'ReplacementPolicyExhausted',
        dimensionsMap: { ChainId: chainId.toString() },
        period: cdk.Duration.minutes(5),
        statistic: 'Sum',
      }),
      threshold: 0,
      evaluationPeriods: 1,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
      alarmDescription: 'A transaction exhausted its bounded replacement policy',
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
    replacementExhaustedAlarm.addAlarmAction(alarmAction);

    const dlqAlarm = new cloudwatch.Alarm(this, 'DlqMessageAlarm', {
      metric: deadLetterQueue.metricApproximateNumberOfMessagesVisible({ period: cdk.Duration.minutes(5) }),
      threshold: 0,
      evaluationPeriods: 1,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
      alarmDescription: 'Messages in TX dead letter queue',
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
    dlqAlarm.addAlarmAction(alarmAction);

    const ecsAlarm = new cloudwatch.Alarm(this, 'EcsRunningTaskCountAlarm', {
      metric: new cloudwatch.Metric({
        namespace: 'ECS/ContainerInsights',
        metricName: 'RunningTaskCount',
        dimensionsMap: {
          ClusterName: cluster.clusterName,
          ServiceName: this.watcherService.serviceName,
        },
        period: cdk.Duration.minutes(5),
        statistic: 'Minimum',
      }),
      threshold: 1,
      evaluationPeriods: 2,
      comparisonOperator: cloudwatch.ComparisonOperator.LESS_THAN_THRESHOLD,
      alarmDescription: 'ECS watcher service running task count dropped below 1',
      // When the service is fully down (or Container Insights stops publishing) the
      // metric goes MISSING rather than 0. The default treatment would keep the alarm
      // OK during exactly the outage it exists to catch.
      treatMissingData: cloudwatch.TreatMissingData.BREACHING,
    });
    ecsAlarm.addAlarmAction(alarmAction);

    // Watcher progress: the watcher emits one EMF `BlocksProcessed` datapoint per fully
    // processed block (namespace TxManager/Watcher, dimension ChainId). Zero or MISSING
    // over two consecutive periods means no block was processed for >= 2 x
    // watcherStallSecs, whether the task is dead, stalled, or wedged.
    const watcherProgressAlarm = new cloudwatch.Alarm(this, 'WatcherBlockProgressAlarm', {
      metric: new cloudwatch.Metric({
        namespace: 'TxManager/Watcher',
        metricName: 'BlocksProcessed',
        dimensionsMap: { ChainId: chainId.toString() },
        period: cdk.Duration.seconds(watcherStallSecs),
        statistic: 'Sum',
      }),
      threshold: 1,
      evaluationPeriods: 2,
      comparisonOperator: cloudwatch.ComparisonOperator.LESS_THAN_THRESHOLD,
      alarmDescription: `TX watcher processed no blocks for ${2 * watcherStallSecs}s (dead, stalled, or wedged)`,
      treatMissingData: cloudwatch.TreatMissingData.BREACHING,
    });
    watcherProgressAlarm.addAlarmAction(alarmAction);

    // Queue age: messages that sit longer than the Lambda can be retried within the
    // visibility window indicate a stuck consumer (throttled, erroring, or wedged wallet).
    const queueAgeAlarm = new cloudwatch.Alarm(this, 'QueueOldestMessageAgeAlarm', {
      metric: this.txQueue.metricApproximateAgeOfOldestMessage({
        period: cdk.Duration.minutes(5),
        statistic: 'Maximum',
      }),
      threshold: 600,
      evaluationPeriods: 2,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
      alarmDescription: 'Oldest message in the TX queue is older than 10 minutes',
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
    queueAgeAlarm.addAlarmAction(alarmAction);

    const lambdaThrottleAlarm = new cloudwatch.Alarm(this, 'LambdaThrottleAlarm', {
      metric: this.broadcastFunction.metricThrottles({ period: cdk.Duration.minutes(5) }),
      threshold: 0,
      evaluationPeriods: 1,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
      alarmDescription: 'TX Broadcast Lambda invocations throttled',
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
    lambdaThrottleAlarm.addAlarmAction(alarmAction);

    const dynamoThrottleAlarm = new cloudwatch.Alarm(this, 'DynamoDbThrottledRequestsAlarm', {
      metric: this.txTrackerTable.metricThrottledRequestsForOperations({
        operations: [
          dynamodb.Operation.PUT_ITEM,
          dynamodb.Operation.GET_ITEM,
          dynamodb.Operation.QUERY,
          dynamodb.Operation.UPDATE_ITEM,
          dynamodb.Operation.DELETE_ITEM,
          dynamodb.Operation.TRANSACT_WRITE_ITEMS,
        ],
        period: cdk.Duration.minutes(5),
      }),
      threshold: 0,
      evaluationPeriods: 1,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
      alarmDescription: 'DynamoDB throttled requests on TX tracker table (nonce path is latency-critical)',
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
    dynamoThrottleAlarm.addAlarmAction(alarmAction);

    const dynamoAlarm = new cloudwatch.Alarm(this, 'DynamoDbSystemErrorsAlarm', {
      metric: this.txTrackerTable.metricSystemErrorsForOperations({
        operations: [dynamodb.Operation.PUT_ITEM, dynamodb.Operation.GET_ITEM, dynamodb.Operation.QUERY, dynamodb.Operation.UPDATE_ITEM],
        period: cdk.Duration.minutes(5),
      }),
      threshold: 0,
      evaluationPeriods: 1,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
      alarmDescription: 'DynamoDB system errors on TX tracker table',
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
    dynamoAlarm.addAlarmAction(alarmAction);

    // ========================================
    // Outputs
    // ========================================
    new cdk.CfnOutput(this, 'BroadcastFunctionArn', {
      value: this.broadcastFunction.functionArn,
      description: 'Lambda ARN for direct invocation (broadcast + sign-hash)',
      exportName: `${resourcePrefix}-BroadcastFunctionArn`,
    });

    new cdk.CfnOutput(this, 'QueueUrl', {
      value: this.txQueue.queueUrl,
      description: 'SQS Queue URL for async transaction submission',
      exportName: `${resourcePrefix}-QueueUrl`,
    });

    new cdk.CfnOutput(this, 'ReplacementQueueUrl', {
      value: this.replacementQueue.queueUrl,
      description: 'Internal queue for watcher-driven replacement requests',
    });

    new cdk.CfnOutput(this, 'ReplacementFunctionArn', {
      value: this.replacementFunction.functionArn,
      description: 'Dedicated policy-bounded replacement Lambda',
    });

    new cdk.CfnOutput(this, 'DynamoDbEncryptionMode', {
      value: dynamoDbKmsKeyArn
        ? 'CUSTOMER_MANAGED_EXISTING'
        : createDynamoDbKmsKey
          ? 'CUSTOMER_MANAGED_STACK'
          : 'AWS_OWNED',
      description: 'DynamoDB tracker table encryption mode',
    });
    if (dynamoDbEncryptionKey) {
      new cdk.CfnOutput(this, 'DynamoDbKmsKeyArn', {
        value: dynamoDbEncryptionKey.keyArn,
        description: 'Customer-managed KMS key used by the DynamoDB tracker table',
      });
    }

    new cdk.CfnOutput(this, 'TxTrackerTableName', {
      value: this.txTrackerTable.tableName,
      description: 'DynamoDB table for transaction tracking',
      exportName: `${resourcePrefix}-TxTrackerTableName`,
    });

    new cdk.CfnOutput(this, 'EcsClusterName', {
      value: cluster.clusterName,
      description: 'ECS cluster name',
    });

    new cdk.CfnOutput(this, 'WatcherServiceName', {
      value: this.watcherService.serviceName,
      description: 'TX Watcher ECS service name',
    });

    if (privateKeysSecret) {
      new cdk.CfnOutput(this, 'PrivateKeysSecretArn', {
        value: privateKeysSecret.secretArn,
        description: 'Secrets Manager ARN (update with actual private keys)',
      });
    }

    new cdk.CfnOutput(this, 'AlarmTopicArn', {
      value: alarmTopic.topicArn,
      description: 'SNS topic for CloudWatch alarm notifications (subscribe to receive alerts)',
    });

    // Tags
    cdk.Tags.of(this).add('Application', 'eth-tx-manager');
    cdk.Tags.of(this).add('Environment', environment);
    cdk.Tags.of(this).add('ChainId', chainId.toString());
    cdk.Tags.of(this).add('ResourcePrefix', resourcePrefix);

    // ========================================
    // cdk-nag suppressions
    //
    // Attached per resource with `appliesTo` narrowed to the exact finding, so a new
    // wildcard or managed policy on the same role still fails synth. Nothing here is
    // stack-wide.
    // ========================================
    NagSuppressions.addResourceSuppressions(
      this.broadcastFunction,
      [
        {
          id: 'AwsSolutions-IAM4',
          reason:
            'AWSLambdaBasicExecutionRole and AWSLambdaVPCAccessExecutionRole are the ' +
            'AWS-managed policies for CloudWatch Logs and the ENI permissions a ' +
            'VPC-attached Lambda requires. Both are scoped to what Lambda itself needs.',
          appliesTo: [
            'Policy::arn:<AWS::Partition>:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole',
            'Policy::arn:<AWS::Partition>:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole',
          ],
        },
        {
          id: 'AwsSolutions-IAM5',
          reason:
            'grantReadWriteData emits the table ARN plus /index/*, which is required to ' +
            'query status-chain-index. Index names are not enumerable in an IAM resource ' +
            'ARN, and the wildcard cannot reach beyond this one table.',
          appliesTo: [
            'Resource::<TxTrackerTable2D01E699.Arn>/index/*',
            'Action::kms:GenerateDataKey*',
            'Action::kms:ReEncrypt*',
          ],
        },
      ],
      true,
    );

    NagSuppressions.addResourceSuppressions(
      this.replacementFunction,
      [
        {
          id: 'AwsSolutions-IAM4',
          reason: 'AWSLambdaBasicExecutionRole and AWSLambdaVPCAccessExecutionRole are required by a VPC-attached Lambda.',
          appliesTo: [
            'Policy::arn:<AWS::Partition>:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole',
            'Policy::arn:<AWS::Partition>:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole',
          ],
        },
        {
          id: 'AwsSolutions-IAM5',
          reason: 'grantReadWriteData emits this table-specific /index/* ARN; the wildcard cannot reach beyond this tracker table.',
          appliesTo: [
            'Resource::<TxTrackerTable2D01E699.Arn>/index/*',
            'Action::kms:GenerateDataKey*',
            'Action::kms:ReEncrypt*',
          ],
        },
      ],
      true,
    );

    NagSuppressions.addResourceSuppressions(
      watcherTaskDef,
      [
        {
          id: 'AwsSolutions-IAM5',
          reason:
            'Two distinct wildcards. The table /index/* grant is required to query ' +
            'status-chain-index and cannot name indexes explicitly. ecr:GetAuthorizationToken ' +
            'is an account-level call that AWS does not permit to be resource-scoped; the ' +
            'token it returns is still constrained by the per-repository grant beside it.',
          appliesTo: [
            'Resource::<TxTrackerTable2D01E699.Arn>/index/*',
            'Action::kms:GenerateDataKey*',
            'Action::kms:ReEncrypt*',
            'Resource::*',
          ],
        },
        {
          id: 'AwsSolutions-ECS2',
          reason:
            'These variables are endpoints and tuning values (RPC URL, table name, chain ' +
            'id, confirmation counts), not credentials. The watcher reads no secret: it ' +
            'holds no signing key and reaches DynamoDB through its task role. Signing keys ' +
            'live only in the Nitro enclave stack.',
        },
      ],
      true,
    );

    if (privateKeysSecret) {
      NagSuppressions.addResourceSuppressions(privateKeysSecret, [
      {
        id: 'AwsSolutions-SMG4',
        reason:
          'Rotation would mint a new random value for a secret whose contents are ' +
          'Ethereum private keys. A wallet address is derived from its key and is on-chain, ' +
          'so rotating in place would abandon the funds at the old address. Key replacement ' +
          'is a deliberate operator action that moves balances first.',
      },
      ]);
    }
  }
}
