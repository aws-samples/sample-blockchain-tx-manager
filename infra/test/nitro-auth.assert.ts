/**
 * Standalone synth assertions for Nitro broadcast authorization wiring.
 *
 * Run with: npx ts-node test/nitro-auth.assert.ts
 *
 * There is no jest harness in this package, so this is a plain script: each check throws
 * on failure (the assertions library throws when a match is not found), and the script
 * prints a PASS line and exits 0 only if every check holds. Synthesis runs with bundling
 * disabled (`aws:cdk:bundling-stacks: []`) so it needs no Docker and no AWS credentials.
 *
 * It proves the two TS-side halves of the design:
 *   1. the broadcast Lambda gets NITRO_AUTH_ROLE_ARN in its environment, and is granted
 *      sts:AssumeRole on exactly that one ARN (a literal string, never a wildcard);
 *   2. a real deploy of the nitro backend without nitroAuthRoleArn fails fast.
 */
import * as cdk from 'aws-cdk-lib';
import { Match, Template } from 'aws-cdk-lib/assertions';
import { TxManagerStack } from '../lib/tx-manager-stack';

const DUMMY_ARN = 'arn:aws:iam::111122223333:role/synthmode-nitro-signing-client';
const RPC_SECRET_ARN = 'arn:aws:secretsmanager:us-east-1:111122223333:secret:tx/rpc-AbCdEf';
const CA_PEM = '-----BEGIN CERTIFICATE-----\nMIIDATCCAemgAwIBAgIURXKyMJntM6ZWjCg+S5V3PRt6PXIwDQYJKoZIhvcNAQEL\nBQAwEDEOMAwGA1UEAwwFdHMtY2EwHhcNMjYwOTEwMTkwOTEzWhcNMjYwOTExMTkw\nOTEzWjAQMQ4wDAYDVQQDDAV0cy1jYTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC\nAQoCggEBAPgDiJAfsyxmhycmMZqEMM+OTxQNgx4zx6MzKNzcNST5BNm7y0MIJeZy\npPARNIkseb4SWypsgnTza5PW+vgMHMRJ7X3b81gxMMtIxvp0QY4872uhnhg+WQXk\nWDtxmZXz/kOlSDCfULsKqIGRUwtjzf7upk2bNnDPAiovLCBEaQiHmOVqyjOIC4Wv\nNnqSl3iI9/F5JObEt6kSo10Voivpn/xT6tPaRcoO1ibQpYQd6oqDkYg0lYMqegzP\n/GZKzCDedystYhrvNolBf0a8RtnwCiK4Z6W9rNb/+qm7YgV6R4R/IPzaW2Q8L0Du\nEACDFj8SFTnhzzkT64RSSTE+G2usdCECAwEAAaNTMFEwHQYDVR0OBBYEFGvpkDlb\nn5oG3YWbY39uYspEVoDzMB8GA1UdIwQYMBaAFGvpkDlbn5oG3YWbY39uYspEVoDz\nMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAGd2s45U4oYP7i8b\n8zJtVmLH4NW+mTyQY+CO51kI+0KLmkXqMKN7k+3x+rPCUbIRnMvEKtx9A3yUz2w0\n+eujTIOMYPxUyl9FQhlm433IkdxL4KpTPIAI3v06ijf8U/krf0+ngy14zAawPEd4\n8b1hKYfN4bHGpAum25Y8FUEwXU6Ouz1OXM9qCGlx4Vye/nvq+rWh3PALnbkZ7ch8\nvYMA+d2LyQNo+zL7yMG5G7hPenYW9cd2OeSl3BAOrWHbdHGN7ttg+wzZopZnEmcm\nySXUzPy9+vkDTeW/PwLt9Q7/+jNP3FWgKUKWOheaYxyYup1Mrz2FrabsH0dtsppR\nAzkSPb8=\n-----END CERTIFICATE-----';

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(`ASSERTION FAILED: ${message}`);
  }
}

// ---------------------------------------------------------------------------
// 1. Positive: synthMode stack wires env + exact sts:AssumeRole grant.
// ---------------------------------------------------------------------------
function testGrantAndEnv(): void {
  const app = new cdk.App({
    context: { synthMode: 'true', 'aws:cdk:bundling-stacks': [] },
  });
  const stack = new TxManagerStack(app, 'TxManagerSynth', {
    env: { account: '111122223333', region: 'us-east-1' },
    vpcId: 'vpc-00000000000000000',
    rpcUrl: 'https://rpc.example',
    wsRpcUrl: 'wss://rpc.example',
    signerBackend: 'nitro',
    nitroEndpoint: 'https://nlb.example',
    nitroAuthRoleArn: DUMMY_ARN,
    nitroCaCertPem: CA_PEM,
    resourcePrefix: 'test-chain',
  });
  const template = Template.fromStack(stack);

  // Env var is set on the broadcast Lambda.
  template.hasResourceProperties('AWS::Lambda::Function', {
    Environment: {
      Variables: Match.objectLike({ NITRO_AUTH_ROLE_ARN: DUMMY_ARN }),
    },
  });

  // Exactly-scoped grant: sts:AssumeRole, Allow, Resource is the literal ARN string.
  template.hasResourceProperties('AWS::IAM::Policy', {
    PolicyDocument: {
      Statement: Match.arrayWith([
        Match.objectLike({
          Action: 'sts:AssumeRole',
          Effect: 'Allow',
          Resource: DUMMY_ARN,
        }),
      ]),
    },
  });

  // Defensively confirm no sts:AssumeRole statement anywhere uses a wildcard resource.
  const policies = template.findResources('AWS::IAM::Policy');
  for (const [logicalId, policy] of Object.entries(policies)) {
    const statements = policy.Properties?.PolicyDocument?.Statement ?? [];
    for (const stmt of statements) {
      const actions = Array.isArray(stmt.Action) ? stmt.Action : [stmt.Action];
      if (actions.includes('sts:AssumeRole')) {
        assert(
          stmt.Resource === DUMMY_ARN,
          `sts:AssumeRole in ${logicalId} must target exactly ${DUMMY_ARN}, got ${JSON.stringify(stmt.Resource)}`,
        );
      }
    }
  }

  console.log('PASS: broadcast Lambda has NITRO_AUTH_ROLE_ARN env and exact sts:AssumeRole grant');
}

function testReplacementBoundary(): void {
  const app = new cdk.App({ context: { synthMode: 'true', 'aws:cdk:bundling-stacks': [] } });
  const stack = new TxManagerStack(app, 'TxManagerReplacement', {
    env: { account: '111122223333', region: 'us-east-1' },
    vpcId: 'vpc-00000000000000000',
    rpcUrl: 'https://rpc.example', wsRpcUrl: 'wss://rpc.example',
    signerBackend: 'nitro', nitroEndpoint: 'https://nlb.example',
    nitroAuthRoleArn: DUMMY_ARN, nitroCaCertPem: CA_PEM,
    resourcePrefix: 'replacement-test',
  });
  const template = Template.fromStack(stack);
  template.hasResourceProperties('AWS::Lambda::Function', {
    FunctionName: 'replacement-test-replacement',
    Environment: { Variables: Match.objectLike({
      FUNCTION_MODE: 'replacement', REPLACEMENT_ENABLED: 'true',
      HARD_MAX_FEE_PER_GAS_WEI: '500000000000',
      HARD_MAX_TOTAL_FEE_WEI: '100000000000000000',
    }) },
  });
  template.hasResourceProperties('AWS::SQS::Queue', {
    QueueName: 'replacement-test-replacement',
    RedrivePolicy: Match.objectLike({ maxReceiveCount: 3 }),
  });
  template.hasResourceProperties('AWS::ECS::TaskDefinition', {
    ContainerDefinitions: Match.arrayWith([
      Match.objectLike({ Environment: Match.arrayWith([Match.objectLike({ Name: 'REPLACEMENT_QUEUE_URL' })]) }),
    ]),
  });
  let assumeStatements = 0;
  let watcherSendPolicyFound = false;
  for (const policy of Object.values(template.findResources('AWS::IAM::Policy'))) {
    const statements = policy.Properties?.PolicyDocument?.Statement ?? [];
    const actions: string[] = statements.flatMap((stmt: { Action?: string | string[] }) =>
      (Array.isArray(stmt.Action) ? stmt.Action : [stmt.Action]).filter((a): a is string => !!a),
    );
    for (const stmt of statements) {
      const stmtActions = Array.isArray(stmt.Action) ? stmt.Action : [stmt.Action];
      if (stmtActions.includes('sts:AssumeRole')) {
        assumeStatements += 1;
        assert(stmt.Resource === DUMMY_ARN, 'replacement signer grant must target the exact Nitro role');
      }
    }
    if (actions.includes('sqs:SendMessage')) {
      watcherSendPolicyFound = true;
      assert(!actions.includes('sts:AssumeRole'), 'watcher send policy must never include Nitro AssumeRole');
    }
  }
  assert(assumeStatements === 2, `broadcast and replacement Lambdas should be the only Nitro clients, got ${assumeStatements}`);
  assert(watcherSendPolicyFound, 'watcher task role must have send-only access to replacement queue');
  template.hasResourceProperties('AWS::CloudWatch::Alarm', {
    Namespace: 'TxManager/Replacement', MetricName: 'ReplacementPolicyExhausted',
  });
  console.log('PASS: replacement queue/Lambda boundary preserves watcher non-signing and hard fee caps');
}

// ---------------------------------------------------------------------------
// 2. Negative: real deploy of nitro backend without nitroAuthRoleArn throws.
// ---------------------------------------------------------------------------
function testDeployRequiresAuthRoleArn(): void {
  const app = new cdk.App({
    context: { stackName: 'TxManager-Deploy', environment: 'dev', 'aws:cdk:bundling-stacks': [] },
  });
  let threw = false;
  let message = '';
  try {
    new TxManagerStack(app, 'TxManager-Deploy', {
      env: { account: '111122223333', region: 'us-east-1' },
      vpcId: 'vpc-real',
      rpcUrl: 'https://rpc.example',
      wsRpcUrl: 'wss://rpc.example',
      signerBackend: 'nitro',
      nitroEndpoint: 'https://nlb.example',
      // nitroAuthRoleArn deliberately omitted
    });
  } catch (err) {
    threw = true;
    message = (err as Error).message;
  }
  assert(threw, 'nitro backend deploy without nitroAuthRoleArn must throw');
  assert(
    message.includes('nitroAuthRoleArn'),
    `error must name nitroAuthRoleArn, got: ${message}`,
  );
  console.log('PASS: nitro backend deploy without nitroAuthRoleArn is rejected');
}

// ---------------------------------------------------------------------------
// 3. Alarms must have a receiver: prod without alarmEmail/alarmTopicArn throws, and
//    alarmEmail produces an SNS subscription on the alarm topic.
// ---------------------------------------------------------------------------
function testProdRequiresAlarmSubscriber(): void {
  const app = new cdk.App({
    context: { stackName: 'TxManager-Prod', environment: 'prod', 'aws:cdk:bundling-stacks': [] },
  });
  let message = '';
  try {
    new TxManagerStack(app, 'TxManager-Prod', {
      env: { account: '111122223333', region: 'us-east-1' },
      vpcId: 'vpc-real',
      rpcUrl: 'https://rpc.example',
      wsRpcUrl: 'wss://rpc.example',
      signerBackend: 'nitro',
      nitroEndpoint: 'https://nlb.example',
      nitroAuthRoleArn: DUMMY_ARN,
      nitroCaCertPem: CA_PEM,
      rpcSecretArn: RPC_SECRET_ARN,
      // alarmEmail / alarmTopicArn deliberately omitted
    });
  } catch (err) {
    message = (err as Error).message;
  }
  assert(
    message.includes('alarmEmail') && message.includes('environment=prod'),
    `prod without an alarm subscriber must throw naming alarmEmail, got: ${message}`,
  );

  const app2 = new cdk.App({
    context: { synthMode: 'true', 'aws:cdk:bundling-stacks': [] },
  });
  const stack = new TxManagerStack(app2, 'TxManagerAlarms', {
    env: { account: '111122223333', region: 'us-east-1' },
    vpcId: 'vpc-00000000000000000',
    rpcUrl: 'https://rpc.example',
    wsRpcUrl: 'wss://rpc.example',
    signerBackend: 'nitro',
    nitroEndpoint: 'https://nlb.example',
    nitroAuthRoleArn: DUMMY_ARN,
    nitroCaCertPem: CA_PEM,
    alarmEmail: 'ops@example.com',
  });
  const template = Template.fromStack(stack);
  template.hasResourceProperties('AWS::SNS::Subscription', {
    Protocol: 'email',
    Endpoint: 'ops@example.com',
  });
  // The two outage alarms must treat missing data as breaching, or they cannot fire
  // during the outage they monitor.
  template.hasResourceProperties('AWS::CloudWatch::Alarm', {
    MetricName: 'RunningTaskCount',
    TreatMissingData: 'breaching',
  });
  template.hasResourceProperties('AWS::CloudWatch::Alarm', {
    Namespace: 'TxManager/Watcher',
    MetricName: 'BlocksProcessed',
    TreatMissingData: 'breaching',
  });
  // Every alarm sets an explicit missing-data policy.
  for (const [logicalId, alarm] of Object.entries(template.findResources('AWS::CloudWatch::Alarm'))) {
    assert(
      typeof alarm.Properties?.TreatMissingData === 'string',
      `${logicalId} must set TreatMissingData explicitly`,
    );
  }
  // The watcher container has a progress health check.
  template.hasResourceProperties('AWS::ECS::TaskDefinition', {
    ContainerDefinitions: Match.arrayWith([
      Match.objectLike({
        HealthCheck: Match.objectLike({ Command: Match.arrayWith(['CMD-SHELL']) }),
      }),
    ]),
  });
  // The topic is SSE-encrypted with a customer-managed key whose policy admits the
  // CloudWatch alarms service principal — the AWS-managed SNS key cannot, and alarms
  // would be dropped silently at the KMS boundary.
  const topics = template.findResources('AWS::SNS::Topic');
  const topic = Object.values(topics)[0];
  assert(
    topic?.Properties?.KmsMasterKeyId !== undefined,
    'alarm topic must be SSE-encrypted with the stack CMK',
  );
  const keys = template.findResources('AWS::KMS::Key');
  const cwStatement = Object.values(keys)
    .flatMap((k) => k.Properties?.KeyPolicy?.Statement ?? [])
    .find((st: { Principal?: { Service?: string } }) => st.Principal?.Service === 'cloudwatch.amazonaws.com');
  assert(cwStatement, 'alarm topic key policy must admit cloudwatch.amazonaws.com');
  const cwActions: string[] = ([] as string[]).concat(cwStatement.Action);
  assert(
    cwActions.includes('kms:Decrypt') && cwActions.some((a) => a.startsWith('kms:GenerateDataKey')),
    `CloudWatch key-policy statement must allow Decrypt + GenerateDataKey*, got ${cwActions}`,
  );
  assert(
    cwStatement.Condition?.StringEquals?.['aws:SourceAccount'] !== undefined,
    'CloudWatch key-policy statement must be scoped to the account',
  );
  // The topic policy must explicitly allow the alarms principal to publish: enforceSSL
  // materializes a resource policy, and a topic with a policy only authorizes what the
  // policy allows — without this, every alarm fails with "not authorized: SNS:Publish".
  const topicPolicies = template.findResources('AWS::SNS::TopicPolicy');
  const publishAllow = Object.values(topicPolicies)
    .flatMap((tp) => tp.Properties?.PolicyDocument?.Statement ?? [])
    .find(
      (st: { Effect?: string; Principal?: { Service?: string } }) =>
        st.Effect === 'Allow' && st.Principal?.Service === 'cloudwatch.amazonaws.com',
    );
  assert(publishAllow, 'topic policy must allow cloudwatch.amazonaws.com sns:Publish');
  assert(
    ([] as string[]).concat(publishAllow.Action).includes('sns:Publish') &&
      publishAllow.Condition?.StringEquals?.['aws:SourceAccount'] !== undefined,
    'alarm publish allow must cover sns:Publish scoped to the account',
  );
  console.log('PASS: alarms require a subscriber in prod; outage alarms breach on missing data; watcher has a health check; alarm topic SSE-CMK admits CloudWatch');
}

// ---------------------------------------------------------------------------
// 4. prod cannot disable Nitro TLS verification; the tracker table is deletion-protected.
// ---------------------------------------------------------------------------
function testProdGuards(): void {
  const app = new cdk.App({
    context: { stackName: 'TxManager-Prod2', environment: 'prod', 'aws:cdk:bundling-stacks': [] },
  });
  let message = '';
  try {
    new TxManagerStack(app, 'TxManager-Prod2', {
      env: { account: '111122223333', region: 'us-east-1' },
      vpcId: 'vpc-real',
      rpcUrl: 'https://rpc.example',
      wsRpcUrl: 'wss://rpc.example',
      signerBackend: 'nitro',
      nitroEndpoint: 'https://nlb.example',
      nitroAuthRoleArn: DUMMY_ARN,
      nitroSkipTlsVerify: true,
      alarmEmail: 'ops@example.com',
      rpcSecretArn: RPC_SECRET_ARN,
    });
  } catch (err) {
    message = (err as Error).message;
  }
  assert(message.includes('nitroSkipTlsVerify'), `prod TLS skip must be rejected, got: ${message}`);

  const app2 = new cdk.App({ context: { synthMode: 'true', 'aws:cdk:bundling-stacks': [] } });
  const stack = new TxManagerStack(app2, 'TxManagerProtected', {
    env: { account: '111122223333', region: 'us-east-1' },
    vpcId: 'vpc-00000000000000000',
    rpcUrl: 'https://rpc.example',
    wsRpcUrl: 'wss://rpc.example',
    signerBackend: 'nitro',
    nitroEndpoint: 'https://nlb.example',
    nitroAuthRoleArn: DUMMY_ARN,
    nitroCaCertPem: CA_PEM,
  });
  Template.fromStack(stack).hasResourceProperties('AWS::DynamoDB::Table', {
    DeletionProtectionEnabled: true,
    PointInTimeRecoverySpecification: { PointInTimeRecoveryEnabled: true },
  });
  console.log('PASS: prod rejects TLS skip; tracker table is deletion-protected');
}

// ---------------------------------------------------------------------------
// 5. RPC credentials: prod requires rpcSecretArn; with it, no plaintext URL env var is
//    emitted and both roles may read exactly that secret.
// ---------------------------------------------------------------------------
function testRpcSecret(): void {
  const app = new cdk.App({
    context: { stackName: 'TxManager-Prod3', environment: 'prod', 'aws:cdk:bundling-stacks': [] },
  });
  let message = '';
  try {
    new TxManagerStack(app, 'TxManager-Prod3', {
      env: { account: '111122223333', region: 'us-east-1' },
      vpcId: 'vpc-real',
      rpcUrl: 'https://rpc.example/v2/KEY',
      wsRpcUrl: 'wss://rpc.example/v2/KEY',
      signerBackend: 'nitro',
      nitroEndpoint: 'https://nlb.example',
      nitroAuthRoleArn: DUMMY_ARN,
      nitroCaCertPem: CA_PEM,
      alarmEmail: 'ops@example.com',
    });
  } catch (err) {
    message = (err as Error).message;
  }
  assert(message.includes('rpcSecretArn'), `prod without rpcSecretArn must throw, got: ${message}`);

  const app2 = new cdk.App({ context: { synthMode: 'true', 'aws:cdk:bundling-stacks': [] } });
  const stack = new TxManagerStack(app2, 'TxManagerRpcSecret', {
    env: { account: '111122223333', region: 'us-east-1' },
    vpcId: 'vpc-00000000000000000',
    rpcUrl: 'https://rpc.example/v2/KEY',
    wsRpcUrl: 'wss://rpc.example/v2/KEY',
    signerBackend: 'nitro',
    nitroEndpoint: 'https://nlb.example',
    nitroAuthRoleArn: DUMMY_ARN,
    nitroCaCertPem: CA_PEM,
    rpcSecretArn: RPC_SECRET_ARN,
  });
  const template = Template.fromStack(stack);
  const rendered = JSON.stringify(template.toJSON());
  assert(!rendered.includes('v2/KEY'), 'RPC URL must not appear anywhere in the template when rpcSecretArn is set');
  template.hasResourceProperties('AWS::Lambda::Function', {
    Environment: { Variables: Match.objectLike({ RPC_SECRET_ARN: RPC_SECRET_ARN }) },
  });
  template.hasResourceProperties('AWS::ECS::TaskDefinition', {
    ContainerDefinitions: Match.arrayWith([
      Match.objectLike({
        Environment: Match.arrayWith([{ Name: 'RPC_SECRET_ARN', Value: RPC_SECRET_ARN }]),
      }),
    ]),
  });
  // Exactly-scoped read grants (Lambda role and watcher task role).
  let grants = 0;
  for (const policy of Object.values(template.findResources('AWS::IAM::Policy'))) {
    for (const stmt of policy.Properties?.PolicyDocument?.Statement ?? []) {
      const actions = Array.isArray(stmt.Action) ? stmt.Action : [stmt.Action];
      if (actions.includes('secretsmanager:GetSecretValue') && stmt.Resource === RPC_SECRET_ARN) {
        grants += 1;
      }
    }
  }
  assert(grants === 3, `expected 3 exact-ARN GetSecretValue grants (broadcast + replacement + watcher), got ${grants}`);
  console.log('PASS: prod requires rpcSecretArn; secret-sourced RPC config leaves no URL in the template');
}

// ---------------------------------------------------------------------------
// 6. Prod Nitro deploy must verify TLS: without a CA and without skip it is rejected;
//    with the CA the Lambda gets NITRO_CA_CERT_PEM and no skip flag.
// ---------------------------------------------------------------------------
function testTls(): void {
  const app = new cdk.App({
    context: { stackName: 'TxManager-Tls', environment: 'prod', 'aws:cdk:bundling-stacks': [] },
  });
  let message = '';
  try {
    new TxManagerStack(app, 'TxManager-Tls', {
      env: { account: '111122223333', region: 'us-east-1' },
      vpcId: 'vpc-real',
      rpcUrl: 'https://rpc.example/v2/KEY',
      wsRpcUrl: 'wss://rpc.example/v2/KEY',
      signerBackend: 'nitro',
      nitroEndpoint: 'https://nlb.example',
      nitroAuthRoleArn: DUMMY_ARN,
      rpcSecretArn: RPC_SECRET_ARN,
      alarmEmail: 'ops@example.com',
      // no CA, no skip
    });
  } catch (err) {
    message = (err as Error).message;
  }
  assert(message.includes('nitroCaCertPem'), `prod Nitro without a CA must be rejected, got: ${message}`);

  const app2 = new cdk.App({
    context: {
      synthMode: 'true',
      'aws:cdk:bundling-stacks': [],
      // The deploy path passes the CA base64 (multi-line values do not survive CLI
      // context); prove the stack decodes it.
      nitroCaCertB64: Buffer.from(CA_PEM.replace(/\\n/g, '\n')).toString('base64'),
    },
  });
  const stack = new TxManagerStack(app2, 'TxManagerTlsOk', {
    env: { account: '111122223333', region: 'us-east-1' },
    vpcId: 'vpc-00000000000000000',
    rpcUrl: 'https://rpc.example/v2/KEY',
    wsRpcUrl: 'wss://rpc.example/v2/KEY',
    signerBackend: 'nitro',
    nitroEndpoint: 'https://nlb.example',
    nitroAuthRoleArn: DUMMY_ARN,
  });
  const template = Template.fromStack(stack);
  template.hasResourceProperties('AWS::Lambda::Function', {
    Environment: {
      Variables: Match.objectLike({ NITRO_CA_CERT_PEM: CA_PEM.replace(/\\n/g, '\n') }),
    },
  });
  // The skip flag must NOT be present when a CA is pinned.
  const fns = template.findResources('AWS::Lambda::Function');
  for (const fn of Object.values(fns)) {
    const vars = fn.Properties?.Environment?.Variables ?? {};
    assert(vars.NITRO_SKIP_TLS_VERIFY === undefined, 'NITRO_SKIP_TLS_VERIFY must be absent when a CA is pinned');
  }
  console.log('PASS: prod Nitro requires a pinned CA; the CA wires NITRO_CA_CERT_PEM and no skip flag');
}

function testDynamoDbEncryptionModes(): void {
  const make = (id: string, extra: Record<string, unknown> = {}): Template => {
    const app = new cdk.App({ context: { synthMode: 'true', 'aws:cdk:bundling-stacks': [] } });
    const stack = new TxManagerStack(app, id, {
      env: { account: '111122223333', region: 'us-east-1' },
      vpcId: 'vpc-00000000000000000', rpcUrl: 'https://rpc.example', wsRpcUrl: 'wss://rpc.example',
      signerBackend: 'nitro', nitroEndpoint: 'https://nlb.example', nitroAuthRoleArn: DUMMY_ARN,
      nitroCaCertPem: CA_PEM, resourcePrefix: id.toLowerCase(), ...extra,
    });
    return Template.fromStack(stack);
  };

  const defaultTemplate = make('EncryptionDefault');
  const defaultTable = Object.values(defaultTemplate.findResources('AWS::DynamoDB::Table'))[0];
  assert(defaultTable.Properties?.SSESpecification?.SSEEnabled === false,
    'default DynamoDB encryption must use the AWS-owned key');

  const createdTemplate = make('EncryptionCreated', { createDynamoDbKmsKey: true });
  createdTemplate.hasResourceProperties('AWS::DynamoDB::Table', {
    SSESpecification: Match.objectLike({ SSEEnabled: true, SSEType: 'KMS' }),
  });
  const createdKeys = Object.values(createdTemplate.findResources('AWS::KMS::Key'));
  assert(createdKeys.some((key) => key.Properties?.EnableKeyRotation === true
    && String(key.Properties?.Description).includes('tracker')),
    'stack-created DynamoDB CMK must rotate and identify the tracker table');

  const importedArn = 'arn:aws:kms:us-east-1:111122223333:key/12345678-1234-1234-1234-1234567890ab';
  const importedTemplate = make('EncryptionImported', { dynamoDbKmsKeyArn: importedArn });
  importedTemplate.hasResourceProperties('AWS::DynamoDB::Table', {
    SSESpecification: Match.objectLike({
      SSEEnabled: true, SSEType: 'KMS', KMSMasterKeyId: importedArn,
    }),
  });
  const importedKeys = Object.values(importedTemplate.findResources('AWS::KMS::Key'));
  assert(!importedKeys.some((key) => String(key.Properties?.Description).includes('tracker')),
    'import mode must not create a DynamoDB CMK');
  const mrkArn = 'arn:aws:kms:us-east-1:111122223333:key/mrk-80bd4b9f0123456789abcdef01234567';
  make('EncryptionMultiRegion', { dynamoDbKmsKeyArn: mrkArn }).hasResourceProperties(
    'AWS::DynamoDB::Table',
    { SSESpecification: Match.objectLike({ KMSMasterKeyId: mrkArn }) },
  );

  let message = '';
  try {
    make('EncryptionConflict', { dynamoDbKmsKeyArn: importedArn, createDynamoDbKmsKey: true });
  } catch (err) { message = (err as Error).message; }
  assert(message.includes('mutually exclusive'), 'CMK import/create conflict must fail fast');
  console.log('PASS: DynamoDB supports AWS-owned, imported CMK, and rotating stack CMK modes');
}

testGrantAndEnv();
testDynamoDbEncryptionModes();
testReplacementBoundary();
testDeployRequiresAuthRoleArn();
testProdRequiresAlarmSubscriber();
testProdGuards();
testRpcSecret();
testTls();
console.log('ALL TS SYNTH ASSERTIONS PASSED');
