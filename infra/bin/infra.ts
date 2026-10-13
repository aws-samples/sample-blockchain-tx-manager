#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { AwsSolutionsChecks } from 'cdk-nag';
import { TxManagerStack } from '../lib/tx-manager-stack';

const app = new cdk.App();

const env = {
  account: process.env.CDK_DEFAULT_ACCOUNT,
  region: process.env.CDK_DEFAULT_REGION,
};

// ========================================
// Per-chain stack
//
// Stack name is read from --context stackName (set by deploy-chain.sh).
// All chain-specific values (chainId, resourcePrefix, rpcUrl, wsRpcUrl)
// are provided via context — no hardcoded chain values in CDK code.
//
// Each chain stack is fully self-contained: its own DynamoDB tracker table
// (the sole per-chain nonce and lifecycle authority), Lambda, ECS watcher,
// and SQS queue. It looks up the existing Nitro Enclave signer VPC directly
// from vpcId — it does not create a VPC and there is no shared stack.
//
// Nonce isolation across chains is inherent: each chain has its own table.
//
// Deploy via script:
//   VPC_ID=vpc-... ./scripts/deploy-chain.sh sepolia dev
//
// Deploy directly:
//   cdk deploy TxManager-Sepolia-Dev \
//     --context vpcId=vpc-... \
//     --context stackName=TxManager-Sepolia-Dev \
//     --context chainId=11155111 \
//     --context resourcePrefix=sepolia-dev \
//     --context rpcUrl=https://... \
//     --context wsRpcUrl=wss://...
// ========================================
const chainStackName = app.node.tryGetContext('stackName') || 'TxManagerChain';

new TxManagerStack(app, chainStackName, {
  env,
  description: `Per-chain TX Manager: ${chainStackName}`,
});

// This app handles signing keys, so it is checked against the AWS Solutions rule pack on
// every synth, the same as the Nitro signer app (nitro_enclave_signer/app.py). Findings
// are errors, not advisories: `cdk synth` fails until each one is either fixed or
// suppressed with a written justification next to the resource it applies to.
cdk.Aspects.of(app).add(new AwsSolutionsChecks({ verbose: true }));
