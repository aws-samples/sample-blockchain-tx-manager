/**
 * cdk-nag check for the TxManagerStack, Docker-free.
 *
 * Run with: npx ts-node test/nag-check.ts
 *
 * Applies the same AwsSolutionsChecks pack that bin/infra.ts applies on every deploy,
 * synthesizes the nitro-backed stack with bundling disabled, and prints every
 * unsuppressed error/warning. Suppressed findings are removed by cdk-nag before
 * annotations are attached, so anything printed here is a finding that would still block
 * a real synth. Exits non-zero if any error remains.
 */
import * as cdk from 'aws-cdk-lib';
import { Annotations, Match } from 'aws-cdk-lib/assertions';
import { AwsSolutionsChecks } from 'cdk-nag';
import { TxManagerStack } from '../lib/tx-manager-stack';

const app = new cdk.App({
  context: { synthMode: 'true', 'aws:cdk:bundling-stacks': [] },
});
const stack = new TxManagerStack(app, 'TxManagerNag', {
  env: { account: '111122223333', region: 'us-east-1' },
  vpcId: 'vpc-00000000000000000',
  rpcUrl: 'https://rpc.example',
  wsRpcUrl: 'wss://rpc.example',
  signerBackend: 'nitro',
  nitroEndpoint: 'https://nlb.example',
  nitroAuthRoleArn: 'arn:aws:iam::111122223333:role/synthmode-nitro-signing-client',
  resourcePrefix: 'nag-chain',
});
cdk.Aspects.of(app).add(new AwsSolutionsChecks({ verbose: true }));
app.synth();

const errors = Annotations.fromStack(stack).findError('*', Match.stringLikeRegexp('AwsSolutions-.*'));
const warnings = Annotations.fromStack(stack).findWarning(
  '*',
  Match.stringLikeRegexp('AwsSolutions-.*'),
);

console.log(`cdk-nag errors:   ${errors.length}`);
for (const e of errors) {
  console.log(`  ERROR ${e.id}: ${JSON.stringify(e.entry.data)}`);
}
console.log(`cdk-nag warnings: ${warnings.length}`);
for (const w of warnings) {
  console.log(`  WARN  ${w.id}: ${JSON.stringify(w.entry.data)}`);
}

if (errors.length > 0) {
  process.exit(1);
}
console.log('NO UNSUPPRESSED cdk-nag ERRORS');
