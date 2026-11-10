# Nitro Enclave Signer (eth1)

> [!NOTE]
> This is sample code from a source-only reference architecture, provided as-is under MIT-0 without warranty or support. It is not a production-ready deployment. See [Known Limitations and Customer Responsibilities](../docs/known-limitations.md).

This directory contains the Nitro Enclave-based Ethereum signing service used
by the main project. It is derived from
[`aws-samples/aws-nitro-enclave-blockchain-wallet`](https://github.com/aws-samples/aws-nitro-enclave-blockchain-wallet)
(Amazon.com, Inc., MIT-0; see [LICENSE](LICENSE)), trimmed to the `eth1`
application type. The other advanced networking patterns from the upstream
sample (`wireguard`, `socat`, `rds_integration`, `https_web_server`,
`dotnet_sqs_integration`) are not included.

For deployment, configuration, and operations, see the project-level guides:

- **[Nitro Enclave Deployment](../docs/nitro-enclave-deployment.md)**: detailed stack setup
- **[Deployment Guide](../docs/deployment-guide.md)**: full end-to-end deployment

## Background

For deeper context on the original Nitro Enclave blockchain wallet architecture
(attestation, KMS integration, enclave-to-host vsock signing), see the AWS blog
series the upstream sample was released alongside:

1. [AWS Nitro Enclaves for secure blockchain key management: Part 1](https://aws.amazon.com/blogs/web3/aws-nitro-enclaves-for-secure-blockchain-key-management-part-1/)
2. [AWS Nitro Enclaves for secure blockchain key management: Part 2](https://aws.amazon.com/blogs/web3/aws-nitro-enclaves-for-secure-blockchain-key-management-part-2/)
3. [AWS Nitro Enclaves for secure blockchain key management: Part 3](https://aws.amazon.com/blogs/web3/aws-nitro-enclaves-for-secure-blockchain-key-management-part-3/)

## Architecture

### High level
![Architecture diagram: an invoke Lambda calls an internal Network Load Balancer in a VPC, which fronts an Auto Scaling group of Nitro-capable EC2 instances across two private subnets. Each instance runs a Docker HTTP server and a Nitro Enclave signing server, and reaches Secrets Manager, KMS, ECR, and Systems Manager through VPC endpoints and a NAT gateway.](./docs/nitro_enclaves.drawio.png)

### Application
![Application diagram: on the EC2 instance, the Docker http_server receives a request from the caller and forwards it over vsock to the signing_server inside the Nitro Enclave. The enclave's kmstool-enclave-cli sends KMS calls, carrying the enclave's attestation document, through a vsock-proxy on the host to AWS KMS.](./docs/nitro_enclaves-Page-3.drawio.png)

## License

The upstream code is licensed under the MIT-0 License by Amazon.com, Inc.
See [LICENSE](LICENSE). The rest of this repository is licensed under the same
MIT No Attribution License (MIT-0); see the [root LICENSE file](../LICENSE).
