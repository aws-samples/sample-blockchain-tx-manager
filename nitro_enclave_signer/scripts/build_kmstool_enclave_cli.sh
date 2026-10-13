#!/usr/bin/env bash
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

set +x
set -euo pipefail

CONTAINER_RUNTIME="${CDK_DOCKER:-docker}"
command -v "$CONTAINER_RUNTIME" >/dev/null 2>&1 || {
  echo "Error: container runtime '$CONTAINER_RUNTIME' not found (set CDK_DOCKER)." >&2
  exit 1
}
RUNTIME_PATH=$(command -v "$CONTAINER_RUNTIME")
# Upstream's pinned build.sh invokes `docker` literally. Put a process-local shim first
# on PATH so the published Finch workflow works without patching or installing a daemon.
RUNTIME_SHIM=$(mktemp -d)
printf '#!/usr/bin/env bash\nexec %q "$@"\n' "$RUNTIME_PATH" > "$RUNTIME_SHIM/docker"
chmod +x "$RUNTIME_SHIM/docker"
trap 'rm -rf "$RUNTIME_SHIM"' EXIT
export PATH="$RUNTIME_SHIM:$PATH"

NITRO_ENCLAVE_CLI_VERSION="v0.4.3"
RUST_TOOLCHAIN_VERSION="1.94.1"
KMS_FOLDER="./application/eth1/enclave/kms"
KMSTOOL_FOLDER="./aws-nitro-enclaves-sdk-c/bin/kmstool-enclave-cli"
TARGET_PLATFORM="linux/amd64"

if [[ ! -d ${KMS_FOLDER} ]]; then
  mkdir -p ${KMS_FOLDER}
fi

# delete repo if already there or if folder exists
rm -rf "${KMS_FOLDER}/aws-nitro-enclaves-sdk-c"

cd ${KMS_FOLDER}
git clone --depth 1 --branch ${NITRO_ENCLAVE_CLI_VERSION} https://github.com/aws/aws-nitro-enclaves-sdk-c.git

# Patch Dockerfile to:
# 1. Add GOPROXY=direct for corporate networks
# 2. Update Rust before building nsm-api (wit-bindgen requires Rust 2024 edition)
cd ./aws-nitro-enclaves-sdk-c/containers

awk -v rust_toolchain="$RUST_TOOLCHAIN_VERSION" '
NR==1 {print; print "ARG GOPROXY=direct"; next}
/^RUN git clone --depth 1 -b v0.4.0 https:\/\/github.com\/aws\/aws-nitro-enclaves-nsm-api.git/ {
    print "RUN source $HOME/.cargo/env && rustup toolchain install " rust_toolchain " && rustup default " rust_toolchain
    print
    next
}
{print}
' Dockerfile.al2 > Dockerfile.al2_new

cd ../../

cd ${KMSTOOL_FOLDER}

sed "s|-f ../../containers/Dockerfile.al2 ../..|-f ../../containers/Dockerfile.al2_new ../.. --platform=${TARGET_PLATFORM}|g" build.sh >build.sh_new
mv build.sh_new build.sh
chmod +x build.sh
./build.sh

cp ./kmstool_enclave_cli ../../../kmstool_enclave_cli
cp ./libnsm.so ../../../libnsm.so

cd -

rm -rf ./aws-nitro-enclaves-sdk-c
rm -rf "$RUNTIME_SHIM"
trap - EXIT

echo "kmstool_enclave_cli build successful ($CONTAINER_RUNTIME)"
