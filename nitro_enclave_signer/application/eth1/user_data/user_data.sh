Content-Type: multipart/mixed; boundary="//"
MIME-Version: 1.0

--//
Content-Type: text/cloud-config; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit
Content-Disposition: attachment; filename="cloud-config.txt"

#cloud-config
packages:
  - aws-nitro-enclaves-cli
  - aws-nitro-enclaves-cli-devel
  - docker
  - htop
  - git
  - jq

--//
Content-Type: text/x-shellscript; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit
Content-Disposition: attachment; filename="userdata.txt"

#!/bin/bash
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

exec > >(tee /var/log/user-data.log | logger -t user-data -s 2>/dev/console) 2>&1

set -x
set +e

# if specific operations should be executed in `dev` deployment use section below
#if [[ ${__DEV_MODE__} == "dev" ]]; then
#
#fi

usermod -aG docker ec2-user
usermod -aG ne ec2-user

ALLOCATOR_YAML=/etc/nitro_enclaves/allocator.yaml
MEM_KEY=memory_mib
CPU_KEY=cpu_count
DEFAULT_MEM=6144
DEFAULT_CPU=2

sed -r "s/^(\s*$MEM_KEY\s*:\s*).*/\1$DEFAULT_MEM/" -i "$ALLOCATOR_YAML"
sed -r "s/^(\s*$CPU_KEY\s*:\s*).*/\1$DEFAULT_CPU/" -i "$ALLOCATOR_YAML"

VSOCK_PROXY_YAML=/etc/nitro_enclaves/vsock-proxy.yaml
cat <<'EOF' > $VSOCK_PROXY_YAML
allowlist:
- {address: kms.${__REGION__}.amazonaws.com, port: 443}
- {address: kms-fips.${__REGION__}.amazonaws.com, port: 443}

EOF

systemctl enable --now docker
systemctl enable --now nitro-enclaves-allocator.service
systemctl enable --now nitro-enclaves-vsock-proxy.service

cd /home/ec2-user || exit 1

if [[ ! -d ./app/server ]]; then
  mkdir -p ./app/server

  cd ./app/server || exit 1
  cat <<'EOF' >>build_signing_server_enclave.sh
#!/usr/bin/bash

set -x
set -e

token=$( curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" )
account_id=$( curl -H "X-aws-ec2-metadata-token: $token" http://169.254.169.254/latest/dynamic/instance-identity/document | jq -r '.accountId' )
region=$( curl -H "X-aws-ec2-metadata-token: $token" http://169.254.169.254/latest/meta-data/placement/region )

# On a fresh stack the instances can boot before the ECR/S3 VPC endpoints serve traffic;
# a single attempt then fails and the instance never starts the signer. Retry for up to
# ~10 minutes. (No brace-style shell expansions here: this file is rendered by Fn::Sub.)
retry() {
  local attempt=1
  until "$@"; do
    if [ $attempt -ge 30 ]; then
      echo "giving up after $attempt attempts: $*" >&2
      return 1
    fi
    echo "attempt $attempt failed: $*; retrying in 20s" >&2
    attempt=$((attempt + 1))
    sleep 20
  done
}
ecr_login() {
  aws ecr get-login-password --region $region | docker login --username AWS --password-stdin $account_id.dkr.ecr.$region.amazonaws.com
}

retry ecr_login
retry docker pull ${__SIGNING_SERVER_IMAGE_URI__}
retry docker pull ${__SIGNING_ENCLAVE_IMAGE_URI__}

nitro-cli build-enclave --docker-uri ${__SIGNING_ENCLAVE_IMAGE_URI__} --output-file signing_server.eif

EOF
  chmod +x build_signing_server_enclave.sh
  cd ../.. || exit 1
  chown -R ec2-user:ec2-user ./app

  sudo -H -u ec2-user bash -c "cd /home/ec2-user/app/server && ./build_signing_server_enclave.sh"
fi

if [[ ! -f /etc/systemd/system/nitro-signing-server.service ]]; then

  cat <<'EOF' >>/etc/systemd/system/nitro-signing-server.service
[Unit]
Description=Nitro Enclaves Signing Server
After=network-online.target
DefaultDependencies=no
Requires=nitro-enclaves-allocator.service
After=nitro-enclaves-allocator.service

[Service]
Type=simple
ExecStart=/home/ec2-user/app/watchdog.py
Restart=always
#RestartSec=5

[Install]
WantedBy=multi-user.target

EOF

  cat <<EOF >>/home/ec2-user/app/watchdog.py
#!/usr/bin/env python3

import json
import subprocess
import time

def nitro_cli_describe_call(name=None):
    subprocess_args = [
        "/bin/nitro-cli",
        "describe-enclaves"
    ]

    print("enclave args: {}".format(subprocess_args))

    proc = subprocess.Popen(
        subprocess_args,
        stdout=subprocess.PIPE
    )

    nitro_cli_response = proc.communicate()[0].decode()

    if name:
        response = json.loads(nitro_cli_response)

        if len(response) != 1:
            return False

        if response[0].get("EnclaveName") != name or response[0].get("State") != "Running":
            return False

    return True


def nitro_cli_run_call():
    subprocess_args = [
        "/bin/nitro-cli",
        "run-enclave",
        "--cpu-count", "2",
        "--memory", "4320",
        "--eif-path", "/home/ec2-user/app/server/signing_server.eif",
        "--enclave-cid", "16"
    ] + [x for x in ["${__DEBUG_FLAG__}"] if x]

    print("enclave args: {}".format(subprocess_args))

    proc = subprocess.Popen(
        subprocess_args,
        stdout=subprocess.PIPE
    )

    # returns b64 encoded plaintext
    nitro_cli_response = proc.communicate()[0].decode()

    return nitro_cli_response


def main():
    print("Starting signing server...")

    nitro_cli_run_call()

    while nitro_cli_describe_call("signing_server"):
        # print("nitro enclave up and running")
        time.sleep(5)


if __name__ == '__main__':
    main()

EOF

  chmod +x /home/ec2-user/app/watchdog.py

fi

# start and register the nitro signing server service for autostart
systemctl enable --now nitro-signing-server.service

# --- TLS server certificate -------------------------------------------------------
# When a deployment CA is configured, issue a per-instance server certificate whose SAN
# is the NLB DNS name and sign it with the CA fetched from Secrets Manager. Clients
# (the broadcast Lambda) trust the CA and validate this SAN, so TLS is genuinely
# verified end to end. When no CA is configured (dev with skip-verify), fall back to the
# legacy self-signed CN=localhost cert.
TLS_CA_SECRET_NAME="${__TLS_CA_SECRET_NAME__}"
NLB_DNS_NAME="${__NLB_DNS_NAME__}"
CERT_DIR=/etc/pki/tls/certs
if [ -n "$TLS_CA_SECRET_NAME" ] && [ -n "$NLB_DNS_NAME" ]; then
  echo "Issuing per-instance server cert (SAN=$NLB_DNS_NAME) from CA $TLS_CA_SECRET_NAME"
  # The CA secret holds a JSON object {"cert": "<PEM>", "key": "<PEM>"}. Global
  # xtrace is useful for first-boot diagnostics, but it must not print this value or any
  # command that expands it. Restore tracing only after the variable and CA key are gone.
  { set +x; } 2>/dev/null
  CA_JSON=$(aws secretsmanager get-secret-value --region "${__REGION__}" \
    --secret-id "$TLS_CA_SECRET_NAME" --query SecretString --output text)
  umask 077
  printf '%s' "$CA_JSON" | jq -r '.cert' > "$CERT_DIR/ca.crt"
  printf '%s' "$CA_JSON" | jq -r '.key'  > "$CERT_DIR/ca.key"
  # Per-instance leaf: fresh key, CSR, then a CA-signed cert carrying the NLB DNS SAN.
  # The CN is a short constant: X.509 CNs are capped at 64 chars and NLB DNS names
  # exceed that; clients validate the hostname against the SAN, never the CN.
  openssl req -newkey rsa:2048 -nodes \
    -keyout "$CERT_DIR/localhost.key" \
    -out "$CERT_DIR/server.csr" \
    -subj "/CN=nitro-signing-server"
  openssl x509 -req -in "$CERT_DIR/server.csr" \
    -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" -CAcreateserial \
    -days 397 -sha256 \
    -extfile <(printf 'subjectAltName=DNS:%s\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n' "$NLB_DNS_NAME") \
    -out "$CERT_DIR/localhost.crt"
  unset CA_JSON
  # The CA private key must not linger on the instance disk after signing. The serial is
  # public, but is one-use bootstrap state and is removed with the CSR for a clean host.
  shred -u "$CERT_DIR/ca.key" 2>/dev/null || rm -f "$CERT_DIR/ca.key"
  rm -f "$CERT_DIR/server.csr" "$CERT_DIR/ca.srl"
  # The CA *certificate* is public material; umask 077 made it 600 root. Open it up so
  # the non-root server user can read it when an mTLS client CA path points at it.
  chmod 644 "$CERT_DIR/ca.crt"
  { set -x; } 2>/dev/null
else
  echo "No deployment CA configured; using self-signed localhost cert (dev/skip-verify only)"
  openssl req -x509 -nodes -days 3650 -newkey rsa:4096 \
    -keyout "$CERT_DIR/localhost.key" \
    -out "$CERT_DIR/localhost.crt" \
    -subj "/CN=localhost"
fi
# Combine key+cert into single file (server expects this format from make-dummy-cert)
cat "$CERT_DIR/localhost.key" >> "$CERT_DIR/localhost.crt"
# The signing server runs as uid 10001 inside its container; give that uid — and only
# that uid — read access to the served key material (umask 077 left these root:root 600).
chown 10001:10001 "$CERT_DIR/localhost.crt" "$CERT_DIR/localhost.key"
chmod 400 "$CERT_DIR/localhost.crt" "$CERT_DIR/localhost.key"

# docker over system process manager
#
# The signing service refuses to start unless it can authenticate callers, so the auth
# mode and its allowlist are passed here. Values are quoted because the allowlist is a
# comma-separated list of ARNs. SECRET_ID names the single wallet this service may sign
# with; the caller does not get to choose it.
docker run -d --restart unless-stopped --name http_server \
  --security-opt no-new-privileges \
  --security-opt seccomp=unconfined \
  --cap-drop ALL \
  -e REGION=${__REGION__} \
  -e SECRET_ID="${__SECRET_ID__}" \
  -e NITRO_AUTH_MODE="${__AUTH_MODE__}" \
  -e NITRO_ALLOWED_PRINCIPALS="${__ALLOWED_PRINCIPALS__}" \
  -e NITRO_ALLOWED_CLIENTS="${__ALLOWED_CLIENTS__}" \
  -e NITRO_CLIENT_CA_PATH="${__CLIENT_CA_PATH__}" \
  -e NITRO_CLIENT_CRL_PATH="${__CLIENT_CRL_PATH__}" \
  -v /etc/pki/tls/certs/:/etc/pki/tls/certs/:ro -p 443:8443 ${__SIGNING_SERVER_IMAGE_URI__}
--//--
