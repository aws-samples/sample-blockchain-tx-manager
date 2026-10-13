#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

# python:3.14-slim (Python 3.14.7), pinned by multi-arch manifest digest.
FROM python@sha256:cad9a2c871761c413caa6fdd6441c783451e740a48aaeba60ae62a8b53525ef6

WORKDIR /usr/src/app

COPY requirements.txt ./
RUN apt-get update && apt-get upgrade -y \
    && rm -rf /var/lib/apt/lists/* \
    && pip3 install --no-cache-dir -r /usr/src/app/requirements.txt \
    && pip3 uninstall -y setuptools wheel jaraco.context \
    && pip3 uninstall -y pip

COPY ./app.py ./mtls_auth.py ./sigv4_auth.py ./

ARG REGION_ARG=us-east-1
ENV REGION=$REGION_ARG

# Non-root: a dedicated system user owns nothing but the process. The server listens on
# an unprivileged port (8443; NITRO_SERVER_PORT) and dockerd publishes host 443 to it,
# so no capability is added back. user_data.sh chowns the bind-mounted TLS material to
# this uid before starting the container.
RUN groupadd --gid 10001 signer && \
    useradd --uid 10001 --gid 10001 --system --no-create-home --shell /usr/sbin/nologin signer
USER 10001:10001

CMD [ "python", "./app.py" ]