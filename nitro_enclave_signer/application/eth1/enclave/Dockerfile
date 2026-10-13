#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

# Amazon Linux 2023 release 2023.12.20260914, pinned by multi-arch index digest.
FROM public.ecr.aws/amazonlinux/amazonlinux@sha256:155687eb8e1f156da67beda919f1ca4dab36a9f6fc7576cc514d7773b7d6a311

RUN dnf --releasever=latest upgrade -y \
    && dnf install gcc python3 python3-devel python3-pip net-tools -y \
    && dnf clean all \
    && rm -rf /var/cache/dnf

WORKDIR /app

COPY ./kms/kmstool_enclave_cli ./
COPY ./kms/libnsm.so /usr/lib64/

COPY requirements.txt ./
RUN pip3 install --no-cache-dir -r /app/requirements.txt \
    && dnf remove -y python3-pip \
    && dnf clean all \
    && rm -rf /var/cache/dnf

ARG REGION_ARG=us-east-1
ENV REGION=$REGION_ARG

COPY server.py ./
CMD [ "python3", "/app/server.py" ]
