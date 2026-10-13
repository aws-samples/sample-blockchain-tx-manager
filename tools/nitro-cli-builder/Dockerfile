# Amazon Linux 2023 release 2023.12.20260831.0, pinned by multi-arch index digest.
# Build with --platform linux/amd64; Nitro CLI/EIF output targets Nitro EC2 (x86_64).
FROM --platform=linux/amd64 public.ecr.aws/amazonlinux/amazonlinux@sha256:fb70bd54d4a849293bfef9785ce63aa1eac2557e0167af4f32f56286bd35d783

# Exact RPM NEVRA values observed in the reviewed builder. The versioned AL2023 base
# selects its release repository; a missing exact package fails the build rather than
# silently upgrading the measurement toolchain.
RUN dnf install -y \
      aws-nitro-enclaves-cli-1.4.4-0.amzn2023.x86_64 \
      aws-nitro-enclaves-cli-devel-1.4.4-0.amzn2023.x86_64 \
      docker-25.0.16-1.amzn2023.0.4.x86_64 \
      containerd-2.2.5-1.amzn2023.0.2.x86_64 \
      runc-1.3.5-1.amzn2023.0.2.x86_64 \
    && dnf clean all \
    && rm -rf /var/cache/dnf

ENTRYPOINT ["nitro-cli"]
