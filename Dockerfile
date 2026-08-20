# syntax=docker/dockerfile:1.7

FROM python:3.12.13-slim-bookworm@sha256:4766d8b510c428e595d74b9cc5bbb2fae8e26316fffb4adc89908d79aacd58a2 AS runtime-dependencies

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /build
COPY requirements.lock /build/requirements.lock
RUN python -m pip install \
      --disable-pip-version-check \
      --no-cache-dir \
      --no-compile \
      --no-deps \
      --only-binary=:all: \
      --require-hashes \
      --target=/opt/adf/dependencies \
      -r /build/requirements.lock

FROM python:3.12.13-slim-bookworm@sha256:4766d8b510c428e595d74b9cc5bbb2fae8e26316fffb4adc89908d79aacd58a2 AS runtime

ARG ADF_IMAGE_CREATED=1970-01-01T00:00:00Z
ARG ADF_IMAGE_REVISION=UNSET
ARG ADF_IMAGE_VERSION=0.4.0a2

LABEL org.opencontainers.image.created="${ADF_IMAGE_CREATED}" \
      org.opencontainers.image.description="Offline synthetic-only Stage A AI Decision Firewall reference runtime" \
      org.opencontainers.image.revision="${ADF_IMAGE_REVISION}" \
      org.opencontainers.image.source="https://github.com/redxking/ai-decision-firewall" \
      org.opencontainers.image.title="AI Decision Firewall Stage A" \
      org.opencontainers.image.version="${ADF_IMAGE_VERSION}"

ENV HOME=/nonexistent \
    PATH=/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin \
    PYTHONFAULTHANDLER=1 \
    PYTHONPATH=/opt/adf/src:/opt/adf/dependencies \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TMPDIR=/tmp

WORKDIR /opt/adf
COPY --from=runtime-dependencies /opt/adf/dependencies /opt/adf/dependencies
COPY src /opt/adf/src
COPY config/phase3_policy.json /opt/adf/config/phase3_policy.json
COPY contracts/v0.3.0/decision-request.schema.json /opt/adf/contracts/v0.3.0/decision-request.schema.json
COPY contracts/v0.3.0/phase3-policy.schema.json /opt/adf/contracts/v0.3.0/phase3-policy.schema.json
COPY contracts/v0.4.0/lab-execution-command.schema.json /opt/adf/contracts/v0.4.0/lab-execution-command.schema.json
COPY contracts/v0.4.0/lab-executor-receipt.schema.json /opt/adf/contracts/v0.4.0/lab-executor-receipt.schema.json
COPY contracts/v0.4.0/lab-observation-request.schema.json /opt/adf/contracts/v0.4.0/lab-observation-request.schema.json
COPY contracts/v0.4.0/lab-observation.schema.json /opt/adf/contracts/v0.4.0/lab-observation.schema.json
COPY artifacts/supply-chain/runtime.cdx.json /opt/adf/artifacts/supply-chain/runtime.cdx.json
COPY run_service.py /opt/adf/run_service.py
COPY run_preview.py /opt/adf/run_preview.py
RUN mkdir -p /etc/adf

USER 10001:10001
STOPSIGNAL SIGTERM
HEALTHCHECK NONE
ENTRYPOINT ["python", "/opt/adf/run_service.py"]
CMD ["serve", "--config", "/etc/adf/service.json", "--host", "127.0.0.1", "--port", "8080", "--workers", "1", "--require-existing"]
