# syntax=docker/dockerfile:1
ARG TARGETPLATFORM=linux/amd64
FROM --platform=$TARGETPLATFORM ubuntu:24.04@sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90

ENV DEBIAN_FRONTEND=noninteractive \
    PATH=/opt/openfhe-venv/bin:$PATH \
    PYTHONPATH=/workspace/cipherscope/src \
    CIPHERSCOPE_OPENFHE_LANE=provisional-wheel-py312 \
    CIPHERSCOPE_OPENFHE_BOOTSTRAP=1

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        ca-certificates \
        libgomp1 \
        python3 \
        python3-venv \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m venv /opt/openfhe-venv

COPY requirements/openfhe-ubuntu24-py312.txt /tmp/openfhe-requirements.txt
RUN python -m pip install \
    --disable-pip-version-check \
    --no-deps \
    --only-binary=:all: \
    --require-hashes \
    --requirement /tmp/openfhe-requirements.txt

WORKDIR /workspace/cipherscope
COPY . /workspace/cipherscope

CMD ["python", "-m", "tests.integration_openfhe.run_gate"]
