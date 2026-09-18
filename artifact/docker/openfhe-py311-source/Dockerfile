# syntax=docker/dockerfile:1
ARG TARGETPLATFORM=linux/amd64
FROM --platform=$TARGETPLATFORM ubuntu:24.04@sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90

ARG MAKE_JOBS=4
ARG PYTHON_VERSION=3.11.15
ARG PYTHON_SHA256=272179ddd9a2e41a0fc8e42e33dfbdca0b3711aa5abf372d3f2d51543d09b625
ARG OPENFHE_NATIVE_COMMIT=1306d14f8c26bb6150d3e6ad54f28dfe1007689e
ARG OPENFHE_WRAPPER_COMMIT=4f13e2c3a7e35f73f4816904dabd3a3db47b6e51

ENV DEBIAN_FRONTEND=noninteractive \
    PATH=/opt/python311/bin:$PATH \
    LD_LIBRARY_PATH=/opt/python311/lib:/opt/openfhe/lib:/opt/openfhe/lib64 \
    PYTHONPATH=/workspace/cipherscope/src \
    CIPHERSCOPE_OPENFHE_LANE=primary-source-py311 \
    CIPHERSCOPE_OPENFHE_BOOTSTRAP=1 \
    CIPHERSCOPE_OPENFHE_NATIVE_COMMIT=1306d14f8c26bb6150d3e6ad54f28dfe1007689e \
    CIPHERSCOPE_OPENFHE_WRAPPER_COMMIT=4f13e2c3a7e35f73f4816904dabd3a3db47b6e51 \
    CIPHERSCOPE_OPENFHE_BUILD_MANIFEST=/opt/cipherscope-openfhe-build-manifest.json

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        build-essential \
        ca-certificates \
        cmake \
        gcc-13-plugin-dev \
        curl \
        git \
        libbz2-dev \
        libffi-dev \
        libgdbm-dev \
        liblzma-dev \
        libncursesw5-dev \
        libreadline-dev \
        libsqlite3-dev \
        libssl-dev \
        libuuid1 \
        libxml2-dev \
        libzstd-dev \
        pybind11-dev \
        tk-dev \
        uuid-dev \
        xz-utils \
        zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /tmp/python-build
RUN curl --fail --location --silent --show-error \
        --output Python.tar.xz \
        https://www.python.org/ftp/python/${PYTHON_VERSION}/Python-${PYTHON_VERSION}.tar.xz \
    && echo "${PYTHON_SHA256}  Python.tar.xz" | sha256sum --check --strict \
    && tar --extract --file Python.tar.xz --xz --strip-components=1 \
    && ./configure \
        --prefix=/opt/python311 \
        --enable-shared \
        --with-ensurepip=install \
    && make --jobs "${MAKE_JOBS}" \
    && make install

RUN git init /tmp/openfhe-development \
    && git -C /tmp/openfhe-development remote add origin https://github.com/openfheorg/openfhe-development.git \
    && git -C /tmp/openfhe-development fetch --depth 1 origin "${OPENFHE_NATIVE_COMMIT}" \
    && git -C /tmp/openfhe-development checkout --detach FETCH_HEAD \
    && test "$(git -C /tmp/openfhe-development rev-parse HEAD)" = "${OPENFHE_NATIVE_COMMIT}"

RUN cmake \
        -S /tmp/openfhe-development \
        -B /tmp/openfhe-development/build \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=/opt/openfhe \
        -DBUILD_UNITTESTS=OFF \
        -DBUILD_EXAMPLES=OFF \
        -DBUILD_BENCHMARKS=OFF \
    && cmake --build /tmp/openfhe-development/build --parallel "${MAKE_JOBS}" \
    && cmake --install /tmp/openfhe-development/build

RUN git init /tmp/openfhe-python \
    && git -C /tmp/openfhe-python remote add origin https://github.com/openfheorg/openfhe-python.git \
    && git -C /tmp/openfhe-python fetch --depth 1 origin "${OPENFHE_WRAPPER_COMMIT}" \
    && git -C /tmp/openfhe-python checkout --detach FETCH_HEAD \
    && test "$(git -C /tmp/openfhe-python rev-parse HEAD)" = "${OPENFHE_WRAPPER_COMMIT}"

RUN cmake \
        -S /tmp/openfhe-python \
        -B /tmp/openfhe-python/build \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_PREFIX_PATH=/opt/openfhe \
        -DCMAKE_INSTALL_PREFIX=/opt/python311/lib/python3.11/site-packages/openfhe \
        -DOPENFHE_REQUIRED_VERSION=1.5.1 \
        -DPython_EXECUTABLE=/opt/python311/bin/python3.11 \
        -DPython_ROOT_DIR=/opt/python311 \
        -DPYTHON_EXECUTABLE_PATH=/opt/python311/bin/python3.11 \
    && cmake --build /tmp/openfhe-python/build --parallel "${MAKE_JOBS}" \
    && cmake --install /tmp/openfhe-python/build \
    && python3.11 -c 'import openfhe; assert openfhe.get_native_int() in (64, 128)'

COPY artifact/docker/openfhe-py311-source/write_build_manifest.py /tmp/write_build_manifest.py
RUN python3.11 /tmp/write_build_manifest.py

WORKDIR /workspace/cipherscope
COPY . /workspace/cipherscope

CMD ["python3.11", "-m", "tests.integration_openfhe.run_gate"]
