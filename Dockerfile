FROM ubuntu:22.04

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    apt-get update && apt-get install -y \
    lsb-release \
    wget \
    software-properties-common \
    gnupg \
    cmake \
    git

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    wget https://apt.llvm.org/llvm.sh \
    && chmod +x llvm.sh \
    && ./llvm.sh 18 \
    && rm llvm.sh

COPY . /root/Mergen

RUN ln -s /usr/bin/clang-18 /usr/bin/clang \
    && ln -s /usr/bin/clang-cpp-18 /usr/bin/clang-cpp \
    && ln -s /usr/bin/clang-cpp-18 /usr/bin/clang++

ENV CC=/usr/bin/clang
ENV CXX=/usr/bin/clang++

RUN mkdir -p /root/Mergen/build
WORKDIR /root/Mergen/build

# Default build argument for testing
ARG TESTING=false

# Run cmake with the option to enable testing if TESTING is true
RUN cmake .. ${TESTING:+-DMERGEN_TESTING=1} && cmake --build . -j $(nproc)

# Provide the built binary path as the default output for the container
WORKDIR /root/Mergen/build

# bash magic
ENTRYPOINT ["/bin/bash", "-c", "if [ \"$TESTING\" == \"true\" ]; then /root/Mergen/build/lifter; else cp /root/Mergen/build/lifter /output/lifter; fi"]