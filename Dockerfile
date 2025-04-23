FROM ubuntu:22.04

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    apt-get update && apt-get install -y \
    lsb-release \
    wget \
    software-properties-common \
    gnupg \
    cmake \
    git \
    rust

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
RUN cmake .. && cmake --build . -j $(nproc)

# Provide the built binary path as the default output for the container
WORKDIR /root/Mergen/build
CMD ["cp", "/root/Mergen/build/lifter", "/output/lifter"]
