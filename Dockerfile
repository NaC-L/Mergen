FROM ubuntu:22.04

ENTRYPOINT [ "/bin/bash" ]

COPY . /root/Mergen

# Install deps
RUN apt update
RUN apt install lsb-release wget software-properties-common gnupg cmake -y

RUN wget https://apt.llvm.org/llvm.sh 
RUN chmod +x llvm.sh 
RUN ./llvm.sh 18



# Create symlinks
RUN ln -s /usr/bin/clang-18 /usr/bin/clang
RUN ln -s /usr/bin/clang-cpp-18 /usr/bin/clang-cpp
RUN ln -s /usr/bin/clang-cpp-18 /usr/bin/clang++


# Prepare enviroment variables before building
ENV CC /usr/bin/clang
ENV CXX /usr/bin/clang++


# Build
RUN mkdir /root/Mergen/build
WORKDIR /root/Mergen/build
RUN cmake ..
RUN cmake --build . -j `nproc`
