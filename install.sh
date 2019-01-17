#!/bin/bash
set -e

echo "# Installing dependencies"
sudo apt-get install -y git cmake build-essential \
  libcapstone-dev libspdlog-dev libxen-dev libreadline-dev \
  libc++abi-dev libc++1 libc++-dev clang \
  autoconf libbost-test-dev \
  libuv-dev

./build.sh
sudo make install
