#!/bin/bash
set -e

echo "# Installing dependencies"
sudo apt install -y git cmake build-essential \
  libcapstone-dev libspdlog-dev libxen-dev libreadline-dev \
  libc++abi-dev libc++1 libc++-dev clang

git submodule update --init

# Build CLI11
echo "# Building third party dep: CLI11"
cd third_party/CLI11
git submodule update --init
mkdir build && cd build
cmake .. && make && sudo make install

# Build ELFIO
echo "# Building third party dep: ELFIO"
cd ../ELFIO
sudo apt install -y autoconf libbost-test-dev
aclocal
autoconf
autoheader
automake --add-missing
./configure && make && sudo make install

# Build uvw
echo "# Building third party dep: uvw"
cd ../uvw/build
sudo apt install libuv-dev
cmake .. && make && sudo make install

echo "# Building xendbg"
mkdir build && cd build
cmake ..
make
