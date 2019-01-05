#!/bin/sh

set -e

export CURDIR="$PWD/`dirname $0`"

if [ `uname` = 'Linux' ]; then
  sudo apt install -y cmake clang bc libssl-dev unzip

  wget https://github.com/Z3Prover/z3/releases/download/z3-4.8.4/z3-4.8.4.d6df51951f4c-x64-debian-8.11.zip
  unzip z3-4.8.4.d6df51951f4c-x64-debian-8.11.zip
  mv z3-4.8.4.d6df51951f4c-x64-debian-8.11 z3
  rm z3-4.8.4.d6df51951f4c-x64-debian-8.11.zip
  sudo ln -s `pwd`/z3/bin/libz3.so /usr/lib/libz3.so
  export Z3_DIR=$CURDIR/z3

  export CPUS=`grep -c ^processor /proc/cpuinfo`
elif [ `uname` = 'FreeBSD' ]; then
  sudo pkg install -y git cmake wget z3
  sudo ln -s /usr/local/bin/perl /usr/bin/perl

  export Z3_DIR=/usr/local

  export CPUS=`sysctl -n hw.ncpu`
elif [ `uname` = 'Darwin' ]; then
  wget https://github.com/Z3Prover/z3/releases/download/z3-4.8.4/z3-4.8.4.d6df51951f4c-x64-osx-10.14.1.zip
  unzip z3-4.8.4.d6df51951f4c-x64-osx-10.14.1.zip
  mv z3-4.8.4.d6df51951f4c-x64-osx-10.14.1 z3
  rm z3-4.8.4.d6df51951f4c-x64-osx-10.14.1.zip
  sudo ln -s `pwd`/z3/bin/libz3.dylib /usr/local/lib/libz3.dylib
  export Z3_DIR=$CURDIR/z3

  export CPUS=`sysctl -n hw.ncpu`
else
  export CPUS=1
fi

git clone https://github.com/llvm-mirror/llvm.git
cd llvm/tools
git checkout 718039ebb75d709b91dcc3ca18eddedb283892fd

git clone https://github.com/llvm-mirror/clang.git
cd clang
git checkout 27ff8dcc77fd7c9f1bcf181b25eaa7d68777fdfe

cd ../../..

patch -p0 < $CURDIR/llvm.patch

ln -s $CURDIR/tests llvm/tools/clang/test/Analysis/kernel-memory-disclosure-checker-tests
ln -s $CURDIR/KernelMemoryDisclosureChecker.cpp llvm/tools/clang/lib/StaticAnalyzer/Checkers/KernelMemoryDisclosureChecker.cpp
ln -s $CURDIR/MachInterface.h llvm/tools/clang/include/clang/StaticAnalyzer/Checkers/MachInterface.h

mkdir build
cd build

cmake \
  -DCLANG_ANALYZER_ENABLE_Z3_SOLVER=ON \
  -DCLANG_ANALYZER_Z3_INSTALL_DIR=$Z3_DIR \
  -DCMAKE_BUILD_TYPE=Release \
  -DLLVM_TARGETS_TO_BUILD="X86;ARM;AArch64" \
  ../llvm

make -j $CPUS
