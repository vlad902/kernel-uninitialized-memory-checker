#!/bin/sh

set -e

export CURDIR="$PWD/`dirname $0`"

if [ `uname` = 'Linux' ]; then
  sudo apt install -y cmake clang bc libssl-dev

  wget https://github.com/Z3Prover/z3/releases/download/z3-4.6.0/z3-4.6.0-x64-debian-8.10.zip
  unzip z3-4.6.0-x64-debian-8.10.zip
  mv z3-4.6.0-x64-debian-8.10 z3
  rm z3-4.6.0-x64-debian-8.10.zip
  sudo ln -s `pwd`/z3/bin/libz3.so /usr/lib/libz3.so
  export Z3_EXE=$CURDIR/z3/bin/z3
  export Z3_LIB=$CURDIR/z3/bin/libz3.so
  export Z3_INC=$CURDIR/z3/include

  export CPUS=`grep -c ^processor /proc/cpuinfo`
elif [ `uname` = 'FreeBSD' ]; then
  sudo pkg install -y git cmake wget z3
  sudo ln -s /usr/local/bin/perl /usr/bin/perl

  export Z3_EXE=/usr/local/bin/z3
  export Z3_LIB=/usr/local/lib/libz3.so
  export Z3_INC=/usr/local/include

  export CPUS=`sysctl -n hw.ncpu`
elif [ `uname` = 'Darwin' ]; then
  wget https://github.com/Z3Prover/z3/releases/download/z3-4.6.0/z3-4.6.0-x64-osx-10.11.6.zip
  unzip z3-4.6.0-x64-osx-10.11.6.zip
  mv z3-4.6.0-x64-osx-10.11.6 z3
  rm z3-4.6.0-x64-osx-10.11.6.zip
  sudo ln -s `pwd`/z3/bin/libz3.dylib /usr/local/lib/libz3.dylib
  export Z3_EXE=$CURDIR/z3/bin/z3
  export Z3_LIB=$CURDIR/z3/bin/libz3.dylib
  export Z3_INC=$CURDIR/z3/include

  export CPUS=`sysctl -n hw.ncpu`
else
  export CPUS=1
fi

git clone https://github.com/llvm-mirror/llvm.git
cd llvm/tools
git checkout 238f816f4c47e1de89fb4647c67bdfb5fb3da7dc

git clone https://github.com/llvm-mirror/clang.git
cd clang
git checkout d8cadd200135a319ef1a7ec2b7cabe210cfb3343

cd ../../..

patch -p0 < $CURDIR/llvm.patch

ln -s $CURDIR/tests llvm/tools/clang/test/Analysis/kernel-memory-disclosure-checker-tests
ln -s $CURDIR/KernelMemoryDisclosureChecker.cpp llvm/tools/clang/lib/StaticAnalyzer/Checkers/KernelMemoryDisclosureChecker.cpp
ln -s $CURDIR/MachInterface.h llvm/tools/clang/include/clang/StaticAnalyzer/Checkers/MachInterface.h

mkdir build
cd build

cmake \
  -DZ3_EXECUTABLE=$Z3_EXE \
  -DZ3_INCLUDE_DIR=$Z3_INC \
  -DZ3_LIBRARIES=$Z3_LIB \
  -DCLANG_ANALYZER_BUILD_Z3=ON \
  -DCMAKE_BUILD_TYPE=Release \
  -DLLVM_TARGETS_TO_BUILD="X86;ARM;AArch64" \
  ../llvm

make -j $CPUS
