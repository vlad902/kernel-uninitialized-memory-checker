#!/bin/sh

set -e

export CURDIR="$PWD/`dirname $0`"

if [ `uname` = 'Linux' ]; then
  sudo apt install -y cmake clang binutils-gold bc libssl-dev
  sudo rm /usr/bin/ld && sudo ln -s /usr/bin/ld.gold /usr/bin/ld
  export CPUS=`grep -c ^processor /proc/cpuinfo`
elif [ `uname` = 'FreeBSD' ]; then
  sudo pkg install -y git cmake wget
  sudo ln -s /usr/local/bin/perl /usr/bin/perl
  export CPUS=`sysctl -n hw.ncpu`
elif [ `uname` = 'Darwin' ]; then
  export CPUS=`sysctl -n hw.ncpu`
else
  export CPUS=1
fi

wget http://releases.llvm.org/3.9.1/llvm-3.9.1.src.tar.xz
wget http://releases.llvm.org/3.9.1/cfe-3.9.1.src.tar.xz
wget http://releases.llvm.org/3.9.1/clang-tools-extra-3.9.1.src.tar.xz

tar -xf llvm-3.9.1.src.tar.xz
tar -xf cfe-3.9.1.src.tar.xz
tar -xf clang-tools-extra-3.9.1.src.tar.xz

mv llvm-3.9.1.src llvm
mv cfe-3.9.1.src llvm/tools/clang
mv clang-tools-extra-3.9.1.src llvm/tools/clang/tools/clang-tools-extra

rm llvm-3.9.1.src.tar.xz cfe-3.9.1.src.tar.xz clang-tools-extra-3.9.1.src.tar.xz

patch -p0 < $CURDIR/llvm-3.9.1.patch

ln -s $CURDIR/KernelMemoryDisclosureChecker.cpp llvm/tools/clang/lib/StaticAnalyzer/Checkers/KernelMemoryDisclosureChecker.cpp
ln -s $CURDIR/MachInterface.h llvm/tools/clang/include/clang/StaticAnalyzer/Checkers/MachInterface.h

mkdir build
cd build

cmake -DCMAKE_BUILD_TYPE=Release -DLLVM_TARGETS_TO_BUILD="X86;ARM;AArch64" ../llvm
make -j $CPUS
