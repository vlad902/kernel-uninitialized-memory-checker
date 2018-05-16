This clang analyzer checkers looks for kernel-to-userland memory disclosure, it was a toy starter project described [here](https://tsyrklevich.net/2017/03/27/kernel-clang-analyzer/).

# Build LLVM/clang with the checker

In a screen session, run `sh build.sh`. It will place the LLVM source tree into a directory named `llvm` and place the new build against it in the directory `build`.

To run tests, run `~/build/bin/llvm-lit llvm/tools/clang/test/Analysis/kernel-memory-disclosure-checker-tests/*.c`

# Options

To run with the z3 constraint manager (very slow!) add the `-constraints z3` flag to the scan-build invocation.

# Run against FreeBSD kernel

Run in a screen session in bash:

    cd /usr/src
    time sudo ~/build/bin/scan-build \
      --use-cc=/usr/bin/cc \
      -disable-checker core,unix,deadcode,nullability \
      -enable-checker alpha.security.KernelMemoryDisclosure \
      -o ~/analyzer \
      make -i -j `sysctl -n hw.ncpu` buildkernel COMPILER_TYPE=clang 2>&1 | tee ~/buildlog

# Run against Linux kernel

    wget https://cdn.kernel.org/pub/linux/kernel/v4.x/linux-4.16.7.tar.xz
    tar -xf linux-4.16.7.tar.xz
    patch -p0 < ~/kernel-uninitialized-memory-checker/linux-4.16.7.patch

    make mrproper allyesconfig
    sed -i 's/CONFIG_KASAN=y/CONFIG_KASAN=n/' .config
    sed -i 's/CONFIG_UBSAN=y/CONFIG_UBSAN=n/' .config
    sed -i 's/CONFIG_READABLE_ASM=y/CONFIG_READABLE_ASM=n/' .config
    sed -i 's/CONFIG_HARDENED_USERCOPY=y/CONFIG_HARDENED_USERCOPY=n/' .config
    sed -i 's/CONFIG_FORTIFY_SOURCE=y/CONFIG_FORTIFY_SOURCE=n/' .config
    yes "" | make oldconfig
    time ~/build/bin/scan-build \
      -disable-checker core,unix,deadcode,nullability \
      -enable-checker alpha.security.KernelMemoryDisclosure \
      -o ~/analyzer \
      make -i -j `grep -c ^processor /proc/cpuinfo` KBUILD_VERBOSE=1 2>&1 | tee ~/buildlog

# Run against XNU kernel

If you running the build on a newer (>10.12.3) version of XNU, you may want to run the [mig-parser](https://github.com/vlad902/mig-parser) to generate a fresh `MachInterface.h`. Run the following in the source tree:

    rm -rf BUILD
    time ~/build/bin/scan-build \
      -disable-checker core,unix,deadcode,nullability \
      -enable-checker alpha.security.KernelMemoryDisclosure \
      -o ~/analyzer \
      make -i SDKROOT=macosx ARCH_CONFIGS=X86_64 KERNEL_CONFIGS=RELEASE VERBOSE=YES USE_WERROR=0 2>&1 | tee ~/buildlog

# Run against Android kernel

Download and set-up an appropriate cross-compiler.

*ARM32*

    git clone https://android.googlesource.com/platform/prebuilts/gcc/linux-x86/arm/arm-eabi-4.6
    export ARCH=arm
    export CROSS_COMPILE=$PWD/arm-eabi-4.6/bin/arm-eabi-
    export CLANG_TARGET=armv5te-none-eabi

*ARM64*

    git clone https://android.googlesource.com/platform/prebuilts/gcc/linux-x86/aarch64/aarch64-linux-android-4.9/
    export ARCH=arm64
    export CROSS_COMPILE=$PWD/aarch64-linux-android-4.9/bin/aarch64-linux-android-
    export CLANG_TARGET=aarch64-none-eabi

Select and download a [kernel repo](https://source.android.com/source/building-kernels.html), e.g. `kernel/msm`.  At this point you will want to check out some branch to build, there will likely be some build errors you will want to fix to make clang build happily. Very hacky (just to get the build to work as quickly as possible, not to make functional builds!) patches I made to get builds to succeed are included in `android_build_with_clang/${KERNEL_REPO}/${BRANCH_NAME}.patch`

    git checkout SOME_BRANCH
    make clean mrproper SOMECONFIGURATION_defconfig
    time ~/build/bin/scan-build \
      --analyzer-target $CLANG_TARGET \
      --use-cc=${CROSS_COMPILE}gcc \
      -disable-checker core,unix,deadcode,nullability \
      -enable-checker alpha.security.KernelMemoryDisclosure \
      -o ~/analyzer \
      make -i -j `grep -c ^processor /proc/cpuinfo` V=1 2>&1 | tee ~/buildlog.android
