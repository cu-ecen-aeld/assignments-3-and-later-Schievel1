#!/bin/bash
# Script outline to install and build kernel.
# Author: Siddhant Jajoo.

set -e
set -u

OUTDIR=/tmp/aeld
SYSROOT=/home/pascal/dev/gcc-arm-10.2-2020.11-x86_64-aarch64-none-linux-gnu/
KERNEL_REPO=git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git
KERNEL_VERSION=v5.1.10
BUSYBOX_VERSION=1_33_1
FINDER_APP_DIR=$(realpath $(dirname $0))
ARCH=arm64
CROSS_COMPILE=aarch64-none-linux-gnu-
MAKE="make -j4 CROSS_COMPILE=${CROSS_COMPILE} ARCH=${ARCH}"

if [ $# -lt 1 ]
then
	echo "Using default directory ${OUTDIR} for output"
else
	OUTDIR=$1
	echo "Using passed directory ${OUTDIR} for output"
fi

mkdir -p "${OUTDIR}"

cd "$OUTDIR"
if [ ! -d "${OUTDIR}/linux-stable" ]; then
    #Clone only if the repository does not exist.
	echo "CLONING GIT LINUX STABLE VERSION ${KERNEL_VERSION} IN ${OUTDIR}"
	git clone ${KERNEL_REPO} --depth 1 --single-branch --branch ${KERNEL_VERSION}
fi
if [ ! -e "${OUTDIR}/linux-stable/arch/${ARCH}/boot/Image" ]; then
    cd linux-stable
    echo "Checking out version ${KERNEL_VERSION}"
    git checkout ${KERNEL_VERSION}

    # TODO: Add your kernel build steps here
	${MAKE} mrproper
	${MAKE} defconfig
	${MAKE} all && true
	# this is fixing the "multiple definition of 'yylloc'" error
	sed -i "s/YYLTYPE yylloc;/extern YYLTYPE yylloc;/" "scripts/dtc/dtc-lexer.lex.c"
	${MAKE} all
	${MAKE} modules
	${MAKE} dtbs
fi

echo "Adding the Image in outdir"
cp "${OUTDIR}/linux-stable/arch/arm64/boot/Image" "${OUTDIR}"

echo "Creating the staging directory for the root filesystem"
cd "$OUTDIR"
if [ -d "${OUTDIR}/rootfs" ]
then
	echo "Deleting rootfs directory at ${OUTDIR}/rootfs and starting over"
    sudo rm  -rf ${OUTDIR}/rootfs
fi

# TODO: Create necessary base directories
mkdir "${OUTDIR}"/rootfs
cd "${OUTDIR}"/rootfs
mkdir -p bin dev etc home lib lib64 proc sbin sys tmp usr var
mkdir -p usr/bin usr/lib usr/sbin
mkdir -p var/log

cd "$OUTDIR"
if [ ! -d "${OUTDIR}/busybox" ]; then
	git clone git://busybox.net/busybox.git
    cd busybox
    git checkout "${BUSYBOX_VERSION}"
    # TODO:  Configure busybox
	${MAKE} distclean
	${MAKE} defconfig
else
    cd busybox
fi

# TODO: Make and install busybox
${MAKE}
${MAKE} CONFIG_PREFIX="${OUTDIR}/rootfs" install

echo "Library dependencies"
cd "${OUTDIR}/rootfs"
${CROSS_COMPILE}readelf -a bin/busybox | grep "program interpreter"
${CROSS_COMPILE}readelf -a bin/busybox | grep "Shared library"

# TODO: Add library dependencies to rootfs
cp "${SYSROOT}/aarch64-none-linux-gnu/libc/lib/ld-linux-aarch64.so.1" "${OUTDIR}/rootfs/lib"
cp "${SYSROOT}/aarch64-none-linux-gnu/libc/lib64/libm.so.6" "${OUTDIR}/rootfs/lib64"
cp "${SYSROOT}/aarch64-none-linux-gnu/libc/lib64/libresolv.so.2" "${OUTDIR}/rootfs/lib64"
cp "${SYSROOT}/aarch64-none-linux-gnu/libc/lib64/libc.so.6" "${OUTDIR}/rootfs/lib64"

# TODO: Make device nodes
sudo mknod -m 666 dev/null c 1 3
sudo mknod -m 666 dev/console c 5 1

# TODO: Clean and build the writer utility
# TODO: Copy the finder related scripts and executables to the /home directory
# on the target rootfs
${MAKE} -C "${FINDER_APP_DIR}" default
cp "${FINDER_APP_DIR}"/{writer,finder.sh,conf/username.txt,finder-test.sh,autorun-qemu.sh} "${OUTDIR}/rootfs/home"

# TODO: Chown the root directory
sudo chown root "${OUTDIR}/rootfs"

# TODO: Create initramfs.cpio.gz
cd "${OUTDIR}/rootfs"
find . | cpio -H newc -ov --owner root:root > "${OUTDIR}/initramfs.cpio"
cd "${OUTDIR}"
gzip -f initramfs.cpio
