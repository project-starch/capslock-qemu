set -e

mkdir -p build
cd build

if [ "z$QEMU_RELEASE" = "z" ]; then
    EXTRA_FLAGS=--enable-debug
else
    EXTRA_FLAGS=""
fi

../configure $EXTRA_FLAGS --target-list=riscv64-softmmu,riscv64-linux-user --prefix=$(pwd)/../installation
# ../configure --enable-debug --target-list=riscv64-softmmu --prefix=$(pwd)/../installation

