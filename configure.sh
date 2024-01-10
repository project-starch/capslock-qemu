set -e

mkdir -p build
cd build
#../configure --enable-debug --target-list=riscv64-softmmu,riscv64-linux-user --prefix=$(pwd)/../installation
../configure --enable-debug --target-list=riscv64-softmmu --prefix=$(pwd)/../installation

