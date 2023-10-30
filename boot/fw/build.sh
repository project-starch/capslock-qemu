# riscv64-unknown-elf-gcc -march=rv64id -o fw.elf -nostdlib -static -T link.ld fw.S

if [ -f ./localconf.sh ]; then
    . ./localconf.sh
fi

if [ -z "FW_CC" ]; then
    FW_CC=riscv64-unknown-elf-gcc
    FW_CFLAGS=-march=rv64id
fi

$FW_CC $FW_CFLAGS -o fw.elf -nostdlib -static -T link.ld fw.S