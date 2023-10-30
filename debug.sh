. ./qemu-vars.sh

echo ${QEMU_ARGS[@]} | xargs gdb --args installation/bin/qemu-system-riscv64 

