. ./qemu-vars.sh 

# OpenSBI fw_dynamic can also be used since qemu prepares the necessary info

echo ${QEMU_ARGS[@]} | xargs installation/bin/qemu-system-riscv64
