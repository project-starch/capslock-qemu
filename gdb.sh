set -e

# OpenSBI fw_dynamic can also be used since qemu prepares the necessary info
xargs -t -a qemu-args.txt installation/bin/qemu-system-riscv64 -s -S &


tmux split-window -h gdb-multiarch -x debug/init.gdb \
    buildroot/output/build/linux-custom/vmlinux

wait

stty echo
