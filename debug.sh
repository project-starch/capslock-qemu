xargs -a qemu-args.txt gdb --args installation/bin/qemu-system-riscv64
#GDB_PID=$!
#kill -SIGSTOP $GDB_PID
#fg
stty echo

