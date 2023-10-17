gdb --args installation/bin/qemu-system-riscv64 \
   -M virt -nographic \
   -bios buildroot/output/images/fw_jump.elf \
   -kernel buildroot/output/images/Image \
   -append "root=/dev/vda ro" \
   -drive file=buildroot/output/images/rootfs.ext2,format=raw,id=hd0 \
   -device virtio-blk-device,drive=hd0

