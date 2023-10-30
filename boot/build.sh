set -e

riscv64-unknown-elf-gcc -march=rv64id -o resetvec -nostdlib -static -T link.ld resetvec.S
riscv64-unknown-elf-objcopy -O binary resetvec resetvec.bin
python3 print_reset_vec.py resetvec.bin
