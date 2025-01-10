void capslock_setup_rom_reset_vec(MachineState *machine, RISCVHartArrayState *harts,
                               hwaddr saddr,
                               hwaddr rom_base, hwaddr rom_size,
                               uint64_t kernel_entry,
                               uint64_t fdt_load_addr);
