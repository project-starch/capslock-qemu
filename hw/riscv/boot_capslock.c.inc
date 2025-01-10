void capslock_setup_rom_reset_vec(MachineState *machine, RISCVHartArrayState *harts,
                               hwaddr saddr,
                               hwaddr rom_base, hwaddr rom_size,
                               uint64_t kernel_entry,
                               uint64_t fdt_load_addr)
{
    int i;

    // TODO: implement
    assert(!riscv_is_32bit(harts)); /* we don't support RV32 for now */

    uint32_t reset_vec[3] = {
        0x0010041b,
        0x01f41413,
        0x00040067,
    };

    for(i = 0; i < ARRAY_SIZE(reset_vec); i ++) {
        reset_vec[i] = cpu_to_le32(reset_vec[i]);
    }

    rom_add_blob_fixed_as("mrom.reset", reset_vec, sizeof(reset_vec),
                          rom_base, &address_space_memory);
}