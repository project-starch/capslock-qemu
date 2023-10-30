ENTRY(_start)

SECTIONS
{
    . = 0x1000;
    .text : AT(ADDR(.text)) {
        *(.text)
    }
    .data ALIGN(4096) : AT(ADDR(.data)) {
        *(.data)
    }
    .rodata ALIGN(4096) : AT(ADDR(.rodata)) {
        *(.rodata)
    }
    .bss ALIGN(4096) : {
        *(.bss)
    }
}
