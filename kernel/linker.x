OUTPUT_FORMAT("elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)
ENTRY(kstuff_kernel_start)
SECTIONS {
  . = 0;
  .payload : {
    KEEP(*(.payload_header))
    *(.payload_code .text .text.*)
    *(.payload_rdata .rodata .rodata.*)
    *(.payload_data .data .data.*)
    *(.payload_bss .bss .bss.* COMMON)
    BYTE(0)
    __image_end = .;
  }
  ASSERT(SIZEOF(.payload) <= 0x10000, "kstuff exceeds the reserved resident region")
  /DISCARD/ : { *(.comment .note* .eh_frame* .interp .gnu*) }
}
