#  Shellcode

Welcome to the reference guide for Shell and code.

---

## Portable Executable

> Using hex dump
> Using PE-bear to view pe

- Header\
> start with **MZ**\
`Offset(h) 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F`\
`00000000  4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00  MZ..........ÿÿ..`\
`00000010  B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00  ¸.......@.......`\
`00000020  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................`\
`00000030  00 00 00 00 00 00 00 00 00 00 00 00 E8 00 00 00  ............è...`\
`00000040  0E 1F BA 0E 00 B4 09 CD 21 B8 01 4C CD 21 54 68  ..º..´.Í!¸.LÍ!Th`

- File section\
> find with Detect It Easy or any tool for PE \
`| Section          | Purpose                                            |`\
`|------------------|----------------------------------------------------|`\
`| .text            | Contains executable code and entry point           |`\
`| .data            | Contains initialized data (strings, variables, etc)|`\
`| .rdata or .idata | Contains imports (Windows API) and DLLs.           |`\
`| .reloc           | Contains relocation information                    |`\
`| .rsrc            | Contains application resources (images, etc.)      |`\
`| .debug           | Contains debug information                         |`

---

