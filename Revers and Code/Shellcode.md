## 📘 Shellcode Reference Guide
Reference guide for shellcode and portable executables.

## ⚙️ Portable Executable Header
The PE header begins with the DOS MZ magic bytes. Verify the structure and offsets using a hex dump utility or PE-bear.

```text
# Hexadecimal dump illustrating DOS MZ header
Offset(h) 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
00000000  4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00  MZ..........ÿÿ..
00000010  B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00  ¸.......@.......
00000020  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000030  00 00 00 00 00 00 00 00 00 00 00 00 E8 00 00 00  ............è...
00000040  0E 1F BA 0E 00 B4 09 CD 21 B8 01 4C CD 21 54 68  ..º..´.Í!¸.LÍ!Th
```
* Tool: PE-bear / Hex Editor

## 🧩 Portable Executable Sections

Extract and identify PE file sections using Detect It Easy (DIE) or equivalent PE mapping software.

| Section | Purpose |
|---|---|
| .text | Contains executable code and entry point |
| .data | Contains initialized data (strings, variables, etc.) |
| .rdata / .idata | Contains imports (Windows API) and DLLs |
| .reloc | Contains relocation information |
| .rsrc | Contains application resources (images, icons, etc.) |
| .debug | Contains debug information |
