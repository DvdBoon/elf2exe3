# elf2exe3

Converts WarpOS PowerPC ELF files (as produced by GCC for WarpOS, e.g.
ScummVM's `ScummVM2_ELF`) into real Amiga Hunk executables with standard
reloc hunks, so AmigaOS `LoadSeg()` loads them like any other program.

Written in C99 and built with vbcc.
