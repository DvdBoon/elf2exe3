# elf2exe3

Converts WarpOS PowerPC ELF files (as produced by GCC for WarpOS, e.g.
ScummVM's `ScummVM2_ELF`) into real Amiga Hunk executables with standard
reloc hunks, so AmigaOS `LoadSeg()` loads them like any other program.

Written in C99 and built with vbcc.

## Status

Steps 1 to 4 of the spec are implemented: layout, `HUNK_RELOC32`, the `lis`
rewrite with the page table, the r2 entry hooks, and the 68k startup in
hunk 0 (`startup/wosstart.s`, built in). Not yet tested on real hardware.

## Build

    make            # host build, any C99 compiler
    make amiga      # vbcc: vc +aos68k -c99 -O2
    make startup    # after editing startup/wosstart.s (needs vasm)

## Test

    ./elf2exe3 -v --map out.map input.elf out.exe
    python3 tests/verify.py input.elf out.exe out.map

`verify.py` loads the hunk file the way LoadSeg does, at addresses whose low
16 bits are not zero, and checks every relocation against the ELF.
