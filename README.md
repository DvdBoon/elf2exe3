# elf2exe3

Converts WarpOS PowerPC ELF files (as produced by GCC for WarpOS, e.g.
ScummVM's `ScummVM2_ELF`) into real Amiga hunk executables with standard
reloc hunks, so the WarpOS `LoadSeg()` loads them like any other program.

Unlike Elf2Exe2, the result does not carry the ELF inside a 68k loader:
`LoadSeg` does all the relocation, nothing is patched at run time, and
there is no 32 MB size limit. ScummVM 2.2 (37.9 MB ELF) converts and runs.

The full design is in `docs/spec.md` (on the `docs/conversion-spec` branch).

## Usage

    elf2exe3 [options] input.elf output

The output is an executable you can start from the Shell or from
Workbench. With no options it uses the same register contract as
Elf2Exe2, which is what GCC WarpOS ELFs expect, so in most cases this is
all you need:

    elf2exe3 ScummVM2_ELF scummvm

### Repacking Elf2Exe2 programs (experimental)

    elf2exe3 --repack uqm uqm.new

`--repack` takes a program that Elf2Exe2 already wrapped and writes it as a
normal elf2exe3 executable. Use it when you only have the wrapped program.
Elf2Exe2 removed the symbols, so elf2exe3 finds the function entries for
the r2 hooks itself (spec section 15.4).

**Experimental:** the function entries are a guess. It matched the real
symbols exactly on ScummVM, and repacked uqm and nblood run on the Amiga,
but a wrong guess in another program would only show up as a crash when a
callback or thread starts. If a repacked program crashes and the
Elf2Exe2 version does not, please report it.

The input must be an Elf2Exe2 executable; anything else is rejected with
the reason. Recognition (spec section 15.1):
- hunk 0 is byte for byte Elf2Exe2's 576-byte 68k startup;
- hunk 1 is BSS, hunks 2 onward are DATA or BSS, and no hunk has reloc,
  symbol or debug blocks;
- the last hunk reads cleanly as Elf2Exe2's relocation table, and every
  patched instruction is a `lis`, an addi/load/store or a branch.

### Options

| Option | Meaning |
|---|---|
| `--symbols` | Keep the global symbols (`HUNK_SYMBOL`), for debuggers. By default no symbols are written. |
| `--all-symbols` | Keep global and local symbols. Makes the file several MB bigger. |
| `--strip` | No symbols. This is the default; the option is kept for old scripts. |
| `--repack` | Experimental. The input is an Elf2Exe2 executable instead of an ELF. |
| `--stack N` | PPC stack size in bytes (`PP_StackSize`). Default: the WarpOS default. |
| `--entry SYMBOL` | PPC entry point. Default: the start of `.text`. |
| `--startup FILE` | Use this 68k hunk object as the startup instead of the built-in one, e.g. vbcc's `warpup.o` for programs that expect `argc`/`argv`. |
| `--m68k-startup SECTION` | Use 68k code from this ELF section as the startup. |
| `--no-hooks` | Leave out the r2 entry hooks. Only for testing: programs with callbacks will crash. |
| `--map FILE` | Write a layout map (used by the tests). |
| `--dump-elf FILE` | With `--repack`: also write the rebuilt ELF (used by the tests). |
| `--Werror` | Treat warnings as errors (exit code 10, no output file). |
| `-v` | Print the hunk layout and statistics. |

Exit codes: 0 success, 10 warnings with `--Werror`, 20 error.

### What the program gets at run time

The built-in startup (`startup/wosstart.s`) runs the PPC code with:

| PPC register | Value |
|---|---|
| r3 | DOS argument line, ending in a newline, without the program name |
| r4 | PowerPCBase |
| r5 | WBStartup message, or 0 from the Shell |
| r6 | length of the argument line |
| r2 | the page table base (`_LinkerDB`) |

The PPC r3 at return becomes the program's exit code. On a Workbench start
the argument line is empty (`"\n"`) and the program gets `NIL:` as input
and output, so writing to stdout is safe. If `powerpc.library` is missing,
the program prints an error (from the Shell) and returns 20.

## Input requirements

- A 32-bit big-endian PowerPC ELF, relocatable (`ld -r`) or an executable
  that still has its relocations (`ld -q`).
- Fully linked: no undefined symbols (weak ones become 0 with a warning).
- Every `R_PPC_ADDR16_HA` must be on a `lis` instruction, and every
  `R_PPC_ADDR16_LO` on an add-type instruction (`addi`, loads, stores).
  The hunk format has no reloc type for these, so elf2exe3 turns each `lis`
  into a load from a page table addressed through r2. GCC output meets
  this; the converter stops with an error if a site does not.
- The code must not change r2. GCC reserves it, so compiled code doesn't.

All other problems (unsupported reloc types, branches out of range,
too many pages for the table) are reported with the section and offset,
and no output file is written.

## Building

Prebuilt converters: Windows (`elf2exe3.exe`), Linux x86-64 (static) and
AmigaOS 68k.

    make            # host build, any C99 compiler
    make amiga      # AmigaOS 68k with vbcc (vc +aos68k -c99 -O2)
    make startup    # after editing startup/wosstart.s (needs vasm)

The built-in startup is compiled into the converter from
`src/wosstart.c`, which `make startup` regenerates.

## Testing

    make check ELF=input.elf

or by hand:

    ./elf2exe3 --map out.map input.elf out.exe
    python3 tests/verify.py input.elf out.exe out.map

For `--repack`, test against the rebuilt ELF:

    ./elf2exe3 --repack --dump-elf out.elf --map out.map wrapped out.exe
    python3 tests/verify.py out.elf out.exe out.map

`verify.py` loads the hunk file the way `LoadSeg` does, at addresses whose
low 16 bits are not zero, and checks every relocation, rewritten `lis`,
entry hook and page table slot against the ELF.

## Known limits of AmigaOS `LoadSeg`

Found on real hardware and handled by the converter:

- A `HUNK_RELOC32` group holds at most 65535 offsets, so longer lists are
  split.
- Symbol names of 32 or more longwords fail with "bad loadfile hunk", so
  names are cut to 124 characters.
- No hunk is marked FAST or CHIP: powerpc.library only places hunks
  without memory flags in PPC-reachable memory.
