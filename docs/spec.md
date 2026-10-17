# elf2exe3: WarpOS ELF to Amiga Hunk conversion spec

Status: draft 15 (2026-10-17). Companion notes: the Elf2Exe2 review in the project files.

## 1. Goal

elf2exe3 is an offline file converter. It reads a WarpOS PowerPC ELF file and
writes a self-contained Amiga Hunk executable that the WarpOS-patched
`LoadSeg()` loads and relocates like any other WarpOS program.

What it is not:

- Not a wrapper. Elf2Exe2 embeds the ELF in a 68k loader and relocates it in
  memory at run time (the same job `ppclibemu/loadelfwos` does). That design is
  capped at 32 MB. elf2exe3 emits real hunks with real reloc hunks, so the only
  size limits are those of the Hunk format itself (hunk sizes up to 2^30
  longwords). The output contains no ELF data and does no ELF parsing at run
  time.
- Nothing is patched at run time. Every relocation is either resolved by the
  converter or expressed as `HUNK_RELOC32`, so `LoadSeg` does all relocation
  and cache handling. `ADDR16_HA/LO`, which no hunk reloc type can express,
  are removed by rewriting the `lis` instructions (section 6.2, Dennis's
  choice).
- Not a linker. Input must already be fully linked (no undefined symbols).

## 2. Reference sample

All numbers in this spec were checked against `ScummVM/ScummVM2_ELF` from
`elf2exe2/ScummVM220_WOSELF [...].lha` (37.9 MB, too big for Elf2Exe2):

| Property | Value |
|---|---|
| ELF type | `ET_REL` (output of `ld -r`), ELFCLASS32, big endian, `EM_PPC` |
| Compiler | `GCC (GNU) 2.95.2` + `GCC/MorphOS 9.2.0` |
| Allocated sections | `.text` (23.4 MB), `CODE` (360 B, 68k code in this file), `.init`, `.fini`, `.rodata` (3.8 MB), `.gcc_except_table`, `.ctors`, `.dtors`, `.data`, `.sdata`, `.sbss`, `.bss` |
| Non-allocated | `.stab`, `.stabstr`, `.comment`, `.gnu.attributes`, `.symtab` (87k syms), `.strtab`, `.shstrtab` |
| Undefined / COMMON symbols | none / none |
| Relocations | `R_PPC_ADDR32` 129,795 · `R_PPC_ADDR16_HA` 140,666 · `R_PPC_ADDR16_LO` 161,945 · no `REL24` (all branches are intra-`.text` and already resolved) · no SDA relocs |

The `tests/*.elf` files in `ppclibemu/tests` are PowerUP objects (they leave
`PPC*` symbols undefined for ppc.library to resolve), so they are not valid
inputs. They are still handy for exercising `R_PPC_REL24`, which a WarpOS
ELF may contain when a call crosses sections.

Key consequence: **about 70 % of the relocations are `ADDR16_HA/LO`, and the
Hunk format has no reloc type for them.** Section 6.2 is the core of this spec.

Measured on the sample's `.text` (checked by decoding every reloc site):

- All 140,666 `ADDR16_HA` sites are `lis rX,sym@ha` (`addis` with `rA = 0`).
- The 161,945 `ADDR16_LO` sites are all add-type D-form instructions:
  `addi` 122,196, `lwz` 29,397, `stw` 5,433, `lfs` 2,767, `lfd` 657, `lbz` 452,
  `sth` 344, `stb` 325, `lha` 218, `lhz` 155, `stfd` 1. No `ori`.
- The HA targets fall into only **374 distinct 64 KB pages** (hunk, high half).
- Compiled code never writes `r2`: the GCC/SysV ABI reserves it, and the only
  `r2` hits in `.text` are data words decoded as instructions. The ELF's
  startup code copies `r2` into `r7` at entry, so the environment's `r2` has
  some meaning to it (open question 2).

## 3. Input validation

Accept:

- `e_ident`: `\x7fELF`, `ELFCLASS32`, `ELFDATA2MSB`.
- `e_machine == EM_PPC (20)`.
- `e_type == ET_REL`. `ET_EXEC` is accepted only if it still carries `.rela*`
  sections (linked with `--emit-relocs`/`-q`); otherwise fail with "executable
  has no relocations, relink with -r or -q".
- `EI_VERSION == 1`; `0` is accepted with a warning (SAS/C HunkObj quirk noted
  in the ppclibemu README).
- Only `SHT_RELA` reloc sections. `SHT_REL` is an error.

Reject with a clear message (list all offenders, then exit non-zero):

- undefined (`SHN_UNDEF`) symbols referenced by a reloc; weak undefined ones
  resolve to 0 with a warning,
- reloc types not listed in section 6,
- more than one `SHT_SYMTAB`.

## 4. Section to hunk mapping

Default layout ("merged"), in this hunk order:

| # | Hunk type | Contents | Memory flag |
|---|---|---|---|
| 0 | `HUNK_CODE` (0x3E9) | 68k startup object, linked in (section 8) | any |
| 1 | `HUNK_CODE` (0x3E9) | Every `SHF_EXECINSTR` section (PPC or 68k), the section holding the entry point first, in file order (`.text`, `.init`, `.fini`, …) | `HUNKF_FAST` |
| 2 | `HUNK_DATA` (0x3EA) | Every `SHF_ALLOC` `SHT_PROGBITS` non-exec section in file order (`.rodata`, `.gcc_except_table`, `.ctors`, `.dtors`, `.data`, `.sdata`, …), then the page table (6.2) | `HUNKF_FAST` |
| 3 | `HUNK_BSS` (0x3EB) | Every `SHT_NOBITS` alloc section (`.sbss`, `.bss`), then COMMON symbols | `HUNKF_FAST` |

Rules:

- Inside a hunk, each section is placed at the next offset satisfying its
  `sh_addralign`. Record `hunk_of[section]` and `base_of[section]` (offset in
  hunk); every later address calculation uses these.
- Merging all PPC code into one hunk is deliberate: it keeps `REL24`/`REL14`
  branches intra-hunk, so they are resolved at conversion time and no
  cross-hunk branch fixup is needed (the 26-bit branch range is ±32 MB, fine for a
  23 MB `.text`).
- Hunk sizes in `HUNK_HEADER` are in longwords; pad section data with zeros to
  a multiple of 4. Set bit 31 (`HUNKF_FAST`) on PPC hunks.
- Non-alloc sections (`.stab*`, `.comment`, `.gnu.attributes`, string and
  symbol tables, `.rela*` themselves) are not emitted.
- `HUNK_BSS` must not be the target of anything that needs initial data; it is
  zero-filled by `LoadSeg`.
- All code hunks, PPC or 68k, are plain `HUNK_CODE`. `HUNK_PPC_CODE` only
  appears in object files, never in executables (confirmed by Dennis). The
  first hunk is always the 68k startup; any later `HUNK_CODE` may hold PPC
  or 68k code. Only hunk types from the standard `dos/doshunks.h` (NDK 45.1)
  are used, so any `LoadSeg` loads the file. PPC code hunks get `HUNKF_FAST`.
- `--split` option: one hunk per section instead (useful for debugging). A
  `REL24` that then crosses hunks is an error, since executables have no hunk
  type for it.

**68k code in the ELF.** An executable section may hold PPC or 68k code; a
section named `CODE` can be either (Dennis). The sample's `CODE` section is
68k (it starts with `48 E7` = `movem.l`, and its `R_PPC_ADDR32` relocs sit at
2-byte-aligned offsets such as 0x9a). The converter does not need to know
which CPU a section is for: both go into `HUNK_CODE`, both only get relocs
that `HUNK_RELOC32` handles (68k code has no HA/LO or REL24), and the hunk's
memory is executable by either CPU. So there is no CPU detection and no
option for it. Only the first hunk, the generated startup, is guaranteed to
be 68k.

**Alignment caveat.** `AllocMem` only guarantees 8-byte alignment of a hunk
start. Sections asking for 16 or 32 are warned about once (cache-line or
AltiVec alignment cannot be promised). Open question: whether the WarpOS
`LoadSeg` patch allocates PPC hunks with stronger alignment.

## 5. Symbol resolution

For symbol `S` referenced by a reloc:

- normal section symbol or `STT_SECTION`: `hunk = hunk_of[shndx]`,
  `off = base_of[shndx] + st_value`.
- `SHN_COMMON`: allocate in the BSS hunk after `.bss`, aligned to `st_value`
  (that field holds the alignment for COMMON), size `st_size`. Same algorithm
  as `loadelfwos/symbols.c`, but placed in hunk 3 instead of a separate block.
- `SHN_ABS`: absolute value `st_value`, no hunk.

For a reloc with addend `A`, the target is `(hunk, off + A)` or the absolute
value `st_value + A`.

RELA rule: **the ELF field contents are ignored** and the converter writes the
computed value itself. Never add to the existing bytes.

## 6. Relocation mapping

Let `P = (phunk, poff)` be the patched location (`poff = base_of[sh_info] +
r_offset`) and `T = (thunk, toff)` the target from section 5.

### 6.1 Types the Hunk format can express

| ELF type | Action |
|---|---|
| `R_PPC_NONE` (0) | ignore |
| `R_PPC_ADDR32` (1), `R_PPC_UADDR32` (24) | Write `toff` as a 32-bit big-endian word at `P`; add `poff` to the `HUNK_RELOC32` list of `phunk` for target `thunk`. If `T` is absolute, write the value and emit no reloc. `poff` may be odd: the sample has 894 of them, because its `.eh_frame` data is linked into `.text` and holds unaligned pointers. `LoadSeg` handles odd offsets on a 68020 or later, which every PPC Amiga has. |
| `R_PPC_REL24` (10), `R_PPC_PLTREL24` (18), `R_PPC_LOCAL24PC` (23) | Same hunk: `d = toff - poff`, check `-2^25 <= d < 2^25` and `d % 4 == 0`, write `(insn & 0xFC000003) \| (d & 0x03FFFFFC)`. Different hunk (only possible with `--split`): error. Target absolute (`SHN_ABS`): error, as in Elf2Exe2 ("REL24 to absolute symbol"). |
| `R_PPC_REL14` (11) and `_BRTAKEN/_BRNTAKEN` (12, 13) | Same hunk only: 16-bit signed range, write into bits 2..15 keeping bits 0,1 and 16..31 (keep the existing `BO` hint bit for the plain type). Cross hunk: error. |
| `R_PPC_REL32` (26) | Same hunk: write `toff - poff`. Cross hunk: error. |

Each `HUNK_RELOC32` block: `0x3EC`, then for each target hunk `count, hunk#,
offsets…`, closed by a `0` longword. Sort offsets ascending. The count is a longword, but
`LoadSeg` only uses its low 16 bits (a `dbf` loop), so a list longer than
65,535 entries is split into several groups for the same target hunk. The
sample needs this: 67,650 relocs from hunk 2 to hunk 1. Without the split,
`LoadSeg` fails with "bad loadfile hunk" (found on the Amiga). Always use `HUNK_RELOC32`, never `HUNK_RELOC32SHORT`: its 16-bit offsets
cannot reach past 64 KB, and the main hunks here are megabytes.

### 6.2 `ADDR16_HA/LO`: rewrite `lis` into a table load

No hunk reloc type can write the high or high-adjusted half of an address
(the standard `doshunks.h` only has `HUNK_RELOC32`, `HUNK_ABSRELOC16`,
`HUNK_RELOC32SHORT`, `HUNK_RELRELOC32` and `HUNK_DREL*`). Instead of patching
those fields at run time, the converter rewrites the code so that the high
half comes from a table of 32-bit words, and those words get ordinary
`HUNK_RELOC32` entries. The instruction count never changes, so no branch or
offset moves.

**Page table.** For every HA reloc with a relocatable target `(thunk, toff)`,
define its page `pg = (toff + 0x8000) >> 16` (the HA value relative to the
hunk start). Each distinct `(thunk, pg)` gets one 32-bit slot holding
`pg << 16`, with a `HUNK_RELOC32` entry against `thunk`. After loading, the
slot therefore holds `hunkaddr[thunk] + (pg << 16)`. The table sits at the
end of hunk 2, 4-byte aligned. The sample needs 353 slots with hooks (374 without), about 1.4 KB.

**Base register.** The end of hunk 2 is the "r2 block": the startup
object's small data (8.1, empty for `wosstart.o`) followed by the page
table. `r2` = `_LinkerDB` = block start + 0x8000, so a signed 16-bit
displacement reaches the whole block (up to 16,384 slots when the startup
has no data). A slot is loaded with `d = table - _LinkerDB + index * 4`. A
block over 64 KB is an error.
`r2` is WarpOS's own small-data/TOC base register (checked in the WarpOS
source, `D:\powerpclib\warpos`), which makes it the natural choice:

- `ppcmacros.i` maps 68k `a4` to PPC `r2` (`_a4 equr base`, `base equr r2`),
  so `RunPPC` loads `r2` from `PP_Regs[12]`. The 68k startup sets that slot, and
  the main task starts with `r2` correct. No PPC prologue is needed.
- powerpc.library functions save the caller's `r2`, switch to their own
  (`lwz r2,PPC_NEARBASE(r2)`) and restore it, so library calls preserve it.
- WarpOS passes `r2` on to exception handlers (`EXCATTR_DATA`, `SPRG3`) and
  supports `TASKATTR_R2`/`TASKATTR_INHERITR2` for new tasks.
- GCC never writes `r2` in the sample.

**HA site.** `lis rX,sym@ha` (`addis rX,0,imm`) becomes
`lwz rX,d(r2)` with `d = slot_index * 4 - 0x8000`. Encoding:
`0x80000000 | rX << 21 | 2 << 16 | (d & 0xFFFF)`. Any HA reloc on an
instruction other than `addis` with `rA = 0` is an error (none in the
sample).

**LO site.** The 16-bit field gets the constant `toff & 0xFFFF`; no reloc.
The instruction itself is unchanged, so `addi`, loads and stores all keep
working.

**Why it is correct.** At run time the LO instruction computes
`rX + sext16(toff_lo & 0xFFFF)` with
`rX = hunkaddr + (pg_ha << 16)`. That equals `hunkaddr + toff_lo` whenever
`(toff_lo + 0x8000) >> 16 == pg_ha`, which is exactly the condition the
compiler relied on when it paired that `lis` with that LO (it holds for the
same symbol and addend, and for the shared-`lis` cases GCC only emits when
alignment guarantees it). Each section keeps its `sh_addralign` inside the
hunk, and all page arithmetic is relative to the hunk start, so the guarantee
holds no matter where `LoadSeg` puts the hunk. The converter checks the cheap part: every LO
reloc's page `(thunk, (toff + 0x8000) >> 16)` must have a slot from some HA
reloc; otherwise it errors.

**Absolute targets** (`SHN_ABS`): HA and LO fields are computed and written
directly; no rewrite.

**Not supported in v1** (error, none in the sample):

| ELF type | Why |
|---|---|
| `R_PPC_ADDR16_HI` (5) | Paired with `ori`, which ORs instead of adding, so the slot trick needs the hunk address's low half to be 0. |
| `R_PPC_ADDR16` (3) to a relocatable target | Full address cannot fit 16 bits. |
| `R_PPC_ADDR16_LO` used by `ori`/`oris`/`andi.` | Same reason as HI. Detected from the opcode. |
| HA on `addis rX,rY,…` with `rY ≠ 0` | Cannot become a single load. |

**Rejected alternatives.**

- A run-time fixup table applied by the startup (Elf2Exe2's way, earlier
  drafts of this spec): works, but patches code after loading.
- A WarpOS/EHF reloc hunk for HA/LO: none exists in Dennis's `doshunks.h`.
  vlink's `amigaehf` target may still be worth a look as a reference.

**Cost.** One `lis` becomes one `lwz` that hits a 1.5 KB table, which stays in
the data cache. The effect on speed should be negligible.

**Entry hooks for other tasks and callbacks.** `CreateTaskPPC` sets a new
task's `r2` from `TASKATTR_R2`, or the creator's `r2` with
`TASKATTR_INHERITR2`, and otherwise to **0** (`lib/functionsppc.c`). ScummVM
creates PPC threads (SDL timer and event threads, AHI) and its code contains
neither tag, so those threads would start with `r2 = 0` and crash at their
first rewritten `lis`. The same applies to PPC code that 68k code calls
through `RunPPC` with some other `a4`.

Fix: every function that can be entered through a pointer sets `r2` itself.
The relocations say exactly which functions those are: any `ADDR32`, HA/LO or
other reloc whose target is the start of an `STT_FUNC` symbol in a code
section. A function only reached by direct `bl` is always called from code
that already has `r2`. For each such function the converter:

1. Appends a trampoline to the end of hunk 1:
   ```
   hook_f:
       mflr    r0              # r0 is free at function entry (SysV ABI)
       bcl     20,31,1f
       .long   table+0x8000    # HUNK_RELOC32 against hunk 2
   1:  mflr    r2
       lwz     r2,0(r2)
       mtlr    r0
       <first instruction of f, relocated if it is a branch>
       b       f+4
   ```
2. Makes every pointer reloc that targets `f` point at `hook_f` instead.
   Direct `bl f` calls are left alone, so they skip the hook.

The sample has 27,522 address-taken functions out of 58,140. That is about
1 MB of trampolines, and roughly 6 extra instructions on each call through a
pointer (C++ virtual calls, callbacks). 697 of these functions start with a
`b` (re-encoded in the trampoline) and 946 with a `blr`/`bctr` (copied as
is). Reloc targets in the middle of a function (3,562, mostly jump tables)
are not hooked: they are reached from inside a function that already set
`r2`.

Not hooked:

- a "function" whose first word carries an `ADDR32` reloc. It is a table
  typed as `STT_FUNC`, such as `__initlist` in `.init` and `__exitlist` in
  `.fini` in the sample (pairs of pointer and priority, read as data).
- targets of relocs from `.gcc_except_table`, `.eh_frame*`, `.stab*` and
  `.debug*`: exception and debug tables, not calls through a pointer.

A function that starts with a relative `bc` the trampoline cannot reach is an
error; a relative `b` or `bl` is re-encoded, any other instruction is copied.

`--no-hooks` skips this for programs that are known not to start tasks or
take callbacks. If hooks ever prove unworkable, the fallback is the run-time
fixup table from draft 5.

## 7. Entry point

ELF entry: `e_entry` if `ET_EXEC`; otherwise offset 0 of `.text`, which is
what Elf2Exe2 and `loadelfwos` both jump to (`PP_Code` = start of the first
ELF section). `--entry SYMBOL` overrides. The section holding the entry point
is placed first in hunk 1. `r2` comes from `PP_Regs[12]` (section 8), so the
entry needs no prologue.

## 8. 68k startup (hunk 0)

DOS starts every hunk executable on the 68k at hunk 0, so hunk 0 must be 68k
startup code. The converter never generates startup code itself. It always
**links a 68k startup object** into hunk 0, using the small hunk-object
linker described in 8.1. Two startup objects are supported, one per argument
convention:

| Startup object | Passes to PPC | For ELFs whose PPC startup is… |
|---|---|---|
| `wosstart.o` (default), built from `wosstart.s` shipped with elf2exe3 | raw argument line, `PowerPCBase`, WB message, line length (Elf2Exe2 contract) | GCC WarpOS ELFs like ScummVM2_ELF (`startupwos.c`), the target format |
| vbcc `warpup.o` (`--startup`) | `argc`, `argv` or WB message | written for vbcc's `__ppc_startup` convention |

Both set `a4 = _LinkerDB`, so the main task starts with `r2` pointing at the
page table. `wosstart.s` is 68k assembler for `vasmm68k_mot -Fhunk` (vbcc's
assembler), so the whole tool chain is vbcc-based. If the ELF itself contains
a 68k startup section, `--m68k-startup SECTION` uses that instead.

**What ScummVM's startup expects** (disassembled `startupwos.c` at `.text`
offset 0, Dennis confirmed this ELF is the target format):

- On entry it copies `r2` to `r7` and `r31` to `r8`.
- If `r31` is the magic `0x1F1F1F1F` (set by ppclibemu's LoadSeg patch), it
  converts that launcher's arguments first. It reads `PowerPCBase` and the WB
  message from the structure in `r2`. It skips the quoted program name in
  `r3` (`"name" args`), appends `"\n"`, and computes the length into `r6`.
  Then it falls through to the normal path.
- Normal path (offset 0x238): stores `r3` (argument line), `r4`
  (`PowerPCBase`, also reading its fields at 0x22 and 0x26, the SysBase and
  DOSBase pointers), `r5` (WB message) and `r6` (line length) into globals.

So the native contract is **Elf2Exe2's**: `r3` = raw argument line without
program name, ending in a newline; `r4` = `PowerPCBase`; `r5` = WB message or
0; `r6` = line length. `loadelfwos`'s format (`"name args "` with no `r5`/`r6`)
would make the program name the first argument and leave the length
undefined, so `wosstart.s` follows Elf2Exe2, not `loadelfwos`.

| Field | 68k reg | PPC reg | Value |
|---|---|---|---|
| `PP_Code` | | | `__ppc_startup` (`EXT_REF32`), resolved to the ELF entry (start of `.text`) |
| `PP_Regs[0]` | d0 | r3 | `a0`: the DOS argument line as received, newline at the end, no program name |
| `PP_Regs[1]` | d1 | r4 | `PowerPCBase` |
| `PP_Regs[8]` | a0 | r5 | `WBStartup` message, or 0 from CLI |
| `PP_Regs[9]` | a1 | r6 | `d0`: argument line length |
| `PP_Regs[12]` | a4 | r2 | `_LinkerDB` = page table + 0x8000 (`EXT_REF32`, resolved by the converter); Elf2Exe2 leaves it 0 |
| `PP_Offset`, `PP_Flags`, `PP_Stack`, `PP_StackSize` | | | 0 (`--stack N` sets `PP_StackSize`) |

The PPC register column is WarpOS's non-linear mapping from `ppcmacros.i`
(`_d0=r3`, `_d1=r4`, `_a0=r5`, `_a1=r6`, `_a4=r2`), which applies because
`PP_Flags` is 0. `r31` must not be `0x1F1F1F1F`. Since `PP_Regs` does not
reach `r31`, it holds whatever the kernel leaves there; a check of the WarpOS
`RunPPC` path for that value is part of on-target testing. The return code is
`PP_Regs[0]` after `RunPPC`.

Steps (as Elf2Exe2's stub, disassembled from the `uqm` file Dennis
supplied; it is byte-identical to the one in `Elf2Exe2`). `wosstart.s` keeps
all its state on the stack, unlike Elf2Exe2's stub, which writes into its own
code hunk:

1. Save `SysBase`, `a0` (DOS argument line) and `d0` (its length).
2. `FindTask(NULL)`. If `pr_CLI` is 0 (Workbench start), `WaitPort` and
   `GetMsg` on `pr_MsgPort` to take the `WBStartup` message. Then pass the
   line `"\n"` with length 1, because `a0`/`d0` are not an argument line on
   a Workbench start (Elf2Exe2 passes them anyway).
3. `OpenLibrary("powerpc.library", 14)`. On failure print an error (CLI only)
   and return 20. Elf2Exe2 silently returns 0 here.
4. Fill `PPCArgs` on the stack and call `RunPPC` (LVO -30). Unlike Elf2Exe2,
   there is no relocation pass: `LoadSeg` has done all of it. If `RunPPC`
   itself fails (not `PPERR_SUCCESS`), return 20.
5. `CloseLibrary`, reply the `WBStartup` message if any (`Forbid()` +
   `ReplyMsg()`), and return `PP_Regs[0]` in `d0`.

No cache handling is needed: nothing is modified after `LoadSeg` (Dennis).
The file can be made resident.

`wosstart.o` (444 bytes, 312 bytes of code) is built into the converter as
`src/wosstart.c`, generated from `startup/wosstart.o`, so the tool needs no
extra file. It exports `__ppc_stacksize`, a longword that `--stack N` sets
and the startup copies to `PP_StackSize`. A startup object without that
symbol (vbcc's `warpup.o`) cannot take `--stack`.

### 8.1 Linking a startup object; vbcc's `warpup.o`

`--startup FILE` selects the startup object (default: `wosstart.o`). The
linker was designed against vbcc's
`targets/ppc-warpos/lib/warpup.o` ("vbccWOS startup 2.3", 1,328 bytes),
analysed from Dennis's vbcc install:

- Hunk object (EHF) with a 68k `HUNK_CODE` "startup" (628 bytes) and small
  sections `.text`, `.tocd` (76 bytes: `_SysBase`, `_DOSBase`,
  `_PowerPCBase`, `_WBenchMsg`, `__stdin/out/err`, `_errno`), `.rodata`,
  `.data`, `.bss`.
- External references: `_LinkerDB` (`EXT_REF32`, loaded into `a4`) and
  `__ppc_startup` (`EXT_REF32`, used as `PP_Code`). Its `.tocd` variables are
  accessed `a4`-relative through `HUNK_DREL16`.
- It opens dos.library and powerpc.library V15, splits the command line into
  `argc`/`argv` (with quotes and `*N`/`*E` escapes), opens a `NIL:` console
  for Workbench starts, and calls `RunPPC` with `PP_Regs[0]` = `argc` (r3),
  `PP_Regs[1]` = `argv` or the `WBStartup` message (r4), and
  `PP_Regs[12]` = `a4` = `_LinkerDB` (r2). The return code is
  `PP_Regs[0]`.

That last point fits section 6.2 directly: vbcc's startup already sets `r2`
to `_LinkerDB`, so the converter defines `_LinkerDB` as the r2 block
start + 0x8000 (6.2) and no extra work is needed for the main task.

What the converter must do to link it (a small hunk-object linker):

1. Read the object's hunks. Put its first section (68k code) in hunk 0, and
   its data sections (`.tocd`, `.rodata`, `.data`) at the start of the r2
   block, before the page table, all within ±32 KB of `_LinkerDB`. Put its
   `.bss` at the end of hunk 3 and any other code (`.text`, PPC, 32 bytes)
   at the end of the ELF code in hunk 1, before the entry hooks.
2. Turn its `HUNK_RELOC32` into output `HUNK_RELOC32` with remapped hunk
   numbers and offsets.
3. Resolve `HUNK_DREL16` at conversion time: write
   `target_offset - LinkerDB_offset` (both in hunk 2) into the 16-bit field.
4. Resolve `_LinkerDB` and `__ppc_startup` (`EXT_REF32`) to `HUNK_RELOC32`
   entries. `__ppc_startup` is the ELF symbol of that name, or the ELF entry
   with `--entry`.
5. Resolve any other reference against the object's own definitions, then
   the ELF's global symbols; error if neither has it. `EXT_DEXT16` (a4
   relative) is resolved like `HUNK_DREL16`.
6. The ELF's undefined symbols are looked up in the object's definitions
   too, so a vbcc-built ELF can use `_PowerPCBase`, `_SysBase` and the other
   `.tocd` variables of `warpup.o`.

Choosing between the two: vbcc's startup passes `argc`/`argv`, Elf2Exe2's
contract passes the raw line, and the ELF's PPC startup expects one of
them. That is why `wosstart.o` exists and is the default, while being linked
exactly like vbcc's `warpup.o`. An adapter that turns `argc`/`argv` back
into a string was considered and rejected: quoting is lost when joining
`argv`.

## 9. Symbols and debug data

- Default: one `HUNK_SYMBOL` (0x3F0) per hunk with all `STB_GLOBAL` and
  `STB_WEAK` `STT_FUNC`/`STT_OBJECT` symbols, value = offset in hunk. Names are
  padded to longwords; length field is the longword count.
- `--all-symbols`: also locals (sample: 87k symbols, ~3.7 MB of names).
- `--strip`: no `HUNK_SYMBOL`.
- `.stab`/`.stabstr`: dropped. A later version could wrap them in
  `HUNK_DEBUG` (0x3F1).

## 10. Output file layout

```
HUNK_HEADER 0x3F3
  0                      (no resident library names)
  nhunks, 0, nhunks-1
  size[i] | flags        (longwords; bit31=FAST)
for each hunk i:
  HUNK_CODE / HUNK_DATA  + size + data
  or HUNK_BSS + size
  HUNK_RELOC32 block     (if any)
  HUNK_SYMBOL block      (unless --strip)
  HUNK_END 0x3F2
```

## 11. Command line

```
elf2exe3 [options] input.elf output.exe
  --split               one hunk per section
  --entry SYMBOL        PPC entry point (default .text+0)
  --no-hooks            do not add r2 entry hooks (6.2)
  --m68k-startup SECT   use this ELF section as the 68k startup (hunk 0)
  --startup FILE        68k startup object for hunk 0 (default wosstart.o; vbcc warpup.o for argc/argv programs)
  --stack N             PPC stack size
  --strip | --all-symbols
  -v                    print section map, hunk sizes, reloc counts
```

Exit codes: 0 ok, 10 warnings treated as errors (`--Werror`), 20 error.

## 11a. Implementation

- Language: C99, compiled with vbcc (Dennis). No GCC extensions and no
  compiler-specific code, so the same source also builds on a PC for the host
  tests in section 13.
- Default build: `vc +aos68k -c99 -O2`, so the tool runs on any Amiga, with or
  without PPC. A `vc +warpos` build is optional.
- All ELF and hunk values are read and written byte by byte as big endian
  through small helpers (`rd32`, `wr32`, …). Never cast file buffers to
  structs, so host byte order and struct padding do not matter.
- Memory: ScummVM2_ELF is 38 MB. Do not load the whole file. Read the section
  headers, symbol table and one `.rela` section at a time with `fseek`/`fread`.
  Keep each output hunk's data in memory only while that hunk is built and
  written. Peak use for the sample is about the size of `.text` (23 MB) plus
  its reloc list.
- Use only the C standard library (`stdio`, `stdlib`, `string`, `stdint`), so
  no AmigaOS calls are needed in the converter itself.

## 12. Edge cases checklist

| Case | Handling |
|---|---|
| Undefined symbol | error, list all |
| Weak undefined | value 0, warning |
| `REL24` out of ±32 MB, or to absolute symbol | error |
| `ADDR32` at odd offset | allowed (needs a 68020+, see 6.1) |
| `ADDR16`, `ADDR16_HI`, or LO on `ori`-type instructions, to a relocatable target | error (6.2) |
| HA on anything but `lis` | error (6.2) |
| LO whose page has no slot | error (6.2) |
| More than 16,384 page slots | error |
| Hooked function whose first instruction is PC-relative other than `b`/`bl`/`bc` (`mflr` excluded) | error |
| Cross-hunk `REL24`/`REL32` (only with `--split`) | error |
| SDA relocs (`SDAREL16`, `EMB_SDA21`, `EMB_SDA2REL`…) | error in v1. They need `r2` set to `_SDA_BASE_` by startup code and `.sdata`+`.sbss` in one 64 KB window of one hunk. Not used by the sample. |
| `GOT16*`, `PLT*` (other than `PLTREL24`), `COPY`, `GLOB_DAT`, `JMP_SLOT`, `RELATIVE` | error (dynamic linking, not WarpOS) |
| Section with `sh_addralign` > 8 | warning |
| Empty section | skipped, but symbols in it resolve to its hunk offset |
| Reloc section whose target is non-alloc (`.rela.stab`) | ignored |
| ELF with no PPC code (pure 68k) | still valid |
| Output > 2^30 longwords per hunk | error (format limit) |

## 13. Verification plan

1. **Relocation check (host side).** Pick fake hunk addresses whose low
   16 bits are not zero, model `LoadSeg` (apply `HUNK_RELOC32`), and relocate
   the same ELF with a port of `loadelfwos/relocelf.c` at the same addresses.
   Every byte outside rewritten `lis` sites and LO fields must match. For each
   HA/LO pair, evaluate the rewritten `lwz` + LO instruction and compare the
   effective address with the original `lis` + LO result.
2. **Structure check.** A hunk dumper parses the output (header sizes match
   hunk lengths, every reloc offset is inside its hunk).
3. **On target.** Run `hello_world` and ScummVM under WarpOS.

## 14. Open questions for Dennis

1. Should Hunk symbols be on by default (bigger file) or off?
2. Are the entry hooks (6.2) acceptable? They cost about 1 MB and a few
   instructions per call through a pointer in ScummVM.
