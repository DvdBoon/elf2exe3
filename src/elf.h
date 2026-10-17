/* elf2exe3 - reading 32-bit big-endian PowerPC ELF files */
#ifndef ELF_H
#define ELF_H

#include <stdint.h>
#include <stdio.h>

#define SHT_NULL     0
#define SHT_PROGBITS 1
#define SHT_SYMTAB   2
#define SHT_STRTAB   3
#define SHT_RELA     4
#define SHT_NOBITS   8
#define SHT_REL      9

#define SHF_WRITE     0x1
#define SHF_ALLOC     0x2
#define SHF_EXECINSTR 0x4

#define SHN_UNDEF  0
#define SHN_LORESERVE 0xff00
#define SHN_ABS    0xfff1
#define SHN_COMMON 0xfff2

#define STB_LOCAL  0
#define STB_GLOBAL 1
#define STB_WEAK   2

#define STT_NOTYPE  0
#define STT_OBJECT  1
#define STT_FUNC    2
#define STT_SECTION 3

#define ET_REL  1
#define ET_EXEC 2
#define EM_PPC  20

typedef struct {
    char *name;
    uint32_t type, flags, addr, offset, size, link, info, align, entsize;
    /* filled in by the layout step */
    int hunk;          /* output hunk, -1 if not loaded */
    uint32_t base;     /* offset of the section inside its hunk */
} ElfSection;

typedef struct {
    char *name;
    uint32_t value, size;
    uint8_t bind, type;
    uint16_t shndx;
    /* COMMON symbols get a place in the BSS hunk during layout */
    int common_hunk;
    uint32_t common_off;
} ElfSymbol;

typedef struct {
    uint32_t offset;
    uint32_t sym;
    uint32_t type;
    int32_t addend;
} ElfRela;

typedef struct {
    FILE *f;
    const char *path;
    uint16_t type;
    uint32_t entry;
    uint32_t nsec;
    ElfSection *sec;
    uint32_t nsym;
    ElfSymbol *sym;
    int symtab;        /* index of the SHT_SYMTAB section */
} ElfFile;

void elf_open(ElfFile *e, const char *path);
void elf_close(ElfFile *e);
/* Reads a section's contents into a new buffer (size bytes). */
uint8_t *elf_read_section(ElfFile *e, uint32_t idx);
/* Reads all entries of a SHT_RELA section. */
ElfRela *elf_read_rela(ElfFile *e, uint32_t idx, uint32_t *count);

#endif
