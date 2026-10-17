/* elf2exe3 - Amiga hunk output */
#ifndef HUNK_H
#define HUNK_H

#include <stdint.h>
#include "util.h"

#define HUNK_CODE    0x3E9
#define HUNK_DATA    0x3EA
#define HUNK_BSS     0x3EB
#define HUNK_RELOC32 0x3EC
#define HUNK_SYMBOL  0x3F0
#define HUNK_END     0x3F2
#define HUNK_HEADER  0x3F3

#define HUNKF_FAST   0x80000000UL

/* Fixed hunk layout (spec section 4). */
enum { H_START = 0, H_CODE = 1, H_DATA = 2, H_BSS = 3, NHUNKS = 4 };

typedef struct {
    char *name;
    uint32_t off;
} HunkSym;

typedef struct {
    uint32_t type;         /* HUNK_CODE, HUNK_DATA or HUNK_BSS */
    uint32_t memflags;     /* HUNKF_FAST or 0 */
    uint32_t size;         /* bytes */
    uint8_t *data;         /* size bytes, NULL for BSS */
    U32Vec reloc[NHUNKS];  /* RELOC32 offsets, per target hunk */
    HunkSym *syms;
    size_t nsyms, capsyms;
} Hunk;

void hunk_add_sym(Hunk *h, const char *name, uint32_t off);
/* Writes the hunk executable; returns 0 on success. */
int hunk_write(const char *path, Hunk *h, int nhunks);

#endif
