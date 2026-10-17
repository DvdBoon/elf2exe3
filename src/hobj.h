/* elf2exe3 - reading Amiga hunk object files (the 68k startup, spec 8.1) */
#ifndef HOBJ_H
#define HOBJ_H

#include <stddef.h>
#include <stdint.h>
#include "util.h"

#define HUNK_UNIT         0x3E7
#define HUNK_NAME         0x3E8
#define HUNK_EXT          0x3EF
#define HUNK_DEBUG        0x3F1
#define HUNK_DREL32       0x3F7
#define HUNK_DREL16       0x3F8
#define HUNK_DREL8        0x3F9
#define HUNK_RELOC32SHORT 0x3FC
#define HUNK_PPC_CODE     0x4E9

#define EXT_DEF     1
#define EXT_ABS     2
#define EXT_REF32   129
#define EXT_DEXT16  134

typedef struct {
    char *name;
    uint8_t type;          /* EXT_REF32, EXT_DEXT16, ... */
    U32Vec offs;           /* offsets in the section holding the reference */
} HRef;

typedef struct {
    char *name;
    uint8_t type;          /* EXT_DEF or EXT_ABS */
    uint32_t value;
    int sec;               /* section the definition belongs to */
} HDef;

typedef struct {
    char *name;
    uint32_t type;         /* HUNK_CODE, HUNK_DATA or HUNK_BSS */
    uint32_t size;         /* bytes */
    uint8_t *data;         /* NULL for BSS */
    U32Vec rel_sec, rel_off;     /* HUNK_RELOC32: target section, offset */
    U32Vec drel_sec, drel_off;   /* HUNK_DREL16 */
    HRef *refs;
    size_t nrefs;
    /* placement in the output, filled by the converter */
    int hunk;
    uint32_t base;
} HSec;

typedef struct {
    HSec *sec;
    size_t nsec;
    HDef *defs;
    size_t ndefs;
} HObj;

/* Parses an object file image; fatal() on malformed input. */
void hobj_parse(HObj *o, const uint8_t *buf, size_t len, const char *name);
/* Reads and parses a file. */
void hobj_load(HObj *o, const char *path);

#endif
