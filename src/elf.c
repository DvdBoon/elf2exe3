/* elf2exe3 - reading 32-bit big-endian PowerPC ELF files
 *
 * The file is never loaded as a whole: headers, the symbol table and one
 * section at a time are read with fseek/fread, so a 38 MB input does not
 * need 38 MB of RAM on the Amiga.
 */
#include <stdlib.h>
#include <string.h>

#include "elf.h"
#include "util.h"

static void read_at(ElfFile *e, uint32_t off, void *buf, uint32_t n)
{
    if (n == 0)
        return;
    if (e->mem) {
        if (off > e->memsize || e->memsize - off < n)
            fatal("%s: unexpected end of file (offset %lu, %lu bytes)",
                  e->path, (unsigned long)off, (unsigned long)n);
        memcpy(buf, e->mem + off, n);
        return;
    }
    if (fseek(e->f, (long)off, SEEK_SET) != 0 || fread(buf, 1, n, e->f) != n)
        fatal("%s: unexpected end of file (offset %lu, %lu bytes)", e->path,
              (unsigned long)off, (unsigned long)n);
}

static char *dupstr(const char *tab, uint32_t tabsize, uint32_t off)
{
    const char *s;
    size_t len;
    char *r;
    if (off >= tabsize)
        return NULL;
    s = tab + off;
    len = 0;
    while (off + len < tabsize && s[len])
        len++;
    r = xmalloc(len + 1);
    memcpy(r, s, len);
    r[len] = 0;
    return r;
}

static void parse(ElfFile *e);

void elf_open(ElfFile *e, const char *path)
{
    memset(e, 0, sizeof(*e));
    e->path = path;
    e->f = fopen(path, "rb");
    if (!e->f)
        fatal("cannot open %s", path);
    parse(e);
}

void elf_open_mem(ElfFile *e, const uint8_t *buf, uint32_t size,
                  const char *name)
{
    memset(e, 0, sizeof(*e));
    e->path = name;
    e->mem = buf;
    e->memsize = size;
    parse(e);
}

static void parse(ElfFile *e)
{
    const char *path = e->path;
    uint8_t h[52];
    uint32_t shoff, shentsize, shstrndx, i;
    uint8_t *shdr;
    uint32_t *nameoff;
    char *shstr = NULL;
    uint32_t shstrsize = 0;

    e->symtab = -1;
    read_at(e, 0, h, sizeof(h));
    if (memcmp(h, "\177ELF", 4) != 0) {
        if (rd32(h) == 0x3F3)
            fatal("%s: is an Amiga hunk executable, not an ELF file (use "
                  "--repack for files made by Elf2Exe2)", path);
        fatal("%s: not an ELF file", path);
    }
    if (h[4] != 1)
        fatal("%s: not a 32-bit ELF file", path);
    if (h[5] != 2)
        fatal("%s: not a big-endian ELF file", path);
    if (h[6] == 0)
        warning("%s: ELF version 0 (SAS/C HunkObj style)", path);
    else if (h[6] != 1)
        fatal("%s: unknown ELF version %d", path, h[6]);

    e->type = rd16(h + 16);
    if (rd16(h + 18) != EM_PPC)
        fatal("%s: not a PowerPC ELF file (machine %u)", path, rd16(h + 18));
    if (e->type != ET_REL && e->type != ET_EXEC)
        fatal("%s: ELF type %u is neither relocatable nor executable", path,
              e->type);
    e->entry = rd32(h + 24);
    shoff = rd32(h + 32);
    shentsize = rd16(h + 46);
    e->nsec = rd16(h + 48);
    shstrndx = rd16(h + 50);
    if (shentsize != 40)
        fatal("%s: unexpected section header size %lu", path,
              (unsigned long)shentsize);
    if (e->nsec == 0)
        fatal("%s: no section headers", path);

    shdr = xmalloc(40 * e->nsec);
    read_at(e, shoff, shdr, 40 * e->nsec);
    e->sec = xcalloc(e->nsec, sizeof(ElfSection));
    nameoff = xcalloc(e->nsec, sizeof(uint32_t));
    for (i = 0; i < e->nsec; i++) {
        uint8_t *p = shdr + 40 * i;
        ElfSection *s = &e->sec[i];
        s->type = rd32(p + 4);
        s->flags = rd32(p + 8);
        s->addr = rd32(p + 12);
        s->offset = rd32(p + 16);
        s->size = rd32(p + 20);
        s->link = rd32(p + 24);
        s->info = rd32(p + 28);
        s->align = rd32(p + 32);
        s->entsize = rd32(p + 36);
        s->hunk = -1;
        nameoff[i] = rd32(p);
    }
    if (shstrndx < e->nsec && e->sec[shstrndx].type == SHT_STRTAB) {
        shstrsize = e->sec[shstrndx].size;
        shstr = xmalloc(shstrsize + 1);
        read_at(e, e->sec[shstrndx].offset, shstr, shstrsize);
        shstr[shstrsize] = 0;
    }
    for (i = 0; i < e->nsec; i++) {
        char *n = shstr ? dupstr(shstr, shstrsize, nameoff[i]) : NULL;
        e->sec[i].name = n ? n : dupstr("", 1, 0);
    }
    free(shstr);
    free(shdr);
    free(nameoff);

    /* Symbol table */
    for (i = 0; i < e->nsec; i++) {
        if (e->sec[i].type == SHT_SYMTAB) {
            if (e->symtab >= 0)
                fatal("%s: more than one symbol table", path);
            e->symtab = (int)i;
        }
        if (e->sec[i].type == SHT_REL)
            fatal("%s: section %s uses SHT_REL; only SHT_RELA is supported",
                  path, e->sec[i].name);
    }
    if (e->symtab >= 0) {
        ElfSection *st = &e->sec[e->symtab];
        uint8_t *raw;
        char *str = NULL;
        uint32_t strsize = 0;
        if (st->link < e->nsec) {
            strsize = e->sec[st->link].size;
            str = xmalloc(strsize + 1);
            read_at(e, e->sec[st->link].offset, str, strsize);
            str[strsize] = 0;
        }
        e->nsym = st->size / 16;
        raw = xmalloc(st->size);
        read_at(e, st->offset, raw, st->size);
        e->sym = xcalloc(e->nsym, sizeof(ElfSymbol));
        for (i = 0; i < e->nsym; i++) {
            uint8_t *p = raw + 16 * i;
            ElfSymbol *y = &e->sym[i];
            char *n = str ? dupstr(str, strsize, rd32(p)) : NULL;
            y->value = rd32(p + 4);
            y->size = rd32(p + 8);
            y->bind = (uint8_t)(p[12] >> 4);
            y->type = (uint8_t)(p[12] & 15);
            y->shndx = rd16(p + 14);
            y->common_hunk = -1;
            if (y->type == STT_SECTION && y->shndx < e->nsec)
                n = dupstr(e->sec[y->shndx].name,
                           (uint32_t)strlen(e->sec[y->shndx].name) + 1, 0);
            y->name = n ? n : dupstr("", 1, 0);
        }
        free(raw);
        free(str);
    }
}

void elf_close(ElfFile *e)
{
    uint32_t i;
    if (e->f)
        fclose(e->f);
    for (i = 0; i < e->nsec; i++)
        free(e->sec[i].name);
    for (i = 0; i < e->nsym; i++)
        free(e->sym[i].name);
    free(e->sec);
    free(e->sym);
    memset(e, 0, sizeof(*e));
}

uint8_t *elf_read_section(ElfFile *e, uint32_t idx)
{
    ElfSection *s = &e->sec[idx];
    uint8_t *buf = xmalloc(s->size);
    if (s->type != SHT_NOBITS)
        read_at(e, s->offset, buf, s->size);
    else
        memset(buf, 0, s->size);
    return buf;
}

ElfRela *elf_read_rela(ElfFile *e, uint32_t idx, uint32_t *count)
{
    ElfSection *s = &e->sec[idx];
    uint32_t n = s->size / 12, i;
    uint8_t *raw = elf_read_section(e, idx);
    ElfRela *r = xcalloc(n, sizeof(ElfRela));
    for (i = 0; i < n; i++) {
        uint8_t *p = raw + 12 * i;
        uint32_t info = rd32(p + 4);
        r[i].offset = rd32(p);
        r[i].sym = info >> 8;
        r[i].type = info & 0xff;
        r[i].addend = (int32_t)rd32(p + 8);
    }
    free(raw);
    *count = n;
    return r;
}
