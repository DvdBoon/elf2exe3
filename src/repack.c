/* elf2exe3 - --repack: reading executables made by Elf2Exe2
 *
 * Elf2Exe2 output (docs/spec.md section 15):
 *   hunk 0      CODE, Elf2Exe2's 576-byte 68k startup
 *   hunk 1      BSS, the ELF's COMMON symbols
 *   hunk 2..n-2 one DATA or BSS hunk per ELF section, .text first
 *   hunk n-1    DATA, Elf2Exe2's relocation table
 * and no reloc or symbol blocks. The table is turned back into ELF RELA
 * entries against one section per hunk, so the normal conversion path does
 * the rest. Function entries are not known (there are no symbols), so they
 * are guessed from the relocation targets for the r2 entry hooks.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "elf.h"
#include "hunk.h"
#include "repack.h"
#include "util.h"

#define STUB_SIZE 576

/* Hunk 0 of every Elf2Exe2 executable (identical in Elf2Exe2 itself,
 * uqm and nblood.warpos). */
static const uint8_t e2e2_stub[STUB_SIZE] = {
    0x48, 0xe7, 0x7f, 0xfe, 0x43, 0xfa, 0x02, 0x0c, 0x22, 0xb9, 0x00, 0x00,
    0x00, 0x04, 0x43, 0xfa, 0x02, 0x06, 0x22, 0x88, 0x43, 0xfa, 0x02, 0x04,
    0x22, 0x80, 0x2c, 0x7a, 0x01, 0xf6, 0x93, 0xc9, 0x4e, 0xae, 0xfe, 0xda,
    0x26, 0x40, 0x4a, 0xab, 0x00, 0xac, 0x66, 0x00, 0x00, 0x18, 0x41, 0xeb,
    0x00, 0x5c, 0x4e, 0xae, 0xfe, 0x80, 0x41, 0xeb, 0x00, 0x5c, 0x4e, 0xae,
    0xfe, 0x8c, 0x43, 0xfa, 0x01, 0xe6, 0x22, 0x80, 0x2c, 0x7a, 0x01, 0xcc,
    0x43, 0xfa, 0x01, 0xe4, 0x20, 0x3c, 0x00, 0x00, 0x00, 0x0e, 0x4e, 0xae,
    0xfd, 0xd8, 0x43, 0xfa, 0x01, 0xd2, 0x22, 0x80, 0x67, 0x00, 0x01, 0xae,
    0x41, 0xfa, 0xff, 0x9a, 0x20, 0x3c, 0x00, 0x00, 0x00, 0x01, 0x22, 0x10,
    0x67, 0x00, 0x00, 0x0c, 0xe5, 0x81, 0x20, 0x41, 0x52, 0x80, 0x60, 0x00,
    0xff, 0xf2, 0x43, 0xfa, 0x01, 0xa2, 0x22, 0x80, 0xe5, 0x80, 0x9f, 0xc0,
    0x43, 0xfa, 0x01, 0x9c, 0x22, 0x8f, 0x22, 0x7a, 0x01, 0x96, 0x20, 0x3a,
    0x01, 0x8e, 0x53, 0x80, 0x41, 0xfa, 0xff, 0x6a, 0x22, 0xc8, 0x22, 0x28,
    0xff, 0xfc, 0xe5, 0x81, 0x58, 0x81, 0x20, 0x41, 0x51, 0xc8, 0xff, 0xf2,
    0x22, 0x7a, 0x01, 0x78, 0x20, 0x3a, 0x01, 0x70, 0x53, 0x80, 0x20, 0x71,
    0x0c, 0x00, 0x20, 0x18, 0x67, 0x00, 0x00, 0xe4, 0x24, 0x71, 0x0c, 0x00,
    0x2e, 0x18, 0x67, 0x00, 0xff, 0xf2, 0x20, 0x18, 0x26, 0x31, 0x0c, 0x00,
    0x24, 0x18, 0x6a, 0x00, 0x00, 0xb4, 0x08, 0x02, 0x00, 0x1e, 0x67, 0x00,
    0x00, 0x6e, 0x08, 0x02, 0x00, 0x1d, 0x66, 0x00, 0x00, 0x3e, 0x08, 0x02,
    0x00, 0x1c, 0x67, 0x00, 0x00, 0x16, 0x02, 0x82, 0x0f, 0xff, 0xff, 0xff,
    0x38, 0x32, 0x28, 0x00, 0xd8, 0x43, 0x35, 0x84, 0x28, 0x00, 0x60, 0x00,
    0x00, 0x8c, 0x02, 0x82, 0x0f, 0xff, 0xff, 0xff, 0x28, 0x18, 0xd8, 0x83,
    0x4a, 0x44, 0x6a, 0x00, 0x00, 0x08, 0x06, 0x84, 0x00, 0x01, 0x00, 0x00,
    0x48, 0x44, 0x35, 0x84, 0x28, 0x00, 0x60, 0x00, 0x00, 0x6c, 0x02, 0x82,
    0x0f, 0xff, 0xff, 0xff, 0x47, 0xf2, 0x28, 0x00, 0x28, 0x13, 0x02, 0x84,
    0x03, 0xff, 0xff, 0xfc, 0xd8, 0x83, 0x98, 0x8b, 0x02, 0x84, 0x03, 0xff,
    0xff, 0xfc, 0x02, 0x93, 0xfc, 0x00, 0x00, 0x03, 0x89, 0x93, 0x60, 0x00,
    0x00, 0x44, 0x28, 0x02, 0x02, 0x84, 0x00, 0x3f, 0xff, 0xff, 0xe5, 0x8c,
    0x3a, 0x32, 0x48, 0x02, 0x48, 0x45, 0x2c, 0x02, 0x48, 0x46, 0xe8, 0x8e,
    0x02, 0x86, 0x00, 0x00, 0x03, 0xfc, 0xdc, 0x84, 0x3a, 0x32, 0x68, 0x02,
    0xda, 0x83, 0x4a, 0x45, 0x6a, 0x00, 0x00, 0x08, 0x06, 0x85, 0x00, 0x01,
    0x00, 0x00, 0x35, 0x85, 0x68, 0x02, 0x48, 0x45, 0x35, 0x85, 0x48, 0x02,
    0x60, 0x00, 0x00, 0x06, 0xd7, 0xb2, 0x28, 0x00, 0x53, 0x87, 0x0c, 0x87,
    0x00, 0x00, 0x00, 0x05, 0x62, 0x00, 0xff, 0x3a, 0x4a, 0x87, 0x66, 0x00,
    0xff, 0x34, 0x60, 0x00, 0xff, 0x24, 0x4f, 0xef, 0xff, 0x70, 0x22, 0x7a,
    0x00, 0x7e, 0x2e, 0xa9, 0x00, 0x08, 0x42, 0xaf, 0x00, 0x04, 0x42, 0xaf,
    0x00, 0x08, 0x42, 0xaf, 0x00, 0x0c, 0x42, 0xaf, 0x00, 0x10, 0x2f, 0x7a,
    0x00, 0x5a, 0x00, 0x14, 0x2f, 0x7a, 0x00, 0x68, 0x00, 0x18, 0x2f, 0x7a,
    0x00, 0x5e, 0x00, 0x34, 0x2f, 0x7a, 0x00, 0x4c, 0x00, 0x38, 0x20, 0x4f,
    0x2c, 0x7a, 0x00, 0x54, 0x4e, 0xae, 0xff, 0xe2, 0x2e, 0x2f, 0x00, 0x14,
    0x4f, 0xef, 0x00, 0x90, 0x20, 0x3a, 0x00, 0x38, 0x4f, 0xf7, 0x0c, 0x00,
    0x22, 0x7a, 0x00, 0x3c, 0x2c, 0x7a, 0x00, 0x20, 0x4e, 0xae, 0xfe, 0x62,
    0x24, 0x3a, 0x00, 0x2c, 0x67, 0x00, 0x00, 0x0c, 0x4e, 0xae, 0xff, 0x7c,
    0x22, 0x42, 0x4e, 0xae, 0xfe, 0x86, 0x20, 0x07, 0x4c, 0xdf, 0x7f, 0xfe,
    0x4e, 0x75, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x70, 0x6f, 0x77, 0x65, 0x72, 0x70,
    0x63, 0x2e, 0x6c, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x00, 0x00, 0x00,
};

#define R_ADDR32 1
#define R_LO     4
#define R_HA     6
#define R_REL24  10

typedef struct {
    uint32_t type;           /* HUNK_DATA or HUNK_BSS (CODE only for 0) */
    uint32_t size;           /* bytes */
    const uint8_t *data;     /* NULL for BSS */
    int code;                /* holds PPC code (instruction relocs) */
    U32Vec r_off, r_info, r_add;   /* RELA entries patching this hunk */
    U32Vec a32;              /* ADDR32 sites (to spot tables in code) */
    U32Vec ha_off, ha_key, ha_add; /* lis sites: offset, reg<<16|hunk, A */
    U32Vec lo_off, lo_hunk;  /* lone LO sites to resolve */
    U32Vec func;             /* guessed function entries */
} WHunk;

typedef struct {
    uint8_t *d;
    uint32_t n, cap;
} Buf;

static void need(Buf *b, uint32_t n)
{
    if (b->n + n > b->cap) {
        while (b->n + n > b->cap)
            b->cap = b->cap ? b->cap * 2 : 65536;
        b->d = xrealloc(b->d, b->cap);
    }
}

static void put(Buf *b, const void *p, uint32_t n)
{
    need(b, n);
    if (p)
        memcpy(b->d + b->n, p, n);
    else
        memset(b->d + b->n, 0, n);
    b->n += n;
}

static void put32(Buf *b, uint32_t v)
{
    need(b, 4);
    wr32(b->d + b->n, v);
    b->n += 4;
}

static void put16(Buf *b, uint16_t v)
{
    need(b, 2);
    wr16(b->d + b->n, v);
    b->n += 2;
}

static void align4(Buf *b)
{
    while (b->n & 3)
        put(b, NULL, 1);
}

static const char *g_path;

static void notwrapped(const char *why)
{
    fatal("%s: not an Elf2Exe2 executable: %s", g_path, why);
}

static void damaged(const char *why, unsigned long at)
{
    fatal("%s: Elf2Exe2 relocation table is damaged at byte %lu: %s",
          g_path, at, why);
}

static uint8_t *read_file(const char *path, uint32_t *len)
{
    FILE *f = fopen(path, "rb");
    long n = 0;
    uint8_t *buf;
    if (!f)
        fatal("cannot open %s", path);
    if (fseek(f, 0, SEEK_END) != 0 || (n = ftell(f)) < 0 ||
        fseek(f, 0, SEEK_SET) != 0)
        fatal("%s: cannot get the file size", path);
    buf = xmalloc(n ? (size_t)n : 1);
    if (fread(buf, 1, (size_t)n, f) != (size_t)n)
        fatal("%s: read error", path);
    fclose(f);
    *len = (uint32_t)n;
    return buf;
}

static int is_lo_op(uint32_t insn)
{
    uint32_t op = insn >> 26;
    return op == 14 || (op >= 32 && op <= 55);
}

static int is_lis(uint32_t insn)
{
    return (insn >> 26) == 15 && ((insn >> 16) & 31) == 0;
}

/* Data, not code: an illegal primary opcode 0, or a small negative
 * number. In the ScummVM ELF this tells every function start apart from
 * the jump tables that code loads with lis/addi. */
static int looks_like_data(uint32_t w)
{
    return (w >> 26) == 0 || (w >> 16) == 0xFFFF;
}

static void add_rel(WHunk *h, uint32_t off, uint32_t sym, uint32_t type,
                    uint32_t addend)
{
    u32_push(&h->r_off, off);
    u32_push(&h->r_info, (sym << 8) | type);
    u32_push(&h->r_add, addend);
}

/* A pointer to (hunk th, offset t) seen; remember it as a possible entry. */
static void maybe_func(WHunk *w, uint32_t th, uint32_t t)
{
    if (w[th].code)
        u32_push(&w[th].func, t);
}

static int contains(const U32Vec *v, uint32_t x)
{
    size_t lo = 0, hi = v->n;
    while (lo < hi) {
        size_t mid = (lo + hi) / 2;
        if (v->v[mid] < x)
            lo = mid + 1;
        else if (v->v[mid] > x)
            hi = mid;
        else
            return 1;
    }
    return 0;
}

uint8_t *repack_load(const char *path, uint32_t *size)
{
    uint8_t *f;
    uint32_t len, n, i, p, tsize, q, nf = 0, nlone = 0, nguess = 0;
    const uint8_t *tab;
    WHunk *w;
    Buf b = {0}, st = {0}, sh = {0}, sy = {0};
    uint32_t *shname, *secoff, *relsec, nsec, symtab, strtab, shstrtab;
    uint32_t nsym, k;
    char name[32];

    g_path = path;
    f = read_file(path, &len);

    /* ---- hunk file structure ---- */
    if (len < 24 || rd32(f) != HUNK_HEADER)
        notwrapped("no hunk header");
    if (rd32(f + 4) != 0)
        notwrapped("resident library names in the header");
    n = rd32(f + 8);
    if (n < 4 || n > 1000 || rd32(f + 12) != 0 || rd32(f + 16) != n - 1)
        notwrapped("unexpected hunk count");
    p = 20 + 4 * n;
    if (p > len)
        notwrapped("file too short");
    w = xcalloc(n, sizeof(WHunk));
    for (i = 0; i < n; i++) {
        uint32_t hs = rd32(f + 20 + 4 * i), t, l;
        if ((hs & 0xC0000000UL) == 0xC0000000UL)
            notwrapped("extended memory flags in the header");
        if (p + 8 > len)
            notwrapped("file too short");
        t = rd32(f + p) & 0x3FFFFFFFUL;
        l = rd32(f + p + 4);
        p += 8;
        if (l != (hs & 0x3FFFFFFFUL))
            notwrapped("hunk size differs from the header");
        if (t == HUNK_CODE || t == HUNK_DATA) {
            if (l > (len - p) / 4)
                notwrapped("file too short");
            w[i].data = f + p;
            p += 4 * l;
        } else if (t != HUNK_BSS) {
            notwrapped("a hunk is not CODE, DATA or BSS");
        }
        w[i].type = t;
        w[i].size = 4 * l;
        if (p + 4 > len || rd32(f + p) != HUNK_END) {
            sprintf(name, "hunk %lu", (unsigned long)i);
            fatal("%s: not an Elf2Exe2 executable: %s has reloc, symbol or "
                  "debug data (Elf2Exe2 writes none)", path, name);
        }
        p += 4;
    }
    if (p != len)
        notwrapped("data after the last hunk");
    if (w[0].type != HUNK_CODE || w[0].size != STUB_SIZE ||
        memcmp(w[0].data, e2e2_stub, STUB_SIZE) != 0)
        notwrapped("hunk 0 is not the Elf2Exe2 startup code");
    if (w[1].type != HUNK_BSS)
        notwrapped("hunk 1 is not BSS");
    if (w[2].type != HUNK_DATA || w[2].size < 4)
        notwrapped("hunk 2 (the PPC code) is not DATA");
    for (i = 3; i < n - 1; i++)
        if (w[i].type != HUNK_DATA && w[i].type != HUNK_BSS)
            notwrapped("a section hunk is CODE");
    if (w[n - 1].type != HUNK_DATA)
        notwrapped("the last hunk is not a relocation table");
    tab = w[n - 1].data;
    tsize = w[n - 1].size;

    /* ---- relocation table, pass 1: which hunks hold code ---- */
    w[2].code = 1;
    for (q = 0; q < 2; q++) {
        uint32_t o = 0;
#define NEXT(v) do { if (o + 4 > tsize) damaged("ends early", o);                      (v) = rd32(tab + o); o += 4; } while (0)
        for (;;) {
            uint32_t ph, cnt, bh, e, x;
            NEXT(ph);
            if (ph == 0)
                break;
            if (ph < 2 || ph >= n - 1 || w[ph].type != HUNK_DATA)
                damaged("bad hunk to patch", o - 4);
            for (;;) {
                NEXT(cnt);
                if (cnt == 0)
                    break;
                NEXT(bh);
                if (bh < 1 || bh >= n - 1)
                    damaged("bad target hunk", o - 4);
                while (cnt--) {
                    WHunk *h = &w[ph];
                    NEXT(e);
                    if (!(e & 0x80000000UL)) {            /* ADDR32 */
                        if (e > h->size || h->size - e < 4)
                            damaged("ADDR32 outside its hunk", o - 4);
                        if (q) {
                            x = rd32(h->data + e);
                            add_rel(h, e, bh, R_ADDR32, x);
                            u32_push(&h->a32, e);
                            maybe_func(w, bh, x);
                        }
                    } else if (!(e & 0x40000000UL)) {     /* HA/LO pair */
                        uint32_t ha = (e & 0x3FFFFF) * 4;
                        uint32_t lo = ha + ((e >> 22) & 0xFF) * 4;
                        uint32_t i1, i2;
                        if (lo == ha || lo + 4 > h->size)
                            damaged("HA/LO pair outside its hunk", o - 4);
                        i1 = rd32(h->data + ha);
                        i2 = rd32(h->data + lo);
                        if (!is_lis(i1) || !is_lo_op(i2))
                            damaged("HA/LO pair not on lis and a load, store "
                                    "or addi", o - 4);
                        h->code = 1;
                        if (q) {
                            x = (i1 & 0xFFFF) << 16 | (i2 & 0xFFFF);
                            add_rel(h, ha + 2, bh, R_HA, x);
                            add_rel(h, lo + 2, bh, R_LO, x);
                            u32_push(&h->ha_off, ha);
                            u32_push(&h->ha_key, ((i1 >> 21) & 31) << 16 | bh);
                            u32_push(&h->ha_add, x);
                            maybe_func(w, bh, x);
                        }
                    } else if (e & 0x20000000UL) {        /* REL24 */
                        uint32_t s = e & 0x0FFFFFFF;
                        if ((s & 3) || s + 4 > h->size ||
                            (rd32(h->data + s) >> 26) != 18)
                            damaged("REL24 not on a branch", o - 4);
                        h->code = 1;
                        if (q)
                            add_rel(h, s, bh, R_REL24,
                                    rd32(h->data + s) & 0x03FFFFFC);
                    } else {                              /* LO16 or HA16 */
                        uint32_t s = e & 0x0FFFFFFF, insn;
                        int islo = (e & 0x10000000UL) != 0;
                        if ((s & 3) != 2 || s + 2 > h->size)
                            damaged("LO16/HA16 not on an instruction", o - 4);
                        insn = rd32(h->data + s - 2);
                        if (islo ? !is_lo_op(insn) : !is_lis(insn))
                            damaged(islo ? "LO16 not on a load, store or addi"
                                         : "HA16 not on lis", o - 4);
                        h->code = 1;
                        if (!islo)
                            NEXT(x);
                        if (q && islo) {
                            u32_push(&h->lo_off, s);
                            u32_push(&h->lo_hunk, bh);
                            nlone++;
                        } else if (q) {
                            add_rel(h, s, bh, R_HA, x);
                            u32_push(&h->ha_off, s - 2);
                            u32_push(&h->ha_key, ((insn >> 21) & 31) << 16 | bh);
                            u32_push(&h->ha_add, x);
                            maybe_func(w, bh, x);
                        }
                    }
                }
            }
        }
        for (; o < tsize; o += 4)
            if (rd32(tab + o) != 0)
                damaged("data after the end marker", o);
#undef NEXT
    }

    /* ---- lone LO16: take the high half from the lis that loads its base
     * register (searching back up to 64 KB). The low 16 bits written are
     * right either way; the high half only decides the hook redirect. ---- */
    for (i = 2; i < n - 1; i++) {
        WHunk *h = &w[i];
        size_t j;
        if (!h->lo_off.n)
            continue;
        /* ha_* are in table order; index them by offset */
        {
            size_t m = h->ha_off.n, a;
            uint32_t *ord = xmalloc((m ? m : 1) * sizeof(uint32_t));
            U32Vec key = {0};
            for (a = 0; a < m; a++)
                u32_push(&key, h->ha_off.v[a]);
            /* sort indexes by offset (insertion into a sorted copy) */
            u32_sort(&key);
            for (a = 0; a < m; a++)
                ord[a] = 0xFFFFFFFFUL;
            for (a = 0; a < m; a++) {
                size_t lo = 0, hi = m;
                while (lo < hi) {
                    size_t mid = (lo + hi) / 2;
                    if (key.v[mid] < h->ha_off.v[a])
                        lo = mid + 1;
                    else
                        hi = mid;
                }
                while (ord[lo] != 0xFFFFFFFFUL)
                    lo++;
                ord[lo] = (uint32_t)a;
            }
            for (j = 0; j < h->lo_off.n; j++) {
                uint32_t s = h->lo_off.v[j], bh = h->lo_hunk.v[j];
                uint32_t insn = rd32(h->data + s - 2);
                uint32_t want = ((insn >> 16) & 31) << 16 | bh;
                uint32_t lo16 = rd32(h->data + s - 2) & 0xFFFF, a32 = lo16;
                size_t lo = 0, hi = m;
                while (lo < hi) {
                    size_t mid = (lo + hi) / 2;
                    if (key.v[mid] < s - 2)
                        lo = mid + 1;
                    else
                        hi = mid;
                }
                while (lo > 0 && s - 2 - key.v[lo - 1] <= 0x10000) {
                    uint32_t a = ord[--lo];
                    if (h->ha_key.v[a] == want) {
                        uint32_t page = (h->ha_add.v[a] + 0x8000) >> 16;
                        a32 = (page << 16) + (uint32_t)(int32_t)(int16_t)lo16;
                        nguess++;
                        maybe_func(w, bh, a32);
                        break;
                    }
                }
                add_rel(h, s, bh, R_LO, a32);
            }
            free(ord);
            u32_free(&key);
        }
    }

    /* ---- guessed function entries ---- */
    for (i = 2; i < n - 1; i++) {
        WHunk *h = &w[i];
        size_t r, wpos = 0;
        if (!h->code)
            continue;
        u32_sort(&h->func);
        u32_sort(&h->a32);
        for (r = 0; r < h->func.n; r++) {
            uint32_t t = h->func.v[r];
            if (wpos && h->func.v[wpos - 1] == t)
                continue;
            if ((t & 3) || t + 8 > h->size ||
                looks_like_data(rd32(h->data + t)) || contains(&h->a32, t))
                continue;
            h->func.v[wpos++] = t;
        }
        h->func.n = wpos;
        nf += (uint32_t)wpos;
    }
    verbose("Repack: %lu hunks, %lu lone LO16 (%lu matched to their lis), "
            "%lu guessed function entries\n", (unsigned long)n,
            (unsigned long)nlone, (unsigned long)nguess, (unsigned long)nf);

    /* ---- the ELF image ----
     * sections 1..n-2 = hunks 1..n-2, then one .rela per patched hunk,
     * .symtab, .strtab, .shstrtab. Symbols: null, one section symbol per
     * hunk (index = hunk number), then the guessed functions (local). */
    nsec = n - 1;
    relsec = xcalloc(n, sizeof(uint32_t));
    for (i = 2; i < n - 1; i++)
        if (w[i].r_off.n)
            relsec[i] = nsec++;
    symtab = nsec++;
    strtab = nsec++;
    shstrtab = nsec++;
    shname = xcalloc(nsec, sizeof(uint32_t));
    secoff = xcalloc(nsec, sizeof(uint32_t));

    put(&sh, NULL, 1);
    put(&st, NULL, 1);
    for (i = 1; i < nsec; i++) {
        if (i == 1)
            strcpy(name, ".bss.common");
        else if (i < n - 1)
            sprintf(name, i == 2 ? ".text" : w[i].code ? ".text.%lu" :
                    w[i].type == HUNK_BSS ? ".bss.%lu" : ".data.%lu",
                    (unsigned long)i);
        else if (i == symtab)
            strcpy(name, ".symtab");
        else if (i == strtab)
            strcpy(name, ".strtab");
        else if (i == shstrtab)
            strcpy(name, ".shstrtab");
        else
            name[0] = 0;   /* .rela, named below */
        if (!name[0]) {
            for (k = 2; k < n - 1; k++)
                if (relsec[k] == i)
                    break;
            shname[i] = sh.n;
            put(&sh, ".rela", 5);
            {
                char sub[32];
                sprintf(sub, k == 2 ? ".text" : w[k].code ? ".text.%lu" :
                        ".data.%lu", (unsigned long)k);
                put(&sh, sub, (uint32_t)strlen(sub) + 1);
            }
            continue;
        }
        shname[i] = sh.n;
        put(&sh, name, (uint32_t)strlen(name) + 1);
    }

    /* symbols */
    put(&sy, NULL, 16);
    for (i = 1; i < n - 1; i++) {
        put32(&sy, 0);
        put32(&sy, 0);
        put32(&sy, 0);
        put(&sy, "\003", 1);        /* STB_LOCAL, STT_SECTION */
        put(&sy, NULL, 1);
        put16(&sy, (uint16_t)i);
    }
    for (i = 2; i < n - 1; i++) {
        size_t r;
        for (r = 0; r < w[i].func.n; r++) {
            sprintf(name, "fn_%lu_%lx", (unsigned long)i,
                    (unsigned long)w[i].func.v[r]);
            put32(&sy, st.n);
            put(&st, name, (uint32_t)strlen(name) + 1);
            put32(&sy, w[i].func.v[r]);
            put32(&sy, 0);
            put(&sy, "\002", 1);    /* STB_LOCAL, STT_FUNC */
            put(&sy, NULL, 1);
            put16(&sy, (uint16_t)i);
        }
    }
    nsym = sy.n / 16;

    /* file: header, section contents, section headers */
    put(&b, NULL, 52);
    for (i = 1; i < n - 1; i++) {
        align4(&b);
        secoff[i] = b.n;
        if (w[i].type != HUNK_BSS)
            put(&b, w[i].data, w[i].size);
    }
    for (i = 2; i < n - 1; i++) {
        size_t r;
        if (!relsec[i])
            continue;
        align4(&b);
        secoff[relsec[i]] = b.n;
        for (r = 0; r < w[i].r_off.n; r++) {
            put32(&b, w[i].r_off.v[r]);
            put32(&b, w[i].r_info.v[r]);
            put32(&b, w[i].r_add.v[r]);
        }
    }
    align4(&b);
    secoff[symtab] = b.n;
    put(&b, sy.d, sy.n);
    secoff[strtab] = b.n;
    put(&b, st.d, st.n);
    secoff[shstrtab] = b.n;
    put(&b, sh.d, sh.n);
    align4(&b);
    {
        uint32_t shoff = b.n;
        put(&b, NULL, 40);
        for (i = 1; i < nsec; i++) {
            uint32_t type, flags = 0, sz, link = 0, info = 0, al = 4, es = 0;
            if (i < n - 1) {
                type = w[i].type == HUNK_BSS ? SHT_NOBITS : SHT_PROGBITS;
                flags = SHF_ALLOC | (w[i].code ? SHF_EXECINSTR : SHF_WRITE);
                sz = w[i].size;
                al = 8;
            } else if (i == symtab) {
                type = SHT_SYMTAB;
                sz = sy.n;
                link = strtab;
                info = nsym;    /* all symbols are local */
                es = 16;
            } else if (i == strtab || i == shstrtab) {
                type = SHT_STRTAB;
                sz = i == strtab ? st.n : sh.n;
                al = 1;
            } else {
                for (k = 2; k < n - 1; k++)
                    if (relsec[k] == i)
                        break;
                type = SHT_RELA;
                sz = (uint32_t)w[k].r_off.n * 12;
                link = symtab;
                info = k;
                es = 12;
            }
            put32(&b, shname[i]);
            put32(&b, type);
            put32(&b, flags);
            put32(&b, 0);
            put32(&b, secoff[i]);
            put32(&b, sz);
            put32(&b, link);
            put32(&b, info);
            put32(&b, al);
            put32(&b, es);
        }
        /* ELF header */
        memcpy(b.d, "\177ELF\001\002\001", 7);
        wr16(b.d + 16, ET_REL);
        wr16(b.d + 18, EM_PPC);
        wr32(b.d + 20, 1);
        wr32(b.d + 32, shoff);
        wr16(b.d + 40, 52);
        wr16(b.d + 46, 40);
        wr16(b.d + 48, (uint16_t)nsec);
        wr16(b.d + 50, (uint16_t)shstrtab);
    }

    for (i = 0; i < n; i++) {
        u32_free(&w[i].r_off);
        u32_free(&w[i].r_info);
        u32_free(&w[i].r_add);
        u32_free(&w[i].a32);
        u32_free(&w[i].ha_off);
        u32_free(&w[i].ha_key);
        u32_free(&w[i].ha_add);
        u32_free(&w[i].lo_off);
        u32_free(&w[i].lo_hunk);
        u32_free(&w[i].func);
    }
    free(w);
    free(relsec);
    free(shname);
    free(secoff);
    free(sy.d);
    free(st.d);
    free(sh.d);
    free(f);
    *size = b.n;
    return b.d;
}

void repack_dump(const char *path, const uint8_t *image, uint32_t size)
{
    FILE *f = fopen(path, "wb");
    if (!f || fwrite(image, 1, size, f) != size || fclose(f) != 0)
        fatal("cannot write %s", path);
}
