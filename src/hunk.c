/* elf2exe3 - Amiga hunk output */
#include <stdlib.h>
#include <string.h>

#include "hunk.h"

void hunk_add_sym(Hunk *h, const char *name, uint32_t off)
{
    size_t len = strlen(name);
    if (h->nsyms == h->capsyms) {
        h->capsyms = h->capsyms ? h->capsyms * 2 : 256;
        h->syms = xrealloc(h->syms, h->capsyms * sizeof(HunkSym));
    }
    h->syms[h->nsyms].name = xmalloc(len + 1);
    memcpy(h->syms[h->nsyms].name, name, len + 1);
    h->syms[h->nsyms].off = off;
    h->nsyms++;
}

#define RELOC_GROUP 65535

static int put32(FILE *f, uint32_t v)
{
    uint8_t b[4];
    wr32(b, v);
    return fwrite(b, 1, 4, f) == 4;
}

static int put_name(FILE *f, const char *name, uint32_t type)
{
    size_t len = strlen(name);
    uint32_t longs = (uint32_t)((len + 3) / 4);
    static const uint8_t zero[4] = {0, 0, 0, 0};
    if (longs > 0xFFFFFF)
        longs = 0xFFFFFF;
    if (!put32(f, (type << 24) | longs))
        return 0;
    if (fwrite(name, 1, len, f) != len)
        return 0;
    return fwrite(zero, 1, longs * 4 - len, f) == longs * 4 - len;
}

int hunk_write(const char *path, Hunk *h, int nhunks)
{
    FILE *f = fopen(path, "wb");
    int i, t, ok = 1;
    if (!f) {
        error("cannot create %s", path);
        return -1;
    }
    ok &= put32(f, HUNK_HEADER);
    ok &= put32(f, 0);                    /* no resident library names */
    ok &= put32(f, (uint32_t)nhunks);
    ok &= put32(f, 0);
    ok &= put32(f, (uint32_t)nhunks - 1);
    for (i = 0; i < nhunks; i++)
        ok &= put32(f, ((h[i].size + 3) / 4) | h[i].memflags);

    for (i = 0; i < nhunks && ok; i++) {
        uint32_t longs = (h[i].size + 3) / 4;
        int any = 0;
        ok &= put32(f, h[i].type);
        ok &= put32(f, longs);
        if (h[i].type != HUNK_BSS) {
            static const uint8_t zero[4] = {0, 0, 0, 0};
            ok &= fwrite(h[i].data, 1, h[i].size, f) == h[i].size;
            ok &= fwrite(zero, 1, longs * 4 - h[i].size, f) ==
                  longs * 4 - h[i].size;
        }
        for (t = 0; t < nhunks; t++)
            if (h[i].reloc[t].n)
                any = 1;
        if (any) {
            ok &= put32(f, HUNK_RELOC32);
            for (t = 0; t < nhunks; t++) {
                U32Vec *r = &h[i].reloc[t];
                size_t k;
                if (!r->n)
                    continue;
                u32_sort(r);
                /* LoadSeg only uses the low 16 bits of the count, so
                 * longer lists are split into groups of at most 65535. */
                for (k = 0; k < r->n; k += RELOC_GROUP) {
                    size_t n = r->n - k, m;
                    if (n > RELOC_GROUP)
                        n = RELOC_GROUP;
                    ok &= put32(f, (uint32_t)n);
                    ok &= put32(f, (uint32_t)t);
                    for (m = 0; m < n; m++)
                        ok &= put32(f, r->v[k + m]);
                }
            }
            ok &= put32(f, 0);
        }
        if (h[i].nsyms) {
            size_t k;
            ok &= put32(f, HUNK_SYMBOL);
            for (k = 0; k < h[i].nsyms; k++) {
                ok &= put_name(f, h[i].syms[k].name, 0);
                ok &= put32(f, h[i].syms[k].off);
            }
            ok &= put32(f, 0);
        }
        ok &= put32(f, HUNK_END);
    }
    if (fclose(f) != 0)
        ok = 0;
    if (!ok) {
        error("write error on %s", path);
        remove(path);
        return -1;
    }
    return 0;
}
