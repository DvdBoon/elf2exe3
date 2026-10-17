/* elf2exe3 - reading Amiga hunk object files (the 68k startup, spec 8.1) */
#include <stdlib.h>
#include <string.h>

#include "hobj.h"
#include "hunk.h"

typedef struct {
    const uint8_t *buf;
    size_t len, pos;
    const char *name;
} Rd;

static uint32_t get(Rd *r)
{
    uint32_t v;
    if (r->pos + 4 > r->len)
        fatal("%s: unexpected end of object file", r->name);
    v = rd32(r->buf + r->pos);
    r->pos += 4;
    return v;
}

static char *get_name(Rd *r, uint32_t longs)
{
    size_t n = (size_t)longs * 4, k;
    char *s;
    if (r->pos + n > r->len)
        fatal("%s: unexpected end of object file", r->name);
    s = xmalloc(n + 1);
    memcpy(s, r->buf + r->pos, n);
    s[n] = 0;
    for (k = 0; k < n && s[k]; k++)
        ;
    s[k] = 0;
    r->pos += n;
    return s;
}

static void skip(Rd *r, size_t n)
{
    if (r->pos + n > r->len)
        fatal("%s: unexpected end of object file", r->name);
    r->pos += n;
}

static HSec *new_sec(HObj *o)
{
    HSec *s;
    o->sec = xrealloc(o->sec, (o->nsec + 1) * sizeof(HSec));
    s = &o->sec[o->nsec++];
    memset(s, 0, sizeof(*s));
    s->hunk = -1;
    return s;
}

static void read_relocs(Rd *r, U32Vec *sec, U32Vec *off, int shortform)
{
    for (;;) {
        uint32_t n, t, k;
        if (shortform) {
            if (r->pos + 2 > r->len)
                fatal("%s: unexpected end of object file", r->name);
            n = rd16(r->buf + r->pos);
            r->pos += 2;
        } else
            n = get(r);
        if (n == 0)
            break;
        if (shortform) {
            t = rd16(r->buf + r->pos);
            r->pos += 2;
        } else
            t = get(r);
        for (k = 0; k < n; k++) {
            uint32_t v;
            if (shortform) {
                if (r->pos + 2 > r->len)
                    fatal("%s: unexpected end of object file", r->name);
                v = rd16(r->buf + r->pos);
                r->pos += 2;
            } else
                v = get(r);
            u32_push(sec, t);
            u32_push(off, v);
        }
    }
    if (shortform && (r->pos & 2))
        r->pos += 2;
}

void hobj_parse(HObj *o, const uint8_t *buf, size_t len, const char *name)
{
    Rd r;
    HSec *cur = NULL;
    char *pending = NULL;
    size_t k;

    memset(o, 0, sizeof(*o));
    r.buf = buf;
    r.len = len;
    r.pos = 0;
    r.name = name;
    if (len < 4 || rd32(buf) != HUNK_UNIT)
        fatal("%s: not a hunk object file", name);

    while (r.pos < r.len) {
        uint32_t t = get(&r) & 0x3FFFFFFF, n;
        switch (t) {
        case HUNK_UNIT:
            free(get_name(&r, get(&r)));
            break;
        case HUNK_NAME:
            free(pending);
            pending = get_name(&r, get(&r));
            break;
        case HUNK_CODE:
        case HUNK_PPC_CODE:
        case HUNK_DATA:
        case HUNK_BSS:
            cur = new_sec(o);
            cur->name = pending ? pending : get_name(&r, 0);
            pending = NULL;
            cur->type = t == HUNK_PPC_CODE ? HUNK_CODE : t;
            n = get(&r) & 0x3FFFFFFF;
            cur->size = n * 4;
            if (t != HUNK_BSS) {
                skip(&r, cur->size);
                cur->data = xmalloc(cur->size);
                memcpy(cur->data, buf + r.pos - cur->size, cur->size);
            }
            break;
        case HUNK_RELOC32:
        case HUNK_RELOC32SHORT:
        case HUNK_DREL16:
            if (!cur)
                fatal("%s: relocations before any section", name);
            if (t == HUNK_DREL16)
                read_relocs(&r, &cur->drel_sec, &cur->drel_off, 0);
            else
                read_relocs(&r, &cur->rel_sec, &cur->rel_off,
                            t == HUNK_RELOC32SHORT);
            break;
        case HUNK_EXT:
            if (!cur)
                fatal("%s: HUNK_EXT before any section", name);
            for (;;) {
                uint32_t w = get(&r), type = w >> 24;
                char *nm;
                if (w == 0)
                    break;
                nm = get_name(&r, w & 0xFFFFFF);
                if (type == EXT_DEF || type == EXT_ABS) {
                    HDef *d;
                    o->defs = xrealloc(o->defs, (o->ndefs + 1) * sizeof(HDef));
                    d = &o->defs[o->ndefs++];
                    d->name = nm;
                    d->type = (uint8_t)type;
                    d->value = get(&r);
                    d->sec = (int)(o->nsec - 1);
                } else if (type >= 128 && type != 130 && type != 137) {
                    HRef *h;
                    uint32_t c = get(&r), i;
                    cur->refs = xrealloc(cur->refs,
                                         (cur->nrefs + 1) * sizeof(HRef));
                    h = &cur->refs[cur->nrefs++];
                    memset(h, 0, sizeof(*h));
                    h->name = nm;
                    h->type = (uint8_t)type;
                    for (i = 0; i < c; i++)
                        u32_push(&h->offs, get(&r));
                } else
                    fatal("%s: unsupported HUNK_EXT entry type %lu (%s)", name,
                          (unsigned long)type, nm);
            }
            break;
        case HUNK_SYMBOL:
            for (;;) {
                uint32_t w = get(&r);
                if (w == 0)
                    break;
                skip(&r, (size_t)(w & 0xFFFFFF) * 4 + 4);
            }
            break;
        case HUNK_DEBUG:
            n = get(&r);
            skip(&r, (size_t)n * 4);
            break;
        case HUNK_END:
            cur = NULL;
            break;
        default:
            fatal("%s: unsupported hunk type 0x%lx", name, (unsigned long)t);
        }
    }
    free(pending);
    for (k = 0; k < o->nsec; k++) {
        size_t i;
        for (i = 0; i < o->sec[k].rel_sec.n; i++)
            if (o->sec[k].rel_sec.v[i] >= o->nsec)
                fatal("%s: relocation to section %lu out of range", name,
                      (unsigned long)o->sec[k].rel_sec.v[i]);
        for (i = 0; i < o->sec[k].drel_sec.n; i++)
            if (o->sec[k].drel_sec.v[i] >= o->nsec)
                fatal("%s: relocation to section %lu out of range", name,
                      (unsigned long)o->sec[k].drel_sec.v[i]);
    }
    if (!o->nsec || o->sec[0].type != HUNK_CODE)
        fatal("%s: the first section must be 68k code", name);
}

void hobj_load(HObj *o, const char *path)
{
    FILE *f = fopen(path, "rb");
    uint8_t *buf;
    long len = 0;
    if (!f)
        fatal("cannot open %s", path);
    if (fseek(f, 0, SEEK_END) != 0 || (len = ftell(f)) < 0 ||
        fseek(f, 0, SEEK_SET) != 0)
        fatal("cannot read %s", path);
    buf = xmalloc((size_t)len);
    if (fread(buf, 1, (size_t)len, f) != (size_t)len)
        fatal("cannot read %s", path);
    fclose(f);
    hobj_parse(o, buf, (size_t)len, path);
    free(buf);
}
