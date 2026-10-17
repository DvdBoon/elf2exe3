/* elf2exe3 - ELF to hunk conversion
 *
 * Section numbers in comments refer to docs/spec.md.
 *
 * Steps:
 *   1. layout: place every loaded section in one of four hunks (4)
 *   2. find address-taken functions that need an r2 entry hook (6.2)
 *   3. copy section data and apply every relocation (5, 6.1, 6.2)
 *   4. build the page table and the hooks, add symbols (9), write (10)
 */
#include <stdlib.h>
#include <string.h>

#include "convert.h"
#include "elf.h"
#include "hobj.h"
#include "hunk.h"
#include "util.h"

#define R_PPC_NONE          0
#define R_PPC_ADDR32        1
#define R_PPC_ADDR16        3
#define R_PPC_ADDR16_LO     4
#define R_PPC_ADDR16_HI     5
#define R_PPC_ADDR16_HA     6
#define R_PPC_REL24         10
#define R_PPC_REL14         11
#define R_PPC_REL14_BRTAKEN 12
#define R_PPC_REL14_BRNTAKEN 13
#define R_PPC_PLTREL24      18
#define R_PPC_LOCAL24PC     23
#define R_PPC_UADDR32       24
#define R_PPC_REL32         26

#define HOOK_SIZE 32

/* built-in startup object, src/wosstart.c (from startup/wosstart.s) */
extern const unsigned char wosstart_o[];
extern const size_t wosstart_o_len;

typedef struct {
    int abs;               /* 1 = absolute value, no hunk */
    int hunk;
    uint32_t off;          /* hunk offset, or the value if abs */
} Target;

typedef struct {
    ElfFile e;
    const Options *opt;
    Hunk h[NHUNKS];
    uint32_t code_end;     /* end of the ELF code in hunk 1 */
    uint32_t data_end;     /* end of the ELF data in hunk 2 */
    uint32_t table_off;    /* page table offset in hunk 2 */
    uint32_t ldb;          /* _LinkerDB = r2 value, offset in hunk 2 */
    uint32_t entry;        /* entry offset in hunk 1 */
    int m68k_sec;          /* ELF section used as hunk 0, or -1 */
    HObj obj;              /* startup object (if m68k_sec < 0) */
    struct { const char *name; uint32_t hunk, off; } *oref; /* for the map */
    size_t noref;

    /* functions in hunk 1 (sorted, unique) and which get a hook */
    U32Vec func;
    uint8_t *hooked;
    uint32_t *hook_off;
    uint32_t nhooks;

    /* page table: slot per (hunk, page) */
    int32_t *slot_of[NHUNKS];
    uint32_t npages[NHUNKS];
    U32Vec slot_hunk, slot_page;

    /* LO relocs to check against the table after all HA are known */
    U32Vec lo_key, lo_poff;

    unsigned long count[32];
    unsigned long redirected;
    unsigned long odd;     /* RELOC32 entries at odd offsets */
} Conv;

static uint32_t align_up(uint32_t v, uint32_t a)
{
    if (a < 2)
        return v;
    return (v + a - 1) / a * a;
}

static int is_code(const ElfSection *s)
{
    return (s->flags & SHF_ALLOC) && (s->flags & SHF_EXECINSTR) &&
           s->type != SHT_NOBITS;
}

static int is_data(const ElfSection *s)
{
    return (s->flags & SHF_ALLOC) && !(s->flags & SHF_EXECINSTR) &&
           s->type != SHT_NOBITS;
}

static int is_bss(const ElfSection *s)
{
    return (s->flags & SHF_ALLOC) && s->type == SHT_NOBITS;
}

static int prefix(const char *s, const char *p)
{
    return strncmp(s, p, strlen(p)) == 0;
}

/* Relocations from these sections keep pointing at the function itself:
 * they are exception and debug tables, not calls through a pointer. */
static int no_redirect(const char *name)
{
    return strcmp(name, ".gcc_except_table") == 0 ||
           prefix(name, ".eh_frame") || prefix(name, ".stab") ||
           prefix(name, ".debug");
}

static long find_u32(const U32Vec *v, uint32_t x)
{
    size_t lo = 0, hi = v->n;
    while (lo < hi) {
        size_t mid = (lo + hi) / 2;
        if (v->v[mid] < x)
            lo = mid + 1;
        else if (v->v[mid] > x)
            hi = mid;
        else
            return (long)mid;
    }
    return -1;
}

/* ---- 1. layout ---------------------------------------------------- */

static void place(Conv *c, ElfSection *s, int hunk, uint32_t *end,
                  int *warned)
{
    uint32_t a = s->align ? s->align : 1;
    if (a > 8 && !*warned) {
        warning("section %s wants %lu byte alignment; hunks are only "
                "guaranteed 8", s->name, (unsigned long)a);
        *warned = 1;
    }
    s->hunk = hunk;
    s->base = align_up(*end, a);
    *end = s->base + s->size;
    verbose("  %-20s hunk %d  offset 0x%08lx  size 0x%08lx\n", s->name, hunk,
            (unsigned long)s->base, (unsigned long)s->size);
    (void)c;
}

static int entry_section(Conv *c, uint32_t *value)
{
    ElfFile *e = &c->e;
    uint32_t i;
    if (c->opt->entry) {
        for (i = 0; i < e->nsym; i++) {
            ElfSymbol *y = &e->sym[i];
            if (strcmp(y->name, c->opt->entry) == 0 && y->shndx != SHN_UNDEF &&
                y->shndx < e->nsec) {
                if (!is_code(&e->sec[y->shndx]))
                    fatal("entry symbol %s is not in a code section",
                          c->opt->entry);
                *value = y->value - e->sec[y->shndx].addr;
                return y->shndx;
            }
        }
        fatal("entry symbol %s not found", c->opt->entry);
    }
    if (e->type == ET_EXEC) {
        for (i = 1; i < e->nsec; i++) {
            ElfSection *s = &e->sec[i];
            if (is_code(s) && e->entry >= s->addr &&
                e->entry < s->addr + s->size) {
                *value = e->entry - s->addr;
                return (int)i;
            }
        }
        fatal("entry address 0x%08lx is not in a code section",
              (unsigned long)e->entry);
    }
    for (i = 1; i < e->nsec; i++)
        if (strcmp(e->sec[i].name, ".text") == 0 && is_code(&e->sec[i])) {
            *value = 0;
            return (int)i;
        }
    fatal("no .text section; use --entry");
    return -1;
}

static void layout(Conv *c)
{
    ElfFile *e = &c->e;
    uint32_t i, end, ev = 0;
    int es = entry_section(c, &ev), warned = 0;

    size_t k;
    HObj *o = &c->obj;

    verbose("Layout:\n");
    /* hunk 0: the 68k startup */
    c->m68k_sec = -1;
    if (c->opt->m68k_sect) {
        for (i = 1; i < e->nsec; i++)
            if (strcmp(e->sec[i].name, c->opt->m68k_sect) == 0 &&
                is_code(&e->sec[i]))
                c->m68k_sec = (int)i;
        if (c->m68k_sec < 0)
            fatal("no code section %s for --m68k-startup", c->opt->m68k_sect);
        if (c->m68k_sec == es)
            fatal("--m68k-startup section %s holds the PPC entry point",
                  c->opt->m68k_sect);
        end = 0;
        place(c, &e->sec[c->m68k_sec], H_START, &end, &warned);
        c->h[H_START].size = end;
    } else {
        if (c->opt->startup)
            hobj_load(o, c->opt->startup);
        else
            hobj_parse(o, wosstart_o, wosstart_o_len, "wosstart.o");
        o->sec[0].hunk = H_START;
        o->sec[0].base = 0;
        c->h[H_START].size = o->sec[0].size;
        verbose("  %-20s hunk 0  offset 0x00000000  size 0x%08lx  (startup)\n",
                o->sec[0].name, (unsigned long)o->sec[0].size);
    }

    /* hunk 1: code, entry section first, then startup object code */
    end = 0;
    place(c, &e->sec[es], H_CODE, &end, &warned);
    for (i = 1; i < e->nsec; i++)
        if ((int)i != es && (int)i != c->m68k_sec && is_code(&e->sec[i]))
            place(c, &e->sec[i], H_CODE, &end, &warned);
    for (k = 1; k < o->nsec; k++)
        if (o->sec[k].type == HUNK_CODE) {
            o->sec[k].hunk = H_CODE;
            o->sec[k].base = align_up(end, 4);
            end = o->sec[k].base + o->sec[k].size;
        }
    c->code_end = align_up(end, 4);
    c->entry = e->sec[es].base + ev;

    /* hunk 2: ELF data, then the r2 block: startup object data followed
     * by the page table, with _LinkerDB = block start + 0x8000 */
    end = 0;
    for (i = 1; i < e->nsec; i++)
        if (is_data(&e->sec[i]))
            place(c, &e->sec[i], H_DATA, &end, &warned);
    c->data_end = align_up(end, 4);
    c->ldb = c->data_end + 0x8000;
    end = c->data_end;
    for (k = 1; k < o->nsec; k++)
        if (o->sec[k].type == HUNK_DATA) {
            o->sec[k].hunk = H_DATA;
            o->sec[k].base = align_up(end, 4);
            end = o->sec[k].base + o->sec[k].size;
        }
    c->table_off = align_up(end, 4);
    if (c->table_off - c->data_end > 0x8000)
        fatal("startup object data is larger than 32 KB");

    /* hunk 3: bss, then COMMON symbols */
    end = 0;
    for (i = 1; i < e->nsec; i++)
        if (is_bss(&e->sec[i]))
            place(c, &e->sec[i], H_BSS, &end, &warned);
    for (i = 0; i < e->nsym; i++) {
        ElfSymbol *y = &e->sym[i];
        if (y->shndx == SHN_COMMON) {
            uint32_t a = y->value ? y->value : 4;
            y->common_hunk = H_BSS;
            y->common_off = align_up(end, a);
            end = y->common_off + y->size;
        }
    }
    for (k = 1; k < o->nsec; k++)
        if (o->sec[k].type == HUNK_BSS) {
            o->sec[k].hunk = H_BSS;
            o->sec[k].base = align_up(end, 4);
            end = o->sec[k].base + o->sec[k].size;
        }
    c->h[H_BSS].size = end;
}

/* ---- relocation targets ------------------------------------------- */

/* A definition in the startup object (vbcc's warpup.o defines _SysBase,
 * _PowerPCBase, ... in its .tocd). */
static int lookup_obj(Conv *c, const char *name, Target *t)
{
    size_t k;
    for (k = 0; k < c->obj.ndefs; k++) {
        HDef *d = &c->obj.defs[k];
        if (strcmp(d->name, name) != 0)
            continue;
        if (d->type == EXT_ABS) {
            t->abs = 1;
            t->off = d->value;
        } else {
            t->abs = 0;
            t->hunk = c->obj.sec[d->sec].hunk;
            t->off = c->obj.sec[d->sec].base + d->value;
        }
        return 1;
    }
    return 0;
}

/* where == NULL: no error messages (used by the hook scan) */
static int target_of(Conv *c, const ElfRela *r, Target *t, const char *where)
{
    ElfFile *e = &c->e;
    ElfSymbol *y;
    if (r->sym >= e->nsym) {
        if (where)
            error("%s: symbol index %lu out of range", where,
                  (unsigned long)r->sym);
        return 0;
    }
    y = &e->sym[r->sym];
    if (y->shndx == SHN_UNDEF) {
        if (r->sym == 0) {
            t->abs = 1;
            t->off = (uint32_t)r->addend;
            return 1;
        }
        if (lookup_obj(c, y->name, t))
            return 1;
        if (y->bind == STB_WEAK) {
            if (where)
                warning("%s: weak symbol %s is undefined, using 0", where,
                        y->name);
            t->abs = 1;
            t->off = (uint32_t)r->addend;
            return 1;
        }
        if (where)
            error("%s: undefined symbol %s", where, y->name);
        return 0;
    }
    if (y->shndx == SHN_ABS) {
        t->abs = 1;
        t->off = y->value + (uint32_t)r->addend;
        return 1;
    }
    if (y->shndx == SHN_COMMON) {
        t->abs = 0;
        t->hunk = y->common_hunk;
        t->off = y->common_off + (uint32_t)r->addend;
        return 1;
    }
    if (y->shndx >= e->nsec || e->sec[y->shndx].hunk < 0) {
        if (where)
            error("%s: symbol %s is in a section that is not loaded", where,
                  y->name);
        return 0;
    }
    t->abs = 0;
    t->hunk = e->sec[y->shndx].hunk;
    t->off = e->sec[y->shndx].base + (y->value - e->sec[y->shndx].addr) +
             (uint32_t)r->addend;
    return 1;
}

static int is_pointer_type(uint32_t type)
{
    return type == R_PPC_ADDR32 || type == R_PPC_UADDR32 ||
           type == R_PPC_ADDR16 || type == R_PPC_ADDR16_LO ||
           type == R_PPC_ADDR16_HI || type == R_PPC_ADDR16_HA;
}

/* Hunk 1 offset of the hook for a function start, or the offset itself. */
static uint32_t redirect(Conv *c, uint32_t off)
{
    long k;
    if (!c->nhooks)
        return off;
    k = find_u32(&c->func, off);
    if (k >= 0 && c->hooked[k]) {
        c->redirected++;
        return c->hook_off[k];
    }
    return off;
}

/* ---- 2. entry hooks ------------------------------------------------ */

static void collect_functions(Conv *c)
{
    ElfFile *e = &c->e;
    uint32_t i;
    for (i = 0; i < e->nsym; i++) {
        ElfSymbol *y = &e->sym[i];
        if (y->type == STT_FUNC && y->shndx != SHN_UNDEF &&
            y->shndx < e->nsec && e->sec[y->shndx].hunk == H_CODE)
            u32_push(&c->func, e->sec[y->shndx].base +
                                   (y->value - e->sec[y->shndx].addr));
    }
    u32_sort(&c->func);
    if (c->func.n) {   /* remove duplicates (aliases) */
        size_t r, w = 1;
        for (r = 1; r < c->func.n; r++)
            if (c->func.v[r] != c->func.v[w - 1])
                c->func.v[w++] = c->func.v[r];
        c->func.n = w;
    }
    c->hooked = xcalloc(c->func.n, 1);
    c->hook_off = xcalloc(c->func.n, sizeof(uint32_t));
}

static void find_hooks(Conv *c)
{
    ElfFile *e = &c->e;
    uint32_t i, j, n, k;
    for (i = 1; i < e->nsec; i++) {
        ElfSection *rs = &e->sec[i], *ts;
        ElfRela *r;
        if (rs->type != SHT_RELA || rs->info >= e->nsec)
            continue;
        ts = &e->sec[rs->info];
        if (ts->hunk < 0 || no_redirect(ts->name))
            continue;
        r = elf_read_rela(e, i, &n);
        for (j = 0; j < n; j++) {
            Target t;
            long f;
            if (!is_pointer_type(r[j].type))
                continue;
            if (!target_of(c, &r[j], &t, NULL) || t.abs ||
                t.hunk != H_CODE)
                continue;
            f = find_u32(&c->func, t.off);
            if (f >= 0 && !c->hooked[f])
                c->hooked[f] = 1;
        }
        free(r);
    }
    /* A "function" whose first word holds an address is a table typed as
     * STT_FUNC (.init/.fini __initlist in the sample), not code. */
    for (i = 1; i < e->nsec; i++) {
        ElfSection *rs = &e->sec[i], *ts;
        ElfRela *r;
        if (rs->type != SHT_RELA || rs->info >= e->nsec)
            continue;
        ts = &e->sec[rs->info];
        if (ts->hunk != H_CODE)
            continue;
        r = elf_read_rela(e, i, &n);
        for (j = 0; j < n; j++) {
            long f;
            if (r[j].type != R_PPC_ADDR32 && r[j].type != R_PPC_UADDR32)
                continue;
            f = find_u32(&c->func, ts->base + (r[j].offset - ts->addr));
            if (f >= 0 && c->hooked[f]) {
                c->hooked[f] = 0;
                verbose("  no hook for data at hunk 1 offset 0x%08lx\n",
                        (unsigned long)c->func.v[f]);
            }
        }
        free(r);
    }
    for (k = 0; k < c->func.n; k++)
        if (c->hooked[k]) {
            if (c->func.v[k] + 4 >= c->code_end) {
                error("function at hunk 1 offset 0x%08lx is too short for "
                      "an entry hook", (unsigned long)c->func.v[k]);
                continue;
            }
            c->hook_off[k] = c->code_end + c->nhooks * HOOK_SIZE;
            c->nhooks++;
        }
    verbose("Entry hooks: %lu of %lu functions\n", (unsigned long)c->nhooks,
            (unsigned long)c->func.n);
}

/* ---- 3. relocation ------------------------------------------------- */

static int32_t slot_for(Conv *c, int hunk, uint32_t page)
{
    if (page >= c->npages[hunk]) {
        error("HA target page %lu outside hunk %d", (unsigned long)page,
              hunk);
        return 0;
    }
    if (c->slot_of[hunk][page] < 0) {
        if ((int32_t)(c->table_off - c->ldb) +
                (int32_t)c->slot_hunk.n * 4 >= 0x8000) {
            error("too many page table slots (%lu)",
                  (unsigned long)c->slot_hunk.n + 1);
            return 0;
        }
        c->slot_of[hunk][page] = (int32_t)c->slot_hunk.n;
        u32_push(&c->slot_hunk, (uint32_t)hunk);
        u32_push(&c->slot_page, page);
    }
    return c->slot_of[hunk][page];
}

static void apply(Conv *c, const ElfRela *r, const ElfSection *ps,
                  const char *rname, int redir)
{
    Hunk *ph = &c->h[ps->hunk];
    uint32_t poff = ps->base + (r->offset - ps->addr);
    uint8_t *p;
    uint32_t insn, v;
    Target t;
    char where[96];

    if (r->type < 32)
        c->count[r->type]++;
    if (r->type == R_PPC_NONE)
        return;
    sprintf(where, "%.40s+0x%lx", rname, (unsigned long)r->offset);
    v = (r->type == R_PPC_ADDR16_LO || r->type == R_PPC_ADDR16_HA ||
         r->type == R_PPC_ADDR16_HI || r->type == R_PPC_ADDR16) ? 2 : 4;
    if (r->offset - ps->addr > ps->size || ps->size - (r->offset - ps->addr) < v) {
        error("%s: relocation outside its section", where);
        return;
    }
    if (ps->hunk == H_BSS) {
        error("%s: relocation in a BSS section", where);
        return;
    }
    if (!target_of(c, r, &t, where))
        return;
    if (redir && !t.abs && t.hunk == H_CODE && is_pointer_type(r->type))
        t.off = redirect(c, t.off);
    p = ph->data + poff;

    switch (r->type) {
    case R_PPC_ADDR32:
    case R_PPC_UADDR32:
        wr32(p, t.off);
        if (!t.abs) {
            /* Odd offsets occur (.eh_frame data linked into .text). The
             * 68k LoadSeg handles them on a 68020 or later. */
            if (poff & 1)
                c->odd++;
            if (ps->hunk == H_CODE && find_u32(&c->func, poff) >= 0 &&
                c->hooked[find_u32(&c->func, poff)])
                error("%s: ADDR32 on the first word of a hooked function",
                      where);
            u32_push(&ph->reloc[t.hunk], poff);
        }
        return;

    case R_PPC_REL24:
    case R_PPC_PLTREL24:
    case R_PPC_LOCAL24PC:
        if (t.abs || t.hunk != ps->hunk) {
            error("%s: REL24 to another hunk or an absolute symbol", where);
            return;
        }
        v = t.off - poff;
        if ((v & 3) || ((int32_t)v < -0x2000000 || (int32_t)v >= 0x2000000)) {
            error("%s: REL24 out of range or misaligned", where);
            return;
        }
        insn = rd32(p);
        wr32(p, (insn & 0xFC000003) | (v & 0x03FFFFFC));
        return;

    case R_PPC_REL14:
    case R_PPC_REL14_BRTAKEN:
    case R_PPC_REL14_BRNTAKEN:
        if (t.abs || t.hunk != ps->hunk) {
            error("%s: REL14 to another hunk or an absolute symbol", where);
            return;
        }
        v = t.off - poff;
        if ((v & 3) || ((int32_t)v < -0x8000 || (int32_t)v >= 0x8000)) {
            error("%s: REL14 out of range or misaligned", where);
            return;
        }
        insn = rd32(p);
        insn = (insn & 0xFFFF0003) | (v & 0xFFFC);
        if (r->type != R_PPC_REL14) {
            /* static prediction bit (BO bit 4, insn bit 21): set when the
             * hint disagrees with the default for the branch direction */
            int taken = r->type == R_PPC_REL14_BRTAKEN;
            int backward = (int32_t)v < 0;
            insn &= ~0x00200000UL;
            if (taken != backward)
                insn |= 0x00200000UL;
        }
        wr32(p, insn);
        return;

    case R_PPC_REL32:
        if (t.abs || t.hunk != ps->hunk) {
            error("%s: REL32 to another hunk or an absolute symbol", where);
            return;
        }
        wr32(p, t.off - poff);
        return;

    case R_PPC_ADDR16_HA:
        if (t.abs) {
            wr16(p, (uint16_t)((t.off + 0x8000) >> 16));
            return;
        }
        if ((poff & 3) != 2 || ps->hunk != H_CODE) {
            error("%s: ADDR16_HA not in the low half of a code word", where);
            return;
        }
        insn = rd32(p - 2);
        if ((insn >> 26) != 15 || ((insn >> 16) & 31) != 0) {
            error("%s: ADDR16_HA on an instruction other than lis", where);
            return;
        }
        {
            uint32_t page = (t.off + 0x8000) >> 16;
            int32_t s = slot_for(c, t.hunk, page);
            uint32_t d = c->table_off - c->ldb + (uint32_t)s * 4;
            uint32_t rd = (insn >> 21) & 31;
            wr32(p - 2, 0x80000000UL | (rd << 21) | (2UL << 16) |
                            (d & 0xFFFF));
        }
        return;

    case R_PPC_ADDR16_LO:
        if (t.abs) {
            wr16(p, (uint16_t)t.off);
            return;
        }
        if ((poff & 3) != 2 || ps->hunk != H_CODE) {
            error("%s: ADDR16_LO not in the low half of a code word", where);
            return;
        }
        insn = rd32(p - 2) >> 26;
        if (insn != 14 && !(insn >= 32 && insn <= 55)) {
            error("%s: ADDR16_LO on an unsupported instruction (opcode %lu)",
                  where, (unsigned long)insn);
            return;
        }
        wr16(p, (uint16_t)t.off);
        u32_push(&c->lo_key, ((uint32_t)t.hunk << 16) |
                                 ((t.off + 0x8000) >> 16));
        u32_push(&c->lo_poff, poff);
        return;

    case R_PPC_ADDR16_HI:
        if (t.abs) {
            wr16(p, (uint16_t)(t.off >> 16));
            return;
        }
        error("%s: ADDR16_HI to a relocatable symbol is not supported", where);
        return;

    case R_PPC_ADDR16:
        if (t.abs && (int32_t)t.off >= -0x8000 && (int32_t)t.off < 0x8000) {
            wr16(p, (uint16_t)t.off);
            return;
        }
        error("%s: ADDR16 value does not fit", where);
        return;

    default:
        error("%s: unsupported relocation type %lu", where,
              (unsigned long)r->type);
    }
}

static void load_and_relocate(Conv *c)
{
    ElfFile *e = &c->e;
    uint32_t i, j, n;
    int k;

    c->h[H_START].type = HUNK_CODE;
    c->h[H_START].data = xcalloc(c->h[H_START].size + 4, 1);

    c->h[H_CODE].type = HUNK_CODE;
    c->h[H_CODE].memflags = HUNKF_FAST;
    c->h[H_CODE].size = c->code_end + c->nhooks * HOOK_SIZE;
    c->h[H_CODE].data = xcalloc(c->h[H_CODE].size + 4, 1);

    c->h[H_DATA].type = HUNK_DATA;
    c->h[H_DATA].memflags = HUNKF_FAST;
    c->h[H_DATA].size = c->table_off;  /* table added later */
    c->h[H_DATA].data = xcalloc(c->table_off + 4, 1);

    c->h[H_BSS].type = HUNK_BSS;
    c->h[H_BSS].memflags = HUNKF_FAST;

    for (i = 1; i < e->nsec; i++) {
        ElfSection *s = &e->sec[i];
        uint8_t *buf;
        if (s->hunk < 0 || s->hunk == H_BSS)
            continue;
        buf = elf_read_section(e, i);
        memcpy(c->h[s->hunk].data + s->base, buf, s->size);
        free(buf);
    }

    for (k = 0; k < NHUNKS; k++) {
        uint32_t size = c->h[k].size;
        if (k == H_DATA)
            size = c->table_off;
        c->npages[k] = ((size + 0x8000) >> 16) + 1;
        c->slot_of[k] = xmalloc(c->npages[k] * sizeof(int32_t));
        for (j = 0; j < c->npages[k]; j++)
            c->slot_of[k][j] = -1;
    }

    for (i = 1; i < e->nsec; i++) {
        ElfSection *rs = &e->sec[i], *ps;
        ElfRela *r;
        if (rs->type != SHT_RELA || rs->info >= e->nsec)
            continue;
        ps = &e->sec[rs->info];
        if (ps->hunk < 0)
            continue;          /* .rela.stab and other debug data */
        r = elf_read_rela(e, i, &n);
        for (j = 0; j < n; j++)
            apply(c, &r[j], ps, ps->name, c->opt->hooks && !no_redirect(ps->name));
        free(r);
    }

    for (j = 0; j < c->lo_key.n; j++) {
        uint32_t hunk = c->lo_key.v[j] >> 16, page = c->lo_key.v[j] & 0xFFFF;
        if (page >= c->npages[hunk] || c->slot_of[hunk][page] < 0)
            error("ADDR16_LO at hunk 1 offset 0x%08lx: no lis loads its "
                  "page", (unsigned long)c->lo_poff.v[j]);
    }
}

/* ---- 4. page table, hooks, symbols --------------------------------- */

static void build_table(Conv *c)
{
    Hunk *d = &c->h[H_DATA];
    uint32_t tab = c->table_off, i;
    d->size = tab + (uint32_t)c->slot_hunk.n * 4;
    d->data = xrealloc(d->data, d->size + 4);
    for (i = 0; i < c->slot_hunk.n; i++) {
        wr32(d->data + tab + i * 4, c->slot_page.v[i] << 16);
        u32_push(&d->reloc[c->slot_hunk.v[i]], tab + i * 4);
    }
    verbose("Page table: %lu slots at hunk 2 offset 0x%08lx\n",
            (unsigned long)c->slot_hunk.n, (unsigned long)tab);
}

static void build_hooks(Conv *c)
{
    Hunk *h = &c->h[H_CODE];
    uint32_t k, base = c->ldb;
    for (k = 0; k < c->func.n; k++) {
        uint32_t f = c->func.v[k], o = c->hook_off[k], insn, op;
        uint8_t *p;
        if (!c->hooked[k])
            continue;
        p = h->data + o;
        wr32(p + 0, 0x7C0802A6UL);              /* mflr r0 */
        wr32(p + 4, 0x429F0009UL);              /* bcl 20,31,.+8 */
        wr32(p + 8, base);                      /* .long table+0x8000 */
        u32_push(&h->reloc[H_DATA], o + 8);
        wr32(p + 12, 0x7C4802A6UL);             /* mflr r2 */
        wr32(p + 16, 0x80420000UL);             /* lwz r2,0(r2) */
        wr32(p + 20, 0x7C0803A6UL);             /* mtlr r0 */
        insn = rd32(h->data + f);
        op = insn >> 26;
        if (op == 18 && !(insn & 2)) {          /* b / bl, relative */
            uint32_t d = insn & 0x03FFFFFC;
            if (d & 0x02000000)
                d |= 0xFC000000;
            d = f + d - (o + 24);
            insn = (insn & 0xFC000003) | (d & 0x03FFFFFC);
        } else if (op == 16 && !(insn & 2)) {   /* bc, relative */
            uint32_t d = insn & 0xFFFC;
            if (d & 0x8000)
                d |= 0xFFFF0000;
            d = f + d - (o + 24);
            if ((int32_t)d < -0x8000 || (int32_t)d >= 0x8000) {
                error("function at hunk 1 offset 0x%08lx starts with a "
                      "conditional branch the hook cannot reach",
                      (unsigned long)f);
                continue;
            }
            insn = (insn & 0xFFFF0003) | (d & 0xFFFC);
        }
        wr32(p + 24, insn);
        wr32(p + 28, 0x48000000UL | ((f + 4 - (o + 28)) & 0x03FFFFFC));
    }
}

/* ---- 4b. the startup object (spec 8.1) ---------------------------- */

static int find_elf_global(Conv *c, const char *name, Target *t)
{
    ElfFile *e = &c->e;
    uint32_t i;
    for (i = 0; i < e->nsym; i++) {
        ElfSymbol *y = &e->sym[i];
        if (y->bind == STB_LOCAL || y->shndx == SHN_UNDEF ||
            strcmp(y->name, name) != 0)
            continue;
        if (y->shndx == SHN_ABS) {
            t->abs = 1;
            t->off = y->value;
        } else if (y->shndx == SHN_COMMON) {
            t->abs = 0;
            t->hunk = y->common_hunk;
            t->off = y->common_off;
        } else if (y->shndx < e->nsec && e->sec[y->shndx].hunk >= 0) {
            t->abs = 0;
            t->hunk = e->sec[y->shndx].hunk;
            t->off = e->sec[y->shndx].base +
                     (y->value - e->sec[y->shndx].addr);
        } else
            continue;
        return 1;
    }
    return 0;
}

static int resolve_ext(Conv *c, const char *name, Target *t)
{
    if (strcmp(name, "_LinkerDB") == 0) {
        t->abs = 0;
        t->hunk = H_DATA;
        t->off = c->ldb;
        return 1;
    }
    if (strcmp(name, "__ppc_startup") == 0) {
        if (!c->opt->entry && find_elf_global(c, name, t))
            return 1;
        t->abs = 0;
        t->hunk = H_CODE;
        t->off = c->entry;
        return 1;
    }
    return lookup_obj(c, name, t) || find_elf_global(c, name, t);
}

/* Remembers a RELOC32 made from the startup object, for the map. */
static void add_oref(Conv *c, const char *name, uint32_t hunk, uint32_t off)
{
    c->oref = xrealloc(c->oref, (c->noref + 1) * sizeof(*c->oref));
    c->oref[c->noref].name = name;
    c->oref[c->noref].hunk = hunk;
    c->oref[c->noref].off = off;
    c->noref++;
}

static void link_startup(Conv *c)
{
    HObj *o = &c->obj;
    size_t k, i, j;
    int stack_set = 0;

    if (c->m68k_sec >= 0)
        return;
    for (k = 0; k < o->nsec; k++) {
        HSec *s = &o->sec[k];
        Hunk *h = &c->h[s->hunk];
        if (s->data)
            memcpy(h->data + s->base, s->data, s->size);
        for (i = 0; i < s->rel_off.n; i++) {
            HSec *ts = &o->sec[s->rel_sec.v[i]];
            uint32_t off = s->rel_off.v[i];
            if (!s->data || off + 4 > s->size)
                fatal("startup: relocation outside section %s", s->name);
            wr32(h->data + s->base + off,
                 rd32(h->data + s->base + off) + ts->base);
            u32_push(&h->reloc[ts->hunk], s->base + off);
            add_oref(c, "", (uint32_t)s->hunk, s->base + off);
        }
        for (i = 0; i < s->drel_off.n; i++) {
            HSec *ts = &o->sec[s->drel_sec.v[i]];
            uint32_t off = s->drel_off.v[i], v;
            if (!s->data || off + 2 > s->size)
                fatal("startup: relocation outside section %s", s->name);
            if (ts->hunk != H_DATA)
                fatal("startup: HUNK_DREL16 to section %s, which is not "
                      "small data", ts->name);
            v = ts->base + (uint32_t)(int32_t)(int16_t)
                    rd16(h->data + s->base + off) - c->ldb;
            if ((int32_t)v < -0x8000 || (int32_t)v >= 0x8000)
                fatal("startup: HUNK_DREL16 out of range");
            wr16(h->data + s->base + off, (uint16_t)v);
        }
        for (i = 0; i < s->nrefs; i++) {
            HRef *r = &s->refs[i];
            Target t;
            if (!resolve_ext(c, r->name, &t)) {
                error("startup: undefined symbol %s", r->name);
                continue;
            }
            for (j = 0; j < r->offs.n; j++) {
                uint32_t off = r->offs.v[j], at = s->base + off, v;
                if (!s->data)
                    fatal("startup: reference in BSS section %s", s->name);
                if (r->type == EXT_REF32) {
                    if (off + 4 > s->size)
                        fatal("startup: reference outside section %s",
                              s->name);
                    wr32(h->data + at, rd32(h->data + at) + t.off);
                    if (!t.abs)
                        u32_push(&h->reloc[t.hunk], at);
                    if (!t.abs)
                        add_oref(c, r->name, (uint32_t)s->hunk, at);
                } else if (r->type == EXT_DEXT16) {
                    if (off + 2 > s->size || t.abs || t.hunk != H_DATA)
                        fatal("startup: bad data-relative reference to %s",
                              r->name);
                    v = t.off + (uint32_t)(int32_t)(int16_t)
                            rd16(h->data + at) - c->ldb;
                    if ((int32_t)v < -0x8000 || (int32_t)v >= 0x8000)
                        fatal("startup: %s out of a4 range", r->name);
                    wr16(h->data + at, (uint16_t)v);
                } else
                    error("startup: unsupported reference type %u to %s",
                          r->type, r->name);
            }
        }
    }
    for (k = 0; k < o->ndefs; k++) {
        HDef *d = &o->defs[k];
        HSec *s = &o->sec[d->sec];
        if (d->type == EXT_DEF && strcmp(d->name, "__ppc_stacksize") == 0 &&
            s->data && d->value + 4 <= s->size) {
            wr32(c->h[s->hunk].data + s->base + d->value,
                 (uint32_t)c->opt->stack);
            stack_set = 1;
        }
        if (d->type == EXT_DEF && c->opt->symbols)
            hunk_add_sym(&c->h[s->hunk], d->name, s->base + d->value);
    }
    if (c->opt->stack && !stack_set)
        error("--stack needs a startup that defines __ppc_stacksize");
}

static void add_symbols(Conv *c)
{
    ElfFile *e = &c->e;
    uint32_t i;
    if (c->opt->symbols == 0)
        return;
    for (i = 0; i < e->nsym; i++) {
        ElfSymbol *y = &e->sym[i];
        int hunk;
        uint32_t off;
        if (!y->name[0] || y->type == STT_SECTION || y->type > STT_FUNC)
            continue;
        if (c->opt->symbols == 1 && y->bind == STB_LOCAL)
            continue;
        if (c->opt->symbols == 1 && y->type == STT_NOTYPE)
            continue;
        if (y->shndx == SHN_COMMON) {
            hunk = y->common_hunk;
            off = y->common_off;
        } else if (y->shndx != SHN_UNDEF && y->shndx < e->nsec &&
                   e->sec[y->shndx].hunk >= 0) {
            hunk = e->sec[y->shndx].hunk;
            off = e->sec[y->shndx].base + (y->value - e->sec[y->shndx].addr);
        } else
            continue;
        hunk_add_sym(&c->h[hunk], y->name, off);
    }
}

static void write_map(Conv *c, const char *path)
{
    ElfFile *e = &c->e;
    FILE *f = fopen(path, "w");
    uint32_t i;
    if (!f) {
        error("cannot create %s", path);
        return;
    }
    fprintf(f, "entry 1 0x%lx\n", (unsigned long)c->entry);
    for (i = 1; i < e->nsec; i++)
        if (e->sec[i].hunk >= 0)
            fprintf(f, "section %lu %s %d 0x%lx 0x%lx\n", (unsigned long)i,
                    e->sec[i].name, e->sec[i].hunk,
                    (unsigned long)e->sec[i].base,
                    (unsigned long)e->sec[i].size);
    for (i = 0; i < e->nsym; i++)
        if (e->sym[i].shndx == SHN_COMMON)
            fprintf(f, "common %lu %d 0x%lx\n", (unsigned long)i,
                    e->sym[i].common_hunk,
                    (unsigned long)e->sym[i].common_off);
    fprintf(f, "table 2 0x%lx %lu\n", (unsigned long)c->table_off,
            (unsigned long)c->slot_hunk.n);
    fprintf(f, "linkerdb 2 0x%lx\n", (unsigned long)c->ldb);
    for (i = 0; i < c->noref; i++)
        fprintf(f, "objref %s %lu 0x%lx\n",
                c->oref[i].name[0] ? c->oref[i].name : "-",
                (unsigned long)c->oref[i].hunk, (unsigned long)c->oref[i].off);
    for (i = 0; i < c->func.n; i++)
        if (c->hooked[i])
            fprintf(f, "hook 0x%lx 0x%lx\n", (unsigned long)c->func.v[i],
                    (unsigned long)c->hook_off[i]);
    fclose(f);
}

int convert(const char *in, const char *out, const Options *opt)
{
    Conv *c = xcalloc(1, sizeof(Conv));
    int k, rc;

    c->opt = opt;
    elf_open(&c->e, in);
    if (c->e.symtab < 0)
        fatal("%s: no symbol table", in);

    layout(c);
    collect_functions(c);
    if (opt->hooks)
        find_hooks(c);
    if (g_errors)
        return -1;
    load_and_relocate(c);
    build_table(c);
    build_hooks(c);
    link_startup(c);
    add_symbols(c);

    verbose("Relocations: ADDR32 %lu, HA %lu, LO %lu, REL24 %lu, "
            "redirected to hooks %lu, at odd offsets %lu\n",
            c->count[R_PPC_ADDR32] + c->count[R_PPC_UADDR32],
            c->count[R_PPC_ADDR16_HA], c->count[R_PPC_ADDR16_LO],
            c->count[R_PPC_REL24], c->redirected, c->odd);
    for (k = 0; k < NHUNKS; k++)
        verbose("Hunk %d: %s %lu bytes\n", k,
                c->h[k].type == HUNK_CODE ? "CODE" :
                c->h[k].type == HUNK_DATA ? "DATA" : "BSS ",
                (unsigned long)c->h[k].size);

    if (g_errors)
        return -1;
    if (opt->map)
        write_map(c, opt->map);
    rc = hunk_write(out, c->h, NHUNKS);
    elf_close(&c->e);
    return rc;
}
