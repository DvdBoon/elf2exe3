/* elf2exe3 - small helpers shared by all modules */
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"

int g_errors = 0;
int g_warnings = 0;
int g_verbose = 0;

uint32_t rd32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

uint16_t rd16(const uint8_t *p)
{
    return (uint16_t)(((unsigned)p[0] << 8) | (unsigned)p[1]);
}

void wr32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

void wr16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

void *xmalloc(size_t n)
{
    void *p = malloc(n ? n : 1);
    if (!p)
        fatal("out of memory (%lu bytes)", (unsigned long)n);
    return p;
}

void *xcalloc(size_t n, size_t sz)
{
    void *p = calloc(n ? n : 1, sz ? sz : 1);
    if (!p)
        fatal("out of memory (%lu bytes)", (unsigned long)(n * sz));
    return p;
}

void *xrealloc(void *p, size_t n)
{
    void *q = realloc(p, n ? n : 1);
    if (!q)
        fatal("out of memory (%lu bytes)", (unsigned long)n);
    return q;
}

static void vmsg(const char *kind, const char *fmt, va_list ap)
{
    fprintf(stderr, "elf2exe3: %s", kind);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
}

void error(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vmsg("error: ", fmt, ap);
    va_end(ap);
    g_errors++;
}

void warning(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vmsg("warning: ", fmt, ap);
    va_end(ap);
    g_warnings++;
}

void fatal(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vmsg("error: ", fmt, ap);
    va_end(ap);
    exit(20);
}

void verbose(const char *fmt, ...)
{
    va_list ap;
    if (!g_verbose)
        return;
    va_start(ap, fmt);
    vfprintf(stdout, fmt, ap);
    va_end(ap);
}

void u32_push(U32Vec *a, uint32_t x)
{
    if (a->n == a->cap) {
        a->cap = a->cap ? a->cap * 2 : 64;
        a->v = xrealloc(a->v, a->cap * sizeof(uint32_t));
    }
    a->v[a->n++] = x;
}

void u32_free(U32Vec *a)
{
    free(a->v);
    a->v = NULL;
    a->n = a->cap = 0;
}

static int cmp_u32(const void *a, const void *b)
{
    uint32_t x = *(const uint32_t *)a, y = *(const uint32_t *)b;
    return x < y ? -1 : x > y;
}

void u32_sort(U32Vec *a)
{
    if (a->n > 1)
        qsort(a->v, a->n, sizeof(uint32_t), cmp_u32);
}
