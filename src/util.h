/* elf2exe3 - small helpers shared by all modules */
#ifndef UTIL_H
#define UTIL_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/* Big-endian access, independent of host byte order. */
uint32_t rd32(const uint8_t *p);
uint16_t rd16(const uint8_t *p);
void wr32(uint8_t *p, uint32_t v);
void wr16(uint8_t *p, uint16_t v);

/* Allocation that exits on failure. */
void *xmalloc(size_t n);
void *xcalloc(size_t n, size_t sz);
void *xrealloc(void *p, size_t n);

/* Messages. error() counts, fatal() exits with 20. */
void error(const char *fmt, ...);
void warning(const char *fmt, ...);
void fatal(const char *fmt, ...);
void verbose(const char *fmt, ...);
extern int g_errors;
extern int g_warnings;
extern int g_verbose;

/* Growable array of 32-bit values. */
typedef struct {
    uint32_t *v;
    size_t n, cap;
} U32Vec;

void u32_push(U32Vec *a, uint32_t x);
void u32_free(U32Vec *a);
void u32_sort(U32Vec *a);

#endif
