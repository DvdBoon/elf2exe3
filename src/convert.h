/* elf2exe3 - ELF to hunk conversion */
#ifndef CONVERT_H
#define CONVERT_H

typedef struct {
    int hooks;             /* add r2 entry hooks (spec 6.2), default 1 */
    int symbols;           /* 0 = strip, 1 = globals, 2 = all */
    const char *entry;     /* entry symbol, NULL = start of .text */
    const char *map;       /* write a layout map here, NULL = none */
} Options;

/* Returns 0 on success; errors are reported through error()/fatal(). */
int convert(const char *in, const char *out, const Options *opt);

#endif
