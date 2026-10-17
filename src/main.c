/* elf2exe3 - convert a WarpOS PowerPC ELF into an Amiga hunk executable */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "convert.h"
#include "util.h"

#define VERSION "0.1"

static void usage(void)
{
    fprintf(stderr,
        "elf2exe3 " VERSION " - WarpOS ELF to Amiga hunk executable\n"
        "usage: elf2exe3 [options] input.elf output.exe\n"
        "  --repack         input is an Elf2Exe2 executable, not an ELF\n"
        "  --entry SYMBOL   PPC entry point (default: start of .text)\n"
        "  --no-hooks       do not add r2 entry hooks\n"
        "  --startup FILE   68k startup object for hunk 0 (default: built-in\n"
        "                   wosstart.o; vbcc's warpup.o for argc/argv programs)\n"
        "  --m68k-startup SECTION  use this ELF code section as hunk 0\n"
        "  --stack N        PPC stack size in bytes\n"
        "  --symbols        keep global symbols (default: none)\n"
        "  --all-symbols    keep global and local symbols\n"
        "  --map FILE       write the layout map (for tests)\n"
        "  --dump-elf FILE  with --repack: write the rebuilt ELF (for tests)\n"
        "  --Werror         treat warnings as errors\n"
        "  -v               print layout and statistics\n");
    exit(20);
}

int main(int argc, char **argv)
{
    Options opt;
    const char *in = NULL, *out = NULL;
    int i, werror = 0;

    memset(&opt, 0, sizeof(opt));
    opt.hooks = 1;
    opt.symbols = 0;
    for (i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "--entry") == 0 && i + 1 < argc)
            opt.entry = argv[++i];
        else if (strcmp(a, "--map") == 0 && i + 1 < argc)
            opt.map = argv[++i];
        else if (strcmp(a, "--startup") == 0 && i + 1 < argc)
            opt.startup = argv[++i];
        else if (strcmp(a, "--m68k-startup") == 0 && i + 1 < argc)
            opt.m68k_sect = argv[++i];
        else if (strcmp(a, "--stack") == 0 && i + 1 < argc)
            opt.stack = strtoul(argv[++i], NULL, 0);
        else if (strcmp(a, "--dump-elf") == 0 && i + 1 < argc)
            opt.dump_elf = argv[++i];
        else if (strcmp(a, "--repack") == 0)
            opt.repack = 1;
        else if (strcmp(a, "--no-hooks") == 0)
            opt.hooks = 0;
        else if (strcmp(a, "--symbols") == 0)
            opt.symbols = 1;
        else if (strcmp(a, "--strip") == 0)   /* the default, kept for scripts */
            opt.symbols = 0;
        else if (strcmp(a, "--all-symbols") == 0)
            opt.symbols = 2;
        else if (strcmp(a, "--Werror") == 0)
            werror = 1;
        else if (strcmp(a, "-v") == 0)
            g_verbose = 1;
        else if (a[0] == '-' && a[1])
            usage();
        else if (!in)
            in = a;
        else if (!out)
            out = a;
        else
            usage();
    }
    if (!in || !out)
        usage();
    if (convert(in, out, &opt) != 0 || g_errors)
        return 20;
    if (g_warnings && werror) {
        remove(out);
        return 10;
    }
    return 0;
}
