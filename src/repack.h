/* elf2exe3 - --repack: reading executables made by Elf2Exe2 */
#ifndef REPACK_H
#define REPACK_H

#include <stdint.h>

/* Checks that path is an Elf2Exe2 executable and rebuilds the program as
 * an ELF image in memory (spec section 15). fatal() if it is not one.
 * Returns the image; *size gets its length. */
uint8_t *repack_load(const char *path, uint32_t *size);
/* Writes the rebuilt ELF image to a file (--dump-elf, for the tests). */
void repack_dump(const char *path, const uint8_t *image, uint32_t size);

#endif
