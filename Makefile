# elf2exe3
#   make            host build (any C99 compiler), used by the tests
#   make amiga      68k AmigaOS build with vbcc
CC      ?= cc
CFLAGS  ?= -std=c99 -pedantic -Wall -Wextra -O2
VC      ?= vc
VCFLAGS ?= +aos68k -c99 -O2

SRC = src/main.c src/convert.c src/elf.c src/hunk.c src/util.c

elf2exe3: $(SRC) src/*.h
	$(CC) $(CFLAGS) -o $@ $(SRC)

amiga: $(SRC) src/*.h
	$(VC) $(VCFLAGS) -o elf2exe3.68k $(SRC)

check: elf2exe3
	python3 tests/verify.py ./elf2exe3 $(ELF)

clean:
	rm -f elf2exe3 elf2exe3.68k

.PHONY: amiga check clean
