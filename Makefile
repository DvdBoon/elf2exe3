# elf2exe3
#   make            host build (any C99 compiler), used by the tests
#   make amiga      68k AmigaOS build with vbcc
CC      ?= cc
CFLAGS  ?= -std=c99 -pedantic -Wall -Wextra -O2
VC      ?= vc
VCFLAGS ?= +aos68k -c99 -O2

SRC = src/main.c src/convert.c src/elf.c src/hobj.c src/hunk.c src/util.c \
      src/repack.c src/wosstart.c

elf2exe3: $(SRC) src/*.h
	$(CC) $(CFLAGS) -o $@ $(SRC)

amiga: $(SRC) src/*.h
	$(VC) $(VCFLAGS) -o elf2exe3.68k $(SRC)

# Rebuilds the built-in startup after editing startup/wosstart.s (needs
# vasm). The generated src/wosstart.c is committed.
startup:
	vasmm68k_mot -Fhunk -nosym -quiet -o startup/wosstart.o startup/wosstart.s
	python3 tools/bin2c.py startup/wosstart.o src/wosstart.c

check: elf2exe3
	./elf2exe3 --map check.map $(ELF) check.exe
	python3 tests/verify.py $(ELF) check.exe check.map

clean:
	rm -f elf2exe3 elf2exe3.68k check.exe check.map

.PHONY: amiga check clean startup
