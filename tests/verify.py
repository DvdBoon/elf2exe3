#!/usr/bin/env python3
"""Host-side check of an elf2exe3 conversion (spec section 13).

usage: verify.py ELF EXE MAP

Loads EXE the way LoadSeg does (at hunk addresses whose low 16 bits are not
zero), then checks the loaded image against the ELF:

  * every byte not touched by a relocation equals the ELF section data
  * every ADDR32 holds the target address (or the target's entry hook)
  * every rewritten lis is "lwz rD,d(r2)" and the slot it reads holds the
    high-adjusted part of the HA target's address
  * every LO, paired with the instruction that loaded its base register,
    gives the exact target address
  * every entry hook sets r2 to table+0x8000 and continues at f+4
  * the file has no RELOC32 entry that the checks above did not expect

Only the Python standard library is used.
"""
import struct
import sys

HUNK_CODE, HUNK_DATA, HUNK_BSS = 0x3E9, 0x3EA, 0x3EB
HUNK_RELOC32, HUNK_SYMBOL, HUNK_END, HUNK_HEADER = 0x3EC, 0x3F0, 0x3F2, 0x3F3
BASES = [0x00102468, 0x0123A5C8, 0x0377F0F8, 0x04A0C338]
SHN_UNDEF, SHN_ABS, SHN_COMMON = 0, 0xFFF1, 0xFFF2
R_ADDR32, R_LO, R_HA, R_UADDR32 = 1, 4, 6, 24


def u32(b, o):
    return struct.unpack_from(">I", b, o)[0]


def s16(v):
    v &= 0xFFFF
    return v - 0x10000 if v & 0x8000 else v


class Fail:
    def __init__(self):
        self.n = 0

    def __call__(self, msg):
        self.n += 1
        if self.n <= 30:
            print("FAIL:", msg)


fail = Fail()


# ---------------------------------------------------------------- hunks
def read_hunks(path):
    d = open(path, "rb").read()
    pos = 0

    def get():
        nonlocal pos
        v = u32(d, pos)
        pos += 4
        return v

    assert get() == HUNK_HEADER, "no HUNK_HEADER"
    assert get() == 0, "resident library names"
    n = get()
    first, last = get(), get()
    assert first == 0 and last == n - 1
    sizes = [get() for _ in range(n)]
    hunks = []
    for i in range(n):
        h = {"type": None, "data": None, "reloc": [], "syms": [],
             "size": (sizes[i] & 0x3FFFFFFF) * 4, "flags": sizes[i] >> 30}
        while True:
            t = get() & 0x3FFFFFFF
            if t in (HUNK_CODE, HUNK_DATA):
                ln = get() * 4
                h["type"] = t
                h["data"] = bytearray(d[pos:pos + ln])
                pos += ln
            elif t == HUNK_BSS:
                h["type"] = t
                h["data"] = bytearray(get() * 4)
            elif t == HUNK_RELOC32:
                while True:
                    cnt = get()
                    if cnt == 0:
                        break
                    if cnt > 0xFFFF:
                        fail("hunk %d: RELOC32 count %d does not fit 16 bits "
                             "(LoadSeg reads only the low word)" % (i, cnt))
                    tgt = get()
                    for _ in range(cnt):
                        h["reloc"].append((tgt, get()))
            elif t == HUNK_SYMBOL:
                while True:
                    ln = get()
                    if ln == 0:
                        break
                    name = d[pos:pos + ln * 4].rstrip(b"\0").decode("latin1")
                    pos += ln * 4
                    h["syms"].append((name, get()))
            elif t == HUNK_END:
                break
            else:
                raise SystemExit("unknown hunk type 0x%x" % t)
        if len(h["data"]) < h["size"]:
            h["data"].extend(bytes(h["size"] - len(h["data"])))
        hunks.append(h)
    assert pos == len(d), "trailing data"
    return hunks


def load(hunks):
    mem = [bytearray(h["data"]) for h in hunks]
    for i, h in enumerate(hunks):
        for tgt, off in h["reloc"]:
            v = (u32(mem[i], off) + BASES[tgt]) & 0xFFFFFFFF
            struct.pack_into(">I", mem[i], off, v)
    return mem


# ------------------------------------------------------------------ ELF
def read_elf(path):
    d = open(path, "rb").read()
    assert d[:4] == b"\x7fELF" and d[4] == 1 and d[5] == 2
    shoff = u32(d, 32)
    nsec, shstrndx = struct.unpack_from(">HH", d, 48)
    secs = []
    for i in range(nsec):
        f = struct.unpack_from(">10I", d, shoff + 40 * i)
        secs.append(dict(name=f[0], type=f[1], flags=f[2], addr=f[3],
                         offset=f[4], size=f[5], link=f[6], info=f[7]))
    st = secs[shstrndx]
    for s in secs:
        o = st["offset"] + s["name"]
        s["name"] = d[o:d.index(b"\0", o)].decode()
    syms = []
    for s in secs:
        if s["type"] == 2:
            strt = secs[s["link"]]
            for k in range(s["size"] // 16):
                name, val, size, info, _, shndx = struct.unpack_from(
                    ">IIIBBH", d, s["offset"] + 16 * k)
                o = strt["offset"] + name
                nm = d[o:d.index(b"\0", o)].decode("latin1")
                syms.append(dict(name=nm, value=val, size=size,
                                 bind=info >> 4, type=info & 15,
                                 shndx=shndx))
    return d, secs, syms


def main():
    elf_path, exe_path, map_path = sys.argv[1:4]
    d, secs, syms = read_elf(elf_path)
    hunks = read_hunks(exe_path)
    mem = load(hunks)

    place, common, hooks = {}, {}, {}
    table = None
    ldb = None
    orefs = []
    for line in open(map_path):
        f = line.split()
        if f[0] == "section":
            place[int(f[1])] = (int(f[3]), int(f[4], 16))
        elif f[0] == "common":
            common[int(f[1])] = (int(f[2]), int(f[3], 16))
        elif f[0] == "table":
            table = (int(f[1]), int(f[2], 16), int(f[3]))
        elif f[0] == "linkerdb":
            ldb = (int(f[1]), int(f[2], 16))
        elif f[0] == "objref":
            orefs.append((f[1], int(f[2]), int(f[3], 16)))
        elif f[0] == "entry":
            entry = (int(f[1]), int(f[2], 16))
        elif f[0] == "hook":
            hooks[int(f[1], 16)] = int(f[2], 16)
    r2 = BASES[ldb[0]] + ldb[1]
    hook_abs = {BASES[1] + f: BASES[1] + h for f, h in hooks.items()}

    def addr(si, r):
        """Absolute target address of a RELA entry, or None if absolute."""
        y = syms[r[1]]
        if y["shndx"] == SHN_ABS:
            return None, y["value"] + r[3]
        if y["shndx"] == SHN_COMMON:
            hk, off = common[r[1]]
        elif y["shndx"] == SHN_UNDEF:
            return None, r[3]
        else:
            hk, base = place[y["shndx"]]
            off = base + y["value"] - secs[y["shndx"]]["addr"]
        return hk, (BASES[hk] + off + r[3]) & 0xFFFFFFFF

    redirect_ok = lambda name: not (name == ".gcc_except_table" or
                                    name.startswith((".eh_frame", ".stab",
                                                     ".debug")))
    touched = {}            # (hunk, off) -> bytes changed by relocs
    expected_relocs = set()
    nchk = dict(addr32=0, ha=0, lo=0, lo_paired=0, hooks=0)

    for si, s in enumerate(secs):
        if s["type"] != 4 or s["info"] not in place:
            continue
        ps = secs[s["info"]]
        ph, pbase = place[s["info"]]
        m = mem[ph]
        redir = redirect_ok(ps["name"])
        los = []
        for k in range(s["size"] // 12):
            off, info, add = struct.unpack_from(">IIi", d, s["offset"] + 12 * k)
            r = (off, info >> 8, info & 0xFF, add)
            poff = pbase + off - ps["addr"]
            th, val = addr(si, r)
            if redir and th == 1 and val in hook_abs:
                val = hook_abs[val]
            t = r[2]
            if t in (R_ADDR32, R_UADDR32):
                nchk["addr32"] += 1
                got = u32(m, poff)
                if got != val:
                    fail("ADDR32 %s+0x%x: 0x%08x != 0x%08x"
                         % (ps["name"], off, got, val))
                if th is not None:
                    expected_relocs.add((ph, th, poff))
                touched[(ph, poff)] = 4
            elif t == R_HA:
                nchk["ha"] += 1
                w = u32(m, poff - 2)
                orig = u32(d, ps["offset"] + off - 2)
                touched[(ph, poff - 2)] = 4
                if th is None:
                    if (w & 0xFFFF) != ((val + 0x8000) >> 16) & 0xFFFF:
                        fail("HA abs at %s+0x%x" % (ps["name"], off))
                    continue
                if w >> 16 != 0x8000 | ((orig >> 21) & 31) << 5 | 2:
                    fail("HA %s+0x%x: 0x%08x is not lwz rD,d(r2) for 0x%08x"
                         % (ps["name"], off, w, orig))
                    continue
                slot = r2 + s16(w)
                so = slot - BASES[table[0]]
                v = u32(mem[table[0]], so)
                # slot = hunk address + high-adjusted hunk offset (6.2)
                toff = val - BASES[th]
                if v != (BASES[th] + ((toff + 0x8000) >> 16 << 16)) & 0xFFFFFFFF:
                    fail("HA %s+0x%x: slot 0x%08x != ha(0x%08x)"
                         % (ps["name"], off, v, val))
            elif t == R_LO:
                nchk["lo"] += 1
                touched[(ph, poff)] = 2
                if th is None:
                    if (u32(m, poff - 2) & 0xFFFF) != val & 0xFFFF:
                        fail("LO abs at %s+0x%x" % (ps["name"], off))
                    continue
                los.append((poff - 2, val))
            elif t == 0:
                pass
            else:
                fail("verifier does not know reloc type %d" % t)

        # pair each LO with the lwz-from-r2 that set its base register
        for ipos, val in los:
            w = u32(m, ipos)
            ra = (w >> 16) & 31
            for back in range(1, 65):
                q = ipos - 4 * back
                if q < pbase:
                    break
                x = u32(m, q)
                op = x >> 26
                rd = (x >> 21) & 31
                if op == 32 and (x >> 16) & 31 == 2 and rd == ra:
                    v = u32(mem[table[0]], r2 + s16(x) - BASES[table[0]])
                    if (v + s16(w)) & 0xFFFFFFFF != val:
                        fail("LO at hunk %d+0x%x: 0x%08x + %d != 0x%08x"
                             % (ph, ipos, v, s16(w), val))
                    nchk["lo_paired"] += 1
                    break
                writes = (op in (14, 15, 24, 25, 28, 29, 32, 33, 34, 35,
                                 40, 41, 42, 43) and rd == ra)
                if writes or op == 18 or op == 16 or (op == 19):
                    break

    # bytes outside relocations must be unchanged
    for si, (ph, base) in place.items():
        s = secs[si]
        if s["type"] == 8:
            continue
        src = d[s["offset"]:s["offset"] + s["size"]]
        img = bytearray(mem[ph][base:base + s["size"]])
        orig = bytearray(src)
        for (h, o), ln in touched.items():
            if h == ph and base <= o < base + s["size"]:
                a = o - base
                img[a:a + ln] = b"\0" * ln
                orig[a:a + ln] = b"\0" * ln
        if img != orig:
            i = next(k for k in range(len(img)) if img[k] != orig[k])
            fail("section %s differs at +0x%x" % (s["name"], i))

    # hooks
    for f, h in hooks.items():
        nchk["hooks"] += 1
        m = mem[1]
        w = [u32(m, h + 4 * k) for k in range(8)]
        expected_relocs.add((1, table[0], h + 8))
        if (w[0], w[1], w[3], w[4], w[5]) != (0x7C0802A6, 0x429F0009,
                                             0x7C4802A6, 0x80420000,
                                             0x7C0803A6):
            fail("hook 0x%x: bad prologue" % h)
        if w[2] != r2:
            fail("hook 0x%x: r2 value 0x%08x != 0x%08x" % (h, w[2], r2))
        first = u32(m, f)
        op = first >> 26

        def btarget(insn, at):
            if insn >> 26 == 18:
                dd = insn & 0x03FFFFFC
                dd -= 0x04000000 if dd & 0x02000000 else 0
            else:
                dd = s16(insn & 0xFFFC)
            return at + dd

        if op in (16, 18) and not first & 2:
            if (w[6] & 0xFC000003) != (first & 0xFC000003) or \
               btarget(w[6], h + 24) != btarget(first, f):
                fail("hook 0x%x: branch copy wrong" % h)
        elif w[6] != first:
            fail("hook 0x%x: first instruction 0x%08x != 0x%08x"
                 % (h, w[6], first))
        if w[7] >> 26 != 18 or w[7] & 3 or btarget(w[7], h + 28) != f + 4:
            fail("hook 0x%x: does not continue at f+4" % h)

    # startup object references (spec 8)
    for name, h, off in orefs:
        v = u32(mem[h], off)
        hit = [t for t, o in hunks[h]["reloc"] if o == off]
        if len(hit) != 1:
            fail("startup reloc at hunk %d+0x%x: %d entries" % (h, off, len(hit)))
            continue
        expected_relocs.add((h, hit[0], off))
        if name == "_LinkerDB":
            if v != r2:
                fail("_LinkerDB in hunk %d+0x%x is 0x%08x, not r2 0x%08x"
                     % (h, off, v, r2))
        elif name == "__ppc_startup":
            if v != BASES[entry[0]] + entry[1]:
                fail("__ppc_startup is 0x%08x, not the entry" % v)
        elif not BASES[hit[0]] <= v <= BASES[hit[0]] + hunks[hit[0]]["size"]:
            fail("startup reloc at hunk %d+0x%x points outside its hunk" % (h, off))
    nchk["startup"] = len(orefs)
    if hunks[0]["type"] != HUNK_CODE or hunks[0]["size"] == 0:
        fail("hunk 0 is not a 68k code hunk")

    # page table entries
    for k in range(table[2]):
        off = table[1] + 4 * k
        hit = [t for t, o in hunks[table[0]]["reloc"] if o == off]
        if len(hit) != 1:
            fail("table slot %d has %d relocs" % (k, len(hit)))
        else:
            expected_relocs.add((table[0], hit[0], off))

    got = {(i, t, o) for i, h in enumerate(hunks) for t, o in h["reloc"]}
    nrel = sum(len(h["reloc"]) for h in hunks)
    if nrel != len(got):
        fail("duplicate RELOC32 entries")
    if got != expected_relocs:
        fail("RELOC32 sets differ: %d unexpected, %d missing"
             % (len(got - expected_relocs), len(expected_relocs - got)))

    print("checked: %d ADDR32, %d HA, %d LO (%d paired with their lis), "
          "%d hooks, %d table slots, %d startup relocs, %d RELOC32"
          % (nchk["addr32"], nchk["ha"], nchk["lo"], nchk["lo_paired"],
             nchk["hooks"], table[2], nchk["startup"], nrel))
    print("hunks:", ", ".join("%d %s %d" % (i, {HUNK_CODE: "CODE",
                              HUNK_DATA: "DATA", HUNK_BSS: "BSS"}[h["type"]],
                              h["size"]) for i, h in enumerate(hunks)))
    if fail.n:
        print("%d failures" % fail.n)
        sys.exit(1)
    print("OK")


if __name__ == "__main__":
    main()
