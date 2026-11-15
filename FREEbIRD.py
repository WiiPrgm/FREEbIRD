#!/usr/bin/env python3
"""makecard.py -- drop your homebrew onto the boot-IRD 1.22A exploit card.

The exploit image (the "golden stub") is frozen, hardware-verified bytes: the
FAT32 volume, the 258-directory overflow, the fake context window, the
control-value FAT patches, and savezelda's loader.bin. All of that work exists
only to reach one end state -- savezelda running and loading /boot.elf off the
card with its own FAT driver. Your homebrew is just that one file.

This tool never regenerates the weapon. It opens a known-good stub, swaps the
single /boot.elf the exploit was designed to let you vary, then PROVES it
changed nothing else by byte-diffing every other region against the stub.

    .elf in  ->  written to /boot.elf as-is
    .dol in  ->  converted to ELF (the inverse of elf2dol) -> /boot.elf

Usage:
    python makecard.py mygame.elf                 # -> bootird_sd.raw
    python makecard.py mygame.dol -o mycard.raw
    python makecard.py --verify mycard.raw        # re-check an existing card
    python makecard.py --inspect                  # dump the stub's layout

Then flash the WHOLE .raw to an SD card (it is an image, not a file copy -- the
payload contains directory names with '/' that no OS file API can create):
    Linux/macOS : sudo dd if=bootird_sd.raw of=/dev/sdX bs=4M conv=fsync
    Windows     : Win32DiskImager / Rufus (DD / image mode)

Honest fine print (the tool enforces what it can):
  * Menu-version lock: these bytes are specific to boot-IRD 1.22A. A different
    devkit menu rev needs a fresh offset analysis; this tool cannot paper over
    that.
  * Hardware only: the stub relies on SJIS / ring-cache behavior Dolphin gets
    wrong, so it will NOT boot in the emulator. Don't "test" in Dolphin.
  * /boot.elf is the required name; a .dol still lands as boot.elf after
    conversion. savezelda looks for exactly that.
"""

import argparse
import struct
import sys
from pathlib import Path

SECTOR = 512
EOC = 0x0FFFFFFF
EOC_MIN = 0x0FFFFFF8
DEFAULT_STUB = "list_overflow_v3r11_e680_small.raw"
DEFAULT_OUT = "bootird_sd.raw"
BOOTELF_NAME = b"BOOT    ELF"   # 8.3 short name; savezelda matches /boot.elf


# ------------------------------------------------------------------ DOL -> ELF
# A DOL is up to 7 text + 11 data sections, each (file-offset, load-address,
# size), plus a BSS address/size and an entry point -- all big-endian. We wrap
# each non-empty section as an ELF PT_LOAD segment and set e_entry. This is the
# exact inverse of the standard elf2dol.

DOL_TEXT = 7
DOL_DATA = 11
DOL_SECTIONS = DOL_TEXT + DOL_DATA      # 18
DOL_HEADER = 0x100


def _in_ram(a):
    # valid cached load window: MEM1 (0x8000_0000..0x817F_FFFF) or
    # MEM2 (0x9000_0000..0x93FF_FFFF, Wii).
    return (0x80000000 <= a < 0x81800000) or (0x90000000 <= a < 0x94000000)


def is_elf(data: bytes) -> bool:
    return data[:4] == b"\x7fELF"


def is_dol(data: bytes) -> bool:
    """Heuristic: a DOL has no magic. Validate the header self-consistently."""
    if len(data) < DOL_HEADER:
        return False
    offs = struct.unpack_from(">18I", data, 0)
    addrs = struct.unpack_from(">18I", data, 0x48)
    sizes = struct.unpack_from(">18I", data, 0x90)
    entry = struct.unpack_from(">I", data, 0xE0)[0]
    any_section = False
    for off, addr, size in zip(offs, addrs, sizes):
        if size == 0:
            continue
        any_section = True
        if off + size > len(data):
            return False
        if not _in_ram(addr):
            return False
    return any_section and _in_ram(entry)


def dol_to_elf(dol: bytes) -> bytes:
    """Convert a GameCube/Wii DOL into a minimal ELF32 BE PPC executable."""
    offs = struct.unpack_from(">18I", dol, 0x00)
    addrs = struct.unpack_from(">18I", dol, 0x48)
    sizes = struct.unpack_from(">18I", dol, 0x90)
    bss_addr = struct.unpack_from(">I", dol, 0xD8)[0]
    bss_size = struct.unpack_from(">I", dol, 0xDC)[0]
    entry = struct.unpack_from(">I", dol, 0xE0)[0]

    segs = []   # (vaddr, data, flags, memsz)
    for i in range(DOL_SECTIONS):
        if sizes[i] == 0:
            continue
        body = dol[offs[i]:offs[i] + sizes[i]]
        is_text = i < DOL_TEXT
        flags = 0x5 if is_text else 0x6     # R|X for text, R|W for data
        segs.append([addrs[i], body, flags, sizes[i]])
    if bss_size:
        # .bss as its own zero-filesz PT_LOAD (p_memsz > p_filesz).
        segs.append([bss_addr, b"", 0x6, bss_size])

    segs.sort(key=lambda s: s[0])
    EH, PH = 52, 32
    phnum = len(segs)
    data_base = EH + PH * phnum

    phdrs = bytearray()
    blob = bytearray()
    cursor = data_base
    for vaddr, body, flags, memsz in segs:
        if body:
            # align each segment's file data to 0x20 for tidy loading
            pad = (-len(blob)) % 0x20
            blob += b"\x00" * pad
            cursor = data_base + len(blob)
            p_offset = cursor
            blob += body
            filesz = len(body)
        else:
            p_offset = 0
            filesz = 0
        phdrs += struct.pack(
            ">IIIIIIII",
            1,            # p_type = PT_LOAD
            p_offset,     # p_offset
            vaddr,        # p_vaddr
            vaddr,        # p_paddr
            filesz,       # p_filesz
            memsz,        # p_memsz
            flags,        # p_flags
            0x20,         # p_align
        )

    ehdr = bytearray(EH)
    ehdr[0:4] = b"\x7fELF"
    ehdr[4] = 1          # EI_CLASS   = ELFCLASS32
    ehdr[5] = 2          # EI_DATA    = ELFDATA2MSB (big-endian)
    ehdr[6] = 1          # EI_VERSION = EV_CURRENT
    struct.pack_into(
        ">HHIIIIIHHHHHH", ehdr, 16,
        2,          # e_type    = ET_EXEC
        20,         # e_machine = EM_PPC
        1,          # e_version
        entry,      # e_entry
        EH,         # e_phoff
        0,          # e_shoff
        0,          # e_flags
        EH,         # e_ehsize
        PH,         # e_phentsize
        phnum,      # e_phnum
        0,          # e_shentsize
        0,          # e_shnum
        0,          # e_shstrndx
    )
    return bytes(ehdr) + bytes(phdrs) + bytes(blob)


def load_homebrew(path: Path) -> bytes:
    raw = path.read_bytes()
    if not raw:
        sys.exit(f"error: {path} is empty")
    if is_elf(raw):
        return raw
    if is_dol(raw):
        print(f"  input is a DOL ({len(raw)} B) -> converting to ELF")
        elf = dol_to_elf(raw)
        print(f"  converted ELF: {len(elf)} B")
        return elf
    sys.exit(f"error: {path} is neither an ELF (7f 45 4c 46) nor a valid DOL")


# --------------------------------------------------------------- FAT32 image
class Card:
    """A flashable boot-IRD stub image: MBR + one FAT32 partition."""

    def __init__(self, data: bytes):
        self.v = bytearray(data)
        self.part = self._find_partition()
        b = self.part
        self.bps = self._u16(b + 11)
        self.spc = self.v[b + 13]
        self.rsvd = self._u16(b + 14)
        self.nfats = self.v[b + 16]
        self.fatsz = self._u32(b + 36)
        self.root_cl0 = self._u32(b + 44)
        self.tot = self._u32(b + 32)
        if self.bps != SECTOR or self.spc != 1:
            sys.exit(f"error: unexpected BPB (bps={self.bps} spc={self.spc})")
        self.data_sec = self.rsvd + self.nfats * self.fatsz
        self.ncl = self.tot - self.data_sec

    # -- byte helpers (absolute offsets into the image) --
    def _u16(self, o): return struct.unpack_from("<H", self.v, o)[0]
    def _u32(self, o): return struct.unpack_from("<I", self.v, o)[0]

    def _find_partition(self) -> int:
        # Prefer an MBR FAT partition; fall back to a bare volume at offset 0.
        if self.v[510:512] == b"\x55\xaa":
            for i in range(4):
                e = 0x1BE + i * 16
                ptype = self.v[e + 4]
                lba = struct.unpack_from("<I", self.v, e + 8)[0]
                if ptype in (0x0B, 0x0C, 0x06, 0x0E, 0x01) and lba:
                    off = lba * SECTOR
                    if self.v[off + 11:off + 13] == b"\x00\x02":
                        return off
        if self.v[11:13] == b"\x00\x02":
            return 0
        sys.exit("error: no FAT32 BPB found (not a boot-IRD stub image?)")

    # -- FAT / cluster primitives (all relative to the partition) --
    def fat_slot_off(self, copy, n):
        return self.part + (self.rsvd + copy * self.fatsz) * SECTOR + n * 4

    def fat_get(self, n):
        return struct.unpack_from("<I", self.v, self.fat_slot_off(0, n))[0] & EOC

    def fat_set(self, n, val):
        for f in range(self.nfats):
            struct.pack_into("<I", self.v, self.fat_slot_off(f, n), val & 0xFFFFFFFF)

    def clus_off(self, n):
        return self.part + (self.data_sec + n - 2) * SECTOR

    def chain(self, n):
        out, seen = [], set()
        while 2 <= n < EOC_MIN and n not in seen:
            seen.add(n)
            out.append(n)
            n = self.fat_get(n)
        return out

    # -- directory --
    def root_clusters(self):
        return self.chain(self.root_cl0)

    def find_dirent(self, name11):
        """Return (abs_offset, start_cluster, size) for a short dirent, or None."""
        rc = self.root_clusters()
        for ci, c in enumerate(rc):
            base = self.clus_off(c)
            for p in range(0, SECTOR, 32):
                first = self.v[base + p]
                if first == 0x00:
                    return None
                if first == 0xE5 or self.v[base + p + 11] == 0x0F:
                    continue
                if self.v[base + p:base + p + 11] == name11:
                    hi = struct.unpack_from("<H", self.v, base + p + 20)[0]
                    lo = struct.unpack_from("<H", self.v, base + p + 26)[0]
                    size = struct.unpack_from("<I", self.v, base + p + 28)[0]
                    return (base + p, (hi << 16) | lo, size)
        return None

    def safe_residues(self):
        """Residues (mod 128) proven followable by the stub's own chains.

        Every cluster the live exploit's own FAT driver walks -- the root dir,
        the loader.bin ('p') file, and the existing /boot.elf -- sits on one of
        these residues by construction. Allocating a replacement chain only on
        these residues guarantees it never lands on a control-patched FAT entry.
        """
        res = set(c % 128 for c in self.root_clusters())
        for name in (b"p          ", BOOTELF_NAME):
            hit = self.find_dirent(name)
            if hit:
                for c in self.chain(hit[1]):
                    res.add(c % 128)
        return res


# ------------------------------------------------------------------- inject
def inject(stub_path: Path, elf: bytes, out_path: Path):
    card = Card(stub_path.read_bytes())
    stub_bytes = bytes(card.v)   # pristine copy for the verifier

    hit = card.find_dirent(BOOTELF_NAME)
    if not hit:
        sys.exit("error: no BOOT.ELF dirent in the stub -- wrong image?")
    dirent_off, old_start, old_size = hit
    old_chain = card.chain(old_start)
    allowed = card.safe_residues()
    print(f"  stub: part@{card.part // SECTOR} LBA, {card.ncl} clusters, "
          f"{card.nfats} FATs")
    print(f"  placeholder /boot.elf: start cl {old_start}, {old_size} B, "
          f"{len(old_chain)} clusters")
    print(f"  safe residues (mod 128): {sorted(allowed)}")

    # 1) free the placeholder chain (both FAT copies)
    for c in old_chain:
        card.fat_set(c, 0)

    # 2) allocate a fresh chain for the new ELF on safe residues only
    need = (len(elf) + SECTOR - 1) // SECTOR
    new_chain = []
    n = 2
    while len(new_chain) < need and n < card.ncl + 2:
        if card.fat_get(n) == 0 and (n % 128) in allowed:
            new_chain.append(n)
        n += 1
    if len(new_chain) < need:
        # restore the FAT we just cleared before bailing, so we never leave a
        # half-edited image behind on error.
        for a, b in zip(old_chain, old_chain[1:]):
            card.fat_set(a, b)
        if old_chain:
            card.fat_set(old_chain[-1], EOC)
        cap = len(new_chain)
        sys.exit(
            f"error: need {need} clusters for a {len(elf)} B ELF but only "
            f"{cap} are free on safe residues (~{cap * SECTOR // 1024} KiB).\n"
            f"       Rebuild the stub on a larger volume: raise CLUSTERS in "
            f"make_small_base.py and regenerate.")

    # 3) link + write the chain
    for a, b in zip(new_chain, new_chain[1:]):
        card.fat_set(a, b)
    card.fat_set(new_chain[-1], EOC)
    for i, c in enumerate(new_chain):
        seg = elf[i * SECTOR:(i + 1) * SECTOR].ljust(SECTOR, b"\x00")
        card.v[card.clus_off(c):card.clus_off(c) + SECTOR] = seg

    # 4) repoint the BOOT.ELF dirent (start cluster hi/lo + size) -- the only
    #    directory bytes we touch.
    struct.pack_into("<H", card.v, dirent_off + 20, (new_chain[0] >> 16) & 0xFFFF)
    struct.pack_into("<H", card.v, dirent_off + 26, new_chain[0] & 0xFFFF)
    struct.pack_into("<I", card.v, dirent_off + 28, len(elf))

    print(f"  new /boot.elf: start cl {new_chain[0]}, {len(elf)} B, "
          f"{len(new_chain)} clusters")

    # 5) prove it: nothing outside the permitted regions may differ
    verify_against_stub(card, stub_bytes, dirent_off, old_chain, new_chain)

    out_path.write_bytes(card.v)
    print(f"OK  wrote {out_path} ({len(card.v) // (1 << 20)} MiB)")


def permitted_mask(card, dirent_off, old_chain, new_chain):
    """Byte offsets makecard.py is allowed to have changed vs the stub."""
    allow = bytearray(len(card.v))      # 1 = change permitted here
    one = b"\x01"
    # the 6 dirent bytes we rewrote: start-hi (20..21), start-lo (26..27),
    # size (28..31)
    for a, b in ((20, 22), (26, 28), (28, 32)):
        allow[dirent_off + a:dirent_off + b] = one * (b - a)
    # data clusters of the old and new boot.elf chains
    for c in set(old_chain) | set(new_chain):
        base = card.clus_off(c)
        allow[base:base + SECTOR] = one * SECTOR
    # FAT slots (every copy) of the old and new chains
    for c in set(old_chain) | set(new_chain):
        for f in range(card.nfats):
            o0 = card.fat_slot_off(f, c)
            allow[o0:o0 + 4] = one * 4
    return allow


# The root-chain weapon window: make_probe writes win[0x60:0x200] into the
# 17th and 18th root clusters. Those same clusters also hold directory entries
# below 0x60 (including the BOOT.ELF dirent we are allowed to edit), so the
# weapon region is exactly [0x60:0x200], not the whole cluster.
WEAPON_LO, WEAPON_HI = 0x60, 0x200
WEAPON_ROOT_IDX = (16, 17)


def verify_against_stub(card, stub_bytes, dirent_off, old_chain, new_chain):
    if len(card.v) != len(stub_bytes):
        sys.exit("verify FAIL: output length changed")
    allow = permitted_mask(card, dirent_off, old_chain, new_chain)
    out = card.v
    step = 4096
    bad = []
    n = len(out)
    for i in range(0, n, step):
        a = out[i:i + step]
        b = stub_bytes[i:i + step]
        if a == b:
            continue
        for j in range(len(a)):
            if a[j] != b[j] and not allow[i + j]:
                bad.append(i + j)
                if len(bad) > 8:
                    break
        if len(bad) > 8:
            break
    if bad:
        sys.exit("verify FAIL: the exploit bytes changed at offsets "
                 + ", ".join(f"0x{o:X}" for o in bad)
                 + " -- aborting, the card was NOT written.")

    # positive spot checks on the weapon: the root-chain payload window and the
    # loader.bin ('p') file must be byte-identical to the stub.
    rc = card.root_clusters()
    for idx in WEAPON_ROOT_IDX:
        if idx < len(rc):
            base = card.clus_off(rc[idx])
            if (out[base + WEAPON_LO:base + WEAPON_HI]
                    != stub_bytes[base + WEAPON_LO:base + WEAPON_HI]):
                sys.exit(f"verify FAIL: root weapon window (cluster {idx}) changed")
    phit = card.find_dirent(b"p          ")
    if phit:
        for c in card.chain(phit[1]):
            base = card.clus_off(c)
            if out[base:base + SECTOR] != stub_bytes[base:base + SECTOR]:
                sys.exit("verify FAIL: loader.bin ('p') changed")
    print("  verify OK: exploit bytes byte-identical to the stub")


def verify_existing(path: Path, stub_path: Path):
    """Re-check an already-built card against the golden stub."""
    card = Card(path.read_bytes())
    stub = Card(stub_path.read_bytes())
    if len(card.v) != len(stub.v):
        sys.exit("verify FAIL: size differs from stub")
    hit = card.find_dirent(BOOTELF_NAME)
    shit = stub.find_dirent(BOOTELF_NAME)
    if not hit or not shit:
        sys.exit("verify FAIL: BOOT.ELF dirent missing")
    dirent_off, start, size = hit
    new_chain = card.chain(start)
    old_chain = stub.chain(shit[1])
    # confirm the new chain avoids patched residues
    allowed = stub.safe_residues()
    stray = [c for c in new_chain if (c % 128) not in allowed]
    if stray:
        sys.exit(f"verify FAIL: boot.elf chain crosses patched residues: "
                 f"{stray[:8]}")
    verify_against_stub(card, bytes(stub.v), dirent_off, old_chain, new_chain)
    print(f"OK  {path} is a valid card: /boot.elf = {size} B, "
          f"{len(new_chain)} clusters, weapon intact")


def inspect(stub_path: Path):
    card = Card(stub_path.read_bytes())
    print(f"stub: {stub_path}")
    print(f"  partition @ LBA {card.part // SECTOR}, {card.ncl} clusters, "
          f"{card.nfats} FATs, fatsz {card.fatsz}")
    print(f"  root chain: {len(card.root_clusters())} clusters")
    for name in (b"p          ", BOOTELF_NAME):
        hit = card.find_dirent(name)
        if hit:
            off, start, size = hit
            ch = card.chain(start)
            print(f"  {name.decode().strip()!r}: start cl {start}, {size} B, "
                  f"{len(ch)} clusters")
    allowed = sorted(card.safe_residues())
    free_safe = sum(1 for n in range(2, card.ncl + 2)
                    if card.fat_get(n) == 0 and n % 128 in allowed)
    hit = card.find_dirent(BOOTELF_NAME)
    reclaim = len(card.chain(hit[1])) if hit else 0
    cap = free_safe + reclaim
    print(f"  safe residues (mod 128): {allowed}")
    print(f"  usable for /boot.elf: ~{cap} clusters "
          f"(~{cap * SECTOR // 1024} KiB)")


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Swap your homebrew /boot.elf onto a boot-IRD 1.22A "
                    "exploit card without touching the exploit bytes.")
    ap.add_argument("input", nargs="?", help="homebrew .elf or .dol")
    ap.add_argument("-o", "--out", default=DEFAULT_OUT,
                    help=f"output image (default {DEFAULT_OUT})")
    ap.add_argument("--stub", default=DEFAULT_STUB,
                    help=f"golden stub image (default {DEFAULT_STUB})")
    ap.add_argument("--verify", metavar="CARD",
                    help="re-check an existing card against the stub and exit")
    ap.add_argument("--inspect", action="store_true",
                    help="print the stub's layout and capacity, then exit")
    args = ap.parse_args(argv)

    stub = Path(args.stub)
    if not stub.exists():
        sys.exit(f"error: stub not found: {stub}")

    if args.inspect:
        inspect(stub)
        return
    if args.verify:
        verify_existing(Path(args.verify), stub)
        return
    if not args.input:
        ap.error("give a homebrew .elf/.dol, or use --verify / --inspect")

    src = Path(args.input)
    if not src.exists():
        sys.exit(f"error: input not found: {src}")
    print(f"makecard: {src} -> {args.out}  (stub {stub.name})")
    elf = load_homebrew(src)
    inject(stub, elf, Path(args.out))


if __name__ == "__main__":
    main()
