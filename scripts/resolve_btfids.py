#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""
Resolve .BTF_ids entries in a linked vmlinux.

Upstream kernels do this with tools/bpf/resolve_btfids (a C program using
libelf).  This tree's build predates that tool, so the .BTF_ids section stays
filled with the placeholder zeros emitted by include/linux/btf_ids.h, and
every BTF_ID_LIST / BTF_SET would resolve to type id 0 at runtime.

This script performs the same job using pyelftools:

  * read .BTF (produced by `pahole -J`) to build a (kind, name) -> type id map
  * for every __BTF_ID__<kind>__<name>__<n> symbol in .BTF_ids, write the
    matching type id into its 4-byte slot
  * for every __BTF_ID__set__<name> symbol, write the element count, so that
    `struct btf_id_set { u32 cnt; u32 ids[]; }` is consistent

Usage: resolve_btfids.py <vmlinux>

The script is deliberately non-fatal: if pyelftools is unavailable, or the
image has no .BTF/.BTF_ids, it prints a note and exits 0 so the build is not
broken on hosts without the dependency.
"""

import sys

try:
    from elftools.elf.elffile import ELFFile
except ImportError:
    print("BTFIDS: pyelftools not available, leaving .BTF_ids unresolved")
    sys.exit(0)

BTF_MAGIC = 0xEB9F

BTF_KIND_INT = 1
BTF_KIND_PTR = 2
BTF_KIND_ARRAY = 3
BTF_KIND_STRUCT = 4
BTF_KIND_UNION = 5
BTF_KIND_ENUM = 6
BTF_KIND_FWD = 7
BTF_KIND_TYPEDEF = 8
BTF_KIND_VOLATILE = 9
BTF_KIND_CONST = 10
BTF_KIND_RESTRICT = 11
BTF_KIND_FUNC = 12
BTF_KIND_FUNC_PROTO = 13
BTF_KIND_VAR = 14
BTF_KIND_DATASEC = 15
BTF_KIND_FLOAT = 16
BTF_KIND_DECL_TAG = 17
BTF_KIND_TYPE_TAG = 18
BTF_KIND_ENUM64 = 19

# prefix used in the symbol name -> BTF kind
KIND_BY_PREFIX = {
    "struct": BTF_KIND_STRUCT,
    "union": BTF_KIND_UNION,
    "func": BTF_KIND_FUNC,
    "typedef": BTF_KIND_TYPEDEF,
    "enum": BTF_KIND_ENUM,
    "enum64": BTF_KIND_ENUM64,
    "datasec": BTF_KIND_DATASEC,
    "float": BTF_KIND_FLOAT,
}

# extra bytes following struct btf_type, per kind
EXTRA_BYTES = {
    BTF_KIND_INT: lambda vlen: 4,
    BTF_KIND_ARRAY: lambda vlen: 12,
    BTF_KIND_STRUCT: lambda vlen: vlen * 12,
    BTF_KIND_UNION: lambda vlen: vlen * 12,
    BTF_KIND_ENUM: lambda vlen: vlen * 8,
    BTF_KIND_FUNC_PROTO: lambda vlen: vlen * 8,
    BTF_KIND_VAR: lambda vlen: 4,
    BTF_KIND_DATASEC: lambda vlen: vlen * 12,
    BTF_KIND_DECL_TAG: lambda vlen: 4,
    BTF_KIND_ENUM64: lambda vlen: vlen * 12,
}


def parse_btf(data):
    """Return {(kind, name): type_id} for every named type in the blob."""
    if len(data) < 24:
        raise ValueError("BTF blob too small")

    magic, version, flags, hdr_len, type_off, type_len, str_off, str_len = (
        int.from_bytes(data[0:2], "little"),
        data[2],
        data[3],
        int.from_bytes(data[4:8], "little"),
        int.from_bytes(data[8:12], "little"),
        int.from_bytes(data[12:16], "little"),
        int.from_bytes(data[16:20], "little"),
        int.from_bytes(data[20:24], "little"),
    )

    if magic != BTF_MAGIC:
        raise ValueError("bad BTF magic 0x%04x" % magic)
    if version != 1:
        raise ValueError("unsupported BTF version %d" % version)

    types = data[hdr_len + type_off: hdr_len + type_off + type_len]
    strings = data[hdr_len + str_off: hdr_len + str_off + str_len]

    def get_str(off):
        if off >= len(strings):
            return ""
        end = strings.find(b"\0", off)
        if end < 0:
            end = len(strings)
        return strings[off:end].decode("utf-8", "replace")

    found = {}
    ambiguous = set()

    off = 0
    type_id = 1  # BTF type ids start at 1; id 0 is "void"
    while off + 12 <= len(types):
        name_off = int.from_bytes(types[off:off + 4], "little")
        info = int.from_bytes(types[off + 4:off + 8], "little")
        kind = (info >> 24) & 0x1F
        vlen = info & 0xFFFF

        name = get_str(name_off)
        if name:
            key = (kind, name)
            if key in found:
                ambiguous.add(key)
            else:
                found[key] = type_id

        extra = EXTRA_BYTES.get(kind, lambda vlen: 0)(vlen)
        off += 12 + extra
        type_id += 1

    # pahole emits a second copy of a struct when the type graph around it
    # differs, even though the layout is identical, so duplicates are expected.
    # Keep the first (what libbpf's btf__find_by_name_kind does too) and only
    # report the ones that actually matter, i.e. the ones we resolve against.
    return found, ambiguous


def main():
    if len(sys.argv) != 2:
        print("usage: %s <vmlinux>" % sys.argv[0])
        return 1

    path = sys.argv[1]

    with open(path, "rb") as f:
        elf = ELFFile(f)
        btf_sec = elf.get_section_by_name(".BTF")
        ids_sec = elf.get_section_by_name(".BTF_ids")
        symtab = elf.get_section_by_name(".symtab")

        if btf_sec is None or ids_sec is None:
            print("BTFIDS: no .BTF/.BTF_ids in %s, nothing to do" % path)
            return 0
        if symtab is None:
            print("BTFIDS: no symbol table in %s, nothing to do" % path)
            return 0

        types, ambiguous = parse_btf(btf_sec.data())

        ids_index = None
        for idx, sec in enumerate(elf.iter_sections()):
            if sec.name == ".BTF_ids":
                ids_index = idx
                break
        if ids_index is None:
            print("BTFIDS: no .BTF_ids in %s, nothing to do" % path)
            return 0

        ids_addr = ids_sec.header["sh_addr"]
        ids_off = ids_sec.header["sh_offset"]

        patches = {}   # offset inside .BTF_ids -> value
        unresolved = []

        # Symbols defined anywhere in the image.  A BTF_ID entry for a function
        # that was not compiled in (e.g. should_failslab with CONFIG_FAILSLAB=n)
        # has no BTF type by design, so it is not worth a warning.
        warned = set()
        defined = {sym.name for sym in symtab.iter_symbols()
                   if sym["st_shndx"] != "SHN_UNDEF"}

        for sym in symtab.iter_symbols():
            name = sym.name
            if not name.startswith("__BTF_ID__"):
                continue
            if sym["st_shndx"] != ids_index:
                continue

            rel = sym["st_value"] - ids_addr
            if rel < 0 or rel + 4 > ids_sec.header["sh_size"]:
                continue

            # __BTF_ID__set__<name>: u32 element count for struct btf_id_set
            if name.startswith("__BTF_ID__set__"):
                size = sym["st_size"]
                if size >= 4:
                    patches[rel] = (size - 4) // 4
                continue

            # __BTF_ID__<kind>__<name>__<n>
            rest = name[len("__BTF_ID__"):]
            parts = rest.split("__")
            if len(parts) < 3:
                continue
            prefix, type_name = parts[0], "__".join(parts[1:-1])

            kind = KIND_BY_PREFIX.get(prefix)
            if kind is None:
                continue

            key = (kind, type_name)
            if key in ambiguous and key not in warned:
                warned.add(key)
                print("BTFIDS: warning: multiple types named '%s' (kind %d), "
                      "using the first" % (type_name, kind))

            type_id = types.get(key)
            if type_id is None:
                if type_name not in defined:
                    # Optional code that this configuration does not build.
                    continue
                unresolved.append(name)
                continue

            patches[rel] = type_id

    if not patches:
        print("BTFIDS: nothing to patch in %s" % path)
        return 0

    with open(path, "r+b") as f:
        for rel, value in sorted(patches.items()):
            f.seek(ids_off + rel)
            f.write(value.to_bytes(4, "little"))

    print("BTFIDS: resolved %d entries in .BTF_ids of %s"
          % (len(patches), path))

    if unresolved:
        print("BTFIDS: warning: %d symbols had no matching BTF type:"
              % len(unresolved))
        for name in unresolved[:10]:
            print("BTFIDS:   %s" % name)

    return 0


if __name__ == "__main__":
    sys.exit(main())
