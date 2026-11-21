"""Exact object-to-load-image binding for the narrow Safe Core checker.

This is deliberately not a general ELF linker verifier.  It accepts the closed
shared-library shapes used by Safe Core: a direct exported function or
an internal function plus its entry wrapper, one ``abort`` PLT slot, immediate
binding, no startup hooks, and no text relocations. The loader,
libc's nonreturning abort and ELF parsing implementation remain trusted.
"""
from __future__ import annotations

from hashlib import sha256
import struct

from .elf_shared_abi import inspect_owned_shared_elf


class SafeCoreELFRejected(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise SafeCoreELFRejected("E_HIA_SAFE_CORE_ELF: " + message)


class _ELF:
    def __init__(self, data, kind):
        from .hia_safe_core_elf_inventory_native import selected_safe_core_elf_inventory

        selected = self._native_inventory = selected_safe_core_elf_inventory()
        if selected is None:
            self._reference_inventory(data, kind)
            return
        self.sections, self.segments, self.authorities = selected.inventory(data, kind, authorities=True)
        self.data = data
        self.by_name = {section['name']: section for section in self.sections}

    def _reference_inventory(self, data, kind):
        self._native_inventory = None
        self.authorities = {}
        require(type(data) is bytes and 64 <= len(data) <= 8 * 1024 * 1024,
                "expected bounded immutable ELF bytes")
        self.data = data
        header = self.unpack("<16sHHIQQQIHHHHHH", 0)
        (ident, typ, machine, version, entry, phoff, shoff, flags, ehsize,
         phsize, phnum, shsize, shnum, shstrndx) = header
        require(ident == b"\x7fELF\x02\x01\x01" + b"\0" * 9 and
                (typ, machine, version, entry, flags, ehsize, shsize) ==
                (kind, 62, 1, 0, 0, 64, 64), "ELF identity is outside the profile")
        require(1 <= shnum <= 64 and 0 < shstrndx < shnum,
                "invalid or extended section inventory")
        rows = [self.unpack("<IIQQQQIIQQ", shoff + 64 * i) for i in range(shnum)]
        strings = rows[shstrndx]
        require(strings[1] == 3, "missing section-name string table")
        self.sections = []
        self.by_name = {}
        for index, row in enumerate(rows):
            name, typ, flags, addr, off, size, link, info, align, entsize = row
            label = self.string(strings[4], strings[5], name)
            require(label not in self.by_name, "duplicate section name")
            require(size <= 8 * 1024 * 1024 and typ != 8,
                    "NOBITS or oversized section is outside the profile")
            content = self.slice(off, size)
            section = dict(index=index, name=label, type=typ, flags=flags, addr=addr,
                           offset=off, size=size, link=link, info=info, align=align,
                           entsize=entsize, data=content)
            self.sections.append(section)
            self.by_name[label] = section
        self.segments = []
        if kind == 3:
            require(phsize == 56 and 1 <= phnum <= 16, "invalid segment inventory")
            for i in range(phnum):
                typ, flags, off, addr, paddr, filesz, memsz, align = self.unpack(
                    "<IIQQQQQQ", phoff + 56 * i)
                require(filesz <= memsz and addr + memsz < 1 << 64,
                        "invalid segment extent")
                require(typ in {1, 2, 0x6474E551, 0x6474E552} and paddr == addr,
                        "unreviewed program-header authority")
                if typ == 1:
                    require(align == 4096 and off % 4096 == addr % 4096 and filesz == memsz,
                            "load alignment or zero-fill range is outside the profile")
                self.slice(off, filesz)
                self.segments.append(dict(type=typ, flags=flags, offset=off, addr=addr,
                                          filesz=filesz, memsz=memsz, align=align))
            # The loader consumes program headers in file order. Sorting only
            # for the overlap check can silently admit a non-ELF load order:
            # first/last PT_LOAD entries determine a loader's mapping bounds.
            # Preserve the gABI p_vaddr ordering contract before normalization.
            loads = [seg for seg in self.segments if seg["type"] == 1]
            require(all(left["addr"] <= right["addr"] for left, right in zip(loads, loads[1:])),
                    "PT_LOAD entries are not in ascending virtual-address order")
            # ELF loaders map pages, not section intervals.  A second partial
            # PT_LOAD could otherwise replace one page of a checked section.
            loaded_pages = sorted((s["addr"] // 4096, (s["addr"] + s["memsz"] + 4095) // 4096)
                                  for s in self.segments if s["type"] == 1 and s["memsz"])
            require(all(left[1] <= right[0] for left, right in zip(loaded_pages, loaded_pages[1:])),
                    "PT_LOAD page ranges overlap")
        else:
            require(phoff == phsize == phnum == 0, "relocatable object has load segments")

    def slice(self, offset, size):
        require(0 <= offset <= len(self.data) and 0 <= size <= len(self.data) - offset,
                "ELF range lies outside the file")
        return self.data[offset:offset + size]

    def unpack(self, fmt, offset):
        return struct.unpack(fmt, self.slice(offset, struct.calcsize(fmt)))

    def string(self, offset, size, index):
        if self._native_inventory is not None:
            return self._native_inventory.string(self.data, offset, size, index)
        return self._reference_string(offset, size, index)

    def _reference_string(self, offset, size, index):
        require(0 <= index < size, "string index is outside the table")
        data = self.slice(offset, size)
        end = data.find(b"\0", index)
        require(end >= index and end - index <= 256, "unterminated or oversized name")
        try:
            return data[index:end].decode("ascii")
        except UnicodeDecodeError as exc:
            raise SafeCoreELFRejected("non-ASCII ELF name") from exc

    def section(self, name, typ=None):
        result = self.authorities[name] if name in self.authorities else self.by_name.get(name)
        require(result is not None, "missing section " + name)
        require(typ is None or result["type"] == typ, "section kind differs: " + name)
        return result

    def symbols(self, name):
        section = self.section(name)
        if self._native_inventory is not None:
            return self._native_inventory.symbols(self.data, section['index'])
        return self._reference_symbols(section)

    def _reference_symbols(self, section):
        require(section["type"] in (2, 11) and section["entsize"] == 24 and
                section["size"] % 24 == 0 and section["size"] <= 24 * 32,
                "symbol table is outside the profile")
        require(section["link"] < len(self.sections), "invalid symbol string-table link")
        strings = self.sections[section["link"]]
        require(strings["type"] == 3, "symbol name table has wrong kind")
        result = []
        for offset in range(section["offset"], section["offset"] + section["size"], 24):
            nameoff, info, other, shndx, value, size = self.unpack("<IBBHQQ", offset)
            result.append(dict(name=self.string(strings["offset"], strings["size"], nameoff),
                               info=info, other=other, shndx=shndx, value=value, size=size))
        return result

    def load_binding(self, section, permissions):
        if self._native_inventory is not None:
            return self._native_inventory.load_binding(self.data, section, permissions)
        return self._reference_load_binding(section, permissions)

    def _reference_load_binding(self, section, permissions):
        matches = [seg for seg in self.segments if seg["type"] == 1 and
                   seg["addr"] <= section["addr"] and
                   section["addr"] + section["size"] <= seg["addr"] + seg["filesz"]]
        require(len(matches) == 1, "section has ambiguous or missing PT_LOAD authority")
        segment = matches[0]
        require(segment["flags"] == permissions and
                section["offset"] - segment["offset"] == section["addr"] - segment["addr"],
                "section bytes differ from the loader mapping")
        return segment


def _functions(elf, section, table):
    if elf._native_inventory is not None:
        index = elf.section(table)['index']
        return elf._native_inventory.functions(elf.data, index, section)
    return _reference_functions(elf, section, table)


def _owned_functions(elf, section, kind):
    if elf._native_inventory is None:
        return _reference_functions(elf, section, ".symtab")
    return elf._native_inventory.owned_functions(elf.data, kind)


def _reference_functions(elf, section, table):
    rows = elf.symbols(table)
    result = {}
    for row in rows:
        if row["info"] & 15 != 2 or row["shndx"] == 0:
            continue
        require(row["name"] not in result and row["shndx"] == section["index"] and
                0 < row["size"] <= section["size"] and
                section["addr"] <= row["value"] <= section["addr"] + section["size"] - row["size"],
                "function is repeated or lies outside exact text")
        result[row["name"]] = row
    return result


def _reference_function_link(srcfunc, dstfunc, export, size, address):
    direct = set(srcfunc) == {export}
    expected = {export} if direct else {export, "__hia_native_fn_0"}
    require(set(srcfunc) == set(dstfunc) == expected and (direct or len(expected) == 2),
            "closed function inventory differs")
    spans = sorted((row["value"], row["value"] + row["size"]) for row in srcfunc.values())
    require(spans[0][0] == 0 and spans[-1][1] == size and
            all(left[1] == right[0] for left, right in zip(spans, spans[1:])),
            "function ranges do not exactly partition text")
    for name, row in srcfunc.items():
        dest = dstfunc[name]
        require(dest["value"] == address + row["value"] and
                dest["size"] == row["size"] and
                (dest["info"], dest["other"]) == (row["info"], row["other"]),
                "linker changed a function identity or extent")
    return direct


def _elf_hash(name):
    value = 0
    for byte in name.encode("ascii"):
        value = (value << 4) + byte
        high = value & 0xf0000000
        if high:
            value ^= high >> 24
        value &= ~high
    return value & 0xffffffff


def _gnu_hash(name):
    value = 5381
    for byte in name.encode("ascii"):
        value = (value * 33 + byte) & 0xffffffff
    return value


def _reference_dynamic_order(dynsymbols, export):
    require(len(dynsymbols) == 3 and dynsymbols[0] ==
            {"name": "", "info": 0, "other": 0, "shndx": 0, "value": 0, "size": 0} and
            dynsymbols[1] == {"name": "abort", "info": 18, "other": 0, "shndx": 0, "value": 0, "size": 0} and
            dynsymbols[2]["name"] == export, "closed dynamic symbol order differs")


def _lookup_tables(final, tags, dynsymbols, export):
    """Bind loader name/version lookup, not merely symbol-table spellings."""
    _reference_dynamic_order(dynsymbols, export)
    _reference_sysv_lookup(final.section(".hash", 5), tags.get(4), dynsymbols)
    _reference_gnu_lookup(final.section(".gnu.hash", 0x6ffffff6), tags.get(0x6ffffef5), export)
    versions = final.section(".gnu.version", 0x6fffffff)
    needed = final.section(".gnu.version_r", 0x6ffffffe)
    _reference_symbol_versions(final, tags, versions, needed)


def _reference_sysv_lookup(table, authority, dynsymbols):
    require(authority == table["addr"] and table["size"] >= 8,
            "SysV hash authority differs")
    buckets, chains = struct.unpack_from("<II", table["data"])
    require(1 <= buckets <= 64 and chains == 3 and table["size"] == 8 + 4 * (buckets + chains),
            "SysV hash shape differs")
    words = struct.unpack("<" + "I" * (buckets + chains), table["data"][8:])
    head, nexts = words[:buckets], words[buckets:]
    require(nexts[0] == 0 and all(value < chains for value in words), "invalid SysV hash index")
    seen = set()
    for bucket, index in enumerate(head):
        while index:
            require(index not in seen and _elf_hash(dynsymbols[index]["name"]) % buckets == bucket,
                    "SysV hash cycle, duplicate or wrong name bucket")
            seen.add(index)
            index = nexts[index]
    require(seen == {1, 2}, "SysV lookup omits a dynamic symbol")


def _reference_gnu_lookup(table, authority, export):
    require(authority == table["addr"] and table["size"] >= 16,
            "GNU hash authority differs")
    count, first, bloom_size, shift = struct.unpack_from("<IIII", table["data"])
    require(1 <= count <= 64 and first == 2 and bloom_size in {1, 2, 4, 8} and shift < 32 and
            table["size"] == 16 + bloom_size * 8 + count * 4 + 4,
            "GNU hash shape differs")
    bloom = list(struct.unpack_from("<" + "Q" * bloom_size, table["data"], 16))
    bucket_words = list(struct.unpack_from("<" + "I" * count, table["data"], 16 + bloom_size * 8))
    chain = struct.unpack_from("<I", table["data"], table["size"] - 4)[0]
    value = _gnu_hash(export)
    expected_bloom, expected_buckets = [0] * bloom_size, [0] * count
    expected_bloom[(value // 64) % bloom_size] = (1 << (value % 64)) | (1 << ((value >> shift) % 64))
    expected_buckets[value % count] = 2
    require(bloom == expected_bloom and bucket_words == expected_buckets and chain == value | 1,
            "GNU lookup does not exactly resolve the checked export")


def _reference_symbol_versions(final, tags, versions, needed):
    require(tags.get(0x6ffffff0) == versions["addr"] and versions["data"] == struct.pack("<HHH", 0, 2, 1) and
            tags.get(0x6ffffffe) == needed["addr"] and tags.get(0x6fffffff) == 1 and needed["size"] == 32,
            "loader symbol-version authority differs")
    version, count, fileoff, auxoff, nextoff = struct.unpack_from("<HHIII", needed["data"])
    hashed, flags, other, nameoff, auxnext = struct.unpack_from("<IHHII", needed["data"], 16)
    strings = final.section(".dynstr", 3)
    require((version, count, auxoff, nextoff, hashed, flags, other, auxnext) ==
            (1, 1, 16, 0, _elf_hash("GLIBC_2.2.5"), 0, 2, 0) and
            final.string(strings["offset"], strings["size"], fileoff) == "libc.so.6" and
            final.string(strings["offset"], strings["size"], nameoff) == "GLIBC_2.2.5",
            "abort is not bound to the reviewed libc symbol version")


def _reference_dynamic_tags(final, dynamic, got, rela):
    authorities = [s for s in final.segments if s["type"] == 2]
    require(len(authorities) == 1 and authorities[0]["offset"] == dynamic["offset"] and
            authorities[0]["addr"] == dynamic["addr"] and authorities[0]["filesz"] == dynamic["size"],
            "dynamic section is not the loader's dynamic table")
    allowed = {0, 1, 2, 3, 4, 5, 6, 10, 11, 20, 23, 30, 0x6ffffef5,
               0x6ffffffb, 0x6ffffffe, 0x6fffffff, 0x6ffffff0}
    tags = {}
    require(dynamic["size"] % 16 == 0, "truncated dynamic table")
    for at in range(0, dynamic["size"], 16):
        tag, value = struct.unpack_from("<QQ", dynamic["data"], at)
        require(tag in allowed, "unreviewed loader hook or relocation tag")
        if tag == 0:
            require(dynamic["data"][at:] == b"\0" * (dynamic["size"] - at),
                    "nonzero dynamic entries follow DT_NULL")
            break
        require(tag not in tags, "duplicated dynamic authority")
        tags[tag] = value
    require(tags.get(3) == got["addr"] and tags.get(2) == 24 and tags.get(20) == 7 and
            tags.get(23) == rela["addr"] and tags.get(30) == 8 and tags.get(0x6ffffffb) == 1,
            "PLT is not the exact immediately bound abort slot")
    return tags


def _reference_relro(final, writable, got):
    relros = [s for s in final.segments if s["type"] == 0x6474E552]
    require(len(relros) == 1, "expected exactly one RELRO authority")
    relro = relros[0]
    require(relro["flags"] == 4 and relro["align"] == 1 and
            relro["filesz"] == relro["memsz"] and relro["memsz"] > 0 and
            writable["addr"] <= relro["addr"] and
            relro["addr"] + relro["memsz"] <= writable["addr"] + writable["filesz"] and
            relro["offset"] - writable["offset"] == relro["addr"] - writable["addr"],
            "RELRO differs from the reviewed writable load mapping")
    # glibc elf/dl-reloc.c:_dl_protect_relro protects
    # [ALIGN_DOWN(start), ALIGN_DOWN(end)) with PROT_READ.
    # Raw GOT containment alone neither establishes its effective protection
    # nor prevents a forged RELRO range from removing execution from .text.
    protected_start = relro["addr"] // 4096 * 4096
    protected_end = (relro["addr"] + relro["memsz"]) // 4096 * 4096
    require(writable["addr"] // 4096 * 4096 <= protected_start < protected_end <=
            (writable["addr"] + writable["memsz"] + 4095) // 4096 * 4096 and
            protected_start <= got["addr"] and got["addr"] + got["size"] <= protected_end,
            "GOT is outside the effective RELRO page protection")

def _reference_plt_slot(plt, got, rela, dynsymbols):
    slot, info, addend = struct.unpack("<QQq", rela["data"])
    require(info & 0xffffffff == 7 and info >> 32 < len(dynsymbols) and
            dynsymbols[info >> 32]["name"] == "abort" and addend == 0 and
            slot == got["addr"] + 24, "abort GOT relocation changed")
    p = plt["data"]
    require(p[:2] == b"\xff\x35" and p[6:8] == b"\xff\x25" and p[12:16] == b"\x0f\x1f\x40\0" and
            plt["addr"] + 6 + struct.unpack("<i", p[2:6])[0] == got["addr"] + 8 and
            plt["addr"] + 12 + struct.unpack("<i", p[8:12])[0] == got["addr"] + 16 and
            p[16:18] == b"\xff\x25" and plt["addr"] + 22 + struct.unpack("<i", p[18:22])[0] == slot and
            p[22:27] == b"\x68\0\0\0\0" and p[27] == 0xe9 and
            plt["addr"] + 32 + struct.unpack("<i", p[28:32])[0] == plt["addr"],
            "abort PLT instruction or GOT target differs")


def _reference_object_relocations(obj, relsec, text_bytes, linked, plt, dstfunc):
    objectsymbols = obj.symbols(".symtab")
    expected_calls = {"abort"}
    if len(dstfunc) == 2:
        expected_calls.add("__hia_native_fn_0")
    expected_text = bytearray(text_bytes)
    calls, records = {}, []
    for at in range(0, relsec["size"], 24):
        offset, info, addend = struct.unpack_from("<QQq", relsec["data"], at)
        require(0 < offset <= len(text_bytes) - 4 and info & 0xffffffff == 4 and
                info >> 32 < len(objectsymbols) and addend == -4 and
                text_bytes[offset - 1:offset + 4] == b"\xe8\0\0\0\0",
                "object relocation does not name an E8 rel32 operand")
        name = objectsymbols[info >> 32]["name"]
        require(name in expected_calls and offset - 1 not in calls,
                "unreviewed or duplicate call relocation")
        target = plt["addr"] + 16 if name == "abort" else dstfunc[name]["value"]
        displacement = target - (linked["addr"] + offset + 4)
        require(-(1 << 31) <= displacement < 1 << 31, "linked call is outside rel32")
        expected_text[offset:offset + 4] = struct.pack("<i", displacement)
        calls[offset - 1] = "abort" if name == "abort" else target - linked["addr"]
        records.append(dict(offset=offset, symbol=name, type=4, addend=-4,
                            linked_target=target, displacement=displacement))
    require({r["symbol"] for r in records} == expected_calls and
            bytes(expected_text) == linked["data"],
            "final text differs outside exact resolved call fields")
    return calls, records


def bind_final_artifact(object_bytes, final_bytes, export):
    """Bind untrusted supplied ELF bytes without a producer's text or symbol map."""
    obj = _ELF(object_bytes, 1)
    text = obj.section(".text", 1)["data"]
    return bind_final_image(object_bytes, text, final_bytes, export)

def _reference_dynamic_symbols(final, text, export):
    exports = _functions(final, text, ".dynsym")
    name = export["name"]
    require(set(exports) == {name} and exports[name] == export, "loader export identity differs")
    symbols = final.symbols(".dynsym")
    undefined = [row["name"] for row in symbols if row["name"] and row["shndx"] == 0]
    require(undefined == ["abort"], "Safe Core admits only the nonreturning abort import")
    return symbols


def _reference_loader_sections(final):
    allocated = {".hash", ".gnu.hash", ".dynsym", ".dynstr", ".gnu.version", ".gnu.version_r",
                 ".rela.plt", ".plt", ".text", ".eh_frame", ".dynamic", ".got"}
    for section in final.sections:
        # The dynamic table names loader authorities independently of section
        # flags.  Their allocation bit cannot opt out of the PT_LOAD binding
        # below; otherwise the checker may inspect bytes the loader never uses.
        if section["name"] in allocated:
            require(section["flags"] & 2,
                    "loader section lacks required allocation flag: " + section["name"])
        if section["flags"] & 2:
            require(section["name"] in allocated and section["flags"] in {2, 3, 6, 0x42},
                    "unreviewed allocated loader section")
            if section["size"]:
                permissions = 6 if section["flags"] & 1 else 5 if section["flags"] & 4 else 4
                final.load_binding(section, permissions)

def _reference_executable_layout(final, linked, plt, got):
    require(plt["flags"] == 6 and plt["size"] == 32 and got["flags"] == 3 and got["size"] == 32,
            "PLT/GOT shape is outside the immediate-binding profile")
    require({s["name"] for s in final.sections if s["flags"] & 4} == {".text", ".plt"},
            "unexpected executable section")
    textload = final.load_binding(linked, 5)
    require([s for s in final.segments if s["type"] == 1 and s["flags"] & 1] == [textload],
            "additional executable load segment")
    require(final.load_binding(plt, 5) == textload and plt["addr"] == textload["addr"] and
            linked["addr"] == plt["addr"] + plt["size"] and
            linked["addr"] + linked["size"] == textload["addr"] + textload["filesz"],
            "executable segment contains unbound bytes")


def _reference_dynamic_relocations(final, rela, got):
    require([s["name"] for s in final.sections if s["type"] in (4, 9)] == [".rela.plt"] and
            rela["entsize"] == 24 and rela["size"] == 24 and
            rela["link"] == final.section(".dynsym")["index"] and rela["info"] == got["index"],
            "unreviewed dynamic relocation inventory")


def _reference_object_inventory(obj, rela, text, direct):
    require(rela["entsize"] == 24 and rela["size"] == (24 if direct else 48) and
            rela["info"] == text["index"] and rela["link"] == obj.section(".symtab")["index"],
            "object relocation inventory is outside the one-function profile")


def _reference_unwinding(section):
    require(section["size"] == 0, "unreviewed nonempty unwinding metadata")


def _reference_text_geometry(source, linked, text_bytes):
    require(source["flags"] == linked["flags"] == 6 and source["addr"] == 0 and
            source["data"] == text_bytes and source["size"] == linked["size"],
            "source and final text shapes differ")
    require(linked["size"] <= 64 * 1024, "Safe Core text budget exceeded")


def bind_final_image(object_bytes, text_bytes, final_bytes, export):
    """Check every relocated byte and return exact machine-entry coordinates.

    This consumes bytes, never objdump output or a producer-supplied symbol map.
    The returned abort call sites have been checked through E8, PLT, GOT,
    R_X86_64_JUMP_SLOT and the loader's actual dynamic table.
    """
    obj, final = _ELF(object_bytes, 1), _ELF(final_bytes, 3)
    inspect_owned_shared_elf(final_bytes, (export,))
    if final._native_inventory is None:
        _reference_loader_sections(final)
        _reference_unwinding(final.section(".eh_frame"))
    else:
        final._native_inventory.verify_loader_sections(final.data)
        final._native_inventory.verify_unwinding(final.data, final.section(".eh_frame"))
    source, linked = obj.section(".text", 1), final.section(".text", 1)
    if obj._native_inventory is None or type(text_bytes) is not bytes:
        _reference_text_geometry(source, linked, text_bytes)
    else:
        obj._native_inventory.verify_text_geometry(obj.data, source, linked, text_bytes)
    if obj._native_inventory is None:
        srcfunc = _owned_functions(obj, source, 1)
        dstfunc = _owned_functions(final, linked, 3)
        direct = _reference_function_link(srcfunc, dstfunc, export, source["size"], linked["addr"])
    else:
        obj_receipt = obj._native_inventory.owned_function_receipt(obj.data, 1)
        final_receipt = final._native_inventory.owned_function_receipt(final.data, 3)
        direct = obj._native_inventory.verify_owned_function_link(obj_receipt, final_receipt, export)
        srcfunc, _ = obj_receipt
        dstfunc, _ = final_receipt
    if final._native_inventory is None:
        dynsymbols = _reference_dynamic_symbols(final, linked, dstfunc[export])
        plt, got, rela = (final.section(".plt", 1), final.section(".got", 1),
                          final.section(".rela.plt", 4))
        _reference_executable_layout(final, linked, plt, got)
        writable = final.load_binding(got, 6)
        _reference_relro(final, writable, got)
        _reference_dynamic_relocations(final, rela, got)
        _reference_plt_slot(plt, got, rela, dynsymbols)
        dynamic = final.section(".dynamic", 6)
        final.load_binding(dynamic, 6)
        tags = _reference_dynamic_tags(final, dynamic, got, rela)
        _lookup_tables(final, tags, dynsymbols, export)
    else:
        final._native_inventory.verify_final_loader(final.data, export)
        plt = final.section(".plt", 1)

    relsec = obj.section(".rela.text", 4)
    if obj._native_inventory is None:
        _reference_object_inventory(obj, relsec, source, direct)
        calls, records = _reference_object_relocations(obj, relsec, text_bytes, linked, plt, dstfunc)
    else:
        obj._native_inventory.verify_object_inventory(obj.data, relsec, source, obj.section(".symtab"), direct=direct)
        # Check all names in table order (including unreferenced entries)
        # before interpreting relocations, as in the retained checker.
        obj.symbols(".symtab")
        calls, records = obj._native_inventory.object_relocations(
            obj.data, relsec, source, linked, plt, 0 if direct else dstfunc["__hia_native_fn_0"]["value"],
        )
    from .hia_sha256_stream_native import selected_stream_hasher

    hasher = selected_stream_hasher()
    digest = sha256 if hasher is None else hasher.new
    object_digest, image_digest, text_digest = (
        digest(data).hexdigest() for data in (object_bytes, final_bytes, linked["data"])
    )
    return {"text": linked["data"], "text_vaddr": linked["addr"],
            "entry": srcfunc[export]["value"], "calls": calls,
            "binding": {"object_sha256": object_digest, "final_image_sha256": image_digest,
                        "linked_text_sha256": text_digest,
                        "linked_text_file_offset": linked["offset"],
                        "linked_text_vaddr": linked["addr"], "relocations": records,
                        "entry_offset": srcfunc[export]["value"],
                        "function_shape": "direct_entry" if direct else "internal_with_wrapper",
                        "entry_symbol": export, "dynamic_binding": "NOW",
                        "external_semantics": "libc abort is nonreturning"}}

# Bind this executing module, including its top-level constants, to retained source.
from .hia_loaded_source import register_loaded_module as _register_loaded_source
_register_loaded_source(__name__)
