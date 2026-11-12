"""Exact original ELF object policy; development authoring input only."""

def _name(value):
    if type(value) is not str or _NAME.fullmatch(value) is None:
        raise MachineObjectError("invalid ELF symbol name")
    return value

def _exact_int(value, lower, upper):
    return type(value) is int and lower <= value < upper

def write_elf_object(code, symbols, relocations, *, text_alignment=16):
    """Encode one machine-code image as Linux x86-64 ET_REL.

    ``symbols`` is a list of ``{name, offset, size, global}`` records. Private
    implementation functions must have ``global=False``. ``relocations`` is a
    list of ``{offset, symbol, type: 4, addend: -4}`` records naming E8 rel32 call
    operands. Input order does not affect symbol or relocation table ordering.
    """
    if type(text_alignment) is not int or text_alignment not in {16, 32, 64}:
        raise MachineObjectError("unreviewed text section alignment")
    if type(code) is not bytes or not code or len(code) > MAX_OBJECT_BYTES:
        raise MachineObjectError("nonempty bounded immutable machine bytes required")
    if (type(symbols) is not list or not 1 <= len(symbols) < MAX_SYMBOLS
            or type(relocations) is not list or len(relocations) > len(code) // 5):
        raise MachineObjectError("invalid symbol or relocation inventory")
    names, definitions = set(), []
    for row in symbols:
        if type(row) is not dict or set(row) != {"name", "offset", "size", "global"}:
            raise MachineObjectError("invalid function symbol record")
        name = _name(row["name"])
        if (name in names or type(row["global"]) is not bool
                or not _exact_int(row["offset"], 0, len(code))
                or not _exact_int(row["size"], 1, len(code) + 1)
                or row["offset"] + row["size"] > len(code)):
            raise MachineObjectError("duplicate or out-of-range function symbol")
        names.add(name)
        definitions.append(dict(row))
    spans = sorted((row["offset"], row["offset"] + row["size"]) for row in definitions)
    if any(right[0] < left[1] for left, right in zip(spans, spans[1:])):
        raise MachineObjectError("function symbol ranges overlap")
    # A local function starts at a known instruction boundary. This writer is
    # not a disassembler and does not assert complete ISA validation.
    checked_relocations = []
    undefined = set()
    for row in relocations:
        if (type(row) is not dict or set(row) != {"offset", "symbol", "type", "addend"}
                or not _exact_int(row["offset"], 1, len(code) - 3)
                or type(row["type"]) is not int or row["type"] != 4
                or type(row["addend"]) is not int or row["addend"] != -4):
            raise MachineObjectError("only explicit PLT32 call relocations are supported")
        name = _name(row["symbol"])
        offset = row["offset"]
        if code[offset - 1] != 0xe8 or code[offset:offset + 4] != b"\0" * 4:
            raise MachineObjectError("call relocation does not point to an E8 placeholder")
        checked_relocations.append(dict(row))
        if name not in names:
            undefined.add(name)
    relocations = sorted(checked_relocations, key=lambda row: row["offset"])
    if any(right["offset"] - left["offset"] < 5
           for left, right in zip(relocations, relocations[1:])):
        raise MachineObjectError("duplicate or overlapping call relocations")
    if len(names) + len(undefined) + 2 > MAX_SYMBOLS:
        raise MachineObjectError("ELF symbol inventory exceeds limit")
    local = sorted((x for x in definitions if not x["global"]), key=lambda x: x["name"])
    public = sorted((x for x in definitions if x["global"]), key=lambda x: x["name"])
    string_table = bytearray(b"\0")
    name_offsets = {}
    for name in sorted(names | undefined):
        name_offsets[name] = len(string_table)
        string_table.extend(name.encode("ascii") + b"\0")
    symtab = bytearray(b"\0" * 24)
    # STT_SECTION local symbol for .text; first function index is 2.
    symtab.extend(struct.pack("<IBBHQQ", 0, 3, 0, 1, 0, 0))
    symbol_indexes = {}
    for row in local + public:
        symbol_indexes[row["name"]] = len(symtab) // 24
        info = (0x10 if row["global"] else 0) | 2  # STT_FUNC
        visibility = 0 if row["global"] else 2  # STV_HIDDEN
        symtab.extend(struct.pack("<IBBHQQ", name_offsets[row["name"]], info, visibility,
                                  1, row["offset"], row["size"]))
    first_global = 2 + len(local)
    for name in sorted(undefined):
        symbol_indexes[name] = len(symtab) // 24
        symtab.extend(struct.pack("<IBBHQQ", name_offsets[name], 0x10, 0, 0, 0, 0))
    rela = bytearray()
    for row in relocations:
        rela.extend(struct.pack("<QQq", row["offset"],
                                (symbol_indexes[row["symbol"]] << 32) | 4, -4))
    section_names = ("", ".text", ".rela.text", ".symtab", ".strtab", ".shstrtab", ".note.GNU-stack")
    shstrtab = bytearray(b"\0")
    section_name_offsets = {"": 0}
    for name in section_names[1:]:
        section_name_offsets[name] = len(shstrtab)
        shstrtab.extend(name.encode("ascii") + b"\0")
    # name, type, flags, alignment, entry size, link, info, bytes
    sections = [
        (".text", 1, 6, text_alignment, 0, 0, 0, code),
        (".rela.text", 4, 0, 8, 24, 3, 1, bytes(rela)),
        (".symtab", 2, 0, 8, 24, 4, first_global, bytes(symtab)),
        (".strtab", 3, 0, 1, 0, 0, 0, bytes(string_table)),
        (".shstrtab", 3, 0, 1, 0, 0, 0, bytes(shstrtab)),
        (".note.GNU-stack", 1, 0, 1, 0, 0, 0, b""),
    ]
    image = bytearray(b"\0" * 64)
    headers = [b"\0" * 64]
    for name, typ, flags, alignment, entsize, link, info, content in sections:
        image.extend(b"\0" * (-len(image) % alignment))
        offset = len(image)
        image.extend(content)
        headers.append(struct.pack("<IIQQQQIIQQ", section_name_offsets[name], typ, flags,
                                   0, offset, len(content), link, info, alignment, entsize))
    image.extend(b"\0" * (-len(image) % 8))
    shoff = len(image)
    image.extend(b"".join(headers))
    if len(image) > MAX_OBJECT_BYTES:
        raise MachineObjectError("ELF object exceeds byte budget")
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\0" * 8
    image[:64] = struct.pack("<16sHHIQQQIHHHHHH", ident, 1, 62, 1, 0, 0,
                             shoff, 0, 64, 0, 0, 64, len(headers), 5)
    return bytes(image)
