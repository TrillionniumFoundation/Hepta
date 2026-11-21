"""Author the HIA plan for mapping one immutable, directly linked ELF64 image.

This covers the two reviewed HIA link layouts, not a general dynamic loader.
No callbacks are selected by ELF pointers or ELF-supplied addresses.
"""
import ast
from pathlib import Path
from tempfile import TemporaryDirectory

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_elf_linker import LinkerBuilder
from tools.generate_hia_selfhost import compact_authoring_cfg, total_scalar_functions

ROOT = Path(__file__).resolve().parents[1]
SOURCE_PATH = 'examples/hia_bootstrap/direct_load_plan.hepta'
PACKER_PATH = 'examples/hia_bootstrap/direct_call_packer.hepta'
ADAPTER_PATH = 'tools/hia_direct_call_syscalls.S'
PACKER_MAGIC = int.from_bytes(b'HIADPK01', 'little')
CALL_SYMBOLS = {'plan': 'direct_plan_call_hole'}
IMPORTS = ('abort', 'calloc', 'free', 'malloc', 'memcpy', 'memmove', 'memset')

SOURCE = '''
def plan(s:readbuf, o:mutbuf, request:mutbuf) -> u32:
    extent = length(s)
    name_length = length(request)
    if extent < 4096 or extent > 67108864 or name_length == 0 or name_length > 512:
        return 4294967295
    if length(o) < 88:
        return 4294967294
    if read(s, 0, 8) != 0x10102464c457f or read(s, 8, 8) != 0:
        return 4294967295
    if read(s, 16, 8) != 0x1003e0003 or read(s, 24, 8) != 0 or read(s, 32, 8) != 64:
        return 4294967295
    if read(s, 48, 8) != 0x38004000000000:
        return 4294967295
    shape = read(s, 56, 8)
    if shape == 0xf001000400006:
        return plan_single_abort(s, o, request)
    if shape != 0xa000b00400006:
        return 4294967295
    text = read(s, 144, 8)
    code_bytes = read(s, 152, 8)
    metadata_bytes = read(s, 96, 8)
    got_page = read(s, 192, 8)
    got_bytes = read(s, 208, 8)
    dynamic_bytes = read(s, 264, 8)
    if text < 4096 or text % 4096 != 0 or metadata_bytes != text or code_bytes == 0:
        return 4294967295
    if inside(extent, text, code_bytes) == 0:
        return 4294967295
    if got_page != ((text + code_bytes + 4095) & 18446744073709547520):
        return 4294967295
    if got_bytes > 4096 or (dynamic_bytes != 128 and dynamic_bytes != 192):
        return 4294967295
    if inside(extent, got_page, 4096) == 0 or got_bytes < dynamic_bytes:
        return 4294967295
    sections = read(s, 40, 8)
    if sections < got_page + 4096 or inside(extent, sections, 704) == 0 or extent - sections != 704:
        return 4294967295
    program_bytes = check_segments(s, sections, text, code_bytes, got_page, got_bytes, dynamic_bytes)
    if program_bytes == 0:
        return 4294967295
    count = dynamic_symbol_count(s, got_page, text)
    if count == 0:
        return 4294967295
    imports = checked_imports(s, got_page, got_bytes, dynamic_bytes, text, count)
    if imports > 7:
        return 4294967295
    return publish_plan(s, o, request, text, code_bytes, got_page, dynamic_bytes, program_bytes, count, imports)

def plan_single_abort(s:readbuf, o:mutbuf, request:mutbuf) -> u32:
    extent = length(s)
    code = read(s, 152, 8)
    if code <= 32 or code > 65568 or inside(extent, 4096, code) == 0:
        return 4294967295
    rw = (4096 + code + 4095) & 18446744073709547520
    sections = read(s, 40, 8)
    if inside(extent, rw, 4096) == 0 or sections < rw + 4096 or inside(extent, sections, 1024) == 0:
        return 4294967295
    if extent - sections != 1024 or (sections & 7) != 0:
        return 4294967295
    if abort_segments(s, code, rw) == 0:
        return 4294967295
    symbols = abort_tables(s, sections, code, rw)
    if symbols == 0 or abort_plt(s, rw) == 0:
        return 4294967295
    strings = read(s, rw + 104, 8)
    symbol = symbols + 48
    name = read(s, symbol, 4)
    address = read(s, symbol + 8, 8)
    size = read(s, symbol + 16, 8)
    if read(s, symbol + 4, 4) != 589842 or name == 0 or name >= strings - 22:
        return 4294967295
    if address < 4128 or size == 0 or inside(4096 + code, address, size) == 0:
        return 4294967295
    if address + size != 4096 + code or equal_name(s, 400 + name, strings - 22 - name, request) == 0:
        return 4294967295
    plan_header(o, 4096, code, rw, address)
    # Runtime slot 1 is the local, nonreturning abort. The adapter never
    # reads callback addresses from the file and never maps its dynamic table.
    save(o, 32, rw + 312, 8)
    return 88

def abort_segments(s:readbuf, code:u64, rw:u64) -> u64:
    if segment(s, 64, 0x400000001, 0, 4096, 4096, 4096) == 0:
        return 0
    if segment(s, 120, 0x500000001, 4096, code, code, 4096) == 0:
        return 0
    if segment(s, 176, 0x600000001, rw, 4096, 4096, 4096) == 0:
        return 0
    if segment(s, 232, 0x600000002, rw, 272, 272, 8) == 0:
        return 0
    if segment(s, 288, 0x66474e551, 0, 0, 0, 16) == 0:
        return 0
    return segment(s, 344, 0x46474e552, rw, 4096, 4096, 1)

def matching_section(s:readbuf, row:u64, kind:u64, flags:u64, address:u64, size:u64) -> u64:
    if read(s, row + 4, 4) != kind or read(s, row + 8, 8) != flags:
        return 0
    if read(s, row + 16, 8) != address or read(s, row + 24, 8) != address:
        return 0
    if read(s, row + 32, 8) != size:
        return 0
    return 1

def abort_tables(s:readbuf, sections:u64, code:u64, rw:u64) -> u64:
    strings = read(s, rw + 104, 8)
    if strings < 29 or strings > 534:
        return 0
    symbols = (400 + strings + 7) & 18446744073709551608
    sysv = symbols + 72
    gnu = sysv + 24
    vers = gnu + 32
    need = (vers + 6 + 7) & 18446744073709551608
    rela = need + 32
    if matching_section(s, sections + 192, 11, 2, symbols, 72) == 0:
        return 0
    if matching_section(s, sections + 256, 3, 2, 400, strings) == 0:
        return 0
    if matching_section(s, sections + 448, 4, 66, rela, 24) == 0:
        return 0
    if matching_section(s, sections + 512, 1, 6, 4096, 32) == 0:
        return 0
    if matching_section(s, sections + 576, 1, 6, 4128, code - 32) == 0:
        return 0
    if matching_section(s, sections + 704, 6, 3, rw, 272) == 0:
        return 0
    if matching_section(s, sections + 768, 1, 3, rw + 288, 32) == 0:
        return 0
    if read(s, 400, 1) != 0 or read(s, 400 + strings - 23, 1) != 0:
        return 0
    if read(s, symbols, 8) != 0 or read(s, symbols + 8, 8) != 0 or read(s, symbols + 16, 8) != 0:
        return 0
    name = read(s, symbols + 24, 4)
    if name == 0 or name >= strings - 22 or import_id(s, 400 + name, strings - 22 - name) != 1:
        return 0
    if read(s, symbols + 28, 4) != 18 or read(s, symbols + 32, 8) != 0 or read(s, symbols + 40, 8) != 0:
        return 0
    if read(s, rela, 8) != rw + 312 or read(s, rela + 8, 8) != 4294967303 or read(s, rela + 16, 8) != 0:
        return 0
    if abort_dynamic(s, rw, strings, symbols, sysv, gnu, vers, need, rela) == 0:
        return 0
    return symbols

def exact_tag(s:readbuf, offset:u64, tag:u64, value:u64) -> u64:
    if read(s, offset, 8) == tag and read(s, offset + 8, 8) == value:
        return 1
    return 0

def abort_dynamic(s:readbuf, rw:u64, strings:u64, symbols:u64, sysv:u64, gnu:u64, vers:u64, need:u64, rela:u64) -> u64:
    library = 400 + strings - 22
    if read(s, library, 8) != @LIBC@ or read(s, library + 8, 2) != 54:
        return 0
    if read(s, library + 10, 8) != 3328827817059765319 or read(s, library + 18, 4) != 3485234:
        return 0
    if exact_tag(s, rw, 1, strings - 22) == 0 or exact_tag(s, rw + 16, 2, 24) == 0:
        return 0
    if exact_tag(s, rw + 32, 3, rw + 288) == 0 or exact_tag(s, rw + 48, 4, sysv) == 0:
        return 0
    if exact_tag(s, rw + 64, 5, 400) == 0 or exact_tag(s, rw + 80, 6, symbols) == 0:
        return 0
    if exact_tag(s, rw + 96, 10, strings) == 0 or exact_tag(s, rw + 112, 11, 24) == 0:
        return 0
    if exact_tag(s, rw + 128, 20, 7) == 0 or exact_tag(s, rw + 144, 23, rela) == 0:
        return 0
    if exact_tag(s, rw + 160, 30, 8) == 0 or exact_tag(s, rw + 176, 0x6ffffef5, gnu) == 0:
        return 0
    if exact_tag(s, rw + 192, 0x6ffffffb, 1) == 0 or exact_tag(s, rw + 208, 0x6ffffffe, need) == 0:
        return 0
    if exact_tag(s, rw + 224, 0x6fffffff, 1) == 0 or exact_tag(s, rw + 240, 0x6ffffff0, vers) == 0:
        return 0
    if exact_tag(s, rw + 256, 0, 0) == 0:
        return 0
    return 1

def abort_plt(s:readbuf, rw:u64) -> u64:
    got = rw + 288
    if read(s, got, 8) != rw or read(s, got + 8, 8) != 0 or read(s, got + 16, 8) != 0 or read(s, got + 24, 8) != 4118:
        return 0
    if read(s, 4096, 2) != 13823 or read(s, 4098, 4) != got + 8 - 4102:
        return 0
    if read(s, 4102, 2) != 9727 or read(s, 4104, 4) != got + 16 - 4108:
        return 0
    if read(s, 4108, 4) != 4202255 or read(s, 4112, 2) != 9727 or read(s, 4114, 4) != got + 24 - 4118:
        return 0
    if read(s, 4118, 5) != 104 or read(s, 4123, 1) != 233 or read(s, 4124, 4) != 4294967264:
        return 0
    return 1

def dynamic_symbol_count(s:readbuf, got_page:u64, text:u64) -> u64:
    first = read(s, got_page + 8, 8)
    symbols = read(s, got_page + 24, 8)
    strings = read(s, got_page + 40, 8)
    sysv_hash = read(s, got_page + 72, 8)
    gnu_hash = read(s, got_page + 88, 8)
    if inside(text, first, strings) == 0 or first != 400 or strings == 0:
        return 0
    if symbols != ((first + strings + 7) & 18446744073709551608) or symbols >= sysv_hash:
        return 0
    if (sysv_hash - symbols) % 24 != 0 or inside(text, sysv_hash, 12) == 0:
        return 0
    count = (sysv_hash - symbols) // 24
    if count > 65536 or read(s, sysv_hash + 4, 4) != count:
        return 0
    if inside(text, gnu_hash, 28) == 0 or gnu_hash < sysv_hash + 12 + count * 4:
        return 0
    if read(s, first, 1) != 0 or read(s, first + strings - 1, 1) != 0:
        return 0
    if read(s, symbols, 8) != 0 or read(s, symbols + 8, 8) != 0 or read(s, symbols + 16, 8) != 0:
        return 0
    if read(s, got_page, 8) != 5 or read(s, got_page + 16, 8) != 6:
        return 0
    if read(s, got_page + 32, 8) != 10 or read(s, got_page + 48, 8) != 11 or read(s, got_page + 56, 8) != 24:
        return 0
    if read(s, got_page + 64, 8) != 4 or read(s, got_page + 80, 8) != 0x6ffffef5:
        return 0
    if read(s, got_page + 96, 8) != 30 or read(s, got_page + 104, 8) != 8:
        return 0
    return count

def checked_imports(s:readbuf, got_page:u64, got_bytes:u64, dynamic_bytes:u64, text:u64, count:u64) -> u64:
    first = read(s, got_page + 8, 8)
    symbols = read(s, got_page + 24, 8)
    strings = read(s, got_page + 40, 8)
    gnu_hash = read(s, got_page + 88, 8)
    imports = 0
    relocations = 0
    if dynamic_bytes == 192:
        relocations = read(s, got_page + 136, 8)
        rel_bytes = read(s, got_page + 152, 8)
        if read(s, got_page + 112, 8) != 1 or read(s, got_page + 128, 8) != 7:
            return 4294967295
        if read(s, got_page + 144, 8) != 8 or read(s, got_page + 160, 8) != 9 or read(s, got_page + 168, 8) != 24:
            return 4294967295
        if rel_bytes == 0 or rel_bytes > 168 or rel_bytes % 24 != 0:
            return 4294967295
        if relocations < gnu_hash + 28 or inside(text, relocations, rel_bytes) == 0:
            return 4294967295
        library = read(s, got_page + 120, 8)
        if library >= strings or strings - library != 10:
            return 4294967295
        if read(s, first + library, 8) != @LIBC@ or read(s, first + library + 8, 2) != 54:
            return 4294967295
        imports = rel_bytes // 24
    if read(s, got_page + dynamic_bytes - 16, 8) != 0 or read(s, got_page + dynamic_bytes - 8, 8) != 0:
        return 4294967295
    if got_bytes != dynamic_bytes + imports * 8 or count <= imports + 1:
        return 4294967295
    if validate_imports(s, got_page + dynamic_bytes, relocations, imports, first, strings, symbols) == 0:
        return 4294967295
    return imports

def publish_plan(s:readbuf, o:mutbuf, request:mutbuf, text:u64, code_bytes:u64, got_page:u64, dynamic_bytes:u64, program_bytes:u64, count:u64, imports:u64) -> u32:
    first = read(s, got_page + 8, 8)
    symbols = read(s, got_page + 24, 8)
    strings = read(s, got_page + 40, 8)
    entry = find_entry(s, request, first, strings, symbols, imports + 1, count, text, program_bytes)
    if entry == 0:
        return 4294967295
    plan_header(o, text, code_bytes, got_page, entry)
    slot = 0
    while slot < imports:
        symbol = symbols + (slot + 1) * 24
        word = read(s, symbol, 4)
        id = import_id(s, first + word, strings - word)
        save(o, 24 + id * 8, got_page + dynamic_bytes + slot * 8, 8)
        slot = slot + 1
    return 88

def plan_header(o:mutbuf, text:u64, code_bytes:u64, got_page:u64, entry:u64) -> u64:
    save(o, 0, text, 8)
    save(o, 8, code_bytes, 8)
    save(o, 16, got_page, 8)
    save(o, 24, entry, 8)
    slot = 0
    while slot < 7:
        save(o, 32 + slot * 8, 0, 8)
        slot = slot + 1
    return 0

def check_segments(s:readbuf, sections:u64, text:u64, code_bytes:u64, got_page:u64, got_bytes:u64, dynamic_bytes:u64) -> u64:
    text_section = sections + 64
    program_bytes = read(s, text_section + 32, 8)
    if read(s, text_section + 4, 4) != 1 or read(s, text_section + 8, 8) != 6:
        return 0
    if read(s, text_section + 16, 8) != text or read(s, text_section + 24, 8) != text:
        return 0
    if program_bytes == 0 or program_bytes > code_bytes:
        return 0
    if segment(s, 64, 0x400000001, 0, text, text, 4096) == 0:
        return 0
    if segment(s, 120, 0x500000001, text, code_bytes, code_bytes, 4096) == 0:
        return 0
    if segment(s, 176, 0x600000001, got_page, got_bytes, 4096, 4096) == 0:
        return 0
    if segment(s, 232, 0x600000002, got_page, dynamic_bytes, dynamic_bytes, 8) == 0:
        return 0
    if segment(s, 288, 0x66474e551, 0, 0, 0, 16) == 0:
        return 0
    if segment(s, 344, 0x46474e552, got_page, got_bytes, 4096, 1) == 0:
        return 0
    return program_bytes

def validate_imports(s:readbuf, got:u64, rel:u64, count:u64, first:u64, strings:u64, symbols:u64) -> u64:
    slot = 0
    used = 0
    while slot < count:
        sym = symbols + (slot + 1) * 24
        name = read(s, sym, 4)
        if name == 0 or name >= strings or read(s, sym + 4, 4) != 16:
            return 0
        if read(s, sym + 8, 8) != 0 or read(s, sym + 16, 8) != 0:
            return 0
        id = import_id(s, first + name, strings - name)
        if id == 0 or (used & (1 << id)) != 0:
            return 0
        used = used | (1 << id)
        base = rel + slot * 24
        address = got + slot * 8
        if read(s, base, 8) != address or read(s, base + 8, 8) != (slot + 1) * 4294967296 + 6:
            return 0
        if read(s, base + 16, 8) != 0 or read(s, address, 8) != 0:
            return 0
        slot = slot + 1
    return 1

def find_entry(s:readbuf, request:mutbuf, strings:u64, string_bytes:u64, symbols:u64, index:u64, count:u64, text:u64, code_bytes:u64) -> u64:
    entry = 0
    while index < count:
        symbol = symbols + index * 24
        name = read(s, symbol, 4)
        address = read(s, symbol + 8, 8)
        size = read(s, symbol + 16, 8)
        if name == 0 or name >= string_bytes or read(s, symbol + 4, 4) != 65554:
            return 0
        if address < text or size == 0 or inside(code_bytes, address - text, size) == 0:
            return 0
        if equal_name(s, strings + name, string_bytes - name, request) == 1:
            if entry != 0:
                return 0
            entry = address
        index = index + 1
    return entry

def equal_name(s:readbuf, first:u64, available:u64, request:mutbuf) -> u64:
    size = length(request)
    if available <= size or read(s, first + size, 1) != 0:
        return 0
    index = 0
    while index < size:
        actual = read(s, first + index, 1)
        requested = byte(request, index)
        if actual == 0 or actual != requested:
            return 0
        index = index + 1
    return 1

def import_id(s:readbuf, start:u64, available:u64) -> u64:
@IMPORTS@
    return 0

def segment(s:readbuf, start:u64, kind:u64, offset:u64, file_bytes:u64, memory_bytes:u64, alignment:u64) -> u64:
    if read(s, start, 8) != kind or read(s, start + 8, 8) != offset:
        return 0
    if read(s, start + 16, 8) != offset or read(s, start + 24, 8) != offset:
        return 0
    if read(s, start + 32, 8) != file_bytes or read(s, start + 40, 8) != memory_bytes:
        return 0
    if read(s, start + 48, 8) != alignment:
        return 0
    return 1

def inside(extent:u64, offset:u64, size:u64) -> u64:
    if offset > extent or size > extent - offset:
        return 0
    return 1

def read(s:readbuf, at:u64, size:u64) -> u64:
    i = 0
    value = 0
    while i < size:
        byte = byte(s, at + i)
        value = value | (byte << (8 * i))
        i = i + 1
    return value

def save(o:mutbuf, at:u64, value:u64, size:u64) -> u64:
    i = 0
    while i < size:
        store(o, at + i, (value >> (8 * i)) & 255)
        i = i + 1
    return 0
'''


def document():
    imports = []
    for number, name in enumerate(IMPORTS, 1):
        raw = name.encode('ascii') + b'\0'
        imports.append(f'    if available >= {len(raw)} and read(s, start, {len(raw)}) == {int.from_bytes(raw, "little")}:'
                       f'\n        return {number}')
    source = SOURCE.replace('@IMPORTS@', '\n'.join(imports)).replace(
        '@LIBC@', str(int.from_bytes(b'libc.so.', 'little')))
    nodes = ast.parse(source).body
    names = {node.name: 'f' + str(i) for i, node in enumerate(nodes)}
    signatures = {node.name: ([arg.annotation.id for arg in node.args.args], node.returns.id) for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = LinkerBuilder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(arg) for arg in builder.params],
                          'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
                          'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8', 'module': 'direct_load_plan',
                                  'functions': functions})


def cli_document():
    from tools.build_hia_agent_batch_commit import adapter_layout
    from tools.generate_hia_native_filter import bind_adapter, document as packer_document, elf_header

    source = (ROOT / ADAPTER_PATH).read_bytes()
    with TemporaryDirectory(prefix='hia-direct-call-adapter-') as directory:
        adapter, holes, _ = adapter_layout(Path(directory), ADAPTER_PATH, source, CALL_SYMBOLS)
    header = elf_header()
    hole = holes['plan']
    packer = packer_document(magic=PACKER_MAGIC, module='direct_call_packer',
                             image_template=(header + adapter, (len(header) + hole,)))
    return bind_adapter(packer, source, adapter, (hole,))


if __name__ == '__main__':
    (ROOT / SOURCE_PATH).write_text(render_assembly(document()))
    (ROOT / PACKER_PATH).write_text(render_assembly(cli_document()))
