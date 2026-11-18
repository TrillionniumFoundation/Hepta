"""Author the HIA discovery router and its eight canonical opcode catalog recipes."""
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_agent_store import wire
from hepta.hia_opcodes import opcode_catalog
from hepta.hia_schema import LATEST_CORE_SCHEMA, PRIMITIVE_PROFILES, schema_registry
from tools.generate_hia_agent_stdio import catalog_source, document, pack_catalog_recipes, writes
from tools.generate_hia_core_json_cli import source_program as core_cli_source

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'examples/hia_bootstrap/agent_discovery.hepta'
HEADER_BYTES = 32
MAGIC = int.from_bytes(b'HIADIS01', 'little')
REGISTRY_MAGIC = int.from_bytes(b'HIADISRG', 'little')

# Stable resource-role IDs in the discovery ABI; the Store binds them to issued refs.
ROUTES = {
    'manifest': (0,),
    'language': (1, 2, 3, 4),
    'backend': (5, 6, 7, 8, 9, 10, 11, 12, 13, 14),
    'examples': (15,),
    'diagnostics': (16,),
    'plans': (17, 18, 19, 20, 21),
}

ENTRY = """
def discover(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 8 or length(o) < 32 or length(w) < TABLE_SIZE:
        return 4294967293
    tag = read_word(s, 0)
    if length(s) == 8 and tag == REGISTRY_MAGIC:
        return render_recipe(o, w, REGISTRY_RECIPE, 0)
    if length(s) < 48 or tag != FRAME_MAGIC:
        return 4294967293
    flags = read_word(s, 8)
    section_size = read_word(s, 16)
    requested_size = read_word(s, 24)
    installed_size = read_word(s, 32)
    schema_size = read_word(s, 40)
    if flags > 7 or section_size > 11 or requested_size > 768 or installed_size > 768 or schema_size > 512:
        return 4294967293
    if 48 + section_size + requested_size + installed_size + schema_size != length(s):
        return 4294967293
    if (flags & 1) != 0:
        return 4294967288
    requested = 48 + section_size
    installed = requested + requested_size
    if (flags & 2) != 0 and same_backend(s, requested, installed, requested_size, installed_size) == 0:
        return 4294967289
    version = DEFAULT_VERSION
    if (flags & 4) != 0:
        version = schema_version(s, installed + installed_size)
        if version == 0:
            return 4294967290
    route = lookup_route(s, section_size)
    if route == 0:
        return 4294967293
    return render_recipe(o, w, version, route)

def render_recipe(o:mutbuf, w:mutbuf, version:u64, route:u64) -> u64:
    seed(w)
    if unpack_table(w) == 0:
        return 4294967293
    size = catalog(w, o, version)
    if size >= 4294967294:
        return size
    put_word(o, 0, version)
    put_word(o, 8, route & 15)
    put_word(o, 16, route >> 4)
    put_word(o, 24, size)
    return size + 32

def unpack_table(w:mutbuf) -> u64:
    source = PACK_START
    target = 0
    while source < PACK_END:
        tag = byte(w, source)
        source = source + 1
        if tag < 128:
            count = tag + 1
            if count > PACK_END - source or count > PACK_START - target:
                return 0
            copy_from = source
            source = source + count
        else:
            count = (tag & 127) + 3
            if PACK_END - source < 2 or count > PACK_START - target:
                return 0
            distance = byte(w, source) | (byte(w, source + 1) << 8)
            source = source + 2
            if distance == 0 or distance > target:
                return 0
            copy_from = target - distance
        index = 0
        while index < count:
            store(w, target + index, byte(w, copy_from + index))
            index = index + 1
        target = target + count
    return choose(target == PACK_START, 1, 0)

def same_backend(s:readbuf, left:u64, right:u64, n:u64, m:u64) -> u64:
    if n != m:
        return 0
    index = 0
    while index < n:
        if byte(s, left + index) != byte(s, right + index):
            return 0
        index = index + 1
    return 1
"""


def canonical_parts(value):
    """Keep shared opcode rows discrete while exactly preserving canonical wire."""
    yield b'{'
    for index, (key, field) in enumerate(sorted(value.items())):
        prefix = (b',' if index else b'') + wire(key) + b':'
        if key == 'instruction_catalog':
            yield prefix
            yield from canonical_parts(field)
        elif key == 'instructions':
            yield prefix + b'['
            for row_index, row in enumerate(field):
                yield (b',' if row_index else b'') + wire(row)
            yield b']'
        else:
            yield prefix + wire(field)
    yield b'}'


def routes_source():
    lines = ['def lookup_route(s:readbuf, size:u64) -> u64:', '    route = 0']
    for token, roles in ROUTES.items():
        raw = token.encode('ascii')
        assert len(roles) < 16 and all(0 <= role < 32 for role in roles)
        encoded = len(roles) | sum(role << (4 + index * 5) for index, role in enumerate(roles))
        conditions = ' and '.join(f'byte(s, {48 + i}) == {unit}' for i, unit in enumerate(raw))
        lines.extend((f'    if size == {len(raw)}:', f'        if {conditions}:', f'            route = {encoded}'))
    return '\n'.join((*lines, '    return route', ''))


def pack_seed(data):
    """Encode literals and overlapping u16-distance copies for the HIA loader."""
    packed = bytearray()
    literals = bytearray()
    seen = {}

    def flush_literals():
        if literals:
            packed.append(len(literals) - 1)
            packed.extend(literals)
            literals.clear()

    index = 0
    while index < len(data):
        key = data[index:index + 3]
        before = seen.get(key, -1)
        # A copy costs three bytes. Short matches can remain in a literal run.
        width = 0
        if len(key) == 3 and 0 <= before < index and index - before <= 65535:
            limit = min(130, len(data) - index)
            while width < limit and data[before + width] == data[index + width]:
                width += 1
        if width >= 4:
            flush_literals()
            packed.append(128 | (width - 3))
            packed.extend((index - before).to_bytes(2, 'little'))
        else:
            literals.append(data[index])
            width = 1
            if len(literals) == 128:
                flush_literals()
        for position in range(index, index + width):
            seen[data[position:position + 3]] = position
        index += width
    flush_literals()
    return bytes(packed)


def seed_source(table, *, offset):
    """Seed a private table with bounded straight-line chunks."""
    names, chunks = [], []
    for start in range(0, len(table), 512):
        name = f'seed_{start // 512}'
        names.append(name)
        body = writes(table[start:start + 512], offset=offset + start)
        chunks.append(f'def {name}(o:mutbuf) -> u64:\n{body}    return 0\n')
    return 'def seed(o:mutbuf) -> u64:\n' + ''.join(f'    {name}(o)\n' for name in names) + '    return 0\n\n' + '\n'.join(chunks)


def source_program():
    catalogs = [opcode_catalog(schema) for schema in PRIMITIVE_PROFILES]
    documents = [*catalogs, schema_registry()]
    table = pack_catalog_recipes(canonical_parts(value) for value in documents)
    seed = pack_seed(table)
    total = len(table) + len(seed)
    assert total <= 65536
    source = (ENTRY.replace('FRAME_MAGIC', str(MAGIC)).replace('TABLE_SIZE', str(total))
              .replace('PACK_START', str(len(table))).replace('PACK_END', str(total))
              .replace('REGISTRY_MAGIC', str(REGISTRY_MAGIC)).replace('REGISTRY_RECIPE', str(len(documents)))
              .replace('DEFAULT_VERSION', str(tuple(PRIMITIVE_PROFILES).index(LATEST_CORE_SCHEMA) + 1)))
    catalog = (catalog_source(recipes=len(documents))
        .replace('def catalog(s:readbuf, o:mutbuf, version:u64) -> u32:',
                 'def catalog(s:mutbuf, o:mutbuf, version:u64) -> u64:')
        .replace('def catalog_u32(s:readbuf', 'def catalog_u32(s:mutbuf')
        .replace('    if size > length(o):', f'    if length(o) < {HEADER_BYTES} or size > length(o) - {HEADER_BYTES}:')
        .replace('store(o, out + j,', f'store(o, {HEADER_BYTES} + out + j,'))
    word_source = core_cli_source()
    words = word_source[word_source.index('\ndef read_word('):word_source.index('\ndef put_four(')]
    return '\n'.join((source, routes_source(), catalog, seed_source(seed, offset=len(table)), words))


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(source_program(), 'agent_discovery')))
