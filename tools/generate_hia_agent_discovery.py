"""Author the HIA discovery router and its eight canonical opcode catalog recipes."""
from pathlib import Path
import re

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_agent_describe_answer_native import (
    BASE_FIELDS, MAGIC as ANSWER_MAGIC, REFERENCE_COUNT, SOURCE_NAME as ANSWER_SOURCE,
)
from hepta.hia_agent_discovery_native import (
    DISCOVERY_RESOURCE_NAMES, MACRO_PROFILE_ROLE, PROFILE_NAMES, WORKSPACE_BYTES,
)
from hepta.hia_agent_macro_discovery import macro_policy_guidance
from hepta.hia_agent_service import HIAAgentService, _manifest_document, _profile_documents
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
PROFILE_MAGIC = int.from_bytes(b'HIADISPF', 'little')
RESOURCE_MAGIC = int.from_bytes(b'HIADISRS', 'little')

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
    if tag == PROFILE_MAGIC:
        return render_profile(s, o, w)
    if tag == RESOURCE_MAGIC:
        if length(s) != 16:
            return 4294967293
        role = read_word(s, 8)
        if role == 0 or role > RESOURCE_COUNT:
            return 4294967293
        return render_recipe(o, w, REGISTRY_RECIPE + PROFILE_COUNT + role, 0)
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

def render_profile(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    if length(s) < 72:
        return 4294967293
    role = read_word(s, 8)
    if role == 0 or role > PROFILE_COUNT:
        return 4294967293
    offset = 16
    extent = 72
    while offset < 72:
        count = read_word(s, offset)
        if count > length(s) - extent:
            return 4294967293
        extent = extent + count
        offset = offset + 8
    if extent != length(s):
        return 4294967293
    seed(w)
    if unpack_table(w) == 0:
        return 4294967293
    version = REGISTRY_RECIPE + role
    recipe = PROFILE_HEADER + catalog_u32(w, 4 + (version - 1) * 12)
    start = catalog_u32(w, 0) + catalog_u32(w, recipe)
    end = start + catalog_u32(w, recipe + 4)
    if end > PACK_START:
        return 4294967293
    out = 32
    while start < end:
        unit = byte(w, start)
        start = start + 1
        if unit != 0:
            if out >= length(o):
                return 4294967294
            store(o, out, unit)
            out = out + 1
        else:
            if start == end:
                return 4294967293
            marker = byte(w, start)
            start = start + 1
            if marker < 1 or marker > 7:
                return 4294967293
            offset = 16
            at = 72
            while marker > 1:
                at = at + read_word(s, offset)
                offset = offset + 8
                marker = marker - 1
            count = read_word(s, offset)
            if count == 0:
                return 4294967293
            if count > length(o) - out:
                return 4294967294
            i = 0
            while i < count:
                store(o, out + i, byte(s, at + i))
                i = i + 1
            out = out + count
    put_word(o, 0, version)
    put_word(o, 8, 0)
    put_word(o, 16, 0)
    put_word(o, 24, out - 32)
    return out

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


def pack_seed(data, *, history=1):
    """Encode literals and overlapping u16-distance copies for the HIA loader."""
    packed = bytearray()
    literals = bytearray()
    seen = {}
    links = {}

    def flush_literals():
        if literals:
            packed.append(len(literals) - 1)
            packed.extend(literals)
            literals.clear()

    index = 0
    while index < len(data):
        key = data[index:index + 3]
        candidate = seen.get(key, -1)
        before = candidate
        # A copy costs three bytes. Short matches can remain in a literal run.
        width = 0
        limit = min(130, len(data) - index)
        if len(key) == 3:
            for _ in range(history):
                if candidate < 0 or index - candidate > 65535:
                    break
                extent = 3
                while extent < limit and data[candidate + extent] == data[index + extent]:
                    extent += 1
                if extent > width:
                    before, width = candidate, extent
                    if width == limit:
                        break
                candidate = links.get(candidate, -1)
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
            block = data[position:position + 3]
            if history > 1 and block in seen:
                links[position] = seen[block]
            seen[block] = position
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


def profile_templates():
    """Encode literal canonical JSON plus variable-width installation fields."""
    identity = {'__hia_profile_identity__': True}
    catalog = 'c' * 64
    root_count = (1 << 64) - 1
    roots = 'd' * 64
    profiles = {'__hia_profile_refs__': True}
    artifacts = {'__hia_profile_manifests__': True}
    resources = {'__hia_resource_refs__': True}
    fields = (wire(identity), catalog.encode('ascii'), wire(root_count), roots.encode('ascii'),
              wire(profiles), wire(artifacts), wire(resources))
    sentinel = {field: bytes((0, marker)) for marker, field in enumerate(fields, 1)}
    expected = {'compiler': (1, 2), 'target': (), 'backend': (1, 2), 'artifact': (3, 4),
                'validation': (1, 2), 'lowering': (1, 2), 'plan': (1, 2),
                'manifest': (1, 2, 5, 6, 7), 'macro_policy': (1, 1)}
    documents = _profile_documents(identity, catalog, root_count, roots)
    assert tuple(documents) == PROFILE_NAMES
    documents['manifest'] = _manifest_document(identity, catalog, profiles, artifacts, resources)
    documents['macro_policy'] = macro_policy_guidance(identity)
    pattern = re.compile(b'|'.join(re.escape(key) for key in sentinel))
    for name, document in documents.items():
        raw = wire(document)
        matches = tuple(sorted(sentinel[key][1] for key in pattern.findall(raw)))
        assert matches == expected[name]
        yield (pattern.sub(lambda match: sentinel[match[0]], raw),)


def source_program():
    catalogs = [opcode_catalog(schema) for schema in PRIMITIVE_PROFILES]
    documents = [*catalogs, schema_registry()]
    resource_documents = HIAAgentService._reference_resource_documents()
    assert tuple(resource_documents) == DISCOVERY_RESOURCE_NAMES
    profile_count = MACRO_PROFILE_ROLE
    resource_count = len(resource_documents)
    recipe_count = len(documents) + profile_count + resource_count
    recipes = [*(canonical_parts(value) for value in documents), *profile_templates(),
               *(canonical_parts(value) for value in resource_documents.values())]
    table = pack_catalog_recipes(recipes)
    seed = pack_seed(table)
    total = len(table) + len(seed)
    if total > WORKSPACE_BYTES:
        raise ValueError('Agent discovery recipes exceed the private workspace')
    source = (ENTRY.replace('FRAME_MAGIC', str(MAGIC)).replace('TABLE_SIZE', str(total))
              .replace('PACK_START', str(len(table))).replace('PACK_END', str(total))
              .replace('REGISTRY_MAGIC', str(REGISTRY_MAGIC)).replace('REGISTRY_RECIPE', str(len(documents)))
              .replace('PROFILE_MAGIC', str(PROFILE_MAGIC)).replace('PROFILE_COUNT', str(profile_count))
              .replace('RESOURCE_MAGIC', str(RESOURCE_MAGIC)).replace('RESOURCE_COUNT', str(resource_count))
              .replace('PROFILE_HEADER', str(4 + 12 * recipe_count))
              .replace('DEFAULT_VERSION', str(tuple(PRIMITIVE_PROFILES).index(LATEST_CORE_SCHEMA) + 1)))
    catalog = (catalog_source(recipes=recipe_count)
        .replace('def catalog(s:readbuf, o:mutbuf, version:u64) -> u32:',
                 'def catalog(s:mutbuf, o:mutbuf, version:u64) -> u64:')
        .replace('def catalog_u32(s:readbuf', 'def catalog_u32(s:mutbuf')
        .replace('    if size > length(o):', f'    if length(o) < {HEADER_BYTES} or size > length(o) - {HEADER_BYTES}:')
        .replace('store(o, out + j,', f'store(o, {HEADER_BYTES} + out + j,'))
    word_source = core_cli_source()
    words = word_source[word_source.index('\ndef read_word('):word_source.index('\ndef put_four(')]
    return '\n'.join((source, routes_source(), catalog, seed_source(seed, offset=len(table)), words))


def answer_source():
    prefixes = (b'{"artifact_profiles":[', b'],"backend_profiles":[', b'],"catalog_sha256":',
                b',"language_catalogs":[', b'],"manifest":', b',"next_cursor":null,"resources":[')
    suffix = b']}'
    fields = BASE_FIELDS + REFERENCE_COUNT
    head = 16 + 8 * fields
    fixed = sum(map(len, prefixes)) + len(suffix)
    routes = [len(roles) | sum(role << (4 + index * 5) for index, role in enumerate(roles))
              for roles in ROUTES.values()]
    unknown_route = ' and '.join(f'route != {route}' for route in routes)
    source = f'''
def describe_answer(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < {head} or read_word(s, 0) != {int.from_bytes(ANSWER_MAGIC, 'little')}:
        return 4294967293
    route = read_word(s, 8)
    if {unknown_route}:
        return 4294967293
    position = {head}
    index = 0
    while index < {fields}:
        size = read_word(s, 16 + index * 8)
        if size == 0 or size > length(s) - position:
            return 4294967293
        position = position + size
        index = index + 1
    if position != length(s):
        return 4294967293
    count = route & 15
    size = {fixed} + count - 1
    index = 0
    while index < {BASE_FIELDS}:
        size = size + read_word(s, 16 + index * 8)
        index = index + 1
    index = 0
    while index < count:
        role = (route >> (4 + index * 5)) & 31
        size = size + read_word(s, 16 + ({BASE_FIELDS} + role) * 8)
        index = index + 1
    if size > length(o):
        return 4294967294
    out = 0
'''
    for index in range(BASE_FIELDS):
        source += f'    out = prefix_{index}(o, out)\n'
        source += f'    out = copy_field(s, o, {index}, out)\n'
    source += f'''    out = prefix_{BASE_FIELDS}(o, out)
    index = 0
    while index < count:
        if index != 0:
            store(o, out, 44)
            out = out + 1
        role = (route >> (4 + index * 5)) & 31
        out = copy_field(s, o, {BASE_FIELDS} + role, out)
        index = index + 1
    return prefix_{len(prefixes)}(o, out)

def copy_field(s:readbuf, o:mutbuf, field:u64, out:u64) -> u64:
    start = {head}
    index = 0
    while index < field:
        start = start + read_word(s, 16 + index * 8)
        index = index + 1
    size = read_word(s, 16 + field * 8)
    index = 0
    while index < size:
        store(o, out + index, byte(s, start + index))
        index = index + 1
    return out + size
'''
    for index, literal in enumerate((*prefixes, suffix)):
        source += f'\ndef prefix_{index}(o:mutbuf, start:u64) -> u64:\n'
        for offset, value in enumerate(literal):
            source += f'    store(o, start + {offset}, {value})\n'
        source += f'    return start + {len(literal)}\n'
    words = core_cli_source()
    return source + words[words.index('\ndef read_word('):words.index('\ndef put_word(')]


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(source_program(), 'agent_discovery')))
    (ROOT / ANSWER_SOURCE).write_text(render_assembly(document(answer_source(), 'agent_describe_answer')))
