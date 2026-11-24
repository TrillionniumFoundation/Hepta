"""Author the runtime-configuration JSON reader; build-time tools only.

This private variant retains the existing JSON grammar and duplicate-key
algorithm, with full-width offsets, input-sized storage, Python bytes decoding,
and the lexical domain of the retired configuration reader. It does not change
the bounded general-purpose JSON components.
"""
from pathlib import Path
import ast
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
from tools.generate_hia_json_preflight import SOURCE as BASE


class ConfigBuilder(Builder):
    def expr(self, node):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'word_store':
            args = [self.expr(value) for value in node.args]
            return self.op('buffer.store.u64.le', [args[0], self.cast(args[1], 'usize'), self.cast(args[2], 'u64')])
        return super().expr(node)


def document(source, module):
    """Render this private configuration program with native v9 word memory."""
    nodes = ast.parse(source).body
    names = {node.name: 'f' + str(i) for i, node in enumerate(nodes)}
    signatures = {node.name: ([arg.annotation.id for arg in node.args.args], node.returns.id) for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = ConfigBuilder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(p) for p in builder.params],
                          'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
                          'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v9', 'module': module, 'functions': functions})

ROOT=Path(__file__).resolve().parents[1]
MAX=18446744073709551615
KEYS=('hia_worker','hosts','host','artifact_roots','worker_sha256','backend_sha256',
      'catalog_sha256','native_helpers_sha256','python_executable','native_helpers_manifest',
      'capsule','capsule_sha256')
PROGRAM=r'''
def inspect(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < 64:
        return 65
    mode = get(w, 0)
    if mode == 1:
        return transcode(s, o, w)
    if mode == 5:
        return root_vector(s, o, w)
    if mode == 7:
        return measure(s, o, w)
    if mode < 2 or mode > 4 or length(s) == 0 or length(w) < 4096:
        return 65
    if get(w, 24) > 576460752303423483 or length(o) < 128 + (get(w, 24) + 1) * 32:
        return 74
    put(o, 48, length(s) + 1)
    put(o, 56, get(w, 24))
    put(o, 112, get(w, 16) + 1)
    if widen(preflight(s, w, o)) != 0:
        return 65
    first = whitespace(s, 0)
    if first >= length(s) or byte(s, first) != 123:
        return 65
    if mode == 3:
        return pins(s, o, w, first)
    if mode == 4:
        return descriptor(s, o, w, first)
    return runtime(s, o, w, first)

def measure(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(o) < 32 or length(w) < 96:
        return 74
    pos = 0
    depth = 0
    maximum = 0
    keys = 0
    put(w, 88, 0)
    while pos < length(s):
        ch = byte(s, pos)
        if ch == 34:
            put(w, 0, pos)
            if string_token(s, w) != 0:
                return 65
            pos = get(w, 0)
            following = whitespace(s, pos)
            if following < length(s) and byte(s, following) == 58:
                keys = keys + 1
        else:
            if ch == 123 or ch == 91:
                depth = depth + 1
                maximum = choose(depth > maximum, depth, maximum)
            if ch == 125 or ch == 93:
                if depth == 0:
                    return 65
                depth = depth - 1
            pos = pos + 1
    if depth != 0:
        return 65
    put(o, 0, MAGIC_COUNT)
    put(o, 8, keys)
    put(o, 16, maximum)
    put(o, 24, get(w, 88))
    put(w, 32, 32)
    return 0

def widen(value:u64) -> u64:
    return value

def runtime(s:readbuf, o:mutbuf, w:mutbuf, first:u64) -> u32:
    worker = find_kind(s, w, first, 0)
    hosts = find_kind(s, w, first, 1)
    if worker == 18446744073709551615 or hosts == 18446744073709551615:
        return 65
    if byte(s, worker) != 123:
        return 65
    host = find_kind(s, w, worker, 2)
    if host == 18446744073709551615:
        return 65
    selected = 18446744073709551615
    if byte(s, hosts) == 123:
        if byte(s, host) != 34:
            return 65
        selected = find_key(s, w, hosts, host + 1)
    if byte(s, hosts) == 91:
        selected = array_host(s, w, hosts, host)
    if selected == 18446744073709551615 or byte(s, selected) != 123:
        return 65
    suspect = get(o, 88)
    clear = 0
    while clear < 512:
        put(o, clear, 0)
        clear = clear + 8
    put(o, 0, MAGIC_META)
    put(o, 8, 2)
    put(o, 32, worker)
    put(o, 40, skip_value(s, w, worker))
    put(o, 48, count_fields(s, w, worker))
    put(o, 80, length(s))
    field = 0
    mask = 0
    while field < 6:
        value = find_kind(s, w, worker, field + 4)
        end = 18446744073709551615
        if value != 18446744073709551615:
            end = skip_value(s, w, value)
            mask = mask | (1 << field)
        put(o, 128 + field * 24, value)
        put(o, 136 + field * 24, end)
        put(o, 144 + field * 24, field)
        field = field + 1
    put(o, 56, mask)
    remaining = 0
    if suspect != 0:
        remaining = remaining_surrogate(s, o, w)
    put(o, 64, remaining)
    roots = find_kind(s, w, worker, 3)
    count = 0
    at = 520
    if roots != 18446744073709551615:
        if byte(s, roots) != 91:
            return 65
        pos = whitespace(s, roots + 1)
        while byte(s, pos) != 93:
            if count == 32 or byte(s, pos) != 34:
                return 65
            if at > length(o) or length(o) - at < 8:
                return 74
            size = path_value(s, o, w, pos, length(s), at + 8, 1, 1)
            if size == 18446744073709551615:
                return 65
            put(o, at, size)
            at = at + 8 + size
            count = count + 1
            pos = whitespace(s, string_end(s, w, pos))
            if byte(s, pos) == 44:
                pos = whitespace(s, pos + 1)
    put(o, 16, count)
    put(o, 24, at - 512)
    put(o, 512, count)
    put(w, 32, at)
    return 0

def root_vector(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 8 or length(o) < 8:
        return 65
    count = read_word(s, 0, 8, 1)
    if count > 32:
        return 65
    pos = 8
    at = 8
    i = 0
    while i < count:
        if pos > length(s) or length(s) - pos < 8:
            return 65
        size = read_word(s, pos, 8, 1)
        pos = pos + 8
        if size > length(s) - pos:
            return 65
        if at > length(o) or length(o) - at < 8:
            return 74
        normalized = path_value(s, o, w, pos, pos + size, at + 8, 0, 0)
        if normalized == 18446744073709551615:
            return 65
        put(o, at, normalized)
        at = at + 8 + normalized
        pos = pos + size
        i = i + 1
    if pos != length(s):
        return 65
    put(o, 0, count)
    put(w, 32, at)
    return 0

def pins(s:readbuf, o:mutbuf, w:mutbuf, first:u64) -> u32:
    if length(o) < 144 or count_fields(s, w, first) != 4:
        return 65
    i = 0
    while i < 4:
        value = find_kind(s, w, first, i + 4)
        if value == 18446744073709551615 or hex_digest(s, o, w, value, 16 + i * 32) == 0:
            return 65
        i = i + 1
    put(o, 0, MAGIC_PINS)
    put(o, 8, 4)
    put(w, 32, 144)
    return 0

def descriptor(s:readbuf, o:mutbuf, w:mutbuf, first:u64) -> u32:
    path = find_kind(s, w, first, 10)
    pin = find_kind(s, w, first, 11)
    if path == 18446744073709551615 or pin == 18446744073709551615:
        return 65
    if byte(s, path) != 34 or capsule_name(s, w, path + 1) == 0:
        return 65
    if hex_digest(s, o, w, pin, 8) == 0:
        return 65
    put(o, 0, MAGIC_DESC)
    put(w, 32, 40)
    return 0

def hex_digest(s:readbuf, o:mutbuf, w:mutbuf, at:u64, target:u64) -> u64:
    if byte(s, at) != 34:
        return 0
    pos = at + 1
    i = 0
    high = 0
    while i < 64:
        cp = decoded(s, w, pos)
        pos = get(w, 8)
        digit = 16
        if cp >= 48 and cp <= 57:
            digit = cp - 48
        if cp >= 97 and cp <= 102:
            digit = cp - 87
        if digit == 16:
            return 0
        if i & 1 == 0:
            high = digit
        else:
            store(o, target + (i >> 1), high * 16 + digit)
        i = i + 1
    return choose(decoded(s, w, pos) == 1114112, 1, 0)

def find_kind(s:readbuf, w:mutbuf, start:u64, wanted:u64) -> u64:
    pos = whitespace(s, start + 1)
    while byte(s, pos) != 125:
        key = pos + 1
        end = string_end(s, w, pos)
        value = whitespace(s, whitespace(s, end) + 1)
        if key_kind(s, w, key) == wanted:
            return value
        pos = whitespace(s, skip_value(s, w, value))
        if byte(s, pos) == 44:
            pos = whitespace(s, pos + 1)
    return 18446744073709551615

def find_key(s:readbuf, w:mutbuf, start:u64, wanted:u64) -> u64:
    pos = whitespace(s, start + 1)
    while byte(s, pos) != 125:
        key = pos + 1
        end = string_end(s, w, pos)
        value = whitespace(s, whitespace(s, end) + 1)
        if same_key(s, w, key, wanted) == 1:
            return value
        pos = whitespace(s, skip_value(s, w, value))
        if byte(s, pos) == 44:
            pos = whitespace(s, pos + 1)
    return 18446744073709551615

def array_host(s:readbuf, w:mutbuf, array:u64, selector:u64) -> u64:
    count = 0
    pos = whitespace(s, array + 1)
    while byte(s, pos) != 93:
        count = count + 1
        pos = whitespace(s, skip_value(s, w, pos))
        if byte(s, pos) == 44:
            pos = whitespace(s, pos + 1)
    end = skip_value(s, w, selector)
    chosen = 0
    negative = False
    index = selector
    if end - selector == 4 and read_word(s, selector, 4, 1) == 1702195828:
        chosen = 1
    else:
        if end - selector == 5 and read_word(s, selector, 5, 1) == 435728179558:
            chosen = 0
        else:
            if byte(s, index) == 45:
                negative = True
                index = index + 1
            if index == end:
                return 18446744073709551615
            while index < end:
                cp = byte(s, index)
                if cp < 48 or cp > 57 or chosen > count:
                    return 18446744073709551615
                digit = cp - 48
                if chosen > 1844674407370955161 or (chosen == 1844674407370955161 and digit > 5):
                    return 18446744073709551615
                chosen = chosen * 10 + digit
                index = index + 1
    if negative and chosen != 0:
        if chosen > count:
            return 18446744073709551615
        chosen = count - chosen
    if chosen >= count:
        return 18446744073709551615
    index = 0
    pos = whitespace(s, array + 1)
    while index < chosen:
        pos = whitespace(s, skip_value(s, w, pos))
        pos = whitespace(s, pos + 1)
        index = index + 1
    return pos

def count_fields(s:readbuf, w:mutbuf, start:u64) -> u64:
    pos = whitespace(s, start + 1)
    count = 0
    while byte(s, pos) != 125:
        end = string_end(s, w, pos)
        value = whitespace(s, whitespace(s, end) + 1)
        pos = whitespace(s, skip_value(s, w, value))
        count = count + 1
        if byte(s, pos) == 44:
            pos = whitespace(s, pos + 1)
    return count

def skip_value(s:readbuf, w:mutbuf, start:u64) -> u64:
    ch = byte(s, start)
    if ch == 34:
        return string_end(s, w, start)
    if ch != 123 and ch != 91:
        return json_atom(s, start)
    depth = 1
    pos = start + 1
    while depth != 0:
        ch = byte(s, pos)
        if ch == 34:
            pos = string_end(s, w, pos)
        else:
            if ch == 123 or ch == 91:
                depth = depth + 1
            if ch == 125 or ch == 93:
                depth = depth - 1
            pos = pos + 1
    return pos

def string_end(s:readbuf, w:mutbuf, start:u64) -> u64:
    pos = start + 1
    cp = 0
    while cp != 1114112:
        cp = decoded(s, w, pos)
        pos = get(w, 8)
    return pos

def remaining_surrogate(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    pos = 0
    while pos < length(s):
        field = 0
        while field < 6:
            if pos == get(o, 128 + field * 24):
                pos = get(o, 136 + field * 24)
            field = field + 1
        if pos < length(s):
            if byte(s, pos) == 34:
                pos = pos + 1
                cp = 0
                while cp != 1114112:
                    cp = decoded(s, w, pos)
                    pos = get(w, 8)
                    if cp >= 55296 and cp <= 57343:
                        return 1
            else:
                pos = pos + 1
    return 0

def path_value(s:readbuf, o:mutbuf, w:mutbuf, start:u64, end:u64, target:u64, json:u64, absolute:u64) -> u64:
    if target >= length(o):
        return 18446744073709551615
    pos = start + choose(json == 1, 1, 0)
    committed = target
    cursor = target
    component = target
    leading = 0
    initial = True
    active = False
    done = False
    while done == False:
        cp = 1114112
        if json == 1:
            cp = decoded(s, w, pos)
            pos = get(w, 8)
        else:
            if pos < end:
                cp = byte(s, pos)
                pos = pos + 1
        if cp == 1114113:
            return 18446744073709551615
        if cp == 1114112:
            done = True
        if initial:
            if cp == 47:
                leading = leading + 1
            else:
                if absolute == 1 and leading == 0:
                    return 18446744073709551615
                if leading != 0:
                    store(o, target, 47)
                    committed = target + 1
                    if leading == 2:
                        if target + 1 >= length(o):
                            return 18446744073709551615
                        store(o, target + 1, 47)
                        committed = target + 2
                cursor = committed
                initial = False
        if initial == False:
            if cp == 47 or done:
                if active:
                    if cursor - component == 1 and byte(o, component) == 46:
                        cursor = committed
                    else:
                        committed = cursor
                    active = False
            else:
                if active == False:
                    cursor = committed
                    if committed > target:
                        if byte(o, committed - 1) != 47:
                            if cursor >= length(o):
                                return 18446744073709551615
                            store(o, cursor, 47)
                            cursor = cursor + 1
                    component = cursor
                    active = True
                cursor = emit_path(o, cursor, cp, json)
                if cursor == 18446744073709551615:
                    return 18446744073709551615
    if committed == target:
        store(o, target, 46)
        committed = target + 1
    return committed - target

def emit_path(o:mutbuf, at:u64, cp:u64, json:u64) -> u64:
    if at >= length(o):
        return 18446744073709551615
    if json == 0:
        store(o, at, cp)
        return at + 1
    if cp >= 56448 and cp <= 56575:
        store(o, at, cp - 56320)
        return at + 1
    if cp >= 55296 and cp <= 57343:
        return 18446744073709551615
    if utf8_width(cp) > length(o) - at:
        return 18446744073709551615
    return emit_utf8(o, at, cp)

def literal_key(s:readbuf, w:mutbuf, pos:u64, size:u64, a:u64, b:u64, c:u64, d:u64) -> u64:
    index = 0
    while index < size:
        cp = decoded(s, w, pos)
        pos = get(w, 8)
        word = a
        if index >= 8:
            word = b
        if index >= 16:
            word = c
        if index >= 24:
            word = d
        expected = (word >> ((index & 7) * 8)) & 255
        if cp != expected:
            return 0
        index = index + 1
    return choose(decoded(s, w, pos) == 1114112, 1, 0)

def string_token(s:readbuf, w:mutbuf) -> u64:
    index = get(w, 0) + 1
    hash = 14695981039346656037
    going = True
    while going:
        cp = decoded(s, w, index)
        if cp == 1114113:
            put(w, 32, 20)
            return 1
        index = get(w, 8)
        if cp == 1114112:
            going = False
        else:
            if cp >= 55296 and cp <= 57343:
                put(w, 88, 1)
            hash = (hash ^ cp) * 1099511628211
    put(w, 0, index)
    put(w, 40, hash)
    return 0

def insert_key(s:readbuf, o:mutbuf, w:mutbuf, slots:u64, scope:u64, start:u64) -> u64:
    slot = (get(w, 40) ^ (scope * 1099511628211)) & (slots - 1)
    probes = 0
    while probes < slots:
        prior_scope = get(o, slot * 16)
        prior_start = get(o, slot * 16 + 8)
        if prior_scope == 0:
            put(o, slot * 16, scope)
            put(o, slot * 16 + 8, start)
            return 0
        if prior_scope == scope:
            if same_key(s, w, prior_start, start) == 1:
                return 4
        slot = (slot + 1) & (slots - 1)
        probes = probes + 1
    return 3

def same_key(s:readbuf, w:mutbuf, left:u64, right:u64) -> u64:
    while True:
        l = decoded(s, w, left)
        left = get(w, 8)
        r = decoded(s, w, right)
        right = get(w, 8)
        if l != r:
            return 0
        if l == 1114112:
            return 1
        if l == 1114113:
            return 0
    return 0

def decoded(s:readbuf, w:mutbuf, index:u64) -> u64:
    size = length(s)
    if index >= size:
        return 1114113
    ch = byte(s, index)
    index = index + 1
    put(w, 8, index)
    if ch == 34:
        return 1114112
    if ch < 32:
        return 1114113
    if ch != 92:
        if ch < 128:
            return ch
        return utf8_point(s, w, index - 1)
    if index >= size:
        return 1114113
    esc = byte(s, index)
    index = index + 1
    put(w, 8, index)
    if esc == 34 or esc == 92 or esc == 47:
        return esc
    if esc == 98:
        return 8
    if esc == 102:
        return 12
    if esc == 110:
        return 10
    if esc == 114:
        return 13
    if esc == 116:
        return 9
    if esc != 117 or size - index < 4:
        return 1114113
    cp = hex4(s, index)
    if cp == 4294967295:
        return 1114113
    index = index + 4
    if cp >= 55296 and cp <= 56319 and size - index >= 6:
        if byte(s, index) == 92 and byte(s, index + 1) == 117:
            low = hex4(s, index + 2)
            if low >= 56320 and low <= 57343:
                cp = 65536 + (cp - 55296) * 1024 + low - 56320
                index = index + 6
    put(w, 8, index)
    return cp

def utf8_point(s:readbuf, w:mutbuf, index:u64) -> u64:
    size = length(s)
    if index >= size:
        return 1114113
    ch = byte(s, index)
    index = index + 1
    if ch < 128:
        put(w, 8, index)
        return ch
    needed = 0
    minimum = 0
    cp = 0
    if ch >= 194 and ch <= 223:
        needed = 1
        minimum = 128
        cp = ch & 31
    if ch >= 224 and ch <= 239:
        needed = 2
        minimum = 2048
        cp = ch & 15
    if ch >= 240 and ch <= 244:
        needed = 3
        minimum = 65536
        cp = ch & 7
    if needed == 0 or needed > size - index:
        return 1114113
    count = 0
    while count < needed:
        ch = byte(s, index)
        if ch < 128 or ch > 191:
            return 1114113
        cp = cp * 64 + (ch & 63)
        index = index + 1
        count = count + 1
    if cp < minimum or cp > 1114111:
        return 1114113
    put(w, 8, index)
    return cp

def json_atom(s:readbuf, index:u64) -> u64:
    size = length(s)
    if size - index >= 3:
        if read_word(s, index, 3, 1) == 5136718:
            return index + 3
    if size - index >= 8:
        if read_word(s, index, 8, 1) == 8751735898823355977:
            return index + 8
    if size - index >= 9:
        if byte(s, index) == 45 and read_word(s, index + 1, 8, 1) == 8751735898823355977:
            return index + 9
    if size - index >= 4:
        word = read_word(s, index, 4, 1)
        if word == 1702195828 or word == 1819047278:
            return index + 4
    if size - index >= 5:
        if read_word(s, index, 5, 1) == 435728179558:
            return index + 5
    if byte(s, index) == 45:
        index = index + 1
    if index >= size:
        return 18446744073709551615
    begin = index
    ch = byte(s, index)
    if ch < 48 or ch > 57:
        return 18446744073709551615
    if ch == 48:
        index = index + 1
    else:
        index = digit_end(s, index)
    digits = index - begin
    floating = False
    if index < size and byte(s, index) == 46:
        floating = True
        part = index + 1
        index = digit_end(s, part)
        if index == part:
            return 18446744073709551615
    if index < size and (byte(s, index) == 101 or byte(s, index) == 69):
        floating = True
        part = index + 1
        if part < size and (byte(s, part) == 43 or byte(s, part) == 45):
            part = part + 1
        index = digit_end(s, part)
        if index == part:
            return 18446744073709551615
    if floating == False and digits > 4300:
        return 18446744073709551615
    return index

def digit_end(s:readbuf, index:u64) -> u64:
    while index < length(s):
        point = byte(s, index)
        if point < 48 or point > 57:
            return index
        index = index + 1
    return index

def transcode(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(o) < 8:
        return 74
    pos = get(w, 8)
    encoding = get(w, 16)
    if pos == 18446744073709551615:
        encoding = encoding_kind(s)
        pos = encoding_skip(s, encoding)
    at = 0
    while pos < length(s) and at + 4 <= length(o):
        cp = 1114113
        if encoding == 1:
            cp = utf8_point(s, w, pos)
            pos = get(w, 8)
        else:
            width = choose(encoding < 4, 2, 4)
            little = choose(encoding == 2 or encoding == 4, 1, 0)
            if width > length(s) - pos:
                return 65
            cp = read_word(s, pos, width, little)
            pos = pos + width
            if width == 2 and cp >= 55296 and cp <= 56319 and length(s) - pos >= 2:
                low = read_word(s, pos, 2, little)
                if low >= 56320 and low <= 57343:
                    cp = 65536 + (cp - 55296) * 1024 + low - 56320
                    pos = pos + 2
        if cp > 1114111:
            return 65
        at = emit_utf8(o, at, cp)
    put(w, 8, pos)
    put(w, 16, encoding)
    put(w, 24, choose(pos == length(s), 1, 0))
    put(w, 32, at)
    return 0

def encoding_kind(s:readbuf) -> u64:
    if length(s) >= 4:
        head = read_word(s, 0, 4, 1)
        if head == 65279:
            return 4
        if head == 4294836224:
            return 5
    if length(s) >= 2:
        head = read_word(s, 0, 2, 1)
        if head == 65279:
            return 2
        if head == 65534:
            return 3
    if length(s) >= 3:
        if read_word(s, 0, 3, 1) == 12565487:
            return 1
    if length(s) >= 4:
        if byte(s, 0) == 0:
            return choose(byte(s, 1) == 0, 5, 3)
        if byte(s, 1) == 0:
            return choose(byte(s, 2) == 0 and byte(s, 3) == 0, 4, 2)
    if length(s) == 2:
        if byte(s, 0) == 0:
            return 3
        if byte(s, 1) == 0:
            return 2
    return 1

def encoding_skip(s:readbuf, encoding:u64) -> u64:
    if length(s) >= 4:
        head = read_word(s, 0, 4, 1)
        if head == 65279 or head == 4294836224:
            return 4
    if length(s) >= 2:
        head = read_word(s, 0, 2, 1)
        if head == 65279 or head == 65534:
            return 2
    if encoding == 1 and length(s) >= 3:
        if read_word(s, 0, 3, 1) == 12565487:
            return 3
    return 0

def read_word(s:readbuf, at:u64, n:u64, little:u64) -> u64:
    value = 0
    i = 0
    while i < n:
        shift = choose(little == 1, i, n - 1 - i) * 8
        value = value | (byte(s, at + i) << shift)
        i = i + 1
    return value

def utf8_width(cp:u64) -> u64:
    if cp < 128:
        return 1
    if cp < 2048:
        return 2
    if cp < 65536:
        return 3
    return 4

def emit_utf8(o:mutbuf, at:u64, cp:u64) -> u64:
    if cp < 128:
        store(o, at, cp)
        return at + 1
    if cp < 2048:
        store(o, at, 192 | (cp >> 6))
        store(o, at + 1, 128 | (cp & 63))
        return at + 2
    if cp < 65536:
        store(o, at, 224 | (cp >> 12))
        store(o, at + 1, 128 | ((cp >> 6) & 63))
        store(o, at + 2, 128 | (cp & 63))
        return at + 3
    store(o, at, 240 | (cp >> 18))
    store(o, at + 1, 128 | ((cp >> 12) & 63))
    store(o, at + 2, 128 | ((cp >> 6) & 63))
    store(o, at + 3, 128 | (cp & 63))
    return at + 4
'''

def source_program():
    pool={n.name:ast.get_source_segment(BASE,n) for n in ast.parse(BASE).body if isinstance(n,ast.FunctionDef)}
    preflight=pool['preflight']
    preflight=preflight.replace('length(s) > 8388608 or length(w) < 128','length(w) < 128')
    preflight=preflight.replace('maximum < 1 or maximum > 1048576 or maximum_depth > 128',
                                'maximum < 1 or maximum > length(s) + 1 or maximum_depth > length(s) + 1')
    preflight=preflight.replace('slots * 8','slots * 16')
    preflight=preflight.replace('key_bound = choose(maximum < (length(s) >> 2) + 1, maximum, (length(s) >> 2) + 1)', 'key_bound = get(w, 112)')
    preflight=preflight.replace('    put(w, 0, 0)\n    nodes = 0', '    put(w, 0, 0)\n    put(w, 88, 0)\n    put(w, 104, 0)\n    nodes = 0')
    old = '                        result = insert_key(s, o, w, slots, get(w, slot + 16), index + 1)\n                        if result != 0:\n                            return result'
    new = '                        put(w, 104, get(w, 104) + 1)\n                        if key_bound != 0:\n                            result = insert_key(s, o, w, slots, get(w, slot + 16), index + 1)\n                            if result != 0:\n                                return result'
    assert preflight.count(old)==1
    preflight=preflight.replace(old,new)
    preflight=preflight.replace('atom(s, index)','json_atom(s, index)').replace('result == 4294967295','result == 18446744073709551615')
    # The original helpers perform eight separate byte loops on every parser
    # cursor access. Use the already supported native v9 operations instead.
    word_helpers = '''
def get(w:mutbuf, index:u64) -> u64:
    return word_load(w, index)

def put(w:mutbuf, index:u64, value:u64) -> u64:
    word_store(w, index, value)
    return value
'''
    code=PROGRAM+'\n'+preflight+'\n'+'\n\n'.join(pool[k] for k in ('whitespace','hex4'))+word_helpers
    code+='\ndef key_kind(s:readbuf, w:mutbuf, pos:u64) -> u64:\n'
    for i,key in enumerate(KEYS):
        raw=key.encode();words=[int.from_bytes(raw[n:n+8].ljust(8,b'\0'),'little') for n in range(0,32,8)]
        code+=f'    if literal_key(s, w, pos, {len(raw)}, '+', '.join(map(str,words))+f') == 1:\n        return {i}\n'
    code+='    return 18446744073709551615\n'
    name=b'evaluate-full-worker-capsule.bin';words=[int.from_bytes(name[n:n+8].ljust(8,b'\0'),'little') for n in range(0,32,8)]
    code+='\ndef capsule_name(s:readbuf, w:mutbuf, pos:u64) -> u64:\n    return literal_key(s, w, pos, '+str(len(name))+', '+', '.join(map(str,words))+')\n'
    for symbol,magic in [('MAGIC_META',b'HIAWCM01'),('MAGIC_PINS',b'HIAWCP01'),('MAGIC_DESC',b'HIAWCD01'),('MAGIC_COUNT',b'HIAWCQ01')]:
        code=code.replace(symbol,str(int.from_bytes(magic,'little')))
    return code

def main():
    code=source_program();doc=document(code,'worker_config_json')
    target=ROOT/'examples/hia_bootstrap/worker_config_json.hepta'
    target.write_text(render_assembly(doc))
    print(target.name,target.stat().st_size,'blocks',sum(len(f['blocks']) for f in doc['functions']),
          'ops',sum(len(b['ops']) for f in doc['functions'] for b in f['blocks']))
if __name__=='__main__':main()
