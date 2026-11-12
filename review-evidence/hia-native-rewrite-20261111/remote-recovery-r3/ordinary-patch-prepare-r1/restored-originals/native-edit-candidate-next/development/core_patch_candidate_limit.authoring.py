def patch_main(s: readbuf, o: mutbuf, w: mutbuf) -> u32:
    if length(w) < 8192 or length(o) < 8192 or length(s) > 16777219:
        return 4294967293
    mode = get(w, 0)
    declared = 0
    if mode == 2:
        declared = get(w, 8)
        if declared < 1 or declared > 2:
            return 4294967293
    if mode > 2:
        return 4294967293
    put(o, 48, 524289)
    put(o, 56, 129)
    status = widen(decode_json(s, w, o))
    if status >= 4294967292:
        return status
    if kind(w, 0) != 5 or count(w, 0) != 2:
        return 4294967291
    base = child(w, 0)
    request = next_node(w, base)
    if kind(w, base) != 6 or kind(w, request) != 6:
        return 4294967291
    start = whitespace(s, whitespace(s, 0) + 1)
    end = component_end(s, start)
    if end - start > 8388608:
        return 4294967294
    start = whitespace(s, whitespace(s, end) + 1)
    end = component_end(s, start)
    if end - start > 8388608:
        return 4294967294
    scratch = get(w, 32)
    if scratch > length(w) or length(w) - scratch < 8192:
        return 4294967293
    put(w, 40, scratch)
    put(w, scratch + 1280, mode)
    put(w, scratch + 1288, declared)
    put(w, scratch + 1296, 0)
    put(w, 48, 0)
    put(w, 56, 32)
    render_fragment(s, o, w, base)
    size = get(w, 56)
    if get(w, 48) != 0 or size > 8388640:
        return 4294967294
    if mode == 0:
        put(o, 0, 3544425546236643656)
        put(o, 8, 0)
        put(o, 16, 0)
        put(o, 24, 0)
        return size
    if tree_limit(w, base, 64) == 0 or tree_limit(w, request, 128) == 0:
        return 4294967294
    if mode == 2:
        if declared == 1 and text_is(w, field(w, request, 1), 18, 7595371767660569960, 3344032074824691297, 12662) == 0:
            return 4294967281
        if declared == 2 and text_is(w, field(w, request, 1), 18, 7595371767660569960, 3344032074824691297, 12918) == 0:
            return 4294967281
    schema = 0
    policy = 0
    if text_is(w, field(w, request, 1), 18, 7595371767660569960, 3344032074824691297, 12662) != 0:
        schema = 1
        if shape(w, request, 1 | 2 | 8) == 0:
            return 4294967291
    elif text_is(w, field(w, request, 1), 18, 7595371767660569960, 3344032074824691297, 12918) != 0:
        schema = 2
        if shape(w, request, 1 | 2 | 8 | 4) == 0:
            return 4294967291
        selected = field(w, request, 4)
        if text_is(w, selected, 7, 28556934527805805, 0, 0) != 0:
            policy = 1
        elif text_is(w, selected, 8, 7311156825135870576, 0, 0) == 0:
            return 4294967291
    else:
        return 4294967291
    expected = field(w, request, 2)
    if kind(w, expected) != 4 or count(w, expected) != 64:
        return 4294967290
    digest_fragment(o, w, size - 32)
    offset = get(w, 64 + expected * 56 + 24)
    i = 0
    while i < 32:
        a = lower_nibble(byte(w, offset + i * 2))
        b = lower_nibble(byte(w, offset + i * 2 + 1))
        if a > 15 or b > 15:
            return 4294967290
        if byte(w, scratch + 1088 + i) != a << 4 | b:
            return 4294967289
        i = i + 1
    edits = field(w, request, 8)
    if kind(w, edits) != 5 or count(w, edits) < 1 or count(w, edits) > 64:
        return 4294967288
    functions = field(w, base, 2048)
    if kind(w, functions) != 5:
        return 4294967291
    put(w, 56, 32)
    render_fragment(s, o, w, request)
    if get(w, 48) != 0 or get(w, 56) > 8388640:
        return 4294967294
    applied = apply_edits(s, o, w, functions, edits, policy)
    if applied >= 4294967264:
        return applied
    put(w, 56, 32)
    render_fragment(s, o, w, base)
    if get(w, 48) != 0 or get(w, 56) > 8388640:
        if mode == 2 and get(w, 48) == 0 and get(w, 56) > 8388640:
            put(o, 0, 3544405802271983944)
            put(o, 8, 1)
            put(o, 16, get(w, 56) - 32)
            put(o, 24, 1)
        return 4294967294
    if mode == 2:
        return patch_result(o, w, schema, policy, applied, expected)
    put(o, 0, 3544425546236643656)
    put(o, 8, schema)
    put(o, 16, policy)
    put(o, 24, applied)
    return get(w, 56)

def apply_edits(s: readbuf, o: mutbuf, w: mutbuf, functions: u64, edits: u64, policy: u64) -> u64:
    edit = child(w, edits)
    applied = 0
    while edit != 18446744073709551615:
        status = edit_target(s, w, functions, edit)
        if status != 0:
            return status
        status = edit_overlap(w, applied)
        if status != 0:
            return status
        status = edit_materialize(s, o, w, functions, edit, policy)
        if status != 0:
            return status
        scratch = get(w, 40)
        entry = scratch + 2048 + applied * 32
        put(w, entry, get(w, scratch + 1216))
        put(w, entry + 8, get(w, scratch + 1232))
        put(w, entry + 16, get(w, scratch + 1240))
        put(w, entry + 24, get(w, scratch + 1200))
        applied = applied + 1
        edit = next_node(w, edit)
    return applied

def edit_target(s: readbuf, w: mutbuf, functions: u64, edit: u64) -> u64:
    action = 0
    tag = field(w, edit, 16)
    if text_is(w, tag, 16, 6874009676333213042, 7957695015192261990, 0) != 0:
        action = 1
    if text_is(w, tag, 12, 7164793139740566625, 1852795252, 0) != 0:
        action = 2
    if text_is(w, tag, 17, 6874009676333213042, 8028075772644520047, 110) != 0:
        action = 3
    if text_is(w, tag, 18, 6874009676333213042, 8386105380227409268, 29295) != 0:
        action = 4
    if action == 0:
        return 4294967287
    fields = 16 | 32
    if action <= 2:
        fields = fields | 64
    elif action == 3:
        fields = fields | 128 | 256 | 512
    else:
        fields = fields | 128 | 1024
    if shape(w, edit, fields) == 0:
        return 4294967291
    name = field(w, edit, 32)
    if kind(w, name) != 4:
        return 4294967286
    fn = named(w, functions, 4096, name)
    if action == 2:
        if fn != 18446744073709551615:
            return 4294967286
    elif fn == 18446744073709551615:
        return 4294967286
    block = 18446744073709551615
    block_name = 18446744073709551615
    index = 18446744073709551615
    if action >= 3:
        block_name = field(w, edit, 128)
        if kind(w, block_name) != 4:
            return 4294967285
        block = named(w, field(w, fn, 131072), 262144, block_name)
        if block == 18446744073709551615:
            return 4294967285
        if action == 3:
            index = exact_index(s, w, field(w, edit, 256))
            ops = field(w, block, 524288)
            if kind(w, ops) != 5 or index >= count(w, ops):
                return 4294967284
    scratch = get(w, 40)
    put(w, scratch + 1200, action)
    put(w, scratch + 1208, fn)
    put(w, scratch + 1216, name)
    put(w, scratch + 1224, block)
    put(w, scratch + 1232, block_name)
    put(w, scratch + 1240, index)
    return 0

def edit_overlap(w: mutbuf, applied: u64) -> u64:
    scratch = get(w, 40)
    action = get(w, scratch + 1200)
    name = get(w, scratch + 1216)
    block_name = get(w, scratch + 1232)
    index = get(w, scratch + 1240)
    previous = 0
    while previous < applied:
        entry = scratch + 2048 + previous * 32
        if same_text(w, name, get(w, entry)) != 0:
            old_action = get(w, entry + 24)
            if action <= 2 or old_action <= 2:
                return 4294967283
            if same_text(w, block_name, get(w, entry + 8)) != 0:
                if action == old_action and index == get(w, entry + 16):
                    return 4294967283
        previous = previous + 1
    return 0

def edit_materialize(s: readbuf, o: mutbuf, w: mutbuf, functions: u64, edit: u64, policy: u64) -> u64:
    scratch = get(w, 40)
    action = get(w, scratch + 1200)
    fn = get(w, scratch + 1208)
    name = get(w, scratch + 1216)
    block = get(w, scratch + 1224)
    index = get(w, scratch + 1240)
    if action <= 2:
        replacement = field(w, edit, 64)
        if kind(w, replacement) != 6 or same_text(w, name, field(w, replacement, 4096)) == 0:
            return 4294967286
        changed = 0
        if action == 2:
            changed = 1
        elif policy == 0 or get(w, scratch + 1280) == 2:
            changed = choose(same_interface(s, o, w, fn, replacement) == 0, 1, 0)
        if changed != 0:
            if policy == 0:
                return 4294967282
            if get(w, scratch + 1280) == 2:
                remember_change(w, name)
        if action == 2:
            append_node(w, functions, replacement)
        else:
            replace_node(w, functions, fn, replacement)
    elif action == 3:
        target = child(w, field(w, block, 524288))
        j = 0
        while j < index:
            target = next_node(w, target)
            j = j + 1
        replace_node(w, field(w, block, 524288), target, field(w, edit, 512))
    else:
        target = field(w, block, 1024)
        if target == 18446744073709551615:
            return 4294967285
        replace_node(w, block, target, field(w, edit, 1024))
    return 0

def component_end(s: readbuf, start: u64) -> u64:
    index = start
    depth = 0
    while index < length(s):
        ch = byte(s, index)
        if ch == 34:
            index = index + 1
            going = True
            while going and index < length(s):
                ch = byte(s, index)
                if ch == 92:
                    index = index + 2
                elif ch == 34:
                    index = index + 1
                    going = False
                else:
                    index = index + 1
        else:
            if ch == 123 or ch == 91:
                depth = depth + 1
            if ch == 125 or ch == 93:
                depth = depth - 1
                if depth == 0:
                    return index + 1
            index = index + 1
    return length(s)

def lower_nibble(value: u64) -> u64:
    if value >= 48 and value <= 57:
        return value - 48
    if value >= 97 and value <= 102:
        return value - 87
    return 256

def tree_limit(w: mutbuf, root: u64, maximum_depth: u64) -> u64:
    node = root
    depth = 0
    nodes = 0
    going = True
    while going:
        nodes = nodes + 1
        if nodes > 262144 or depth > maximum_depth:
            return 0
        if (kind(w, node) == 5 or kind(w, node) == 6) and count(w, node) > 0:
            node = child(w, node)
            depth = depth + 1
        else:
            moving = True
            while moving:
                if node == root:
                    going = False
                    moving = False
                elif next_node(w, node) != 18446744073709551615:
                    node = next_node(w, node)
                    moving = False
                else:
                    node = get(w, 64 + node * 56 + 8)
                    depth = depth - 1
    return 1

def same_text(w: mutbuf, a: u64, b: u64) -> u64:
    if kind(w, a) != 4 or kind(w, b) != 4 or count(w, a) != count(w, b):
        return 0
    start_a = get(w, 64 + a * 56 + 24)
    start_b = get(w, 64 + b * 56 + 24)
    i = 0
    while i < count(w, a):
        if byte(w, start_a + i) != byte(w, start_b + i):
            return 0
        i = i + 1
    return 1

def named(w: mutbuf, array: u64, key: u64, name: u64) -> u64:
    if kind(w, array) != 5:
        return 18446744073709551615
    node = child(w, array)
    found = 18446744073709551615
    while node != 18446744073709551615:
        if same_text(w, field(w, node, key), name) != 0:
            if found != 18446744073709551615:
                return 18446744073709551615
            found = node
        node = next_node(w, node)
    return found

def exact_index(s: readbuf, w: mutbuf, node: u64) -> u64:
    if kind(w, node) != 3:
        return 18446744073709551615
    start = get(w, 64 + node * 56 + 24)
    size = count(w, node)
    if size == 2 and byte(s, start) == 45 and (byte(s, start + 1) == 48):
        return 0
    if size == 0 or size > 20:
        return 18446744073709551615
    value = 0
    i = 0
    while i < size:
        ch = byte(s, start + i)
        if ch < 48 or ch > 57 or value > 1844674407370955161:
            return 18446744073709551615
        digit = ch - 48
        if value == 1844674407370955161 and digit > 5:
            return 18446744073709551615
        value = value * 10 + digit
        i = i + 1
    return value

def replace_node(w: mutbuf, parent: u64, old: u64, replacement: u64) -> u64:
    node = child(w, parent)
    previous = 18446744073709551615
    while node != old:
        previous = node
        node = next_node(w, node)
    record = 64 + replacement * 56
    old_record = 64 + old * 56
    put(w, record + 8, parent)
    put(w, record + 16, next_node(w, old))
    put(w, record + 40, get(w, old_record + 40))
    put(w, record + 48, get(w, old_record + 48))
    if previous == 18446744073709551615:
        put(w, 64 + parent * 56 + 24, replacement)
    else:
        put(w, 64 + previous * 56 + 16, replacement)
    return 0

def append_node(w: mutbuf, parent: u64, replacement: u64) -> u64:
    node = child(w, parent)
    if node == 18446744073709551615:
        put(w, 64 + parent * 56 + 24, replacement)
    else:
        while next_node(w, node) != 18446744073709551615:
            node = next_node(w, node)
        put(w, 64 + node * 56 + 16, replacement)
    put(w, 64 + parent * 56 + 32, count(w, parent) + 1)
    put(w, 64 + replacement * 56 + 8, parent)
    put(w, 64 + replacement * 56 + 16, 18446744073709551615)
    put(w, 64 + replacement * 56 + 40, 0)
    put(w, 64 + replacement * 56 + 48, 0)
    return 0

def equal_json(s: readbuf, o: mutbuf, w: mutbuf, a: u64, b: u64) -> u64:
    if a == 18446744073709551615 or b == 18446744073709551615:
        return 0
    put(w, 56, 32)
    render_fragment(s, o, w, a)
    first_end = get(w, 56)
    render_fragment(s, o, w, b)
    if get(w, 48) != 0 or get(w, 56) - first_end != first_end - 32:
        return 0
    i = 0
    while i < first_end - 32:
        if byte(o, 32 + i) != byte(o, first_end + i):
            return 0
        i = i + 1
    return 1

def default_loans(w: mutbuf, loans: u64, results: u64) -> u64:
    if kind(w, loans) != 5 or kind(w, results) != 5 or count(w, loans) != count(w, results):
        return 0
    node = child(w, loans)
    while node != 18446744073709551615:
        if kind(w, node) != 0:
            return 0
        node = next_node(w, node)
    return 1

def same_interface(s: readbuf, o: mutbuf, w: mutbuf, a: u64, b: u64) -> u64:
    if same_text(w, field(w, a, 4096), field(w, b, 4096)) == 0:
        return 0
    if equal_json(s, o, w, field(w, a, 8192), field(w, b, 8192)) == 0:
        return 0
    if equal_json(s, o, w, field(w, a, 16384), field(w, b, 16384)) == 0:
        return 0
    if equal_json(s, o, w, field(w, a, 32768), field(w, b, 32768)) == 0:
        return 0
    x = field(w, a, 65536)
    y = field(w, b, 65536)
    if x == 18446744073709551615:
        if y == 18446744073709551615:
            return 1
        return default_loans(w, y, field(w, a, 16384))
    if y == 18446744073709551615:
        return default_loans(w, x, field(w, b, 16384))
    return equal_json(s, o, w, x, y)

def text_less(w: mutbuf, a: u64, b: u64) -> u64:
    left = get(w, 64 + a * 56 + 24)
    right = get(w, 64 + b * 56 + 24)
    i = 0
    while i < count(w, a) and i < count(w, b):
        x = byte(w, left + i)
        y = byte(w, right + i)
        if x < y:
            return 1
        if x > y:
            return 0
        i = i + 1
    return choose(count(w, a) < count(w, b), 1, 0)

def remember_change(w: mutbuf, name: u64) -> u64:
    scratch = get(w, 40)
    size = get(w, scratch + 1296)
    if size >= 64:
        put(w, 48, 4294967294)
        return 0
    index = size
    moving = True
    while index > 0 and moving:
        previous = get(w, scratch + 4096 + (index - 1) * 8)
        if text_less(w, name, previous) != 0:
            put(w, scratch + 4096 + index * 8, previous)
            index = index - 1
        else:
            moving = False
    put(w, scratch + 4096 + index * 8, name)
    put(w, scratch + 1296, size + 1)
    return 0

def receipt_digest(o: mutbuf, w: mutbuf) -> u64:
    start = get(w, 40) + 1088
    i = 0
    while i < 32:
        value = byte(w, start + i)
        append_byte(o, w, hex_digit(value >> 4))
        append_byte(o, w, hex_digit(value & 15))
        i = i + 1
    return 0

def receipt_count(o: mutbuf, w: mutbuf, value: u64) -> u64:
    tens = 0
    while value >= 10:
        value = value - 10
        tens = tens + 1
    if tens != 0:
        append_byte(o, w, tens + 48)
    append_byte(o, w, value + 48)
    return 0

def receipt_changes(o: mutbuf, w: mutbuf) -> u64:
    scratch = get(w, 40)
    append_byte(o, w, 91)
    i = 0
    while i < get(w, scratch + 1296):
        if i != 0:
            append_byte(o, w, 44)
        name = get(w, scratch + 4096 + i * 8)
        append_string(o, w, get(w, 64 + name * 56 + 24), count(w, name))
        i = i + 1
    append_byte(o, w, 93)
    return 0

def receipt_claims(o: mutbuf, w: mutbuf, schema: u64) -> u64:
    emit(o, w, 24, 8317419953974354476, 7018971491416619554, 8462656635422075254)
    emit(o, w, 23, 7305804402414155369, 2478217254310932575, 12496445389235770)
    if schema == 2:
        emit(o, w, 24, 7020674649188492578, 8243113905717731180, 7596553832603213683)
        emit(o, w, 24, 7366237955112067428, 7955927790802660449, 6874009676232680820)
        emit(o, w, 11, 7311156825135870576, 3809892, 0)
        if get(w, get(w, 40) + 1296) == 0:
            emit(o, w, 5, 190680756852, 0, 0)
        else:
            emit(o, w, 6, 48814239801702, 0, 0)
    emit(o, w, 24, 6874030601547116066, 7234316423968159845, 3199090019644357154)
    emit(o, w, 24, 7881129389321647906, 7310010034391704687, 2478217206864111715)
    emit(o, w, 6, 137874715604026, 0, 0)
    return 0

def patch_result(o: mutbuf, w: mutbuf, schema: u64, policy: u64, edits: u64, expected: u64) -> u32:
    candidate_end = get(w, 56)
    digest_fragment(o, w, candidate_end - 32)
    emit(o, w, 17, 6877671131556422267, 4188970205514393715, 34)
    receipt_digest(o, w)
    emit(o, w, 18, 8245922028362804258, 3906083645759381349, 14882)
    append_string(o, w, get(w, 64 + expected * 56 + 24), 64)
    receipt_claims(o, w, schema)
    emit(o, w, 24, 7232627522585043500, 2466321603548507503, 7236833184642788969)
    emit(o, w, 24, 7311136020197830245, 7953185853682379122, 7312272859201368687)
    emit(o, w, 16, 3180215829046452068, 4189037547229570338, 0)
    receipt_count(o, w, edits)
    emit(o, w, 21, 7382074289956659756, 7953753192924537697, 249686091111)
    receipt_changes(o, w)
    if schema == 2:
        emit(o, w, 21, 7382074289956659756, 7596569199894684513, 147004225891)
        if policy == 0:
            emit(o, w, 8, 7311156825135870576, 0, 0)
        else:
            emit(o, w, 7, 28556934527805805, 0, 0)
        append_byte(o, w, 34)
    emit(o, w, 24, 8247280737127965228, 7451612880101467509, 8101528638247235177)
    emit(o, w, 11, 3833233334085842037, 3809846, 0)
    append_string(o, w, get(w, 64 + expected * 56 + 24), 64)
    emit(o, w, 24, 7020378893159965228, 7022361299818527266, 8386107325645678638)
    emit(o, w, 11, 7815279607915833443, 7745140, 0)
    append_byte(o, w, schema + 48)
    emit(o, w, 24, 8463496752511724578, 7598247079382229619, 8101541832252811622)
    emit(o, w, 10, 7234303221339808373, 32034, 0)
    size = get(w, 56)
    if get(w, 48) != 0 or size - candidate_end > 8388608:
        return 4294967294
    put(o, 0, 3544423347213388104)
    put(o, 8, candidate_end - 32)
    put(o, 16, size - candidate_end)
    put(o, 24, 0)
    return size

def hash_get(w: mutbuf, index: u64) -> u64:
    return get(w, get(w, 40) + index)

def hash_put(w: mutbuf, index: u64, value: u64) -> u64:
    return put(w, get(w, 40) + index, value)
def kind(w: mutbuf, node: u64) -> u64:
    if node == 18446744073709551615:
        return 18446744073709551615
    return get(w, 64 + node * 56)

def count(w: mutbuf, node: u64) -> u64:
    if node == 18446744073709551615:
        return 0
    return get(w, 64 + node * 56 + 32)

def child(w: mutbuf, node: u64) -> u64:
    if kind(w, node) != 5 and kind(w, node) != 6:
        return 18446744073709551615
    return get(w, 64 + node * 56 + 24)

def field(w: mutbuf, node: u64, flag: u64) -> u64:
    if kind(w, node) != 6:
        return 18446744073709551615
    item = child(w, node)
    while item != 18446744073709551615:
        if key_id(w, item) == flag:
            return item
        item = next_node(w, item)
    return 18446744073709551615

def shape(w: mutbuf, node: u64, expected: u64) -> u64:
    if kind(w, node) != 6:
        return 0
    actual = 0
    item = child(w, node)
    while item != 18446744073709551615:
        flag = key_id(w, item)
        if flag == 0:
            return 0
        actual = actual | flag
        item = next_node(w, item)
    return choose(actual == expected, 1, 0)

def same(w: mutbuf, start: u64, size: u64, n: u64, a: u64, b: u64, c: u64) -> u64:
    if size != n:
        return 0
    i = 0
    while i < n:
        word = a
        shift = i * 8
        if i >= 8:
            word = b
            shift = (i - 8) * 8
        if i >= 16:
            word = c
            shift = (i - 16) * 8
        if byte(w, start + i) != word >> shift & 255:
            return 0
        i = i + 1
    return 1

def text_is(w: mutbuf, node: u64, n: u64, a: u64, b: u64, c: u64) -> u64:
    if kind(w, node) != 4:
        return 0
    return same(w, get(w, 64 + node * 56 + 24), count(w, node), n, a, b, c)

def emit(o: mutbuf, w: mutbuf, n: u64, a: u64, b: u64, c: u64) -> u64:
    i = 0
    while i < n:
        word = a
        shift = i * 8
        if i >= 8:
            word = b
            shift = (i - 8) * 8
        if i >= 16:
            word = c
            shift = (i - 16) * 8
        append_byte(o, w, word >> shift & 255)
        i = i + 1
    return 0

def render_fragment(s: readbuf, o: mutbuf, w: mutbuf, root: u64) -> u64:
    node = root
    going = True
    while going:
        record = 64 + node * 56
        kind = get(w, record)
        parent = get(w, record + 8)
        if node != root:
            if get(w, 64 + parent * 56) == 6:
                append_string(o, w, get(w, record + 40), get(w, record + 48))
                append_byte(o, w, 58)
        complete = True
        if kind == 5 or kind == 6:
            if kind == 6:
                sort_object(w, node)
            append_byte(o, w, choose(kind == 5, 91, 123))
            if get(w, record + 32) == 0:
                append_byte(o, w, choose(kind == 5, 93, 125))
            else:
                node = get(w, record + 24)
                complete = False
        else:
            start = get(w, record + 24)
            size = get(w, record + 32)
            if kind == 4:
                append_string(o, w, start, size)
            elif kind == 3 and size == 2 and (byte(s, start) == 45) and (byte(s, start + 1) == 48):
                append_byte(o, w, 48)
            else:
                i = 0
                while i < size:
                    append_byte(o, w, byte(s, start + i))
                    i = i + 1
        if complete:
            moving = True
            while moving:
                record = 64 + node * 56
                sibling = choose(node == root, 18446744073709551615, get(w, record + 16))
                if sibling != 18446744073709551615:
                    append_byte(o, w, 44)
                    node = sibling
                    moving = False
                else:
                    parent = get(w, record + 8)
                    if node == root:
                        going = False
                        moving = False
                    else:
                        node = parent
                        append_byte(o, w, choose(get(w, 64 + node * 56) == 5, 93, 125))
    return get(w, 56)

def append_byte(o: mutbuf, w: mutbuf, value: u64) -> u64:
    index = get(w, 56)
    if index >= 16777248 or index >= length(o):
        put(w, 48, 4294967294)
    else:
        store(o, index, value)
        put(w, 56, index + 1)
    return 0

def hex_digit(value: u64) -> u64:
    return choose(value < 10, value + 48, value + 87)

def append_string(o: mutbuf, w: mutbuf, start: u64, size: u64) -> u64:
    append_byte(o, w, 34)
    i = 0
    while i < size:
        value = byte(w, start + i)
        if value < 32:
            append_byte(o, w, 92)
            escape = 0
            if value == 8:
                escape = 98
            if value == 9:
                escape = 116
            if value == 10:
                escape = 110
            if value == 12:
                escape = 102
            if value == 13:
                escape = 114
            if escape != 0:
                append_byte(o, w, escape)
            else:
                append_byte(o, w, 117)
                append_byte(o, w, 48)
                append_byte(o, w, 48)
                append_byte(o, w, hex_digit(value >> 4))
                append_byte(o, w, hex_digit(value & 15))
        else:
            if value == 34 or value == 92:
                append_byte(o, w, 92)
            append_byte(o, w, value)
        i = i + 1
    append_byte(o, w, 34)
    return 0

def next_node(w: mutbuf, node: u64) -> u64:
    return get(w, 64 + node * 56 + 16)

def key_less(w: mutbuf, a: u64, b: u64) -> u64:
    ra = 64 + a * 56
    rb = 64 + b * 56
    aa = get(w, ra + 40)
    bb = get(w, rb + 40)
    na = get(w, ra + 48)
    nb = get(w, rb + 48)
    i = 0
    while i < na and i < nb:
        x = byte(w, aa + i)
        y = byte(w, bb + i)
        if x < y:
            return 1
        if x > y:
            return 0
        i = i + 1
    return choose(na <= nb, 1, 0)

def sort_object(w: mutbuf, node: u64) -> u64:
    record = 64 + node * 56
    size = get(w, record + 32)
    head = get(w, record + 24)
    width = 1
    while width < size:
        p = head
        head = 18446744073709551615
        tail = 18446744073709551615
        while p != 18446744073709551615:
            q = p
            left = 0
            while left < width and q != 18446744073709551615:
                q = next_node(w, q)
                left = left + 1
            right = width
            element = 0
            while left > 0 or (right > 0 and q != 18446744073709551615):
                take_left = False
                if left > 0:
                    if right == 0 or q == 18446744073709551615:
                        take_left = True
                    elif key_less(w, p, q) == 1:
                        take_left = True
                if take_left:
                    element = p
                    p = next_node(w, p)
                    left = left - 1
                else:
                    element = q
                    q = next_node(w, q)
                    right = right - 1
                if tail == 18446744073709551615:
                    head = element
                else:
                    put(w, 64 + tail * 56 + 16, element)
                tail = element
            p = q
        put(w, 64 + tail * 56 + 16, 18446744073709551615)
        width = width * 2
    put(w, record + 24, head)
    return 0
def key_id(w:mutbuf, node:u64) -> u64:
    start = get(w, 64 + node * 56 + 40)
    size = get(w, 64 + node * 56 + 48)
    if same(w, start, size, 6, 107122480669555, 0, 0) == 1:
        return 1
    if same(w, start, size, 15, 7234316346693023845, 15258139241247583, 0) == 1:
        return 2
    if same(w, start, size, 16, 7161117524010233449, 8746950815730655077, 0) == 1:
        return 4
    if same(w, start, size, 5, 495874303077, 0, 0) == 1:
        return 8
    if same(w, start, size, 6, 121424789660513, 0, 0) == 1:
        return 16
    if same(w, start, size, 8, 7957695015192261990, 0, 0) == 1:
        return 32
    if same(w, start, size, 10, 7598814394216506724, 28271, 0) == 1:
        return 64
    if same(w, start, size, 5, 461229747298, 0, 0) == 1:
        return 128
    if same(w, start, size, 5, 517097156201, 0, 0) == 1:
        return 256
    if same(w, start, size, 9, 8028075772644520047, 110, 0) == 1:
        return 512
    if same(w, start, size, 4, 1836213620, 0, 0) == 1:
        return 1024
    if same(w, start, size, 9, 7957695015192261990, 115, 0) == 1:
        return 2048
    if same(w, start, size, 4, 1701667182, 0, 0) == 1:
        return 4096
    if same(w, start, size, 6, 126913623515504, 0, 0) == 1:
        return 8192
    if same(w, start, size, 7, 32491060197614962, 0, 0) == 1:
        return 16384
    if same(w, start, size, 7, 32497592573519461, 0, 0) == 1:
        return 32768
    if same(w, start, size, 12, 7809081716759618930, 1936613743, 0) == 1:
        return 65536
    if same(w, start, size, 6, 126905066941538, 0, 0) == 1:
        return 131072
    if same(w, start, size, 2, 25705, 0, 0) == 1:
        return 262144
    if same(w, start, size, 3, 7565423, 0, 0) == 1:
        return 524288
    return 0

def decode_json(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) > 16777219 or length(w) < 128 or length(o) < 128:
        return 4294967293
    maximum = get(w, 48)
    maximum_depth = get(w, 56)
    if maximum < 1 or maximum > 1048576 or maximum_depth > 129:
        return 4294967293
    if length(w) < 128 + (maximum_depth + 1) * 48:
        return 4294967293
    put(o, 48, maximum)
    put(o, 56, maximum_depth)
    result = widen(preflight(s, w, o))
    if result == 1:
        return 4294967295
    if result == 2:
        return 4294967294
    if result == 4:
        return 4294967292
    if result != 0:
        return 4294967293
    count = get(o, 64)
    base = 64 + count * 56
    if length(o) < base + length(s):
        return 4294967293
    # Phase one used o as a small state stack and w as key slots. Phase two
    # reuses w for a private container stack; no value graph was built earlier.
    put(w, 0, 0)
    put(w, 64, 0)
    put(w, 72, base)
    put(w, 96, 0)
    going = True
    while going:
        index = whitespace(s, get(w, 0))
        put(w, 0, index)
        if index == length(s):
            going = False
        else:
            ch = byte(s, index)
            if ch == 44 or ch == 58:
                put(w, 0, index + 1)
            else:
                if ch == 93 or ch == 125:
                    put(w, 96, get(w, 96) - 1)
                    put(w, 0, index + 1)
                else:
                    if ch == 91 or ch == 123:
                        kind = choose(ch == 91, 5, 6)
                        node = new_node(o, w, kind, 18446744073709551615, 0)
                        depth = get(w, 96)
                        frame = 128 + depth * 48
                        put(w, frame, node)
                        put(w, frame + 8, kind)
                        put(w, frame + 16, 18446744073709551615)
                        put(w, frame + 24, 0)
                        put(w, frame + 32, 0)
                        put(w, frame + 40, 0)
                        put(w, 96, depth + 1)
                        put(w, 0, index + 1)
                    else:
                        if ch == 34:
                            decode_string(s, o, w)
                            depth = get(w, 96)
                            key = False
                            frame = 128
                            if depth > 0:
                                frame = 128 + (depth - 1) * 48
                                if get(w, frame + 8) == 6 and get(w, frame + 40) == 0:
                                    key = True
                            if key:
                                put(w, frame + 24, get(w, 80))
                                put(w, frame + 32, get(w, 88))
                                put(w, frame + 40, 1)
                            else:
                                new_node(o, w, 4, get(w, 80), get(w, 88))
                        else:
                            end = atom(s, index)
                            kind = 3
                            if ch == 110:
                                kind = 0
                            if ch == 102:
                                kind = 1
                            if ch == 116:
                                kind = 2
                            new_node(o, w, kind, index, end - index)
                            put(w, 0, end)
    if get(w, 64) != count or get(w, 96) != 0:
        return 4294967293
    put(o, 0, 5208772604367785521)
    put(o, 8, count)
    put(o, 16, base)
    put(o, 24, get(w, 72))
    put(o, 32, get(w, 72))
    put(o, 40, length(s))
    put(o, 48, 1)
    put(o, 56, 0)
    return get(w, 72)

def widen(value:u64) -> u64:
    return value

def new_node(o:mutbuf, w:mutbuf, kind:u64, start:u64, size:u64) -> u64:
    node = get(w, 64)
    record = 64 + node * 56
    put(w, 64, node + 1)
    put(o, record, kind)
    put(o, record + 8, 18446744073709551615)
    put(o, record + 16, 18446744073709551615)
    put(o, record + 24, start)
    put(o, record + 32, size)
    put(o, record + 40, 0)
    put(o, record + 48, 0)
    depth = get(w, 96)
    if depth > 0:
        frame = 128 + (depth - 1) * 48
        parent = get(w, frame)
        put(o, record + 8, parent)
        parent_record = 64 + parent * 56
        previous = get(w, frame + 16)
        if previous == 18446744073709551615:
            put(o, parent_record + 24, node)
        else:
            put(o, 64 + previous * 56 + 16, node)
        put(w, frame + 16, node)
        put(o, parent_record + 32, get(o, parent_record + 32) + 1)
        if get(w, frame + 8) == 6:
            put(o, record + 40, get(w, frame + 24))
            put(o, record + 48, get(w, frame + 32))
            put(w, frame + 40, 0)
    return node

def decode_string(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    index = get(w, 0) + 1
    start = get(w, 72)
    going = True
    while going:
        unit = decoded(s, index)
        cp = unit & 4294967295
        index = unit >> 32
        if cp == 1114112:
            going = False
        else:
            write_scalar(o, w, cp)
    put(w, 0, index)
    put(w, 80, start)
    put(w, 88, get(w, 72) - start)
    return 0

def write_scalar(o:mutbuf, w:mutbuf, cp:u64) -> u64:
    index = get(w, 72)
    if cp < 128:
        store(o, index, cp)
        index = index + 1
    else:
        if cp < 2048:
            store(o, index, 192 | (cp >> 6))
            store(o, index + 1, 128 | (cp & 63))
            index = index + 2
        else:
            if cp < 65536:
                store(o, index, 224 | (cp >> 12))
                store(o, index + 1, 128 | ((cp >> 6) & 63))
                store(o, index + 2, 128 | (cp & 63))
                index = index + 3
            else:
                store(o, index, 240 | (cp >> 18))
                store(o, index + 1, 128 | ((cp >> 12) & 63))
                store(o, index + 2, 128 | ((cp >> 6) & 63))
                store(o, index + 3, 128 | (cp & 63))
                index = index + 4
    put(w, 72, index)
    return 0

def preflight(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) > 16777219 or length(w) < 128:
        return 3
    # Preserve the status ABI. Offset 32 is a private diagnostic reason, not
    # an input claim; the native parser sets it at the first grammar refusal.
    put(w, 32, 0)
    maximum = get(w, 48)
    maximum_depth = get(w, 56)
    if maximum < 1 or maximum > 1048576 or maximum_depth > 129:
        return 3
    if length(w) < 128 + (maximum_depth + 1) * 32:
        return 3
    # Even before a missing value is found, every inserted key consumed at
    # least four wire bytes, except the one currently waiting for its value.
    key_bound = choose(maximum < (length(s) >> 2) + 1, maximum, (length(s) >> 2) + 1)
    slots = 2
    while slots < key_bound * 2:
        slots = slots * 2
    if length(o) < slots * 8:
        return 3
    clear = 0
    while clear < slots * 8:
        put(o, clear, 0)
        clear = clear + 8
    put(w, 0, 0)
    nodes = 0
    depth = 0
    want_value = True
    done = False
    while True:
        index = whitespace(s, get(w, 0))
        put(w, 0, index)
        if done:
            if index == length(s):
                put(w, 64, nodes)
                return 0
            put(w, 32, 12)
            return 1
        if want_value:
            if index >= length(s):
                put(w, 32, 9)
                return 1
            nodes = nodes + 1
            if nodes > maximum or depth > maximum_depth:
                return 2
            ch = byte(s, index)
            if ch == 91 or ch == 123:
                slot = 128 + depth * 32
                put(w, slot, choose(ch == 91, 1, 2))
                put(w, slot + 8, 0)
                put(w, slot + 16, index + 1)
                depth = depth + 1
                put(w, 0, index + 1)
            else:
                if ch == 34:
                    result = string_token(s, w)
                    if result != 0:
                        return 1
                else:
                    result = atom(s, index)
                    if result == 4294967295:
                        put(w, 32, 10)
                        return 1
                    put(w, 0, result)
                if depth == 0:
                    done = True
                else:
                    put(w, 128 + (depth - 1) * 32 + 8, 5)
            want_value = False
        else:
            if depth == 0:
                put(w, 32, 13)
                return 1
            slot = 128 + (depth - 1) * 32
            kind = get(w, slot)
            state = get(w, slot + 8)
            ch = 256
            if index < length(s):
                ch = byte(s, index)
            closing = False
            if kind == 1:
                if state == 0 or state == 1:
                    if state == 0 and ch == 93:
                        closing = True
                    else:
                        put(w, slot + 8, 4)
                        want_value = True
                else:
                    if state != 5:
                        put(w, 32, 15)
                        return 1
                    if ch == 44:
                        put(w, 0, index + 1)
                        put(w, slot + 8, 1)
                    else:
                        if ch == 93:
                            closing = True
                        else:
                            put(w, 32, 14)
                            return 1
            else:
                if state == 0 or state == 1:
                    if state == 0 and ch == 125:
                        closing = True
                    else:
                        if ch != 34:
                            put(w, 32, 16)
                            return 1
                        result = string_token(s, w)
                        if result != 0:
                            return 1
                        result = insert_key(s, o, w, slots, get(w, slot + 16), index + 1)
                        if result != 0:
                            return result
                        put(w, slot + 8, 2)
                else:
                    if state == 2:
                        if ch != 58:
                            put(w, 32, 17)
                            return 1
                        put(w, 0, index + 1)
                        put(w, slot + 8, 3)
                    else:
                        if state == 3:
                            put(w, slot + 8, 4)
                            want_value = True
                        else:
                            if state != 5:
                                put(w, 32, 19)
                                return 1
                            if ch == 44:
                                put(w, 0, index + 1)
                                put(w, slot + 8, 1)
                            else:
                                if ch == 125:
                                    closing = True
                                else:
                                    put(w, 32, 18)
                                    return 1
            if closing:
                put(w, 0, index + 1)
                depth = depth - 1
                if depth == 0:
                    done = True
                else:
                    put(w, 128 + (depth - 1) * 32 + 8, 5)
    put(w, 32, 13)
    return 1

def whitespace(s:readbuf, index:u64) -> u64:
    going = True
    while going and index < length(s):
        ch = byte(s, index)
        if ch == 32 or ch == 9 or ch == 10 or ch == 13:
            index = index + 1
        else:
            going = False
    return index

def atom(s:readbuf, index:u64) -> u64:
    size = length(s)
    if size - index >= 4:
        if byte(s, index) == 116 and byte(s, index + 1) == 114 and byte(s, index + 2) == 117 and byte(s, index + 3) == 101:
            return index + 4
        if byte(s, index) == 110 and byte(s, index + 1) == 117 and byte(s, index + 2) == 108 and byte(s, index + 3) == 108:
            return index + 4
    if size - index >= 5:
        if byte(s, index) == 102 and byte(s, index + 1) == 97 and byte(s, index + 2) == 108 and byte(s, index + 3) == 115 and byte(s, index + 4) == 101:
            return index + 5
    if byte(s, index) == 45:
        index = index + 1
    if index >= size:
        return 4294967295
    ch = byte(s, index)
    if ch < 48 or ch > 57:
        return 4294967295
    if ch == 48:
        return index + 1
    going = True
    while going and index < size:
        ch = byte(s, index)
        if ch >= 48 and ch <= 57:
            index = index + 1
        else:
            going = False
    return index

def string_token(s:readbuf, w:mutbuf) -> u64:
    index = get(w, 0) + 1
    hash = 14695981039346656037
    going = True
    while going:
        unit = decoded(s, index)
        cp = unit & 4294967295
        if cp == 1114113:
            put(w, 32, unit >> 32)
            return 1
        index = unit >> 32
        if cp == 1114112:
            going = False
        else:
            hash = (hash ^ cp) * 1099511628211
    put(w, 0, index)
    put(w, 40, hash)
    return 0

def insert_key(s:readbuf, o:mutbuf, w:mutbuf, slots:u64, scope:u64, start:u64) -> u64:
    # Every key belongs to its exact object's opening byte, not merely depth.
    # Closed and sibling scopes cannot alias. Entries never need tombstones.
    slot = (get(w, 40) ^ (scope * 1099511628211)) & (slots - 1)
    probes = 0
    while probes < slots:
        item = get(o, slot * 8)
        if item == 0:
            put(o, slot * 8, (scope << 32) | start)
            return 0
        if item >> 32 == scope:
            if same_key(s, item & 4294967295, start) == 1:
                return 4
        slot = (slot + 1) & (slots - 1)
        probes = probes + 1
    return 3

def same_key(s:readbuf, left:u64, right:u64) -> u64:
    going = True
    while going:
        l = decoded(s, left)
        r = decoded(s, right)
        cp = l & 4294967295
        if cp != r & 4294967295:
            return 0
        if cp == 1114112:
            return 1
        if cp == 1114113:
            return 0
        left = l >> 32
        right = r >> 32
    return 0

def hex4(s:readbuf, index:u64) -> u64:
    if index + 4 > length(s):
        return 4294967295
    count = 0
    value = 0
    while count < 4:
        ch = byte(s, index + count)
        digit = 16
        if ch >= 48 and ch <= 57:
            digit = ch - 48
        if ch >= 65 and ch <= 70:
            digit = ch - 55
        if ch >= 97 and ch <= 102:
            digit = ch - 87
        if digit == 16:
            return 4294967295
        value = value * 16 + digit
        count = count + 1
    return value

def decoded(s:readbuf, index:u64) -> u64:
    # Packed next-byte offset and Unicode scalar. On the invalid sentinel the
    # high word carries a reason instead of an offset. Escaped quotes remain
    # scalars; same_key and the arena decoder consume only admitted strings.
    size = length(s)
    if index >= size:
        return (8 << 32) | 1114113
    ch = byte(s, index)
    index = index + 1
    if ch == 34:
        return (index << 32) | 1114112
    if ch < 32:
        return (2 << 32) | 1114113
    if ch == 92:
        if index >= size:
            return (3 << 32) | 1114113
        esc = byte(s, index)
        index = index + 1
        if esc == 34 or esc == 92 or esc == 47:
            return (index << 32) | esc
        if esc == 98:
            return (index << 32) | 8
        if esc == 102:
            return (index << 32) | 12
        if esc == 110:
            return (index << 32) | 10
        if esc == 114:
            return (index << 32) | 13
        if esc == 116:
            return (index << 32) | 9
        if esc != 117 or index + 4 > size:
            return (4 << 32) | 1114113
        # The public str scanner tests four characters before their hex
        # spellings. A truncated non-ASCII escape must retain that ordering.
        cursor = index
        characters = 0
        while cursor < size and characters < 4:
            unit = byte(s, cursor)
            if unit < 128 or unit >= 192:
                characters = characters + 1
            cursor = cursor + 1
        if characters < 4:
            return (4 << 32) | 1114113
        cp = hex4(s, index)
        if cp == 4294967295:
            return (5 << 32) | 1114113
        index = index + 4
        if cp >= 55296 and cp <= 56319:
            if index + 6 > size:
                return (6 << 32) | 1114113
            if byte(s, index) != 92 or byte(s, index + 1) != 117:
                return (6 << 32) | 1114113
            low = hex4(s, index + 2)
            if low < 56320 or low > 57343:
                return (6 << 32) | 1114113
            cp = 65536 + (cp - 55296) * 1024 + low - 56320
            index = index + 6
        else:
            if cp >= 56320 and cp <= 57343:
                return (7 << 32) | 1114113
        return (index << 32) | cp
    if ch < 128:
        return (index << 32) | ch
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
    if needed == 0 or index + needed > size:
        return (20 << 32) | 1114113
    count = 0
    while count < needed:
        ch = byte(s, index)
        if ch < 128 or ch > 191:
            return (20 << 32) | 1114113
        cp = cp * 64 + (ch & 63)
        index = index + 1
        count = count + 1
    if cp < minimum or cp > 1114111:
        return (20 << 32) | 1114113
    if cp >= 55296 and cp <= 57343:
        return (20 << 32) | 1114113
    return (index << 32) | cp

def get(w:mutbuf, index:u64) -> u64:
    value = 0
    count = 0
    while count < 8:
        value = value | (byte(w, index + count) << (count * 8))
        count = count + 1
    return value

def put(w:mutbuf, index:u64, value:u64) -> u64:
    count = 0
    while count < 8:
        store(w, index + count, value >> (count * 8))
        count = count + 1
    return value

def digest_fragment(s: mutbuf, w: mutbuf, size: u64) -> u32:
    if size > 8388608:
        return 4294967293
    hash_put(w, 0, 1116352408)
    hash_put(w, 8, 1899447441)
    hash_put(w, 16, 3049323471)
    hash_put(w, 24, 3921009573)
    hash_put(w, 32, 961987163)
    hash_put(w, 40, 1508970993)
    hash_put(w, 48, 2453635748)
    hash_put(w, 56, 2870763221)
    hash_put(w, 64, 3624381080)
    hash_put(w, 72, 310598401)
    hash_put(w, 80, 607225278)
    hash_put(w, 88, 1426881987)
    hash_put(w, 96, 1925078388)
    hash_put(w, 104, 2162078206)
    hash_put(w, 112, 2614888103)
    hash_put(w, 120, 3248222580)
    hash_put(w, 128, 3835390401)
    hash_put(w, 136, 4022224774)
    hash_put(w, 144, 264347078)
    hash_put(w, 152, 604807628)
    hash_put(w, 160, 770255983)
    hash_put(w, 168, 1249150122)
    hash_put(w, 176, 1555081692)
    hash_put(w, 184, 1996064986)
    hash_put(w, 192, 2554220882)
    hash_put(w, 200, 2821834349)
    hash_put(w, 208, 2952996808)
    hash_put(w, 216, 3210313671)
    hash_put(w, 224, 3336571891)
    hash_put(w, 232, 3584528711)
    hash_put(w, 240, 113926993)
    hash_put(w, 248, 338241895)
    hash_put(w, 256, 666307205)
    hash_put(w, 264, 773529912)
    hash_put(w, 272, 1294757372)
    hash_put(w, 280, 1396182291)
    hash_put(w, 288, 1695183700)
    hash_put(w, 296, 1986661051)
    hash_put(w, 304, 2177026350)
    hash_put(w, 312, 2456956037)
    hash_put(w, 320, 2730485921)
    hash_put(w, 328, 2820302411)
    hash_put(w, 336, 3259730800)
    hash_put(w, 344, 3345764771)
    hash_put(w, 352, 3516065817)
    hash_put(w, 360, 3600352804)
    hash_put(w, 368, 4094571909)
    hash_put(w, 376, 275423344)
    hash_put(w, 384, 430227734)
    hash_put(w, 392, 506948616)
    hash_put(w, 400, 659060556)
    hash_put(w, 408, 883997877)
    hash_put(w, 416, 958139571)
    hash_put(w, 424, 1322822218)
    hash_put(w, 432, 1537002063)
    hash_put(w, 440, 1747873779)
    hash_put(w, 448, 1955562222)
    hash_put(w, 456, 2024104815)
    hash_put(w, 464, 2227730452)
    hash_put(w, 472, 2361852424)
    hash_put(w, 480, 2428436474)
    hash_put(w, 488, 2756734187)
    hash_put(w, 496, 3204031479)
    hash_put(w, 504, 3329325298)
    hash_put(w, 1024, 1779033703)
    hash_put(w, 1032, 3144134277)
    hash_put(w, 1040, 1013904242)
    hash_put(w, 1048, 2773480762)
    hash_put(w, 1056, 1359893119)
    hash_put(w, 1064, 2600822924)
    hash_put(w, 1072, 528734635)
    hash_put(w, 1080, 1541459225)
    padded = size + 72 & 18446744073709551552
    block = 0
    while block < padded:
        i = 0
        while i < 16:
            value = 0
            j = 0
            while j < 4:
                value = value << 8 | padded_byte(s, block + i * 4 + j, padded, size)
                j = j + 1
            hash_put(w, 512 + i * 8, value)
            i = i + 1
        while i < 64:
            x = hash_get(w, 512 + (i - 15) * 8)
            y = hash_get(w, 512 + (i - 2) * 8)
            sx = rotate(x, 7) ^ rotate(x, 18) ^ x >> 3
            sy = rotate(y, 17) ^ rotate(y, 19) ^ y >> 10
            value = hash_get(w, 512 + (i - 16) * 8) + sx + hash_get(w, 512 + (i - 7) * 8) + sy & 4294967295
            hash_put(w, 512 + i * 8, value)
            i = i + 1
        a = hash_get(w, 1024)
        b = hash_get(w, 1032)
        c = hash_get(w, 1040)
        d = hash_get(w, 1048)
        e = hash_get(w, 1056)
        f = hash_get(w, 1064)
        g = hash_get(w, 1072)
        h = hash_get(w, 1080)
        i = 0
        while i < 64:
            s1 = rotate(e, 6) ^ rotate(e, 11) ^ rotate(e, 25)
            choose_bits = e & f ^ (4294967295 ^ e) & g
            t1 = h + s1 + choose_bits + hash_get(w, i * 8) + hash_get(w, 512 + i * 8) & 4294967295
            s0 = rotate(a, 2) ^ rotate(a, 13) ^ rotate(a, 22)
            majority = a & b ^ a & c ^ b & c
            t2 = s0 + majority & 4294967295
            h = g
            g = f
            f = e
            e = d + t1 & 4294967295
            d = c
            c = b
            b = a
            a = t1 + t2 & 4294967295
            i = i + 1
        hash_put(w, 1024, hash_get(w, 1024) + a & 4294967295)
        hash_put(w, 1032, hash_get(w, 1032) + b & 4294967295)
        hash_put(w, 1040, hash_get(w, 1040) + c & 4294967295)
        hash_put(w, 1048, hash_get(w, 1048) + d & 4294967295)
        hash_put(w, 1056, hash_get(w, 1056) + e & 4294967295)
        hash_put(w, 1064, hash_get(w, 1064) + f & 4294967295)
        hash_put(w, 1072, hash_get(w, 1072) + g & 4294967295)
        hash_put(w, 1080, hash_get(w, 1080) + h & 4294967295)
        block = block + 64
    i = 0
    while i < 8:
        value = hash_get(w, 1024 + i * 8)
        j = 0
        while j < 4:
            store(w, get(w, 40) + 1088 + i * 4 + j, value >> (3 - j) * 8 & 255)
            j = j + 1
        i = i + 1
    return 32

def padded_byte(s: mutbuf, index: u64, total: u64, size: u64) -> u64:
    if index < size:
        return byte(s, 32 + index)
    if index == size:
        return 128
    if index < total - 8:
        return 0
    return size << 3 >> (total - 1 - index) * 8 & 255

def rotate(value: u64, shift: u64) -> u64:
    return value >> shift | value << 32 - shift & 4294967295
