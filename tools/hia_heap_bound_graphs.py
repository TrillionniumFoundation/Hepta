"""HIA graph and private-map primitives for the heap resource owner.

All graph order, edge sets and SCC decisions are executable HIA. This module
is authoring input and is never imported by an installed runtime. The caller
supplies get/put, same_text, size_of, tag and ordinary typed transport readers.
Arena offsets 64/72 hold used bytes and the minimum requested extent. A zero
allocation result requests more private storage; it never authorizes a bound.
Graphs have a two-word header followed by six-word node records. Names refer
to immutable text nodes in the copied source packet. No source-node quota or
fixed graph capacity is introduced here.
"""

BODY = r'''
def heap_alloc(w:mutbuf, amount:u64) -> u64:
    at = get(w, 64)
    if at > length(w) or amount > 18446744073709551615 - at - 7:
        put(w, 80, 1)
        return 0
    stop = (at + amount + 7) & 18446744073709551608
    if stop > length(w):
        if stop > get(w, 72):
            put(w, 72, stop)
        return 0
    put(w, 64, stop)
    fill_range(w, at, stop - at, 0)
    return at

def heap_copy(w:mutbuf, dest:u64, source:u64, count:u64) -> u64:
    index = 0
    while index < count:
        store(w, dest + index, byte(w, source + index))
        index = index + 1
    return 0

def heap_text_cmp(w:mutbuf, left:u64, right:u64) -> u64:
    a = size_of(w, left)
    b = size_of(w, right)
    index = 0
    while index < a and index < b:
        first = byte(w, left + 16 + index)
        second = byte(w, right + 16 + index)
        if first != second:
            return choose(first < second, 1, 2)
        index = index + 1
    if a == b:
        return 0
    return choose(a < b, 1, 2)

def heap_graph(w:mutbuf, count:u64) -> u64:
    if count > (18446744073709551615 - 16) // 48:
        put(w, 80, 1)
        return 0
    graph = heap_alloc(w, 16 + count * 48)
    if graph == 0:
        return 0
    put(w, graph, count)
    put(w, graph + 8, graph + 16)
    return graph

def heap_node(w:mutbuf, graph:u64, index:u64) -> u64:
    return get(w, graph + 8) + index * 48

def heap_name(w:mutbuf, graph:u64, index:u64) -> u64:
    return get(w, heap_node(w, graph, index))

def heap_named(w:mutbuf, graph:u64, name:u64) -> u64:
    index = 0
    while index < get(w, graph):
        if same_text(w, heap_name(w, graph, index), name) != 0:
            return index
        index = index + 1
    return 18446744073709551615

def heap_has_edge(w:mutbuf, graph:u64, source:u64, target:u64) -> u64:
    edge = get(w, heap_node(w, graph, source) + 16)
    while edge != 0:
        if get(w, edge + 8) == target:
            return 1
        edge = get(w, edge)
    return 0

def heap_edge(w:mutbuf, graph:u64, source:u64, target:u64) -> u64:
    if source >= get(w, graph) or target >= get(w, graph):
        put(w, 80, 2)
        return 0
    if heap_has_edge(w, graph, source, target) != 0:
        return 1
    edge = heap_alloc(w, 16)
    if edge == 0:
        return 0
    node = heap_node(w, graph, source)
    put(w, edge, get(w, node + 16))
    put(w, edge + 8, target)
    put(w, node + 16, edge)
    node = heap_node(w, graph, target)
    put(w, node + 24, get(w, node + 24) + 1)
    return 1

def heap_sort_ids(w:mutbuf, graph:u64, values:u64, count:u64) -> u64:
    index = 1
    while index < count:
        value = get(w, values + index * 8)
        at = index
        going = True
        while going and at != 0:
            previous = get(w, values + (at - 1) * 8)
            if heap_text_cmp(w, heap_name(w, graph, value), heap_name(w, graph, previous)) != 1:
                going = False
            else:
                put(w, values + at * 8, previous)
                at = at - 1
        put(w, values + at * 8, value)
        index = index + 1
    return 0

def heap_neighbors(w:mutbuf, graph:u64, source:u64) -> u64:
    count = 0
    edge = get(w, heap_node(w, graph, source) + 16)
    while edge != 0:
        count = count + 1
        edge = get(w, edge)
    values = heap_alloc(w, 8 + count * 8)
    if values == 0:
        return 0
    put(w, values, count)
    edge = get(w, heap_node(w, graph, source) + 16)
    index = 0
    while edge != 0:
        put(w, values + 8 + index * 8, get(w, edge + 8))
        index = index + 1
        edge = get(w, edge)
    heap_sort_ids(w, graph, values + 8, count)
    return values

def heap_topological(w:mutbuf, graph:u64) -> u64:
    count = get(w, graph)
    output = heap_alloc(w, 8 + count * 8)
    queue = heap_alloc(w, count * 8)
    degrees = heap_alloc(w, count * 8)
    if output == 0 or queue == 0 or degrees == 0:
        return 0
    tail = 0
    index = 0
    while index < count:
        degree = get(w, heap_node(w, graph, index) + 24)
        put(w, degrees + index * 8, degree)
        if degree == 0:
            put(w, queue + tail * 8, index)
            tail = tail + 1
        index = index + 1
    heap_sort_ids(w, graph, queue, tail)
    head = 0
    used = 0
    while head < tail:
        source = get(w, queue + head * 8)
        head = head + 1
        put(w, output + 8 + used * 8, source)
        used = used + 1
        neighbors = heap_neighbors(w, graph, source)
        if neighbors == 0:
            return 0
        index = 0
        while index < get(w, neighbors):
            target = get(w, neighbors + 8 + index * 8)
            degree = get(w, degrees + target * 8) - 1
            put(w, degrees + target * 8, degree)
            if degree == 0:
                put(w, queue + tail * 8, target)
                tail = tail + 1
            index = index + 1
    put(w, output, used)
    if used != count:
        put(w, 80, 3)
        return 18446744073709551615
    return output

def heap_reverse_graph(w:mutbuf, graph:u64) -> u64:
    count = get(w, graph)
    reverse = heap_graph(w, count)
    if reverse == 0:
        return 0
    source = 0
    while source < count:
        put(w, heap_node(w, reverse, source), heap_name(w, graph, source))
        source = source + 1
    source = 0
    while source < count:
        edge = get(w, heap_node(w, graph, source) + 16)
        while edge != 0:
            if heap_edge(w, reverse, get(w, edge + 8), source) == 0:
                return 0
            edge = get(w, edge)
        source = source + 1
    return reverse

def heap_finish_order(w:mutbuf, graph:u64) -> u64:
    count = get(w, graph)
    names = heap_alloc(w, count * 8)
    seen = heap_alloc(w, count * 8)
    stack = heap_alloc(w, count * 24)
    finished = heap_alloc(w, 8 + count * 8)
    if names == 0 or seen == 0 or stack == 0 or finished == 0:
        return 0
    index = 0
    while index < count:
        put(w, names + index * 8, index)
        index = index + 1
    heap_sort_ids(w, graph, names, count)
    used = 0
    index = 0
    while index < count:
        start = get(w, names + index * 8)
        if get(w, seen + start * 8) == 0:
            neighbors = heap_neighbors(w, graph, start)
            if neighbors == 0:
                return 0
            put(w, seen + start * 8, 1)
            put(w, stack, start)
            put(w, stack + 8, neighbors)
            put(w, stack + 16, 0)
            depth = 1
            while depth != 0:
                frame = stack + (depth - 1) * 24
                node = get(w, frame)
                targets = get(w, frame + 8)
                cursor = get(w, frame + 16)
                if cursor == get(w, targets):
                    put(w, finished + 8 + used * 8, node)
                    used = used + 1
                    depth = depth - 1
                else:
                    target = get(w, targets + 8 + cursor * 8)
                    put(w, frame + 16, cursor + 1)
                    if get(w, seen + target * 8) == 0:
                        neighbors = heap_neighbors(w, graph, target)
                        if neighbors == 0:
                            return 0
                        put(w, seen + target * 8, 1)
                        frame = stack + depth * 24
                        put(w, frame, target)
                        put(w, frame + 8, neighbors)
                        put(w, frame + 16, 0)
                        depth = depth + 1
        index = index + 1
    put(w, finished, used)
    return finished

def heap_components(w:mutbuf, graph:u64) -> u64:
    count = get(w, graph)
    reverse = heap_reverse_graph(w, graph)
    finished = heap_finish_order(w, graph)
    seen = heap_alloc(w, count * 8)
    pending = heap_alloc(w, count * 8)
    members = heap_alloc(w, count * 8)
    components = heap_alloc(w, 8 + count * 8)
    if reverse == 0 or finished == 0 or seen == 0 or pending == 0 or members == 0 or components == 0:
        return 0
    cursor = get(w, finished)
    used = 0
    while cursor != 0:
        cursor = cursor - 1
        start = get(w, finished + 8 + cursor * 8)
        if get(w, seen + start * 8) == 0:
            put(w, seen + start * 8, 1)
            put(w, pending, start)
            tail = 1
            size = 0
            while tail != 0:
                tail = tail - 1
                node = get(w, pending + tail * 8)
                put(w, members + size * 8, node)
                size = size + 1
                neighbors = heap_neighbors(w, reverse, node)
                if neighbors == 0:
                    return 0
                index = 0
                while index < get(w, neighbors):
                    source = get(w, neighbors + 8 + index * 8)
                    if get(w, seen + source * 8) == 0:
                        put(w, seen + source * 8, 1)
                        put(w, pending + tail * 8, source)
                        tail = tail + 1
                    index = index + 1
            component = heap_alloc(w, 8 + size * 8)
            if component == 0:
                return 0
            put(w, component, size)
            heap_copy(w, component + 8, members, size * 8)
            heap_sort_ids(w, graph, component + 8, size)
            put(w, components + 8 + used * 8, component)
            used = used + 1
    put(w, components, used)
    index = 1
    while index < used:
        value = get(w, components + 8 + index * 8)
        at = index
        going = True
        while going and at != 0:
            previous = get(w, components + at * 8)
            first = heap_name(w, graph, get(w, value + 8))
            second = heap_name(w, graph, get(w, previous + 8))
            if heap_text_cmp(w, first, second) != 1:
                going = False
            else:
                put(w, components + 8 + at * 8, previous)
                at = at - 1
        put(w, components + 8 + at * 8, value)
        index = index + 1
    return components

def heap_map(w:mutbuf) -> u64:
    return heap_alloc(w, 16)

def heap_map_entry(w:mutbuf, table:u64, key:u64) -> u64:
    entry = get(w, table)
    while entry != 0:
        if same_text(w, get(w, entry + 8), key) != 0:
            return entry
        entry = get(w, entry)
    return 0

def heap_map_get(w:mutbuf, table:u64, key:u64) -> u64:
    entry = heap_map_entry(w, table, key)
    if entry == 0:
        return 18446744073709551615
    return get(w, entry + 16)

def heap_map_put(w:mutbuf, table:u64, key:u64, value:u64) -> u64:
    entry = heap_map_entry(w, table, key)
    if entry == 0:
        entry = heap_alloc(w, 24)
        if entry == 0:
            return 0
        put(w, entry, get(w, table))
        put(w, entry + 8, key)
        put(w, table, entry)
        put(w, table + 8, get(w, table + 8) + 1)
    put(w, entry + 16, value)
    return 1

def heap_map_drop(w:mutbuf, table:u64, key:u64) -> u64:
    previous = 0
    entry = get(w, table)
    while entry != 0:
        if same_text(w, get(w, entry + 8), key) != 0:
            if previous == 0:
                put(w, table, get(w, entry))
            else:
                put(w, previous, get(w, entry))
            put(w, table + 8, get(w, table + 8) - 1)
            return 1
        previous = entry
        entry = get(w, entry)
    return 0

def heap_map_copy(w:mutbuf, table:u64) -> u64:
    target = heap_map(w)
    if target == 0:
        return 0
    entry = get(w, table)
    while entry != 0:
        if heap_map_put(w, target, get(w, entry + 8), get(w, entry + 16)) == 0:
            return 0
        entry = get(w, entry)
    return target
'''
