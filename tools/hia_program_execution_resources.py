"""Resource, loan, byte-memory and argument transport HIA for the finite VM.

Only generic raw allocation/free/window requests leave the native machine.
All permission, extent, deterministic failure, budget and ledger decisions
remain in this emitted program, including stopped iterative chain destruction.
"""

BODY = r'''
def vm_type_width(typ:u64) -> u64:
    if typ == 1 or typ == 5:
        return 8
    if typ == 2 or typ == 6:
        return 16
    if typ == 3 or typ == 7:
        return 32
    return 64

def vm_type_signed(typ:u64) -> bool:
    return typ <= 4 or typ == 9

def vm_type_mask(typ:u64) -> u64:
    width = vm_type_width(typ)
    if width == 64:
        return N
    return (1 << width) - 1

def resource_slot(w:mutbuf, ident:u64) -> u64:
    capacity = get(w, 448)
    if ident == 0 or capacity == 0:
        return 0
    index = (ident * 11400714819323198485) & (capacity - 1)
    count = 0
    while count < capacity:
        entry = get(w, 440) + index * 16
        key = get(w, entry)
        if key == 0:
            return 0
        if key == ident:
            return entry
        index = (index + 1) & (capacity - 1)
        count = count + 1
    return 0

def resource(w:mutbuf, ident:u64) -> u64:
    entry = resource_slot(w, ident)
    if entry == 0:
        return 0
    return get(w, entry + 8)

def reserve_resources(w:mutbuf, count:u64) -> u64:
    if count == 0:
        return 1
    capacity = get(w, 448)
    if capacity == 0:
        capacity = 16
    while capacity < (get(w, 456) + count) * 2:
        capacity = capacity * 2
    if capacity != get(w, 448) or get(w, 960) + count > capacity - (capacity >> 2):
        table = arena(w, capacity * 16)
        if table == 0:
            return 0
        fill_range(w, table, capacity * 16, 0)
        old = get(w, 440)
        index = 0
        while index < get(w, 448):
            key = get(w, old + index * 16)
            if key != 0 and key != N:
                target = (key * 11400714819323198485) & (capacity - 1)
                while get(w, table + target * 16) != 0:
                    target = (target + 1) & (capacity - 1)
                put(w, table + target * 16, key)
                put(w, table + target * 16 + 8, get(w, old + index * 16 + 8))
            index = index + 1
        put(w, 440, table)
        put(w, 448, capacity)
        put(w, 960, get(w, 456))
        if old != 0:
            arena_free(w, old)
    if get(w, 888) < count:
        amount = count - get(w, 888)
        if amount < 64:
            amount = 64
        records = arena(w, amount * 80)
        if records == 0:
            return 0
        index = 0
        while index < amount:
            record = records + index * 80
            put(w, record + 72, get(w, 464))
            put(w, 464, record)
            index = index + 1
        put(w, 880, get(w, 880) + amount)
        put(w, 888, get(w, 888) + amount)
    return 1

def create_resource(w:mutbuf, kind:u64) -> u64:
    record = get(w, 464)
    if record == 0:
        stop(w, 5, 250, 0)
        return 0
    put(w, 464, get(w, record + 72))
    put(w, 888, get(w, 888) - 1)
    fill_range(w, record, 80, 0)
    ident = get(w, 432) + 1
    put(w, 432, ident)
    put(w, record, ident)
    put(w, record + 8, kind)
    index = (ident * 11400714819323198485) & (get(w, 448) - 1)
    while get(w, get(w, 440) + index * 16) != 0 and get(w, get(w, 440) + index * 16) != N:
        index = (index + 1) & (get(w, 448) - 1)
    entry = get(w, 440) + index * 16
    if get(w, entry) == 0:
        put(w, 960, get(w, 960) + 1)
    put(w, entry, ident)
    put(w, entry + 8, record)
    put(w, 456, get(w, 456) + 1)
    return ident

def delete_resource(w:mutbuf, ident:u64) -> u64:
    entry = resource_slot(w, ident)
    if entry == 0:
        return stop(w, 5, 250, 0)
    record = get(w, entry + 8)
    put(w, entry, N)
    put(w, entry + 8, 0)
    put(w, record, 0)
    put(w, record + 72, get(w, 464))
    put(w, 464, record)
    put(w, 888, get(w, 888) + 1)
    put(w, 456, get(w, 456) - 1)
    return 0

def underlying(w:mutbuf, ident:u64) -> u64:
    count = 0
    record = resource(w, ident)
    while record != 0 and get(w, record + 8) == 2:
        count = count + 1
        if count > get(w, 456):
            stop(w, 5, 232, 0)
            return 0
        record = resource(w, get(w, record + 24))
        if record == 0:
            stop(w, 5, 232, 0)
            return 0
    if record == 0 or get(w, record + 8) != 1:
        stop(w, 5, 231, 0)
        return 0
    return record

def chain_head(w:mutbuf, ident:u64) -> u64:
    record = resource(w, ident)
    if record == 0 or get(w, record + 8) != 3:
        stop(w, 5, 230, 0)
        return 0
    return get(w, record + 24)

def new_owner(w:mutbuf, handle:u64, size:u64) -> u64:
    ident = create_resource(w, 1)
    record = resource(w, ident)
    put(w, record + 16, get(w, 288) + 1)
    put(w, record + 24, handle)
    put(w, record + 32, size)
    put(w, 288, get(w, 288) + 1)
    put(w, 304, get(w, 304) + 1)
    if size != 0:
        put(w, 264, get(w, 264) + 1)
    put(w, 312, get(w, 312) + size)
    if get(w, 312) > get(w, 320):
        put(w, 320, get(w, 312))
    return ident

def new_view(w:mutbuf, parent:u64, mutable:u64, local:u64) -> u64:
    ident = create_resource(w, 2)
    record = resource(w, ident)
    put(w, record + 24, parent)
    put(w, record + 32, mutable)
    if local != 0:
        put(w, 328, get(w, 328) + 1)
    else:
        put(w, record + 40, 1)
    return ident

def new_chain(w:mutbuf, head:u64) -> u64:
    ident = create_resource(w, 3)
    record = resource(w, ident)
    put(w, record + 16, get(w, 344) + 1)
    put(w, record + 24, head)
    put(w, 344, get(w, 344) + 1)
    put(w, 360, get(w, 360) + 1)
    return ident

def consume_chain(w:mutbuf, ident:u64) -> u64:
    head = chain_head(w, ident)
    if get(w, 88) != 0:
        return 0
    delete_resource(w, ident)
    put(w, 352, get(w, 352) + 1)
    put(w, 360, get(w, 360) - 1)
    return head

def drop_owner(w:mutbuf, ident:u64, next_phase:u64) -> u64:
    record = underlying(w, ident)
    if get(w, 88) != 0:
        return 0
    if get(w, record + 40) != 0:
        return stop(w, 5, 233, 0)
    size = get(w, record + 32)
    handle = get(w, record + 24)
    delete_resource(w, get(w, record))
    put(w, 296, get(w, 296) + 1)
    put(w, 304, get(w, 304) - 1)
    put(w, 312, get(w, 312) - size)
    if size != 0:
        put(w, 272, get(w, 272) + 1)
        put(w, 688, next_phase)
        return issue(w, 4, handle, 0, 0, 0)
    put(w, 8, next_phase)
    return 0

def consume_operand(w:mutbuf, index:u64) -> u64:
    names = field(w, get(w, 576), 16)
    return frame_consume(w, get(w, 584), element(w, names, index))

def allocation(w:mutbuf, size:u64, optional:u64, purpose:u64) -> u64:
    put(w, 592, purpose)
    put(w, 600, size)
    if size == 0:
        return allocation_done(w, new_owner(w, 0, 0), 1)
    if size > 9223372036854775807:
        if optional != 0:
            return allocation_done(w, new_owner(w, 0, 0), 0)
        return stop(w, 2, 5, 0)
    if size > get(w, 400) - get(w, 312):
        return stop(w, 3, 21, 0)
    put(w, 280, get(w, 280) + 1)
    if get(w, 424) != 0 and get(w, 424) <= 64 and get(w, 416) == get(w, 280):
        if optional != 0:
            return allocation_done(w, new_owner(w, 0, 0), 0)
        return stop(w, 2, 6, 0)
    put(w, 8, 5)
    return issue(w, 3, size, 0, 0, 0)

def allocation_reply(w:mutbuf) -> u64:
    handle = get(w, 608)
    if handle == 0:
        if get(w, 592) == 1:
            return stop(w, 2, 6, 0)
        return allocation_done(w, new_owner(w, 0, 0), 0)
    return allocation_done(w, new_owner(w, handle, get(w, 600)), 1)

def allocation_done(w:mutbuf, owner:u64, ok:u64) -> u64:
    purpose = get(w, 592)
    if purpose == 1 or purpose == 2:
        put(w, 616, owner)
        put(w, 624, ok)
        put(w, 640, purpose)
        return finish_operation(w)
    if purpose != 3:
        return stop(w, 5, 250, 0)
    head = chain_head(w, get(w, 648))
    payload = get(w, 656)
    if ok != 0:
        node = create_resource(w, 4)
        record = resource(w, node)
        put(w, record + 48, payload)
        put(w, record + 56, owner)
        put(w, record + 64, head)
        put(w, 368, get(w, 368) + 1)
        fallback = new_owner(w, 0, 0)
        consume_chain(w, get(w, 648))
        put(w, 616, new_chain(w, node))
        put(w, 624, fallback)
    else:
        drop_owner(w, owner, 4)
        consume_chain(w, get(w, 648))
        put(w, 616, new_chain(w, head))
        put(w, 624, payload)
    put(w, 632, ok)
    put(w, 640, 3)
    consume_operand(w, 0)
    consume_operand(w, 1)
    return finish_operation(w)

def resource_operation(w:mutbuf, code:u64) -> u64:
    value = get(w, 800)
    if code == 28 or code == 29:
        return allocation(w, value, choose(code == 29, 1, 0), code - 27)
    if code == 30:
        record = underlying(w, value)
        if get(w, 88) != 0:
            return 0
        put(w, 616, get(w, record + 32))
        put(w, 640, 1)
    elif code == 31:
        put(w, 616, new_chain(w, 0))
        put(w, 640, 1)
    elif code == 32:
        chain_head(w, value)
        underlying(w, get(w, 808))
        if get(w, 88) != 0:
            return 0
        put(w, 648, value)
        put(w, 656, get(w, 808))
        return allocation(w, 24, 1, 3)
    elif code == 33:
        head = consume_chain(w, value)
        if get(w, 88) != 0:
            return 0
        if head == 0:
            put(w, 616, new_chain(w, 0))
            put(w, 624, new_owner(w, 0, 0))
            put(w, 632, 0)
            put(w, 640, 3)
            consume_operand(w, 0)
        else:
            put(w, 672, head)
            record = resource(w, head)
            put(w, 656, get(w, record + 48))
            put(w, 680, get(w, record + 64))
            return drop_owner(w, get(w, record + 56), 12)
    elif code == 34:
        head = chain_head(w, value)
        if get(w, 88) != 0:
            return 0
        put(w, 616, choose(head == 0, 1, 0))
        put(w, 640, 1)
    elif code == 35 or code == 36:
        head = chain_head(w, value)
        if get(w, 88) != 0:
            return 0
        if head == 0:
            return stop(w, 2, 7, 0)
        payload = get(w, resource(w, head) + 48)
        underlying(w, payload)
        if get(w, 88) != 0:
            return 0
        put(w, 616, new_view(w, payload, choose(code == 36, 1, 0), 1))
        put(w, 640, 1)
    elif code == 37 or code == 38:
        underlying(w, value)
        if get(w, 88) != 0:
            return 0
        put(w, 616, new_view(w, value, choose(code == 38, 1, 0), 1))
        put(w, 640, 1)
    elif code == 39:
        underlying(w, value)
        if get(w, 88) != 0:
            return 0
        record = resource(w, value)
        if get(w, record + 8) != 2:
            return stop(w, 5, 234, 0)
        delete_resource(w, value)
        put(w, 336, get(w, 336) + 1)
        consume_operand(w, 0)
    elif code == 40:
        record = resource(w, value)
        if record != 0 and get(w, record + 8) == 3:
            chain_head(w, value)
        else:
            underlying(w, value)
        if get(w, 88) != 0:
            return 0
        put(w, 616, value)
        put(w, 640, 1)
        consume_operand(w, 0)
    elif code == 41:
        record = resource(w, value)
        if record != 0 and get(w, record + 8) == 3:
            head = consume_chain(w, value)
            if get(w, 88) != 0:
                return 0
            put(w, 672, head)
            put(w, 8, 15)
            return 0
        return drop_owner(w, value, 11)
    elif code >= 42 and code <= 49:
        return memory_guard(w, code)
    else:
        return stop(w, 5, 255, 0)
    return finish_operation(w)

def consumed_owner(w:mutbuf) -> u64:
    consume_operand(w, 0)
    return finish_operation(w)

def popped_chain(w:mutbuf) -> u64:
    put(w, 376, get(w, 376) + 1)
    delete_resource(w, get(w, 672))
    put(w, 616, new_chain(w, get(w, 680)))
    put(w, 624, get(w, 656))
    put(w, 632, 1)
    put(w, 640, 3)
    consume_operand(w, 0)
    return finish_operation(w)

def chain_drop_next(w:mutbuf) -> u64:
    node = get(w, 672)
    if node == 0:
        consume_operand(w, 0)
        return finish_operation(w)
    if tick(w) == 0:
        return 0
    record = resource(w, node)
    put(w, 664, get(w, record + 56))
    put(w, 680, get(w, record + 64))
    return drop_owner(w, get(w, record + 48), 13)

def chain_storage_drop(w:mutbuf) -> u64:
    return drop_owner(w, get(w, 664), 14)

def chain_node_done(w:mutbuf) -> u64:
    put(w, 376, get(w, 376) + 1)
    delete_resource(w, get(w, 672))
    put(w, 672, get(w, 680))
    put(w, 8, 15)
    return 0

def view_mutable(w:mutbuf, ident:u64) -> bool:
    record = resource(w, ident)
    return record != 0 and get(w, record + 8) == 2 and get(w, record + 32) != 0

def view_live(w:mutbuf, ident:u64) -> bool:
    record = resource(w, ident)
    return record != 0 and get(w, record + 8) == 2

def memory_guard(w:mutbuf, code:u64) -> u64:
    owner = underlying(w, get(w, 800))
    if get(w, 88) != 0:
        return 0
    extent = get(w, owner + 32)
    handle = get(w, owner + 24)
    put(w, 976, 0)
    put(w, 984, handle)
    put(w, 992, 0)
    put(w, 1000, extent)
    if code == 42:
        if get(w, 808) >= extent:
            return stop(w, 2, 8, 0)
        put(w, 976, handle)
        put(w, 984, 0)
        put(w, 992, extent)
        put(w, 1000, 0)
    elif code == 43:
        if view_mutable(w, get(w, 800)) == False:
            return stop(w, 5, 235, 0)
        if get(w, 808) >= extent:
            return stop(w, 2, 9, 0)
    elif code == 44:
        if view_mutable(w, get(w, 800)) == False:
            return stop(w, 5, 236, 0)
    elif code == 45 or code == 48:
        return copy_guard(w, owner, code)
    elif code == 46:
        if view_mutable(w, get(w, 800)) == False:
            return stop(w, 5, 239, 0)
        destination = get(w, 808)
        source = get(w, 816)
        size = get(w, 824)
        if destination > extent or source > extent:
            return stop(w, 2, 11, 0)
        if size > extent - destination or size > extent - source:
            return stop(w, 2, 11, 0)
    elif code == 47:
        if view_mutable(w, get(w, 800)) == False:
            return stop(w, 5, 242, 0)
        if get(w, 808) >= extent or get(w, 816) >= extent:
            return stop(w, 2, 14, 0)
    elif code == 49:
        if view_mutable(w, get(w, 800)) == False:
            return stop(w, 5, 240, 0)
        offset = get(w, 808)
        size = get(w, 816)
        if offset > extent or size > extent - offset:
            return stop(w, 2, 13, 0)
    put(w, 8, 7)
    return issue(w, 5, get(w, 976), get(w, 984), get(w, 992), get(w, 1000))

def copy_guard(w:mutbuf, destination:u64, code:u64) -> u64:
    source = underlying(w, get(w, 808))
    if get(w, 88) != 0:
        return 0
    if code == 45:
        if view_mutable(w, get(w, 800)) == False or view_live(w, get(w, 808)) == False:
            return stop(w, 5, 237, 0)
        if destination == source:
            return stop(w, 5, 238, 0)
        if get(w, 816) > get(w, destination + 32) or get(w, 816) > get(w, source + 32):
            return stop(w, 2, 10, 0)
    else:
        if view_mutable(w, get(w, 800)) == False or view_live(w, get(w, 808)) == False or destination == source:
            return stop(w, 5, 241, 0)
        dest_offset = get(w, 816)
        src_offset = get(w, 824)
        size = get(w, 832)
        if dest_offset > get(w, destination + 32) or src_offset > get(w, source + 32):
            return stop(w, 2, 12, 0)
        if size > get(w, destination + 32) - dest_offset or size > get(w, source + 32) - src_offset:
            return stop(w, 2, 12, 0)
    put(w, 976, get(w, source + 24))
    put(w, 992, get(w, source + 32))
    put(w, 8, 7)
    return issue(w, 5, get(w, 976), get(w, 984), get(w, 992), get(w, 1000))

def memory_operation(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    code = get(w, 696)
    if code == 42:
        put(w, 616, byte(s, get(w, 808)))
        put(w, 640, 1)
    elif code == 43:
        store(o, get(w, 808), get(w, 816))
    elif code == 44:
        fill_range(o, 0, length(o), get(w, 808))
    elif code == 45:
        copy_in(o, s, 0, 0, get(w, 816))
    elif code == 46:
        move_within(o, get(w, 808), get(w, 816), get(w, 824))
    elif code == 47:
        left = byte(o, get(w, 808))
        right = byte(o, get(w, 816))
        store(o, get(w, 808), right)
        store(o, get(w, 816), left)
    elif code == 48:
        copy_in(o, s, get(w, 816), get(w, 824), get(w, 832))
    elif code == 49:
        fill_range(o, get(w, 808), get(w, 816), get(w, 824))
    else:
        return stop(w, 5, 250, 0)
    return finish_operation(w)

def returned_view(w:mutbuf, value:u64, parent:u64, typ:u64) -> u64:
    underlying(w, value)
    underlying(w, parent)
    if get(w, 88) != 0:
        return 0
    if view_live(w, value) == False or view_live(w, parent) == False:
        stop(w, 5, 243, 0)
        return 0
    if typ == 15 and (view_mutable(w, value) == False or view_mutable(w, parent) == False):
        stop(w, 5, 243, 0)
        return 0
    if value == parent:
        return new_view(w, parent, choose(typ == 15, 1, 0), 1)
    if get(w, resource(w, value) + 24) != parent:
        stop(w, 5, 244, 0)
        return 0
    return value

def argument_scalar(w:mutbuf, row:u64, typ:u64) -> u64:
    kind = decimal(w, element(w, row, 0))
    first = decimal(w, element(w, row, 1))
    bits = decimal(w, element(w, row, 2))
    value = decimal(w, element(w, row, 3))
    if typ == 12 and kind == 0:
        return 0
    if typ == 11 and kind == 1 and first <= 1:
        return first
    if typ >= 1 and typ <= 10 and kind == 2 and first <= 1:
        width = vm_type_width(typ)
        if first == 0:
            if bits <= width - choose(vm_type_signed(typ), 1, 0):
                return value & vm_type_mask(typ)
        elif vm_type_signed(typ) and bits <= width:
            if bits < width or (value & vm_type_mask(typ)) == (1 << (width - 1)):
                return value & vm_type_mask(typ)
    stop(w, 4, 42, 0)
    return 0

def arguments(s:readbuf, w:mutbuf) -> u64:
    if get(w, 896) == 0:
        if src_validate(s, w) == 0 or src_word(s, 0) != 5 or src_word(s, 16) != 2:
            return stop(w, 5, 250, 0)
        at = arena(w, length(s))
        if at == 0:
            return 0
        copy_in(w, s, at, 0, length(s))
        put(w, 896, at)
        put(w, 920, element(w, at, 0))
        put(w, 912, element(w, at, 1))
        if total(w, get(w, 920)) != get(w, 536):
            return stop(w, 5, 250, 0)
    if get(w, 904) == 0:
        at = arena(w, get(w, 536) * 8)
        if at == 0:
            return 0
        put(w, 904, at)
    if get(w, 928) == 0:
        at = arena(w, total(w, get(w, 912)) * 16)
        if at == 0:
            return 0
        put(w, 928, at)
    if get(w, 944) == 0:
        if reserve_resources(w, total(w, get(w, 912)) * 2) == 0:
            return 0
        install_external(w)
        put(w, 944, 1)
    parameter = get(w, get(w, 736) + 8) + 24
    row = get(w, 920) + 24
    index = 0
    while index < get(w, 536):
        typ = type_id(w, field(w, parameter, 19))
        value = 0
        if typ <= 12:
            value = argument_scalar(w, row, typ)
        else:
            object_index = decimal(w, element(w, row, 1))
            if get(w, 560) != 1 or decimal(w, element(w, row, 0)) != 8 or object_index >= total(w, get(w, 912)):
                return stop(w, 4, 42, 0)
            value = get(w, get(w, 928) + object_index * 16 + 8)
            if (typ != 14 and typ != 15) or (typ == 15 and view_mutable(w, value) == False):
                return stop(w, 4, 42, 0)
        if get(w, 88) != 0:
            return 0
        put(w, get(w, 904) + index * 8, value)
        parameter = end(w, parameter)
        row = end(w, row)
        index = index + 1
    put(w, 744, get(w, 904))
    put(w, 752, 0)
    put(w, 768, 0)
    put(w, 8, 3)
    return 0

def install_external(w:mutbuf) -> u64:
    rows = get(w, 912)
    row = rows + 24
    index = 0
    while index < total(w, rows):
        ident = create_resource(w, 1)
        record = resource(w, ident)
        put(w, record + 16, index + 1)
        put(w, record + 24, decimal(w, element(w, row, 0)))
        put(w, record + 32, decimal(w, element(w, row, 1)))
        put(w, record + 40, 1)
        view = new_view(w, ident, decimal(w, element(w, row, 2)), 0)
        put(w, get(w, 928) + index * 16, ident)
        put(w, get(w, 928) + index * 16 + 8, view)
        row = end(w, row)
        index = index + 1
    put(w, 568, index)
    return 0

def validate_ledger(w:mutbuf) -> u64:
    allocated = get(w, 264)
    freed = get(w, 272)
    created = get(w, 288)
    dropped = get(w, 296)
    live = get(w, 304)
    if freed > allocated or allocated > get(w, 280) or allocated > created or freed > dropped or dropped > created or live != created - dropped:
        return 0
    nonempty = allocated - freed
    if nonempty > live or nonempty > get(w, 312) or ((nonempty == 0) != (get(w, 312) == 0)):
        return 0
    if get(w, 336) > get(w, 328):
        return 0
    loans = get(w, 328) - get(w, 336)
    if live == 0 and get(w, 568) == 0 and loans != 0:
        return 0
    if get(w, 312) > get(w, 320) or get(w, 320) > get(w, 400):
        return 0
    if get(w, 384) != 0:
        if get(w, 352) > get(w, 344) or get(w, 360) != get(w, 344) - get(w, 352) or get(w, 376) > get(w, 368):
            return 0
        if (get(w, 368) - get(w, 376)) * 2 > live:
            return 0
    if get(w, 88) == 1:
        if live != 0 or loans != 0 or (get(w, 384) != 0 and (get(w, 360) != 0 or get(w, 368) != get(w, 376))):
            return 0
    elif get(w, 88) == 2:
        if get(w, 96) == 0 or get(w, 96) > 19:
            return 0
    elif get(w, 88) == 3:
        if get(w, 96) < 20 or get(w, 96) > 22:
            return 0
    else:
        return 0
    if get(w, 88) == 3 and get(w, 96) == 20:
        if get(w, 256) != get(w, 392) + 1:
            return 0
    elif get(w, 256) == 0 or get(w, 256) > get(w, 392):
        return 0
    return external_ledger(w)

def external_ledger(w:mutbuf) -> u64:
    index = 0
    while index < get(w, 568):
        owner_id = get(w, get(w, 928) + index * 16)
        view_id = get(w, get(w, 928) + index * 16 + 8)
        owner = resource(w, owner_id)
        view = resource(w, view_id)
        if owner == 0 or view == 0:
            return 0
        if get(w, owner + 8) != 1 or get(w, owner + 40) != 1:
            return 0
        if get(w, view + 8) != 2 or get(w, view + 24) != owner_id or get(w, view + 40) != 1:
            return 0
        index = index + 1
    return 1
'''

