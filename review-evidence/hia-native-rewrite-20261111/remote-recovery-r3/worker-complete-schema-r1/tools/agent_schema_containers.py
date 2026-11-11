"""Dictionary and array stages for the complete HIA schema validator.

Source iteration order, sorted missing-field diagnostics, independent wire calls
for every uniqueItems element, and contains()'s separate default label are kept.
NEW UNEXECUTED; fixed private issued Graph/actual peer leases are mandatory.
"""
CONTAINERS=r'''
def sv_string_order(g:readbuf, w:mutbuf, left:u64, right:u64) -> u64:
    a = sv_node(g, w, left)
    b = sv_node(g, w, right)
    if a == 0 or b == 0:
        return 3
    if sn_word(g, a) != 4 or sn_word(g, b) != 4:
        sv_badset(w, 100)
        return 3
    ap = sn_word(g, a + 8)
    bp = sn_word(g, b + 8)
    an = sn_word(g, a + 16)
    bn = sn_word(g, b + 16)
    index = 0
    while index < an and index < bn:
        av = byte(g, ap + index)
        bv = byte(g, bp + index)
        if av < bv:
            return 0
        if av > bv:
            return 2
        index = index + 1
    if an < bn:
        return 0
    if an > bn:
        return 2
    return 1

def sv_missing(g:readbuf, w:mutbuf, key:u64) -> u64:
    frame = sv_get(w, V_FRAME)
    if sv_kind(g, w, key) != 4:
        return sv_badset(w, 101)
    if sv_find_key(g, w, sv_get(w, frame + F_VALUE), key) != 0:
        return 1
    previous = 0
    cursor = sv_get(w, frame + F_EXTRA)
    search = 1
    while cursor != 0 and search != 0:
        order = sv_string_order(g, w, key, sv_get(w, cursor + 8))
        if order == 1:
            return 1
        if order == 0:
            search = 0
        elif order == 2:
            previous = cursor
            cursor = sv_get(w, cursor)
        else:
            return 0
    if sv_require(w, 16) == 0:
        return 0
    item = sv_alloc(w, 16)
    sv_put(w, item, cursor)
    sv_put(w, item + 8, key)
    if previous == 0:
        sv_put(w, frame + F_EXTRA, item)
    else:
        sv_put(w, previous, item)
    sv_put(w, frame + F_EXTRA2, sv_get(w, frame + F_EXTRA2) + 1)
    return 1

def sv_dict_required(g:readbuf, w:mutbuf) -> u64:
    frame = sv_get(w, V_FRAME)
    stage = sv_get(w, frame + F_STAGE)
    schema = sv_get(w, frame + F_SCHEMA)
    value = sv_get(w, frame + F_VALUE)
    if stage == 400:
        if sv_kind(g, w, value) != 6:
            sv_put(w, frame + F_STAGE, 500)
            return 0
        required = sv_field(g, w, schema, K_required)
        if required == 0:
            sv_put(w, frame + F_STAGE, 410)
            return 0
        if sv_kind(g, w, required) != 5:
            return sv_badset(w, 102)
        sv_put(w, frame + F_LIST, required)
        sv_put(w, frame + F_INDEX, 0)
        sv_put(w, frame + F_EXTRA, 0)
        sv_put(w, frame + F_EXTRA2, 0)
        sv_put(w, frame + F_STAGE, 401)
        return 0
    if stage == 401:
        required = sv_get(w, frame + F_LIST)
        index = sv_get(w, frame + F_INDEX)
        if index >= sv_count(g, w, required):
            if sv_get(w, frame + F_EXTRA2) != 0:
                return sv_failure(w, 1, 8, sv_get(w, frame + F_EXTRA))
            sv_put(w, frame + F_STAGE, 410)
            return 0
        key = sv_item(g, w, required, index)
        if sv_missing(g, w, key) == 0:
            return 0
        sv_put(w, frame + F_INDEX, index + 1)
        return 0
    return sv_badset(w, 103)

def sv_dict_properties(g:readbuf, w:mutbuf) -> u64:
    frame = sv_get(w, V_FRAME)
    stage = sv_get(w, frame + F_STAGE)
    schema = sv_get(w, frame + F_SCHEMA)
    value = sv_get(w, frame + F_VALUE)
    if stage == 410:
        props = sv_field(g, w, schema, K_properties)
        if props != 0:
            if sv_kind(g, w, props) != 6:
                return sv_badset(w, 104)
        sv_put(w, frame + F_LIST, props)
        sv_put(w, frame + F_INDEX, 0)
        sv_put(w, frame + F_STAGE, 411)
        return 0
    if stage == 411:
        index = sv_get(w, frame + F_INDEX)
        if index >= sv_count(g, w, value):
            sv_put(w, frame + F_STAGE, 420)
            return 0
        key = sv_item(g, w, value, index * 2)
        child = sv_item(g, w, value, index * 2 + 1)
        if sv_kind(g, w, key) != 4:
            return sv_badset(w, 105)
        props = sv_get(w, frame + F_LIST)
        target = 0
        if props != 0:
            target = sv_find_key(g, w, props, key)
        if target != 0:
            sv_push(g, w, child, target, 1, key, 0, 412, 100)
            return 0
        additional = sv_field(g, w, schema, K_additionalProperties)
        if additional != 0:
            ak = sv_kind(g, w, additional)
            if ak == 1:
                at = sv_node(g, w, additional)
                if sn_word(g, at + 48) == 0:
                    return sv_failure(w, 1, 9, key)
            elif ak == 6:
                sv_push(g, w, child, additional, 1, key, 0, 412, 100)
                return 0
        sv_put(w, frame + F_INDEX, index + 1)
        return 0
    if stage == 412:
        sv_put(w, frame + F_INDEX, sv_get(w, frame + F_INDEX) + 1)
        sv_put(w, frame + F_STAGE, 411)
        return 0
    if stage == 420:
        size = sv_count(g, w, value)
        if sv_length_limits(g, w, size, schema, K_minProperties, K_maxProperties) == 0:
            if sv_get(w, V_BAD) != 0:
                return 0
            return sv_failure(w, 1, 10, 0)
        sv_put(w, frame + F_STAGE, 500)
        return 0
    return sv_badset(w, 106)

def sv_unique_bytes(r:readbuf, w:mutbuf, start:u64, size:u64, item:u64) -> u64:
    if sv_get(w, item + 16) != size:
        return 0
    index = 0
    while index < size:
        if byte(r, start + index) != byte(w, item + 24 + index):
            return 0
        index = index + 1
    return 1

def sv_unique_insert(r:readbuf, w:mutbuf) -> u64:
    if sv_get(w, V_RESPONSE_ACTIVE) == 0 or sv_get(w, V_PEER) != 1:
        return sv_badset(w, 107)
    frame = sv_get(w, V_FRAME)
    size = sv_get(w, V_RESPONSE_SIZE)
    if size == 0:
        return sv_badset(w, 108)
    start = sv_get(w, V_RESPONSE_OUT)
    hash = 14695981039346656037
    index = 0
    while index < size:
        hash = (hash ^ byte(r, start + index)) * 1099511628211
        index = index + 1
    slot = sv_get(w, frame + F_EXTRA) + (hash & sv_get(w, frame + F_EXTRA2)) * 8
    cursor = sv_get(w, slot)
    while cursor != 0:
        if sv_get(w, cursor + 8) == hash:
            if sv_unique_bytes(r, w, start, size, cursor) != 0:
                sv_put(w, frame + F_MATCHES, 1)
                sv_clear_response(w)
                return 1
        cursor = sv_get(w, cursor)
    extent = (size + 31) & 18446744073709551608
    if sv_require(w, extent) == 0:
        return 0
    item = sv_alloc(w, extent)
    sv_put(w, item, sv_get(w, slot))
    sv_put(w, item + 8, hash)
    sv_put(w, item + 16, size)
    copy_bytes(w, r, item + 24, start, size)
    sv_put(w, slot, item)
    sv_clear_response(w)
    return 1

def sv_array_unique(g:readbuf, r:readbuf, w:mutbuf) -> u64:
    frame = sv_get(w, V_FRAME)
    stage = sv_get(w, frame + F_STAGE)
    schema = sv_get(w, frame + F_SCHEMA)
    value = sv_get(w, frame + F_VALUE)
    if stage == 500:
        if sv_kind(g, w, value) != 5:
            sv_put(w, frame + F_STAGE, 600)
            return 0
        count = sv_count(g, w, value)
        if sv_length_limits(g, w, count, schema, K_minItems, K_maxItems) == 0:
            if sv_get(w, V_BAD) != 0:
                return 0
            return sv_failure(w, 1, 11, 0)
        unique = sv_field(g, w, schema, K_uniqueItems)
        if unique == 0:
            sv_put(w, frame + F_STAGE, 510)
            return 0
        if sv_truth(g, w, unique) == 0 or count == 0:
            sv_put(w, frame + F_STAGE, 510)
            return 0
        sv_put(w, frame + F_STAGE, 501)
        return 0
    if stage == 501:
        count = sv_count(g, w, value)
        if count > SV_MAX >> 1:
            return sv_badset(w, 109)
        slots = 2
        while slots < count * 2:
            if slots > SV_MAX >> 1:
                return sv_badset(w, 110)
            slots = slots * 2
        if slots > SV_MAX >> 3:
            return sv_badset(w, 111)
        bytes = slots * 8
        if sv_require(w, bytes) == 0:
            return 0
        sv_put(w, frame + F_TEMP_MARK, sv_get(w, V_HEAP))
        table = sv_alloc(w, bytes)
        fill_range(w, table, bytes, 0)
        sv_put(w, frame + F_EXTRA, table)
        sv_put(w, frame + F_EXTRA2, slots - 1)
        sv_put(w, frame + F_INDEX, 0)
        sv_put(w, frame + F_MATCHES, 0)
        sv_put(w, frame + F_STAGE, 502)
        return 0
    if stage == 502:
        index = sv_get(w, frame + F_INDEX)
        if index >= sv_count(g, w, value):
            duplicate = sv_get(w, frame + F_MATCHES)
            sv_put(w, V_HEAP, sv_get(w, frame + F_TEMP_MARK))
            if duplicate != 0:
                return sv_failure(w, 1, 12, 0)
            sv_put(w, frame + F_STAGE, 510)
            return 0
        child = sv_item(g, w, value, index)
        sv_wire_request(w, child, 503)
        return 0
    if stage == 503:
        if sv_unique_insert(r, w) == 0:
            return 0
        sv_put(w, frame + F_INDEX, sv_get(w, frame + F_INDEX) + 1)
        sv_put(w, frame + F_STAGE, 502)
        return 0
    return sv_badset(w, 112)

def sv_array_children(g:readbuf, w:mutbuf) -> u64:
    frame = sv_get(w, V_FRAME)
    stage = sv_get(w, frame + F_STAGE)
    schema = sv_get(w, frame + F_SCHEMA)
    value = sv_get(w, frame + F_VALUE)
    if stage == 510:
        items = sv_field(g, w, schema, K_items)
        if items == 0:
            sv_put(w, frame + F_STAGE, 530)
            return 0
        sv_put(w, frame + F_LIST, items)
        sv_put(w, frame + F_INDEX, 0)
        sv_put(w, frame + F_STAGE, 511)
        return 0
    if stage == 511:
        index = sv_get(w, frame + F_INDEX)
        if index >= sv_count(g, w, value):
            sv_put(w, frame + F_STAGE, 530)
            return 0
        child = sv_item(g, w, value, index)
        sub = sv_get(w, frame + F_LIST)
        sv_push(g, w, child, sub, 2, index, 0, 512, 100)
        return 0
    if stage == 512:
        sv_put(w, frame + F_INDEX, sv_get(w, frame + F_INDEX) + 1)
        sv_put(w, frame + F_STAGE, 511)
        return 0
    if stage == 530:
        sub = sv_field(g, w, schema, K_contains)
        if sub == 0:
            sv_put(w, frame + F_STAGE, 600)
            return 0
        sv_put(w, frame + F_LIST, sub)
        sv_put(w, frame + F_INDEX, 0)
        sv_put(w, frame + F_STAGE, 531)
        return 0
    if stage == 531:
        index = sv_get(w, frame + F_INDEX)
        if index >= sv_count(g, w, value):
            return sv_failure(w, 1, 13, 0)
        child = sv_item(g, w, value, index)
        sub = sv_get(w, frame + F_LIST)
        sv_push(g, w, child, sub, 3, 0, 1, 532, 100)
        return 0
    if stage == 532:
        if sv_get(w, frame + F_SUBRESULT) != 0:
            sv_put(w, frame + F_STAGE, 600)
        else:
            sv_put(w, frame + F_INDEX, sv_get(w, frame + F_INDEX) + 1)
            sv_put(w, frame + F_STAGE, 531)
        return 0
    return sv_badset(w, 113)

def sv_step(g:readbuf, r:readbuf, w:mutbuf) -> u64:
    stage = sv_get(w, sv_get(w, V_FRAME) + F_STAGE)
    if stage == 400 or stage == 401:
        return sv_dict_required(g, w)
    if stage == 410 or stage == 411 or stage == 412 or stage == 420:
        return sv_dict_properties(g, w)
    if stage >= 500 and stage <= 503:
        return sv_array_unique(g, r, w)
    if stage >= 510 and stage <= 532:
        return sv_array_children(g, w)
    return sv_badset(w, 114)
'''
