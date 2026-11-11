"""All branch/catch and vocabulary stages for the complete schema owner.

Both oneOf and anyOf evaluate every matches() branch. A uniquely tagged branch
is replayed after zero successful matches. Only schema-domain AgentRejected is
caught. This is NEW UNEXECUTED authoring, not a qualification claim.
"""
LOGIC=r'''
def sv_union_next(w:mutbuf) -> u64:
    frame = sv_get(w, V_FRAME)
    if sv_get(w, frame + F_AUX) == K_oneOf:
        sv_put(w, frame + F_AUX, K_anyOf)
        sv_put(w, frame + F_STAGE, 201)
    else:
        sv_put(w, frame + F_STAGE, 300)
    return 0

def sv_union_fail(w:mutbuf) -> u64:
    frame = sv_get(w, V_FRAME)
    reason = 6
    if sv_get(w, frame + F_AUX) == K_oneOf:
        reason = 5
    return sv_failure(w, 1, reason, 0)

def sv_union(g:readbuf, w:mutbuf) -> u64:
    frame = sv_get(w, V_FRAME)
    stage = sv_get(w, frame + F_STAGE)
    schema = sv_get(w, frame + F_SCHEMA)
    value = sv_get(w, frame + F_VALUE)
    if stage == 200:
        sv_put(w, frame + F_AUX, K_oneOf)
        sv_put(w, frame + F_STAGE, 201)
        return 0
    if stage == 201:
        branches = sv_field(g, w, schema, sv_get(w, frame + F_AUX))
        if branches == 0:
            return sv_union_next(w)
        if sv_kind(g, w, branches) != 5:
            return sv_badset(w, 80)
        sv_put(w, frame + F_LIST, branches)
        sv_put(w, frame + F_INDEX, 0)
        sv_put(w, frame + F_MATCHES, 0)
        sv_put(w, frame + F_STAGE, 202)
        return 0
    if stage == 202:
        index = sv_get(w, frame + F_INDEX)
        branches = sv_get(w, frame + F_LIST)
        if index < sv_count(g, w, branches):
            sub = sv_item(g, w, branches, index)
            sv_push(g, w, value, sub, 0, 0, 1, 203, 100)
            return 0
        matches = sv_get(w, frame + F_MATCHES)
        accepted = choose(matches != 0, 1, 0)
        if sv_get(w, frame + F_AUX) == K_oneOf:
            accepted = choose(matches == 1, 1, 0)
        if accepted != 0:
            return sv_union_next(w)
        if matches == 0 and sv_kind(g, w, value) == 6:
            sv_put(w, frame + F_STAGE, 220)
            return 0
        return sv_union_fail(w)
    if stage == 203:
        sv_put(w, frame + F_MATCHES, sv_get(w, frame + F_MATCHES) + sv_get(w, frame + F_SUBRESULT))
        sv_put(w, frame + F_INDEX, sv_get(w, frame + F_INDEX) + 1)
        sv_put(w, frame + F_STAGE, 202)
        return 0
    return sv_badset(w, 81)

def sv_tagged_start(g:readbuf, w:mutbuf) -> u64:
    frame = sv_get(w, V_FRAME)
    stage = sv_get(w, frame + F_STAGE)
    value = sv_get(w, frame + F_VALUE)
    if stage == 220:
        sv_put(w, frame + F_INDEX, 0)
        sv_put(w, frame + F_MATCHES, 0)
        sv_put(w, frame + F_SELECTED, 0)
        sv_put(w, frame + F_STAGE, 221)
        return 0
    if stage == 221:
        branches = sv_get(w, frame + F_LIST)
        index = sv_get(w, frame + F_INDEX)
        if index >= sv_count(g, w, branches):
            if sv_get(w, frame + F_MATCHES) == 1:
                sub = sv_get(w, frame + F_SELECTED)
                sv_push(g, w, value, sub, 0, 0, 0, 229, 100)
                return 0
            return sv_union_fail(w)
        sub = sv_item(g, w, branches, index)
        if sv_kind(g, w, sub) != 6:
            sv_put(w, frame + F_STAGE, 225)
            return 0
        props = sv_field(g, w, sub, K_properties)
        if props == 0:
            sv_put(w, frame + F_STAGE, 225)
            return 0
        if sv_kind(g, w, props) != 6:
            return sv_badset(w, 82)
        sv_put(w, frame + F_AUX2, props)
        sv_put(w, frame + F_AUX3, 0)
        sv_put(w, frame + F_EXTRA, 0)
        sv_put(w, frame + F_STAGE, 222)
        return 0
    if stage == 225:
        sv_put(w, frame + F_INDEX, sv_get(w, frame + F_INDEX) + 1)
        sv_put(w, frame + F_STAGE, 221)
        return 0
    if stage == 229:
        return sv_union_fail(w)
    return sv_badset(w, 83)

def sv_tagged_values(g:readbuf, r:readbuf, w:mutbuf) -> u64:
    frame = sv_get(w, V_FRAME)
    stage = sv_get(w, frame + F_STAGE)
    value = sv_get(w, frame + F_VALUE)
    if stage == 222:
        props = sv_get(w, frame + F_AUX2)
        index = sv_get(w, frame + F_AUX3)
        if index >= sv_count(g, w, props):
            if sv_get(w, frame + F_EXTRA) != 0:
                sv_put(w, frame + F_MATCHES, sv_get(w, frame + F_MATCHES) + 1)
                sub = sv_item(g, w, sv_get(w, frame + F_LIST), sv_get(w, frame + F_INDEX))
                sv_put(w, frame + F_SELECTED, sub)
            sv_put(w, frame + F_STAGE, 225)
            return 0
        child = sv_item(g, w, props, index * 2 + 1)
        target = 0
        if sv_kind(g, w, child) == 6:
            target = sv_field(g, w, child, K_const)
        if target == 0:
            sv_put(w, frame + F_AUX3, index + 1)
            return 0
        sv_put(w, frame + F_EXTRA, 1)
        key = sv_item(g, w, props, index * 2)
        actual = sv_find_key(g, w, value, key)
        if actual == 0:
            if sv_get(w, V_BAD) == 0:
                sv_put(w, frame + F_STAGE, 225)
            return 0
        sv_put(w, frame + F_EXTRA3, target)
        sv_put(w, frame + F_TEMP_MARK, sv_get(w, V_HEAP))
        sv_wire_request(w, actual, 223)
        return 0
    if stage == 223:
        if sv_copy_wire(r, w) == 0:
            return 0
        sv_wire_request(w, sv_get(w, frame + F_EXTRA3), 224)
        return 0
    if stage == 224:
        same = sv_compare_wire(r, w)
        sv_rewind_wire(w)
        if same == 0:
            sv_put(w, frame + F_STAGE, 225)
        else:
            sv_put(w, frame + F_AUX3, sv_get(w, frame + F_AUX3) + 1)
            sv_put(w, frame + F_STAGE, 222)
        return 0
    return sv_badset(w, 84)

def sv_other_logic(g:readbuf, w:mutbuf) -> u64:
    frame = sv_get(w, V_FRAME)
    stage = sv_get(w, frame + F_STAGE)
    schema = sv_get(w, frame + F_SCHEMA)
    value = sv_get(w, frame + F_VALUE)
    if stage == 300:
        branches = sv_field(g, w, schema, K_allOf)
        if branches == 0:
            sv_put(w, frame + F_STAGE, 310)
            return 0
        if sv_kind(g, w, branches) != 5:
            return sv_badset(w, 85)
        sv_put(w, frame + F_LIST, branches)
        sv_put(w, frame + F_INDEX, 0)
        sv_put(w, frame + F_STAGE, 301)
        return 0
    if stage == 301:
        index = sv_get(w, frame + F_INDEX)
        branches = sv_get(w, frame + F_LIST)
        if index >= sv_count(g, w, branches):
            sv_put(w, frame + F_STAGE, 310)
            return 0
        sub = sv_item(g, w, branches, index)
        sv_push(g, w, value, sub, 0, 0, 0, 302, 100)
        return 0
    if stage == 302:
        sv_put(w, frame + F_INDEX, sv_get(w, frame + F_INDEX) + 1)
        sv_put(w, frame + F_STAGE, 301)
        return 0
    if stage == 310:
        sub = sv_field(g, w, schema, K_not)
        if sub == 0:
            sv_put(w, frame + F_STAGE, 320)
            return 0
        sv_push(g, w, value, sub, 0, 0, 1, 311, 100)
        return 0
    if stage == 311:
        if sv_get(w, frame + F_SUBRESULT) != 0:
            return sv_failure(w, 1, 7, 0)
        sv_put(w, frame + F_STAGE, 320)
        return 0
    if stage == 320:
        sub = sv_field(g, w, schema, K_if)
        if sub == 0:
            sv_put(w, frame + F_STAGE, 400)
            return 0
        sv_push(g, w, value, sub, 0, 0, 1, 321, 100)
        return 0
    if stage == 321:
        key = K_else
        if sv_get(w, frame + F_SUBRESULT) != 0:
            key = K_then
        sub = sv_field(g, w, schema, key)
        if sub == 0:
            sv_put(w, frame + F_STAGE, 400)
            return 0
        sv_push(g, w, value, sub, 0, 0, 0, 322, 100)
        return 0
    if stage == 322:
        sv_put(w, frame + F_STAGE, 400)
        return 0
    return sv_badset(w, 86)

def sv_vocabulary_initial(g:readbuf, w:mutbuf) -> u64:
    frame = sv_get(w, V_FRAME)
    schema = sv_get(w, frame + F_SCHEMA)
    kind = sv_kind(g, w, schema)
    if kind == 1:
        return sv_pop(w, 1)
    if kind != 6:
        return sv_failure(w, 3, 1, 0)
    index = 0
    count = sv_count(g, w, schema)
    while index < count:
        key = sv_item(g, w, schema, index * 2)
        keyword = 1
        found = 0
        while keyword <= 28:
            if sv_named(g, w, key, keyword) != 0:
                found = 1
            keyword = keyword + 1
        if found == 0:
            return sv_failure(w, 3, 1, 0)
        index = index + 1
    sv_put(w, frame + F_AUX, K_oneOf)
    sv_put(w, frame + F_STAGE, 801)
    return 0

def sv_vocabulary_list(g:readbuf, w:mutbuf) -> u64:
    frame = sv_get(w, V_FRAME)
    stage = sv_get(w, frame + F_STAGE)
    schema = sv_get(w, frame + F_SCHEMA)
    if stage == 801:
        key = sv_get(w, frame + F_AUX)
        if key > K_allOf:
            sv_put(w, frame + F_INDEX, 0)
            sv_put(w, frame + F_STAGE, 811)
            return 0
        branches = sv_field(g, w, schema, key)
        if branches == 0:
            sv_put(w, frame + F_AUX, key + 1)
            return 0
        if sv_kind(g, w, branches) != 5:
            return sv_badset(w, 87)
        sv_put(w, frame + F_LIST, branches)
        sv_put(w, frame + F_INDEX, 0)
        sv_put(w, frame + F_STAGE, 802)
        return 0
    if stage == 802:
        index = sv_get(w, frame + F_INDEX)
        branches = sv_get(w, frame + F_LIST)
        if index >= sv_count(g, w, branches):
            sv_put(w, frame + F_AUX, sv_get(w, frame + F_AUX) + 1)
            sv_put(w, frame + F_STAGE, 801)
            return 0
        sub = sv_item(g, w, branches, index)
        sv_push(g, w, 0, sub, 0, 0, 0, 803, 800)
        return 0
    if stage == 803:
        sv_put(w, frame + F_INDEX, sv_get(w, frame + F_INDEX) + 1)
        sv_put(w, frame + F_STAGE, 802)
        return 0
    return sv_badset(w, 88)

def sv_vocabulary_key(index:u64) -> u64:
    if index == 0:
        return K_items
    if index == 1:
        return K_contains
    if index == 2:
        return K_if
    if index == 3:
        return K_then
    if index == 4:
        return K_else
    return K_not

def sv_vocabulary_rest(g:readbuf, w:mutbuf) -> u64:
    frame = sv_get(w, V_FRAME)
    stage = sv_get(w, frame + F_STAGE)
    schema = sv_get(w, frame + F_SCHEMA)
    if stage == 811:
        index = sv_get(w, frame + F_INDEX)
        if index >= 6:
            sv_put(w, frame + F_STAGE, 820)
            return 0
        sub = sv_field(g, w, schema, sv_vocabulary_key(index))
        if sub == 0:
            sv_put(w, frame + F_INDEX, index + 1)
            return 0
        sv_push(g, w, 0, sub, 0, 0, 0, 812, 800)
        return 0
    if stage == 812:
        sv_put(w, frame + F_INDEX, sv_get(w, frame + F_INDEX) + 1)
        sv_put(w, frame + F_STAGE, 811)
        return 0
    if stage == 820:
        props = sv_field(g, w, schema, K_properties)
        if props == 0:
            sv_put(w, frame + F_STAGE, 830)
            return 0
        if sv_kind(g, w, props) != 6:
            return sv_badset(w, 89)
        sv_put(w, frame + F_LIST, props)
        sv_put(w, frame + F_INDEX, 0)
        sv_put(w, frame + F_STAGE, 821)
        return 0
    if stage == 821:
        props = sv_get(w, frame + F_LIST)
        index = sv_get(w, frame + F_INDEX)
        if index >= sv_count(g, w, props):
            sv_put(w, frame + F_STAGE, 830)
            return 0
        sub = sv_item(g, w, props, index * 2 + 1)
        sv_push(g, w, 0, sub, 0, 0, 0, 822, 800)
        return 0
    if stage == 822:
        sv_put(w, frame + F_INDEX, sv_get(w, frame + F_INDEX) + 1)
        sv_put(w, frame + F_STAGE, 821)
        return 0
    if stage == 830:
        sub = sv_field(g, w, schema, K_additionalProperties)
        if sub != 0:
            if sv_kind(g, w, sub) == 6:
                sv_push(g, w, 0, sub, 0, 0, 0, 831, 800)
                return 0
        return sv_pop(w, 1)
    if stage == 831:
        return sv_pop(w, 1)
    return sv_badset(w, 90)

def sv_step(g:readbuf, r:readbuf, w:mutbuf) -> u64:
    stage = sv_get(w, sv_get(w, V_FRAME) + F_STAGE)
    if stage >= 200 and stage <= 203:
        return sv_union(g, w)
    if stage == 222 or stage == 223 or stage == 224:
        return sv_tagged_values(g, r, w)
    if stage == 220 or stage == 221 or stage == 225 or stage == 229:
        return sv_tagged_start(g, w)
    if stage >= 300 and stage <= 322:
        return sv_other_logic(g, w)
    if stage == 800:
        return sv_vocabulary_initial(g, w)
    if stage >= 801 and stage <= 803:
        return sv_vocabulary_list(g, w)
    if stage >= 811 and stage <= 831:
        return sv_vocabulary_rest(g, w)
    return sv_badset(w, 91)
'''
