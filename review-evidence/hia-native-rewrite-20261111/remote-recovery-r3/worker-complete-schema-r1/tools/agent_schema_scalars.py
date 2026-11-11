"""Scalar, const/enum, string and exact numeric stages for the complete validator.

Every old wire(value) and wire(choice) is independently requested. Successful
temporary bytes are released only after their exact comparison. This file is
NEW UNEXECUTED authoring; it does not itself grant schema or Worker qualification.
"""
SCALARS=r'''
def sv_type_valid(g:readbuf, w:mutbuf, value:u64, typ:u64) -> u64:
    kind = sv_kind(g, w, value)
    if sv_named(g, w, typ, T_object) != 0:
        return choose(kind == 6, 1, 0)
    if sv_named(g, w, typ, T_array) != 0:
        return choose(kind == 5, 1, 0)
    if sv_named(g, w, typ, T_string) != 0:
        return choose(kind == 4, 1, 0)
    if sv_named(g, w, typ, T_integer) != 0:
        return sn_integral(g, value)
    if sv_named(g, w, typ, T_number) != 0:
        return sn_finite(g, value)
    if sv_named(g, w, typ, T_boolean) != 0:
        return choose(kind == 1, 1, 0)
    if sv_named(g, w, typ, T_null) != 0:
        return choose(kind == 0, 1, 0)
    return 0

def sv_length_limits(g:readbuf, w:mutbuf, size:u64, schema:u64, minkey:u64, maxkey:u64) -> u64:
    minimum = sv_field(g, w, schema, minkey)
    if minimum != 0:
        mk = sv_kind(g, w, minimum)
        if mk != 2 and mk != 3:
            return sv_badset(w, 60)
        if sn_unsigned_order(g, size, minimum) == 0:
            return 0
    maximum = sv_field(g, w, schema, maxkey)
    if maximum != 0:
        mk = sv_kind(g, w, maximum)
        if mk != 2 and mk != 3:
            return sv_badset(w, 61)
        if sn_unsigned_order(g, size, maximum) == 2:
            return 0
    elif size > 9223372036854775808:
        return 0
    return 1

def sv_rewind_wire(w:mutbuf) -> u64:
    frame = sv_get(w, V_FRAME)
    sv_clear_response(w)
    sv_put(w, V_HEAP, sv_get(w, frame + F_TEMP_MARK))
    sv_put(w, frame + F_WIRE_AT, 0)
    sv_put(w, frame + F_WIRE_BYTES, 0)
    return 0

def sv_scalar_initial(g:readbuf, w:mutbuf) -> u64:
    frame = sv_get(w, V_FRAME)
    schema = sv_get(w, frame + F_SCHEMA)
    value = sv_get(w, frame + F_VALUE)
    sk = sv_kind(g, w, schema)
    if sk == 1:
        at = sv_node(g, w, schema)
        if sn_word(g, at + 48) != 0:
            return sv_pop(w, 1)
        return sv_failure(w, 1, 1, 0)
    if sk != 6:
        return sv_badset(w, 62)
    typ = sv_field(g, w, schema, K_type)
    if typ != 0:
        tk = sv_kind(g, w, typ)
        if tk != 0:
            if tk != 4:
                return sv_badset(w, 63)
            if sv_type_valid(g, w, value, typ) == 0:
                return sv_failure(w, 1, 2, typ)
    sv_put(w, frame + F_STAGE, 101)
    return 0

def sv_scalar_constraints(g:readbuf, r:readbuf, w:mutbuf) -> u64:
    frame = sv_get(w, V_FRAME)
    stage = sv_get(w, frame + F_STAGE)
    schema = sv_get(w, frame + F_SCHEMA)
    value = sv_get(w, frame + F_VALUE)
    if stage == 100:
        return sv_scalar_initial(g, w)
    if stage == 101:
        target = sv_field(g, w, schema, K_const)
        if target == 0:
            sv_put(w, frame + F_STAGE, 110)
            return 0
        sv_put(w, frame + F_SELECTED, target)
        sv_put(w, frame + F_TEMP_MARK, sv_get(w, V_HEAP))
        sv_wire_request(w, value, 102)
        return 0
    if stage == 102:
        if sv_copy_wire(r, w) == 0:
            return 0
        sv_wire_request(w, sv_get(w, frame + F_SELECTED), 103)
        return 0
    if stage == 103:
        same = sv_compare_wire(r, w)
        sv_rewind_wire(w)
        if same == 0:
            return sv_failure(w, 1, 3, 0)
        sv_put(w, frame + F_STAGE, 110)
        return 0
    if stage == 110:
        target = sv_field(g, w, schema, K_enum)
        if target == 0:
            sv_put(w, frame + F_STAGE, 200)
            return 0
        if sv_kind(g, w, target) != 5:
            return sv_badset(w, 64)
        sv_put(w, frame + F_LIST, target)
        sv_put(w, frame + F_INDEX, 0)
        sv_put(w, frame + F_STAGE, 111)
        return 0
    if stage == 111:
        choices = sv_get(w, frame + F_LIST)
        index = sv_get(w, frame + F_INDEX)
        if index >= sv_count(g, w, choices):
            return sv_failure(w, 1, 4, 0)
        sv_put(w, frame + F_TEMP_MARK, sv_get(w, V_HEAP))
        sv_wire_request(w, value, 112)
        return 0
    if stage == 112:
        if sv_copy_wire(r, w) == 0:
            return 0
        target = sv_item(g, w, sv_get(w, frame + F_LIST), sv_get(w, frame + F_INDEX))
        if target == 0:
            return 0
        sv_wire_request(w, target, 113)
        return 0
    if stage == 113:
        same = sv_compare_wire(r, w)
        sv_rewind_wire(w)
        if same != 0:
            sv_put(w, frame + F_STAGE, 200)
        else:
            sv_put(w, frame + F_INDEX, sv_get(w, frame + F_INDEX) + 1)
            sv_put(w, frame + F_STAGE, 111)
        return 0
    return sv_badset(w, 65)

def sv_scalar_final(g:readbuf, w:mutbuf) -> u64:
    frame = sv_get(w, V_FRAME)
    stage = sv_get(w, frame + F_STAGE)
    schema = sv_get(w, frame + F_SCHEMA)
    value = sv_get(w, frame + F_VALUE)
    if stage == 600:
        if sv_kind(g, w, value) == 4:
            at = sv_node(g, w, value)
            size = sn_word(g, at + 48)
            if sv_length_limits(g, w, size, schema, K_minLength, K_maxLength) == 0:
                if sv_get(w, V_BAD) != 0:
                    return 0
                return sv_failure(w, 1, 14, 0)
            pattern = sv_field(g, w, schema, K_pattern)
            if pattern != 0:
                sv_put(w, frame + F_TEMP_MARK, sv_get(w, V_HEAP))
                sv_pattern_request(g, w, pattern, value, 610)
                return 0
        sv_put(w, frame + F_STAGE, 620)
        return 0
    if stage == 610:
        if sv_get(w, V_RESPONSE_ACTIVE) == 0 or sv_get(w, V_PEER) != 2:
            return sv_badset(w, 66)
        matched = sv_get(w, V_PATTERN_MATCH)
        sv_rewind_wire(w)
        if matched == 0:
            return sv_failure(w, 1, 15, 0)
        sv_put(w, frame + F_STAGE, 620)
        return 0
    if stage == 620:
        kind = sv_kind(g, w, value)
        if kind == 2 or kind == 3:
            if sn_finite(g, value) == 0:
                return sv_failure(w, 1, 16, 0)
            minimum = sv_field(g, w, schema, K_minimum)
            if minimum != 0:
                mk = sv_kind(g, w, minimum)
                if mk != 2 and mk != 3:
                    return sv_badset(w, 67)
                if sn_order(g, value, minimum) == 0:
                    return sv_failure(w, 1, 16, 0)
            maximum = sv_field(g, w, schema, K_maximum)
            if maximum != 0:
                mk = sv_kind(g, w, maximum)
                if mk != 2 and mk != 3:
                    return sv_badset(w, 68)
                if sn_order(g, value, maximum) == 2:
                    return sv_failure(w, 1, 16, 0)
        return sv_pop(w, 1)
    return sv_badset(w, 69)

def sv_step(g:readbuf, r:readbuf, w:mutbuf) -> u64:
    stage = sv_get(w, sv_get(w, V_FRAME) + F_STAGE)
    if stage >= 100 and stage < 200:
        return sv_scalar_constraints(g, r, w)
    if stage >= 600 and stage < 700:
        return sv_scalar_final(g, w)
    return sv_badset(w, 70)
'''
