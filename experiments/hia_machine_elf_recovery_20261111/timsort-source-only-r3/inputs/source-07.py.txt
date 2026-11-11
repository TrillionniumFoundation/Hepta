"""HIA-controlled foreign comparator selection and comparison continuations.

These source literals complement sort_algorithm.py. They are static authoring
input only. No host function here sorts, selects a run, chooses a comparison
order or decides which foreign comparison operation should be invoked.
"""

COMPARISON_SOURCE = r'''
def ts_select_comparator():
    effect(17, get(w, SORT_KIND), get(w, SORT_N), 0, 0)
    if length(s) != 16:
        abort(ABI)
    major = read_word(s, 0)
    minor = read_word(s, 8)
    if major != 3 or minor < 11 or minor > 14:
        abort(ABI)
    put(w, TS_RUN_VERSION, choose(minor >= 13, 1, 0))
    put(w, TS_TUPLES, 0)
    put(w, TS_COMPARE_MODE, 0)
    put(w, TS_CACHED_SLOT, 0)
    if get(w, SORT_KIND) == 4:
        return 0
    array = get(w, SORT_ARRAY)
    effect(18, get(w, array), 0, 0, 0)
    if length(s) != 64:
        abort(ABI)
    tuples = choose(read_word(s, 8) != 0 and read_word(s, 16) != 0, 1, 0)
    key_type = choose(tuples != 0, read_word(s, 24), read_word(s, 0))
    key_is_tuple = choose(tuples != 0, read_word(s, 32), read_word(s, 8))
    slot = choose(tuples != 0, read_word(s, 40), read_word(s, 48))
    homogeneous = 1
    index = 1
    while index < get(w, SORT_N):
        effect(18, ts_at(w, array, index), 0, 0, 0)
        if length(s) != 64:
            abort(ABI)
        if tuples != 0:
            if read_word(s, 8) == 0 or read_word(s, 16) == 0:
                homogeneous = 0
                tuples = 0
                break
            current_type = read_word(s, 24)
        else:
            current_type = read_word(s, 0)
        if current_type != key_type:
            homogeneous = 0
            if tuples == 0:
                break
        index = index + 1
    mode = choose(homogeneous != 0 and slot != 0, 1, 0)
    if tuples != 0 and key_is_tuple != 0:
        mode = 0
    put(w, TS_TUPLES, tuples)
    put(w, TS_COMPARE_MODE, mode)
    put(w, TS_CACHED_SLOT, slot)
    return 0

def ts_boolean_response():
    if length(s) != 8:
        abort(ABI)
    value = read_word(s, 0)
    if value > 1:
        abort(ABI)
    return value

def ts_selected_compare(left, right, item):
    if get(w, TS_COMPARE_MODE) != 0:
        effect(23, left, item, 0, 0)
        if length(s) != 8:
            abort(ABI)
        if read_word(s, 0) == get(w, TS_CACHED_SLOT):
            effect(24, left, right, item, get(w, TS_CACHED_SLOT))
            if length(s) != 16:
                abort(ABI)
            result_kind = read_word(s, 0)
            value = read_word(s, 8)
            if result_kind == 0:
                effect(26, 0, 0, 0, 0)
            elif result_kind == 1:
                if value > 1:
                    abort(ABI)
                effect(26, 0, 0, 0, 0)
                return value
            elif result_kind == 2:
                effect(25, 0, 0, 0, 0)
                value = ts_boolean_response()
                return value
            else:
                abort(ABI)
    effect(19, left, right, item, 0)
    value = ts_boolean_response()
    return value

def ts_compare(left, right):
    kind = get(w, SORT_KIND)
    pure = sort_compare(w, left, right, kind)
    if pure != 2:
        return pure
    if get(w, TS_TUPLES) == 0:
        result = ts_selected_compare(left, right, 0)
        return result
    effect(20, left, right, 0, 0)
    if length(s) != 16:
        abort(ABI)
    left_length = read_word(s, 0)
    right_length = read_word(s, 8)
    index = 0
    while index < left_length and index < right_length:
        effect(21, left, right, index, 0)
        equal = ts_boolean_response()
        if equal == 0:
            if index == 0:
                result = ts_selected_compare(left, right, 1)
            else:
                effect(22, left, right, index, 0)
                result = ts_boolean_response()
            return result
        index = index + 1
    return choose(left_length < right_length, 1, 0)

def ts_release_keys():
    if get(w, SORT_KIND) != 4:
        index = 0
        while index < get(w, SORT_N):
            effect(27, ts_at(w, get(w, SORT_ARRAY), index), 0, 0, 0)
            index = index + 1
    effect(28, 0, 0, 0, 0)
    return 0
'''
