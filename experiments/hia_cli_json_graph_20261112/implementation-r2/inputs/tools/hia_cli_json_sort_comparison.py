"""HIA no-key comparator selection and versioned list restoration.

Only source literals are defined here.  No Python function performs sorting.
The raw observer returns facts or executes one HIA-named CPython primitive;
all comparator choice, tuple walking, error priority and cleanup loops below
are compiled into HIA.  ERROR propagates through the retained merge control.
"""

COMPARISON_SOURCE = r'''
def ts_sort(object):
    effect(16, 0, 0, 0, 0)
    profile = answer(w, 0)
    if profile != 31214 and profile != 31404 and profile != 31410:
        abort(ABI)
    put(w, PROFILE, profile)
    put(w, TS_RUN_VERSION, choose(profile == 31214, 0, 1))
    effect(17, 0, 0, 0, 0)
    put(w, TUPLE_TYPE, answer(w, 0))
    put(w, VALUE_ERROR_TYPE, answer(w, 4))
    effect(8, object, 0, 0, 0)
    if get(w, REPLY_ERROR) != 0:
        result = ts_cleanup(ERROR)
        return result
    put(w, SORT_N, answer(w, 0))
    put(w, SORT_ARRAY, ORIGINAL_BASE)
    put(w, SORT_TMP, TEMP_BASE)
    put(w, TEMP_CAPACITY, 256)
    put(w, MERGE_KIND, 0)
    result = ts_main()
    result = ts_cleanup(result)
    return result

def ts_select_comparator():
    array = get(w, SORT_ARRAY)
    effect(1, routed_get(s, o, w, array), 0, 0, 0)
    tuples = choose(answer(w, 1) != 0 and answer(w, 2) != 0, 1, 0)
    if tuples != 0:
        effect(1, answer(w, 3), 0, 0, 0)
    key_type = answer(w, 0)
    homogeneous = 1
    latin = 1
    compact = 1
    representation = answer(w, 5)
    slot = answer(w, 4)
    index = 0
    while index < get(w, SORT_N):
        effect(1, ts_at(s, o, w, array, index), 0, 0, 0)
        if tuples != 0:
            if answer(w, 1) == 0 or answer(w, 2) == 0:
                tuples = 0
                homogeneous = 0
                break
            effect(1, answer(w, 3), 0, 0, 0)
        if answer(w, 0) != key_type:
            homogeneous = 0
            if tuples == 0:
                break
        if homogeneous != 0:
            if representation == 2 and answer(w, 5) != 2:
                compact = 0
            if representation == 1 and answer(w, 5) != 1:
                latin = 0
        index = index + 1
    mode = 0
    if homogeneous != 0:
        if representation == 1 and latin != 0:
            mode = 2
        elif representation == 2 and compact != 0:
            mode = 3
        elif representation == 3:
            mode = 4
        elif slot != 0:
            mode = 1
    if tuples != 0 and key_type == get(w, TUPLE_TYPE):
        mode = 0
    put(w, TS_TUPLES, tuples)
    put(w, TS_COMPARE_MODE, mode)
    put(w, TS_CACHED_SLOT, slot)
    return 0

def ts_selected_compare(left, right):
    mode = get(w, TS_COMPARE_MODE)
    if mode == 1:
        effect(19, left, 0, 0, 0)
        if answer(w, 0) == get(w, TS_CACHED_SLOT):
            effect(4, left, right, get(w, TS_CACHED_SLOT), 0)
            kind = answer(w, 0)
            if kind == 5 or get(w, REPLY_ERROR) != 0:
                return ERROR
            if kind == 0:
                effect(6, 0, 0, 0, 0)
            elif kind == 1 or kind == 2:
                value = kind - 1
                effect(6, 0, 0, 0, 0)
                return value
            elif kind == 3:
                effect(5, 0, 0, 0, 0)
                value = answer(w, 0)
                failed = choose(get(w, REPLY_ERROR) != 0, 1, 0)
                effect(6, 0, 0, 0, 0)
                if failed != 0:
                    return ERROR
                if value > 1:
                    abort(ABI)
                return value
            elif kind != 4:
                abort(ABI)
    elif mode == 2:
        effect(1, left, 0, 0, 0)
        left_length = answer(w, 6)
        effect(1, right, 0, 0, 0)
        right_length = answer(w, 6)
        index = 0
        while index < left_length and index < right_length:
            effect(18, left, index, 0, 0)
            first = answer(w, 0)
            effect(18, right, index, 0, 0)
            second = answer(w, 0)
            if first != second:
                return choose(first < second, 1, 0)
            index = index + 1
        return choose(left_length < right_length, 1, 0)
    elif mode == 3:
        effect(1, left, 0, 0, 0)
        first = answer(w, 6) ^ ORIGINAL_BASE
        effect(1, right, 0, 0, 0)
        second = answer(w, 6) ^ ORIGINAL_BASE
        return choose(first < second, 1, 0)
    elif mode == 4:
        effect(1, left, 0, 0, 0)
        first = answer(w, 6)
        effect(1, right, 0, 0, 0)
        second = answer(w, 6)
        return binary64_less(first, second)
    effect(3, left, right, 0, 0)
    if get(w, REPLY_ERROR) != 0:
        return ERROR
    value = answer(w, 0)
    if value > 1:
        abort(ABI)
    return value

def ts_compare(left, right):
    if get(w, TS_TUPLES) == 0:
        result = ts_selected_compare(left, right)
        return result
    effect(1, left, 0, 0, 0)
    left_length = answer(w, 2)
    effect(1, right, 0, 0, 0)
    right_length = answer(w, 2)
    index = 0
    while index < left_length and index < right_length:
        effect(2, left, index, 0, 0)
        first = answer(w, 0)
        effect(2, right, index, 0, 0)
        second = answer(w, 0)
        effect(3, first, second, 2, 0)
        if get(w, REPLY_ERROR) != 0:
            return ERROR
        equal = answer(w, 0)
        if equal == 0:
            if index == 0:
                result = ts_selected_compare(first, second)
                return result
            effect(3, first, second, 0, 0)
            if get(w, REPLY_ERROR) != 0:
                return ERROR
            return answer(w, 0)
        if equal != 1:
            abort(ABI)
        index = index + 1
    return choose(left_length < right_length, 1, 0)

def ts_ensure_temp(count):
    if count <= get(w, TEMP_CAPACITY):
        return 0
    effect(14, 0, 0, 0, 0)
    put(w, TEMP_CAPACITY, 0)
    effect(15, count, 0, 0, 0)
    if answer(w, 0) == 0:
        effect(20, 0, 0, 0, 0)
        return ERROR
    put(w, TEMP_CAPACITY, count)
    return 0

def ts_cleanup(result):
    # This continuation is also entered after a transport/ledger exception,
    # once that actual exception is captured and its Python except has ended.
    if get(w, MERGE_KIND) != 0:
        ts_move(s, o, w, get(w, MERGE_TO), get(w, MERGE_FROM), get(w, MERGE_COUNT))
        put(w, MERGE_KIND, 0)
    if get(w, CONTEXT_SLOT) != 0:
        effect(6, 0, 0, 0, 0)
    if get(w, CONTEXT_PHASE) == 1:
        if result == 0 and get(w, REPLY_ERROR) == 0:
            effect(9, 0, 0, 0, 0)
            if answer(w, 0) != 0:
                mutation_message(w)
                effect(10, get(w, VALUE_ERROR_TYPE), ERROR_TEXT_OFFSET, 26, 0)
                result = ERROR
        effect(14, 0, 0, 0, 0)
        put(w, TEMP_CAPACITY, 0)
        effect(11, 0, 0, 0, 0)
    if get(w, CONTEXT_PHASE) == 2:
        count = get(w, DISPLACED_COUNT)
        while count != 0:
            count = count - 1
            effect(12, count, 0, 0, 0)
        effect(13, 0, 0, 0, 0)
    if get(w, REPLY_ERROR) != 0:
        return ERROR
    return result
'''
