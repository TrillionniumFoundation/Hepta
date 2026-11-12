"""HIA no-key PowerSort control with explicit compare-error restoration.

The 078d source and unexecuted implementation-r2 are retained independently.
Every comparison ERROR now propagates before a Boolean branch; live merge
state is committed before each yield-capable compare/gallop so an external
transport failure restores the remaining temporary tail before list fields.
This module contains authoring text only. No host sort is called.
"""

ALGORITHM_SOURCE = r'''
def ts_binary(array, n, ok):
    if ok == 0:
        ok = 1
    while ok < n:
        left = 0
        right = ok
        pivot = ts_at(w, array, ok)
        while left < right:
            middle = left + right >> 1
            less = ts_compare(pivot, ts_at(w, array, middle))
            if less == ERROR:
                return ERROR
            if less != 0:
                right = middle
            else:
                left = middle + 1
        ts_move(w, array + (left + 1) * 8, array + left * 8, ok - left)
        put(w, array + left * 8, pivot)
        ok = ok + 1
    return 0

def ts_count_old(array, remaining):
    if remaining == 1:
        return 1
    n = 2
    descending = ts_compare(ts_at(w, array, 1), ts_at(w, array, 0))
    if descending == ERROR:
        return ERROR
    if descending != 0:
        while n < remaining:
            less = ts_compare(ts_at(w, array, n), ts_at(w, array, n - 1))
            if less == ERROR:
                return ERROR
            if less == 0:
                break
            n = n + 1
        ts_reverse(w, array, n)
    else:
        while n < remaining:
            less = ts_compare(ts_at(w, array, n), ts_at(w, array, n - 1))
            if less == ERROR:
                return ERROR
            if less != 0:
                break
            n = n + 1
    return n

def ts_count_new(array, remaining):
    n = 1
    while n < remaining:
        less = ts_compare(ts_at(w, array, n), ts_at(w, array, n - 1))
        if less == ERROR:
            return ERROR
        if less != 0:
            break
        n = n + 1
    if n == remaining:
        return n
    if n > 1:
        less = ts_compare(ts_at(w, array, 0), ts_at(w, array, n - 1))
        if less == ERROR:
            return ERROR
        if less != 0:
            return n
        ts_reverse(w, array, n)
    n = n + 1
    equal = 0
    while n < remaining:
        less = ts_compare(ts_at(w, array, n), ts_at(w, array, n - 1))
        if less == ERROR:
            return ERROR
        if less != 0:
            if equal != 0:
                equal = equal + 1
                ts_reverse(w, array + (n - equal) * 8, equal)
                equal = 0
        else:
            greater = ts_compare(ts_at(w, array, n - 1), ts_at(w, array, n))
            if greater == ERROR:
                return ERROR
            if greater != 0:
                break
            equal = equal + 1
        n = n + 1
    if equal != 0:
        equal = equal + 1
        ts_reverse(w, array + (n - equal) * 8, equal)
    ts_reverse(w, array, n)
    while n < remaining:
        less = ts_compare(ts_at(w, array, n), ts_at(w, array, n - 1))
        if less == ERROR:
            return ERROR
        if less != 0:
            break
        n = n + 1
    return n

def ts_gallop_left(key, array, n, hint):
    last = 0
    offset = 1
    less = ts_compare(ts_at(w, array, hint), key)
    if less == ERROR:
        return ERROR
    if less != 0:
        maximum = n - hint
        while offset < maximum:
            less = ts_compare(ts_at(w, array, hint + offset), key)
            if less == ERROR:
                return ERROR
            if less == 0:
                break
            last = offset
            offset = (offset << 1) + 1
        if offset > maximum:
            offset = maximum
        last = last + hint
        offset = offset + hint
    else:
        maximum = hint + 1
        while offset < maximum:
            less = ts_compare(ts_at(w, array, hint - offset), key)
            if less == ERROR:
                return ERROR
            if less != 0:
                break
            last = offset
            offset = (offset << 1) + 1
        if offset > maximum:
            offset = maximum
        previous = last
        last = hint - offset
        offset = hint - previous
    last = last + 1
    while last < offset:
        middle = last + (offset - last >> 1)
        less = ts_compare(ts_at(w, array, middle), key)
        if less == ERROR:
            return ERROR
        if less != 0:
            last = middle + 1
        else:
            offset = middle
    return offset

def ts_gallop_right(key, array, n, hint):
    last = 0
    offset = 1
    less = ts_compare(key, ts_at(w, array, hint))
    if less == ERROR:
        return ERROR
    if less != 0:
        maximum = hint + 1
        while offset < maximum:
            less = ts_compare(key, ts_at(w, array, hint - offset))
            if less == ERROR:
                return ERROR
            if less == 0:
                break
            last = offset
            offset = (offset << 1) + 1
        if offset > maximum:
            offset = maximum
        previous = last
        last = hint - offset
        offset = hint - previous
    else:
        maximum = n - hint
        while offset < maximum:
            less = ts_compare(key, ts_at(w, array, hint + offset))
            if less == ERROR:
                return ERROR
            if less != 0:
                break
            last = offset
            offset = (offset << 1) + 1
        if offset > maximum:
            offset = maximum
        last = last + hint
        offset = offset + hint
    last = last + 1
    while last < offset:
        middle = last + (offset - last >> 1)
        less = ts_compare(key, ts_at(w, array, middle))
        if less == ERROR:
            return ERROR
        if less != 0:
            offset = middle
        else:
            last = middle + 1
    return offset

def ts_merge_lo(array_a, length_a, array_b, length_b):
    ready = ts_ensure_temp(length_a)
    if ready == ERROR:
        return ERROR
    temporary = get(w, SORT_TMP)
    ts_move(w, temporary, array_a, length_a)
    destination = array_a
    array_a = temporary
    put(w, destination, get(w, array_b))
    destination = destination + 8
    array_b = array_b + 8
    length_b = length_b - 1
    if length_b == 0:
        ts_move(w, destination, array_a, length_a)
        put(w, MERGE_KIND, 0)
        return 0
    if length_a == 1:
        ts_move(w, destination, array_b, length_b)
        put(w, destination + length_b * 8, get(w, array_a))
        put(w, MERGE_KIND, 0)
        return 0
    minimum = get(w, TS_MIN_GALLOP)
    while True:
        count_a = 0
        count_b = 0
        while True:
            put(w, MERGE_KIND, 1)
            put(w, MERGE_FROM, array_a)
            put(w, MERGE_TO, destination)
            put(w, MERGE_COUNT, length_a)
            less = ts_compare(get(w, array_b), get(w, array_a))
            if less == ERROR:
                ts_move(w, destination, array_a, length_a)
                put(w, MERGE_KIND, 0)
                return ERROR
            if less != 0:
                put(w, destination, get(w, array_b))
                destination = destination + 8
                array_b = array_b + 8
                count_b = count_b + 1
                count_a = 0
                length_b = length_b - 1
                if length_b == 0:
                    ts_move(w, destination, array_a, length_a)
                    put(w, MERGE_KIND, 0)
                    return 0
                if count_b >= minimum:
                    break
            else:
                put(w, destination, get(w, array_a))
                destination = destination + 8
                array_a = array_a + 8
                count_a = count_a + 1
                count_b = 0
                length_a = length_a - 1
                if length_a == 1:
                    ts_move(w, destination, array_b, length_b)
                    put(w, destination + length_b * 8, get(w, array_a))
                    put(w, MERGE_KIND, 0)
                    return 0
                if count_a >= minimum:
                    break
        minimum = minimum + 1
        while True:
            if minimum > 1:
                minimum = minimum - 1
            put(w, TS_MIN_GALLOP, minimum)
            put(w, MERGE_KIND, 1)
            put(w, MERGE_FROM, array_a)
            put(w, MERGE_TO, destination)
            put(w, MERGE_COUNT, length_a)
            count_a = ts_gallop_right(get(w, array_b), array_a, length_a, 0)
            if count_a == ERROR:
                ts_move(w, destination, array_a, length_a)
                put(w, MERGE_KIND, 0)
                return ERROR
            if count_a != 0:
                ts_move(w, destination, array_a, count_a)
                destination = destination + count_a * 8
                array_a = array_a + count_a * 8
                length_a = length_a - count_a
                if length_a == 1:
                    ts_move(w, destination, array_b, length_b)
                    put(w, destination + length_b * 8, get(w, array_a))
                    put(w, MERGE_KIND, 0)
                    return 0
                if length_a == 0:
                    put(w, MERGE_KIND, 0)
                    return 0
            put(w, destination, get(w, array_b))
            destination = destination + 8
            array_b = array_b + 8
            length_b = length_b - 1
            if length_b == 0:
                ts_move(w, destination, array_a, length_a)
                put(w, MERGE_KIND, 0)
                return 0
            put(w, MERGE_KIND, 1)
            put(w, MERGE_FROM, array_a)
            put(w, MERGE_TO, destination)
            put(w, MERGE_COUNT, length_a)
            count_b = ts_gallop_left(get(w, array_a), array_b, length_b, 0)
            if count_b == ERROR:
                ts_move(w, destination, array_a, length_a)
                put(w, MERGE_KIND, 0)
                return ERROR
            if count_b != 0:
                ts_move(w, destination, array_b, count_b)
                destination = destination + count_b * 8
                array_b = array_b + count_b * 8
                length_b = length_b - count_b
                if length_b == 0:
                    ts_move(w, destination, array_a, length_a)
                    put(w, MERGE_KIND, 0)
                    return 0
            put(w, destination, get(w, array_a))
            destination = destination + 8
            array_a = array_a + 8
            length_a = length_a - 1
            if length_a == 1:
                ts_move(w, destination, array_b, length_b)
                put(w, destination + length_b * 8, get(w, array_a))
                put(w, MERGE_KIND, 0)
                return 0
            if count_a < 7 and count_b < 7:
                break
        minimum = minimum + 1
        put(w, TS_MIN_GALLOP, minimum)
    put(w, MERGE_KIND, 0)
    return 0

def ts_merge_hi(array_a, length_a, array_b, length_b):
    ready = ts_ensure_temp(length_b)
    if ready == ERROR:
        return ERROR
    temporary = get(w, SORT_TMP)
    destination = array_b + (length_b - 1) * 8
    ts_move(w, temporary, array_b, length_b)
    base_a = array_a
    base_b = temporary
    array_b = temporary + (length_b - 1) * 8
    array_a = array_a + (length_a - 1) * 8
    put(w, destination, get(w, array_a))
    destination = destination - 8
    array_a = array_a - 8
    length_a = length_a - 1
    if length_a == 0:
        ts_move(w, destination + 8 - length_b * 8, base_b, length_b)
        put(w, MERGE_KIND, 0)
        return 0
    if length_b == 1:
        ts_move(w, destination + 8 - length_a * 8, array_a + 8 - length_a * 8, length_a)
        put(w, destination - length_a * 8, get(w, array_b))
        put(w, MERGE_KIND, 0)
        return 0
    minimum = get(w, TS_MIN_GALLOP)
    while True:
        count_a = 0
        count_b = 0
        while True:
            put(w, MERGE_KIND, 2)
            put(w, MERGE_FROM, base_b)
            put(w, MERGE_TO, destination + 8 - length_b * 8)
            put(w, MERGE_COUNT, length_b)
            less = ts_compare(get(w, array_b), get(w, array_a))
            if less == ERROR:
                ts_move(w, destination + 8 - length_b * 8, base_b, length_b)
                put(w, MERGE_KIND, 0)
                return ERROR
            if less != 0:
                put(w, destination, get(w, array_a))
                destination = destination - 8
                array_a = array_a - 8
                count_a = count_a + 1
                count_b = 0
                length_a = length_a - 1
                if length_a == 0:
                    ts_move(w, destination + 8 - length_b * 8, base_b, length_b)
                    put(w, MERGE_KIND, 0)
                    return 0
                if count_a >= minimum:
                    break
            else:
                put(w, destination, get(w, array_b))
                destination = destination - 8
                array_b = array_b - 8
                count_b = count_b + 1
                count_a = 0
                length_b = length_b - 1
                if length_b == 1:
                    ts_move(w, destination + 8 - length_a * 8, array_a + 8 - length_a * 8, length_a)
                    put(w, destination - length_a * 8, get(w, array_b))
                    put(w, MERGE_KIND, 0)
                    return 0
                if count_b >= minimum:
                    break
        minimum = minimum + 1
        while True:
            if minimum > 1:
                minimum = minimum - 1
            put(w, TS_MIN_GALLOP, minimum)
            put(w, MERGE_KIND, 2)
            put(w, MERGE_FROM, base_b)
            put(w, MERGE_TO, destination + 8 - length_b * 8)
            put(w, MERGE_COUNT, length_b)
            count_a = ts_gallop_right(get(w, array_b), base_a, length_a, length_a - 1)
            if count_a == ERROR:
                ts_move(w, destination + 8 - length_b * 8, base_b, length_b)
                put(w, MERGE_KIND, 0)
                return ERROR
            count_a = length_a - count_a
            if count_a != 0:
                destination = destination - count_a * 8
                array_a = array_a - count_a * 8
                ts_move(w, destination + 8, array_a + 8, count_a)
                length_a = length_a - count_a
                if length_a == 0:
                    ts_move(w, destination + 8 - length_b * 8, base_b, length_b)
                    put(w, MERGE_KIND, 0)
                    return 0
            put(w, destination, get(w, array_b))
            destination = destination - 8
            array_b = array_b - 8
            length_b = length_b - 1
            if length_b == 1:
                ts_move(w, destination + 8 - length_a * 8, array_a + 8 - length_a * 8, length_a)
                put(w, destination - length_a * 8, get(w, array_b))
                put(w, MERGE_KIND, 0)
                return 0
            put(w, MERGE_KIND, 2)
            put(w, MERGE_FROM, base_b)
            put(w, MERGE_TO, destination + 8 - length_b * 8)
            put(w, MERGE_COUNT, length_b)
            count_b = ts_gallop_left(get(w, array_a), base_b, length_b, length_b - 1)
            if count_b == ERROR:
                ts_move(w, destination + 8 - length_b * 8, base_b, length_b)
                put(w, MERGE_KIND, 0)
                return ERROR
            count_b = length_b - count_b
            if count_b != 0:
                destination = destination - count_b * 8
                array_b = array_b - count_b * 8
                ts_move(w, destination + 8, array_b + 8, count_b)
                length_b = length_b - count_b
                if length_b == 1:
                    ts_move(w, destination + 8 - length_a * 8, array_a + 8 - length_a * 8, length_a)
                    put(w, destination - length_a * 8, get(w, array_b))
                    put(w, MERGE_KIND, 0)
                    return 0
                if length_b == 0:
                    put(w, MERGE_KIND, 0)
                    return 0
            put(w, destination, get(w, array_a))
            destination = destination - 8
            array_a = array_a - 8
            length_a = length_a - 1
            if length_a == 0:
                ts_move(w, destination + 8 - length_b * 8, base_b, length_b)
                put(w, MERGE_KIND, 0)
                return 0
            if count_a < 7 and count_b < 7:
                break
        minimum = minimum + 1
        put(w, TS_MIN_GALLOP, minimum)
    put(w, MERGE_KIND, 0)
    return 0

def ts_merge_at(index):
    pending = ts_pending(w, index)
    array_a = get(w, pending)
    length_a = get(w, pending + 8)
    array_b = get(w, pending + 24)
    length_b = get(w, pending + 32)
    put(w, pending + 8, length_a + length_b)
    count = get(w, TS_COUNT)
    if index + 3 == count:
        copy_work(w, pending + 24, w, pending + 48, 24)
    put(w, TS_COUNT, count - 1)
    skip = ts_gallop_right(get(w, array_b), array_a, length_a, 0)
    if skip == ERROR:
        return ERROR
    array_a = array_a + skip * 8
    length_a = length_a - skip
    if length_a == 0:
        return 0
    length_b = ts_gallop_left(ts_at(w, array_a, length_a - 1), array_b, length_b, length_b - 1)
    if length_b == ERROR:
        return ERROR
    if length_b == 0:
        return 0
    if length_a <= length_b:
        done = ts_merge_lo(array_a, length_a, array_b, length_b)
        if done == ERROR:
            return ERROR
    else:
        done = ts_merge_hi(array_a, length_a, array_b, length_b)
        if done == ERROR:
            return ERROR
    return done

def ts_found_run(length):
    count = get(w, TS_COUNT)
    if count != 0:
        previous = ts_pending(w, count - 1)
        start = get(w, previous) - get(w, SORT_ARRAY) >> 3
        previous_length = get(w, previous + 8)
        power = ts_power(start, previous_length, length, get(w, SORT_N))
        while get(w, TS_COUNT) > 1:
            before_last = ts_pending(w, get(w, TS_COUNT) - 2)
            if get(w, before_last + 16) <= power:
                break
            done = ts_merge_at(get(w, TS_COUNT) - 2)
            if done == ERROR:
                return ERROR
        previous = ts_pending(w, get(w, TS_COUNT) - 1)
        put(w, previous + 16, power)
    return 0

def ts_force_collapse():
    while get(w, TS_COUNT) > 1:
        index = get(w, TS_COUNT) - 2
        if index > 0:
            prior = ts_pending(w, index - 1)
            following = ts_pending(w, index + 1)
            if get(w, prior + 8) < get(w, following + 8):
                index = index - 1
        done = ts_merge_at(index)
        if done == ERROR:
            return ERROR
    return 0

def ts_main():
    remaining = get(w, SORT_N)
    if remaining < 2:
        return 0
    ready = ts_select_comparator()
    if ready == ERROR:
        return ERROR
    put(w, TS_COUNT, 0)
    put(w, TS_MIN_GALLOP, 7)
    minimum = ts_minrun(remaining)
    cursor = get(w, SORT_ARRAY)
    while remaining != 0:
        if get(w, TS_RUN_VERSION) == 0:
            length = ts_count_old(cursor, remaining)
            if length == ERROR:
                return ERROR
        else:
            length = ts_count_new(cursor, remaining)
            if length == ERROR:
                return ERROR
        if length < minimum:
            forced = choose(remaining <= minimum, remaining, minimum)
            done = ts_binary(cursor, forced, length)
            if done == ERROR:
                return ERROR
            length = forced
        done = ts_found_run(length)
        if done == ERROR:
            return ERROR
        count = get(w, TS_COUNT)
        if count >= 64:
            abort(ABI)
        pending = ts_pending(w, count)
        put(w, pending, cursor)
        put(w, pending + 8, length)
        put(w, TS_COUNT, count + 1)
        cursor = cursor + length * 8
        remaining = remaining - length
    done = ts_force_collapse()
    if done == ERROR:
        return ERROR
    return 0
'''

PURE_SOURCE = r'''

def ts_at(w:mutbuf, array:u64, index:u64) -> u64:
    return get(w, array + index * 8)

def ts_move(w:mutbuf, destination:u64, source:u64, count:u64) -> u64:
    copy_work(w, destination, w, source, count * 8)
    return 0

def ts_reverse(w:mutbuf, array:u64, count:u64) -> u64:
    left = 0
    right = count
    while left < right:
        right = right - 1
        if left < right:
            first = get(w, array + left * 8)
            second = get(w, array + right * 8)
            put(w, array + left * 8, second)
            put(w, array + right * 8, first)
        left = left + 1
    return 0

def ts_pending(w:mutbuf, index:u64) -> u64:
    return get(w, TS_FRAME) + 8192 + index * 24

def ts_minrun(n:u64) -> u64:
    rest = 0
    while n >= 64:
        rest = rest | (n & 1)
        n = n >> 1
    return n + rest

def ts_power(start:u64, first:u64, second:u64, n:u64) -> u64:
    result = 0
    a = 2 * start + first
    b = a + first + second
    while True:
        result = result + 1
        if a >= n:
            a = a - n
            b = b - n
        elif b >= n:
            return result
        a = a << 1
        b = b << 1
    return result
'''
