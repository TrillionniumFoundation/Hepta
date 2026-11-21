"""Author Context freeze effect decisions for the native continuation carrier."""
from pathlib import Path
import re

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_worker_artifact_authority import source_program as primitives

SOURCE = Path('examples/hia_bootstrap/worker_context_effect.hepta')
POLICY = r'''
# The pinned phases have separate owner receipts. The platform can transport
# only the HIA decision for a claimed port, not substitute a budget predicate.
def context_effect(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) >= 8 and length(o) >= 48:
        mode = input_word(s, 0)
        if mode == TIME_SAMPLE and length(s) == 24:
            return sampled_time(s, o)
        if mode == CPU_SAMPLE:
            return online_cpus(s, o)
        if mode == WALL_SAMPLE and length(s) == 32:
            return wall_window(s, o)
    if length(s) < 260 or length(s) > 1024 or length(o) < 48:
        return 4294967293
    extent = input_word(s, 8)
    if input_word(s, 0) != REQUEST or extent != length(s) - 256:
        return 4294967293
    if input_word(s, 16) != CLAIM or input_word(s, 24) != 0 or input_word(s, 40) == 0:
        return 4294967293
    if input_word(s, 48) != 2 or input_word(s, 56) != 1 or input_word(s, 72) != 0:
        return 4294967293
    if (input_word(s, 80) | input_word(s, 88)) == 0 or input_word(s, 96) != PLAN:
        return 4294967293
    port = input_word(s, 32)
    index = input_word(s, 64)
    if port == 8 or (port >= 9 and port <= 17):
        if input_word(s, 136) != WORKLOAD:
            return 4294967293
        return workload_effect(s, o, port)
    if port >= 21 and port <= 36:
        if input_word(s, 184) != COST or input_word(s, 232) != AMOUNT:
            return 4294967293
        return budget_effect(s, o, port, index)
    if port == 38:
        if extent == 4 and byte(s, 256) == 110 and byte(s, 257) == 117 and byte(s, 258) == 108 and byte(s, 259) == 108:
            return respond(o, 0)
        if byte(s, 256) != 123 or byte(s, length(s) - 1) != 125:
            return 4294967293
        return respond(o, 1)
    if port == 90 or port == 91 or port == 92:
        return refusal(o, 4, port - 89)
    if port == 94 or port == 95:
        return refusal(o, 4, port - 90)
    if (port >= 1 and port <= 7) or port == 18 or port == 19 or port == 39 or port == 40 or port == 41 or port == 42 or port == 43 or port == 44 or port == 45 or port == 46:
        return result(o, 0, port, 0)
    if port == 20 or port == 37:
        return respond(o, 0)
    return 4294967293

def workload_effect(s:readbuf, o:mutbuf, port:u64) -> u64:
    exports = input_word(s, 152)
    snapshots = input_word(s, 160)
    if exports > 3 or snapshots > 3:
        return 4294967293
    if port == 8 and exports != 0:
        return refusal(o, 6, exports)
    if port == 14:
        if snapshots == 0:
            return 4294967293
        return refusal(o, 6, 3 + snapshots)
    if port == 10:
        return respond(o, choose(snapshots == 0, 0, 1))
    if port == 12 or port == 13:
        return respond(o, 1)
    if port == 17:
        return respond(o, choose(input_word(s, 168) > 33554432, 1, 0))
    return respond(o, 0)

def budget_effect(s:readbuf, o:mutbuf, port:u64, index:u64) -> u64:
    flags = input_word(s, 192)
    memory = input_word(s, 248)
    if flags > 255 or input_word(s, 240) > 1:
        return 4294967293
    if port == 21 and (flags & 1) == 0:
        return refusal(o, 5, 1)
    if port == 22 and input_word(s, 240) == 0:
        return refusal(o, 5, 2)
    if port == 23:
        return respond(o, choose(memory >= 67108864, 1, 0))
    if port == 24:
        return respond(o, choose(memory <= 4294967296, 1, 0))
    if port == 25:
        return respond(o, choose(input_word(s, 128) > input_word(s, 120), 1, 0))
    if port == 27 or port == 28:
        if index > 1:
            return 4294967293
        wall = (flags >> (3 + index * 2)) & 3
        if port == 27:
            return respond(o, wall & 1)
        if wall != 3:
            return refusal(o, 5, 3 + index)
    if port == 31:
        return respond(o, (flags >> 1) & 1)
    if port == 32:
        if (flags & 6) != 6:
            return 4294967293
        return respond(o, choose(input_word(s, 208) > input_word(s, 112), 1, 0))
    if port == 33:
        return respond(o, flags >> 7)
    if port == 35 or port == 36:
        return respond(o, choose((flags & 42) != 42, 1, 0))
    return respond(o, 0)

def respond(o:mutbuf, observation:u64) -> u64:
    return result(o, 1, observation, 0)

def refusal(o:mutbuf, group:u64, reason:u64) -> u64:
    return result(o, 2, group, reason)

def result(o:mutbuf, action:u64, first:u64, second:u64) -> u64:
    put(o, 0, EFFECT)
    put(o, 8, action)
    put(o, 16, first)
    put(o, 24, second)
    return 32

# Linux CLOCK_REALTIME seconds and nanoseconds to the canonical quoted
# datetime at microsecond precision. Shift the signed Unix time to year 1.
def sampled_time(s:readbuf, o:mutbuf) -> u64:
    seconds = input_word(s, 8) + 62135596800
    nanos = input_word(s, 16)
    if seconds > 315537897599 or nanos >= 1000000000:
        return 4294967293
    day = quotient(seconds, 86400)
    clock = seconds - day * 86400
    march = day + 306
    era = quotient(march, 146097)
    within = march - era * 146097
    years = quotient(within - quotient(within, 1460) + quotient(within, 36524) - quotient(within, 146096), 365)
    year = era * 400 + years
    day_of_year = within - (365 * years + quotient(years, 4) - quotient(years, 100))
    month_index = quotient(5 * day_of_year + 2, 153)
    day_of_month = day_of_year - quotient(153 * month_index + 2, 5) + 1
    month = month_index + 3
    if month > 12:
        month = month - 12
        year = year + 1
    hours = quotient(clock, 3600)
    minutes = quotient(clock - hours * 3600, 60)
    remaining = clock - hours * 3600 - minutes * 60
    store(o, 0, 34)
    digits(o, 1, year, 1000)
    store(o, 5, 45)
    digits(o, 6, month, 10)
    store(o, 8, 45)
    digits(o, 9, day_of_month, 10)
    store(o, 11, 84)
    digits(o, 12, hours, 10)
    store(o, 14, 58)
    digits(o, 15, minutes, 10)
    store(o, 17, 58)
    digits(o, 18, remaining, 10)
    micros = quotient(nanos, 1000)
    past = 20
    if micros != 0:
        store(o, past, 46)
        past = digits(o, past + 1, micros, 100000)
    put(o, past, UTC_SUFFIX)
    return past + 7

def digits(o:mutbuf, at:u64, value:u64, divisor:u64) -> u64:
    while divisor != 0:
        unit = quotient(value, divisor)
        store(o, at, 48 + unit)
        value = value - unit * divisor
        divisor = quotient(divisor, 10)
        at = at + 1
    return at

def quotient(number:u64, divisor:u64) -> u64:
    result = 0
    remainder = 0
    bit = 64
    while bit > 0:
        bit = bit - 1
        remainder = (remainder << 1) | ((number >> bit) & 1)
        if remainder >= divisor:
            remainder = remainder - divisor
            result = result | (1 << bit)
    return result

def wall_window(s:readbuf, o:mutbuf) -> u64:
    created = input_word(s, 8)
    observed = input_word(s, 16)
    limit = input_word(s, 24)
    if limit < 1 or limit > 86400000:
        return 4294967293
    expired = 0
    remaining = 0
    if observed < created:
        remaining = limit + quotient(created - observed, 1000000)
    else:
        elapsed = observed - created
        allowed = limit * 1000000
        if elapsed > allowed:
            expired = 1
        else:
            remaining = quotient(allowed - elapsed, 1000000)
    put(o, 0, WALL_RESULT)
    put(o, 8, expired)
    put(o, 16, remaining)
    return 24

# A Linux online-CPU descriptor reports sorted, disjoint decimal ranges.
# Decode the complete observation rather than trusting an ambient CPU count.
def online_cpus(s:readbuf, o:mutbuf) -> u64:
    end = length(s)
    if end < 10 or end > 4104 or byte(s, end - 1) != 10:
        return 4294967293
    at = 8
    limit = end - 1
    previous = 0
    total = 0
    while at < limit:
        first_pair = cpu_index(s, at, limit)
        if first_pair == 0:
            return 4294967293
        first = first_pair >> 32
        at = first_pair & 4294967295
        last = first
        if at < limit and byte(s, at) == 45:
            last_pair = cpu_index(s, at + 1, limit)
            if last_pair == 0:
                return 4294967293
            last = last_pair >> 32
            at = last_pair & 4294967295
        if last < first or (total != 0 and first <= previous):
            return 4294967293
        previous = last
        total = total + last - first + 1
        if at < limit:
            if byte(s, at) != 44 or at + 1 == limit:
                return 4294967293
            at = at + 1
    divisor = 1
    while total >= divisor * 10:
        divisor = divisor * 10
    put(o, 0, CPU_RESULT)
    return digits(o, 8, total, divisor)

def cpu_index(s:readbuf, at:u64, limit:u64) -> u64:
    first = at
    value = 0
    while at < limit and byte(s, at) >= 48 and byte(s, at) <= 57:
        value = value * 10 + byte(s, at) - 48
        if value > 1048575:
            return 0
        at = at + 1
    if at == first or (at > first + 1 and byte(s, first) == 48):
        return 0
    return (value << 32) | at
'''


def program():
    tags = {'REQUEST': b'HIACTE01', 'CLAIM': b'HCTXRSP1', 'PLAN': b'HIACTP01',
            'WORKLOAD': b'HIACTF01', 'COST': b'HIACTC01', 'AMOUNT': b'HIACTM01',
            'TIME_SAMPLE': b'HIACTT01', 'CPU_SAMPLE': b'HIACTN01', 'CPU_RESULT': b'HIACTN02',
            'WALL_SAMPLE': b'HIACWB01', 'WALL_RESULT': b'HIACWB02',
            'UTC_SUFFIX': b'+00:00"', 'EFFECT': b'HIACTE02'}
    source = re.sub(r'\b(' + '|'.join(tags) + r')\b',
                    lambda match: str(int.from_bytes(tags[match.group()], 'little')), POLICY)
    shared = primitives()
    for name in ('input_word', 'put'):
        begin = shared.index('\ndef ' + name + '(')
        end = shared.index('\ndef ', begin + 1)
        source += shared[begin:end] + '\n'
    return source


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(program(), SOURCE.stem)), encoding='utf-8')
