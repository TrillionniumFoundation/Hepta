"""Author the batched HIA reference executor for a sealed finite domain."""

from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_scalar_reference import document

SOURCE = Path('examples/hia_bootstrap/worker_finite_batch.hepta')
REQUEST = int.from_bytes(b'HIAVFB01', 'little')
RESPONSE = int.from_bytes(b'HIAVFR01', 'little')

POLICY = r'''
# The program body uses the ordinary independent scalar-reference layout.
# The verifier-selected kind bytes follow the unused one-shot argument array.
# This child has no resource protocol, calls, solver or launcher authority.
def finite_batch(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 84 or uint(s, 0, 8) != REQUEST_TAG or uint(s, 8, 8) != 10000 or uint(s, 16, 8) != 1:
        return 4294967293
    arguments = uint(s, 40, 8)
    count = uint(s, 48, 8)
    results = uint(s, 56, 8)
    kinds = length(s) - 12
    if count > 12 or results > 1 or arguments < 72 or arguments > kinds or count * 8 != kinds - arguments:
        return 4294967293
    registers = uint(s, 24, 8)
    bounce = uint(s, 32, 8)
    if registers < count or registers > 8192 or bounce < results or bounce > 8192:
        return 4294967293
    if registers == 0 or bounce == 0 or length(w) < 72 + 8 * (registers + bounce):
        return 4294967293
    variants = domain_count(s, kinds, count)
    if variants == 0 or length(o) < 40 + variants * 40:
        return 4294967293
    case_index = 0
    while case_index < variants:
        clear_frame(w, registers + bounce)
        put(w, 8, 0)
        set_arguments(s, w, kinds, count, case_index)
        size = reference_program_with_args(s, o, w, 1)
        if append_terminal(o, 40 + case_index * 40, size, results) == False:
            return 4294967293
        case_index = case_index + 1
    put(o, 0, RESPONSE_TAG)
    put(o, 8, 0)
    put(o, 16, variants)
    put(o, 24, count)
    put(o, 32, results)
    return 40 + variants * 40

def domain_count(s:readbuf, kinds:u64, count:u64) -> u64:
    bits = 0
    at = 0
    while at < 12:
        kind = byte(s, kinds + at)
        if at < count:
            if kind != 1 and kind != 8 and kind != 136:
                return 0
            bits = bits + (kind & 127)
            if bits > 12:
                return 0
        elif kind != 0:
            return 0
        at = at + 1
    return 1 << bits

def clear_frame(w:mutbuf, words:u64) -> u64:
    at = 0
    while at < words:
        put(w, 64 + at * 8, 0)
        at = at + 1
    return 0

def set_arguments(s:readbuf, w:mutbuf, kinds:u64, count:u64, ordinal:u64) -> u64:
    # The last parameter changes fastest. Signed byte enumeration starts
    # from -128, exactly as in the existing independent reference ABI.
    while count > 0:
        count = count - 1
        kind = byte(s, kinds + count)
        width = kind & 127
        digit = ordinal & ((1 << width) - 1)
        if kind == 136:
            digit = digit - 128
        put(w, 64 + count * 8, digit)
        ordinal = ordinal >> width
    return 0

def append_terminal(o:mutbuf, at:u64, size:u64, results:u64) -> bool:
    if size != 32 and size != 40:
        return False
    status = get(o, 8)
    if status == 5 or status == 6 or status > 11:
        return False
    if (status == 0 and size != 32 + 8 * results) or (status != 0 and size != 32):
        return False
    put(o, at, get(o, 0))
    put(o, at + 8, status)
    put(o, at + 16, get(o, 16))
    put(o, at + 24, get(o, 24))
    if size == 40:
        put(o, at + 32, get(o, 32))
    else:
        put(o, at + 32, 0)
    return True
'''


if __name__ == '__main__':
    policy = POLICY.replace('REQUEST_TAG', str(REQUEST)).replace('RESPONSE_TAG', str(RESPONSE))
    SOURCE.write_text(render_assembly(document(prefix=policy, module=SOURCE.stem)), encoding='utf-8')
