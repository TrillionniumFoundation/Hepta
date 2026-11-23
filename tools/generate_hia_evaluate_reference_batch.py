"""Generate native case framing for already admitted Core and workload bytes."""

from pathlib import Path
import re
from tempfile import TemporaryDirectory

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_scalar_reference_wire import RESOURCE_KINDS, RESOURCE_PROGRAM_MAGIC, TYPES
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_evaluate_reference_wire import compact_enum
from tools.generate_hia_json_decode import source_program as json_decoder
from tools.generate_hia_mcp_request import WIRE_HELPERS
from tools.generate_hia_worker_context_workload import POLICY as WORKLOAD
from tools.generate_hia_worker_finite_reference import POLICY as FINITE, key_reader, program as finite_program
from tools.generate_hia_worker_inspection_effect import function

SOURCE = Path('examples/hia_bootstrap/evaluate_reference_batch.hepta')
PACKER = SOURCE.with_name('evaluate_reference_batch_packer.hepta')
ADAPTER = 'tools/hia_evaluate_reference_batch.S'
BATCH_MAGIC = int.from_bytes(b'HIAERB01', 'little')
PACK_MAGIC = int.from_bytes(b'HIAEBP01', 'little')
FIELDS = ('functions', 'exports', 'name', 'function', 'params', 'type', 'bytes_hex', 'byte_length', 'fill_byte',
          'arguments', 'cases', 'foreign_buffer_exports', 'max_buffer_bytes', 'returns', 'warmup_iterations', 'repetitions')
BAD = 0xfffffffd
NONE = (1 << 64) - 1

POLICY = r"""
# The fixed transport copies the two sealed inputs into [Core,workload] once.
# Only the selector at the last eight bytes of private workspace varies by case.
def batch_case(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(o) < 33554432 or length(w) < 67108864:
        return BAD
    if get(w, length(w) - 8) == NONE:
        return reference_packet(s, o)
    if get(w, length(w) - 8) == NONE - 1:
        return terminal(s, w)
    if length(s) < 8 or length(s) > 16777219:
        return BAD
    selected = get(w, length(w) - 8)
    put(o, 48, 524289)
    put(o, 56, 128)
    extent = widen(decode_json(s, w, o))
    if extent >= 4294967292 or extent >= length(w) - 32768 or kind(w, 64) != 5 or get(w, 96) != 2:
        return BAD
    core = child(w, 64)
    workload = next(w, core)
    cases = lookup(w, workload, K_cases)
    if kind(w, core) != 6 or kind(w, workload) != 6 or kind(w, cases) != 5:
        return BAD
    count = get(w, cases + 32)
    if count == 0 or count > 512 or selected >= count:
        return BAD
    selected_case = child(w, cases)
    i = 0
    while i < selected:
        selected_case = next(w, selected_case)
        i = i + 1
    name = lookup(w, selected_case, K_function)
    fn = public_function(w, core, name)
    if fn == NONE:
        return BAD
    # Canonical Core preserves the decoded identifier even if the workload
    # spells its name using JSON escapes.
    name = lookup(w, fn, K_name)
    put(o, 8, count)
    put(o, 16, selected)
    put(o, 24, get(w, name + 56))
    put(o, 32, get(w, name + 64))
    return arguments(s, o, w, workload, fn, selected_case)

def arguments(s:readbuf, o:mutbuf, w:mutbuf, workload:u64, fn:u64, selected_case:u64) -> u64:
    params = lookup(w, fn, K_params)
    args = lookup(w, selected_case, K_arguments)
    returns = lookup(w, fn, K_returns)
    if kind(w, params) != 5 or kind(w, args) != 5 or kind(w, returns) != 5:
        return BAD
    result = child(w, returns)
    while result != NONE:
        if type_code(w, result) >= SCALAR_COUNT:
            return BAD
        result = next(w, result)
    n = get(w, params + 32)
    if n > 128 or n != get(w, args + 32):
        return BAD
    exports = lookup(w, workload, K_foreign_buffer_exports)
    selected = named(w, exports, lookup(w, fn, K_name), K_function)
    maxbuf = 0
    if selected != NONE:
        maxbuf = uint(s, w, lookup(w, selected, K_max_buffer_bytes), 1048576)
        if maxbuf == NONE or maxbuf == 0 or get(w, returns + 32) != 1 or type_code(w, child(w, returns)) != U32:
            return BAD
    put(o, 40, n)
    put(o, 48, get(w, returns + 32))
    put(o, 56, maxbuf)
    put(o, 64, 0)
    put(o, 72, 0)
    if capture_arguments(s, o, w, params, args, maxbuf) == False:
        return BAD
    loans = get(o, 64)
    if (loans > 0 and maxbuf == 0) or (loans == 0 and maxbuf > 0):
        return BAD
    put(o, 0, BATCH)
    return suffix(s, o, w, params, args)

def capture_arguments(s:readbuf, o:mutbuf, w:mutbuf, params:u64, args:u64, limit:u64) -> bool:
    typ = child(w, params)
    value = child(w, args)
    index = 0
    while typ != NONE:
        role = type_code(w, lookup(w, typ, K_type))
        if role == READBUF or role == MUTBUF:
            if kind(w, value) != 6 or get(o, 64) == 8:
                return False
            size = snapshot(s, w, value)
            if size > limit:
                return False
            put(o, 64, get(o, 64) + 1)
            put(o, 72, get(o, 72) + size)
            put(o, 80 + 8 * index, 0)
        else:
            if role >= SCALAR_COUNT or capture_value(s, w, length(w) - 1024, value, role) == False:
                return False
            put(o, 80 + 8 * index, get(w, length(w) - 976))
        typ = next(w, typ)
        value = next(w, value)
        index = index + 1
    return True

def suffix(s:readbuf, o:mutbuf, w:mutbuf, params:u64, args:u64) -> u64:
    n = get(o, 40)
    loans = get(o, 64)
    after = 80 + 8 * n
    put(o, after, 16777216)
    put(o, after + 8, 0)
    if loans == 0:
        return after + 16
    put(o, after + 16, loans)
    row = after + 24
    at = row + 24 * loans
    if get(o, 72) > length(o) - at:
        return BAD
    typ = child(w, params)
    value = child(w, args)
    i = 0
    while typ != NONE:
        role = type_code(w, lookup(w, typ, K_type))
        if role == READBUF or role == MUTBUF:
            size = snapshot(s, w, value)
            put(o, row, i)
            put(o, row + 8, choose(role == MUTBUF, 1, 0))
            put(o, row + 16, size)
            materialize(s, o, w, value, at, size)
            at = at + size
            row = row + 24
        i = i + 1
        typ = next(w, typ)
        value = next(w, value)
    return at

def materialize(s:readbuf, o:mutbuf, w:mutbuf, node:u64, at:u64, size:u64) -> u64:
    hex = lookup(w, node, K_bytes_hex)
    i = 0
    if hex != NONE:
        base = get(w, hex + 24)
        while i < size:
            store(o, at + i, 16 * nibble(w, base + 2 * i) + nibble(w, base + 2 * i + 1))
            i = i + 1
    else:
        fill = uint(s, w, lookup(w, node, K_fill_byte), 255)
        while i < size:
            store(o, at + i, fill)
            i = i + 1
    return 0

# [u64 projection-size, HIAERW02, HIAERB01] carries two immutable replies.
# Both ordinary scalar entries and owned programs run on the owned ELF. Its
# reference machine has the same scalar instructions, with an empty ledger.
def reference_packet(s:readbuf, o:mutbuf) -> u64:
    if length(s) < 176:
        return BAD
    n = read_word(s, 0)
    if n < 72 or n > 33554432 or n > length(s) - 88 or read_word(s, 8) != PROJECTED:
        return BAD
    b = 8 + n
    if read_word(s, b) != BATCH or read_word(s, 48) > 1 or read_word(s, 56) != 0 or read_word(s, 64) != 0:
        return BAD
    end = read_word(s, 32)
    returns = read_word(s, 40)
    args = read_word(s, b + 40)
    if end < 72 or end > n or ((n - end) & 7) != 0 or returns != (n - end) >> 3:
        return BAD
    if returns != read_word(s, b + 48) or args > 128:
        return BAD
    tail = b + 80
    if tail > length(s) or length(s) - tail < 16 + args * 8 or length(s) - tail > 33554432 - end:
        return BAD
    put(o, 0, RESOURCE_PROGRAM)
    put(o, 8, choose(read_word(s, b + 56) == 0, 1000000, 10000000))
    put(o, 16, 256)
    put(o, 24, read_word(s, 16))
    put(o, 32, read_word(s, 24))
    put(o, 40, end)
    put(o, 48, args)
    put(o, 56, returns)
    copy_wire(s, o, 72, 64, end - 64)
    copy_wire(s, o, tail, end, length(s) - tail)
    return end + length(s) - tail

def terminal(s:readbuf, w:mutbuf) -> u64:
    if length(s) < 144 or read_word(s, 0) != RESULT:
        return BAD
    status = read_word(s, 8)
    if status > 19 or (status > 11 and status < 15):
        return BAD
    returned = 0
    if status == 0:
        returned = get(w, length(w) - 16)
    if length(s) != 144 + 8 * returned + get(w, length(w) - 24):
        return BAD
    return choose(status == 5 or status == 6 or status == 16, 2, 1)

def read_word(s:readbuf, at:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (widen(byte(s, at + i)) << (i * 8))
        i = i + 1
    return value

def copy_wire(s:readbuf, o:mutbuf, start:u64, at:u64, size:u64) -> u64:
    i = 0
    while i < size:
        store(o, at + i, byte(s, start + i))
        i = i + 1
    return 0

def nibble(w:mutbuf, at:u64) -> u64:
    c = widen(byte(w, at))
    return choose(c < 58, c - 48, c - 87)
"""


def program():
    finite = finite_program()
    helpers = ('public_function', 'published', 'named', 'capture_value', 'kind', 'object', 'child', 'next', 'eq_text')
    types = (*TYPES, *RESOURCE_KINDS[1:])
    constants = {f'K_{name}': i for i, name in enumerate(FIELDS, 1)}
    constants.update(BATCH=BATCH_MAGIC, RESULT=int.from_bytes(b'HIASPR01','little'), PROJECTED=int.from_bytes(b'HIAERW02','little'), RESOURCE_PROGRAM=RESOURCE_PROGRAM_MAGIC, READBUF=types.index('readbuf'), MUTBUF=types.index('mutbuf'),
                     U32=types.index('u32'), SCALAR_COUNT=len(TYPES), BAD=BAD, NONE=NONE)
    policy = '\n'.join((POLICY, *(function(FINITE, name) for name in helpers),
                        *(function(WORKLOAD, name) for name in ('snapshot','uint'))))
    policy = re.sub(r'\b(' + '|'.join(constants) + r')\b', lambda m:str(constants[m[0]]),policy)
    decoder = json_decoder(wire_spans=True).replace('length(s) > 8388608 or','length(s) > 16777219 or')
    return '\n'.join((policy, *(function(finite, name) for name in ('width', 'signed_type')),
                      WIRE_HELPERS.split('\ndef signed_id',1)[0].replace('NONE',str(NONE)), key_reader(FIELDS),
                      compact_enum('type_code',list(zip(types,range(len(types))))),decoder))


def packer_document():
    from tools.build_hia_agent_batch_commit import adapter_layout
    from tools.generate_hia_native_filter import bind_adapter, document as packer, elf_header
    source = Path(ADAPTER).read_bytes()
    with TemporaryDirectory(prefix='hia-evaluate-reference-batch-') as directory:
        adapter, places, _ = adapter_layout(Path(directory), ADAPTER, source, {'plan':'batch_case_call_hole'})
    holes = (places['plan'],)
    head = elf_header()
    result = packer(magic=PACK_MAGIC, module=PACKER.stem,
                    image_template=(head + adapter, (len(head) + holes[0],)))
    return bind_adapter(result, source, adapter, holes)


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(program(), SOURCE.stem)), encoding='utf-8')
    PACKER.write_text(render_assembly(packer_document()), encoding='utf-8')
