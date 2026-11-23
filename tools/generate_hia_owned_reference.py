"""Compose the standalone HIA owned-buffer reference entry with its VM and arenas."""
from pathlib import Path
from tempfile import TemporaryDirectory

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_scalar_reference_wire import RESOURCE_CODES
from tools.generate_hia_scalar_reference import document as reference_document

ROOT = Path(__file__).resolve().parents[1]
SOURCE_PATH = 'examples/hia_bootstrap/owned_reference.hepta'
PACKER_PATH = 'examples/hia_bootstrap/owned_reference_cli_packer.hepta'
ADAPTER_PATH = 'tools/hia_owned_reference_syscalls.S'
PACKER_MAGIC = int.from_bytes(b'HIAOPK01', 'little')
ADAPTER_CALLS = {'plan': 'owned_plan_call_hole', 'run': 'owned_run_call_hole'}
# The closed executor follows the public planner and its two local preamble
# helpers. The cold compiler emits this function's offset in its own table.
RUN_FUNCTION = 3

SOURCE = '''
def plan(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    end = budget_offset(s)
    if end == 0 or length(o) < 96:
        return 4294967295
    external = external_extent(s, end)
    if external > @MAX_EXTERNAL_BYTES@:
        return 4294967295
    steps = uint(s, 8, 8)
    depth = uint(s, 16, 8)
    registers = uint(s, 24, 8)
    bounce = uint(s, 32, 8)
    output = 216 + bounce * 8 + external
    stride = (registers + bounce + 1) * 8
    mapping(o, 0, output, output)
    mapping(o, 8, 64 + stride * depth, 64 + stride)
    mapping(o, 16, arena_bytes(2 * steps + @MAX_RANGES@, @OWNER_RECORD_BYTES@), 64 * @OWNER_RECORD_BYTES@)
    mapping(o, 24, arena_bytes(steps + bounce * depth + @MAX_RANGES@, 24), 64 * 24)
    mapping(o, 32, uint(s, end, 8) + external, 65536 + external)
    mapping(o, 40, (steps + 1) * 40, 64 * 40)
    return 96

def arena_bytes(slots:u64, width:u64) -> u64:
    if slots > 16777215:
        slots = 16777215
    return (slots + 1) * width

def budget_offset(s:readbuf) -> u64:
    if length(s) < 88 or length(s) > @MAX_PACKET_BYTES@ or uint(s, 0, 8) != @RESOURCE_PROGRAM_MAGIC@:
        return 0
    steps = uint(s, 8, 8)
    depth = uint(s, 16, 8)
    if steps == 0 or steps > 10000000 or depth == 0 or depth > 256:
        return 0
    registers = uint(s, 24, 8)
    bounce = uint(s, 32, 8)
    if registers == 0 or registers > @MAX_FRAME_WORDS@ or bounce == 0 or bounce > @MAX_FRAME_WORDS@ - registers:
        return 0
    start = uint(s, 40, 8)
    args = uint(s, 48, 8)
    if start < 72 or start % 8 != 0 or start > length(s) or args > registers or args > (length(s) - start) // 8:
        return 0
    end = start + args * 8
    if length(s) - end < 16 or uint(s, end, 8) > 1073741824 or uint(s, end + 8, 8) > 10000000:
        return 0
    return end

def standalone(s:readbuf, o:mutbuf, frames:mutbuf, owners:mutbuf, loans:mutbuf, backing:mutbuf, chains:mutbuf) -> u32:
    end = budget_offset(s)
    if end == 0:
        return 4294967295
    maximum = uint(s, end, 8)
    failure = uint(s, end + 8, 8)
    external = external_extent(s, end)
    if external > @MAX_EXTERNAL_BYTES@ or length(backing) < external or length(backing) - external > maximum:
        return 4294967295
    if length(frames) < 64 or length(owners) < @OWNER_RECORD_BYTES@ or length(loans) < 24 or length(chains) < 40:
        return 4294967294
    bounce = uint(s, 32, 8)
    if length(o) < 216 + bounce * 8 + external:
        return 4294967294
    put(o, length(o) - 56, external)
    preloaded = 0
    if length(s) > end + 16:
        if initialize_external(s, frames, owners, loans, backing, end) == 0:
            return 4294967295
        preloaded = 1
    return run_owned(s, o, frames, owners, loans, backing, chains, maximum, failure, preloaded)

def external_extent(s:readbuf, end:u64) -> u64:
    if length(s) == end + 16:
        return 0
    if length(s) < end + 24:
        return 18446744073709551615
    count = uint(s, end + 16, 8)
    if count == 0 or count > @MAX_RANGES@ or within(length(s), end + 24, count * 24) == 0:
        return 18446744073709551615
    last = 0
    i = 0
    extent = 0
    start = uint(s, 40, 8)
    arguments = uint(s, 48, 8)
    while i < count:
        record = end + 24 + i * 24
        index = uint(s, record, 8)
        mode = uint(s, record + 8, 8)
        size = uint(s, record + 16, 8)
        if index < last or index >= arguments or mode > 1 or size > @MAX_EXTENT@:
            return 18446744073709551615
        if uint(s, start + index * 8, 8) != 0:
            return 18446744073709551615
        last = index + 1
        extent = extent + size
        i = i + 1
    if length(s) - end - 24 - count * 24 != extent:
        return 18446744073709551615
    return extent

def initialize_external(s:readbuf, frames:mutbuf, owners:mutbuf, loans:mutbuf, backing:mutbuf, end:u64) -> u64:
    arguments = uint(s, 48, 8)
    if length(frames) < 64 + 8 * arguments:
        return 0
    start = uint(s, 40, 8)
    i = 0
    while i < arguments:
        put(frames, 64 + 8 * i, uint(s, start + 8 * i, 8))
        i = i + 1
    return external_arguments(s, frames, owners, loans, backing, end)

def external_arguments(s:readbuf, frames:mutbuf, owners:mutbuf, loans:mutbuf, backing:mutbuf, end:u64) -> u64:
    count = uint(s, end + 16, 8)
    data = end + 24 + 24 * count
    i = 0
    offset = 0
    while i < count:
        record = end + 24 + 24 * i
        size = uint(s, record + 16, 8)
        root = external_owner(owners, offset, size)
        if root == 0:
            return 0
        view = loan_allocate(loans, root, 2 + uint(s, record + 8, 8))
        if view == 0:
            return 0
        put(frames, 64 + 8 * uint(s, record, 8), view)
        copy_range(backing, s, offset, data + offset, size)
        offset = offset + size
        i = i + 1
    return 1

def external_owner(w:mutbuf, offset:u64, extent:u64) -> u64:
    token = arena_claim(w, @OWNER_RECORD_BYTES@)
    if token == 0:
        return 0
    slot = arena_slot(w, token, @OWNER_RECORD_BYTES@)
    put(w, slot + 16, extent)
    put(w, slot + 24, offset)
    put(w, slot + 48, 1)
    if extent != 0:
        tail = get(w, 88)
        if tail == 0:
            put(w, 80, slot)
        else:
            put(w, tail + 32, slot)
        put(w, slot + 40, tail)
        put(w, 88, slot)
        put(w, 96, offset + extent)
    return token & 18446744073709551614

def run_owned(s:readbuf, o:mutbuf, frames:mutbuf, owners:mutbuf, loans:mutbuf, backing:mutbuf, chains:mutbuf, maximum:u64, failure:u64, preloaded:u64) -> u32:
    while length(s) > 0:
        size = unsigned_word(reference_program_with_args(s, o, frames, preloaded))
        if size < 32 or size > length(o):
            return size
        status = get(o, 8)
        if status == 14:
            return 4294967041
        if status != 13:
            return resource_terminal(o, owners, backing, chains, size)
        site = get(o, 24)
        code = uint(s, site, 8)
        if code == @RETURN_LOANS_CODE@:
            restored = restore_returns(s, o, owners, loans, site, length(backing))
            if restored == 2:
                return 4294967043
            if restored == 0:
                return 4294967295
        else:
            kind = uint(s, site + 8, 8)
            outcome = 0
            if (code >= @r.chain.empty@ and code <= @r.chain.head_mut@) or kind == 2:
                outcome = owned_chain_command(s, o, frames, owners, loans, backing, chains, code, maximum, failure)
            else:
                outcome = owned_command(o, owners, loans, backing, code, kind, maximum, failure)
            if outcome != 0:
                if outcome == 5:
                    put(o, 8, 5)
                    put(o, 16, get(frames, 0))
                    put(o, 24, 0)
                elif outcome >= 15 and outcome <= 19:
                    put(o, 8, outcome)
                    put(o, 24, code)
                elif outcome >= 22 and outcome <= 25:
                    return 4294967020 + outcome
                else:
                    return 4294967295
                return resource_terminal(o, owners, backing, chains, 32)
    return 4294967295

def mapping(o:mutbuf, offset:u64, limit:u64, initial:u64) -> u64:
    put(o, offset, limit)
    if initial > limit:
        initial = limit
    put(o, offset + 48, initial)
    return 0

def unsigned_word(value:u64) -> u64:
    return value

def resource_terminal(o:mutbuf, owners:mutbuf, backing:mutbuf, chains:mutbuf, size:u64) -> u32:
    ledger = length(o) - 48
    external = get(o, ledger - 8)
    if size > ledger or ledger - size < 112 or external > length(o) - size - 112:
        return 4294967294
    if get(o, 8) == 0:
        if get(owners, 48) != get(owners, 56) or get(o, ledger + 32) != get(o, ledger + 40) or get(chains, 24) != 0:
            return 4294967295
    i = 0
    while i < 7:
        put(o, size + 8 * i, get(owners, 24 + 8 * i))
        i = i + 1
    put(o, size + 56, get(o, ledger + 32))
    put(o, size + 64, get(o, ledger + 40))
    i = 0
    while i < 4:
        put(o, size + 72 + 8 * i, get(o, ledger + 8 * i))
        i = i + 1
    put(o, size + 104, get(chains, 24))
    if external != 0:
        snapshot(o, backing, size + 112, external)
    return size + 112 + external

def snapshot(o:mutbuf, backing:mutbuf, offset:u64, extent:u64) -> u64:
    original = borrow_read(backing)
    copy_range(o, original, offset, 0, extent)
    loan_end(original)
    return 0

def restore_returns(s:readbuf, o:mutbuf, owners:mutbuf, loans:mutbuf, site:u64, maximum:u64) -> u64:
    count = uint(s, site + 24, 8)
    index = 0
    started = length(o) - 16
    while index < count:
        tag = uint(s, site + 32 + 8 * index, 8)
        if tag != 0:
            value = get(o, 32 + 8 * index)
            origin = get(o, 32 + 8 * ((tag >> 1) - 1))
            root = loan_root(loans, value)
            if owner_span(owners, root >> 1, maximum) == 0:
                return 0
            restored = restore_loan(loans, value, origin, tag & 1, root, loan_slot(loans, value))
            if restored == 2:
                return 2
            if restored < 2:
                return 0
            if restored != value:
                put(o, started, get(o, started) + 1)
                put(o, 32 + 8 * index, restored)
        index = index + 1
    return 1

def owned_command(o:mutbuf, owners:mutbuf, loans:mutbuf, backing:mutbuf, code:u64, kind:u64, maximum:u64, failure:u64) -> u64:
    first = get(o, 32)
    if code == @r.buffer.new@ or code == @r.buffer.try_new@:
        return owned_allocate(o, owners, backing, first, maximum, failure, code)
    if code == @r.owner.move@ or code == @r.owner.drop@:
        if kind != 1:
            return 20
        slot = owner_span(owners, first, length(backing))
        if slot == 0 or get(owners, slot + 48) != 0:
            return 20
        if code == @r.owner.drop@:
            drop_storage(owners, slot)
        return 0
    if code == @r.borrow.read@ or code == @r.borrow.mut@:
        root = first
        if kind == 1:
            root = first << 1
        writable = 0
        if code == @r.borrow.mut@:
            writable = 1
        parent = owned_root(loans, root, writable)
        slot = owner_span(owners, parent, length(backing))
        if slot == 0 or (kind == 1 and get(owners, slot + 48) != 0):
            return 20
        return make_loan(o, loans, root, writable)
    if code == @r.loan.end@:
        row = loan_slot(loans, first)
        if row == 0 or get(loans, row + 16) >= 2 or owned_root(loans, first, 0) == 0:
            return 20
        arena_release(loans, row, 24)
        put(loans, row + 16, 0)
        count = length(o) - 8
        put(o, count, get(o, count) + 1)
        return 0
    word = code >= @r.buffer.load.u64.le@ and code <= @r.buffer.store.u64.be@
    if (code < @r.buffer.len@ or code > @r.buffer.swap@) and not word:
        return 20
    writable = 0
    if code != @r.buffer.len@ and code != @r.buffer.load@ and code != @r.buffer.load.u64.le@ and code != @r.buffer.load.u64.be@:
        writable = 1
    handle = first
    if kind == 1:
        handle = first << 1
    owner = owned_root(loans, handle, writable)
    if owner == 0:
        return 20
    return owned_bytes(o, owners, loans, backing, code, owner)

def make_loan(o:mutbuf, loans:mutbuf, root:u64, writable:u64) -> u64:
    loan = loan_allocate(loans, root, writable)
    if loan == 0:
        return 23
    put(o, 32, loan)
    increment(o, length(o) - 16)
    return 0

def increment(o:mutbuf, offset:u64) -> u64:
    put(o, offset, get(o, offset) + 1)
    return 0

def owned_chain_command(s:readbuf, o:mutbuf, frames:mutbuf, owners:mutbuf, loans:mutbuf, backing:mutbuf, chains:mutbuf, code:u64, maximum:u64, failure:u64) -> u64:
    subject = get(o, 32)
    if code == @r.owner.drop@:
        return dispose_chain(s, o, frames, owners, chains, subject, length(backing))
    if code == @r.chain.try_push@:
        return push_chain(o, owners, backing, chains, subject, maximum, failure)
    if code == @r.chain.pop@:
        return pop_chain(o, owners, chains, subject, length(backing))
    if code == @r.chain.empty@:
        reply = chain_call(o, chains, 1, 0, 0, 0, 0)
        if reply == 1:
            return 25
        if reply == 0:
            return 20
        put(o, 32, get(o, reply + 16))
        increment(o, length(o) - 48)
        return 0
    return inspect_chain(o, owners, loans, chains, subject, code, length(backing))

def chain_call(o:mutbuf, chains:mutbuf, operation:u64, subject:u64, payload:u64, storage:u64, admitted:u64) -> u64:
    reply = length(o) - 112
    if unsigned_word(apply_chain_operation(o, chains, reply, operation, subject, payload, storage, admitted)) != 56:
        return 0
    status = get(o, reply + 8)
    if status == 3:
        return 1
    if status != 0:
        return 0
    return reply

def inspect_chain(o:mutbuf, owners:mutbuf, loans:mutbuf, chains:mutbuf, subject:u64, code:u64, maximum:u64) -> u64:
    reply = chain_call(o, chains, 2, subject, 0, 0, 0)
    if reply == 0:
        return 20
    if code == @r.owner.move@:
        return 0
    present = get(o, reply + 40)
    if code == @r.chain.is_empty@:
        put(o, 32, 1 - present)
        return 0
    if code != @r.chain.head_read@ and code != @r.chain.head_mut@:
        return 20
    if present == 0:
        return 19
    payload = get(o, reply + 24)
    if owner_span(owners, payload, maximum) == 0:
        return 20
    writable = 0
    if code == @r.chain.head_mut@:
        writable = 1
    return make_loan(o, loans, payload << 1, writable)

def push_chain(o:mutbuf, owners:mutbuf, backing:mutbuf, chains:mutbuf, subject:u64, maximum:u64, failure:u64) -> u64:
    payload = get(o, 40)
    slot = owner_span(owners, payload, length(backing))
    if chain_call(o, chains, 2, subject, 0, 0, 0) == 0 or slot == 0 or get(owners, slot + 48) != 0:
        return 20
    status = owned_allocate(o, owners, backing, @CHAIN_NODE_BYTES@, maximum, failure, @r.buffer.try_new@)
    if status != 0:
        return status
    storage = get(o, 32)
    admitted = get(o, 40)
    reply = chain_call(o, chains, 3, subject, payload, storage, admitted)
    if reply == 1:
        return 25
    if reply == 0:
        return 20
    remainder = payload
    if admitted == 1:
        remainder = claim_owner(owners, 0) >> 1
        if remainder == 0:
            return 22
        increment(o, length(o) - 32)
    elif release_owner(owners, storage, length(backing)) == 0:
        return 20
    return chain_replace(o, get(o, reply + 16), remainder, admitted)

def pop_chain(o:mutbuf, owners:mutbuf, chains:mutbuf, subject:u64, maximum:u64) -> u64:
    reply = chain_call(o, chains, 4, subject, 0, 0, 0)
    if reply == 0:
        return 20
    present = get(o, reply + 40)
    payload = get(o, reply + 24)
    if present == 1:
        if release_owner(owners, get(o, reply + 32), maximum) == 0:
            return 20
        increment(o, length(o) - 24)
    else:
        payload = claim_owner(owners, 0) >> 1
        if payload == 0:
            return 22
    return chain_replace(o, get(o, reply + 16), payload, present)

def chain_replace(o:mutbuf, chain:u64, payload:u64, present:u64) -> u64:
    put(o, 32, chain)
    put(o, 40, payload)
    put(o, 48, present)
    increment(o, length(o) - 48)
    increment(o, length(o) - 40)
    return 0

def release_owner(owners:mutbuf, owner:u64, maximum:u64) -> u64:
    slot = owner_span(owners, owner, maximum)
    if slot == 0 or get(owners, slot + 48) != 0:
        return 0
    drop_storage(owners, slot)
    return 1

def dispose_chain(s:readbuf, o:mutbuf, frames:mutbuf, owners:mutbuf, chains:mutbuf, subject:u64, maximum:u64) -> u64:
    reply = chain_call(o, chains, 5, subject, 0, 0, 0)
    if reply == 0:
        return 20
    increment(o, length(o) - 40)
    head = get(o, reply + 16)
    while head != 0:
        if tick(s, frames) == 0:
            return 5
        reply = chain_call(o, chains, 6, head, 0, 0, 0)
        if reply == 0 or release_owner(owners, get(o, reply + 24), maximum) == 0 or release_owner(owners, get(o, reply + 32), maximum) == 0:
            return 20
        increment(o, length(o) - 24)
        head = get(o, reply + 16)
    return 0

def owned_root(loans:mutbuf, handle:u64, writable:u64) -> u64:
    slot = loan_slot(loans, handle)
    if writable == 1 and slot != 0 and (get(loans, slot + 16) & 1) != 1:
        return 0
    return loan_root(loans, handle) >> 1

def owned_allocate(o:mutbuf, owners:mutbuf, backing:mutbuf, amount:u64, maximum:u64, failure:u64, code:u64) -> u64:
    live = get(owners, 64)
    attempts = get(owners, 24)
    if live > maximum or attempts >= 10000000:
        return 20
    decision = allocation_status(amount, maximum, live, attempts, failure)
    if decision == 2:
        return 16
    if decision >= 3:
        put(owners, 24, attempts + 1)
    token = 0
    if decision == 4:
        status = unsigned_word(allocate_storage_after_prefix(backing, owners, amount, maximum, get(o, length(o) - 56)))
        if status == 2:
            return 24
        if status == 3:
            return 22
        if status != 0:
            return 20
        token = get(owners, 104)
    else:
        if decision != 0 and code == @r.buffer.new@:
            if decision == 1:
                return 15
            return 17
        token = claim_owner(owners, 0) >> 1
        if token == 0:
            return 22
    put(o, 32, token)
    if code == @r.buffer.try_new@:
        success = 0
        if decision == 0 or decision == 4:
            success = 1
        put(o, 40, success)
    return 0

def owned_bytes(o:mutbuf, owners:mutbuf, loans:mutbuf, backing:mutbuf, code:u64, owner:u64) -> u64:
    slot = owner_span(owners, owner, length(backing))
    if slot == 0:
        return 20
    second = get(o, 40)
    third = get(o, 48)
    fourth = get(o, 56)
    fifth = get(o, 64)
    if code == @r.buffer.len@:
        put(o, 32, get(owners, slot + 16))
        return 0
    if code >= @r.buffer.load.u64.le@ and code <= @r.buffer.store.u64.be@:
        operation = 7 + code - @r.buffer.load.u64.le@
        status = unsigned_word(access_storage(backing, owners, operation, owner, 0, second, 0, 0, third))
        if status == 4294967293:
            return 18
        if status != 0:
            return 20
        if operation <= 8:
            put(o, 32, get(owners, 104))
        return 0
    if code == @r.buffer.load@:
        return finish_bytes(o, access_storage(backing, owners, 1, owner, 0, second, 0, 0, 0), 1)
    if code == @r.buffer.store@:
        return finish_bytes(o, access_storage(backing, owners, 2, owner, 0, second, 0, 0, third), 0)
    if code == @r.buffer.fill@:
        return finish_bytes(o, access_storage(backing, owners, 3, owner, 0, 0, 0, get(owners, slot + 16), second), 0)
    if code == @r.buffer.fill_range@:
        return finish_bytes(o, access_storage(backing, owners, 3, owner, 0, second, 0, third, fourth), 0)
    if code == @r.buffer.copy@ or code == @r.buffer.copy_range@:
        source = owned_root(loans, second, 0)
        if source == 0 or source == owner:
            return 20
        if code == @r.buffer.copy@:
            return finish_bytes(o, access_storage(backing, owners, 4, owner, source, 0, 0, third, 0), 0)
        return finish_bytes(o, access_storage(backing, owners, 4, owner, source, third, fourth, fifth, 0), 0)
    if code == @r.buffer.move_within@:
        return finish_bytes(o, access_storage(backing, owners, 5, owner, 0, second, third, fourth, 0), 0)
    return finish_bytes(o, access_storage(backing, owners, 6, owner, 0, second, third, 0, 0), 0)

def finish_bytes(o:mutbuf, status:u64, load:u64) -> u64:
    if status == 4294967293:
        return 18
    if status >= 256 and status <= 511 and load == 1:
        put(o, 32, status - 256)
        return 0
    if status == 0 and load == 0:
        return 0
    return 20
'''


def document():
    from hepta.hia_native_byte_abi import MAX_EXTENT, MAX_RANGES
    from hepta.hia_program_runtime import CHAIN_NODE_BYTES

    source = SOURCE
    constants = {'CHAIN_NODE_BYTES': CHAIN_NODE_BYTES, 'MAX_RANGES': MAX_RANGES,
                 'MAX_EXTENT': MAX_EXTENT, 'MAX_EXTERNAL_BYTES': MAX_EXTENT * MAX_RANGES}
    for name, value in constants.items():
        source = source.replace(f'@{name}@', str(value))
    for name, code in RESOURCE_CODES.items():
        source = source.replace(f'@r.{name}@', str(code))
    return reference_document(prefix=source, module='owned_reference')


def cli_document():
    from tools.build_hia_agent_batch_commit import adapter_layout
    from tools.generate_hia_native_filter import bind_adapter, document as packer_document, elf_header

    source = (ROOT / ADAPTER_PATH).read_bytes()
    with TemporaryDirectory(prefix='hia-owned-reference-adapter-') as directory:
        adapter, locations, _ = adapter_layout(Path(directory), ADAPTER_PATH, source, ADAPTER_CALLS)
    holes = (locations['plan'], locations['run'])
    header = elf_header()
    packer = packer_document(magic=PACKER_MAGIC, module='owned_reference_cli_packer',
                             image_template=(header + adapter, tuple(len(header) + hole for hole in holes)),
                             private_entry=True)
    return bind_adapter(packer, source, adapter, holes)


if __name__ == '__main__':
    (ROOT / SOURCE_PATH).write_text(render_assembly(document()))
    (ROOT / PACKER_PATH).write_text(render_assembly(cli_document()))
