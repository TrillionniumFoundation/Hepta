"""Fixed native default-DataJSON forwarding controller: transport helpers.

NEW UNEXECUTED DEVELOPMENT. Forked protocol, not an executed revision of the
CLI carrier. Only actual HIA owners choose data operations. Matching lease
numbers do not authenticate external arenas: the exact fixed executor holds all
private immutable input and actual-output mappings for this invocation.
"""
def magic(value):
    assert len(value)==8
    return int.from_bytes(value.encode('ascii'),'little')

CONSTANTS={
 'FD_BAD':0xfffffffd,'FD_MAX':(1<<64)-1,'FD_MIN':65536,
 'FD_EVENT':magic('HIACDE01'),'FD_ACK':magic('HIACDA01'),
 'FD_STATE':magic('HIAWDW01'),'FD_START':magic('HIAWDI01'),
 'FD_INPUT':magic('HIAGFI01'),
 'FD_PREFIX_COMMAND':magic('HIAGDC01'),'FD_PREFIX_ACK':magic('HIAGDA01'),
 'FD_PREFIX_EVENT':magic('HIAGDE01'),'FD_VALUES_EVENT':magic('HIADGE01'),
 'FD_VALUES_ACK':magic('HIADGR01'),
 'F_MAGIC':0,'F_STATUS':8,'F_LEASE':16,'F_SEQ':24,'F_PHASE':32,
 'F_PENDING':40,'F_NEXT':48,'F_RETURN':56,'F_OBSERVE':64,
 'F_GROW_SLOT':72,'F_GROW_BYTES':80,'F_ERROR':88,
 'FD_INPUT_HEADER':128,'FD_OBS':512,'FD_ARGS':1024,'FD_WIRE':2048,
 'FD_PREFIX_FRAME':2304,'FD_VALUES_FRAME':2560,'FD_CAPS':4096,
 'B_INPUT':1,'B_CONTROL':2,'B_FRAME':3,
 'B_RAW':4,'B_PREFIX':5,'B_PEER_OUTPUT':6,'B_PEER_WORK':7,
 'B_VALUES':8,'B_BITS':9,'B_BINARY_WORK':10,'B_UNUSED':11,'B_RESULT':12,
}
FIELDS=('INV','CALL','RAW_LEASE','GRAPH_LEASE','KIND','DIGITS',
 'ARENA_LEASE','VALUES_LEASE','RAW_BYTES','INPUT_BYTES',
 'PREFIX_ROLE','PREFIX_SEQ','PEER','PEER_SEQ','PREFIX_PHASE',
 'INPUT_SLOT','INPUT_AT','INPUT_SIZE','OUTPUT_CAP','WORK_CAP',
 'CONFIG_AT','CONFIG_SIZE','OUTPUT_SLOT','WORK_SLOT','PEER_IMAGE',
 'ACTUAL','REPLY_SLOT','REPLY_SIZE','REPLY_WORK_BYTES','OUTPUT_LEASE',
 'WORKSPACE_LEASE','ARENA_SIZE','VALUES_SEQ','VALUES_NODE',
 'NUMBER_AT','NUMBER_SIZE','VALUES_STATUS','RESULT_KIND','RESULT_SOURCE',
 'RESULT_AT','RESULT_SIZE','CLEAN_SLOT','VALUES_STARTED')
CONSTANTS.update({'F_'+key:8192+8*i for i,key in enumerate(FIELDS)})

COMMON=r'''
def fd_word(s:readbuf, at:u64) -> u64:
    value = byte(s, at)
    value = value | (byte(s, at + 1) << 8)
    value = value | (byte(s, at + 2) << 16)
    value = value | (byte(s, at + 3) << 24)
    value = value | (byte(s, at + 4) << 32)
    value = value | (byte(s, at + 5) << 40)
    value = value | (byte(s, at + 6) << 48)
    return value | (byte(s, at + 7) << 56)

def fd_get(w:mutbuf, at:u64) -> u64:
    value = byte(w, at)
    value = value | (byte(w, at + 1) << 8)
    value = value | (byte(w, at + 2) << 16)
    value = value | (byte(w, at + 3) << 24)
    value = value | (byte(w, at + 4) << 32)
    value = value | (byte(w, at + 5) << 40)
    value = value | (byte(w, at + 6) << 48)
    return value | (byte(w, at + 7) << 56)

def fd_put(w:mutbuf, at:u64, value:u64) -> u64:
    store(w, at, value & 255)
    store(w, at + 1, (value >> 8) & 255)
    store(w, at + 2, (value >> 16) & 255)
    store(w, at + 3, (value >> 24) & 255)
    store(w, at + 4, (value >> 32) & 255)
    store(w, at + 5, (value >> 40) & 255)
    store(w, at + 6, (value >> 48) & 255)
    store(w, at + 7, (value >> 56) & 255)
    return 0

def fd_refuse(w:mutbuf, reason:u64) -> u32:
    fd_put(w, F_MAGIC, FD_STATE)
    fd_put(w, F_STATUS, 3)
    fd_put(w, F_ERROR, reason)
    return FD_BAD

def fd_cap(w:mutbuf, slot:u64) -> u64:
    if slot >= 64:
        return 0
    return fd_get(w, FD_CAPS + slot * 8)

def fd_inside(w:mutbuf, slot:u64, at:u64, size:u64) -> u64:
    if slot >= 64:
        return 0
    capacity = fd_cap(w, slot)
    if at > capacity or size > capacity - at:
        return 0
    return 1

def fd_args(w:mutbuf, a:u64, b:u64, c:u64, d:u64, e:u64, f:u64, g:u64, h:u64, i:u64, j:u64, k:u64, l:u64) -> u64:
    fd_put(w, FD_ARGS, a)
    fd_put(w, FD_ARGS + 8, b)
    fd_put(w, FD_ARGS + 16, c)
    fd_put(w, FD_ARGS + 24, d)
    fd_put(w, FD_ARGS + 32, e)
    fd_put(w, FD_ARGS + 40, f)
    fd_put(w, FD_ARGS + 48, g)
    fd_put(w, FD_ARGS + 56, h)
    fd_put(w, FD_ARGS + 64, i)
    fd_put(w, FD_ARGS + 72, j)
    fd_put(w, FD_ARGS + 80, k)
    fd_put(w, FD_ARGS + 88, l)
    return 0

def fd_event(o:mutbuf, w:mutbuf, opcode:u64, phase:u64) -> u32:
    if fd_get(w, F_STATUS) != 1 or fd_get(w, F_PENDING) != 0:
        return fd_refuse(w, 1)
    sequence = fd_get(w, F_SEQ)
    if sequence == FD_MAX:
        return fd_refuse(w, 2)
    fd_put(w, F_SEQ, sequence + 1)
    fd_put(w, F_PENDING, opcode)
    fd_put(w, F_NEXT, phase)
    fd_put(o, 0, FD_EVENT)
    fd_put(o, 8, opcode)
    fd_put(o, 16, fd_get(w, F_LEASE))
    fd_put(o, 24, sequence + 1)
    index = 0
    while index < 96:
        store(o, 32 + index, byte(w, FD_ARGS + index))
        index = index + 1
    return 128

def fd_ack(s:readbuf, w:mutbuf) -> u64:
    pending = fd_get(w, F_PENDING)
    count = fd_get(w, F_OBSERVE)
    if pending == 0 or count > 256 or length(s) != 64 + count:
        return 0
    if fd_word(s, 0) != FD_ACK or fd_word(s, 8) != fd_get(w, F_LEASE):
        return 0
    if fd_word(s, 16) != fd_get(w, F_SEQ) or fd_word(s, 24) != pending:
        return 0
    if fd_word(s, 32) != 0 or fd_word(s, 48) != count or fd_word(s, 56) != 0:
        return 0
    if pending == 1:
        if fd_word(s, 40) > 4294967295 or fd_word(s, 40) == FD_BAD:
            return 0
    elif fd_word(s, 40) != 0:
        return 0
    if pending == 2:
        fd_put(w, FD_CAPS + fd_get(w, F_GROW_SLOT) * 8, fd_get(w, F_GROW_BYTES))
    if pending == 5:
        fd_put(w, FD_CAPS + fd_get(w, FD_ARGS) * 8, 0)
    fd_put(w, F_RETURN, fd_word(s, 40))
    copy_bytes(w, s, FD_OBS, 64, count)
    fd_put(w, F_PENDING, 0)
    fd_put(w, F_PHASE, fd_get(w, F_NEXT))
    fd_put(w, F_OBSERVE, 0)
    return 1

def fd_grow(o:mutbuf, w:mutbuf, slot:u64, size:u64, phase:u64) -> u32:
    if slot < 4 or slot >= 64 or size == 0:
        return fd_refuse(w, 3)
    if fd_cap(w, slot) >= size:
        fd_put(w, F_PHASE, phase)
        return 0
    fd_put(w, F_GROW_SLOT, slot)
    fd_put(w, F_GROW_BYTES, size)
    fd_put(w, F_OBSERVE, 0)
    fd_args(w, slot, size, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    return fd_event(o, w, 2, phase)

def fd_clear(o:mutbuf, w:mutbuf, slot:u64, at:u64, size:u64, phase:u64) -> u32:
    if slot < 4 or fd_inside(w, slot, at, size) == 0:
        return fd_refuse(w, 4)
    fd_put(w, F_OBSERVE, 0)
    fd_args(w, slot, at, size, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    return fd_event(o, w, 3, phase)

def fd_copy(o:mutbuf, w:mutbuf, source:u64, at:u64, target:u64, to:u64, size:u64, phase:u64) -> u32:
    if source == target or target < 4:
        return fd_refuse(w, 5)
    if fd_inside(w, source, at, size) == 0 or fd_inside(w, target, to, size) == 0:
        return fd_refuse(w, 6)
    fd_put(w, F_OBSERVE, 0)
    fd_args(w, source, at, target, to, size, 0, 0, 0, 0, 0, 0, 0)
    return fd_event(o, w, 4, phase)

def fd_protect(o:mutbuf, w:mutbuf, slot:u64, readonly:u64, phase:u64) -> u32:
    if slot < 4 or slot >= 64 or fd_cap(w, slot) == 0 or readonly > 1:
        return fd_refuse(w, 7)
    fd_put(w, F_OBSERVE, 0)
    fd_args(w, slot, readonly, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    return fd_event(o, w, 6, phase)

def fd_release(o:mutbuf, w:mutbuf, slot:u64, phase:u64) -> u32:
    if slot < 4 or slot >= 64:
        return fd_refuse(w, 8)
    if fd_cap(w, slot) == 0:
        fd_put(w, F_PHASE, phase)
        return 0
    fd_put(w, F_OBSERVE, 0)
    fd_args(w, slot, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    return fd_event(o, w, 5, phase)

def fd_view(o:mutbuf, w:mutbuf, slot:u64, at:u64, size:u64, phase:u64) -> u32:
    if size > 256 or fd_inside(w, slot, at, size) == 0:
        return fd_refuse(w, 9)
    fd_put(w, F_OBSERVE, size)
    fd_args(w, slot, at, size, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    return fd_event(o, w, 14, phase)

def fd_call(o:mutbuf, w:mutbuf, image:u64, first:u64, at:u64, size:u64, second:u64, extent:u64, work:u64, worksize:u64, observe:u64, offset:u64, count:u64, phase:u64) -> u32:
    if image == 0 or image > 7 or first == second or first == work or second == work:
        return fd_refuse(w, 10)
    if first == B_CONTROL or second == B_CONTROL or work < 4:
        return fd_refuse(w, 11)
    if fd_inside(w, first, at, size) == 0 or fd_inside(w, second, 0, extent) == 0:
        return fd_refuse(w, 12)
    if fd_inside(w, work, 0, worksize) == 0 or count > 256:
        return fd_refuse(w, 13)
    if fd_inside(w, observe, offset, count) == 0:
        return fd_refuse(w, 14)
    fd_put(w, F_OBSERVE, count)
    fd_args(w, image, first, at, size, second, extent, work, worksize, observe, offset, count, 0)
    return fd_event(o, w, 1, phase)

def fd_role(phase:u64) -> u64:
    if phase == 1 or phase == 10:
        return 1
    if phase == 20 or phase == 30 or phase == 40:
        return 2
    if phase == 50 or phase == 51:
        return 3
    return 0

def fd_prefix_word(w:mutbuf, index:u64) -> u64:
    return fd_get(w, FD_PREFIX_FRAME + index * 8)

def fd_values_word(w:mutbuf, index:u64) -> u64:
    return fd_get(w, FD_VALUES_FRAME + index * 8)
'''
