"""Author the privileged no-argument HIA system-job control admission.

The HIA owner reads the original one-line Request, authenticates the fixed
administrator policy and preserves the root registry namespace and flock.
All policy, path and resource decisions are HIA. Linux adapter code only
performs requested syscalls or dispatches fixed embedded HIA components.
"""
from __future__ import annotations
import argparse,ast,re
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_system_jobctl_request import document,request_source
from tools import generate_hia_system_jobctl_worker_profile as worker_profile
ROOT=Path(__file__).resolve().parents[1]

CONSTANTS=dict(STATE_BYTES=128<<20,RAW=1<<20,ARENA=4<<20,ARENA_BYTES=64<<20,
 SCRATCH=68<<20,SCRATCH_BYTES=32<<20,FILE_RAW=100<<20,REQUEST_OUT=112<<20,
 PWORK=114<<20,CWORK=115<<20,PWORK_UTF8=116<<20,CWORK_UTF8=117<<20,
 NONE=(1<<64)-1,NEG100=(1<<64)-100,NEG4=(1<<64)-4,NEG2=(1<<64)-2,NEG17=(1<<64)-17,
 ARG_MAGIC=int.from_bytes(b'HIAARG02','little'),JOB_ID=8192,UNIT=8320,REGISTRY=8704,
 PATH=16384,TEMP_PATH=20480,PROC_PATH=24576,STAT=32768,
 TABLE=512,VALUES=768,ENV_COUNT=920,REQUEST_SIZE=928,
 OVERRIDE_CWD=944,OVERRIDE_CWD_SIZE=952,OVERRIDE_TIMEOUT=960,OVERRIDE_MASK=968,ERROR=976,
 POLICY_TABLE=40960, **worker_profile.CONSTANTS)

TEXT={
 'root':'/var/lib/hepta-runtime-jobctl','policy':'/etc/hepta-runtime/job-policy.json',
 'workspace_prefix':'/var/lib/hepta-runtime/workspaces','var':'/var','varlib':'/var/lib',
 'procfd':'/proc/self/fd/','lock':'/lock','unit_prefix':'hepta-job-','unit_suffix':'.service',
 'record':'/record.json','spec':'/spec.json','boot':'/proc/sys/kernel/random/boot_id',
 'uuid':'/proc/sys/kernel/random/uuid','start':'start','pty':'pty','status':'status',
 'read':'read','cancel':'cancel','supervise':'supervise','supervise_pty':'supervise-pty'
}
POLICY=r"""
def advance(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(o) != 128 or length(w) != STATE_BYTES:
        return 0
    phase = get(w, 0)
    result = get(w, 8)
    if phase < 100:
        return admission(s, o, w, phase, result)
    if phase >= 1000 and phase < 1010:
        return file_load(s, o, w, phase, result)
    if phase >= 1100 and phase < 1120:
        return canonical(s, o, w, phase, result)
    if phase >= 1200 and phase < 1220:
        return lock_registry(s, o, w, phase, result)
    if phase >= 1500 and phase < 1600:
        return 11
    if (phase >= 200 and phase < 300) or (phase >= 400 and phase < 700):
        return 6
    if (phase >= 300 and phase < 400) or (phase >= 700 and phase < 800) or (phase >= 1400 and phase < 1420):
        return 7
    return 0

def admission(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase >= 80 and phase <= 96:
        return worker_admission(o, w, phase, result)
    if phase == 0:
        if length(s) < 32 or uint(s, 0) != ARG_MAGIC or uint(s, 8) != 1 or uint(s, 24) != length(s):
            return 0
        return call(o, w, 1, 107, 0, 0, 0, 0, 0, 0, 0)
    if phase == 1:
        if result != 0:
            return 0
        put(w, 32, 0)
        put(w, 984, 0)
        put(w, 992, 0)
        return input_byte(o, w)
    if phase == 2:
        if result == NEG4:
            return input_byte(o, w)
        if failed(result) or result > 8192:
            return 0
        put(w, 984, 0)
        put(w, 992, result)
        size = get(w, 32)
        while get(w, 984) < result:
            value = byte(w, 98304 + get(w, 984))
            put(w, 984, get(w, 984) + 1)
            if value == 10:
                put(w, 32, size)
                put(w, OVERRIDE_MASK, 0)
                return decode(o, w, 3, RAW, size)
            if size == 1048576:
                return 0
            store(w, RAW + size, value)
            size = size + 1
        put(w, 32, size)
        if result == 0:
            put(w, OVERRIDE_MASK, 0)
            return decode(o, w, 3, RAW, size)
        return input_byte(o, w)
    if phase == 3 or phase == 23:
        if result >= 4294967280:
            return 0
        return request(o, w, choose(phase == 3, 4, 24))
    if phase == 4:
        if result != 1 or retain_identity(w) == 0:
            return 0
        operation = get(w, 40)
        if operation == 1 or operation == 2:
            terminated(w, text_policy(w, PATH))
            return call(o, w, 10, 262, NEG100, PATH, STAT, 256, 0, 0, 60)
        if operation == 4:
            put(w, 0, 200)
            return 6
        return begin_lock(o, w, 200)
    if phase == 10:
        if result != 0 or getn(w, STAT + 24, 4) & 61440 != 32768 or getn(w, STAT + 28, 4) != 0 or getn(w, STAT + 24, 4) & 18 != 0:
            return 0
        return begin_file(o, w, 11, PATH, FILE_RAW, 1048576)
    if phase == 11:
        return decode(o, w, 12, FILE_RAW, get(w, 288))
    if phase == 12:
        if result >= 4294967280 or policy(s, w) == 0:
            return 0
        return begin_canonical(o, w, 20, PWORK, PWORK, 1048576)
    if phase == 20:
        size = get(w, 344)
        if workspace_prefix(w, PWORK, size) == 0:
            return 0
        if get(w, 2072) == 0 or get(w, 2072) > 604800 or get(w, 2080) == 0 or get(w, 2080) > 1000 or get(w, 2088) < 67108864:
            return 0
        put(w, 2048, PWORK)
        put(w, 2056, size)
        size = lossy(w, PWORK_UTF8, PWORK, size)
        put(w, 2096, PWORK_UTF8)
        put(w, 2104, size)
        return decode(o, w, 23, RAW, get(w, 32))
    if phase == 24:
        if result != 1:
            return 0
        child = get(w, TABLE + 32)
        size = get(w, 2056)
        if child != NONE and node(w, child, 0) != 0:
            size = node(w, child, 32)
            if size > 1048576 or clean(w, ARENA + node(w, child, 24), size) == 0:
                return 0
            copy(w, CWORK, ARENA + node(w, child, 24), size)
        else:
            copy(w, CWORK, PWORK, size)
        store(w, CWORK + size, 0)
        return begin_canonical(o, w, 25, CWORK, CWORK, 1048576)
    if phase == 25:
        size = get(w, 344)
        if component_prefix(w, CWORK, size, PWORK, get(w, 2056)) == 0:
            return 0
        size = lossy(w, CWORK_UTF8, CWORK, size)
        put(w, OVERRIDE_CWD, CWORK_UTF8)
        put(w, OVERRIDE_CWD_SIZE, size)
        put(w, OVERRIDE_MASK, 5)
        return request(o, w, 26)
    if phase == 26:
        if result != 1:
            return 0
        return worker_begin(s, o, w)
    return 0

def input_byte(o:mutbuf, w:mutbuf) -> u32:
    return call(o, w, 2, 0, 0, 98304, 8192, 0, 0, 0, 12)

def retain_identity(w:mutbuf) -> u64:
    child = get(w, TABLE + 8)
    size = node(w, child, 32)
    source = ARENA + node(w, child, 24)
    if size == 0 or size > 96:
        return 0
    index = 0
    while index < size:
        point = byte(w, source + index)
        if (point < 48 or point > 57) and (point < 65 or point > 90) and (point < 97 or point > 122) and point != 45:
            return 0
        store(w, JOB_ID + index, point)
        index = index + 1
    put(w, 48, size)
    store(w, JOB_ID + size, 0)
    at = text_unit_prefix(w, UNIT)
    copy(w, at, JOB_ID, size)
    at = text_unit_suffix(w, at + size)
    put(w, 56, at - UNIT)
    store(w, at, 0)
    at = text_root(w, REGISTRY)
    store(w, at, 47)
    copy(w, at + 1, JOB_ID, size)
    put(w, 64, at + 1 + size - REGISTRY)
    store(w, at + 1 + size, 0)
    child = get(w, TABLE)
    source = ARENA + node(w, child, 24)
    size = node(w, child, 32)
    operation = operation_id(w, source, size)
    if operation == 0:
        return 0
    put(w, 40, operation)
    put(w, 72, get(w, VALUES + 88))
    put(w, 80, get(w, VALUES + 96))
    limit = 16384
    child = get(w, TABLE + 104)
    if child != NONE and node(w, child, 0) != 0:
        limit = get(w, VALUES + 104)
    put(w, 88, limit)
    return 1

def policy(s:readbuf, w:mutbuf) -> u64:
    kind = node(w, 0, 0)
    if kind != 6 and kind != 5:
        return 0
    index = 0
    while index < 6:
        put(w, POLICY_TABLE + index * 8, NONE)
        index = index + 1
    mask = 0
    child = node(w, 0, 24)
    ordinal = 0
    while child != NONE:
        ordinal = ordinal + 1
        if kind == 5:
            if ordinal > 5:
                return 0
            field = ordinal
        else:
            field = policy_key(w, ARENA + node(w, child, 40), node(w, child, 48))
        if field == 0 or mask & (1 << (field - 1)) != 0:
            return 0
        mask = mask | (1 << (field - 1))
        put(w, POLICY_TABLE + (field - 1) * 8, child)
        child = node(w, child, 16)
    child = get(w, POLICY_TABLE)
    if child == NONE or node(w, child, 0) != 4:
        return 0
    size = node(w, child, 32)
    if size > 1048576 or clean(w, ARENA + node(w, child, 24), size) == 0:
        return 0
    copy(w, PWORK, ARENA + node(w, child, 24), size)
    store(w, PWORK + size, 0)
    put(w, 2064, 0)
    put(w, 2072, 3600)
    put(w, 2080, 100)
    put(w, 2088, 1073741824)
    child = get(w, POLICY_TABLE + 8)
    if child != NONE:
        if node(w, child, 0) != 1 and node(w, child, 0) != 2:
            return 0
        put(w, 2064, choose(node(w, child, 0) == 2, 1, 0))
    index = 2
    while index < 5:
        child = get(w, POLICY_TABLE + index * 8)
        if child != NONE:
            if node(w, child, 0) != 3:
                return 0
            value = file_integer(w, child)
            if get(w, ERROR) != 0 or (index == 3 and value > 65535):
                return 0
            put(w, 2072 + (index - 2) * 8, value)
        index = index + 1
    return worker_profile_policy(w, get(w, POLICY_TABLE + 40))

def file_integer(w:mutbuf, child:u64) -> u64:
    put(w, ERROR, 0)
    start = node(w, child, 24)
    size = node(w, child, 32)
    if size == 0 or size > 20 or start + size > get(w, 288):
        put(w, ERROR, 1)
        return 0
    value = 0
    index = 0
    while index < size:
        point = byte(w, FILE_RAW + start + index)
        if point < 48 or point > 57:
            put(w, ERROR, 1)
            return 0
        digit = point - 48
        if value > 1844674407370955161 or (value == 1844674407370955161 and digit > 5):
            put(w, ERROR, 1)
            return 0
        value = value * 10 + digit
        index = index + 1
    return value

def begin_file(o:mutbuf, w:mutbuf, next:u64, path:u64, target:u64, limit:u64) -> u32:
    put(w, 256, next)
    put(w, 264, target)
    put(w, 272, limit)
    put(w, 288, 0)
    return call(o, w, 1000, 257, NEG100, path, 657408, 0, 0, 0, 12)

def file_load(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase == 1000:
        if failed(result):
            return 0
        put(w, 280, result)
        return call(o, w, 1001, 5, result, STAT, 0, 0, 0, 0, 12)
    if phase == 1001:
        if result != 0 or getn(w, STAT + 24, 4) & 61440 != 32768 or get(w, STAT + 48) > get(w, 272):
            return 0
        return file_bytes(o, w)
    if phase == 1002:
        if result == NEG4:
            return file_bytes(o, w)
        if result == 0:
            return call(o, w, 1003, 3, get(w, 280), 0, 0, 0, 0, 0, 0)
        if failed(result) or result > get(w, 272) + 1 - get(w, 288):
            return 0
        put(w, 288, get(w, 288) + result)
        return file_bytes(o, w)
    if phase == 1003:
        if result != 0:
            return 0
        put(w, 0, get(w, 256))
        return 8
    return 0

def file_bytes(o:mutbuf, w:mutbuf) -> u32:
    return call(o, w, 1002, 0, get(w, 280), get(w, 264) + get(w, 288), get(w, 272) + 1 - get(w, 288), 0, 0, 0, 12)

def begin_canonical(o:mutbuf, w:mutbuf, next:u64, path:u64, target:u64, limit:u64) -> u32:
    put(w, 304, next)
    put(w, 312, target)
    put(w, 320, limit)
    return call(o, w, 1100, 257, NEG100, path, 2621440, 0, 0, 0, 12)

def canonical(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase == 1100:
        if failed(result):
            return 0
        put(w, 328, result)
        at = decimal(w, text_procfd(w, PROC_PATH), result)
        store(w, at, 0)
        return call(o, w, 1101, 267, NEG100, PROC_PATH, get(w, 312), get(w, 320), 0, 0, 60)
    if phase == 1101:
        if result == 0 or failed(result) or result >= get(w, 320):
            return 0
        put(w, 344, result)
        store(w, get(w, 312) + result, 0)
        return call(o, w, 1102, 3, get(w, 328), 0, 0, 0, 0, 0, 0)
    if phase == 1102:
        if result != 0:
            return 0
        put(w, 0, get(w, 304))
        return 8
    return 0

def begin_lock(o:mutbuf, w:mutbuf, next:u64) -> u32:
    put(w, 352, next)
    put(w, 360, 0)
    return mkdir_next(o, w)

def mkdir_next(o:mutbuf, w:mutbuf) -> u32:
    index = get(w, 360)
    at = text_var(w, PATH)
    if index == 1:
        at = text_varlib(w, PATH)
    elif index == 2:
        at = text_root(w, PATH)
    store(w, at, 0)
    return call(o, w, 1200, 258, NEG100, PATH, 511, 0, 0, 0, 12)

def lock_registry(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase == 1200:
        if result != 0 and result != NEG17:
            return 0
        return call(o, w, 1204, 262, NEG100, PATH, STAT, 0, 0, 0, 60)
    if phase == 1204:
        if result != 0 or getn(w, STAT + 24, 4) & 61440 != 16384:
            return 0
        index = get(w, 360) + 1
        put(w, 360, index)
        if index < 3:
            return mkdir_next(o, w)
        terminated(w, text_root(w, PATH))
        return call(o, w, 1201, 90, PATH, 448, 0, 0, 0, 0, 3)
    if phase == 1201:
        if result != 0:
            return 0
        terminated(w, text_lock(w, text_root(w, PATH)))
        return call(o, w, 1202, 257, NEG100, PATH, 524354, 384, 0, 0, 12)
    if phase == 1202:
        if failed(result):
            return 0
        put(w, 368, result)
        return call(o, w, 1203, 73, result, 2, 0, 0, 0, 0, 0)
    if phase == 1203:
        if result != 0:
            return 0
        put(w, 0, get(w, 352))
        return 8
    return 0

def decode(o:mutbuf, w:mutbuf, next:u64, source:u64, size:u64) -> u32:
    put(w, SCRATCH + 48, 1048576)
    put(w, SCRATCH + 56, 128)
    put(w, 0, next)
    put(o, 0, source)
    put(o, 8, size)
    put(o, 16, ARENA)
    put(o, 24, ARENA_BYTES)
    put(o, 32, SCRATCH)
    put(o, 40, SCRATCH_BYTES)
    return 4

def request(o:mutbuf, w:mutbuf, next:u64) -> u32:
    put(w, 0, next)
    put(o, 0, RAW)
    put(o, 8, get(w, 32))
    return 5

def call(o:mutbuf, w:mutbuf, next:u64, number:u64, a:u64, b:u64, c:u64, d:u64, e:u64, f:u64, pointers:u64) -> u32:
    put(w, 0, next)
    put(o, 0, number)
    put(o, 8, a)
    put(o, 16, b)
    put(o, 24, c)
    put(o, 32, d)
    put(o, 40, e)
    put(o, 48, f)
    put(o, 56, pointers)
    return 1

def workspace_prefix(w:mutbuf, source:u64, size:u64) -> u64:
    stop = text_workspace_prefix(w, PATH)
    return component_prefix(w, source, size, PATH, stop - PATH)

def component_prefix(w:mutbuf, source:u64, size:u64, prefix:u64, prefix_size:u64) -> u64:
    if size < prefix_size or (size > prefix_size and byte(w, source + prefix_size) != 47):
        return 0
    index = 0
    while index < prefix_size:
        if byte(w, source + index) != byte(w, prefix + index):
            return 0
        index = index + 1
    return 1

def lossy(w:mutbuf, target:u64, source:u64, size:u64) -> u64:
    at = 0
    out = 0
    while at < size:
        point = byte(w, source + at)
        width = 1
        if point >= 194 and point <= 223:
            width = 2
        elif point >= 224 and point <= 239:
            width = 3
        elif point >= 240 and point <= 244:
            width = 4
        good = choose(point < 128 or width > 1, 1, 0)
        used = 1
        while good == 1 and used < width and at + used < size:
            next = byte(w, source + at + used)
            if next < 128 or next > 191:
                good = 0
            elif used == 1 and ((point == 224 and next < 160) or (point == 237 and next > 159) or (point == 240 and next < 144) or (point == 244 and next > 143)):
                good = 0
            else:
                used = used + 1
        if good == 1 and used == width:
            copy(w, target + out, source + at, width)
            out = out + width
            at = at + width
        else:
            store(w, target + out, 239)
            store(w, target + out + 1, 191)
            store(w, target + out + 2, 189)
            out = out + 3
            at = at + used
    store(w, target + out, 0)
    return out

def terminated(w:mutbuf, at:u64) -> u64:
    store(w, at, 0)
    return 0

def clean(w:mutbuf, source:u64, size:u64) -> u64:
    index = 0
    while index < size:
        if byte(w, source + index) == 0:
            return 0
        index = index + 1
    return 1

def copy(w:mutbuf, target:u64, source:u64, size:u64) -> u64:
    index = 0
    while index + 8 <= size:
        word_store(w, target + index, word_load(w, source + index))
        index = index + 8
    while index < size:
        store(w, target + index, byte(w, source + index))
        index = index + 1
    return 0

def uint(s:readbuf, at:u64) -> u64:
    return word_load(s, at)

def failed(value:u64) -> bool:
    return value >> 63 != 0
"""

def source_program():
    source=POLICY+'\n'+worker_profile.source_program()
    helpers={n.name:ast.get_source_segment(request_source(),n) for n in ast.parse(request_source()).body if isinstance(n,ast.FunctionDef)}
    for name in ['get','getn','put','putn','decimal','node']:
        source+='\n'+helpers[name]+'\n'
    for label,values in [('policy_key',['workspace','allow_network','max_timeout_seconds','max_cpu_percent','max_memory_bytes','native_worker']),
                         ('worker_profile_key', worker_profile.KEYS),
                         ('operation_id',['start','pty','status','read','cancel'])]:
        source+=f'\ndef {label}(w:mutbuf, at:u64, size:u64) -> u64:\n'
        for index,name in enumerate(values,1):
            raw=name.encode();condition=' and '.join(f'getn(w, at + {i}, {len(raw[i:i+8])}) == {int.from_bytes(raw[i:i+8],"little")}' for i in range(0,len(raw),8))
            source+=f'    if size == {len(raw)} and {condition}:\n        return {index}\n'
        source+='    return 0\n'
    for name,value in {**TEXT, **worker_profile.TEXT}.items():
        raw=value.encode();source+=f'\ndef text_{name}(w:mutbuf, at:u64) -> u64:\n'
        for i in range(0,len(raw),8):
            chunk=raw[i:i+8];source+=f'    putn(w, at + {i}, {int.from_bytes(chunk,"little")}, {len(chunk)})\n'
        source+=f'    return at + {len(raw)}\n'
    for key in sorted(CONSTANTS,key=len,reverse=True):
        source=re.sub(r'\b'+key+r'\b',str(CONSTANTS[key]),source)
    return source

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--check',action='store_true');args=parser.parse_args()
    source=source_program();doc=document(source,'system_jobctl_control');path=ROOT/'examples/hia_bootstrap/system_jobctl_control.hepta';text=render_assembly(doc)
    if args.check:assert path.read_text()==text
    else:path.write_text(text)
    print(path.name,len(text),'functions',len(doc['functions']),'blocks',sum(len(f['blocks']) for f in doc['functions']),'ops',sum(len(b['ops']) for f in doc['functions'] for b in f['blocks']),flush=True)
if __name__=='__main__':main()
