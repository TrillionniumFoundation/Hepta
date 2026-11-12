"""Complete raw program admission, normalization, hashes and receipt in HIA."""
import ast
from hashlib import sha256
from pathlib import Path
from tools.program_authoring import source,document as build,write_document
from tools.hia_composite_lowering_driver_common import COMMON,CONSTANTS as LOWER
from tools.hia_composite_lowering_driver_services import BODY as SERVICES

ROOT=Path(__file__).resolve().parents[1]
FROZEN=ROOT.parent/'native-composite-legacy-import-next/tools/generate_hia_legacy_import_driver.py'
CONSTANTS=dict(LOWER)
CONSTANTS.update({'PROGRAM_DRIVER':46,'PROGRAM_INIT':int.from_bytes(b'HIAPAI01','little'),
    'PROGRAM_STATE':int.from_bytes(b'HIAPAS01','little'),'DISPATCH':int.from_bytes(b'HIAPDP01','little'),
    'RECEIPT':int.from_bytes(b'HIAPRV01','little'),'INPUT_LIMIT':8<<20,
    'B_PROBE':4,'B_PROBE_WORK':5,'B_CORE':45,'B_INPUT':52,'B_RECEIPT':56,
    'B_ADMISSION_STATE':47,'B_ADMISSION_ARENA':48,
    'B_SHA_INPUT':49,'B_SHA_OUTPUT':50,'B_SHA_WORK':51,
    'ADMISSION_STATE':64<<20,'ADMISSION_ARENA':32<<20})
FIELDS=('PACKET','KIND','VERSION','CORE_VERSION','INPUT_BYTES','CORE_BYTES','ERROR','RELEASE',
        'CHILD_MODE','CHILD_TARGET','CHILD_LEASE','HASH_SLOT','HASH_BYTES','HASH_TO',
        'HASH_RETURN','HASH_OFFSET','HASH_CHUNK')
CONSTANTS.update({'M_'+name:24576+8*i for i,name in enumerate(FIELDS)})
CONSTANTS.update({'M_INPUT_HASH':24832,'M_CORE_HASH':24864})

BODY=r'''
def program_admission(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) != MIN_WORK:
        return ABI
    if length(o) < 128:
        return refuse(w, 900)
    if get(w, C_MAGIC) == 0 and get(w, L_MAGIC) == 0:
        if program_begin(s, w) == 0:
            return refuse(w, 901)
    elif get(w, C_MAGIC) != PROGRAM_STATE or acknowledge(s, w, PROGRAM_DRIVER) == 0:
        return refuse(w, 902)
    while get(w, L_STATUS) == 1:
        phase = get(w, C_PHASE)
        if phase >= 26000 and phase < 27000:
            result = index_step(o, w)
        elif phase >= 300 and phase < 320:
            result = import_hash_step(o, w)
        else:
            result = program_step(o, w)
        if result != 0:
            return result
    return refuse(w, 903)

def program_begin(s:readbuf, w:mutbuf) -> u64:
    if length(s) != 64 or word(s, 0) != PROGRAM_INIT:
        return 0
    lease = word(s, 8)
    extent = word(s, 24)
    if lease == 0 or lease > MAX - 3 or word(s, 16) != 0:
        return 0
    if extent < 82 or extent > SOURCE_LEASE_LIMIT or extent != cap(w, B_SOURCE):
        return 0
    if cap(w, B_EMPTY) != 1 or cap(w, B_CONTROLLER) != MIN_WORK:
        return 0
    at = 32
    while at < 64:
        if word(s, at) != 0:
            return 0
        at = at + 8
    slot = 3
    while slot < 64:
        if cap(w, slot) != 0:
            return 0
        slot = slot + 1
    zero(w, 0, 4096)
    zero(w, 8192, MIN_WORK - 8192)
    put(w, C_MAGIC, PROGRAM_STATE)
    put(w, C_STATUS, 1)
    put(w, C_LEASE, lease)
    put(w, C_SOURCE_EXTENT, extent)
    put(w, L_MAGIC, LOWER_MAGIC)
    put(w, L_STATUS, 1)
    put(w, L_DRIVER, PROGRAM_DRIVER)
    put(w, C_PHASE, 1)
    return 1

def program_step(o:mutbuf, w:mutbuf) -> u64:
    phase = get(w, C_PHASE)
    if phase == 1:
        return grow(o, w, B_PROBE, 64, 2)
    if phase == 2:
        return grow(o, w, B_PROBE_WORK, 64, 3)
    if phase == 3:
        return invoke(o, w, 28, B_SOURCE, 0, cap(w, B_SOURCE), B_PROBE, 64, B_PROBE_WORK, 64, B_PROBE, 0, 64, 4)
    if phase == 4:
        if get(w, C_RETURN) != 64 or get(w, OBS) != DISPATCH or get(w, OBS + 40) != cap(w, B_SOURCE):
            return refuse(w, 904)
        kind = get(w, OBS + 8)
        version = get(w, OBS + 16)
        core = get(w, OBS + 24)
        packet = get(w, OBS + 32)
        if kind > 2 or version > 8 or packet < 16 or packet > PACKET_LIMIT:
            return refuse(w, 905)
        if get(w, OBS + 48) != 0 or get(w, OBS + 56) != 0:
            return refuse(w, 906)
        if kind == 2:
            if version != 2 or core != 2:
                return refuse(w, 907)
            return finish(o, w, 10, 1, 0)
        if kind == 1:
            if version < 1 or version > 4 or core < 6 or core > 8:
                return refuse(w, 908)
            if (version == 1 and core != 6) or (version == 4 and core != 8):
                return refuse(w, 909)
            if (version == 2 or version == 3) and core != 7:
                return refuse(w, 910)
        elif core != version:
            return refuse(w, 911)
        put(w, M_KIND, kind)
        put(w, M_VERSION, version)
        put(w, M_CORE_VERSION, core)
        put(w, M_PACKET, packet)
        put(w, C_PACKET_SLOT, B_SOURCE)
        put(w, C_PACKET_OFFSET, 64)
        put(w, C_PACKET_BYTES, packet)
        put(w, L_INDEX_TARGET, 0)
        put(w, L_INDEX_RETURN, 10)
        put(w, C_PHASE, 26000)
        return 0
    if phase == 10:
        size = get(w, C_JSON_BYTES)
        if size == 0 or size > INPUT_LIMIT:
            return refuse(w, 912)
        put(w, M_INPUT_BYTES, size)
        return grow(o, w, B_INPUT, size, 11)
    if phase == 11:
        return copy(o, w, B_PACKET_JSON, 64, B_INPUT, 0, get(w, M_INPUT_BYTES), 12)
    if phase == 12:
        return protect(o, w, B_INPUT, 1, 13)
    if phase == 13:
        return release(o, w, B_PROBE, 14)
    if phase == 14:
        return release(o, w, B_PROBE_WORK, 15)
    if phase == 15:
        return release(o, w, B_PACKET_JSON, 16)
    if phase == 16:
        return release(o, w, B_PACKET_WORK, 17)
    if phase == 17:
        if get(w, M_KIND) == 1:
            return run_child(o, w, 0, B_INPUT, get(w, M_INPUT_BYTES), B_CORE, get(w, C_LEASE) + 1, 40)
        return grow(o, w, B_ADMISSION_STATE, ADMISSION_STATE, 20)
    if phase == 20:
        return grow(o, w, B_ADMISSION_ARENA, ADMISSION_ARENA, 21)
    if phase == 21:
        return invoke(o, w, 27, B_INPUT, 0, get(w, M_INPUT_BYTES), B_ADMISSION_STATE, ADMISSION_STATE, B_ADMISSION_ARENA, ADMISSION_ARENA, B_EMPTY, 0, 0, 22)
    if phase == 22:
        result = get(w, C_RETURN)
        if result != 0 and admission_status(result) == 0:
            return refuse(w, 913)
        put(w, M_ERROR, result)
        return release(o, w, B_ADMISSION_STATE, 23)
    if phase == 23:
        return release(o, w, B_ADMISSION_ARENA, 24)
    if phase == 24:
        if get(w, M_ERROR) != 0:
            return finish(o, w, 8, get(w, M_ERROR), 0)
        if get(w, M_VERSION) < 1 or get(w, M_VERSION) > 8:
            return refuse(w, 914)
        put(w, M_CORE_BYTES, get(w, M_INPUT_BYTES))
        return grow(o, w, B_CORE, get(w, M_CORE_BYTES), 25)
    if phase == 25:
        return copy(o, w, B_INPUT, 0, B_CORE, 0, get(w, M_CORE_BYTES), 26)
    if phase == 26:
        return protect(o, w, B_CORE, 1, 50)
    if phase == 40:
        if child_result(w) == 0:
            return refuse(w, 915)
        if get(w, OBS + 32) != 0:
            return child_error(o, w)
        put(w, M_CORE_BYTES, get(w, OBS + 88))
        copy_digest(w, M_CORE_HASH, OBS + 96)
        put(w, C_PHASE, 50)
        return 0
    if phase == 50:
        if get(w, M_CORE_BYTES) < 33 or get(w, M_CORE_BYTES) > INPUT_LIMIT:
            return refuse(w, 916)
        return view(o, w, B_CORE, get(w, M_CORE_BYTES) - 33, 33, 51)
    if phase == 51:
        if actual_schema_suffix(w) == 0:
            return refuse(w, 917)
        return hash_start(w, B_INPUT, get(w, M_INPUT_BYTES), M_INPUT_HASH, 60)
    if phase == 60:
        if get(w, M_KIND) == 0:
            copy_digest(w, M_CORE_HASH, M_INPUT_HASH)
        put(w, M_RELEASE, 4)
        put(w, C_PHASE, 61)
        return 0
    if phase == 61:
        slot = get(w, M_RELEASE)
        if slot == 64:
            return grow(o, w, B_RECEIPT, 256, 70)
        put(w, M_RELEASE, slot + 1)
        if slot != B_CORE and (slot != B_INPUT or get(w, M_KIND) == 0):
            return release(o, w, slot, 61)
        return 0
    if phase == 70:
        if get(w, C_SEQUENCE) > MAX - 2:
            return refuse(w, 918)
        program_receipt(w)
        return copy(o, w, B_CONTROLLER, WIRE, B_RECEIPT, 0, 256, 71)
    if phase == 71:
        return protect(o, w, B_RECEIPT, 1, 72)
    if phase == 72:
        if get(w, L_STATUS) != 1 or get(w, C_PENDING) != 0:
            return refuse(w, 919)
        put(w, L_STATUS, 2)
        zero(o, 0, 128)
        put(o, 0, EVENT_MAGIC)
        put(o, 8, 7)
        put(o, 16, get(w, C_LEASE))
        put(o, 24, get(w, C_SEQUENCE))
        put(o, 48, B_RECEIPT)
        put(o, 56, 256)
        put(o, 64, get(w, M_KIND))
        put(o, 72, get(w, M_VERSION))
        put(o, 80, get(w, M_CORE_VERSION))
        put(o, 88, get(w, M_CORE_BYTES))
        i = 0
        while i < 32:
            store(o, 96 + i, byte(w, M_CORE_HASH + i))
            i = i + 1
        return 128
    return refuse(w, 920)

def program_receipt(w:mutbuf) -> u64:
    zero(w, WIRE, 256)
    put(w, WIRE, RECEIPT)
    put(w, WIRE + 8, 1)
    put(w, WIRE + 16, get(w, C_LEASE))
    put(w, WIRE + 24, get(w, C_SEQUENCE) + 2)
    put(w, WIRE + 32, get(w, M_KIND))
    put(w, WIRE + 40, get(w, M_VERSION))
    put(w, WIRE + 48, get(w, M_CORE_VERSION))
    put(w, WIRE + 56, get(w, M_INPUT_BYTES))
    put(w, WIRE + 64, get(w, M_CORE_BYTES))
    if get(w, M_KIND) == 1:
        put(w, WIRE + 72, get(w, M_INPUT_BYTES))
        put(w, WIRE + 152, B_INPUT)
    copy_digest(w, WIRE + 80, M_INPUT_HASH)
    copy_digest(w, WIRE + 112, M_CORE_HASH)
    put(w, WIRE + 144, B_CORE)
    put(w, WIRE + 160, B_RECEIPT)
    put(w, WIRE + 168, 256)
    put(w, WIRE + 176, 1)
    put(w, WIRE + 184, get(w, M_KIND))
    return 0
'''

def assigned_body(path,expected):
    raw=path.read_bytes();assert sha256(raw).hexdigest()==expected,(path,sha256(raw).hexdigest())
    return next(ast.literal_eval(n.value) for n in ast.parse(raw).body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='BODY' for t in n.targets))

def source_program():
    previous=assigned_body(FROZEN,'53cdf4ce01c8f14ab4894062fdc321a124f0b2ed16e39e284876d7eb37f9968c')
    names={'run_child','child_result','mirror_frame','child_error','copy_digest','hash_start','import_hash_step'}
    helpers='\n'.join(ast.unparse(n) for n in ast.parse(previous).body if n.name in names)
    admission=assigned_body(ROOT.parent/'native-composite-driver-reconstructed/tools/generate_hia_composite_publication_driver.py','e30dfdc977e532c812f985a52d683198203654c260ca52c23e4d38772825a93f')
    helpers+='\n'+'\n'.join(ast.unparse(n) for n in ast.parse(admission).body if n.name=='admission_status')
    suffix=b',"schema":"hepta.hia.program.v1"}'
    assert len(suffix)==33
    extra='\ndef actual_schema_suffix(w:mutbuf) -> u64:\n'
    for i,b in enumerate(suffix):
        expected='get(w, M_CORE_VERSION) + 48' if i==30 else str(b)
        extra+=f'    if byte(w, OBS + {i}) != {expected}:\n        return 0\n'
    extra+='    return 1\n'
    common=COMMON.replace('or image > 23:','or image > 28:')
    common=common.replace('if pending != 1 and pending != 14 and word(s, 40) != 0:',
        'if pending != 1 and pending != 14 and pending != 15 and word(s, 40) != 0:')
    return source(BODY+extra+'\n'+helpers+'\n'+SERVICES+'\n'+common,CONSTANTS,'program_admission')

def document():return build(source_program(),'program_admission_driver')
if __name__=='__main__':write_document(document(),'program_admission_driver.hiaasm')
