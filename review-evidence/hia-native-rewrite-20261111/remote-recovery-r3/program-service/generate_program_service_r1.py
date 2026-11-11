"""New HIA A-service root: actual program admission, report and CLI handoff.

Python authors HIA only. This source is unqualified until its generated native
image and the fixed finite context carrier complete the independent gates.
No hosted program, JSON, publication or error policy is invoked at runtime.
"""
from pathlib import Path
from hashlib import sha256
import ast,importlib.util,json,sys,types
BASE=Path("/var/tmp/hia9acdfa-native-resume-a3c61136-20261111")
WORK=BASE/"root-recovery/workspace"
REF=BASE/"root-recovery/reference-0ef-r2"
ROOT=WORK/"native-program-service-root-r1"
FROZEN=WORK/"native-edit-json-next/development/main-compile-r3/source"
LOWER=FROZEN/"8/hia_composite_lowering_driver_common.py"
EDIT=WORK/"native-edit-controller-next/tools/hia_edit_controller_common.py"
MAIN=WORK/"native-edit-candidate-next/development/build-r1/source/161/main_r4.py"
FRONT=WORK/"native-edit-candidate-next/development/build-r1/source/156/generate_hia_edit_json_main.py"
LEGACY=FROZEN/"10/generate_hia_legacy_import_driver.py"
AUTHOR=FROZEN/"2/edit_authoring.py"
HELPER=FROZEN/"6/hia_agent_edit_source_views.py"
PINS={LOWER:"fe63327671ea51ca950b955512a0f574d706176a4a8d050e3f8f12c83ef5e3a1",
 EDIT:"758d395a1e99653403365c407e7eaa068345cf9e8d8720356f1c1396c8de58a8",
 MAIN:"edce3bbb0e355a3a12a5363a3e0a97475cc588716b053fe00da828cefa105d39",
 FRONT:"2fa02b39b7774d7d2f0e790c0ea3143d170c7a0e4a157fb76f81ee4c72a3ea9a",
 LEGACY:"53cdf4ce01c8f14ab4894062fdc321a124f0b2ed16e39e284876d7eb37f9968c",
 AUTHOR:"a9040b23586f7bf289fdddb7337a986cf9d207666b46dc2771fa00a0d06e70d9",
 HELPER:"555472263213f15deb239fcf3bf8e5b273a28caf3a67bb29ffd037f171d7ae5c"}
RAW={path:path.read_bytes() for path in PINS}
assert all(sha256(RAW[p]).hexdigest()==v for p,v in PINS.items())
def literal(path,name):
    nodes=ast.parse(RAW[path]).body
    return next(ast.literal_eval(n.value) for n in nodes if isinstance(n,ast.Assign)
        and any(isinstance(t,ast.Name) and t.id==name for t in n.targets))
def prefix_constants(path,begin,end,namespace):
    selected=[];started=begin is None
    for node in ast.parse(RAW[path]).body:
        targets=[x.id for x in node.targets if isinstance(x,ast.Name)] if isinstance(node,ast.Assign) else []
        if end in targets:break
        if begin in targets:started=True
        if started:selected.append(node)
    assert selected
    exec(compile(ast.Module(body=selected,type_ignores=[]),str(path)+":constant-prefix","exec"),namespace)
    return namespace["CONSTANTS"]
lower_env={};lower=prefix_constants(LOWER,None,"COMMON",lower_env)
edit_env={"old":types.SimpleNamespace(CONSTANTS=lower),"magic":lambda s:int.from_bytes(s.encode(),"little")}
constants=prefix_constants(EDIT,"CONSTANTS","COMMON",edit_env)
assert all(type(k) is str and type(v) is int for k,v in constants.items())
def magic(s):return int.from_bytes(s.encode(),"little")
CONSTANTS=dict(constants,CORE_DIAGNOSTIC=magic("HIACDT01"),PREFIX_TEXT=17344,
    A_MAGIC=magic("HIAAPS01"),A_INIT=magic("HIACBI01"),A_REPLY=magic("HIACBR01"),
    A_RESULT=magic("HIACBE01"),A_PUBLICATION=magic("HIACPR01"),
    DECODE_COMMAND=magic("HIADJC01"),DECODE_EVENT=magic("HIAJDE01"),
    GRAPH_MAGIC=magic("HIAGRF01"),PROJECT_COMMAND=magic("HIAPIC01"),
    PROJECT_EVENT=magic("HIAPIE01"),WIRE_COMMAND=magic("HIAGWC01"),
    WIRE_EVENT=magic("HIAGWE01"),CLI_WIRE_MAX=(1<<61)-1,
    B_ARGV=4,B_PARSER=5,B_GRAPH=8,B_PROJECT_WORK=10,B_WIRE_WORK=12,
    B_PUBLIC_JSON=13,B_PUBLIC_RECEIPT=31,B_RESULT=30,
    A_HEAD=32768,A_TEXT1=34000,A_TEXT2=34512,A_TEXT3=35024,A_EXPECT=35536)
FIELDS=("MAGIC","ACTION","PARENT_LEASE","PARENT_SEQUENCE","OUTPUT","FIELD_INDEX",
 "GRAPH_BYTES","GRAPH_LEASE","GRAPH_ROOT","PROJECT_SEQUENCE","PROJECT_ROOT",
 "PROJECT_AT","PROJECT_BYTES","WIRE_ROLE","RESULT_KIND","RESULT_DOMAIN","RESULT_EXIT",
 "RESULT_FIELD","RESULT_POLICY","RESULT_TARGET","RESULT_SOURCE","RESULT_AT","RESULT_BYTES",
 "REQUEST","YIELD_SEQUENCE","LIFECYCLE","RELEASE","DEST_BYTES","RECEIPT_AT",
 "RECEIPT_BYTES","PUBLIC_BYTES","EXPECTED_BYTES")
CONSTANTS.update({"A_"+name:32000+8*i for i,name in enumerate(FIELDS)})
# The state field and magic value have distinct names.
CONSTANTS["A_STATE_MAGIC"]=magic("HIAAPS01")
COMMON=literal(LOWER,"COMMON")
COMMON=COMMON.replace("or image > 23:",
 "or image > 63 or (image >= 40 and image <= 46) or (image >= 56 and image <= 59):")
COMMON=COMMON.replace("if target < 40 or target > 42 or target == get(w, L_DRIVER):",
 "if target < 56 or target > 59 or target == get(w, L_DRIVER):")
COMMON=COMMON.replace("if pending != 1 and pending != 14 and word(s, 40) != 0:",
 "if pending != 1 and pending != 14 and pending != 15 and word(s, 40) != 0:")
HELPERS=literal(EDIT,"HELPERS")
main_nodes={n.name:n for n in ast.parse(literal(MAIN,"BODY")).body}
ADMISSION="\n".join(ast.unparse(main_nodes[name]) for name in
 ("program_child","program_child_frame","program_receipt_header"))
legacy_nodes={n.name:n for n in ast.parse(literal(LEGACY,"BODY")).body}
HASH=ast.unparse(legacy_nodes["import_hash_step"]).replace(
 "get(w, M_HASH_SLOT), get(w, M_HASH_OFFSET), B_SHA_INPUT",
 "get(w, M_HASH_SLOT), get(w, M_HASH_AT) + get(w, M_HASH_OFFSET), B_SHA_INPUT")
HEX=ast.unparse(legacy_nodes["hex_digest"])
PREFIX_MESSAGES=literal(FRONT,"PREFIX_MESSAGES")
sys.path.insert(0,str(REF));sys.dont_write_bytecode=True
from hepta.hia_agent_assembly import render_assembly,assemble_program
from tools.generate_hia_selfhost import compact_authoring_cfg,total_scalar_functions
spec=importlib.util.spec_from_file_location("program_service_copy_builder",HELPER)
helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
CopyBuilder=helper.CopyBuilder

SOURCE=r'''
def program_service(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) != MIN_WORK:
        return ABI
    if length(o) < 128:
        return refuse(w, 2000)
    if get(w, C_MAGIC) == 0 and get(w, L_MAGIC) == 0:
        if service_begin(s, w) == 0:
            return refuse(w, 2001)
    elif get(w, C_MAGIC) != EDIT_STATE or get(w, A_MAGIC) != A_STATE_MAGIC or acknowledge(s, w, MAIN) == 0:
        return refuse(w, 2002)
    while get(w, L_STATUS) == 1:
        phase = get(w, C_PHASE)
        if phase >= 300 and phase < 320:
            result = import_hash_step(o, w)
        elif phase >= 800 and phase < 810:
            result = result_step(o, w)
        elif phase >= 810 and phase < 850:
            result = publication_step(o, w)
        elif phase >= 50 and phase < 70:
            result = wire_step(o, w)
        elif phase >= 30 and phase < 50:
            result = projection_step(o, w)
        else:
            result = admission_step(o, w)
        if result != 0:
            return result
    return refuse(w, 2003)

def service_begin(s:readbuf, w:mutbuf) -> u64:
    if length(s) != 128 or word(s, 0) != A_INIT or word(s, 8) != 1 or word(s, 16) != 1:
        return 0
    lease = word(s, 24)
    action = word(s, 48)
    digits = word(s, 56)
    if lease == 0 or lease > MAX - 3 or word(s, 32) == 0 or word(s, 40) == 0:
        return 0
    if action < 6 or action > 8 or digits > 4294967295:
        return 0
    if digits != 0 and digits < 640:
        return 0
    if word(s, 64) != cap(w, B_PROGRAM) or word(s, 72) != cap(w, B_ARGV) or word(s, 80) != cap(w, B_PARSER):
        return 0
    if word(s, 88) != 16 or word(s, 96) != 1024 or word(s, 104) != 32 or word(s, 112) != 0 or word(s, 120) != 0:
        return 0
    if cap(w, B_EMPTY) != 1 or cap(w, B_CONTROLLER) != MIN_WORK or cap(w, B_PARSER) < 1536:
        return 0
    slot = 3
    while slot < 64:
        if slot != B_ARGV and slot != B_PARSER and cap(w, slot) != 0:
            return 0
        slot = slot + 1
    at = 0
    while at < MIN_WORK:
        if at < CAPS or at >= CAPS + 512:
            if byte(w, at) != 0:
                return 0
        at = at + 1
    put(w, C_MAGIC, EDIT_STATE)
    put(w, C_STATUS, 1)
    put(w, C_LEASE, lease)
    put(w, L_MAGIC, LOWER_MAGIC)
    put(w, L_STATUS, 1)
    put(w, L_DRIVER, MAIN)
    put(w, A_MAGIC, A_STATE_MAGIC)
    put(w, A_ACTION, action)
    put(w, A_PARENT_LEASE, word(s, 32))
    put(w, A_PARENT_SEQUENCE, word(s, 40))
    put(w, E_DIGITS, digits)
    put(w, E_REQUEST, 1)
    put(w, C_PHASE, 1)
    return 1

def admission_step(o:mutbuf, w:mutbuf) -> u64:
    phase = get(w, C_PHASE)
    if phase == 1:
        return program_child(o, w, 2)
    if phase == 2:
        state = program_child_frame(w)
        if state == 0:
            return refuse(w, 2004)
        if state == 2:
            return prefix_failure(w)
        if state == 3:
            return view(o, w, B_PROGRAM_FRAME, 0, 64, 20)
        return view(o, w, B_PROGRAM_FRAME, 0, 256, 3)
    if phase == 3:
        if program_receipt_header(w) == 0:
            return refuse(w, 2005)
        return grow(o, w, B_CORE, get(w, E_CORE_BYTES), 4)
    if phase == 4:
        return copy(o, w, B_PROGRAM_FRAME, 256, B_CORE, 0, get(w, E_CORE_BYTES), 5)
    if phase == 5:
        return protect(o, w, B_CORE, 1, 6)
    if phase == 6:
        return hash_start(w, B_CORE, get(w, E_CORE_BYTES), E_ACTUAL_CORE_HASH, 7)
    if phase == 7:
        if same_digest(w, E_ACTUAL_CORE_HASH, E_CORE_HASH) == 0:
            return refuse(w, 2006)
        put(w, A_FIELD_INDEX, 0)
        put(w, C_PHASE, 8)
        return 0
    if phase == 8:
        index = get(w, A_FIELD_INDEX)
        if index == 16:
            if get(w, A_OUTPUT) == 1:
                put(w, A_REQUEST, 1)
                return start_result(w, 2, 0, 0, 2, 1, B_PUBLIC_RECEIPT, B_CORE, 0, get(w, E_CORE_BYTES))
            put(w, C_PHASE, 10)
            return 0
        return view(o, w, B_PARSER, 1024 + index * 32, 32, 9)
    if phase == 9:
        if parser_row(w) == 0:
            return refuse(w, 2007)
        put(w, A_FIELD_INDEX, get(w, A_FIELD_INDEX) + 1)
        put(w, C_PHASE, 8)
        return 0
    if phase == 10:
        wire8(w, DECODE_COMMAND, 41, get(w, E_REQUEST), 9, get(w, E_DIGITS), 0, 0, 0)
        result = edit_service_start(w, 2, B_CORE, 0, get(w, E_CORE_BYTES), B_CONTROLLER, WIRE, 64, 512, MAIN, 11)
        if result != 0:
            return result
        return switch(o, w, SERVICE, 50000)
    if phase == 11:
        if get(w, S_STATE) != 2 or get(w, S_KIND) != 2 or get(w, S_RESULT_CODE) != 128 or get(w, S_RESULT_EVENT_BYTES) != 128:
            return refuse(w, 2008)
        if get(w, S_RESULT_EVENT) != DECODE_EVENT or get(w, S_RESULT_EVENT + 16) != 41 or get(w, S_RESULT_EVENT + 24) != get(w, E_REQUEST):
            return refuse(w, 2009)
        if cap(w, get(w, S_RESULT_SLOT)) != get(w, S_RESULT_BYTES):
            return refuse(w, 2010)
        at = get(w, S_RESULT_EVENT + 112)
        size = get(w, S_RESULT_EVENT + 120)
        if get(w, S_RESULT_EVENT + 8) != 0 or get(w, S_RESULT_EVENT + 104) != 0 or size < 128:
            return refuse(w, 2011)
        if inside(w, get(w, S_RESULT_SLOT), at, size) == 0:
            return refuse(w, 2012)
        put(w, A_GRAPH_BYTES, size)
        put(w, A_RESULT_AT, at)
        return grow(o, w, B_GRAPH, size, 12)
    if phase == 12:
        return copy(o, w, get(w, S_RESULT_SLOT), get(w, A_RESULT_AT), B_GRAPH, 0, get(w, A_GRAPH_BYTES), 13)
    if phase == 13:
        return protect(o, w, B_GRAPH, 1, 14)
    if phase == 14:
        put(w, A_RELEASE, 32)
        put(w, C_PHASE, 15)
        return 0
    if phase == 15:
        slot = get(w, A_RELEASE)
        if slot == 50:
            put(w, C_PHASE, 30)
            return 0
        put(w, A_RELEASE, slot + 1)
        return release(o, w, slot, 15)
    if phase == 20:
        if get(w, OBS) != CORE_DIAGNOSTIC or get(w, OBS + 8) != 1:
            return refuse(w, 2013)
        if get(w, OBS + 16) != get(w, E_ERROR_CODE) or get(w, OBS + 24) == 0 or get(w, OBS + 24) > 92:
            return refuse(w, 2014)
        if get(w, OBS + 40) != get(w, E_ERROR_BYTES) or get(w, OBS + 32) != get(w, E_ERROR_BYTES) - 64:
            return refuse(w, 2015)
        if get(w, OBS + 48) == 0 or get(w, OBS + 48) > NODES or get(w, OBS + 56) != 0:
            return refuse(w, 2016)
        return start_result(w, 4, 1, 2, 0, 0, 0, B_PROGRAM_FRAME, 64, get(w, OBS + 32))
    return refuse(w, 2017)

def parser_row(w:mutbuf) -> u64:
    defined = get(w, OBS)
    owner = get(w, OBS + 8)
    at = get(w, OBS + 16)
    size = get(w, OBS + 24)
    if defined > 1 or owner > 2:
        return 0
    if owner == 0:
        if at != 0 or size != 0:
            return 0
    elif defined != 1:
        return 0
    elif owner == 1:
        if inside(w, B_ARGV, at, size) == 0:
            return 0
    elif inside(w, B_PARSER, at, size) == 0:
        return 0
    if get(w, A_FIELD_INDEX) == 2:
        if get(w, A_ACTION) != 8:
            if defined != 0 or owner != 0:
                return 0
        else:
            if defined != 1:
                return 0
            if owner != 0 and size != 0:
                put(w, A_OUTPUT, 1)
    return 1

def prefix_failure(w:mutbuf) -> u64:
    group = get(w, E_ERROR_GROUP)
    error = get(w, E_ERROR_CODE)
    stage = get(w, E_CHILD_EVENT + 48)
    status = get(w, E_CHILD_EVENT + 56)
    message = 0
    if group == 7:
        if error == 1:
            if stage != 0 or status != 0:
                return refuse(w, 2020)
            message = 1
        elif error == 2:
            if stage == 0:
                if status != 0:
                    return refuse(w, 2021)
            elif stage != 1 or (status != 4294967295 and status != 4294967292):
                return refuse(w, 2022)
            message = 2
        elif error == 3:
            if stage != 1 or status != 4294967294:
                return refuse(w, 2023)
            message = 3
        elif error == 4:
            if stage != 2 or status != 4294967280:
                return refuse(w, 2024)
            message = 2
        else:
            return refuse(w, 2025)
    elif group == 10:
        if error != 1 or stage != 0 or status != 0:
            return refuse(w, 2026)
        message = 4
    else:
        return refuse(w, 2027)
    size = prefix_message(w, message)
    if size == 0:
        return refuse(w, 2028)
    return start_result(w, 4, 1, 2, 0, 0, 0, B_CONTROLLER, PREFIX_TEXT, size)

def projection_step(o:mutbuf, w:mutbuf) -> u64:
    phase = get(w, C_PHASE)
    if phase == 30:
        return view(o, w, B_GRAPH, 0, 64, 31)
    if phase == 31:
        if get(w, OBS) != GRAPH_MAGIC or get(w, OBS + 8) != 9 or get(w, OBS + 16) == 0:
            return refuse(w, 2030)
        if get(w, OBS + 24) == 0 or get(w, OBS + 24) > get(w, OBS + 16) or get(w, OBS + 48) != get(w, A_GRAPH_BYTES) or get(w, OBS + 56) != 0:
            return refuse(w, 2031)
        put(w, A_GRAPH_LEASE, get(w, OBS + 8))
        put(w, A_GRAPH_ROOT, get(w, OBS + 24))
        put(w, A_PROJECT_SEQUENCE, 1)
        return grow(o, w, B_COMMAND, 160, 32)
    if phase == 32:
        mode = 3
        if get(w, A_ACTION) == 6:
            mode = 4
        elif get(w, A_ACTION) == 7:
            mode = 2
        schema = get(w, E_VERSION)
        if get(w, E_KIND) == 1:
            schema = 8 + schema
        zero(w, WIRE, 160)
        wire8(w, PROJECT_COMMAND, get(w, A_GRAPH_LEASE), get(w, A_PROJECT_SEQUENCE), mode, get(w, A_GRAPH_ROOT), schema, get(w, E_CORE_VERSION), get(w, E_KIND))
        copy_local(w, WIRE + 64, E_INPUT_HASH, 32)
        copy_local(w, WIRE + 96, E_CORE_HASH, 32)
        put(w, WIRE + 128, get(w, A_GRAPH_BYTES))
        return copy(o, w, B_CONTROLLER, WIRE, B_COMMAND, 0, 160, 33)
    if phase == 33:
        return protect(o, w, B_COMMAND, 1, 34)
    if phase == 34:
        return grow(o, w, B_PROJECT_WORK, 65536, 35)
    if phase == 35:
        return invoke(o, w, 60, B_GRAPH, 0, get(w, A_GRAPH_BYTES), B_COMMAND, 160, B_PROJECT_WORK, cap(w, B_PROJECT_WORK), B_PROJECT_WORK, 0, 128, 36)
    if phase == 36:
        if get(w, OBS) != PROJECT_EVENT or get(w, OBS + 16) != get(w, A_GRAPH_LEASE) or get(w, OBS + 24) != get(w, A_PROJECT_SEQUENCE):
            return refuse(w, 2032)
        if get(w, OBS + 32) == 0 or get(w, OBS + 64) != 0:
            return refuse(w, 2033)
        at = 72
        while at < 128:
            if get(w, OBS + at) != 0:
                return refuse(w, 2034)
            at = at + 8
        if get(w, A_PROJECT_ROOT) == 0:
            put(w, A_PROJECT_ROOT, get(w, OBS + 32))
        elif get(w, A_PROJECT_ROOT) != get(w, OBS + 32):
            return refuse(w, 2035)
        if get(w, OBS + 8) == 1:
            needed = get(w, OBS + 56)
            if get(w, C_RETURN) != 4294967294 or needed <= cap(w, B_PROJECT_WORK) or get(w, OBS + 40) != 0 or get(w, OBS + 48) != 0:
                return refuse(w, 2036)
            return grow(o, w, B_PROJECT_WORK, needed, 35)
        if get(w, C_RETURN) != 128 or get(w, OBS + 8) != 0 or get(w, OBS + 56) != 0:
            return refuse(w, 2037)
        at = get(w, OBS + 40)
        size = get(w, OBS + 48)
        if at != 65536 or size < 128 or inside(w, B_PROJECT_WORK, at, size) == 0:
            return refuse(w, 2038)
        put(w, A_PROJECT_AT, at)
        put(w, A_PROJECT_BYTES, size)
        return protect(o, w, B_PROJECT_WORK, 1, 37)
    if phase == 37:
        return release(o, w, B_COMMAND, 50)
    return refuse(w, 2039)

def wire_step(o:mutbuf, w:mutbuf) -> u64:
    phase = get(w, C_PHASE)
    if phase == 50:
        return grow(o, w, B_COMMAND, 64, 51)
    if phase == 51:
        wire8(w, WIRE_COMMAND, get(w, A_GRAPH_LEASE), 1, get(w, A_PROJECT_ROOT), CLI_WIRE_MAX, 6, get(w, E_DIGITS), 0)
        return copy(o, w, B_CONTROLLER, WIRE, B_COMMAND, 0, 64, 52)
    if phase == 52:
        return protect(o, w, B_COMMAND, 1, 53)
    if phase == 53:
        put(w, A_WIRE_ROLE, 29)
        return grow(o, w, B_WIRE_WORK, 32768, 54)
    if phase == 54:
        return invoke(o, w, get(w, A_WIRE_ROLE), B_PROJECT_WORK, get(w, A_PROJECT_AT), get(w, A_PROJECT_BYTES), B_COMMAND, 64, B_WIRE_WORK, cap(w, B_WIRE_WORK), B_WIRE_WORK, 0, 128, 55)
    if phase == 55:
        if get(w, C_RETURN) != 128 or get(w, OBS) != WIRE_EVENT:
            return refuse(w, 2040)
        if get(w, OBS + 16) != get(w, A_GRAPH_LEASE) or get(w, OBS + 24) != 1 or get(w, OBS + 32) != get(w, A_PROJECT_ROOT):
            return refuse(w, 2041)
        if get(w, OBS + 40) != CLI_WIRE_MAX or get(w, OBS + 48) != 6 or get(w, OBS + 56) != get(w, E_DIGITS):
            return refuse(w, 2042)
        if get(w, OBS + 64) != 0 or get(w, OBS + 72) != 0:
            return refuse(w, 2043)
        action = get(w, OBS + 8)
        if action == 1:
            needed = get(w, OBS + 80)
            if needed <= cap(w, B_WIRE_WORK):
                return refuse(w, 2044)
            return grow(o, w, B_WIRE_WORK, needed, 54)
        if action == 2:
            if get(w, A_WIRE_ROLE) != 29 or get(w, OBS + 104) != 2:
                return refuse(w, 2045)
            put(w, A_WIRE_ROLE, 30)
            put(w, C_PHASE, 54)
            return 0
        if action != 0 or get(w, A_WIRE_ROLE) != 30:
            return refuse(w, 2046)
        at = get(w, OBS + 88)
        size = get(w, OBS + 96)
        if size == 0 or inside(w, B_WIRE_WORK, at, size) == 0:
            return refuse(w, 2047)
        put(w, A_RESULT_AT, at)
        put(w, A_RESULT_BYTES, size)
        return protect(o, w, B_WIRE_WORK, 1, 56)
    if phase == 56:
        return start_result(w, 3, 0, 0, 0, 1, 0, B_WIRE_WORK, get(w, A_RESULT_AT), get(w, A_RESULT_BYTES))
    return refuse(w, 2048)

def start_result(w:mutbuf, kind:u64, domain:u64, exitcode:u64, field:u64, policy:u64, target:u64, source:u64, at:u64, size:u64) -> u64:
    if kind < 2 or kind > 4 or size == 0 or size > MAX - 128 or inside(w, source, at, size) == 0:
        return refuse(w, 2050)
    if cap(w, B_RESULT) != 0:
        return refuse(w, 2051)
    if kind == 2:
        if get(w, A_ACTION) != 8 or get(w, A_OUTPUT) != 1 or domain != 0 or exitcode != 0 or field != 2 or policy != 1 or target != B_PUBLIC_RECEIPT or cap(w, target) != 0 or get(w, A_REQUEST) == 0:
            return refuse(w, 2052)
        put(w, A_LIFECYCLE, 0)
    elif kind == 3:
        if domain != 0 or exitcode > 1 or field != 0 or policy != 1 or target != 0:
            return refuse(w, 2053)
        put(w, A_LIFECYCLE, 1)
    else:
        if domain != 1 or exitcode != 2 or field != 0 or policy != 0 or target != 0:
            return refuse(w, 2054)
        put(w, A_LIFECYCLE, 1)
    put(w, A_RESULT_KIND, kind)
    put(w, A_RESULT_DOMAIN, domain)
    put(w, A_RESULT_EXIT, exitcode)
    put(w, A_RESULT_FIELD, field)
    put(w, A_RESULT_POLICY, policy)
    put(w, A_RESULT_TARGET, target)
    put(w, A_RESULT_SOURCE, source)
    put(w, A_RESULT_AT, at)
    put(w, A_RESULT_BYTES, size)
    put(w, C_PHASE, 800)
    return 0

def result_step(o:mutbuf, w:mutbuf) -> u64:
    phase = get(w, C_PHASE)
    if phase == 800:
        return grow(o, w, B_RESULT, 128 + get(w, A_RESULT_BYTES), 801)
    if phase == 801:
        return copy(o, w, get(w, A_RESULT_SOURCE), get(w, A_RESULT_AT), B_RESULT, 128, get(w, A_RESULT_BYTES), 802)
    if phase == 802:
        if get(w, C_SEQUENCE) > MAX - 3:
            return refuse(w, 2055)
        sequence = get(w, C_SEQUENCE) + 3
        put(w, A_YIELD_SEQUENCE, sequence)
        request = 0
        if get(w, A_RESULT_KIND) == 2:
            request = get(w, A_REQUEST)
        zero(w, A_HEAD, 128)
        put(w, A_HEAD, A_RESULT)
        put(w, A_HEAD + 8, 1)
        put(w, A_HEAD + 16, 1)
        put(w, A_HEAD + 24, get(w, C_LEASE))
        put(w, A_HEAD + 32, sequence)
        put(w, A_HEAD + 40, request)
        put(w, A_HEAD + 48, get(w, A_RESULT_KIND))
        put(w, A_HEAD + 56, get(w, A_RESULT_DOMAIN))
        put(w, A_HEAD + 64, get(w, A_RESULT_EXIT))
        put(w, A_HEAD + 72, get(w, A_RESULT_FIELD))
        put(w, A_HEAD + 80, get(w, A_RESULT_POLICY))
        put(w, A_HEAD + 88, get(w, A_RESULT_TARGET))
        put(w, A_HEAD + 96, 128)
        put(w, A_HEAD + 104, get(w, A_RESULT_BYTES))
        put(w, A_HEAD + 112, 128 + get(w, A_RESULT_BYTES))
        return copy(o, w, B_CONTROLLER, A_HEAD, B_RESULT, 0, 128, 803)
    if phase == 803:
        return protect(o, w, B_RESULT, 1, 804)
    if phase == 804:
        if get(w, C_SEQUENCE) == MAX or get(w, C_SEQUENCE) + 1 != get(w, A_YIELD_SEQUENCE):
            return refuse(w, 2056)
        mask = 0
        observed = 0
        if get(w, A_LIFECYCLE) == 0:
            mask = 2147483648
            observed = 128
        put(w, C_OBSERVE, observed)
        args(w, get(w, C_LEASE), get(w, A_LIFECYCLE), B_RESULT, 0, 128 + get(w, A_RESULT_BYTES), mask, 0, 0, 0, 0, 0, 0)
        return event(o, w, 18, 805)
    if phase == 805:
        if get(w, A_RESULT_KIND) != 2 or get(w, A_LIFECYCLE) != 0 or get(w, C_RETURN) != 0:
            return refuse(w, 2057)
        if get(w, OBS) != A_REPLY or get(w, OBS + 8) != 1 or get(w, OBS + 16) != 1 or get(w, OBS + 24) != get(w, C_LEASE):
            return refuse(w, 2058)
        if get(w, OBS + 32) != get(w, A_YIELD_SEQUENCE) or get(w, OBS + 40) != get(w, A_REQUEST) or get(w, OBS + 48) != 2:
            return refuse(w, 2059)
        if get(w, OBS + 56) <= get(w, A_PARENT_SEQUENCE) or get(w, OBS + 64) != 2 or get(w, OBS + 72) != B_PUBLIC_RECEIPT or get(w, OBS + 88) != 1:
            return refuse(w, 2060)
        size = get(w, OBS + 80)
        if size < 132 or cap(w, B_PUBLIC_RECEIPT) != 0:
            return refuse(w, 2061)
        at = 96
        while at < 128:
            if get(w, OBS + at) != 0:
                return refuse(w, 2062)
            at = at + 8
        put(w, A_PARENT_SEQUENCE, get(w, OBS + 56))
        put(w, CAPS + B_PUBLIC_RECEIPT * 8, size)
        return release(o, w, B_RESULT, 810)
    return refuse(w, 2063)

def publication_step(o:mutbuf, w:mutbuf) -> u64:
    phase = get(w, C_PHASE)
    if phase == 810:
        return view(o, w, B_PUBLIC_RECEIPT, 0, 128, 811)
    if phase == 811:
        if get(w, OBS) != A_PUBLICATION or get(w, OBS + 8) != 1 or get(w, OBS + 16) != 1 or get(w, OBS + 24) != get(w, C_LEASE):
            return refuse(w, 2070)
        if get(w, OBS + 32) != get(w, A_YIELD_SEQUENCE) or get(w, OBS + 40) != get(w, A_REQUEST) or get(w, OBS + 48) != get(w, A_PARENT_SEQUENCE) or get(w, OBS + 56) != 1:
            return refuse(w, 2071)
        size = cap(w, B_PUBLIC_RECEIPT)
        count = get(w, OBS + 72)
        if get(w, OBS + 64) != 128 or count < 2 or count > size - 128:
            return refuse(w, 2072)
        at = 128 + count
        if get(w, OBS + 80) != at or get(w, OBS + 88) != size - at or get(w, OBS + 96) != size:
            return refuse(w, 2073)
        if get(w, OBS + 104) != 0 or get(w, OBS + 112) != 0 or get(w, OBS + 120) != 0:
            return refuse(w, 2074)
        put(w, A_DEST_BYTES, count)
        put(w, A_RECEIPT_AT, at)
        put(w, A_RECEIPT_BYTES, size - at)
        expected = publication_literals(w)
        if expected < 2 or expected > 256 or get(w, A_RECEIPT_BYTES) != expected:
            return refuse(w, 2075)
        put(w, A_EXPECTED_BYTES, expected)
        return view(o, w, B_PUBLIC_RECEIPT, at, expected, 812)
    if phase == 812:
        at = 0
        while at < get(w, A_EXPECTED_BYTES):
            if byte(w, OBS + at) != byte(w, A_EXPECT + at):
                return refuse(w, 2076)
            at = at + 1
        return view(o, w, B_PUBLIC_RECEIPT, 128, 1, 813)
    if phase == 813:
        if byte(w, OBS) != 34:
            return refuse(w, 2077)
        return view(o, w, B_PUBLIC_RECEIPT, 127 + get(w, A_DEST_BYTES), 1, 814)
    if phase == 814:
        if byte(w, OBS) != 34:
            return refuse(w, 2078)
        fixed = A_TEXT1_BYTES + A_TEXT2_BYTES + A_TEXT3_BYTES
        if get(w, A_DEST_BYTES) > MAX - fixed or get(w, A_RECEIPT_BYTES) > MAX - fixed - get(w, A_DEST_BYTES):
            return refuse(w, 2079)
        size = fixed + get(w, A_DEST_BYTES) + get(w, A_RECEIPT_BYTES)
        put(w, A_PUBLIC_BYTES, size)
        return grow(o, w, B_PUBLIC_JSON, size, 815)
    if phase == 815:
        return copy(o, w, B_CONTROLLER, A_TEXT1, B_PUBLIC_JSON, 0, A_TEXT1_BYTES, 816)
    if phase == 816:
        return copy(o, w, B_PUBLIC_RECEIPT, 128, B_PUBLIC_JSON, A_TEXT1_BYTES, get(w, A_DEST_BYTES), 817)
    if phase == 817:
        return copy(o, w, B_CONTROLLER, A_TEXT2, B_PUBLIC_JSON, A_TEXT1_BYTES + get(w, A_DEST_BYTES), A_TEXT2_BYTES, 818)
    if phase == 818:
        return copy(o, w, B_PUBLIC_RECEIPT, get(w, A_RECEIPT_AT), B_PUBLIC_JSON, A_TEXT1_BYTES + get(w, A_DEST_BYTES) + A_TEXT2_BYTES, get(w, A_RECEIPT_BYTES), 819)
    if phase == 819:
        return copy(o, w, B_CONTROLLER, A_TEXT3, B_PUBLIC_JSON, get(w, A_PUBLIC_BYTES) - A_TEXT3_BYTES, A_TEXT3_BYTES, 820)
    if phase == 820:
        return protect(o, w, B_PUBLIC_JSON, 1, 821)
    if phase == 821:
        return start_result(w, 3, 0, 0, 0, 1, 0, B_PUBLIC_JSON, 0, get(w, A_PUBLIC_BYTES))
    return refuse(w, 2080)

def decimal_text(w:mutbuf, at:u64, value:u64) -> u64:
    digits = 1
    remaining = value
    while remaining >= 10:
        remaining = remaining // 10
        digits = digits + 1
    index = digits
    while index != 0:
        index = index - 1
        store(w, at + index, 48 + value % 10)
        value = value // 10
    return digits
'''

def writes(raw,expression,indent="    "):
    lines=[]
    for offset in range(0,len(raw),8):
        block=raw[offset:offset+8]
        if len(block)==8:lines.append(f"{indent}put(w, {expression} + {offset}, {int.from_bytes(block,'little')})")
        else:
            lines.extend(f"{indent}store(w, {expression} + {offset+i}, {value})" for i,value in enumerate(block))
    return lines

def literal_functions():
    result=["def prefix_message(w:mutbuf, message:u64) -> u64:"]
    for identifier,payload in sorted(PREFIX_MESSAGES.items()):
        result.append(f"    if message == {identifier}:")
        result.extend(writes(payload,"PREFIX_TEXT","        "))
        result.append(f"        return {len(payload)}")
    result.append("    return 0")
    parts=[
      b'{"input_sha256":"'+b"A"*64+b'","ok":true,"output":',
      b',"program_sha256":"'+b"B"*64+b'","publication":',
      b',"published_representation":"independently_verified_normalized_core","schema":"hepta.hia.output.v1","status":"verified_program_published"}']
    for i,part in enumerate(parts,1):CONSTANTS["A_TEXT"+str(i)+"_BYTES"]=len(part)
    result.append("\ndef publication_literals(w:mutbuf) -> u64:")
    for i,part in enumerate(parts,1):result.extend(writes(part,"A_TEXT"+str(i)))
    result.append(f"    hex_digest(w, E_INPUT_HASH, A_TEXT1 + {parts[0].index(b'A'*64)})")
    result.append(f"    hex_digest(w, E_CORE_HASH, A_TEXT2 + {parts[1].index(b'B'*64)})")
    prefix=b'{"bytes":';suffix=b',"sha256":"'
    result.extend(writes(prefix,"A_EXPECT"))
    result.append(f"    count = {len(prefix)} + decimal_text(w, A_EXPECT + {len(prefix)}, get(w, E_CORE_BYTES))")
    result.extend(writes(suffix,"A_EXPECT + count"))
    result.append(f"    count = count + {len(suffix)}")
    result.append("    hex_digest(w, E_CORE_HASH, A_EXPECT + count)")
    result.append("    store(w, A_EXPECT + count + 64, 34)")
    result.append("    store(w, A_EXPECT + count + 65, 125)")
    result.append("    return count + 66")
    return "\n".join(result)+"\n"

def expanded_source():
    extra=literal_functions()
    tree=ast.parse(SOURCE+"\n"+ADMISSION+"\n"+HASH+"\n"+HEX+"\n"+HELPERS+"\n"+COMMON+"\n"+extra)
    fns={node.name:node for node in tree.body};assert len(fns)==len(tree.body)
    live={"program_service"};pending=["program_service"]
    while pending:
        for node in ast.walk(fns[pending.pop()]):
            if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id in fns and node.func.id not in live:
                live.add(node.func.id);pending.append(node.func.id)
    tree.body=[fns["program_service"]]+[node for node in tree.body if node.name!="program_service" and node.name in live]
    class Expand(ast.NodeTransformer):
        def visit_Name(self,node):
            if isinstance(node.ctx,ast.Load) and node.id in CONSTANTS:
                return ast.copy_location(ast.Constant(CONSTANTS[node.id]),node)
            return node
    tree=ast.fix_missing_locations(Expand().visit(tree))
    for node in tree.body:
        if node.name!="program_service":
            assert node.returns.id in ("u32","u64")
            node.returns.id="u64"
    return ast.unparse(tree)+"\n"

def document(source):
    nodes=ast.parse(source).body
    names={node.name:"f"+str(index) for index,node in enumerate(nodes)}
    sigs={node.name:([a.annotation.id for a in node.args.args],node.returns.id) for node in nodes}
    total=total_scalar_functions(nodes);functions=[]
    for node in nodes:
        builder=CopyBuilder(node,names,sigs,total);builder.statements(node.body)
        functions.append(dict(name=names[node.name],params=[builder.param(p) for p in builder.params],
          returns=[builder.returns],effects=["read","write","trap"],entry="b0",blocks=builder.blocks))
    return compact_authoring_cfg(dict(schema="hepta.hia.program.v8",
        module="cli_program_service_root_reconstructed_r1",functions=functions))

def main():
    assert not ROOT.exists(),"Preserve the earlier attempt"
    (ROOT/"tools").mkdir(parents=True);(ROOT/"development").mkdir();(ROOT/"examples/hia_bootstrap").mkdir(parents=True)
    original=Path(__file__).read_bytes();(ROOT/"tools"/Path(__file__).name).write_bytes(original)
    text=expanded_source();(ROOT/"development/program_service.authoring.py").write_text(text)
    doc=document(text);raw=render_assembly(doc).encode();assemble_program(raw)
    target=ROOT/"examples/hia_bootstrap/program_service.hiaasm";target.write_bytes(raw)
    profile=dict(functions=len(doc["functions"]),blocks=sum(len(f["blocks"]) for f in doc["functions"]),
        max_blocks=max(len(f["blocks"]) for f in doc["functions"]),
        ops=sum(len(b["ops"]) for f in doc["functions"] for b in f["blocks"]),
        max_block_params=max(len(b["params"]) for f in doc["functions"] for b in f["blocks"]),
        source_bytes=len(raw),source_sha256=sha256(raw).hexdigest())
    assert profile["functions"]<=128 and profile["blocks"]<=1536 and profile["max_blocks"]<=256
    assert profile["ops"]<=8192 and profile["max_block_params"]<=16 and len(raw)<=1<<20
    assert all(p.read_bytes()==original for p,original in RAW.items())
    pins=[dict(path=str(p),bytes=len(raw),sha256=sha256(raw).hexdigest()) for p,raw in RAW.items()]
    (ROOT/"development/authoring-source-pins.json").write_text(json.dumps(pins,indent=2,sort_keys=True)+"\n")
    report=dict(status="GENERATED_ONLY",source_path=str(target),profile=profile,
        generator_sha256=sha256(original).hexdigest(),original_authoring_sources_preserved=True,
        actual_native_compilations=0,actual_native_entries=0,
        old_owners_deleted=False,whole_stack_closed=False,
        installed_CLI_claim=False,publication_parent_owner_still_required=True,
        private_publication_receipt_requires_actual_parent_issued_provenance=True)
    (ROOT/"development/source-r1.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print(json.dumps(report,sort_keys=True),flush=True)
if __name__=="__main__":main()
