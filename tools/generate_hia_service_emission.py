"""Author HIA emission, compilation and ABI-signature continuation policy.

Only the authoring process interprets these finite transition tables. The
installed owner executes their ordinary Core control flow. Python retains
foreign object identities and performs one issued primitive at a time.
The internal fourth mode is the body of an explicit context-manager mechanism;
it contains all build-path, timeout-choice, provider-call and file-read policy.
"""
from __future__ import annotations
import ast
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import compact_authoring_cfg, total_scalar_functions
from tools.hia_program_execution_scalars import ScalarBuilder as Builder
from tools.hia_exception_delivery import BODY as DELIVERY_BODY, EMIT_MAGIC

REQUEST_MAGIC = int.from_bytes(b'HIAEMQ01', 'little')
STATE_MAGIC = int.from_bytes(b'HIAEMS01', 'little')
RESULT_MAGIC = int.from_bytes(b'HIAEMR01', 'little')
STATE_BYTES = 128
# Fixed foreign slot names; the HIA table below owns their retirement order.
# These are the original named locals, including compiler-created inlined
# comprehension slots and generator free variables. Missing slots are legal.
NAMED_LOCALS = {
    1: ('service_local', 'args', 'context', 'program', 'ref', 'codegen', 'plan',
        '_', 'receipt', 'expected_subject', 'exports', 'data', 'native_build',
        'pair', 'metadata', 'artifact'),
    2: ('service_local', 'program', 'kind', 'machine_plan', 'timeout_ms',
        'foreign_buffer_exports', 'emit_program_machine', 'compile_program_machine',
        'deadline', 'image', 'object_bytes', 'commands', 'directory', 'output',
        'build_result', 'data'),
    3: ('program', 'foreign_buffer_exports', 'normalize_exports', 'BUFFER_PROFILE',
        'document', 'fn', 'p', 'signatures', 'exports', 'WIDTHS'),
    5: ('iterator', 'item', 'WIDTHS'),
    6: ('iterator', 'item', 'WIDTHS'),
    7: ('iterator', 'item'),
}
LOCAL_SLOTS = tuple(dict.fromkeys(name for names in NAMED_LOCALS.values() for name in names))
TEMPORARIES = ('receipts_iterator', 'subject_fields', 'checks_iterator', 'check_value',
    'compile_kind', 'compile_remaining', 'compile_kwargs', 'metadata_fields',
    'export_list', 'export_iterator', 'export_pair', 'build_document', 'clock_first',
    'quotient', 'manager', 'publisher_callee', 'object_metadata', 'object_artifact_result',
    'functions_iterator_comp', 'fn_comp', 'parameter_iterator_check', 'p_check',
    'return_iterator_check', 'typ_check', 'signature_key', 'parameter_list',
    'parameter_iterator_build', 'p_build', 'signature_value_fields', 'signature_value',
    'functions_iterator_outer', 'parameter_iterator_outer', 'p_outer',
    'outer_signature_fields', 'outer_signature_value', 'outer_signature_key',
    'path_left', 'compile_callee', 'clock_second', 'difference', 'floor', 'timeout_value', 'yield_value')

def mask(*names):
    return sum(1 << TEMPORARIES.index(name) for name in names)

GRAPHS = {
  1: {1:2,2:3,3:4,4:5,5:(7,6),6:5,7:8,8:(10,9),9:30,
      10:11,11:12,12:13,13:14,14:15,15:16,16:17,17:18,18:19,
      19:(20,29),20:21,21:(29,22),22:(21,24),24:30,29:0,
      30:31,31:32,32:33,33:35,35:(37,36),36:38,37:38,38:40,
      40:41,41:42,42:43,43:44,44:45,45:46,46:47,47:48,48:49,
      49:(51,50),50:49,51:52,52:53,53:54,54:55,55:56,56:57,
      57:58,58:59,59:60,60:61,61:62,62:63,63:0},
  2: {201:202,202:(203,290),203:204,204:205,205:206,206:207,207:208,
      208:(291,209),209:210,210:211,211:'choose((observed & 1) != 0, 213, 294)',
      213:214,214:215,215:(216,292),
      216:('choose((flags & 2) != 0, 218, 295)',292),
      218:(219,292),219:(221,220),220:(221,292),221:222,222:223,
      223:224,224:225,225:0,290:0,291:0,292:0,294:0,295:0},
  3: {401:402,402:403,403:404,404:(430,405),405:(404,406),406:407,
      407:'choose(observed == 2, 409, choose(observed == 1, 407, 410))',
      409:411,410:404,411:(404,412),
      412:413,413:'choose(observed == 2, 415, choose(observed == 1, 413, 416))',
      415:417,416:404,
      417:418,418:419,419:(421,420),420:419,421:422,422:423,423:424,424:404,
      430:431,431:432,432:(449,433),433:(432,434),434:435,435:(437,436),
      436:435,437:438,438:439,439:440,440:441,441:442,442:443,443:432,449:0},
  4: {601:701,701:702,702:(704,703),703:705,704:705,705:706,706:707,
      707:708,708:709,709:(710,711),710:712,711:712,712:(714,713),
      713:715,714:715,715:716,716:717,717:0},
  5: {801:(804,802),802:(803,803),804:805,805:806,806:0},
  6: {851:(854,852),852:(853,853),854:855,855:856,856:0},
  7: {1001:(1009,1002),1002:1003,1003:(1008,1004),1004:1005,1005:1008,
      1009:1010,1010:1011,1011:0},
}
# Phase 601 is the internal body entry, with no policy effect.
CREATED = {
  4:mask('receipts_iterator'),14:mask('subject_fields'),
  20:mask('checks_iterator'),21:mask('check_value'),31:mask('compile_callee'),
  32:mask('compile_kind'),33:mask('compile_remaining'),36:mask('compile_kwargs'),
  37:mask('compile_kwargs'),40:mask('metadata_fields'),
  48:mask('export_list','export_iterator'),49:mask('export_pair'),56:mask('build_document'),
  203:mask('clock_first'),204:mask('quotient'),210:mask('manager'),
  221:mask('publisher_callee'),222:mask('object_metadata'),223:mask('object_artifact_result'),
  403:mask('functions_iterator_comp'),404:mask('fn_comp'),406:mask('parameter_iterator_check'),
  412:mask('return_iterator_check'),
  417:mask('signature_key'),418:mask('parameter_list','parameter_iterator_build'),419:mask('p_build'),
  421:mask('signature_value_fields'),423:mask('signature_value'),
  431:mask('functions_iterator_outer'),434:mask('parameter_list','parameter_iterator_outer'),
  435:mask('p_outer'),437:mask('outer_signature_fields'),441:mask('outer_signature_value'),
  442:mask('outer_signature_key'),701:mask('path_left'),706:mask('compile_callee'),
  707:mask('clock_second'),708:mask('difference'),710:mask('floor'),711:mask('floor'),
  713:mask('timeout_value'),714:mask('timeout_value'),
  1002:mask('yield_value'),1005:mask('yield_value'),
}
CLEARED = {
  5:(mask('receipts_iterator'),0),18:mask('subject_fields'),
  21:(mask('checks_iterator','check_value'),0),22:mask('check_value'),24:mask('checks_iterator','check_value'),
  38:mask('compile_callee','compile_kind','compile_remaining','compile_kwargs'),
  49:(mask('export_iterator'),0),51:mask('export_pair','export_list'),54:mask('metadata_fields'),
  62:mask('build_document'),205:mask('clock_first','quotient'),211:mask('manager'),
  223:mask('publisher_callee','object_metadata'),224:mask('object_artifact_result'),
  404:(mask('functions_iterator_comp'),0),407:'choose(observed == 2, @PARAMETER_MASK@, 0)',
  409:mask('p_check'),410:mask('p_check','parameter_iterator_check'),
  413:'choose(observed == 2, @RETURN_MASK@, 0)',415:mask('typ_check'),416:mask('typ_check','return_iterator_check'),
  419:(mask('parameter_iterator_build'),0),421:mask('parameter_list','p_build'),
  423:mask('signature_value_fields'),424:mask('signature_key','signature_value'),
  430:mask('fn_comp'),432:(mask('functions_iterator_outer'),0),
  435:(mask('parameter_iterator_outer'),0),437:mask('parameter_list','p_outer'),
  441:mask('outer_signature_fields'),443:mask('outer_signature_value','outer_signature_key'),
  705:mask('path_left'),708:mask('clock_second'),710:mask('difference'),711:mask('difference'),
  713:mask('floor'),714:mask('floor'),715:mask('compile_callee','timeout_value'),1004:mask('yield_value'),
}
PREDICATES = frozenset(p for graph in GRAPHS.values() for p,target in graph.items() if type(target) is tuple)

SOURCE = '''
def emission_main(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) == 64:
        if read_word(s, 0) == @EMIT_MAGIC@:
            return emit_exception_delivery(s, o, w)
    if length(s) != 64 or length(o) < 144 or length(w) != 128:
        return 4294967293
    profile = read_word(s, 56)
    if read_word(s, 0) != @REQUEST_MAGIC@ or (profile != 312 and profile != 313 and profile != 314):
        return refuse(o, 1)
    event = read_word(s, 8)
    if event == 0:
        return initialize(s, o, w)
    if valid(w) == 0:
        return refuse(o, 2)
    if read_word(s, 24) != get(w, 6) or read_word(s, 32) != get(w, 7):
        return refuse(o, 3)
    if read_word(s, 16) != get(w, 4) or read_word(s, 48) != get(w, 2):
        return refuse(o, 4)
    if profile != get(w, 12):
        return refuse(o, 4)
    if event == 7:
        return start_retirement(s, o, w)
    if get(w, 5) >= 9:
        return retirement_outcome(s, o, w, event)
    if event == 1:
        if get(w, 5) != 1 or read_word(s, 40) != 0 or get(w, 4) == 18446744073709551615:
            return refuse(o, 5)
        if get(w, 10) == 0:
            put(w, 9, get(w, 9) | created_mask(get(w, 3)))
        put(w, 5, 2)
        seal(w)
        return answer(o, w)
    if event == 2 or event == 3:
        return outcome(s, o, w, event)
    if event == 4:
        allowed = 0
        if get(w, 5) == 6 and get(w, 2) == 7:
            allowed = @YIELD_MASK@
        if read_word(s, 40) != 0 or get(w, 9) != allowed:
            return refuse(o, 5)
        if get(w, 5) == 6 and get(w, 10) == 0:
            put(w, 9, 0)
            put(w, 5, 8)
        elif get(w, 5) == 3 and get(w, 10) == 0:
            put(w, 5, 5)
        elif get(w, 5) == 4 and get(w, 10) == 1:
            put(w, 5, 7)
        else:
            return refuse(o, 5)
        seal(w)
        return answer(o, w)
    if event == 5 or event == 6:
        if get(w, 5) != 8 or get(w, 10) != 0 or read_word(s, 40) != 0:
            return refuse(o, 5)
        if get(w, 4) == 18446744073709551615:
            return refuse(o, 5)
        first = choose(get(w, 2) == 5, 801, choose(get(w, 2) == 6, 851, 1001))
        cleanup = choose(get(w, 2) == 7, 1009, first + 3)
        put(w, 3, choose(event == 5, first, cleanup))
        put(w, 5, 1)
        put(w, 4, get(w, 4) + 1)
        seal(w)
        return answer(o, w)
    return refuse(o, 1)

def initialize(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    kind = read_word(s, 48)
    if kind < 1 or kind > 7 or read_word(s, 16) != 0 or read_word(s, 40) != 0:
        return refuse(o, 1)
    if read_word(s, 24) == 0 and read_word(s, 32) == 0:
        return refuse(o, 3)
    i = 0
    while i < 16:
        if get(w, i) != 0:
            return refuse(o, 2)
        i = i + 1
    put(w, 0, @STATE_MAGIC@)
    put(w, 1, 2)
    put(w, 2, kind)
    first = (kind - 1) * 200 + 1
    if kind == 6:
        first = 851
    if kind == 7:
        first = 1001
    put(w, 3, first)
    put(w, 4, 1)
    put(w, 5, 1)
    put(w, 6, read_word(s, 24))
    put(w, 7, read_word(s, 32))
    put(w, 12, read_word(s, 56))
    seal(w)
    return answer(o, w)

def outcome(s:readbuf, o:mutbuf, w:mutbuf, event:u64) -> u32:
    if get(w, 5) != 2 or get(w, 4) == 18446744073709551615:
        return refuse(o, 5)
    observed = read_word(s, 40)
    if event == 3:
        if observed != 0 or get(w, 10) != 0:
            return refuse(o, 1)
        put(w, 10, 1)
        put(w, 11, get(w, 3))
        next = cleanup_next(get(w, 9))
        put(w, 3, next)
        put(w, 5, choose(next == 0, 4, 1))
        put(w, 4, get(w, 4) + 1)
        seal(w)
        return answer(o, w)
    if get(w, 10) == 1:
        if observed != 0 or get(w, 3) < 900 or get(w, 3) >= @CLEANUP_END@:
            return refuse(o, 1)
        put(w, 9, get(w, 9) & (18446744073709551615 ^ (1 << (get(w, 3) - 900))))
        next = cleanup_next(get(w, 9))
        put(w, 3, next)
        put(w, 5, choose(next == 0, 4, 1))
        put(w, 4, get(w, 4) + 1)
        seal(w)
        return answer(o, w)
    next = next_phase(get(w, 2), get(w, 3), observed, get(w, 14))
    if next == 18446744073709551615:
        return refuse(o, 6)
    remaining = get(w, 9) & (18446744073709551615 ^ cleared_mask(get(w, 3), observed))
    if get(w, 2) == 2 and get(w, 3) == 211:
        put(w, 14, observed)
    if get(w, 2) == 4 and get(w, 3) == 715:
        put(w, 14, get(w, 14) | 1)
    if get(w, 2) == 4 and get(w, 3) == 716:
        put(w, 14, get(w, 14) | 2)
    if get(w, 3) == 802 or get(w, 3) == 852:
        put(w, 14, observed)
    if next == 0 and remaining != 0:
        return refuse(o, 7)
    put(w, 9, remaining)
    put(w, 3, next)
    put(w, 4, get(w, 4) + 1)
    stage = choose(next == 0, 3, 1)
    if next == 803 or next == 853 or next == 1008:
        stage = 6
    put(w, 5, stage)
    seal(w)
    return answer(o, w)

def valid(w:mutbuf) -> u64:
    if get(w, 0) != @STATE_MAGIC@ or get(w, 1) != 2 or get(w, 2) < 1 or get(w, 2) > 7:
        return 0
    if get(w, 5) < 1 or get(w, 5) > 11 or get(w, 4) == 0:
        return 0
    if get(w, 9) > @ALL_TEMPORARIES@ or get(w, 10) > 1 or get(w, 14) > 3:
        return 0
    if get(w, 12) != 312 and get(w, 12) != 313 and get(w, 12) != 314:
        return 0
    if get(w, 5) >= 9:
        return retirement_valid(w)
    if get(w, 5) == 6 or get(w, 5) == 8:
        allowed = 0
        if get(w, 2) == 7 and get(w, 5) == 6:
            allowed = @YIELD_MASK@
        if get(w, 2) < 5 or get(w, 2) > 7 or get(w, 10) != 0 or get(w, 9) != allowed or get(w, 14) > 1:
            return 0
        if get(w, 3) != choose(get(w, 2) == 5, 803, choose(get(w, 2) == 6, 853, 1008)):
            return 0
    if get(w, 10) == 0:
        if get(w, 11) != 0 or get(w, 5) == 4 or get(w, 5) == 7:
            return 0
        if get(w, 5) <= 2 and next_phase(get(w, 2), get(w, 3), 0, get(w, 14)) == 18446744073709551615:
            return 0
    else:
        if get(w, 5) == 3 or get(w, 5) == 5 or next_phase(get(w, 2), get(w, 11), 0, get(w, 14)) == 18446744073709551615:
            return 0
        if get(w, 5) <= 2 and (get(w, 9) == 0 or get(w, 3) != cleanup_next(get(w, 9))):
            return 0
    if get(w, 5) >= 3 and get(w, 5) != 6 and get(w, 5) != 8 and (get(w, 3) != 0 or get(w, 9) != 0):
        return 0
    if get(w, 13) != 0 or get(w, 15) != 0:
        return 0
    return choose(get(w, 8) == checksum(w), 1, 0)

def start_retirement(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if (get(w, 5) != 5 and get(w, 5) != 7) or get(w, 2) == 4:
        return refuse(o, 8)
    if read_word(s, 40) != 0 or get(w, 4) == 18446744073709551615:
        return refuse(o, 8)
    put(w, 15, get(w, 5))
    put(w, 13, 0)
    next = retirement_action(get(w, 2), get(w, 12), 0)
    put(w, 3, next)
    put(w, 5, choose(next == 0, 11, 9))
    put(w, 4, get(w, 4) + 1)
    seal(w)
    return answer(o, w)

def retirement_outcome(s:readbuf, o:mutbuf, w:mutbuf, event:u64) -> u32:
    if read_word(s, 40) != 0 or get(w, 4) == 18446744073709551615:
        return refuse(o, 8)
    if event == 1:
        if get(w, 5) != 9:
            return refuse(o, 8)
        put(w, 5, 10)
    elif event == 2:
        if get(w, 5) != 10:
            return refuse(o, 8)
        put(w, 13, get(w, 13) + 1)
        next = retirement_action(get(w, 2), get(w, 12), get(w, 13))
        put(w, 3, next)
        put(w, 5, choose(next == 0, 11, 9))
        put(w, 4, get(w, 4) + 1)
    else:
        return refuse(o, 8)
    seal(w)
    return answer(o, w)

def retirement_valid(w:mutbuf) -> u64:
    if get(w, 2) == 4 or get(w, 9) != 0 or get(w, 13) > local_count(get(w, 2)):
        return 0
    if get(w, 15) == 5:
        if get(w, 10) != 0 or get(w, 11) != 0:
            return 0
    elif get(w, 15) == 7:
        if get(w, 10) != 1 or next_phase(get(w, 2), get(w, 11), 0, get(w, 14)) == 18446744073709551615:
            return 0
    else:
        return 0
    next = retirement_action(get(w, 2), get(w, 12), get(w, 13))
    if get(w, 3) != next or (get(w, 5) == 11) != (next == 0):
        return 0
    return choose(get(w, 8) == checksum(w), 1, 0)

def retirement_action(kind:u64, profile:u64, index:u64) -> u64:
    count = local_count(kind)
    if index >= count:
        return 0
    if profile == 314:
        index = count - 1 - index
    return named_local(kind, index)

def cleanup_next(live:u64) -> u64:
    i = @TEMPORARY_COUNT@
    while i > 0:
        i = i - 1
        if (live & (1 << i)) != 0:
            return 900 + i
    return 0

def checksum(w:mutbuf) -> u64:
    result = 1469598103934665603
    i = 0
    while i < 16:
        if i != 8:
            result = ((result << 7) | (result >> 57)) ^ get(w, i)
        i = i + 1
    return result

def seal(w:mutbuf) -> u64:
    put(w, 8, checksum(w))
    return 0

def answer(o:mutbuf, w:mutbuf) -> u32:
    put(o, 0, @RESULT_MAGIC@)
    put(o, 1, 0)
    i = 0
    while i < 128:
        store(o, 16 + i, byte(w, i))
        i = i + 1
    return 144

def refuse(o:mutbuf, status:u64) -> u32:
    put(o, 0, @RESULT_MAGIC@)
    put(o, 1, status)
    return 16

def get(w:mutbuf, index:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(w, index * 8 + i) << (i * 8))
        i = i + 1
    return value

def read_word(s:readbuf, index:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(s, index + i) << (i * 8))
        i = i + 1
    return value

def put(w:mutbuf, index:u64, value:u64) -> u64:
    i = 0
    while i < 8:
        store(w, index * 8 + i, value >> (i * 8))
        i = i + 1
    return value
'''

def source_program():
    source = SOURCE
    for name,value in (('REQUEST_MAGIC',REQUEST_MAGIC),('STATE_MAGIC',STATE_MAGIC),
                       ('RESULT_MAGIC',RESULT_MAGIC),('EMIT_MAGIC',EMIT_MAGIC),('YIELD_MASK',mask('yield_value')),
                       ('ALL_TEMPORARIES',(1 << len(TEMPORARIES))-1),
                       ('CLEANUP_END',900+len(TEMPORARIES)),('TEMPORARY_COUNT',len(TEMPORARIES))):
        source=source.replace('@'+name+'@',str(value))
    source += '\ndef local_count(kind:u64) -> u64:\n'
    for kind,names in NAMED_LOCALS.items():
        source += f'    if kind == {kind}:\n        return {len(names)}\n'
    source += '    return 0\n'
    source += '\ndef named_local(kind:u64, index:u64) -> u64:\n'
    for kind in NAMED_LOCALS:
        source += f'    if kind == {kind}:\n        return named_{kind}(index)\n'
    source += '    return 0\n'
    for kind,names in NAMED_LOCALS.items():
        source += f'\ndef named_{kind}(index:u64) -> u64:\n'
        for index,name in enumerate(names):
            source += f'    if index == {index}:\n        return {1100 + LOCAL_SLOTS.index(name)}\n'
        source += '    return 0\n'
    source += '\ndef created_mask(phase:u64) -> u64:\n'
    for phase,value in sorted(CREATED.items()):
        source += f'    if phase == {phase}:\n        return {value}\n'
    source += '    return 0\n'
    source += '\ndef cleared_mask(phase:u64, observed:u64) -> u64:\n'
    for phase,value in sorted(CLEARED.items()):
        source += f'    if phase == {phase}:\n'
        source += (f'        return choose(observed == 0, {value[0]}, {value[1]})\n'
                   if type(value) is tuple else f'        return {value}\n')
    source += '    return 0\n'
    source=source.replace('@PARAMETER_MASK@',str(mask('parameter_iterator_check'))).replace('@RETURN_MASK@',str(mask('return_iterator_check')))
    source += '\ndef next_phase(kind:u64, phase:u64, observed:u64, flags:u64) -> u64:\n'
    for kind in GRAPHS:
        source += f'    if kind == {kind}:\n        return next_{kind}(phase, observed, flags)\n'
    source += '    return 18446744073709551615\n'
    for kind,graph in GRAPHS.items():
        items=sorted(graph.items())
        chunks=[items[i:i+18] for i in range(0,len(items),18)]
        source += f'\ndef next_{kind}(phase:u64, observed:u64, flags:u64) -> u64:\n'
        for index,chunk in enumerate(chunks):
            source += f'    if phase <= {max(p for p,_ in chunk)}:\n        return next_{kind}_{index}(phase, observed, flags)\n'
        source += '    return 18446744073709551615\n'
        for index,chunk in enumerate(chunks):
            source += f'\ndef next_{kind}_{index}(phase:u64, observed:u64, flags:u64) -> u64:\n'
            for phase,target in chunk:
                source += f'    if phase == {phase}:\n'
                if type(target) is tuple:
                    source += ('        if observed > 1:\n            return 18446744073709551615\n'
                               f'        return choose(observed == 1, {target[1]}, {target[0]})\n')
                elif phase in (211, 407, 413):
                    limit=3 if phase==211 else 2
                    source += (f'        if observed > {limit}:\n            return 18446744073709551615\n'
                               f'        return {target}\n')
                else:
                    source += ('        if observed != 0:\n            return 18446744073709551615\n'
                               f'        return {target}\n')
            source += '    return 18446744073709551615\n'
    return source+'\n'+DELIVERY_BODY

def document():
    nodes=ast.parse(source_program()).body
    names={node.name:'f'+str(i) for i,node in enumerate(nodes)}
    signatures={node.name:([a.annotation.id for a in node.args.args],node.returns.id) for node in nodes}
    total=total_scalar_functions(nodes)
    functions=[]
    for node in nodes:
        builder=Builder(node,names,signatures,total)
        builder.statements(node.body)
        functions.append({'name':names[node.name],'params':[builder.param(v) for v in builder.params],
                          'returns':[builder.returns],'effects':['read','write','trap'],
                          'entry':'b0','blocks':builder.blocks})
    return compact_authoring_cfg({'schema':'hepta.hia.program.v8','module':'service_emission','functions':functions})

def main():
    target=Path(__file__).resolve().parents[1]/'examples/hia_bootstrap/service_emission.hepta'
    target.write_text(render_assembly(document()))
    print(target.name,target.stat().st_size)

if __name__=='__main__':
    main()
