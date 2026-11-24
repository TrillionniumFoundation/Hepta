"""Author isolated supervisor admission, credentials and lifecycle in HIA."""
from __future__ import annotations
import argparse
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_system_jobctl_request import document
from tools.generate_hia_system_jobctl_diagnostics import HELPERS as DIAGNOSTICS, RENDERER as DIAGNOSTIC_RENDERER
from tools.generate_hia_system_jobctl_errors import error_source
from tools.generate_hia_system_jobctl_typed_errors import HELPERS as TYPED_ERRORS
from tools.generate_hia_system_jobctl_supervisor_common import helpers,literals,substitute
ROOT=Path(__file__).resolve().parents[1]

POLICY=r'''
def supervisor(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(o) != 128 or length(w) != STATE_BYTES:
        return 0
    phase = get(w, 0)
    result = get(w, 8)
    if phase >= 2060 and phase < 2070:
        return diagnostic_step(o, w, phase, result)
    if phase == 2000:
        return call(o, w, 2001, 107, 0, 0, 0, 0, 0, 0, 0)
    if phase == 2001:
        if result == 0:
            return diagnostic(w, SUP_ERROR_TEXT, text_root(w, SUP_ERROR_TEXT) - SUP_ERROR_TEXT)
        if failed(result):
            return diagnostic_errno(w, result)
        put(w, 0, 2002)
        return 15
    if phase == 2002:
        return call(o, w, 2003, 158, 4097, 0, 0, 0, 0, 0, 12)
    if phase == 2003:
        if result != 0:
            return 0
        put(w, SUP_STOP, 0)
        put(w, SUP_SIGNAL, get(w, SUP_HANDLER))
        put(w, SUP_SIGNAL + 8, 335544320)
        put(w, SUP_SIGNAL + 16, get(w, SUP_RESTORER))
        put(w, SUP_SIGNAL + 24, 0)
        return call(o, w, 2004, 13, 15, SUP_SIGNAL, 0, 8, 0, 0, 12)
    if phase == 2004:
        if result != 0:
            return 0
        return call(o, w, 2005, 13, 2, SUP_SIGNAL, 0, 8, 0, 0, 12)
    if phase == 2005:
        if result != 0:
            return 0
        return call(o, w, 2010, 13, 1, SUP_SIGNAL, 0, 8, 0, 0, 12)
    if phase == 2010:
        if environment_value(s, w, 0, SUP_CREDENTIAL, SUP_CREDENTIAL_SIZE) == 0:
            if get(w, 68200) == 1:
                return typed_error(o, w, 10, SUP_CREDENTIAL, get(w, SUP_CREDENTIAL_SIZE), 2071)
            return diagnostic(w, SUP_ERROR_TEXT, text_environment_missing(w, SUP_ERROR_TEXT) - SUP_ERROR_TEXT)
        end = joined(w, SUP_PATH, SUP_CREDENTIAL, get(w, SUP_CREDENTIAL_SIZE))
        end = text_spec(w, end)
        store(w, end, 0)
        return begin_file(o, w, 2011, SUP_PATH, FILE_RAW, 1048576)
    if phase == 2011:
        put(w, SPEC_MODE, 0)
        put(o, 0, FILE_RAW)
        put(o, 8, get(w, 288))
        put(w, 0, 2012)
        return 17
    if phase == 2012:
        if result != 1:
            return typed_error(o, w, 259, FILE_RAW, get(w, 288), 2071)
        put(w, SUP_REQUEST_SIZE, get(w, SPEC_FIELDS + 8))
        return decode_request(o, w, 2013)
    if phase == 2013 or phase == 2021:
        if result >= 4294967280:
            if phase == 2013:
                return typed_error(o, w, 259, FILE_RAW, get(w, 288), 2071)
            return 0
        put(w, OVERRIDE_MASK, 0)
        return request(o, w, choose(phase == 2013, 2014, 2022))
    if phase == 2014:
        if result != 1:
            return typed_error(o, w, 259, FILE_RAW, get(w, 288), 2071)
        child = get(w, TABLE + 8)
        if equal(w, ARENA + node(w, child, 24), node(w, child, 32), SUP_JOB, get(w, SUP_JOB_SIZE)) == 0:
            return diagnostic(w, SUP_ERROR_TEXT, text_identity(w, SUP_ERROR_TEXT) - SUP_ERROR_TEXT)
        end = text_boot(w, SUP_PATH)
        store(w, end, 0)
        return begin_file(o, w, 2015, SUP_PATH, FILE_RAW, 1048576)
    if phase == 2015:
        if kernel_text(w, FILE_RAW, get(w, 288)) == 0:
            return diagnostic(w, SUP_ERROR_TEXT, text_invalid_utf8(w, SUP_ERROR_TEXT) - SUP_ERROR_TEXT)
        if equal(w, get(w, SCAN_NEXT), get(w, SCAN_SIZE), get(w, SPEC_FIELDS + 32), get(w, SPEC_FIELDS + 40)) == 0:
            return diagnostic(w, SUP_ERROR_TEXT, text_identity(w, SUP_ERROR_TEXT) - SUP_ERROR_TEXT)
        protocol = get(w, SPEC_PROTOCOL)
        expected = choose(get(w, SUP_INTERACTIVE) == 1, 2, 1)
        if protocol != 0 and protocol != expected:
            return diagnostic(w, SUP_ERROR_TEXT, text_protocol(w, SUP_ERROR_TEXT) - SUP_ERROR_TEXT)
        put(w, SUP_PROTOCOL, expected)
        if environment_value(s, w, 1, SUP_STATE, SUP_STATE_SIZE) == 0:
            if get(w, 68200) == 1:
                return typed_error(o, w, 10, SUP_STATE, get(w, SUP_STATE_SIZE), 2071)
            return diagnostic(w, SUP_ERROR_TEXT, text_environment_missing(w, SUP_ERROR_TEXT) - SUP_ERROR_TEXT)
        put(w, SUP_TIMEOUT, choose(present(w, 7) == 1, get(w, VALUES + 56), 3600))
        put(w, SUP_STDIN_PRESENT, present(w, 6))
        put(w, SUP_STDIN_SIZE, 0)
        if get(w, SUP_STDIN_PRESENT) == 1:
            child = get(w, TABLE + 48)
            size = node(w, child, 32)
            copy(w, SUP_INPUT, ARENA + node(w, child, 24), size)
            put(w, SUP_STDIN_SIZE, size)
        put(w, 62000, 0)
        put(w, 62008, 2020)
        put(w, 62024, get(w, SUP_INTERACTIVE))
        child = get(w, TABLE + 24)
        count = 0
        if child != NONE:
            count = node(w, child, 32)
        put(w, 62032, count)
        if count == 1:
            child = node(w, child, 24)
            put(w, 62040, ARENA + node(w, child, 24))
            put(w, 62048, node(w, child, 32))
        put(w, 62056, get(w, SUP_STDIN_PRESENT))
        put(w, 62064, SUP_INPUT)
        put(w, 62072, get(w, SUP_STDIN_SIZE))
        put(w, 62080, SUP_STATE)
        put(w, 62088, get(w, SUP_STATE_SIZE))
        put(w, 62096, SUP_JOB)
        put(w, 62104, get(w, SUP_JOB_SIZE))
        put(w, 62112, get(w, SPEC_FIELDS + 16))
        put(w, 62120, get(w, SPEC_FIELDS + 24))
        put(w, 0, 3000)
        return 8
    if phase == 2020:
        if get(w, 62144) != 0:
            return diagnostic(w, get(w, 62176), get(w, 62184))
        put(w, SUP_SCRATCH, get(w, 62192))
        put(w, SUP_BINDING, get(w, 62160))
        put(w, SUP_BINDING_SIZE, get(w, 62168))
        return decode_request(o, w, 2021)
    if phase == 2022:
        if result != 1:
            return 0
        put(w, 0, 2023)
        return 24
    if phase == 2023:
        if result != 1:
            return diagnostic(w, SUP_ERROR_TEXT, text_prefix(w, SUP_ERROR_TEXT) - SUP_ERROR_TEXT)
        put(w, SPAWN_FDS + 64, NONE)
        if get(w, SUP_INTERACTIVE) == 1:
            return start_spawn(w)
        if get(w, SUP_STDIN_PRESENT) == 0:
            return start_spawn(w)
        input_path(w)
        return call(o, w, 2024, 257, NEG100, SUP_PATH, 524865, 438, 0, 0, 12)
    if phase == 2024:
        if result == NEG4:
            return call(o, w, 2024, 257, NEG100, SUP_PATH, 524865, 438, 0, 0, 12)
        if failed(result):
            return diagnostic_errno(w, result)
        put(w, SUP_FD, result)
        put(w, SUP_USED, 0)
        return input_write(o, w)
    if phase == 2025:
        if result == NEG4:
            return input_write(o, w)
        if result == 0 or failed(result):
            put(w, 68208, result)
            return call(o, w, 2072, 3, get(w, SUP_FD), 0, 0, 0, 0, 0, 0)
        if result > get(w, SUP_STDIN_SIZE) - get(w, SUP_USED):
            return 0
        put(w, SUP_USED, get(w, SUP_USED) + result)
        return input_write(o, w)
    if phase == 2026:
        put(w, SUP_FD, NONE)
        input_path(w)
        return call(o, w, 2027, 257, NEG100, SUP_PATH, 524288, 0, 0, 0, 12)
    if phase == 2027:
        if result == NEG4:
            return call(o, w, 2027, 257, NEG100, SUP_PATH, 524288, 0, 0, 0, 12)
        if failed(result):
            return diagnostic_errno(w, result)
        put(w, SPAWN_FDS + 64, result)
        return start_spawn(w)
    if phase == 2028:
        if get(w, SPAWN_ERROR) != 0:
            put(w, SUP_EXIT_CODE, 127)
            put(w, SUP_TIMED_OUT, 0)
            put(w, SUP_CANCELLED, 0)
            put(w, SUP_RETURN_ERROR, 1)
            put(w, 0, 2500)
            return 8
        put(w, 0, 2300)
        return 8
    if phase == 2050:
        if get(w, SUP_ERROR_SIZE) != 0:
            if get(w, SUP_SCRATCH) == 0:
                return diagnostic(w, get(w, SUP_ERROR), get(w, SUP_ERROR_SIZE))
            put(w, 62000, 4)
            put(w, 62008, 2052)
            put(w, 62176, get(w, SUP_ERROR))
            put(w, 62184, get(w, SUP_ERROR_SIZE))
            put(w, 0, 3000)
            return 8
        return call(o, w, 2053, 228, 0, PUB_TIME, 0, 0, 0, 0, 12)
    if phase == 2053:
        if result != 0:
            put(w, PUB_TIME, 0)
            put(w, PUB_TIME + 8, 0)
        put(w, PUB_TIME_READY, 1)
        if get(w, SUP_SCRATCH) == 1:
            put(w, 62000, 3)
            put(w, 62008, 2051)
            put(w, 62128, get(w, SUP_PID))
            put(w, 62136, get(w, SUP_GROUP_STOPPED))
            put(w, 0, 3000)
            return 8
        put(w, SUP_CLEANUP, 0)
        put(w, SUP_CLEANUP_SIZE, 0)
        put(w, 0, 2500)
        return 8
    if phase == 2051:
        if get(w, 62144) != 0:
            return diagnostic(w, get(w, 62176), get(w, 62184))
        put(w, SUP_CLEANUP, get(w, 62160))
        put(w, SUP_CLEANUP_SIZE, get(w, 62168))
        put(w, 0, 2500)
        return 8
    if phase == 2052:
        return diagnostic(w, get(w, SUP_ERROR), get(w, SUP_ERROR_SIZE))
    if phase == 2071:
        return typed_failure(w, 0, 0)
    if phase == 2072:
        put(w, SUP_FD, NONE)
        if get(w, 68208) == 0:
            return diagnostic(w, SUP_ERROR_TEXT, text_write_zero(w, SUP_ERROR_TEXT) - SUP_ERROR_TEXT)
        return diagnostic_errno(w, get(w, 68208))
    if phase == 2070:
        if get(w, SUP_RETURN_ERROR) != 0:
            return diagnostic(w, get(w, SUP_ERROR), get(w, SUP_ERROR_SIZE))
        return call(o, w, 99999, 231, 0, 0, 0, 0, 0, 0, 0)
    return 0

def start_spawn(w:mutbuf) -> u32:
    put(w, SPAWN_NEXT, 2028)
    put(w, 0, 2200)
    return 8

def decode_request(o:mutbuf, w:mutbuf, next:u64) -> u32:
    put(w, 32, get(w, SUP_REQUEST_SIZE))
    action = decode(o, w, next, RAW, get(w, SUP_REQUEST_SIZE))
    put(w, SCRATCH + 56, 127)
    return action

def input_path(w:mutbuf) -> u64:
    end = joined(w, SUP_PATH, SUP_STATE, get(w, SUP_STATE_SIZE))
    end = text_input(w, end)
    store(w, end, 0)
    return end

def input_write(o:mutbuf, w:mutbuf) -> u32:
    if get(w, SUP_USED) == get(w, SUP_STDIN_SIZE):
        return call(o, w, 2026, 3, get(w, SUP_FD), 0, 0, 0, 0, 0, 0)
    return call(o, w, 2025, 1, get(w, SUP_FD), SUP_INPUT + get(w, SUP_USED), get(w, SUP_STDIN_SIZE) - get(w, SUP_USED), 0, 0, 0, 12)

def joined(w:mutbuf, target:u64, source:u64, size:u64) -> u64:
    copy(w, target, source, size)
    at = target + size
    if size != 0 and byte(w, at - 1) != 47:
        store(w, at, 47)
        at = at + 1
    return at

def environment_value(s:readbuf, w:mutbuf, kind:u64, target:u64, size_slot:u64) -> u64:
    put(w, 68200, 0)
    key_size = text_credentials(w, SUP_TEMP) - SUP_TEMP
    if kind == 1:
        key_size = text_state(w, SUP_TEMP) - SUP_TEMP
    at = 32
    index = 0
    while index < uint(s, 8):
        at = at + uint(s, at) + 9
        index = index + 1
    index = 0
    while index < uint(s, 16):
        if at > length(s) or length(s) - at < 9:
            return 0
        size = uint(s, at)
        if size >= length(s) - at - 8:
            return 0
        if size >= key_size:
            cursor = 0
            while cursor < key_size and byte(s, at + 8 + cursor) == byte(w, SUP_TEMP + cursor):
                cursor = cursor + 1
            if cursor == key_size:
                value_size = size - key_size
                cursor = 0
                while cursor < value_size:
                    store(w, target + cursor, byte(s, at + 8 + key_size + cursor))
                    cursor = cursor + 1
                store(w, target + value_size, 0)
                put(w, size_slot, value_size)
                put(w, 68200, 1)
                return kernel_text(w, target, value_size)
        at = at + size + 9
        index = index + 1
    return 0
'''

def source_program():
    names=['call','get','put','putn','uint','failed','copy','node','present','request','decode','begin_file','kernel_text','equal']
    return substitute(POLICY+'\n'+TYPED_ERRORS+'\n'+DIAGNOSTICS+'\n'+DIAGNOSTIC_RENDERER+'\n'+error_source()+'\n'+helpers(names)+literals({'environment_missing':'environment variable not found','invalid_utf8':'stream did not contain valid UTF-8','write_zero':'failed to write whole buffer','spec':'spec','input':'stdin.bin','null':'/dev/null','boot':'/proc/sys/kernel/random/boot_id','credentials':'CREDENTIALS_DIRECTORY=','state':'STATE_DIRECTORY=','root':'supervisor must never execute as root','identity':'supervisor identity mismatch','protocol':'supervisor capture protocol mismatch','prefix':'prefix not found'}))

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--check',action='store_true');args=parser.parse_args()
    doc=document(source_program(),'system_jobctl_supervisor');text=render_assembly(doc);p=ROOT/'examples/hia_bootstrap/system_jobctl_supervisor.hepta'
    if args.check:assert p.read_text()==text
    else:p.write_text(text)
    print(p.name,len(doc['functions']),sum(len(b['ops']) for f in doc['functions'] for b in f['blocks']),flush=True)
if __name__=='__main__':main()
