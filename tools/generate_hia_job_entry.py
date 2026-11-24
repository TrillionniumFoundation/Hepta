"""Author the fixed native SSH job entry and two-image HIA ELF packer."""
from __future__ import annotations
import argparse
import re
import struct
import subprocess
import tempfile
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_job_supervisor import document
from tools.generate_hia_native_filter import LINK_SOURCE
ROOT = Path(__file__).resolve().parents[1]
STATE_BYTES = 2097152
PACKER_MAGIC = int.from_bytes(b'HIAJEK01', 'little')

POLICY = '''def advance(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(o) != 128 or length(w) != STATE_BYTES:
        return 0
    phase = get(w, 0)
    result = get(w, 8)
    if phase == 0:
        if arguments(s, w) == 0:
            return 0
        if get(w, 160) == 1:
            return launch_begin(o, w)
        put(w, 64, 0)
        return read_header(o, w)
    if phase == 1:
        if result == NEG4:
            return read_header(o, w)
        if failed(result) or result == 0 or result > 96 - get(w, 64):
            return 0
        put(w, 64, get(w, 64) + result)
        if get(w, 64) < 96:
            return read_header(o, w)
        if header(w) == 0:
            return 0
        put(w, 96, 0)
        return capture_begin(o, w)
    if phase >= 30 and phase <= 41:
        return launch_capture(s, o, w, phase, result)
    if phase >= 10 and phase <= 19:
        return capture(o, w, phase, result)
    if phase == 20:
        if result == NEG4:
            return call(o, w, 20, 0, 0, CHUNK + 1, 1, 0, 0, 0, 12)
        if result != 0 or payload_role(w) == 0:
            return 0
        return call(o, w, 21, 436, 3, 4294967295, 4, 0, 0, 0, 0)
    if phase == 21:
        if result != 0:
            return 0
        return call(o, w, 22, 8, get(w, 136), 0, 0, 0, 0, 0, 0)
    if phase == 22:
        if result != 0:
            return 0
        return call(o, w, 23, 33, get(w, 136), 0, 0, 0, 0, 0, 0)
    if phase == 23:
        if result != 0:
            return 0
        operation = get(w, HEADER + 8)
        end = text_submit(w, NAME)
        if operation == 2:
            end = text_observation(w, NAME)
        elif operation == 3:
            end = text_cancel(w, NAME)
        store(w, end, 0)
        store(w, NAME + 128, 0)
        put(w, POINTERS, NAME)
        put(w, POINTERS + 8, NONE)
        put(o, 0, POINTERS)
        put(o, 8, get(w, 144) + 3)
        put(o, 16, RELOCATED)
        put(w, 0, 24)
        return 2
    if phase == 24:
        if result != 0:
            return 0
        return call(o, w, 25, 322, get(w, 128), NAME + 128, RELOCATED, RELOCATED + 16, 4096, 0, 252)
    return 0

def arguments(s:readbuf, w:mutbuf) -> u64:
    if length(s) < 32 or length(s) > 2097152 or uint(s, 0) != ARG_MAGIC or uint(s, 24) != length(s):
        return 0
    argc = uint(s, 8)
    count = uint(s, 16)
    if (argc != 1 and (argc < 6 or argc > 128)) or count > 128:
        return 0
    mode = choose(argc == 1, 0, 1)
    put(w, 160, mode)
    envbase = choose(mode == 0, 16, 40)
    at = 32
    index = 0
    target = ENV_BYTES
    while index < count + argc:
        if at + 8 > length(s):
            return 0
        size = uint(s, at)
        maximum = choose(index < argc, 65536, 8192)
        if size > maximum or at + size + 9 > length(s) or byte(s, at + size + 8) != 0:
            return 0
        offset = 0
        while offset < size:
            if byte(s, at + 8 + offset) == 0:
                return 0
            offset = offset + 1
        if index < argc:
            put(w, ARGS + index * 16, at + 8)
            put(w, ARGS + index * 16 + 8, size)
        else:
            if target + size + 1 > ENV_END:
                return 0
            put(w, POINTERS + envbase + (index - argc) * 8, target)
            copy_input(s, w, target, at + 8, size)
            store(w, target + size, 0)
            target = target + size + 1
        at = at + size + 9
        index = index + 1
    if at != length(s):
        return 0
    put(w, POINTERS + envbase + count * 8, NONE)
    put(w, 144, count)
    put(w, 152, argc)
    if mode == 1:
        return launch_arguments(s, w)
    return 1

def launch_arguments(s:readbuf, w:mutbuf) -> u64:
    at = get(w, ARGS + 16)
    if get(w, ARGS + 24) != 15 or uint(s, at) != LAUNCH_MODE_FIRST or uint(s, at + 8) != LAUNCH_MODE_LAST:
        return 0
    at = get(w, ARGS + 32)
    if get(w, ARGS + 40) != 64:
        return 0
    index = 0
    while index < 64:
        point = byte(s, at + index)
        if (point < 48 or point > 57) and (point < 97 or point > 102):
            return 0
        store(w, HEADER + 32 + index, point)
        index = index + 1
    at = get(w, ARGS + 48)
    size = get(w, ARGS + 56)
    if size == 0 or size > 4096 or byte(s, at) != 47:
        return 0
    copy_input(s, w, NAME + 512, at, size)
    store(w, NAME + 512 + size, 0)
    at = get(w, ARGS + 64)
    size = get(w, ARGS + 72)
    if size == 0 or size > 8192:
        return 0
    copy_input(s, w, NAME + 8192, at, size)
    store(w, NAME + 8192 + size, 0)
    index = 5
    while index < get(w, 152):
        size = get(w, ARGS + index * 16 + 8)
        if size == 0 or size % 4 != 0 or size > 65536 or (index + 1 < get(w, 152) and size != 65536):
            return 0
        index = index + 1
    put(w, 168, 5)
    put(w, 176, 0)
    return 1

def launch_begin(o:mutbuf, w:mutbuf) -> u32:
    end = text_image(w, NAME)
    store(w, end, 0)
    return call(o, w, 30, 319, NAME, 3, 0, 0, 0, 0, 3)

def launch_capture(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase == 30:
        if failed(result) or result < 3:
            return 0
        put(w, 128, result)
        return call(o, w, 31, 91, result, 320, 0, 0, 0, 0, 0)
    if phase == 31:
        if result != 0:
            return 0
        return sha(o, w, 32, 0, 1)
    if phase == 32 or phase == 35:
        if result != 0:
            return 0
        return launch_next(s, o, w)
    if phase == 33:
        if result == NEG4:
            return launch_write(o, w)
        if failed(result) or result == 0 or result > get(w, 1072) - get(w, 1080):
            return 0
        put(w, 1080, get(w, 1080) + result)
        if get(w, 1080) < get(w, 1072):
            return launch_write(o, w)
        return sha(o, w, 35, 1, get(w, 1072) + 1)
    if phase == 36:
        if result != 32 or valid_image(w) == 0:
            return 0
        return call(o, w, 37, 72, get(w, 128), 1033, 15, 0, 0, 0, 0)
    if phase == 37:
        if result != 0:
            return 0
        return call(o, w, 38, 72, get(w, 128), 1034, 0, 0, 0, 0, 0)
    if phase == 38:
        if result != 15:
            return 0
        return call(o, w, 39, 436, 3, 4294967295, 4, 0, 0, 0, 0)
    if phase == 39:
        if result != 0:
            return 0
        end = text_launch(w, NAME)
        store(w, end, 0)
        store(w, NAME + 128, 0)
        end = text_systemd(w, NAME + 256)
        store(w, end, 0)
        put(w, POINTERS, NAME)
        put(w, POINTERS + 8, NAME + 512)
        put(w, POINTERS + 16, NAME + 8192)
        put(w, POINTERS + 24, NAME + 256)
        put(w, POINTERS + 32, NONE)
        put(o, 0, POINTERS)
        put(o, 8, get(w, 144) + 6)
        put(o, 16, RELOCATED)
        put(w, 0, 40)
        return 2
    if phase == 40:
        if result != 0:
            return 0
        return call(o, w, 41, 322, get(w, 128), NAME + 128, RELOCATED, RELOCATED + 40, 4096, 0, 252)
    return 0

def launch_next(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    index = get(w, 168)
    if index == get(w, 152):
        if get(w, 176) < 64:
            return 0
        return sha(o, w, 36, 2, 1)
    at = get(w, ARGS + index * 16)
    size = get(w, ARGS + index * 16 + 8)
    decoded = decode_base64(s, w, at, size, choose(index + 1 == get(w, 152), 1, 0))
    if decoded == NONE or decoded == 0 or get(w, 176) + decoded > 1048576:
        return 0
    before = get(w, 176)
    offset = 0
    while before + offset < 96 and offset < decoded:
        store(w, PREFIX + before + offset, byte(w, CHUNK + 1 + offset))
        offset = offset + 1
    put(w, 176, before + decoded)
    put(w, 168, index + 1)
    put(w, 1072, decoded)
    put(w, 1080, 0)
    return launch_write(o, w)

def launch_write(o:mutbuf, w:mutbuf) -> u32:
    return call(o, w, 33, 1, get(w, 128), CHUNK + 1 + get(w, 1080), get(w, 1072) - get(w, 1080), 0, 0, 0, 12)

def decode_base64(s:readbuf, w:mutbuf, at:u64, size:u64, final:u64) -> u64:
    index = 0
    output = 0
    while index < size:
        a = base64_value(byte(s, at + index))
        b = base64_value(byte(s, at + index + 1))
        c = byte(s, at + index + 2)
        d = byte(s, at + index + 3)
        if a == NONE or b == NONE:
            return NONE
        if c == 61:
            if d != 61 or final == 0 or index + 4 != size or b & 15 != 0:
                return NONE
            store(w, CHUNK + 1 + output, (a << 2) | (b >> 4))
            return output + 1
        c = base64_value(c)
        if c == NONE:
            return NONE
        store(w, CHUNK + 1 + output, (a << 2) | (b >> 4))
        store(w, CHUNK + 2 + output, ((b & 15) << 4) | (c >> 2))
        if d == 61:
            if final == 0 or index + 4 != size or c & 3 != 0:
                return NONE
            return output + 2
        d = base64_value(d)
        if d == NONE:
            return NONE
        store(w, CHUNK + 3 + output, ((c & 3) << 6) | d)
        output = output + 3
        index = index + 4
    return output

def base64_value(point:u64) -> u64:
    if point >= 65 and point <= 90:
        return point - 65
    if point >= 97 and point <= 122:
        return point - 71
    if point >= 48 and point <= 57:
        return point + 4
    if point == 43:
        return 62
    if point == 47:
        return 63
    return NONE

def copy_input(s:readbuf, w:mutbuf, target:u64, source:u64, size:u64) -> u64:
    index = 0
    while index < size:
        store(w, target + index, byte(s, source + index))
        index = index + 1
    return 0


def header(w:mutbuf) -> u64:
    if get(w, HEADER) != ENTRY_MAGIC:
        return 0
    operation = get(w, HEADER + 8)
    image_size = get(w, HEADER + 16)
    payload_size = get(w, HEADER + 24)
    if operation < 1 or operation > 3 or image_size < 64 or image_size > 4194304:
        return 0
    maximum = 545259584
    minimum = 64
    if operation == 2:
        maximum = 65536
        minimum = 80
    elif operation == 3:
        maximum = 2162688
        minimum = 80
    if payload_size < minimum or payload_size > maximum:
        return 0
    index = 0
    while index < 64:
        point = byte(w, HEADER + 32 + index)
        if (point < 48 or point > 57) and (point < 97 or point > 102):
            return 0
        index = index + 1
    return 1

def read_header(o:mutbuf, w:mutbuf) -> u32:
    return call(o, w, 1, 0, 0, HEADER + get(w, 64), 96 - get(w, 64), 0, 0, 0, 12)

def capture_begin(o:mutbuf, w:mutbuf) -> u32:
    index = get(w, 96)
    if index == 2:
        return call(o, w, 20, 0, 0, CHUNK + 1, 1, 0, 0, 0, 12)
    end = text_image(w, NAME)
    if index == 1:
        end = text_stdin(w, NAME)
    store(w, end, 0)
    put(w, 1040, 0)
    put(w, 1056, get(w, HEADER + 16 + index * 8))
    return call(o, w, 10, 319, NAME, 3, 0, 0, 0, 0, 3)

def capture(o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    index = get(w, 96)
    if phase == 10:
        if failed(result) or result < 3:
            return 0
        put(w, 128 + index * 8, result)
        return call(o, w, 11, 91, result, choose(index == 0, 320, 256), 0, 0, 0, 0, 0)
    if phase == 11:
        if failed(result):
            return 0
        if index == 0:
            return sha(o, w, 12, 0, 1)
        return read_chunk(o, w)
    if phase == 12 or phase == 15:
        if result != 0:
            return 0
        return read_chunk(o, w)
    if phase == 13:
        if result == NEG4:
            return read_chunk(o, w)
        before = get(w, 1040)
        if failed(result) or result == 0 or result > get(w, 1056) - before or result > 65536:
            return 0
        offset = 0
        while before + offset < 96 and offset < result:
            store(w, PREFIX + index * 128 + before + offset, byte(w, CHUNK + 1 + offset))
            offset = offset + 1
        put(w, 1040, before + result)
        put(w, 1072, result)
        put(w, 1080, 0)
        return write_chunk(o, w)
    if phase == 14:
        if result == NEG4:
            return write_chunk(o, w)
        if failed(result) or result == 0 or result > get(w, 1072) - get(w, 1080):
            return 0
        put(w, 1080, get(w, 1080) + result)
        if get(w, 1080) < get(w, 1072):
            return write_chunk(o, w)
        if index == 0:
            return sha(o, w, 15, 1, get(w, 1072) + 1)
        return read_chunk(o, w)
    if phase == 16:
        if result != 32 or valid_image(w) == 0:
            return 0
        return seal(o, w)
    if phase == 17:
        if failed(result):
            return 0
        return call(o, w, 18, 72, get(w, 128 + index * 8), 1034, 0, 0, 0, 0, 0)
    if phase == 18:
        if failed(result) or result & 15 != 15:
            return 0
        put(w, 96, index + 1)
        return capture_begin(o, w)
    return 0

def valid_image(w:mutbuf) -> u64:
    if get(w, PREFIX) & 72057594037927935 != ELF_WORD or getn(w, PREFIX + 16, 4) != 4063234:
        return 0
    offset = 0
    while offset < 32:
        point = byte(w, 4096 + offset)
        if byte(w, HEADER + 32 + offset * 2) != hex_digit(point >> 4) or byte(w, HEADER + 33 + offset * 2) != hex_digit(point & 15):
            return 0
        offset = offset + 1
    return 1

def read_chunk(o:mutbuf, w:mutbuf) -> u32:
    remaining = get(w, 1056) - get(w, 1040)
    if remaining == 0:
        if get(w, 96) == 0:
            return sha(o, w, 16, 2, 1)
        return seal(o, w)
    return call(o, w, 13, 0, 0, CHUNK + 1, choose(remaining > 65536, 65536, remaining), 0, 0, 0, 12)

def write_chunk(o:mutbuf, w:mutbuf) -> u32:
    return call(o, w, 14, 1, get(w, 128 + get(w, 96) * 8), CHUNK + 1 + get(w, 1080), get(w, 1072) - get(w, 1080), 0, 0, 0, 12)

def seal(o:mutbuf, w:mutbuf) -> u32:
    return call(o, w, 17, 72, get(w, 128 + get(w, 96) * 8), 1033, 15, 0, 0, 0, 0)

def payload_role(w:mutbuf) -> u64:
    at = PREFIX + 128
    operation = get(w, HEADER + 8)
    if operation == 1:
        return choose(get(w, at) == SUBMIT_MAGIC, 1, 0)
    if operation == 2:
        if get(w, at) != OBSERVATION_MAGIC:
            return 0
        mode = get(w, at + 8)
        flags = get(w, at + 72)
        return choose((mode == 0 and flags == 0) or (mode == 1 and flags == 63), 1, 0)
    return choose(get(w, at) == CANCEL_MAGIC, 1, 0)

def sha(o:mutbuf, w:mutbuf, phase:u64, command:u64, size:u64) -> u32:
    put(w, 0, phase)
    store(w, CHUNK, command)
    put(o, 0, size)
    return 3

def hex_digit(value:u64) -> u64:
    return choose(value < 10, 48 + value, 87 + value)
def call(o:mutbuf, w:mutbuf, phase:u64, number:u64, a:u64, b:u64, c:u64, d:u64, e:u64, f:u64, pointers:u64) -> u32:
    put(w, 0, phase)
    put(o, 0, number)
    put(o, 8, a)
    put(o, 16, b)
    put(o, 24, c)
    put(o, 32, d)
    put(o, 40, e)
    put(o, 48, f)
    put(o, 56, pointers)
    return 1
def failed(value:u64) -> bool:
    return value >> 63 != 0
def uint(s:readbuf, at:u64) -> u64:
    index = 0
    value = 0
    while index < 8:
        value = value | (byte(s, at + index) << (8 * index))
        index = index + 1
    return value
def get(w:mutbuf, at:u64) -> u64:
    return getn(w, at, 8)
def getn(w:mutbuf, at:u64, count:u64) -> u64:
    index = 0
    value = 0
    while index < count:
        value = value | (byte(w, at + index) << (8 * index))
        index = index + 1
    return value
def put(w:mutbuf, at:u64, value:u64) -> u64:
    index = 0
    while index < 8:
        store(w, at + index, (value >> (8 * index)) & 255)
        index = index + 1
    return 0'''

def policy_source():
    source = POLICY
    texts = {'submit':'hia-job-submit','observation':'hia-job-observation','cancel':'hia-job-cancel',
             'image':'hia-job-entry-image','stdin':'hia-job-entry-stdin',
             'launch':'hia-job-launch','systemd':'systemd'}
    for name, value in texts.items():
        source += f'\ndef text_{name}(w:mutbuf, at:u64) -> u64:\n'
        for i, point in enumerate(value.encode()):
            source += f'    store(w, at + {i}, {point})\n'
        source += f'    return at + {len(value)}\n'
    values = dict(STATE_BYTES=STATE_BYTES, NONE=(1 << 64) - 1, NEG4=(1 << 64) - 4,
                  ARG_MAGIC=int.from_bytes(b'HIAARG02','little'),
                  ENTRY_MAGIC=int.from_bytes(b'HIAJEX01','little'),
                  SUBMIT_MAGIC=int.from_bytes(b'HIAJSB01','little'),
                  OBSERVATION_MAGIC=int.from_bytes(b'HIAJOBQ1','little'),
                  CANCEL_MAGIC=int.from_bytes(b'HIAJCQ02','little'),
                  ELF_WORD=int.from_bytes(b'\x7fELF\x02\x01\x01','little'),
                  LAUNCH_MODE_FIRST=int.from_bytes(b'--launch','little'),
                  LAUNCH_MODE_LAST=int.from_bytes(b'-base64\0','little'),
                  ARGS=147456, HEADER=8192, CHUNK=65536, PREFIX=16384, NAME=32768,
                  POINTERS=24576, RELOCATED=26624, ENV_BYTES=262144, ENV_END=1310720)
    for name in sorted(values,key=len,reverse=True):
        source = re.sub(r'\b'+re.escape(name)+r'\b',str(values[name]),source)
    return source

def template():
    adapter = ROOT/'tools/hia_job_entry_syscalls.S'
    with tempfile.TemporaryDirectory(prefix='hia-job-entry-author-') as tmp:
        obj, raw = Path(tmp)/'adapter.o', Path(tmp)/'adapter.bin'
        subprocess.run(['as','--64',str(adapter),'-o',str(obj)],check=True,capture_output=True)
        subprocess.run(['objcopy','-O','binary','-j','.text',str(obj),str(raw)],check=True,capture_output=True)
        symbols = {name:int(address,16) for address,_,name in
                   (line.split() for line in subprocess.check_output(['nm','-n',str(obj)],text=True).splitlines())}
        if symbols['_start'] != 0 or 'R_X86_64' in subprocess.check_output(['objdump','-r',str(obj)],text=True):
            raise ValueError('entry adapter has unresolved relocations')
        code=raw.read_bytes()
    header=(b'\x7fELF\x02\x01\x01'+bytes(9)
            +struct.pack('<HHIQQQIHHHHHH',2,62,1,0x4000b0,64,0,0,64,56,2,0,0,0)
            +struct.pack('<IIQQQQQQ',1,5,0,0x400000,0x400000,0,0,4096)
            +struct.pack('<IIQQQQQQ',0x6474e551,6,0,0,0,0,0,16))
    return header+code,{name:176+symbols[name] for name in ('job_entry_policy_hole','job_entry_sha_hole')}

def packer_source():
    prefix,holes=template()
    source=f"""def pack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 26 or uint(s, 0, 8) != {PACKER_MAGIC}:
        return 4294967295
    policy = uint(s, 8, 8)
    sha = uint(s, 16, 8)
    if policy == 0 or sha == 0 or policy > 1048576 or sha > 1048576:
        return 4294967295
    if length(s) != 24 + policy + sha:
        return 4294967295
    size = {len(prefix)} + policy + sha
    if size > 2097152 or length(o) < size:
        return 4294967294
"""
    for at in range(0,len(prefix),8):
        chunk=prefix[at:at+8]
        source+=f'    write(o, {at}, {int.from_bytes(chunk,"little")}, {len(chunk)})\n'
    source+='    write(o, 96, size, 8)\n    write(o, 104, size, 8)\n'
    for name,at in holes.items():
        target=str(len(prefix)) + (' + policy' if name.endswith('sha_hole') else '')
        source+=f'    write(o, {at}, {target} - {at+4}, 4)\n'
    source+=f'    copy_bytes(s, o, 24, {len(prefix)}, policy + sha)\n    return size\n'
    return source+LINK_SOURCE[LINK_SOURCE.index('\ndef uint('):]

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--check',action='store_true');args=parser.parse_args()
    for module,source in [('job_entry',policy_source()),('job_entry_packer',packer_source())]:
        path=ROOT/'examples/hia_bootstrap'/(module+'.hepta')
        rendered=render_assembly(document(source,module))
        if args.check:
            if path.read_text()!=rendered:raise SystemExit('generated source differs: '+str(path))
        else:path.write_text(rendered)
        print(module,len(rendered),flush=True)
if __name__=='__main__':main()
