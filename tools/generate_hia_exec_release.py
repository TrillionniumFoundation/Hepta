"""Author the explicit native executable release builder and its ELF packer.

This is authoring-time code only. Every runtime command, source-digest check,
compiler-result classification, ELF/profile check, HIAREL01 byte/mode decision,
SHA stream sequence and output receipt is executed by the resulting HIA policy.
The literal assembly file is fixed Linux syscall and three-buffer ABI transport.
"""
from __future__ import annotations
from pathlib import Path
import struct
import subprocess
import tempfile

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document

ROOT = Path(__file__).resolve().parents[1]
MAGIC = int.from_bytes(b'HIAERB01', 'little')
BUNDLE_MAGIC = int.from_bytes(b'HIAREL01', 'little')
LIMIT = 1 << 20
WIRE_LIMIT = 8 << 20
OUTPUT_BYTES = 16 << 20
POLICY_BYTES = 4096
ASSEMBLY = 0x1000
CODE = 0x101000
SHA_INPUT = 0x202000
SHA_OUTPUT = 0x213000
PACKAGE = 0x220000
PACKAGE_CAPACITY = (9 << 20) + 4096
SOURCE_BYTES = WIRE_LIMIT + 4096
OUTPUT_OFFSET = SOURCE_BYTES
POLICY_OFFSET = OUTPUT_OFFSET + OUTPUT_BYTES
FRONTEND_OFFSET = POLICY_OFFSET + POLICY_BYTES
FRONTEND_BYTES = (64 << 20) + 4096
SHA_WORK_OFFSET = FRONTEND_OFFSET + FRONTEND_BYTES
SHA_WORK_BYTES = 8192
MAPPING_BYTES = SHA_WORK_OFFSET + SHA_WORK_BYTES

# State offsets and action numbers are a private fixed ABI, not Python providers.
# The adapter reports the exact captured action/sequence and full u64 return.
# The policy is the only writer of phase, issued action, sequence and byte cursors.
POLICY_SOURCE = '''def policy(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    decision = policy_step(s, o, w)
    s = decision
    if decision == 258 or decision == 259 or decision == 260 or decision == 261 or decision == 262 or decision == 272 or decision == 320:
        return rejected(o, w, decision - 256)
    return decision

def start(w:mutbuf) -> u32:
    if get(w, 56) != 0 or get(w, 64) != 0 or get(w, 72) != 0:
        return 272
    put(w, 80, 0)
    put(w, 88, 0)
    put(w, 96, 0)
    put(w, 104, 0)
    put(w, 112, 0)
    put(w, 176, 0)
    put(w, 192, 0)
    put(w, 200, 0)
    put(w, 224, 0)
    put(w, 768, 2)
    put(w, 776, 1048576)
    put(w, 784, 128)
    put(w, 1024, 1)
    put(w, 1032, 0)
    put(w, 1040, 0)
    put(w, 1048, 0)
    return issue(w, 1, 9)

def arguments(w:mutbuf) -> u32:
    if get(w, 16) != 3 or get(w, 32) != 64:
        return 320
    syntax = 0
    if get(w, 24) == 8 and get(w, 256) == ASSEMBLY_WORD:
        syntax = 1
    if get(w, 24) == 9 and get(w, 256) == JSON_WORD and byte(w, 264) == 110:
        syntax = 2
    if syntax == 0:
        return 320
    i = 0
    while i < 64:
        if unhex(byte(w, 320 + i)) > 15:
            return 320
        i = i + 1
    put(w, 112, syntax)
    return issue(w, 2, 10)

def issue(w:mutbuf, phase:u64, action:u64) -> u32:
    sequence = get(w, 72)
    if sequence == 18446744073709551615:
        return 4294967295
    put(w, 56, phase)
    put(w, 64, action)
    put(w, 72, sequence + 1)
    return action

def read_request(w:mutbuf) -> u32:
    limit = 8388608
    if get(w, 112) == 1:
        limit = 1048576
    size = get(w, 80)
    if size > limit:
        return 4294967295
    put(w, 152, limit + 1 - size)
    put(w, 160, size)
    return issue(w, 3, 1)

def read_return(s:readbuf, w:mutbuf, result:u64) -> u32:
    if result == 18446744073709551612:
        return read_request(w)
    if result >= 18446744073709547521:
        return 260
    if result > get(w, 152) or length(s) != get(w, 80):
        return 272
    s = result
    if result == 0:
        if get(w, 80) == 0:
            return 258
        return issue(w, 4, 8)
    size = get(w, 80) + result
    limit = 8388608
    if get(w, 112) == 1:
        limit = 1048576
    if size > limit:
        return 259
    put(w, 80, size)
    return read_request(w)

def begin_hash(o:mutbuf, w:mutbuf, target:u64) -> u32:
    end = get(w, 80)
    if target == 2:
        end = get(w, 96)
    if target == 3:
        end = get(w, 104)
    if target < 1 or target > 3 or end == 0:
        return 272
    put(w, 120, target)
    put(w, 128, 0)
    put(w, 136, end)
    put(w, 144, 0)
    store(o, 2105344, 0)
    put(w, 152, 1)
    put(w, 160, 2105344)
    return issue(w, 5, 2)

def hash_return(s:readbuf, o:mutbuf, w:mutbuf, result:u64) -> u32:
    operation = get(w, 144)
    target = get(w, 120)
    at = get(w, 128)
    end = get(w, 136)
    if target < 1 or target > 3 or at > end:
        return 272
    if operation == 2:
        return hash_completed(s, o, w, result, target, at, end)
    return hash_progress(s, o, w, result, operation, target, at, end)

def compile_request(w:mutbuf, region:u64) -> u32:
    put(w, 152, get(w, 88))
    put(w, 160, 0)
    put(w, 168, region)
    return issue(w, 7, 4)

def frontend_return(w:mutbuf, result:u64) -> u32:
    if result == 4294967294 or result == 4294967290:
        return 259
    if result == 4294967293:
        return 260
    if result == 0 or result > 1048576:
        return 258
    put(w, 88, result)
    return compile_request(w, 2)

def compiler_return(o:mutbuf, w:mutbuf, result:u64) -> u32:
    if result == 4294967294:
        return 259
    if result == 0 or result > 1048576:
        return 258
    if executable(o, 1052672, result) == 0:
        return 262
    put(w, 96, result)
    return begin_hash(o, w, 2)

def executable(o:mutbuf, at:u64, size:u64) -> u64:
    if size <= 176 or at > length(o) or size > length(o) - at:
        return 0
    word = 0
    while word < 22:
        if get(o, at + word * 8) != executable_word(word, size):
            return 0
        word = word + 1
    return 1

def package(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    source = length(s)
    image = get(w, 96)
    size = 91 + source + image
    if source == 0 or source != get(w, 80) or source > 8388608:
        return 0
    if image <= 176 or image > 1048576 or size > 9441280:
        return 0
    if length(o) < 2228224 + size:
        return 0
    at = 2228224
    put(o, at, BUNDLE_WORD)
    put(o, at + 8, 2)
    put(o, at + 16, 0)
    put(o, at + 24, 12)
    put(o, at + 32, 256)
    put(o, at + 40, source)
    write(o, at + 48, SOURCE_NAME_A, 8)
    write(o, at + 56, SOURCE_NAME_B, 4)
    copy_source(s, o, 0, at + 60, source)
    at = at + 60 + source
    put(o, at, 7)
    put(o, at + 8, 320)
    put(o, at + 16, image)
    write(o, at + 24, PROGRAM_NAME, 7)
    copy_output(o, 1052672, at + 31, image)
    put(w, 104, size)
    return 1

def package_write_return(w:mutbuf, result:u64) -> u32:
    if result == 18446744073709551612:
        return issue(w, 9, 5)
    if result == 0 or result > get(w, 152):
        return 260
    at = get(w, 192) + result
    if at > get(w, 104):
        return 272
    put(w, 192, at)
    if at == get(w, 104):
        put(w, 224, 0)
        put(w, 152, get(w, 184))
        put(w, 160, 0)
        return issue(w, 10, 6)
    put(w, 152, get(w, 104) - at)
    put(w, 160, 2228224 + at)
    return issue(w, 9, 5)

def diagnostic_write_return(w:mutbuf, result:u64) -> u32:
    if result == 18446744073709551612:
        return issue(w, 10, 6)
    if result == 0 or result > get(w, 152):
        put(w, 176, 4)
        return issue(w, 11, 7)
    at = get(w, 224) + result
    if at > get(w, 184):
        put(w, 176, 16)
        return issue(w, 11, 7)
    put(w, 224, at)
    if at == get(w, 184):
        return issue(w, 11, 7)
    put(w, 152, get(w, 184) - at)
    put(w, 160, at)
    return issue(w, 10, 6)

def rejected(o:mutbuf, w:mutbuf, code:u64) -> u32:
    put(w, 176, code)
    put(w, 224, 0)
    at = 0
    REJECT_PREFIX
    at = decimal(o, at, code)
    REJECT_MIDDLE
    at = decimal(o, at, get(w, 192))
    REJECT_SUFFIX
    put(w, 184, at)
    put(w, 152, at)
    put(w, 160, 0)
    return issue(w, 10, 6)

def success_receipt(o:mutbuf, w:mutbuf) -> u64:
    at = 0
    SUCCESS_PREFIX
    if get(w, 112) == 1:
        SYNTAX_ASSEMBLY
    else:
        SYNTAX_JSON
    SOURCE_HASH_PREFIX
    at = digest(o, w, at, 512)
    IMAGE_HASH_PREFIX
    at = digest(o, w, at, 544)
    PACKAGE_HASH_PREFIX
    at = digest(o, w, at, 576)
    SOURCE_BYTES_PREFIX
    at = decimal(o, at, get(w, 80))
    IMAGE_BYTES_PREFIX
    at = decimal(o, at, get(w, 96))
    PACKAGE_BYTES_PREFIX
    at = decimal(o, at, get(w, 104))
    SUCCESS_SUFFIX
    return at

def digest(o:mutbuf, w:mutbuf, at:u64, offset:u64) -> u64:
    i = 0
    while i < 32:
        value = byte(w, offset + i)
        store(o, at + i * 2, hex(value >> 4))
        store(o, at + i * 2 + 1, hex(value & 15))
        i = i + 1
    return at + 64

def decimal(o:mutbuf, at:u64, value:u64) -> u64:
    divisor = 10000000000000000000
    started = 0
    while divisor > 0:
        digit = 0
        while value >= divisor:
            value = value - divisor
            digit = digit + 1
        if digit != 0 or started != 0 or divisor == 1:
            store(o, at, digit + 48)
            at = at + 1
            started = 1
        divisor = divide10(divisor)
    return at

def divide10(value:u64) -> u64:
    quotient = 0
    remainder = 0
    bit = 64
    while bit > 0:
        bit = bit - 1
        remainder = remainder * 2 + ((value >> bit) & 1)
        if remainder >= 10:
            remainder = remainder - 10
            quotient = quotient | (1 << bit)
    return quotient

def hex(value:u64) -> u64:
    if value < 10:
        return value + 48
    return value + 87

def unhex(value:u64) -> u64:
    if value >= 48 and value <= 57:
        return value - 48
    if value >= 97 and value <= 102:
        return value - 87
    return 16

def get(w:mutbuf, at:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | byte(w, at + i) << (i * 8)
        i = i + 1
    return value

def put(w:mutbuf, at:u64, value:u64) -> u64:
    return write(w, at, value, 8)

def write(w:mutbuf, at:u64, value:u64, count:u64) -> u64:
    i = 0
    while i < count:
        store(w, at + i, value >> (i * 8) & 255)
        i = i + 1
    return 0

def append(o:mutbuf, at:u64, value:u64, count:u64) -> u64:
    write(o, at, value, count)
    return at + count

def copy_source(s:readbuf, o:mutbuf, source:u64, target:u64, count:u64) -> u64:
    i = 0
    while i < count:
        store(o, target + i, byte(s, source + i))
        i = i + 1
    return 0

def copy_output(o:mutbuf, source:u64, target:u64, count:u64) -> u64:
    i = 0
    while i < count:
        store(o, target + i, byte(o, source + i))
        i = i + 1
    return 0
# Private HIA tail continuations keep the original reads, writes, and first
# refusal order while avoiding live buffer values across unrelated SSA arms.
# They are appended so every original function keeps its numeric identity.
def return_receipt_valid(w:mutbuf, event:u64) -> u64:
    if event == 2:
        return 0
    if event != 1 or get(w, 40) != get(w, 64) or get(w, 48) != get(w, 72):
        return 0
    if get(w, 72) == 0 or get(w, 64) == 7:
        return 0
    return 1

def hash_completed(s:readbuf, o:mutbuf, w:mutbuf, result:u64, target:u64, at:u64, end:u64) -> u32:
    if result != 32 or at != end:
        return 260
    copy_digest(o, w, target)
    if target == 1:
        return source_hash_return(s, w)
    if target == 2:
        if package(s, o, w) == 0:
            return 272
        return begin_hash(o, w, 3)
    put(w, 184, success_receipt(o, w))
    put(w, 176, 0)
    return issue(w, 8, 11)

def copy_digest(o:mutbuf, w:mutbuf, target:u64) -> u64:
    i = 0
    while i < 32:
        store(w, 512 + (target - 1) * 32 + i, byte(o, 2174976 + i))
        i = i + 1
    return 0

def source_hash_return(s:readbuf, w:mutbuf) -> u32:
    if source_digest_matches(w) == 0:
        return 261
    if length(s) != get(w, 80):
        return 272
    s = 0
    if get(w, 112) == 1:
        put(w, 88, get(w, 80))
        return compile_request(w, 1)
    if get(w, 112) != 2 or get(w, 768) != 2 or get(w, 776) != 1048576 or get(w, 784) != 128:
        return 272
    put(w, 152, get(w, 80))
    put(w, 160, 0)
    return issue(w, 6, 3)

def hash_progress(s:readbuf, o:mutbuf, w:mutbuf, result:u64, operation:u64, target:u64, at:u64, end:u64) -> u32:
    if result != 0 or operation > 1:
        return 260
    if operation == 1:
        count = get(w, 152)
        if count <= 1 or count > 65537 or count - 1 > end - at:
            return 272
        at = at + count - 1
        put(w, 128, at)
    if at == end:
        store(o, 2105344, 2)
        put(w, 144, 2)
        put(w, 152, 1)
        return issue(w, 5, 2)
    return hash_chunk(s, o, w, target, at, end)

def hash_chunk(s:readbuf, o:mutbuf, w:mutbuf, target:u64, at:u64, end:u64) -> u32:
    count = end - at
    if count > 65536:
        count = 65536
    if target == 1:
        if end != length(s) or end != get(w, 80):
            return 272
        copy_source(s, o, at, 2105345, count)
        s = at
    else:
        s = at
        base = 1052672
        if target == 3:
            base = 2228224
        if base > length(o) or end > length(o) - base:
            return 272
        copy_output(o, base + at, 2105345, count)
    store(o, 2105344, 1)
    put(w, 144, 1)
    put(w, 152, count + 1)
    return issue(w, 5, 2)

# The same 22 little-endian words, in the same first-mismatch read order.
# This scalar function has no buffer/provider/state access.
def executable_word(word:u64, size:u64) -> u64:
    if word == 0:
        return ELF_MAGIC
    if word == 2:
        return ELF_TYPES
    if word == 3:
        return 4194480
    if word == 4:
        return 64
    if word == 6:
        return ELF_SIZES
    if word == 7:
        return 2
    if word == 8:
        return ELF_LOAD
    if word == 10 or word == 11:
        return 4194304
    if word == 12 or word == 13:
        return size
    if word == 14:
        return 4096
    if word == 15:
        return ELF_STACK
    if word == 21:
        return 16
    return 0

# A rejection is a private scalar tail result until the public f0 boundary.
# Actions 1..11 and UINT32_MAX are disjoint from the seven explicit tags.
# No policy-tail function resumes after returning one of these tags; f0 invokes
# the original rejected formatter exactly once, with the original buffers/code.
# Source bindings rebound to scalars below are dead borrowed views, not writes
# or loan.end operations. All original I/O and first-refusal order is retained.
def policy_step(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    if length(w) < 4096 or length(o) < 4096:
        return 4294967295
    event = get(w, 0)
    if event == 0:
        return start(w)
    if return_receipt_valid(w, event) == 0:
        return 272
    phase = get(w, 56)
    result = get(w, 8)
    if phase == 1:
        if result != 0:
            return 260
        return arguments(w)
    if phase == 2:
        if result >= 18446744073709547521:
            return 260
        if length(o) != 16777216 or length(s) != 0:
            return 272
        put(w, 200, 1)
        return read_request(w)
    if phase == 10:
        return diagnostic_write_return(w, result)
    if get(w, 200) != 1 or length(o) != 16777216:
        return 272
    if phase == 3:
        return read_return(s, w, result)
    if phase == 4:
        if result != 0:
            return 260
        return begin_hash(o, w, 1)
    if phase == 5:
        return hash_return(s, o, w, result)
    s = result
    if phase == 6:
        return frontend_return(w, result)
    if phase == 7:
        return compiler_return(o, w, result)
    o = result
    if phase == 8:
        if result != 0:
            return 260
        put(w, 192, 0)
        put(w, 152, get(w, 104))
        put(w, 160, 2228224)
        return issue(w, 9, 5)
    if phase == 9:
        return package_write_return(w, result)
    return 272

def source_digest_matches(w:mutbuf) -> u64:
    i = 0
    while i < 32:
        wanted = unhex(byte(w, 320 + i * 2)) * 16 + unhex(byte(w, 321 + i * 2))
        if byte(w, 512 + i) != wanted:
            return 0
        i = i + 1
    return 1

'''


def literal(raw, indent=4):
    lines = []
    for offset in range(0, len(raw), 8):
        chunk = raw[offset:offset + 8]
        lines.append(' ' * indent + 'at = append(o, at, ' +
                     str(int.from_bytes(chunk, 'little')) + ', ' + str(len(chunk)) + ')')
    return '\n'.join(lines)


def policy_source():
    source = POLICY_SOURCE
    constants = {
        'ASSEMBLY_WORD': int.from_bytes(b'assembly', 'little'),
        'JSON_WORD': int.from_bytes(b'core-jso', 'little'),
        'ELF_MAGIC': int.from_bytes(b'\x7fELF\x02\x01\x01\x00', 'little'),
        'ELF_TYPES': 2 | (62 << 16) | (1 << 32),
        'ELF_SIZES': (64 << 32) | (56 << 48),
        'ELF_LOAD': 1 | (5 << 32),
        'ELF_STACK': 0x6474e551 | (6 << 32),
        'BUNDLE_WORD': BUNDLE_MAGIC,
        'SOURCE_NAME_A': int.from_bytes(b'source.h', 'little'),
        'SOURCE_NAME_B': int.from_bytes(b'epta', 'little'),
        'PROGRAM_NAME': int.from_bytes(b'program', 'little'),
    }
    for name, value in constants.items():
        source = source.replace(name, str(value))
    parts = {
        'REJECT_PREFIX': b'{"schema":"hepta.hia.exec-release.v1","status":"rejected","code":',
        'REJECT_MIDDLE': b',"observed_stdout_bytes":',
        'REJECT_SUFFIX': b',"installed":false,"published":false}\n',
        'SUCCESS_PREFIX': b'{"schema":"hepta.hia.exec-release.v1","status":"PACKAGE_BUILT","syntax":"',
        'SYNTAX_ASSEMBLY': b'assembly',
        'SYNTAX_JSON': b'core-json',
        'SOURCE_HASH_PREFIX': b'","profile":"selfhost-exec-linux-x86_64.v1","source_sha256":"',
        'IMAGE_HASH_PREFIX': b'","image_sha256":"',
        'PACKAGE_HASH_PREFIX': b'","package_sha256":"',
        'SOURCE_BYTES_PREFIX': b'","source_bytes":',
        'IMAGE_BYTES_PREFIX': b',"image_bytes":',
        'PACKAGE_BYTES_PREFIX': b',"package_bytes":',
        'SUCCESS_SUFFIX': b',"members":2,"runtime_python":false,"generated_program_executed":false,"installed":false,"published":false}\n',
    }
    for name, raw in parts.items():
        indent = 8 if name.startswith('SYNTAX_') else 4
        source = source.replace(' ' * indent + name, literal(raw, indent))
    return source


def template():
    with tempfile.TemporaryDirectory(prefix='hia-exec-release-template-') as folder:
        obj, binary = Path(folder) / 'adapter.o', Path(folder) / 'adapter.bin'
        subprocess.run(['as', '--64', str(ROOT / 'tools/hia_exec_release_syscalls.S'), '-o', str(obj)],
                       check=True, capture_output=True)
        subprocess.run(['objcopy', '-O', 'binary', '-j', '.text', str(obj), str(binary)],
                       check=True, capture_output=True)
        symbols = {}
        for line in subprocess.check_output(['nm', '-n', str(obj)], text=True).splitlines():
            address, kind, name = line.split()
            symbols[name] = int(address, 16)
        if symbols['_start'] != 0 or 'R_X86_64' in subprocess.check_output(['objdump', '-r', str(obj)], text=True):
            raise ValueError('exec-release transport has unresolved relocations or a displaced entry')
        code = binary.read_bytes()
    header = (b'\x7fELF\x02\x01\x01' + bytes(9)
        + struct.pack('<HHIQQQIHHHHHH', 2, 62, 1, 0x4000b0, 64, 0, 0, 64, 56, 2, 0, 0, 0)
        + struct.pack('<IIQQQQQQ', 1, 5, 0, 0x400000, 0x400000, 0, 0, 4096)
        + struct.pack('<IIQQQQQQ', 0x6474e551, 6, 0, 0, 0, 0, 0, 16))
    return header + code, {name: 176 + symbols[name] for name in
                          ('policy_hole', 'frontend_hole', 'compiler_hole', 'sha_hole')}


def packer_source():
    from tools.generate_hia_native_filter import LINK_SOURCE
    prefix, holes = template()
    source = f'''def pack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 44 or length(s) > 1048576:
        return 4294967295
    if uint(s, 0, 8) != {MAGIC}:
        return 4294967295
    policy = uint(s, 8, 8)
    frontend = uint(s, 16, 8)
    compiler = uint(s, 24, 8)
    sha = uint(s, 32, 8)
    if policy == 0 or frontend == 0 or compiler == 0 or sha == 0:
        return 4294967295
    if policy > 1048576 or frontend > 1048576 or compiler > 1048576 or sha > 1048576:
        return 4294967295
    total = policy + frontend + compiler + sha
    if length(s) != 40 + total:
        return 4294967295
    size = {len(prefix)} + total
    if size > 1048576 or length(o) < size:
        return 4294967294
'''
    functions = []
    for index, start in enumerate(range(0, len(prefix), 2048)):
        source += f'    template_{index}(o)\n'
        body = f'\ndef template_{index}(o:mutbuf) -> u64:\n'
        for at in range(start, min(start + 2048, len(prefix)), 8):
            chunk = prefix[at:at + 8]
            body += f'    write(o, {at}, {int.from_bytes(chunk, "little")}, {len(chunk)})\n'
        functions.append(body + '    return 0\n')
    source += '    write(o, 96, size, 8)\n    write(o, 104, size, 8)\n'
    targets = {'policy_hole': '0', 'frontend_hole': 'policy',
               'compiler_hole': 'policy + frontend', 'sha_hole': 'policy + frontend + compiler'}
    for name, offset in holes.items():
        source += f'    write(o, {offset}, {len(prefix) - offset - 4} + {targets[name]}, 4)\n'
    source += f'    copy_bytes(s, o, 40, {len(prefix)}, total)\n    return size\n'
    return source + ''.join(functions) + LINK_SOURCE[LINK_SOURCE.index('\ndef uint('):]


def main():
    for name, source in (('exec_release_policy', policy_source()), ('exec_release_packer', packer_source())):
        path = ROOT / 'examples/hia_bootstrap' / (name + '.hepta')
        text = render_assembly(document(source, name))
        path.write_text(text)
        print(path.name, path.stat().st_size)


if __name__ == '__main__':
    main()
