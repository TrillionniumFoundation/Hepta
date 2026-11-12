"""Author the HIA release-package policy and its syscall-only ELF packer.

The installer publishes one operator-authorized, content-addressed directory.
It does not switch a worker, own request journals or qualify the installed code.
"""
from __future__ import annotations

import hashlib

import struct
import subprocess
import tempfile
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document

ROOT = Path(__file__).resolve().parents[1]
MAGIC = int.from_bytes(b'HIAINS01', 'little')
BUNDLE_MAGIC = int.from_bytes(b'HIAREL01', 'little')
WIRE_LIMIT = 64 << 20
WORK_BYTES = 65536

POLICY_SOURCE = '''def policy(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < 65536:
        return 16
    phase = get(w, 0)
    if phase == 0:
        return arguments(s, o, w)
    if phase == 1:
        if length(s) != 32:
            return 16
        i = 0
        while i < 32:
            v = unhex(byte(w, 768 + i * 2)) * 16 + unhex(byte(w, 769 + i * 2))
            if byte(s, i) != v:
                return 11
            i = i + 1
        return 0
    if phase == 2:
        return package(s, w)
    if phase == 4:
        return select(s, w)
    if phase == 5:
        if directory(w, 416) == 0:
            return 10
        if get(w, 440) & 18 != 0:
            return 10
        return 0
    if phase == 6:
        if directory(w, 416) == 0:
            return 10
        mode = 16704
        if get(w, 8) == 1:
            mode = 16832
        actual = get(w, 440) & 4294967295
        if actual != mode:
            if get(w, 8) != 1 or actual != 17856:
                return 10
        copy(w, 416, 272, 144)
        return 0
    if phase == 7:
        if directory(w, 560) == 0:
            return 10
        if get(w, 560) != get(w, 272) or get(w, 568) != get(w, 280):
            return 12
        if get(w, 584) & 4294967295 != 16704:
            return 10
        return 0
    if phase == 8 or phase == 9:
        return file_stat(w, phase)
    if phase == 10:
        offset = get(w, 72)
        count = get(w, 80)
        total = get(w, 48)
        start = get(w, 40)
        if offset > total or count > total - offset or count > length(o):
            return 11
        if start > length(s) or total > length(s) - start:
            return 16
        i = 0
        while i < count:
            if byte(s, start + offset + i) != byte(o, i):
                return 11
            i = i + 1
        return 0
    if phase == 11:
        return entries(s, o, w)
    if phase == 12:
        if get(w, 112) != get(w, 24):
            return 11
        return 0
    if phase == 13:
        write(w, 848, 7022071303105570862, 8)
        write(w, 856, 2975591, 3)
        i = 0
        while i < 16:
            v = byte(w, 912 + i)
            store(w, 859 + i * 2, hex(v >> 4))
            store(w, 860 + i * 2, hex(v & 15))
            i = i + 1
        store(w, 891, 0)
        return 0
    if phase == 14:
        return receipt(o, w)
    if phase == 15:
        put(w, 112, 0)
        i = 0
        while i < get(w, 24):
            at = 4096 + i * 96 + 88
            put(w, at, get(w, at) & 1)
            i = i + 1
        return 0
    if phase == 17:
        if directory(w, 416) == 0 or get(w, 440) & 4294967295 != 16704:
            return 10
        if get(w, 416) != get(w, 272) or get(w, 424) != get(w, 280):
            return 12
        return 0
    return 16

def arguments(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 24 or length(o) < 8192:
        return 16
    a = uint(s, 0, 8)
    b = uint(s, 8, 8)
    c = uint(s, 16, 8)
    if a > 7 or b == 0 or b > 4095 or c != 64 or length(s) != 24 + a + b + c:
        return 16
    op = 0
    if a == 7 and uint(s, 24, 7) == 30526565255720553:
        op = 1
    if a == 6 and uint(s, 24, 6) == 133476589827702:
        op = 2
    if op == 0:
        return 16
    root = 24 + a
    if byte(s, root) != 47:
        return 16
    store(o, 0, 0)
    i = 1
    begin = 1
    while i < b:
        v = byte(s, root + i)
        if v == 0:
            return 16
        if v == 47:
            if component(s, root + begin, i - begin) == 0:
                return 16
            store(o, i, 0)
            begin = i + 1
        else:
            store(o, i, v)
        i = i + 1
    if b > 1:
        if component(s, root + begin, b - begin) == 0:
            return 16
    store(o, b, 0)
    i = 0
    while i < 64:
        v = byte(s, root + b + i)
        if unhex(v) > 15:
            return 16
        store(w, 768 + i, v)
        i = i + 1
    store(w, 832, 0)
    put(w, 8, op)
    put(w, 88, b)
    return op

def component(s:readbuf, at:u64, size:u64) -> u64:
    if size == 0 or size > 255:
        return 0
    if size == 1 and byte(s, at) == 46:
        return 0
    if size == 2 and byte(s, at) == 46 and byte(s, at + 1) == 46:
        return 0
    return 1

def package(s:readbuf, w:mutbuf) -> u32:
    if length(s) < 24 or length(s) > 67108864:
        return 16
    if uint(s, 0, 8) != 3544407730921556296 or uint(s, 16, 8) != 0:
        return 16
    count = uint(s, 8, 8)
    if count == 0 or count > 256:
        return 16
    at = 24
    i = 0
    while i < count:
        if at > length(s) or length(s) - at < 24:
            return 16
        name = uint(s, at, 8)
        mode = uint(s, at + 8, 8)
        size = uint(s, at + 16, 8)
        if name == 0 or name > 127 or mode != 256 and mode != 320:
            return 16
        at = at + 24
        if name > length(s) - at:
            return 16
        j = 0
        while j < name:
            v = byte(s, at + j)
            if alnum(v) == 0:
                if j == 0 or v != 46 and v != 45 and v != 95:
                    return 16
            j = j + 1
        j = 0
        while j < i:
            row = 4096 + j * 96
            if get(w, row + 8) == name:
                k = 0
                same = 1
                while k < name:
                    if byte(s, at + k) != byte(s, get(w, row) + k):
                        same = 0
                    k = k + 1
                if same == 1:
                    return 16
            j = j + 1
        row = 4096 + i * 96
        put(w, row, at)
        put(w, row + 8, name)
        at = at + name
        if size > length(s) - at:
            return 16
        put(w, row + 16, at)
        put(w, row + 24, size)
        put(w, row + 32, mode)
        put(w, row + 88, 0)
        at = at + size
        i = i + 1
    if at != length(s):
        return 16
    put(w, 16, length(s))
    put(w, 24, count)
    return 0

def select(s:readbuf, w:mutbuf) -> u32:
    index = get(w, 32)
    if index >= get(w, 24) or index >= 256:
        return 16
    row = 4096 + index * 96
    name = get(w, row)
    size = get(w, row + 8)
    if size == 0 or size > 127 or name > length(s) or size > length(s) - name:
        return 16
    i = 0
    while i < size:
        store(w, 960 + i, byte(s, name + i))
        i = i + 1
    store(w, 960 + size, 0)
    put(w, 40, get(w, row + 16))
    put(w, 48, get(w, row + 24))
    put(w, 56, get(w, row + 32))
    return 0

def directory(w:mutbuf, at:u64) -> u64:
    if get(w, at + 24) & 61440 != 16384:
        return 0
    if get(w, at + 28) & 4294967295 != get(w, 64):
        return 0
    return 1

def file_stat(w:mutbuf, phase:u64) -> u32:
    index = get(w, 32)
    if index >= get(w, 24) or index >= 256:
        return 16
    row = 4096 + index * 96
    if get(w, 440) & 4294967295 != 32768 + get(w, row + 32):
        return 10
    if get(w, 444) & 4294967295 != get(w, 64) or get(w, 432) != 1:
        return 10
    if get(w, 464) != get(w, row + 24):
        return 11
    if get(w, row + 88) & 1 == 1:
        if get(w, 416) != get(w, row + 40) or get(w, 424) != get(w, row + 48):
            return 12
        if get(w, 504) != get(w, row + 56) or get(w, 512) != get(w, row + 64):
            return 12
        if get(w, 520) != get(w, row + 72) or get(w, 528) != get(w, row + 80):
            return 12
        return 0
    if phase == 9:
        return 16
    put(w, row + 40, get(w, 416))
    put(w, row + 48, get(w, 424))
    put(w, row + 56, get(w, 504))
    put(w, row + 64, get(w, 512))
    put(w, row + 72, get(w, 520))
    put(w, row + 80, get(w, 528))
    put(w, row + 88, 1)
    return 0

def entries(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    size = get(w, 80)
    if size > length(o):
        return 16
    at = 0
    while at < size:
        if size - at < 20:
            return 16
        extent = byte(o, at + 16) | byte(o, at + 17) << 8
        if extent < 20 or extent > size - at:
            return 16
        n = 0
        while n < extent - 19 and byte(o, at + 19 + n) != 0:
            n = n + 1
        if n == extent - 19 or n == 0:
            return 16
        special = 0
        if n == 1 and byte(o, at + 19) == 46:
            special = 1
        if n == 2 and byte(o, at + 19) == 46 and byte(o, at + 20) == 46:
            special = 1
        if special == 0:
            found = 0
            i = 0
            while i < get(w, 24):
                row = 4096 + i * 96
                if get(w, row + 8) == n:
                    same = 1
                    j = 0
                    while j < n:
                        if byte(o, at + 19 + j) != byte(s, get(w, row) + j):
                            same = 0
                        j = j + 1
                    if same == 1:
                        if get(w, row + 88) != 1 or get(w, row + 48) != get(o, at):
                            return 12
                        if byte(o, at + 18) != 0 and byte(o, at + 18) != 8:
                            return 10
                        put(w, row + 88, 3)
                        put(w, 112, get(w, 112) + 1)
                        found = 1
                i = i + 1
            if found == 0:
                return 11
        at = at + extent
    return 0

def receipt(o:mutbuf, w:mutbuf) -> u32:
    if length(o) < 512:
        return 16
    RECEIPT_PREFIX
    at = RECEIPT_PREFIX_SIZE
    i = 0
    while i < 64:
        store(o, at + i, byte(w, 768 + i))
        i = i + 1
    at = at + 64
    at = append(o, at, 4189033144851666980, 8)
    at = append(o, at, 14882, 2)
    at = decimal(o, at, get(w, 24))
    at = append(o, at, 8315161642760679980, 8)
    at = append(o, at, 14882, 2)
    at = decimal(o, at, get(w, 16))
    at = append(o, at, 7810778314095127084, 8)
    at = append(o, at, 24590976124585574, 7)
    if get(w, 8) == 1:
        at = append(o, at, 1702195828, 4)
    else:
        at = append(o, at, 435728179558, 5)
    at = append(o, at, 2685, 2)
    return at

def decimal(o:mutbuf, at:u64, v:u64) -> u64:
    divisor = 10000000000000000000
    started = 0
    while divisor > 0:
        digit = 0
        while v >= divisor:
            digit = digit + 1
            v = v - divisor
        if digit != 0 or started != 0 or divisor == 1:
            store(o, at, digit + 48)
            at = at + 1
            started = 1
        divisor = divide10(divisor)
    return at

def divide10(v:u64) -> u64:
    quotient = 0
    remainder = 0
    bit = 64
    while bit > 0:
        bit = bit - 1
        remainder = remainder * 2 + ((v >> bit) & 1)
        if remainder >= 10:
            remainder = remainder - 10
            quotient = quotient | (1 << bit)
    return quotient

def append(o:mutbuf, at:u64, value:u64, size:u64) -> u64:
    write(o, at, value, size)
    return at + size

def hex(v:u64) -> u64:
    if v < 10:
        return v + 48
    return v + 87

def unhex(v:u64) -> u64:
    if v >= 48 and v <= 57:
        return v - 48
    if v >= 97 and v <= 102:
        return v - 87
    return 16

def alnum(v:u64) -> u64:
    if v >= 48 and v <= 57 or v >= 65 and v <= 90 or v >= 97 and v <= 122:
        return 1
    return 0

def copy(w:mutbuf, source:u64, target:u64, size:u64) -> u64:
    i = 0
    while i < size:
        store(w, target + i, byte(w, source + i))
        i = i + 1
    return 0

def uint(s:readbuf, at:u64, size:u64) -> u64:
    v = 0
    i = 0
    while i < size:
        v = v | byte(s, at + i) << (i * 8)
        i = i + 1
    return v

def get(w:mutbuf, at:u64) -> u64:
    v = 0
    i = 0
    while i < 8:
        v = v | byte(w, at + i) << (i * 8)
        i = i + 1
    return v

def put(w:mutbuf, at:u64, v:u64) -> u64:
    return write(w, at, v, 8)

def write(o:mutbuf, at:u64, v:u64, size:u64) -> u64:
    i = 0
    while i < size:
        store(o, at + i, v >> (i * 8) & 255)
        i = i + 1
    return 0
'''


def policy_source():
    source = POLICY_SOURCE.replace('30526565255720553', str(int.from_bytes(b'install', 'little')))
    source = source.replace('133476589827702', str(int.from_bytes(b'verify', 'little')))
    source = source.replace('3544407730921556296', str(BUNDLE_MAGIC))
    source = source.replace('7022071303105570862', str(int.from_bytes(b'.hia-sta', 'little')))
    source = source.replace('2975591', str(int.from_bytes(b'ge-', 'little')))
    prefix = b'{"schema":"hepta.hia.release-install.v1","sha256":"'
    writes = []
    for at in range(0, len(prefix), 8):
        chunk = prefix[at:at+8]
        writes.append(f'write(o, {at}, {int.from_bytes(chunk, "little")}, {len(chunk)})')
    source = source.replace('RECEIPT_PREFIX_SIZE', str(len(prefix)))
    source = source.replace('RECEIPT_PREFIX', '\n    '.join(writes))
    for old, raw in [('4189033144851666980', b'","files'), ('14882', b'":'),
                     ('8315161642760679980', b',"bytes"'),
                     ('7810778314095127084', b',"publis'), ('24590976124585574', b'hed":')]:
        source = source.replace(old, str(int.from_bytes(raw, 'little')))
    source = source.replace('14882, 2)\n    at = decimal(o, at, get(w, 16))',
                            str(int.from_bytes(b':', 'little'))+', 1)\n    at = decimal(o, at, get(w, 16))')
    # The second fragment has only five bytes; its explicit count is part of
    # the HIA receipt writer, not implicit C-string formatting.
    source = source.replace(str(int.from_bytes(b'hed":', 'little'))+', 7)',
                            str(int.from_bytes(b'hed":', 'little'))+', 5)')
    return source


# Fixed Linux/SysV transport. HIA owns the policy and ELF packer below.
# Keep the .S source and assembled_template() as the independent authoring oracle.
# No assembler, linker, payload code, or native image is executed by template().
TRANSPORT_SOURCE_SHA256 = '8d131a8f2453f35230851621e9c093be8142e275f8d5c06487564590f4b4bd3e'
TRANSPORT_SHA256 = '1ffa5ef695edbd5b3ec44443cb626e12fd730de3b65013f03323ea5ac9a0f021'
TRANSPORT_BYTES = 3447
TRANSPORT = bytes.fromhex(
    '4989e749833f040f85580d000031ffbe00800300ba0300000041ba2200000049c7c0ffffffff4531c9b8090000000f05'
    '483d01f0ffff0f83140d00004889c548c785d047000001000000bf0d000000488db5d047000031d241ba08000000b80d'
    '0000000f054885c00f88e20c000041bc18000000bb01000000498b74df08e82b0c0000483dff0f00000f87c80c000048'
    '8944ddf84889c14a8d7c25004901c44981fc002000000f87ab0c0000f3a4ffc383fb0475c44889ef4c89e6488d950020'
    '0000b9002000004c8d850040000041b900000100e80000000083f8010f82750c000083f8020f876c0c000031ffbe0010'
    '0004ba0300000041ba2200000049c7c0ffffffff4531c9b8090000000f05483d01f0ffff0f83360c00004989c44531ed'
    '31ff4b8d342cba010000044c29ea31c048898500480000488b85004800000f054883f8fc74f14885c00f88010c000074'
    '124901c54981fd000000040f87fd0b0000ebbdc6850040020000be01000000e8910b000085c00f85db0b000031db4c39'
    'eb744b4c89e94829d94881f9000001007605b90000010048898d50400000498d341c488dbd01400200f3a4c685004002'
    '0001488bb5504000004801f348ffc6e8410b000085c00f858b0b0000ebb0c6850040020002be01000000e8260b000083'
    'f8200f856f0b000048c7850040000001000000488dbd00500300be20000000e8c60a000085c00f852b0b000048c78500'
    '40000002000000e8a80a000085c00f85130b00004c89e7be00100004ba01000000b80a0000000f054885c00f880f0b00'
    '00b86b0000000f0548898540400000bf9cffffff488d35180b0000ba00002b004531d2b8010100004889850048000048'
    '8b85004800000f054883f8fc74f14885c00f88b40a00004989c6bb01000000483b9d58400000736c4c89f7488db41d00'
    '200000ba00002b004531d2b80101000048898500480000488b85004800000f054883f8fc74f14885c00f886c0a000048'
    '8985784000004c89f7b8030000000f054885c00f88670a00004c8bb57840000080bc1d0020000000740548ffc3ebf148'
    'ffc3eb8b4c89f7488d35670a0000ba00000b004531d2b80101000048898500480000488b85004800000f054883f8fc74'
    'f14885c00f88010a0000488985784000004c89f7b8030000000f054885c00f88fc0900004c8bb5784000004489f7488d'
    'b5a0410000b80500000048898500480000488b85004800000f054883f8fc74f14885c00f88c709000048c78500400000'
    '05000000e82b09000085c00f85960900004883bd08400000020f842d040000bf3f000000b85f0000000f05488dbd9043'
    '0000be1000000031d2b83e01000048898500480000488b85004800000f054883f8fc74f14883f8100f856209000048c7'
    '85004000000d000000e8c608000085c00f85310900004c89f7488db550430000bac0010000b802010000488985004800'
    '00488b85004800000f054883f8fc74f14885c00f88100900004c89f7488db550430000ba00000b004531d2b801010000'
    '48898500480000488b85004800000f054883f8fc74f14885c00f88cc0800004889c389df488db5a0410000b805000000'
    '48898500480000488b85004800000f054883f8fc74f14885c00f88b108000048c7850040000006000000e81508000085'
    'c00f85800800004889dfbec0010000b85b00000048898500480000488b85004800000f054883f8fc74f14885c00f886d'
    '08000048c7852040000000000000488b8520400000483b85184000000f838201000048c7850040000004000000e8b207'
    '000085c00f851d0800004889df488db5c0430000bac2000a0041ba80010000b80101000048898500480000488b850048'
    '00000f054883f8fc74f14885c00f88fd0700004889857840000048c7854840000000000000488b9530400000482b9548'
    '4000007445488bbd78400000488bb5284000004c01e64803b548400000b80100000048898500480000488b8500480000'
    '0f054883f8fc74f14885c00f8e9f07000048018548400000ebab488bbd78400000488bb538400000b85b000000488985'
    '00480000488b85004800000f054883f8fc74f14885c00f8864070000488bbd78400000b84a0000004889850048000048'
    '8b85004800000f054883f8fc74f14885c00f8839070000488bbd78400000488db5a0410000b805000000488985004800'
    '00488b85004800000f054883f8fc74f14885c00f880707000048c7850040000008000000e86b06000085c00f85d60600'
    '00488bbd78400000b8030000000f054885c00f88d806000048ff8520400000e96afeffff4889dfbe40010000b85b0000'
    '0048898500480000488b85004800000f054883f8fc74f14885c00f88a00600004889dfb84a0000004889850048000048'
    '8b85004800000f054883f8fc74f14885c00f8879060000e8890200004c89f7488db550430000488d953042000041ba00'
    '010000b80601000048898500480000488b85004800000f054883f8fc74f14885c00f882406000048c785004000000700'
    '0000e89d05000085c00f85080600004489f7488db5a0410000b80500000048898500480000488b85004800000f054883'
    'f8fc74f14885c00f88f305000048c7850040000005000000e85705000085c00f85c20500004c89f7488db5504300004c'
    '89f24c8d950043000041b801000000b83c01000048898500480000488b85004800000f054883f8fc74f14885c00f8896'
    '0500004c89f7b84a00000048898500480000488b85004800000f054883f8fc74f14885c00f8876050000eb7e4c89f748'
    '8db500430000ba00000b004531d2b80101000048898500480000488b85004800000f054883f8fc74f14885c00f882905'
    '00004889c389df488db5a0410000b80500000048898500480000488b85004800000f054883f8fc74f14885c00f880e05'
    '000048c7850040000006000000e87204000085c00f85dd040000e8060100004c89f7488db500430000488d9530420000'
    '41ba00010000b80601000048898500480000488b85004800000f054883f8fc74f14885c00f88a104000048c785004000'
    '0007000000e81a04000085c00f85850400004489f7488db5a0410000b80500000048898500480000488b85004800000f'
    '054883f8fc74f14885c00f887004000048c7850040000005000000e8d403000085c00f853f04000048c785004000000e'
    '000000e8bc03000085c00f84470400003d000200000f873c0400004189c54c8da5002000004d85ed0f8405040000bf01'
    '0000004c89e64c89eab80100000048898500480000488b85004800000f054883f8fc74f14885c00f8ef30300004901c4'
    '4929c5ebc04883ec0889df488db5a0410000b80500000048898500480000488b85004800000f054883f8fc74f14885c0'
    '0f88ba03000048c7850040000011000000e81e03000085c00f858903000048c7852040000000000000488b8520400000'
    '483b85184000000f83e601000048c7850040000004000000e8e702000085c00f85520300004889df488db5c0430000ba'
    '00080a004531d2b80101000048898500480000488b85004800000f054883f8fc74f14885c00f88200300004889857840'
    '00004889c7488db5a0410000b80500000048898500480000488b85004800000f054883f8fc74f14885c00f8800030000'
    '48c7850040000008000000e86402000085c00f85cf02000048c7854840000000000000488b9530400000482b95484000'
    '00747f4881fa000001007605ba00000100488bbd78400000488db5004001004c8b9548400000b8110000004889850048'
    '0000488b85004800000f054883f8fc74f14885c00f88860200000f84720200004889855040000048c785004000000a00'
    '0000e8f101000085c00f8548020000488b855040000048018548400000e971ffffff488bbd78400000488db500400100'
    'ba010000004c8b9548400000b81100000048898500480000488b85004800000f054883f8fc74f14885c00f8810020000'
    '0f85fc010000488bbd78400000488db5a0410000b80500000048898500480000488b85004800000f054883f8fc74f148'
    '85c00f88d801000048c7850040000009000000e83c01000085c00f85a7010000488bbd78400000b8030000000f054885'
    'c00f88a901000048ff8520400000e906feffff48c785004000000f000000e80101000085c00f856c0100004889df31f6'
    '31d2b80800000048898500480000488b85004800000f054883f8fc74f14885c00f885a0100004889df488db500400100'
    'ba00000100b8d900000048898500480000488b85004800000f054883f8fc74f14885c00f882701000074214889855040'
    '000048c785004000000b000000e89600000085c00f85ed000000ebaa48c785004000000c000000e86800000085c00f85'
    'd300000089df488db5a0410000b80500000048898500480000488b85004800000f054883f8fc74f14885c00f88bf0000'
    '0048c7850040000011000000e82300000085c00f858e0000004883c408c331c0483d00100000730b803c0600740548ff'
    'c0ebedc34c89e74c89ee488d9500200000b900200000eb124c89e74c89ee488d9500400100b9000001004c8d85004000'
    '0041b9000001004883ec08e8000000004883c408c3488dbd00400200488d9500500300b9200000004c8d850060030041'
    'b9001000004883ec08e8000000004883c408c331ffeb3389c7eb2fbf0a000000eb28bf0b000000eb21bf0e000000eb1a'
    'bf0f000000eb13bf10000000eb0cbf11000000eb05bf40000000b83c0000000f050f0b2f002e00'
)
TRANSPORT_HOLES = {'policy_initial_hole': 213, 'policy_hole': 3324, 'sha_hole': 3370}


def template():
    source = ROOT / "tools/hia_release_install_syscalls.S"
    if hashlib.sha256(source.read_bytes()).hexdigest() != TRANSPORT_SOURCE_SHA256:
        raise ValueError("fixed release_install syscall source changed; refresh and independently verify the transport")
    if len(TRANSPORT) != TRANSPORT_BYTES or hashlib.sha256(TRANSPORT).hexdigest() != TRANSPORT_SHA256:
        raise ValueError("fixed release_install transport bytes changed")
    expected_holes = {'policy_initial_hole': 213, 'policy_hole': 3324, 'sha_hole': 3370}
    if TRANSPORT_HOLES != expected_holes:
        raise ValueError("fixed release_install transport holes changed")
    for offset in TRANSPORT_HOLES.values():
        if TRANSPORT[offset - 1:offset + 4] != b"\xe8\0\0\0\0":
            raise ValueError("fixed release_install rel32 call hole changed")
    header = (b"\x7fELF\x02\x01\x01" + bytes(9)
              + struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, 0x4000b0, 64, 0, 0, 64, 56, 2, 0, 0, 0)
              + struct.pack("<IIQQQQQQ", 1, 5, 0, 0x400000, 0x400000, 0, 0, 4096)
              + struct.pack("<IIQQQQQQ", 0x6474e551, 6, 0, 0, 0, 0, 0, 16))
    return header + TRANSPORT, {name: 176 + offset for name, offset in TRANSPORT_HOLES.items()}


def assembled_template():
    with tempfile.TemporaryDirectory(prefix='hia-release-template-') as folder:
        obj, raw = Path(folder)/'adapter.o', Path(folder)/'adapter.bin'
        subprocess.run(['as', '--64', str(ROOT/'tools/hia_release_install_syscalls.S'), '-o', str(obj)],
                       check=True, capture_output=True)
        subprocess.run(['objcopy', '-O', 'binary', '-j', '.text', str(obj), str(raw)],
                       check=True, capture_output=True)
        symbols = {}
        for line in subprocess.check_output(['nm', '-n', str(obj)], text=True).splitlines():
            address, _, name = line.split()
            symbols[name] = int(address, 16)
        if 'R_X86_64' in subprocess.check_output(['objdump', '-r', str(obj)], text=True):
            raise ValueError('unresolved release adapter relocation')
        code = raw.read_bytes()
    header = (b'\x7fELF\x02\x01\x01'+bytes(9)
              +struct.pack('<HHIQQQIHHHHHH', 2,62,1,0x4000b0,64,0,0,64,56,2,0,0,0)
              +struct.pack('<IIQQQQQQ', 1,5,0,0x400000,0x400000,0,0,4096)
              +struct.pack('<IIQQQQQQ', 0x6474e551,6,0,0,0,0,0,16))
    return header+code, {name:176+symbols[name] for name in
                        ('policy_initial_hole','policy_hole','sha_hole')}


def packer_source():
    from tools.generate_hia_native_filter import LINK_SOURCE
    prefix, holes = template()
    source = f'''def pack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 26 or length(s) > 1048576:
        return 4294967295
    if uint(s, 0, 8) != {MAGIC}:
        return 4294967295
    policy = uint(s, 8, 8)
    sha = uint(s, 16, 8)
    if policy == 0 or sha == 0 or policy > 1048576 or sha > 1048576:
        return 4294967295
    if length(s) != 24 + policy + sha:
        return 4294967295
    size = {len(prefix)} + policy + sha
    if size > 1048576 or length(o) < size:
        return 4294967294
'''
    for at in range(0, len(prefix), 8):
        chunk = prefix[at:at+8]
        source += f'    write(o, {at}, {int.from_bytes(chunk,"little")}, {len(chunk)})\n'
    source += '    write(o, 96, size, 8)\n    write(o, 104, size, 8)\n'
    for name, offset in holes.items():
        target = str(len(prefix)) + (' + policy' if name == 'sha_hole' else '')
        source += f'    write(o, {offset}, {target} - {offset + 4}, 4)\n'
    source += f'    copy_bytes(s, o, 24, {len(prefix)}, policy + sha)\n    return size\n'
    return source + LINK_SOURCE[LINK_SOURCE.index('\ndef uint('):]


def main():
    for name, source in [('release_install_policy', policy_source()), ('release_install_packer', packer_source())]:
        path = ROOT/'examples/hia_bootstrap'/f'{name}.hiaasm'
        path.write_text(render_assembly(document(source, name)))
        print(path.name, path.stat().st_size)


if __name__ == '__main__':
    main()
