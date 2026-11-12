"""HIA historical root keys/schema owner and complete renamed-packet copy.

Input is the exact private SourceIndexLease issued by the public native raw
pipeline. Header/extent/bitmap correlation is not external authentication.
"""
from tools.legacy_authoring import source,document as build,write_document
from tools.hia_composite_lowering_driver_common import COMMON

CONSTANTS={'BAD':0xfffffffd,'MAX':(1<<64)-1,'SOURCE_MAGIC':int.from_bytes(b'HIASIL01','little'),
           'MAGIC':int.from_bytes(b'HIALIP01','little'),'PACKET_MAX':64<<20}

BODY=r'''
def project(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(o) < 64 or length(w) < 64:
        return BAD
    if source_lease(s) == 0:
        return BAD
    packet = word(s, 8)
    if word(s, 64) != 6:
        return result(o, 1, 0, packet, 0)
    if packet < 24:
        return BAD
    if word(s, 80) != 4:
        return result(o, 1, 0, packet, 0)
    at = 88
    mask = 0
    schema = 0
    i = 0
    while i < 4:
        key = at
        if key > 64 + packet - 16 or word(s, key) != 4:
            return BAD
        key_bytes = word(s, key + 8)
        if key_bytes > 64 + packet - key - 16:
            return BAD
        value = key + 16 + key_bytes
        if value > 64 + packet - 16:
            return BAD
        value_bytes = word(s, value + 8)
        if value_bytes > 64 + packet - value - 16:
            return BAD
        bit = key_bit(s, key)
        if bit == 0 or (mask & bit) != 0:
            return result(o, 1, 0, packet, 0)
        mask = mask | bit
        if bit == 1:
            schema = value
        at = value + 16 + value_bytes
        i = i + 1
    if at != 64 + packet:
        return BAD
    if mask != 15:
        return result(o, 1, 0, packet, 0)
    if text_old_schema(s, schema) == 0:
        return result(o, 2, 0, packet, schema - 64)
    if packet > PACKET_MAX - 2 or length(o) < packet + 66:
        return 4294967294
    # Packet offsets are relative to the packet, not the source lease. Copy
    # every original byte except the one schema value and its length field.
    copy_bytes(s, o, 64, 64, schema - 64)
    put(o, 72, word(s, 72) + 2)
    put(o, schema, 4)
    put(o, schema + 8, 22)
    renamed_schema(o, schema + 16)
    tail = schema + 16 + 20
    copy_bytes(s, o, tail, tail + 2, 64 + packet - tail)
    result(o, 0, packet + 2, packet, schema - 64)
    return 66 + packet

def source_lease(s:readbuf) -> u64:
    if length(s) < 82 or word(s, 0) != SOURCE_MAGIC:
        return 0
    packet = word(s, 8)
    if packet < 16 or packet > PACKET_MAX or word(s, 24) != 64:
        return 0
    count = (packet + 7) >> 3
    index = (64 + packet + 7) & (MAX - 7)
    if word(s, 16) != count or word(s, 32) != index or word(s, 40) != length(s):
        return 0
    if index > length(s) or count != length(s) - index or word(s, 48) != 0 or word(s, 56) != 0:
        return 0
    if word(s, 72) != packet - 16 or (byte(s, index) & 1) == 0:
        return 0
    at = 64 + packet
    while at < index:
        if byte(s, at) != 0:
            return 0
        at = at + 1
    if (packet & 7) != 0 and (byte(s, length(s) - 1) >> (packet & 7)) != 0:
        return 0
    return 1

def text(s:readbuf, at:u64, size:u64, a:u64, b:u64, c:u64) -> u64:
    if word(s, at) != 4 or word(s, at + 8) != size:
        return 0
    i = 0
    while i < size:
        value = a
        if i >= 8:
            value = b
        if i >= 16:
            value = c
        if byte(s, at + 16 + i) != ((value >> ((i & 7) * 8)) & 255):
            return 0
        i = i + 1
    return 1

def result(o:mutbuf, error:u64, size:u64, original:u64, schema:u64) -> u32:
    put(o, 0, MAGIC)
    put(o, 8, error)
    put(o, 16, 64)
    put(o, 24, size)
    put(o, 32, original)
    put(o, 40, schema)
    put(o, 48, 0)
    put(o, 56, 0)
    return 64

def copy_bytes(s:readbuf, o:mutbuf, start:u64, target:u64, size:u64) -> u64:
    i = 0
    while i < size:
        store(o, target + i, byte(s, start + i))
        i = i + 1
    return 0
'''

def literal_args(text):
    raw=text.encode(); return ', '.join(map(str,[len(raw)]+[int.from_bytes(raw[i:i+8],'little') for i in (0,8,16)]))

def source_program():
    extra='\ndef key_bit(s:readbuf, at:u64) -> u64:\n'
    for key,bit in [('schema',1),('module',2),('types',4),('functions',8)]:
        extra+=f'    if text(s, at, {literal_args(key)}) != 0:\n        return {bit}\n'
    extra+='    return 0\n'
    extra+=f'\ndef text_old_schema(s:readbuf, at:u64) -> u64:\n    return text(s, at, {literal_args("hepta.hia.program.v2")})\n'
    extra+='\ndef renamed_schema(o:mutbuf, at:u64) -> u64:\n'
    for i,b in enumerate(b'hepta.hia.composite.v1'): extra+=f'    store(o, at + {i}, {b})\n'
    extra+='    return 0\n'
    return source(BODY+extra+'\n'+COMMON,CONSTANTS,'project')

def document(): return build(source_program(),'legacy_composite_projection')
if __name__=='__main__': write_document(document(),'legacy_composite_projection.hiaasm')
