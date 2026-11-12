"""HIA native build receipt and HIAREL01 package composition."""
TEXTS=[
 b'{"schema":"hepta.hia.native-clean-build.v1","status":"SOURCE_BOUND_NATIVE_BUILD","compiler_sha256":"',
 b'","kit_sha256":"',b'","builder_sha256":"',b'","stdio_profile":',b',"images":[',
 b'{"input_sha256":"',b'","image_sha256":"',b'","image_bytes":',b'}',b',',
 b'],"runtime_python_required":false,"new_builder_matching_source_cold_qualified":false,"whole_native_delivery_qualified":false}\n',
 b'hia',b'hia-release',b'hia-build',b'compiler.bin',b'source-kit.hiabuild',b'build.json',
]
BODY=r'''
def package(s:readbuf, w:mutbuf) -> u32:
    cursor = get(w, B_CURSOR)
    if cursor > NONE - 4096:
        return bad(w, 118)
    if length(w) < cursor + 4096:
        return grow(w, cursor + 4096)
    receipt_size = receipt(w, cursor)
    put(w, B_RECEIPT, cursor)
    put(w, B_RECEIPT_BYTES, receipt_size)
    start = cursor + 4096
    size = 24 + 6 * 24 + 3 + 11 + 9 + 12 + 19 + 10
    size = size + get(w, B_AGENT_BYTES) + get(w, B_INSTALL_BYTES) + get(w, B_SELF_BYTES)
    size = size + get(w, B_ROWS + 24) + receipt_size
    if size > 67108864 or length(s) - 64 > 67108864 - size:
        return refused(w, 14)
    size = size + length(s) - 64
    if start > NONE - size:
        return bad(w, 119)
    if length(w) < start + size:
        return grow(w, start + size)
    put(w, start, RELEASE_MAGIC)
    put(w, start + 8, 6)
    put(w, start + 16, 0)
    next = start + 24
    next = pack_file(w, next, 11, 3, 320, get(w, B_AGENT), get(w, B_AGENT_BYTES))
    next = pack_file(w, next, 12, 11, 320, get(w, B_INSTALL), get(w, B_INSTALL_BYTES))
    next = pack_file(w, next, 13, 9, 320, get(w, B_SELF), get(w, B_SELF_BYTES))
    next = pack_file(w, next, 14, 12, 256, get(w, B_ROWS + 16), get(w, B_ROWS + 24))
    put(w, next, 19)
    put(w, next + 8, 256)
    put(w, next + 16, length(s) - 64)
    next = emit_text(w, next + 24, 15)
    copy_read(s, w, 64, next, length(s) - 64)
    next = next + length(s) - 64
    next = pack_file(w, next, 16, 10, 256, cursor, receipt_size)
    if next != start + size:
        return bad(w, 120)
    put(w, B_FINAL, start)
    put(w, B_FINAL_BYTES, size)
    hash_work(w, start, size, 704)
    put(w, 16, 99)
    event(w, 0, start, size, cursor, receipt_size)
    i = 0
    while i < 4:
        put(w, EVENT + 96 + i * 8, get(w, 704 + i * 8))
        i = i + 1
    return 128

def pack_file(w:mutbuf, at:u64, name:u64, name_size:u64, mode:u64, source:u64, size:u64) -> u64:
    put(w, at, name_size)
    put(w, at + 8, mode)
    put(w, at + 16, size)
    cursor = emit_text(w, at + 24, name)
    copy_work(w, source, cursor, size)
    return cursor + size

def receipt(w:mutbuf, at:u64) -> u64:
    cursor = emit_text(w, at, 0)
    cursor = emit_hex(w, cursor, 448)
    cursor = emit_text(w, cursor, 1)
    cursor = emit_hex(w, cursor, 272)
    cursor = emit_text(w, cursor, 2)
    cursor = emit_hex(w, cursor, B_HASH)
    cursor = emit_text(w, cursor, 3)
    cursor = decimal(w, cursor, get(w, 392))
    cursor = emit_text(w, cursor, 4)
    index = 0
    while index < 9:
        if index != 0:
            cursor = emit_text(w, cursor, 9)
        row = B_ROWS + index * 96
        cursor = emit_text(w, cursor, 5)
        cursor = emit_hex(w, cursor, row + 64)
        cursor = emit_text(w, cursor, 6)
        cursor = emit_hex(w, cursor, row + 32)
        cursor = emit_text(w, cursor, 7)
        cursor = decimal(w, cursor, get(w, row + 24))
        cursor = emit_text(w, cursor, 8)
        index = index + 1
    cursor = emit_text(w, cursor, 10)
    return cursor - at

def emit_hex(w:mutbuf, at:u64, source:u64) -> u64:
    i = 0
    while i < 32:
        value = byte(w, source + i)
        store(w, at + i * 2, hex_digit(value >> 4))
        store(w, at + i * 2 + 1, hex_digit(value & 15))
        i = i + 1
    return at + 64

def decimal(w:mutbuf, at:u64, value:u64) -> u64:
    # Private scratch below hash workspace; at most 20 decimal digits.
    i = 0
    going = True
    while going:
        quotient = divide10(value)
        store(w, 3584 + i, 48 + value - quotient * 10)
        i = i + 1
        value = quotient
        if value == 0:
            going = False
    size = i
    while i > 0:
        i = i - 1
        store(w, at, byte(w, 3584 + i))
        at = at + 1
    return at

def divide10(value:u64) -> u64:
    # Exact unsigned binary long division; no host integer rendering.
    result = 0
    remainder = 0
    bit = 64
    while bit > 0:
        bit = bit - 1
        remainder = (remainder << 1) | ((value >> bit) & 1)
        if remainder >= 10:
            remainder = remainder - 10
            result = result | (1 << bit)
    return result
'''

def texts():
 source='\ndef emit_text(w:mutbuf, at:u64, id:u64) -> u64:\n'
 for i,raw in enumerate(TEXTS):source+=f'    if id == {i}:\n        return emit_text_{i}(w, at)\n'
 source+='    return at\n'
 for i,raw in enumerate(TEXTS):
  source+=f'\ndef emit_text_{i}(w:mutbuf, at:u64) -> u64:\n'
  for j in range(0,len(raw),8):
   b=raw[j:j+8]
   if len(b)==8:source+=f'    put(w, at + {j}, {int.from_bytes(b,"little")})\n'
   else:
    for k,v in enumerate(b):source+=f'    store(w, at + {j+k}, {v})\n'
  source+=f'    return at + {len(raw)}\n'
 return source
