"""Native release-kit gate helpers, emitted into HIA (not host policy)."""
CONSTANTS={
 'IMAGIC':int.from_bytes(b'HIABIN01','little'),'KMAGIC':int.from_bytes(b'HIABKT01','little'),
 'WMAGIC':int.from_bytes(b'HIABGW01','little'),'EMAGIC':int.from_bytes(b'HIABBE01','little'),
 'RMAGIC':int.from_bytes(b'HIABRP01','little'),'JMAGIC':int.from_bytes(b'HIADATA1','little'),
 'NONE':(1<<64)-1,'BAD':(1<<32)-3,'GROW':(1<<32)-2,
 'EVENT':1024,'TABLE':8192,'MIN_WORK':8192,
}
# IDs are an internal source-code ABI, never caller-selected language policy.
LITERALS=[
 b'docs/HIA_SELFHOST_CORE_SUPPORT.json',b'schema',b'profile',b'status',b'returncode',
 b'checks',b'generation_sha256',b'source_manifest',b'source_identity',b'files',
 b'hepta.hia.selfhost-cold-replay.v1',b'COLD_SELFHOST_REPLAY_PASS',
 b'selfhost-core-linux-x86_64-v65-native-request-release-journal',
 b'export_manifest_matches_qualification',b'isolated_python_without_site',
 b'nested_full_qualification_pass',b'nested_process_exit_zero',b'no_ancestor_git_identity',
 b'no_bytecode_cache_created',b'no_inherited_home_or_python_cache',
 b'no_inherited_seed_or_successor_images',b'origin_hashes_preserved',
 b'owned_process_tree_cleanup_confirmed',b'source_export_hashes_preserved',
 b'examples/hia_bootstrap/selfhost.hiaasm',
 b'examples/hia_bootstrap/core_json_frontend.hiaasm',
 b'examples/hia_bootstrap/agent_stdio_dispatch.hiaasm',
 b'examples/hia_bootstrap/agent_stdio_packer.hiaasm',
 b'examples/hia_bootstrap/release_install_policy.hiaasm',
 b'examples/hia_bootstrap/release_install_packer.hiaasm',
 b'examples/hia_bootstrap/sha256_stream.hiaasm',
]
BODY=r'''
def uint(s:readbuf, at:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(s, at + i) << (i * 8))
        i = i + 1
    return value

def get(w:mutbuf, at:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(w, at + i) << (i * 8))
        i = i + 1
    return value

def put(w:mutbuf, at:u64, value:u64) -> u64:
    i = 0
    while i < 8:
        store(w, at + i, value & 255)
        value = value >> 8
        i = i + 1
    return 0

def copy_read(s:readbuf, w:mutbuf, start:u64, target:u64, size:u64) -> u64:
    i = 0
    while i < size:
        store(w, target + i, byte(s, start + i))
        i = i + 1
    return 0

def equal_source(s:readbuf, a:u64, b:u64, size:u64) -> u64:
    i = 0
    while i < size:
        if byte(s, a + i) != byte(s, b + i):
            return 0
        i = i + 1
    return 1

def equal_read_work(s:readbuf, w:mutbuf, a:u64, b:u64, size:u64) -> u64:
    i = 0
    while i < size:
        if byte(s, a + i) != byte(w, b + i):
            return 0
        i = i + 1
    return 1

def event(w:mutbuf, action:u64, source:u64, size:u64, needed:u64, reason:u64) -> u32:
    i = 0
    while i < 128:
        store(w, EVENT + i, 0)
        i = i + 1
    put(w, EVENT, EMAGIC)
    put(w, EVENT + 8, action)
    put(w, EVENT + 16, get(w, 24))
    put(w, EVENT + 24, source)
    put(w, EVENT + 32, size)
    put(w, EVENT + 40, needed)
    put(w, EVENT + 48, reason)
    put(w, EVENT + 56, get(w, 16))
    put(w, EVENT + 64, get(w, 96))
    put(w, EVENT + 72, TABLE)
    put(w, EVENT + 80, get(w, 48))
    put(w, EVENT + 88, get(w, 56))
    put(w, EVENT + 96, get(w, 344))
    put(w, EVENT + 104, get(w, 352))
    put(w, EVENT + 112, get(w, 360))
    put(w, EVENT + 120, get(w, 368))
    return 128

def bad(w:mutbuf, reason:u64) -> u32:
    put(w, 8, 1)
    put(w, 400, reason)
    event(w, 4, 0, 0, 0, reason)
    return BAD

def refused(w:mutbuf, reason:u64) -> u32:
    put(w, 8, 1)
    put(w, 400, reason)
    return event(w, 3, 0, 0, 0, reason)

def grow(w:mutbuf, needed:u64) -> u32:
    if needed <= length(w):
        return bad(w, 90)
    event(w, 2, 0, 0, needed, 0)
    return GROW

def decode_request(w:mutbuf, source:u64, size:u64, phase:u64) -> u32:
    if get(w, 24) == NONE:
        return bad(w, 91)
    put(w, 24, get(w, 24) + 1)
    put(w, 16, phase)
    put(w, 376, source)
    put(w, 384, size)
    return event(w, 1, source, size, 0, 0)

def node(w:mutbuf, base:u64, id:u64) -> u64:
    return base + 64 + id * 56

def field(w:mutbuf, base:u64, parent:u64, key:u64) -> u64:
    at = node(w, base, parent)
    if get(w, at) != 6:
        return NONE
    current = get(w, at + 24)
    while current != NONE:
        entry = node(w, base, current)
        if literal(w, base + get(w, entry + 40), get(w, entry + 48), key) == 1:
            return current
        current = get(w, entry + 16)
    return NONE

def text_is(w:mutbuf, base:u64, id:u64, value:u64) -> u64:
    if id == NONE:
        return 0
    at = node(w, base, id)
    if get(w, at) != 4:
        return 0
    return literal(w, base + get(w, at + 24), get(w, at + 32), value)

def hex_digit(v:u64) -> u64:
    if v < 10:
        return v + 48
    return v + 87

def digest_is(w:mutbuf, base:u64, id:u64, digest:u64) -> u64:
    if id == NONE:
        return 0
    at = node(w, base, id)
    if get(w, at) != 4 or get(w, at + 32) != 64:
        return 0
    start = base + get(w, at + 24)
    i = 0
    while i < 32:
        v = byte(w, digest + i)
        if byte(w, start + i * 2) != hex_digit(v >> 4):
            return 0
        if byte(w, start + i * 2 + 1) != hex_digit(v & 15):
            return 0
        i = i + 1
    return 1
'''

def literals(source=False):
 prefix='literal_source' if source else 'literal'
 param='s:readbuf' if source else 'w:mutbuf'
 owner='s' if source else 'w';getter='uint' if source else 'get'
 ids=[0,24,25,26,27,28,29,30] if source else list(range(1,24))
 text=f'\ndef {prefix}({param}, at:u64, size:u64, value:u64) -> u64:\n'
 for i in ids:text+=f'    if value == {i}:\n        return {prefix}_{i}({owner}, at, size)\n'
 text+='    return 0\n'
 for i in ids:
  raw=LITERALS[i]
  text+=f'\ndef {prefix}_{i}({param}, at:u64, size:u64) -> u64:\n    if size != {len(raw)}:\n        return 0\n'
  for j in range(0,len(raw),8):
   part=raw[j:j+8]
   if len(part)==8:text+=f'    if {getter}({owner}, at + {j}) != {int.from_bytes(part,"little")}:\n        return 0\n'
   else:
    for k,v in enumerate(part):text+=f'    if byte({owner}, at + {j+k}) != {v}:\n        return 0\n'
  text+='    return 1\n'
 return text

def hashing():
 from tools.generate_hia_sha256 import source_program
 text=source_program()
 old='def sha256(s:readbuf, o:mutbuf, w:mutbuf) -> u32:\n    if length(s) > 8388608 or length(o) < 32 or length(w) < 1088:\n        return 4294967293\n'
 assert text.startswith(old)
 text=text.replace(old,'def hash_range(s:readbuf, start:u64, size:u64, w:mutbuf, target:u64) -> u64:\n',1)
 text=text.replace('padded_byte(s, block + i * 4 + j, padded)','hpadded(s, start, size, block + i * 4 + j, padded)')
 text=text.replace('def padded_byte(s:readbuf, index:u64, total:u64) -> u64:', 'def hpadded(s:readbuf, start:u64, size:u64, index:u64, total:u64) -> u64:')
 text=text.replace('byte(s, index)','byte(s, start + index)').replace('length(s)','size')
 text=text.replace('store(o, i * 4 + j,','store(w, target + i * 4 + j,')
 text=text.replace('rotate(', 'hrotate(').replace('get(', 'hget(').replace('put(', 'hput(')
 # Only the hash helper's private scratch access receives this fixed displacement.
 text=text.replace('byte(w, index + i)','byte(w, 4096 + index + i)').replace('store(w, index + i,','store(w, 4096 + index + i,')
 return text
