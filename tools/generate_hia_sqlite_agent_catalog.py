"""Author the native fixed Agent SQLite schema admission program."""
import struct
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = (
    ('artifacts', 'id text primary key,sha256 text not null,uri text unique not null,kind text not null,metadata text not null,content_key text unique not null', 3),
    ('profiles', 'id text not null,sha256 text not null,artifact text not null,primary key(id,sha256)', 1),
    ('contexts', 'id text primary key,sha256 text not null,artifact text not null,created_ns text not null,attempts integer not null default 0', 1),
    ('requests', 'key text primary key,digest text not null,tool text not null,state text not null,response text,started_ns text not null', 1),
    ('costs', 'sequence integer primary key autoincrement,context_id text,tool text not null,request_id text not null,wall_ns text not null,status text not null,details text not null', 0),
    ('cursors', 'id text primary key,artifact_id text not null,sha256 text not null,offset integer not null', 1),
    ('slots', 'name text primary key,context_id text not null,generation text not null,epoch text not null,abi_sha256 text not null', 1),
    ('versions', 'slot text not null,generation text not null,artifact text not null,primary key(slot,generation)', 1),
    ('leases', 'id text primary key,slot text not null,generation text not null,artifact text not null,active integer not null', 1),
    ('execution_budgets', 'context_id text primary key,used_native_ns text not null,owner text', 1),
    ('sqlite_sequence', 'name,seq', 0),
)

POLICY = '''def catalog(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 16:
        return 1
    if uint(s, 0) != MAGIC:
        return 1
    if length(w) < 1024:
        return 3
    phase = uint(s, 8)
    if phase == 1:
        if length(s) != 32:
            return 1
        pages = uint(s, 16)
        if uint(s, 24) != 1:
            return 5
        if pages < 2 or pages > 4294967294 or get(w, 0) != 0:
            return 1
        i = 0
        while i < 512:
            put(w, i, 0)
            i = i + 8
        put(w, 0, 1)
        put(w, 8, pages)
        return 0
    if get(w, 0) != 1:
        return 1
    if phase == 2:
        return accept_row(s, w)
    if phase != 3 or length(s) != 16:
        return 1
    if get(w, 24) != 2047 or get(w, 32) != INDEX_MASK:
        return 4
    if length(o) < 112:
        return 2
    emit(o, 0, RESULT_MAGIC)
    emit(o, 8, 1)
    emit(o, 16, 11)
    i = 0
    while i < 11:
        emit(o, 24 + i * 8, get(w, 64 + i * 8))
        i = i + 1
    put(w, 0, 2)
    return 0

def accept_row(s:readbuf, w:mutbuf) -> u32:
    if length(s) <= 224 or uint(s, 24) != 192 or uint(s, 32) != RECORD_MAGIC:
        return 1
    if uint(s, 40) != 5 or uint(s, 48) != length(s) - 224:
        return 1
    rowid = uint(s, 16)
    if rowid <= get(w, 16) or rowid > 9223372036854775807:
        return 1
    i = uint(s, 56)
    if i == 0 or i > length(s) - 224:
        return 1
    current = 64
    while current < 224:
        extent = uint(s, current + 16)
        if uint(s, current + 8) != i or extent > length(s) - 224 - i:
            return 1
        i = i + extent
        current = current + 32
    if i != length(s) - 224:
        return 1
    if text(s, 64) == 0 or text(s, 96) == 0 or text(s, 128) == 0:
        return 1
    serial = uint(s, 160)
    extent = uint(s, 176)
    if serial != 1 and serial != 2 and serial != 3 and serial != 4 and serial != 5 and serial != 6:
        return 5
    expected_size = serial
    if serial == 5:
        expected_size = 6
    if serial == 6:
        expected_size = 8
    if extent != expected_size:
        return 1
    page = uint(s, 184)
    root_at = 224 + uint(s, 168)
    observed = 0
    i = 0
    while i < extent:
        observed = (observed << 8) | byte(s, root_at + i)
        i = i + 1
    if observed != page or page < 2 or page > get(w, 8):
        return 5
    i = 0
    count = get(w, 40)
    if count >= RECORD_COUNT:
        return 4
    while i < count:
        if page == get(w, 160 + i * 8):
            return 4
        i = i + 1
    kind = word5(s, 224 + uint(s, 72), uint(s, 80))
    table_at = 224 + uint(s, 136)
    table_len = uint(s, 144)
    table = table_id(s, table_at, table_len)
    if table == 0:
        return 5
    name = 224 + uint(s, 104)
    name_len = uint(s, 112)
    if kind == TABLE_WORD:
        if name_len != table_len or same(s, table_at, name, table_len) == 0 or text(s, 192) == 0:
            return 5
        bit = 1 << (table - 1)
        if get(w, 24) & bit != 0:
            return 4
        sql = 224 + uint(s, 200)
        sql_len = uint(s, 208)
        model_len = ddl(w, table)
        if matches(s, w, sql, sql_len, model_len) == 0:
            return 5
        put(w, 64 + (table - 1) * 8, page)
        put(w, 24, get(w, 24) | bit)
    else:
        if kind != INDEX_WORD or uint(s, 192) != 0 or uint(s, 208) != 0 or uint(s, 216) != 0:
            return 5
        code = index_bit(s, table, table_at, table_len, name, name_len)
        if code == 0:
            return 5
        if get(w, 32) & code != 0:
            return 4
        put(w, 32, get(w, 32) | code)
    put(w, 160 + count * 8, page)
    put(w, 40, count + 1)
    put(w, 16, rowid)
    return 0

def index_bit(s:readbuf, table:u64, table_at:u64, n:u64, name:u64, length_name:u64) -> u64:
    if length_name != n + 19 or uint(s, name) != INDEX_PREFIX_A or uint(s, name + 8) != INDEX_PREFIX_B:
        return 0
    if byte(s, name + 16) != 95 or byte(s, name + 17 + n) != 95:
        return 0
    if same(s, table_at, name + 17, n) == 0:
        return 0
    number = byte(s, name + 18 + n)
    return index_for(table, number)

def text(s:readbuf, at:u64) -> u64:
    serial = uint(s, at)
    size = uint(s, at + 16)
    if size > 512 or serial != 13 + size * 2 or uint(s, at + 24) != 0:
        return 0
    return 1

def word5(s:readbuf, at:u64, n:u64) -> u64:
    if n != 5:
        return 0
    value = 0
    i = 0
    while i < 5:
        value = value | (byte(s, at + i) << (i * 8))
        i = i + 1
    return value

def same(s:readbuf, left:u64, right:u64, n:u64) -> u64:
    i = 0
    while i < n:
        if byte(s, left + i) != byte(s, right + i):
            return 0
        i = i + 1
    return 1

def matches(s:readbuf, w:mutbuf, at:u64, n:u64, want:u64) -> u64:
    i = 0
    j = 0
    previous = 0
    while i < n:
        chr = byte(s, at + i)
        if space(chr) == 1:
            while i < n and space(byte(s, at + i)) == 1:
                i = i + 1
            if word(previous) == 1 and i < n and word(byte(s, at + i)) == 1:
                if j >= want or byte(w, 512 + j) != 32:
                    return 0
                j = j + 1
        else:
            if chr >= 65 and chr <= 90:
                chr = chr + 32
            if j >= want or byte(w, 512 + j) != chr:
                return 0
            j = j + 1
            i = i + 1
            previous = chr
    if j == want:
        return 1
    return 0

def word(chr:u64) -> u64:
    if chr >= 48 and chr <= 57 or chr >= 65 and chr <= 90 or chr == 95 or chr >= 97 and chr <= 122:
        return 1
    return 0

def space(chr:u64) -> u64:
    if chr == 32 or chr >= 9 and chr <= 13:
        return 1
    return 0

def uint(s:readbuf, at:u64) -> u64:
    i = 0
    value = 0
    while i < 8:
        value = value | (byte(s, at + i) << (i * 8))
        i = i + 1
    return value

def get(s:mutbuf, at:u64) -> u64:
    i = 0
    value = 0
    while i < 8:
        value = value | (byte(s, at + i) << (i * 8))
        i = i + 1
    return value

def put(o:mutbuf, at:u64, value:u64) -> u64:
    i = 0
    while i < 8:
        store(o, at + i, value >> (i * 8) & 255)
        i = i + 1
    return 0

def emit(o:mutbuf, at:u64, value:u64) -> u64:
    return put(o, at, value)
'''


def constants():
    words = {'RESULT_MAGIC': b'HIASCOK1', 'RECORD_MAGIC': b'HIASREC1',
             'TABLE_WORD': b'table', 'INDEX_WORD': b'index',
             'INDEX_PREFIX_A': b'sqlite_a', 'INDEX_PREFIX_B': b'utoindex',
             'MAGIC': b'HIASCAT1'}
    policy = POLICY
    for name, value in words.items():
        policy = policy.replace(name, str(int.from_bytes(value, 'little')))
    indexes = sum(row[2] for row in SCHEMA)
    return policy.replace('INDEX_MASK', str((1 << indexes) - 1)).replace('RECORD_COUNT', str(len(SCHEMA) + indexes))


def expected_schema():
    names = ['def table_id(s:readbuf, at:u64, n:u64) -> u64:']
    ddls = ['def ddl(w:mutbuf, table:u64) -> u64:']
    indexes = ['def index_for(table:u64, number:u64) -> u64:']
    bit = 1
    for i, (name, fields, index_count) in enumerate(SCHEMA, 1):
        checks = ' and '.join(f'byte(s, at + {j}) == {b}' for j, b in enumerate(name.encode()))
        names.extend((f'    if n == {len(name)} and {checks}:', f'        return {i}'))
        raw = f'create table {name}({fields})'.encode()
        padded = raw + bytes((-len(raw)) % 8)
        ddls.append(f'    if table == {i}:')
        for j, (value,) in enumerate(struct.iter_unpack('<Q', padded)):
            ddls.append(f'        put(w, {512 + j * 8}, {value})')
        ddls.append(f'        return {len(raw)}')
        for index in range(1, index_count + 1):
            indexes.extend((f'    if table == {i} and number == {48+index}:', f'        return {bit}'))
            bit <<= 1
    return '\n\n'.join('\n'.join(fn + ['    return 0']) for fn in (names, ddls, indexes))


def main():
    body = constants() + '\n' + expected_schema() + '\n'
    source = render_assembly(document(body, 'sqlite_agent_catalog'))
    (ROOT / 'examples/hia_bootstrap/sqlite_agent_catalog.hepta').write_text(source)


if __name__ == '__main__':
    main()
