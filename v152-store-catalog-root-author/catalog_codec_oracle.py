"""Independent specification oracle for catalog bytes, never a production provider."""
from hashlib import sha256
import struct

U64_MAX = (1 << 64) - 1
TABLES = ('artifacts','profiles','contexts','requests','costs','cursors','slots',
          'versions','leases','execution_budgets')
CATALOG_MAGIC = b'HIACAT01'
EMPTY_MAGIC = b'HIATBL01'
REQUEST_MAGIC = b'HIACRQ01'

def exact_bytes(value, size, label):
    if type(value) is not bytes or len(value) != size:
        raise ValueError(label)
    return value

def exact_integer(value, label):
    if type(value) is not int or not 0 <= value <= U64_MAX:
        raise ValueError(label)
    return value

def uuid(value):
    value = exact_bytes(value, 16, 'Store UUID length')
    if value == bytes(16):
        raise ValueError('zero Store UUID')
    return value

def empty_page(store_uuid, table):
    store_uuid = uuid(store_uuid)
    if type(table) is not int or not 1 <= table <= 10:
        raise ValueError('table ID')
    return EMPTY_MAGIC + struct.pack('<QQQ', 1, table, 0) + store_uuid + bytes(16)

def table_pair(store_uuid, table, pair):
    if type(pair) is not tuple or len(pair) != 2:
        raise ValueError('count/digest pair')
    count = exact_integer(pair[0], 'table count')
    digest = exact_bytes(pair[1], 32, 'table root digest')
    if digest == bytes(32):
        raise ValueError('zero table root digest')
    if count == 0 and digest != sha256(empty_page(store_uuid, table)).digest():
        raise ValueError('noncanonical empty table root')
    return count, digest

def encode_catalog(store_uuid, generation, tables):
    store_uuid = uuid(store_uuid)
    generation = exact_integer(generation, 'catalog generation')
    if type(tables) is not tuple or len(tables) != 10:
        raise ValueError('complete ordered ten-family root required')
    prefix = CATALOG_MAGIC + struct.pack('<Q', 1) + store_uuid
    prefix += struct.pack('<QQ', generation, 10) + bytes(16)
    for table, pair in enumerate(tables, 1):
        count, digest = table_pair(store_uuid, table, pair)
        prefix += struct.pack('<QQ', table, count) + digest
    if len(prefix) != 544:
        raise AssertionError('specification format error')
    return prefix + sha256(prefix).digest()

def decode_catalog(raw, store_uuid, generation):
    raw = exact_bytes(raw, 576, 'catalog extent')
    store_uuid = uuid(store_uuid)
    generation = exact_integer(generation, 'expected generation')
    if raw[:8] != CATALOG_MAGIC or raw[8:16] != struct.pack('<Q', 1):
        raise ValueError('catalog format')
    if raw[16:32] != store_uuid or raw[32:48] != struct.pack('<QQ', generation, 10):
        raise ValueError('Store/generation/ten-table binding')
    if raw[48:64] != bytes(16) or raw[544:] != sha256(raw[:544]).digest():
        raise ValueError('reserved/hash')
    tables = []
    for table in range(1, 11):
        offset = 64 + (table - 1) * 48
        actual, count = struct.unpack_from('<QQ', raw, offset)
        if actual != table:
            raise ValueError('missing/duplicate/reordered table')
        tables.append(table_pair(store_uuid, table, (count, raw[offset + 16:offset + 48])))
    tables = tuple(tables)
    if encode_catalog(store_uuid, generation, tables) != raw:
        raise ValueError('noncanonical catalog')
    return tables

def genesis(store_uuid):
    store_uuid = uuid(store_uuid)
    tables = tuple((0, sha256(empty_page(store_uuid, table)).digest()) for table in range(1, 11))
    return encode_catalog(store_uuid, 0, tables)

def transition(expected, store_uuid, generation, updates):
    if exact_integer(generation, 'expected generation') == U64_MAX:
        raise ValueError('generation exhausted')
    old = decode_catalog(expected, store_uuid, generation)
    if type(updates) is not dict or not updates:
        raise ValueError('nonempty explicit change set')
    changed = list(old)
    for table, pair in updates.items():
        if type(table) is not int or not 1 <= table <= 10:
            raise ValueError('table ID')
        pair = table_pair(store_uuid, table, pair)
        if pair == old[table - 1]:
            raise ValueError('unchanged table marked changed')
        changed[table - 1] = pair
    return encode_catalog(store_uuid, generation + 1, tuple(changed))

def request(operation, store_uuid, generation=0, expected=None, updates=None, table=0):
    store_uuid = uuid(store_uuid)
    generation = exact_integer(generation, 'generation')
    if type(operation) is not int or operation not in (0, 1, 2, 3):
        raise ValueError('operation')
    if type(table) is not int or not 0 <= table <= 10:
        raise ValueError('exact integer table selector')
    mask = 0
    payload = b''
    if operation == 0:
        if updates is not None or table != 0:
            raise ValueError('validate arguments')
        decode_catalog(expected, store_uuid, generation)
        payload = expected
    elif operation == 1:
        if table != 0:
            raise ValueError('transition table selector')
        transition(expected, store_uuid, generation, updates)
        changes = bytearray(400)
        for table_id, pair in updates.items():
            mask |= 1 << (table_id - 1)
            count, digest = pair
            offset = (table_id - 1) * 40
            changes[offset:offset + 40] = struct.pack('<Q', count) + digest
        payload = expected + bytes(changes)
    elif operation == 2:
        if generation != 0 or table != 0 or expected is not None or updates is not None:
            raise ValueError('genesis arguments')
    else:
        empty_page(store_uuid, table)
        if generation != 0 or expected is not None or updates is not None:
            raise ValueError('empty-page arguments')
    return (REQUEST_MAGIC + struct.pack('<QQQ', operation, generation, mask)
            + store_uuid + struct.pack('<Q', table) + bytes(72) + payload)
