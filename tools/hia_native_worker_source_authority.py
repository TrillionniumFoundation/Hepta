"""Development-time reader for the explicit native Worker source authority.

The installed Worker never imports this module. Its HIA identity owner and
native recipe tables bind the admitted path catalog and captured source pins.
No directory glob or host-language source is part of the native authority.
"""
from pathlib import Path, PurePosixPath
import json
import struct

SCHEMA = 'hepta.hia.native-source-authority.v1'
BACKEND_DOMAIN = b'hepta.hia.native-backend-source-authority.v1\0'
SOURCE_SUFFIXES = frozenset({'.hepta', '.S', '.s', '.inc', '.hiastd'})
DATA_SUFFIXES = frozenset({'.hiacases', '.hiadat', '.hiabundle', '.json', '.tsv', '.md', '.txt'})
CONTINUATION_RUNTIME_V2 = (
    'examples/hia_bootstrap/continuation_policy_v2.hepta',
    'examples/hia_bootstrap/continuation_inprocess_packer_v2.hepta',
    'examples/hia_bootstrap/source_worker_continuation_pack_v2.hepta',
)
CONTINUATION_RUNTIME = (
    'examples/hia_bootstrap/continuation_policy.hepta',
    'examples/hia_bootstrap/continuation_inprocess_packer.hepta',
    'examples/hia_bootstrap/source_worker_continuation_pack.hepta',
)


def _object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('duplicate native source authority field: ' + key)
        value[key] = item
    return value


def checked_paths(value):
    if type(value) not in (tuple, list) or not 1 <= len(value) <= 4096:
        raise ValueError('native source authority requires 1..4096 explicit paths')
    paths = tuple(value)
    for path in paths:
        if type(path) is not str:
            raise ValueError('native source path must be text')
        try:
            encoded = path.encode('ascii')
        except UnicodeEncodeError as exc:
            raise ValueError('native source path must use the source-inventory ASCII domain') from exc
        parts = path.split('/')
        if (not 1 <= len(encoded) <= 4095 or path.startswith('/')
                or any(part in ('', '.', '..', '.git') for part in parts)
                or any(ch < 32 or ch > 126 or ch in (34, 92) for ch in encoded)
                or (path != 'Makefile' and PurePosixPath(path).suffix not in SOURCE_SUFFIXES | DATA_SUFFIXES)):
            raise ValueError('invalid native source authority path: ' + path)
    if tuple(sorted(set(paths))) != paths:
        raise ValueError('native source authority paths must be sorted and unique')
    # This is the retained HIASPI01 input budget of the existing identity owner.
    if 16 + sum(40 + len(path.encode('ascii')) for path in paths) > 1048576:
        raise ValueError('native source authority exceeds the original inventory budget')
    return paths


def load_native_source_authority(path):
    raw = Path(path).read_bytes()
    if len(raw) > 1048576:
        raise ValueError('native source authority document exceeds 1 MiB')
    value = json.loads(raw, object_pairs_hook=_object)
    if type(value) is not dict or set(value) != {'schema', 'paths'} or value['schema'] != SCHEMA:
        raise ValueError('invalid native source authority schema')
    return checked_paths(value['paths'])


def path_table(paths):
    paths = checked_paths(paths)
    return b'HIAWIS01' + struct.pack('<Q', len(paths)) + b''.join(
        struct.pack('<Q', len(path.encode('ascii'))) + path.encode('ascii') for path in paths)


def table_count(raw):
    if type(raw) is not bytes or len(raw) < 16 or raw[:8] != b'HIAWIS01':
        raise ValueError('invalid Worker identity path table')
    count, = struct.unpack_from('<Q', raw, 8)
    if not 1 <= count <= 4096:
        raise ValueError('invalid Worker identity path count')
    cursor = 16
    paths = []
    for _ in range(count):
        if cursor > len(raw) - 8:
            raise ValueError('truncated Worker identity path length')
        size, = struct.unpack_from('<Q', raw, cursor)
        cursor += 8
        if not 1 <= size <= 4095 or size > len(raw) - cursor:
            raise ValueError('truncated Worker identity path')
        encoded = raw[cursor:cursor + size]
        if any(ch < 32 or ch > 126 or ch in (34, 92) for ch in encoded):
            raise ValueError('invalid Worker identity path bytes')
        paths.append(encoded.decode('ascii'))
        cursor += size
    if cursor != len(raw) or len(set(paths)) != count or paths != sorted(paths):
        raise ValueError('noncanonical Worker identity path table')
    return count


def native_model(original, authority_path):
    paths = load_native_source_authority(authority_path)
    required = set(CONTINUATION_RUNTIME) | set(original['continuation_resources'])
    required.update(h['source'] for h in original['helpers'])
    required.update(f['abi_source'] for f in original['families'])
    required.update(u['source'] for f in original['families'] for u in f['units'])
    for family in original['families']:
        required.update(family.get('continuation_resources', ()))
        if family.get('continuation_schema') == 'hepta.hia.native-continuation-inprocess.v2':
            required.update(CONTINUATION_RUNTIME_V2)
    missing = sorted(required - set(paths))
    if missing:
        raise ValueError('native Worker authority omits required implementation inputs: ' + repr(missing))
    result = dict(original)
    result['continuation_runtime'] = list(CONTINUATION_RUNTIME)
    result['families'] = [dict(family) for family in original['families']]
    for family in result['families']:
        if 'continuation_runtime' in family:
            if family.get('continuation_schema') != 'hepta.hia.native-continuation-inprocess.v2' or family['name'] != 'core-lowering':
                raise ValueError('unknown per-family native continuation authority')
            family['continuation_runtime'] = list(CONTINUATION_RUNTIME + CONTINUATION_RUNTIME_V2)
    result['runtime_files'] = [p for p in paths if PurePosixPath(p).suffix in SOURCE_SUFFIXES]
    result['native_source_authority'] = {'schema': SCHEMA, 'paths': list(paths),
        'backend_domain_hex': BACKEND_DOMAIN.hex(),
        'binding': 'SHA256 of the canonical complete native path-to-source-pin map, followed by the unchanged compiled profile/ABI/image binding terms'}
    return result
