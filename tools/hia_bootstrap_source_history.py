"""Data-only admission of the complete historical Bootstrap source.

The current physical service is never replaced. A fixed ten-layer relation
recovers the five-body qualification source and replays every byte forward.
Only explicitly named function code is compiled as data by this module.
"""
from __future__ import annotations
import ast
from hashlib import sha1, sha256
import json
from pathlib import Path
from types import CodeType

SOURCE = 'hepta/hia_agent_service.py'
HELPER = 'tools/hia_bootstrap_source_history.py'
FIXTURE = 'tests/fixtures/hia_bootstrap_current_source_relation_v2.json'
FIXTURE_PIN = {"bytes":372894,"sha256":"48bc861f702688ffa2c8f14afd1f08c05c138997a0289e7acf0e3c457d549c64","git_blob":"fad8bd7ed47fbe617487a1aedf5409eda058c50b"}
CURRENT = {"bytes":268278,"sha256":"afc92b555bd0dfa23f25c4f9c2661af30853474342f4e32a036d37c1ce663a57","git_blob":"b51e992d328aa7527b7aad454f63eea024426202"}
HISTORICAL = {"bytes":161343,"sha256":"f73d14d6271044ef7d2232d926d18741d05ed199527337219ec3171f95adb328","git_blob":"d4f7ce571dff516f6039ef3b70546892f3e423da"}
PREFIX = {"bytes":124988,"sha256":"f6231510db28254e06f0af0da78ef4d4598cf761f4dfad66a51ae07011a537b5","git_blob":"ddede4b3c1f79a508eea5a30fe44e0e0c1bd6fb0"}
METHODS = ('__init__', 'close', '_profiles', '_profile', '_program')
RELATION_SCHEMA = 'hepta.hia.bootstrap-historical-source-relation.v2'
PROOF_SCHEMA = 'hepta.hia.bootstrap-historical-source-admission.v2'

def identity(raw):
    if type(raw) is not bytes:
        raise ValueError('Bootstrap source must be complete immutable bytes')
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
            'git_blob': sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}

def _hex(value):
    if type(value) is not str or len(value) % 2 or value != value.lower():
        raise ValueError('Bootstrap source splice is not canonical hexadecimal')
    try:
        raw = bytes.fromhex(value)
    except ValueError as error:
        raise ValueError('Bootstrap source splice is not hexadecimal') from error
    if raw.hex() != value:
        raise ValueError('Bootstrap source splice is not canonical hexadecimal')
    return raw

def _record(raw, record):
    if (type(record) is not dict
            or set(record) != {'old_bytes', 'new_bytes', 'old_sha256', 'new_sha256', 'hunks'}
            or type(record['old_bytes']) is not int or record['old_bytes'] <= 0
            or type(record['new_bytes']) is not int or record['new_bytes'] != len(raw)
            or sha256(raw).hexdigest() != record['new_sha256']
            or type(record['hunks']) is not list or not record['hunks']):
        raise ValueError('Bootstrap complete source layer differs')
    pieces = []
    old_at = new_at = 0
    decoded = []
    for hunk in record['hunks']:
        if (type(hunk) is not dict or set(hunk) != {'old_offset', 'new_offset', 'old_hex', 'new_hex'}
                or type(hunk['old_offset']) is not int or type(hunk['new_offset']) is not int
                or hunk['old_offset'] < old_at or hunk['new_offset'] < new_at):
            raise ValueError('Bootstrap source layer coordinates differ')
        old, new = _hex(hunk['old_hex']), _hex(hunk['new_hex'])
        gap = hunk['new_offset'] - new_at
        if (old == new or hunk['old_offset'] != old_at + gap
                or hunk['new_offset'] + len(new) > len(raw)
                or raw[hunk['new_offset']:hunk['new_offset'] + len(new)] != new):
            raise ValueError('Bootstrap source splice differs from physical bytes')
        pieces.extend((raw[new_at:hunk['new_offset']], old))
        new_at, old_at = hunk['new_offset'] + len(new), hunk['old_offset'] + len(old)
        decoded.append((hunk['old_offset'], old, new))
    pieces.append(raw[new_at:])
    restored = b''.join(pieces)
    if (len(restored) != record['old_bytes']
            or sha256(restored).hexdigest() != record['old_sha256']):
        raise ValueError('Bootstrap complete predecessor digest differs')
    parts, at = [], 0
    for offset, old, new in decoded:
        if restored[offset:offset + len(old)] != old:
            raise ValueError('Bootstrap source forward predecessor differs')
        parts.extend((restored[at:offset], new))
        at = offset + len(old)
    if b''.join((*parts, restored[at:])) != raw:
        raise ValueError('Bootstrap complete current forward replay differs')
    return restored

def restore(physical, fixture):
    if identity(physical) != CURRENT or identity(fixture) != FIXTURE_PIN:
        raise ValueError('unreviewed Bootstrap physical source or relation')
    value = json.loads(fixture)
    if (type(value) is not dict or set(value) != {'schema', 'source', 'current', 'historical',
            'original_prefix', 'order', 'layers', 'provenance', 'qualification_granted'}
            or value['schema'] != RELATION_SCHEMA or value['source'] != SOURCE
            or value['current'] != CURRENT or value['historical'] != HISTORICAL
            or value['original_prefix'] != PREFIX or value['order'] != 'historical-to-current'
            or value['qualification_granted'] is not False
            or type(value['layers']) is not list or len(value['layers']) != 10):
        raise ValueError('Bootstrap source relation scope differs')
    historical = physical
    for layer in reversed(value['layers']):
        historical = _record(historical, layer)
    if identity(historical) != HISTORICAL or identity(historical[:PREFIX['bytes']]) != PREFIX:
        raise ValueError('Bootstrap complete original source or original prefix differs')
    return historical, {
        'schema': PROOF_SCHEMA, 'domain': 'HISTORICAL_FIVE_BODY_COMPATIBILITY',
        'physical_source': {'path': SOURCE, **CURRENT},
        'historical_source': dict(HISTORICAL), 'original_prefix': dict(PREFIX),
        'fixture': {'path': FIXTURE, **FIXTURE_PIN}, 'relation_layers': 10,
        'complete_original_inverse_verified': True,
        'complete_current_forward_replay_verified': True,
        'current_semantics_qualified': False, 'whole_native_stack_qualified': False,
    }

def capture(root, *, take=Path.read_bytes):
    root = Path(root)
    saved = {name: take(root / name) for name in (SOURCE, FIXTURE)}
    historical, proof = restore(saved[SOURCE], saved[FIXTURE])
    unchanged(root, saved, take=take)
    return historical, proof, saved

def _code(raw):
    root = compile(raw, SOURCE, 'exec')
    classes = [item for item in root.co_consts if type(item) is CodeType and item.co_name == 'HIAAgentService']
    if len(classes) != 1:
        raise ValueError('Bootstrap source class is not unique')
    retained = {item.co_name: item for item in classes[0].co_consts
                if type(item) is CodeType and item.co_name in METHODS}
    public = {item.co_name: item for item in root.co_consts if type(item) is CodeType
              and item.co_name in {'_service_bootstrap_dispatch_' + name for name in METHODS}}
    if set(retained) != set(METHODS) or len(public) != len(METHODS):
        raise ValueError('Bootstrap five complete bodies or public routes are missing')
    return retained, public

def code_bindings(raw):
    retained, public = _code(raw)
    return {
        'retained': {name: sha256(retained[name].co_code).hexdigest() for name in METHODS},
        'public': {name: sha256(public['_service_bootstrap_dispatch_' + name].co_code).hexdigest()
                   for name in METHODS},
        'local_layouts': {name: list(retained[name].co_varnames) for name in METHODS},
    }

def graph_bindings(physical, historical):
    if identity(physical) != CURRENT or identity(historical) != HISTORICAL:
        raise ValueError('Bootstrap graph source pair differs')
    def ports(raw):
        return {node.name: ast.dump(node, include_attributes=False)
                for node in ast.parse(raw).body if isinstance(node, ast.FunctionDef)
                and node.name.startswith('_service_bootstrap_literal_')}
    current_ports, old_ports = ports(physical), ports(historical)
    if len(current_ports) != 40 or current_ports != old_ports:
        raise ValueError('Bootstrap current import-port definitions changed')
    return {'current_code': code_bindings(physical), 'historical_code': code_bindings(historical),
            'import_port_count': 40, 'import_port_names': sorted(current_ports),
            'all_import_port_definitions_identical': True}

def unchanged(root, saved, *, take=Path.read_bytes):
    root = Path(root)
    for name, raw in saved.items():
        if take(root / name) != raw:
            raise ValueError('Bootstrap physical source changed during observation: ' + name)
