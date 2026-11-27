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
PROOF_SCHEMA = 'hepta.hia.bootstrap-historical-source-admission.v3'

LIVE_CURRENT = {'bytes': 268730, 'sha256': '353bd2673cc4f269c9c2d6cbf226d8956703d434ca960214864f56689d8f82c1', 'git_blob': '1df2bc27349cccc3f7834856db187632c13f25f0'}
SUCCESSOR_FIXTURE = 'tests/fixtures/hia_bootstrap_service_evaluation_successor_v1.json'
SUCCESSOR_PIN = {'bytes': 2189, 'sha256': '7d4fb8a6a57ba4c25598f7b0c6cd7e191a5cc869260e46fed37bc5ae7860e97d', 'git_blob': '23645419a63f5c0fbde2f45f2b10a0a569a55b10'}
_SUCCESSOR_SCHEMA = 'hepta.hia.bootstrap-service-evaluation-successor.v1'
# Bind the implementation that actually executed, before any caller admission.
_EXECUTED_PATH = Path(__file__).resolve()
_EXECUTED_SOURCE = _EXECUTED_PATH.read_bytes()

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

def _restore_relation(physical, fixture):
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

def _executed_self():
    if _EXECUTED_PATH.read_bytes() != _EXECUTED_SOURCE:
        raise ValueError('Bootstrap source reader changed after import')


def _actual_bytes(root, name, take):
    path = root / name
    raw = take(path)
    if type(raw) is not bytes or path.read_bytes() != raw:
        raise ValueError('Bootstrap capture differs from actual physical bytes: ' + name)
    return raw


def restore(physical, fixture, *, successor=None):
    actual_pin = identity(physical)
    if actual_pin == CURRENT:
        if successor is not None:
            raise ValueError('legacy Bootstrap source has an unexpected successor layer')
        return _restore_relation(physical, fixture)
    if actual_pin != LIVE_CURRENT or successor is None or identity(successor) != SUCCESSOR_PIN:
        raise ValueError('unreviewed Bootstrap physical source or missing successor relation')
    value = json.loads(successor)
    if (type(value) is not dict or set(value) != {'schema', 'source', 'prior', 'current',
            'record', 'provenance', 'qualification_granted'}
            or value['schema'] != _SUCCESSOR_SCHEMA or value['source'] != SOURCE
            or value['prior'] != CURRENT or value['current'] != LIVE_CURRENT
            or value['qualification_granted'] is not False):
        raise ValueError('Bootstrap service successor relation scope differs')
    prior = _record(physical, value['record'])
    if identity(prior) != CURRENT:
        raise ValueError('Bootstrap service successor does not restore the complete prior')
    historical, proof = _restore_relation(prior, fixture)
    proof['physical_source'] = {'path': SOURCE, **actual_pin}
    proof['physical_predecessor'] = {
        'schema': _SUCCESSOR_SCHEMA, 'current': dict(actual_pin), 'prior': dict(CURRENT),
        'fixture': {'path': SUCCESSOR_FIXTURE, **SUCCESSOR_PIN},
        'complete_inverse_verified': True, 'complete_forward_replay_verified': True,
        'qualification_granted': False,
    }
    return historical, proof


def capture(root, *, take=Path.read_bytes):
    root = Path(root).resolve()
    _executed_self()
    saved = {HELPER: _actual_bytes(root, HELPER, take)}
    if saved[HELPER] != _EXECUTED_SOURCE:
        raise ValueError('Bootstrap captured reader differs from its executed implementation')
    for name in (SOURCE, FIXTURE):
        saved[name] = _actual_bytes(root, name, take)
    if identity(saved[SOURCE]) == LIVE_CURRENT:
        saved[SUCCESSOR_FIXTURE] = _actual_bytes(root, SUCCESSOR_FIXTURE, take)
    historical, proof = restore(saved[SOURCE], saved[FIXTURE],
                                successor=saved.get(SUCCESSOR_FIXTURE))
    proof['reader'] = {'path': HELPER, **identity(saved[HELPER])}
    proof['captured_files'] = {name: identity(raw) for name, raw in sorted(saved.items())}
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

def _code_value(value):
    if value is None:
        return ['none']
    if value is Ellipsis:
        return ['ellipsis']
    if type(value) is bool:
        return ['bool', value]
    if type(value) is int:
        return ['int', str(value)]
    if type(value) is float:
        return ['float', value.hex()]
    if type(value) is complex:
        return ['complex', value.real.hex(), value.imag.hex()]
    if type(value) is str:
        return ['str', value]
    if type(value) is bytes:
        return ['bytes', value.hex()]
    if type(value) is tuple:
        return ['tuple', [_code_value(item) for item in value]]
    if type(value) is frozenset:
        items = [_code_value(item) for item in value]
        return ['frozenset', sorted(items, key=lambda item: json.dumps(item, sort_keys=True))]
    if type(value) is CodeType:
        if Path(value.co_filename).as_posix().split('/')[-2:] != SOURCE.split('/'):
            raise ValueError('Bootstrap code filename is outside its exact source')
        names = ('co_argcount', 'co_posonlyargcount', 'co_kwonlyargcount', 'co_nlocals',
                 'co_stacksize', 'co_flags', 'co_code', 'co_exceptiontable', 'co_names',
                 'co_varnames', 'co_freevars', 'co_cellvars', 'co_name', 'co_qualname',
                 'co_firstlineno', 'co_linetable', 'co_consts')
        return ['code', {name: _code_value(getattr(value, name)) for name in names},
                ['source', SOURCE]]
    raise ValueError('unsupported Bootstrap code constant type: ' + type(value).__name__)


def complete_code_digest(code):
    if type(code) is not CodeType:
        raise ValueError('Bootstrap runtime function has no exact code object')
    raw = json.dumps(_code_value(code), sort_keys=True, separators=(',', ':'),
                     ensure_ascii=True).encode('ascii')
    return sha256(raw).hexdigest()


def code_bindings(raw):
    retained, public = _code(raw)
    return {
        'retained': {name: sha256(retained[name].co_code).hexdigest() for name in METHODS},
        'public': {name: sha256(public['_service_bootstrap_dispatch_' + name].co_code).hexdigest()
                   for name in METHODS},
        'retained_complete': {name: complete_code_digest(retained[name]) for name in METHODS},
        'public_complete': {name: complete_code_digest(public['_service_bootstrap_dispatch_' + name])
                            for name in METHODS},
        'complete_code_schema': 'hepta.hia.bootstrap-typed-code.v1',
        'local_layouts': {name: list(retained[name].co_varnames) for name in METHODS},
    }

def graph_bindings(physical, historical):
    if identity(physical) not in (CURRENT, LIVE_CURRENT) or identity(historical) != HISTORICAL:
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
    root = Path(root).resolve()
    _executed_self()
    if type(saved) is not dict or SOURCE not in saved:
        raise ValueError('Bootstrap terminal capture is incomplete')
    required = {HELPER, SOURCE, FIXTURE}
    actual_pin = identity(saved[SOURCE])
    if actual_pin == LIVE_CURRENT:
        required.add(SUCCESSOR_FIXTURE)
    elif actual_pin != CURRENT:
        raise ValueError('Bootstrap terminal service is outside its reviewed source domain')
    if (set(saved) != required or saved[HELPER] != _EXECUTED_SOURCE
            or identity(saved[FIXTURE]) != FIXTURE_PIN
            or (SUCCESSOR_FIXTURE in saved and identity(saved[SUCCESSOR_FIXTURE]) != SUCCESSOR_PIN)):
        raise ValueError('Bootstrap terminal source closure is incomplete or unreviewed')
    for name, raw in saved.items():
        if type(raw) is not bytes or _actual_bytes(root, name, take) != raw:
            raise ValueError('Bootstrap physical source changed during observation: ' + name)
    _executed_self()
