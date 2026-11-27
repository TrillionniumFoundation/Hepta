"""Data-only native cold and authoring-custody readback for component evidence.

No product, generator, builder or oracle is imported. The caller supplies its
independent physical capture function and retains its terminal reread checks.
This does not turn development builds into current-cold qualifications.
"""
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path

from tools.hia_cold_compiler import MAX_REPORT_BYTES, _regular, read_native_locations
from tools.hia_component_input_custody import verify_component_custody
from tools.hia_native_cold_admission import SCHEMA, admit_native_report, read_json
from tools.hia_native_worker_source_authority import checked_paths


AUTHORITY = 'docs/HIA_NATIVE_SOURCE_AUTHORITY.json'
CONTRACT = 'docs/HIA_SELFHOST_CORE_SUPPORT.json'
METADATA = 'docs/HIA_NATIVE_SELFHOST_METADATA.json'
# Independent 1107-byte x86-64 flat ABI observer, retained by the original gate.
OBSERVER_SHA256 = '830b80e8b1acf852cb7cb103abe453cfdd800b34d6f992e5396769cb6c7f8e30'


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _relative(name):
    _require(type(name) is str and bool(name) and not Path(name).is_absolute()
             and all(part not in ('', '.', '..', '.git') for part in name.split('/'))
             and all(32 <= ord(char) < 127 and char not in '\\"' for char in name),
             'component input is not a safe relative source path')
    return name


def _physical(path, read, *, allow_empty=False, limit=64 * 1024 * 1024):
    raw = _regular(Path(path).absolute(), limit, allow_empty=allow_empty)
    _require(read(Path(path)) == raw, 'physical component input changed while capturing it')
    return raw


def read_native_cold(root, cold_path, compiler_path, compiler_bytes, *, read):
    """Rebuild the exact native contract from data, then apply every cold check."""
    root, cold_path, compiler_path = Path(root), Path(cold_path).absolute(), Path(compiler_path).absolute()
    cold_raw = _physical(cold_path, read, limit=MAX_REPORT_BYTES)
    cold = read_json(cold_raw)
    _require(type(cold) is dict and cold.get('schema') == SCHEMA,
             'native readback requires the original native cold report')
    authority_raw = _physical(root / AUTHORITY, read)
    authority = read_json(authority_raw)
    _require(type(authority) is dict and set(authority) == {'schema', 'paths'}
             and authority['schema'] == 'hepta.hia.native-source-authority.v1',
             'native source authority shape differs')
    paths = checked_paths(authority['paths'])
    _require({AUTHORITY, CONTRACT, METADATA} <= set(paths),
             'native authority omits its complete contract or metadata')
    physical = {name: _physical(root / name, read, allow_empty=True) for name in paths}
    _require(physical[AUTHORITY] == authority_raw, 'native authority changed before source capture')
    sources = {name: sha256(raw).hexdigest() for name, raw in physical.items()}
    metadata = read_json(physical[METADATA])
    _require(type(metadata) is dict and type(metadata.get('source_identity')) is dict
             and metadata['source_identity'].get('files') == {}
             and type(metadata['source_identity'].get('roles')) is dict
             and metadata['source_identity']['roles'].get('authoring_authority') == AUTHORITY,
             'native metadata does not declare its separate source domain')
    expected = deepcopy(metadata)
    expected['source_identity']['files'] = {name: digest for name, digest in sources.items()
                                           if name != CONTRACT}
    contract = read_json(physical[CONTRACT])
    _require(_canonical(contract) == _canonical(expected),
             'current native contract differs from its complete physical source closure')
    observer_hex = cold.get('native_flat_observer_hex')
    _require(type(observer_hex) is str and len(observer_hex) == 2214,
             'native observer has an invalid physical extent')
    try:
        observer = bytes.fromhex(observer_hex)
    except ValueError as exc:
        raise ValueError('native observer is not canonical bytes') from exc
    _require(observer.hex() == observer_hex and sha256(observer).hexdigest() == OBSERVER_SHA256,
             'native observer differs from the independently pinned ABI reference')
    admit_native_report(compiler_bytes, cold_raw, contract=contract, sources=sources,
                        observer_bytes=observer)
    index_raw = _physical(cold_path.with_suffix('.generations.json'), read, limit=MAX_REPORT_BYTES)
    generations = read_native_locations(cold_path, cold_raw, index_raw)
    _require(generations[-1] == (compiler_path, compiler_bytes),
             'component selected another physical compiler than the admitted B3')
    for path, raw in generations:
        _require(read(path) == raw, 'physical cold compiler changed during readback')
    _require(read(root / AUTHORITY) == physical[AUTHORITY] and read(cold_path) == cold_raw
             and read(cold_path.with_suffix('.generations.json')) == index_raw,
             'native cold authority changed during independent readback')
    return sources


def native_cold_compiler(root, cold_path, *, read):
    """Locate B3, then independently admit its complete native source domain."""
    cold_path = Path(cold_path).absolute()
    cold_raw = _physical(cold_path, read, limit=MAX_REPORT_BYTES)
    index_raw = _physical(cold_path.with_suffix('.generations.json'), read, limit=MAX_REPORT_BYTES)
    images = read_native_locations(cold_path, cold_raw, index_raw)
    path, raw = images[-1]
    sources = read_native_cold(root, cold_path, path, raw, read=read)
    return path, raw, sources


def read_component_inputs(root, build, compiler_bytes, cold_path, *, read):
    """Bind builder inputs after the caller's complete cold-admission check."""
    root = Path(root)
    names = build.get('component_inputs')
    _require(type(names) is dict and bool(names), 'component build has no complete input declaration')
    captured = {name: _physical(root / _relative(name), read, allow_empty=True) for name in names}
    _require(all(type(digest) is str and sha256(captured[name]).hexdigest() == digest
                 for name, digest in names.items()), 'physical component input differs from its build')
    if cold_path is None:
        _require(build.get('source_manifest') is None and build.get('cold_report_sha256') is None
                 and 'component_input_custody' not in build,
                 'development component invented cold or native authoring authority')
        return captured
    cold_raw = _physical(Path(cold_path), read, limit=MAX_REPORT_BYTES)
    cold = read_json(cold_raw)
    _require(type(cold) is dict, 'component cold report is not an object')
    _require(_canonical(build.get('source_manifest')) == _canonical(cold.get('source_manifest'))
             and build.get('cold_report_sha256') == sha256(cold_raw).hexdigest(),
             'component build does not bind the exact admitted cold bytes')
    if cold.get('schema') == SCHEMA:
        _require('component_input_custody' in build, 'native component omitted separate authoring custody')
        verify_component_custody(build['component_input_custody'], compiler_bytes, cold_raw,
                                 cold['source_manifest'], captured, root=root)
    else:
        _require('component_input_custody' not in build
                 and all(cold['source_manifest'].get(name) == digest for name, digest in names.items()),
                 'legacy component input is not in the complete admitted cold source')
    return captured
