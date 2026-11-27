"""Read complete file-capture caller evidence against the same current cold build.

This reader executes no product, test, compiler, VM or native entry. The original
qualifier owns the complete 112-method run. Readback binds its retained raw files
and terminal CLI record; it does not manufacture process or whole-stack custody.
"""
from __future__ import annotations
import argparse
import ast
from hashlib import sha256
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ''):
    sys.path.insert(0, str(ROOT))

from tools.hia_native_cold_admission import SCHEMA as NATIVE_COLD_SCHEMA
from tools.hia_component_cold_readback import (
    native_cold_compiler, native_cold_inputs, read_component_inputs,
)
from tools.hia_cold_compiler import NATIVE_CUSTODY_INPUTS
from tools.hia_frozen_component_sources import history_inverse
from tools.hia_native_cold_caller_history import cold_caller_source
from tools.hia_current_store_source_history import (
    restore_reader_evaluation_test, reviewed_source,
)
from tools import hia_current_caller_source_history as current_history

CONTRACT = 'docs/HIA_SELFHOST_CORE_SUPPORT.json'
COLD_PROFILE = 'selfhost-core-linux-x86_64-v92p-native-closed-output-before-exec'
FIXTURE = 'tests/fixtures/hia_emission_original_73f1634/original-freeze.json'
FIXTURE_SHA256 = 'dec08c099ea1d262f1a3d32dc34801c816484bda6724fac60f5a8a1d5d8c4048'
SOURCE = 'examples/hia_bootstrap/store_file_capture.hepta'
QUALIFIER = 'tools/qualify_hia_store_file_capture_callers.py'
READER = 'tools/read_hia_store_file_capture_callers.py'
COLD_CHECKS = {
    'export_manifest_matches_qualification', 'isolated_python_without_site',
    'nested_full_qualification_pass', 'nested_process_exit_zero',
    'no_ancestor_git_identity', 'no_bytecode_cache_created',
    'no_inherited_home_or_python_cache', 'no_inherited_seed_or_successor_images',
    'origin_hashes_preserved', 'owned_process_tree_cleanup_confirmed',
    'source_export_hashes_preserved',
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def integer(value, *, minimum=0, expected=None):
    require(type(value) is int and value >= minimum
            and (expected is None or value == expected), 'exact integer evidence differs')
    return value


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False,
                      separators=(',', ':')).encode('ascii')


def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, 'duplicate evidence JSON member')
        result[key] = value
    return result


def digest(raw):
    return sha256(raw).hexdigest()


def pin(raw):
    return {'bytes': len(raw), 'sha256': digest(raw)}


def absolute(path):
    path = Path(os.path.abspath(path))
    require(not any(item.is_symlink() for item in (path, *path.parents)),
            'evidence or source path traverses a symbolic link')
    return path


def relative(root, name):
    require(type(name) is str and name and PurePosixPath(name).as_posix() == name
            and not PurePosixPath(name).is_absolute()
            and all(part not in ('', '.', '..') for part in name.split('/')),
            'source name is not a canonical relative file')
    return absolute(root / name)


class Captures:
    def __init__(self):
        self.raw = {}

    def take(self, path, expected_sha=None):
        path = absolute(path)
        require(stat.S_ISREG(path.stat().st_mode), 'captured member is not a regular file')
        raw = path.read_bytes()
        if expected_sha is not None:
            require(type(expected_sha) is str and digest(raw) == expected_sha,
                    'consumed raw bytes differ from their prior SHA: ' + str(path))
        if path in self.raw:
            require(raw == self.raw[path], 'previously consumed file changed: ' + str(path))
        self.raw[path] = raw
        return raw

    def json(self, path, expected_sha=None):
        raw = self.take(path, expected_sha)
        return json.loads(raw, object_pairs_hook=pairs,
                          parse_constant=lambda name: (_ for _ in ()).throw(ValueError(name)))

    def unchanged(self):
        for path, raw in self.raw.items():
            require(self.take(path) == raw, 'consumed raw file changed at terminal')


def literal_assignment(raw, name):
    """Read constant source catalogs, including explicit named tuple expansions."""
    module = ast.parse(raw)
    active = set()

    def declaration(key):
        require(key not in active, 'source declaration contains a cycle: ' + key)
        nodes = [node for node in module.body if isinstance(node, ast.Assign)
                 and any(isinstance(target, ast.Name) and target.id == key for target in node.targets)]
        require(len(nodes) == 1 and len(nodes[0].targets) == 1,
                'source declaration is not unique: ' + key)
        require(not any(isinstance(node, (ast.AugAssign, ast.AnnAssign))
                        and isinstance(node.target, ast.Name) and node.target.id == key
                        for node in module.body), 'source declaration has another write: ' + key)
        active.add(key)
        try:
            return value(nodes[0].value)
        finally:
            active.remove(key)

    def value(node):
        if isinstance(node, ast.Constant) and type(node.value) is str:
            return node.value
        if isinstance(node, ast.Name):
            return declaration(node.id)
        if isinstance(node, (ast.Tuple, ast.List)):
            result = []
            for item in node.elts:
                if isinstance(item, ast.Starred):
                    expanded = value(item.value)
                    require(type(expanded) in (tuple, list), 'source expansion is not a literal sequence')
                    result.extend(expanded)
                else:
                    result.append(value(item))
            return tuple(result) if isinstance(node, ast.Tuple) else result
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left, right = value(node.left), value(node.right)
            require(type(left) is type(right) and type(left) in (str, tuple, list),
                    'source literal concatenation types differ')
            return left + right
        raise ValueError('source catalog contains a nonliteral expression')

    return declaration(name)

def source_map(repository, captures):
    contract = captures.json(repository / CONTRACT)
    contract_raw = captures.raw[absolute(repository / CONTRACT)]
    files = contract['source_identity']['files']
    require(type(files) is dict and files, 'current source contract is empty')
    from tools.hia_release_contract import source_domain, validate_release_contract
    if source_domain(contract) == 'native':
        require(repository == ROOT and validate_release_contract(repository) == contract,
                'native readback must bind this exact current source checkout')
        for name, expected in files.items():
            captures.take(relative(repository, name), expected)
        require(SOURCE in files and READER not in files and QUALIFIER not in files,
                'native implementation or separate host observation domain differs')
        return {**files, CONTRACT: digest(contract_raw)}
    source_decl = captures.take(repository / 'tools/hia_selfhost_contract.py')
    declared = literal_assignment(source_decl, 'SOURCE_FILES')
    require(type(declared) in (tuple, list)
            and all(type(name) is str for name in declared), 'SOURCE_FILES declaration differs')
    actual_names = set(declared) | {
        path.relative_to(repository).as_posix() for path in (repository / 'hepta').rglob('*.py')}
    require(set(files) == actual_names, 'source contract omits or adds a current source member')
    for name, expected in files.items():
        captures.take(relative(repository, name), expected)
    require(READER in files and QUALIFIER in files and SOURCE in files,
            'caller, reader or authored HIA source absent from current source closure')
    return {**files, CONTRACT: digest(contract_raw)}


WORKER_CALLER = 'tests/test_hia_worker_native_helpers.py'
WORKER_CALLER_FIXTURE = 'tests/fixtures/store_caller_worker_helpers_successor.json'
WORKER_CALLER_FIXTURE_SHA256 = '168ef69fadf672e41f3dd717d3d79e54fcd1af70105d2e3552687b72af824904'
WORKER_CALLER_CURRENT_SHA256 = '4fef9e2f0a8188f5f3a6c81e522b5babd3a1f0c0a88f58e286cdf762433caab3'


def hosted_source_map(repository, captures, original):
    """Reproduce the producer's hosted source inventory without importing it."""
    declared = literal_assignment(captures.take(repository / 'tools/hia_selfhost_contract.py'),
                                  'SOURCE_FILES')
    require(type(declared) in (tuple, list) and all(type(name) is str for name in declared),
            'hosted SOURCE_FILES declaration differs')
    names = set(declared) | {
        path.relative_to(repository).as_posix() for path in (repository / 'hepta').rglob('*.py')}
    shadow = repository / 'rust/hia-core-shadow'
    names.update(path.relative_to(repository).as_posix() for path in shadow.rglob('*.rs')
                 if path.relative_to(shadow).parts[0] != 'target')
    names.update((shadow / name).relative_to(repository).as_posix()
                 for name in ('Cargo.toml', 'Cargo.lock'))
    names.update(builder_inputs(repository, captures))
    names.update(row['path'] for row in original['callers'].values())
    names.update((FIXTURE, QUALIFIER, 'tools/qualify_hia_emission_callers.py'))
    require({READER, QUALIFIER, SOURCE} <= names,
            'hosted source inventory omits caller, reader or authored HIA')
    return {name: digest(captures.take(relative(repository, name))) for name in sorted(names)}


def reviewed_terminal_source(repository, captures, name):
    physical = captures.take(relative(repository, name))
    known = (_TERMINAL_OLD[name], _TERMINAL_CURRENT[name])
    if pin(physical) in known:
        if name == _TERMINAL_EVALUATION:
            restore_reader_evaluation_test(physical, root=repository, take=captures.take)
        return physical
    return reviewed_source(repository, name, physical, take=captures.take)


def worker_caller_source(repository, captures, raw, expected):
    """Restore the whole original helper caller from its fixed five-splice relation."""
    frozen = captures.json(relative(repository, WORKER_CALLER_FIXTURE),
                           WORKER_CALLER_FIXTURE_SHA256)
    require(type(frozen) is dict
            and set(frozen) == {'schema', 'path', 'original_commit', 'record'}
            and frozen['schema'] == 'hepta.hia.store-caller-worker-helpers-successor.v1'
            and frozen['path'] == WORKER_CALLER and frozen['original_commit'] == '73f16346',
            'complete worker caller relation scope differs')
    record = frozen['record']
    original = {'bytes': record['old_bytes'], 'sha256': expected}
    history_inverse(raw, record, original)
    return {'physical': pin(raw), 'original': original,
            'fixture': WORKER_CALLER_FIXTURE,
            'fixture_sha256': WORKER_CALLER_FIXTURE_SHA256,
            'whole_original_restored_and_replayed': True}


def cold_build(cold_path, captures, current, *, repository=None):
    cold = captures.json(cold_path)
    cold_raw = captures.raw[absolute(cold_path)]
    from tools.hia_native_cold_admission import SCHEMA
    if type(cold) is dict and cold.get('schema') == SCHEMA:
        inputs = native_cold_inputs(ROOT if repository is None else repository,
                                    cold_path, read=captures.take)
        require(inputs.report_bytes == cold_raw and canonical(inputs.sources) == canonical(current),
                'native cold source/report differs from the current readback')
        for path, raw in inputs.files:
            require(captures.take(path) == raw, 'native cold input changed during readback')
        inputs.unchanged()
        return inputs.compiler_bytes, digest(cold_raw)
    require(cold['schema'] == 'hepta.hia.selfhost-cold-replay.v1'
            and cold['profile'] == COLD_PROFILE
            and cold['status'] == 'COLD_SELFHOST_REPLAY_PASS',
            'matching current-source cold qualification is required')
    integer(cold['returncode'], expected=0)
    integer(cold['qualification_wall_limit_seconds'], expected=180)
    integer(cold['cleanup_wall_limit_seconds'], expected=3)
    require(type(cold['checks']) is dict and set(cold['checks']) == COLD_CHECKS
            and all(value is True for value in cold['checks'].values())
            and canonical(cold['source_manifest']) == canonical(current),
            'cold checks or complete source identity differ')
    owner = cold['process_owner']
    require(owner['status'] == 'OWNED_PROCESS_COMPLETED'
            and owner['exit_observed_before_deadline'] is True
            and owner['timed_out'] is False and owner['cleanup']['complete'] is True,
            'cold owned process did not finish within its original deadline')
    integer(owner['returncode'], expected=0)
    nested = captures.json(absolute(cold['nested_report']), cold['nested_report_sha256'])
    require(nested['status'] == 'SELF_HOSTED_FIXED_CORE_PASS'
            and canonical(nested['source_manifest']) == canonical(current)
            and type(nested['generations']) is list and len(nested['generations']) == 3,
            'cold nested fixed-point source or generation list differs')
    images = []
    for generation in nested['generations']:
        raw = captures.take(absolute(generation['produced_image']), generation['produced_sha256'])
        integer(generation['produced_bytes'], expected=len(raw))
        images.append(raw)
    require(images[0] == images[1] == images[2]
            and cold['generation_sha256'] == [digest(images[-1])] * 3,
            'cold three-generation compiler identity differs')
    return images[-1], digest(cold_raw)


def builder_inputs(repository, captures):
    raw = captures.take(repository / 'tools/build_hia_store_file_capture.py')
    module = ast.parse(raw)
    bindings = {}
    def value(node, names):
        if isinstance(node, ast.Constant) and type(node.value) is str:
            return node.value
        if isinstance(node, ast.Name) and node.id in names:
            return names[node.id]
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return value(node.left, names) + value(node.right, names)
        if isinstance(node, (ast.Tuple, ast.List)):
            result = []
            for item in node.elts:
                if isinstance(item, ast.Starred):
                    result.extend(value(item.value, names))
                else:
                    result.append(value(item, names))
            return tuple(result)
        if isinstance(node, ast.GeneratorExp) and len(node.generators) == 1:
            clause = node.generators[0]
            require(isinstance(clause.target, ast.Name) and not clause.is_async
                    and not clause.ifs, 'builder input generator shape differs')
            return tuple(value(node.elt, {**names, clause.target.id: item})
                         for item in value(clause.iter, names))
        raise ValueError('unexpected builder input expression')
    for node in module.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            if isinstance(target, ast.Name) and target.id in ('SOURCE_NAME', 'ORIGINAL_DIRECTORY', 'INPUTS'):
                bindings[target.id] = value(node.value, bindings)
    inputs = bindings['INPUTS']
    require(type(inputs) is tuple and len(inputs) == len(set(inputs))
            and READER in inputs, 'complete builder input declaration differs')
    return inputs


def component_build(repository, evidence, captures, current, compiler, cold_sha,
                    *, native_cold_path=None, native_sources=None):
    require((native_cold_path is None) == (native_sources is None),
            'native cold path and source authority must be paired')
    directory = absolute(evidence / 'qualified')
    manifest = captures.json(directory / 'manifest.json')
    build = captures.json(directory / 'build.json')
    require(manifest['schema'] == 'hepta.hia.store-file-capture.v2'
            and build['schema'] == 'hepta.hia.store-file-capture-build.v2'
            and build['scope'] == 'MATCHING_SOURCE_COLD_COMPONENT'
            and build['cold_report_sha256'] == cold_sha
            and canonical(build['source_manifest']) == canonical(
                current if native_sources is None else native_sources)
            and canonical(build['manifest']) == canonical(manifest),
            'caller build is not the same current cold component')
    inputs = builder_inputs(repository, captures)
    require(canonical(build['component_inputs']) == canonical({name: current[name] for name in inputs}),
            'complete component inputs are not the same frozen source')
    if native_cold_path is not None:
        require(type(build.get('development_inputs')) is dict
                and set(build['development_inputs']) == set(NATIVE_CUSTODY_INPUTS),
                'native component development dependencies differ')
        consumed = read_component_inputs(repository, build, compiler, native_cold_path,
                                         read=captures.take)
        require(set(consumed) == set(inputs), 'native custody omits or adds a builder input')
        admitted = native_cold_inputs(repository, native_cold_path, read=captures.take)
        require(admitted.compiler_bytes == compiler and admitted.sources == native_sources,
                'component compiler or source differs from its admitted native cold')
        require(build['component_input_custody']['source_head'] == admitted.source_head,
                'component authoring commit differs from the native cold campaign')
        admitted.unchanged()
    source = captures.take(repository / SOURCE, current[SOURCE])
    image_path = relative(directory, manifest['image_path'])
    require(image_path.parent == directory, 'component image escapes its bundle')
    image = captures.take(image_path, manifest['image_sha256'])
    output = captures.take(directory / 'store_file_capture.output.bin')
    receipt = build['native_compile_receipt']
    require(canonical(captures.json(directory / 'store_file_capture.receipt.json')) == canonical(receipt),
            'component compile receipt differs from the retained raw receipt')
    size = integer(receipt['core_u32'], minimum=1)
    integer(receipt['result_u64'], expected=size)
    integer(receipt['abi_status'], expected=0)
    integer(receipt['input_bytes'], expected=len(source))
    integer(receipt['produced_bytes'], expected=size)
    require(size <= len(output) <= 1 << 20 and image == output[:size]
            and receipt['status'] == 'returned'
            and receipt['format'] == 'flat-x86-64'
            and receipt['return_encoding'] == 'zero-extended-u32'
            and receipt['source_unchanged'] is True
            and type(receipt['forbidden_compiler_modules_loaded']) is list
            and receipt['forbidden_compiler_modules_loaded'] == []
            and receipt['output_sha256'] == digest(output)
            and receipt['artifact_sha256'] == receipt['image_sha256'] == digest(compiler)
            and receipt['input_sha256'] == receipt['source_sha256'] == digest(source)
            and receipt['produced_sha256'] == manifest['image_sha256'] == digest(image)
            and absolute(receipt['produced_image']) == image_path
            and manifest['compiler_sha256'] == digest(compiler)
            and manifest['source_sha256'] == digest(source),
            'complete native pack return, image or compiler custody differs')
    return directory, manifest

# These immutable test successors do not expand production source admission.
_TERMINAL_TRANSPORT = 'tests/test_hia_native_transport_failures.py'
_TERMINAL_DELIVERY = 'tests/test_hia_native_delivery.py'
_TERMINAL_EVALUATION = 'tests/test_hia_evaluation_native.py'
_TERMINAL_PAIR = 'tests/fixtures/native_transport_worker_terminal_v2_provenance.json'
_TERMINAL_PAIR_PIN = {'bytes': 38004, 'sha256': '15f48d98210006523a800be1a743a7f6ce8e427838fc24d157d9bf317d680957'}
_TERMINAL_EVALUATION_PROOF = 'tests/fixtures/evaluation_worker_terminal_v2_provenance.json'
_TERMINAL_EVALUATION_PROOF_PIN = {'bytes': 16316, 'sha256': '49aadebc293d7051b281db3e5a589f00d86098a13a313b9c7b50f76373a2b2c9'}
_TERMINAL_OLD = {
    _TERMINAL_TRANSPORT: {'bytes': 32859, 'sha256': '6c9505646078ebc03f4f44b35526d31b5534d9766ffbf408f69b9fc12ee7b484'},
    _TERMINAL_DELIVERY: {'bytes': 12700, 'sha256': 'cd56657339898843d78f705872be63625395f58479c11f9784e7e0e7ccccd541'},
    _TERMINAL_EVALUATION: {'bytes': 43338, 'sha256': '22433d0de525210953c8ab23559b1cc7b3bd3575cfaa80fe2618415f03623ede'},
}
_TERMINAL_CURRENT = {
    _TERMINAL_TRANSPORT: {'bytes': 37466, 'sha256': '6c7dfe5f723a951fe0c24d05f4f52b579149de71c3e112ba735af2c496d9a084'},
    _TERMINAL_DELIVERY: {'bytes': 13263, 'sha256': '09692f4ce91da30ad3aac0b009e15e520058022cd01af8fdf1a7dd8811aab64b'},
    _TERMINAL_EVALUATION: {'bytes': 49105, 'sha256': '673b1e330b48df5915a4a544188397e33055ac023986cb136e8b067e4574b9d3'},
}
_TERMINAL_ORIGINALS = {
    'native': ('tests/fixtures/native_delivery_original_9c46166.json',
               {'bytes': 71708, 'sha256': 'a1f82e1c955ece21319cc49a0e3834658a2eeb0be7636d6f13690e1d6b83dea7'}),
    'store': ('tests/fixtures/store_native_delivery_original_c019.json',
              {'bytes': 173802, 'sha256': '5fccb548e4b98fd6de5ad2eb4dc88e1adac41112b1f2c850e8254d6b10853b54'}),
}


def terminal_inverse(raw, original_pin, current_pin, splices):
    """Independent segment construction; never import a producer or test helper."""
    require(type(raw) is bytes and pin(raw) == current_pin
            and type(splices) is list and splices, 'terminal current whole-source pin differs')
    old_end = new_end = displacement = 0
    pieces, entries = [], []
    for item in splices:
        require(type(item) is dict
                and set(item) == {'old_offset', 'new_offset', 'old_hex', 'new_hex'},
                'terminal exact splice shape differs')
        old_at, new_at = item['old_offset'], item['new_offset']
        require(type(old_at) is int and old_at >= old_end
                and type(new_at) is int and new_at >= new_end
                and old_at + displacement == new_at, 'terminal disjoint splice offsets differ')
        values = []
        for key in ('old_hex', 'new_hex'):
            text = item[key]
            require(type(text) is str and text
                    and re.fullmatch(r'(?:[0-9a-f]{2})+', text) is not None,
                    'terminal splice bytes are not canonical hexadecimal')
            values.append(bytes.fromhex(text))
        before, after = values
        require(before != after and new_at + len(after) <= len(raw)
                and raw[new_at:new_at + len(after)] == after,
                'terminal exact current splice bytes differ')
        pieces.extend((raw[new_end:new_at], before))
        entries.append((old_at, new_at, before, after))
        old_end, new_end = old_at + len(before), new_at + len(after)
        displacement += len(after) - len(before)
    pieces.append(raw[new_end:])
    restored = b''.join(pieces)
    require(pin(restored) == original_pin, 'terminal inverse does not restore the complete original')
    replay, old_end = [], 0
    for old_at, new_at, before, after in entries:
        require(restored[old_at:old_at + len(before)] == before,
                'terminal reconstructed original splice differs')
        replay.extend((restored[old_end:old_at], after))
        old_end = old_at + len(before)
    replay.append(restored[old_end:])
    require(b''.join(replay) == raw, 'terminal complete forward replay differs')
    return restored


def terminal_source_admission(repository, captures, original):
    records = {row['path']: row['sha256'] for row in original['callers'].values()}
    require(len(records) == 17
            and records.get(_TERMINAL_TRANSPORT) == _TERMINAL_OLD[_TERMINAL_TRANSPORT]['sha256']
            and records.get(_TERMINAL_EVALUATION) == _TERMINAL_OLD[_TERMINAL_EVALUATION]['sha256'],
            'terminal original17 source authority differs')
    original_values, authority_pins = {}, {}
    for kind, (name, expected) in _TERMINAL_ORIGINALS.items():
        path = relative(repository, name)
        value = captures.json(path, expected['sha256'])
        require(pin(captures.raw[path]) == expected, 'terminal independent original authority differs')
        original_values[kind], authority_pins[name] = value, expected
        for source in (_TERMINAL_TRANSPORT, _TERMINAL_EVALUATION):
            require(canonical(value['unchanged_files'][source]) == canonical(_TERMINAL_OLD[source]),
                    'terminal independent old test-source pin differs')
    require(canonical(original_values['store']['shared_dependency_review'][_TERMINAL_DELIVERY])
            == canonical(_TERMINAL_OLD[_TERMINAL_DELIVERY]),
            'terminal independent original Delivery pin differs')
    paths = (_TERMINAL_TRANSPORT, _TERMINAL_DELIVERY)
    raw_pair = {name: reviewed_terminal_source(repository, captures, name) for name in paths}
    legacy = all(pin(raw_pair[name]) == _TERMINAL_OLD[name] for name in paths)
    allowed, provenance = {}, {}
    state = 'EXACT_LEGACY_PAIR'
    pair = None
    if not legacy:
        path = relative(repository, _TERMINAL_PAIR)
        pair = captures.json(path, _TERMINAL_PAIR_PIN['sha256'])
        require(pin(captures.raw[path]) == _TERMINAL_PAIR_PIN
                and type(pair) is dict
                and pair['schema'] == 'hepta.hia.native-transport-terminal-source.v2'
                and pair['state'] == 'FROZEN_EXACT_TWO_SOURCE_SUCCESSOR'
                and type(pair['source_count']) is int and pair['source_count'] == 2
                and type(pair['production_composition_source_count']) is int
                and pair['production_composition_source_count'] == 13
                and set(pair['files']) == set(paths),
                'terminal pair provenance scope differs')
        for name, definition in ((_TERMINAL_TRANSPORT, '_child_store_worker'),
                                 (_TERMINAL_DELIVERY, 'admit_originals')):
            record = pair['files'][name]
            require(type(record) is dict
                    and set(record) == {'old', 'new', 'definition', 'offset', 'old_hex', 'new_hex'}
                    and canonical(record['old']) == canonical(_TERMINAL_OLD[name])
                    and canonical(record['new']) == canonical(_TERMINAL_CURRENT[name])
                    and record['definition'] == definition,
                    'terminal pair exact old/new source relation differs')
            terminal_inverse(raw_pair[name], _TERMINAL_OLD[name], _TERMINAL_CURRENT[name], [{
                'old_offset': record['offset'], 'new_offset': record['offset'],
                'old_hex': record['old_hex'], 'new_hex': record['new_hex']}])
        provenance[_TERMINAL_PAIR] = dict(_TERMINAL_PAIR_PIN)
        allowed[_TERMINAL_TRANSPORT] = {
            'original': dict(_TERMINAL_OLD[_TERMINAL_TRANSPORT]),
            'current': dict(_TERMINAL_CURRENT[_TERMINAL_TRANSPORT]),
            'provenance_path': _TERMINAL_PAIR, 'provenance': dict(_TERMINAL_PAIR_PIN),
            'definition': '_child_store_worker', 'exact_splices': 1,
            'whole_original_restored_and_replayed': True, 'production_source_exception': False}
        state = 'EXACT_TERMINAL_V2_PAIR'
    evaluation = reviewed_terminal_source(repository, captures, _TERMINAL_EVALUATION)
    if pin(evaluation) != _TERMINAL_OLD[_TERMINAL_EVALUATION]:
        require(not legacy, 'terminal Evaluation successor requires the complete new pair')
        path = relative(repository, _TERMINAL_EVALUATION_PROOF)
        value = captures.json(path, _TERMINAL_EVALUATION_PROOF_PIN['sha256'])
        require(pin(captures.raw[path]) == _TERMINAL_EVALUATION_PROOF_PIN
                and type(value) is dict and set(value) == {
                    'schema', 'state', 'test_source_count', 'production_composition_source_count',
                    'path', 'original_inventories', 'pair_fixture', 'required_pair', 'record'}
                and value['schema'] == 'hepta.hia.evaluation-terminal-test-source.v2'
                and value['state'] == 'FROZEN_EXACT_EVALUATION_TEST_SUCCESSOR'
                and type(value['test_source_count']) is int and value['test_source_count'] == 3
                and type(value['production_composition_source_count']) is int
                and value['production_composition_source_count'] == 13
                and value['path'] == _TERMINAL_EVALUATION
                and canonical(value['original_inventories']) == canonical({
                    kind: {'path': row[0], **row[1]} for kind, row in _TERMINAL_ORIGINALS.items()})
                and canonical(value['pair_fixture']) == canonical({
                    'path': _TERMINAL_PAIR, **_TERMINAL_PAIR_PIN})
                and canonical(value['required_pair']) == canonical({
                    name: _TERMINAL_CURRENT[name] for name in paths}),
                'terminal Evaluation provenance scope differs')
        record = value['record']
        definition = 'EvaluationNativeTests.test_actual_installed_worker_replay_process_loss_and_source_pinning'
        require(type(record) is dict and set(record) == {'old', 'new', 'definition', 'splices'}
                and canonical(record['old']) == canonical(_TERMINAL_OLD[_TERMINAL_EVALUATION])
                and canonical(record['new']) == canonical(_TERMINAL_CURRENT[_TERMINAL_EVALUATION])
                and record['definition'] == definition
                and type(record['splices']) is list and len(record['splices']) == 7,
                'terminal Evaluation exact old/new source relation differs')
        terminal_inverse(evaluation, _TERMINAL_OLD[_TERMINAL_EVALUATION],
                         _TERMINAL_CURRENT[_TERMINAL_EVALUATION], record['splices'])
        provenance[_TERMINAL_EVALUATION_PROOF] = dict(_TERMINAL_EVALUATION_PROOF_PIN)
        allowed[_TERMINAL_EVALUATION] = {
            'original': dict(_TERMINAL_OLD[_TERMINAL_EVALUATION]),
            'current': dict(_TERMINAL_CURRENT[_TERMINAL_EVALUATION]),
            'provenance_path': _TERMINAL_EVALUATION_PROOF,
            'provenance': dict(_TERMINAL_EVALUATION_PROOF_PIN),
            'definition': definition, 'exact_splices': 7,
            'whole_original_restored_and_replayed': True, 'production_source_exception': False}
        state = 'EXACT_TERMINAL_V2_PAIR_WITH_EVALUATION_V2'
    require(set(allowed) <= {_TERMINAL_TRANSPORT, _TERMINAL_EVALUATION},
            'terminal exception exceeds the two reviewed test sources')
    proof = {'schema': 'hepta.hia.caller-terminal-source-readback.v1',
             'scope': 'ORIGINAL_SOURCE_ADMISSION_ONLY', 'state': state,
             'original_source_count': 17, 'production_composition_source_count': 13,
             'fixed_caller_inventory': {'path': FIXTURE, 'bytes': 59973, 'sha256': FIXTURE_SHA256},
             'independent_original_authorities': authority_pins,
             'captured_provenance': provenance,
             'original_expected_sha256': records,
             'reviewed_test_source_adjustments': allowed,
             'delivery_pair_dependency': pin(raw_pair[_TERMINAL_DELIVERY]),
             'production_source_exceptions': [],
             'producer_or_test_helper_imported': False,
             'terminal_reread_deferred_to_outer_captures': True,
             'whole_caller_readback_qualified': False}
    return allowed, proof



_DIAGNOSTIC_PATH = 'tests/test_hia_agent_native_tools.py'
_DIAGNOSTIC_FIXTURE = 'tests/fixtures/caller_deadline_diagnostics_v1.json'
_DIAGNOSTIC_SHA = '53aff1f370ac337d6246a0179f8b6d5c346fcc44ffd7f2187c515c95c663f97c'
_DIAGNOSTIC_OLD = {'bytes': 45385, 'sha256': 'c7a3b2b486e55a600ddd5e691729e8cddc6acd5935e5aad337e27c1f20be856a'}
_DIAGNOSTIC_CURRENT = {'bytes': 46518, 'sha256': 'b98c24327639363d266eb5e263c042e0a20d82a8f2e8cc08ffafb8f34f73f355'}


def diagnostic_source_admission(raw, expected, provenance):
    """Independently reconstruct the frozen caller; import no producer/helper."""
    require(expected == _DIAGNOSTIC_OLD['sha256']
            and type(provenance) is bytes and digest(provenance) == _DIAGNOSTIC_SHA,
            'deadline diagnostics original authority or provenance differs')
    value = json.loads(provenance)
    require(type(value) is dict and set(value) == {
                'schema', 'state', 'path', 'original', 'current', 'definition',
                'original_deadline_seconds', 'original_native_budget_ms',
                'original_method_ids_unchanged', 'production_source_exception', 'splices'}
            and value['schema'] == 'hepta.hia.caller-deadline-diagnostics-source.v1'
            and value['state'] == 'FROZEN_EXACT_FAILURE_DIAGNOSTICS_SUCCESSOR'
            and value['path'] == _DIAGNOSTIC_PATH
            and canonical(value['original']) == canonical(_DIAGNOSTIC_OLD)
            and canonical(value['current']) == canonical(_DIAGNOSTIC_CURRENT)
            and value['definition'] == 'NativeLifecycleTests.test_native_timeout_is_incomplete_terminated_and_not_adoptable'
            and type(value['original_deadline_seconds']) is int and value['original_deadline_seconds'] == 5
            and type(value['original_native_budget_ms']) is int and value['original_native_budget_ms'] == 1
            and value['original_method_ids_unchanged'] is True
            and value['production_source_exception'] is False
            and type(value['splices']) is list and len(value['splices']) == 2,
            'deadline diagnostics exact source scope differs')
    terminal_inverse(raw, _DIAGNOSTIC_OLD, _DIAGNOSTIC_CURRENT, value['splices'])
    return {'path': _DIAGNOSTIC_PATH, 'original': dict(_DIAGNOSTIC_OLD),
            'current': dict(_DIAGNOSTIC_CURRENT), 'provenance_path': _DIAGNOSTIC_FIXTURE,
            'provenance_sha256': _DIAGNOSTIC_SHA, 'exact_splices': 2,
            'complete_original_inverse_verified': True,
            'complete_current_forward_replay_verified': True,
            'original_deadline_seconds': 5, 'original_native_budget_ms': 1,
            'production_source_exception': False}


def original_callers(repository, captures, *, terminal_evidence=None):
    require(terminal_evidence is None or type(terminal_evidence) is list,
            'terminal source evidence must be an explicit list')
    original = captures.json(repository / FIXTURE, FIXTURE_SHA256)
    modules, planned = original['ordinary_modules'], original['ordinary_ordered_ids']
    require(type(modules) is list and len(modules) == 9 and len(set(modules)) == 9
            and type(planned) is list and len(planned) == len(set(planned)) == 112
            and all(type(test) is str for test in planned)
            and len(original['callers']) == 17
            and sum(len(row['recorded_ids']) for row in original['callers'].values()) == 240,
            'immutable complete ordinary caller inventory differs')
    integer(original['ordinary_count'], expected=112)
    integer(original['separate_scope_count'], expected=128)
    terminal_sources, terminal_proof = terminal_source_admission(repository, captures, original)
    admitted_terminal_sources = set()
    helper_raw = captures.take(repository / 'hepta/hia_native_helpers.py')
    helper_nodes = [node.value for node in ast.parse(helper_raw).body
                    if isinstance(node, ast.Assign)
                    and any(isinstance(t, ast.Name) and t.id == 'HELPERS' for t in node.targets)]
    require(len(helper_nodes) == 1 and isinstance(helper_nodes[0], ast.Dict),
            'native helper registry declaration differs')
    keys = [ast.literal_eval(node) for node in helper_nodes[0].keys]
    require(all(type(key) is str for key in keys) and len(keys) == len(set(keys)) >= 37,
            'native helper registry keys differ')
    old_line = b'        self.assertEqual(len(HELPERS), 37)\n'
    current_line = ('        self.assertEqual(len(HELPERS), ' + str(len(keys)) + ')\n').encode('ascii')
    adjustments, caller_sources, diagnostic_sources = [], {}, {}
    successor_sources = {}
    for record in original['callers'].values():
        name, expected = record['path'], record['sha256']
        raw = captures.take(relative(repository, name))
        caller_sources[name] = digest(raw)
        if digest(raw) == expected:
            continue
        if name == WORKER_CALLER:
            physical = raw
            raw, cold_proof = cold_caller_source(repository, name, raw, take=captures.take)
            if digest(raw) == WORKER_CALLER_CURRENT_SHA256:
                proof = worker_caller_source(repository, captures, raw, expected)
                successor_sources[name] = proof if cold_proof is None else {
                    'physical': pin(physical), 'reviewed': pin(raw),
                    'native_cold_caller_source': cold_proof,
                    'reviewed_worker_relation': proof,
                    'fixed_complete_source_relation': True}
                continue
        # Keep the original count-only return API for historical fixtures.
        count_only = (name == WORKER_CALLER and raw.count(current_line) == 1
                      and digest(raw.replace(current_line, old_line, 1)) == expected)
        known_terminal = name in terminal_sources and pin(raw) == terminal_sources[name]['current']
        known_diagnostic = name == _DIAGNOSTIC_PATH and pin(raw) == _DIAGNOSTIC_CURRENT
        if not (count_only or known_terminal or known_diagnostic):
            physical = raw
            if (name == current_history.RESULT_PATH
                    and pin(raw) == current_history.RESULT_CURRENT):
                helper = captures.take(relative(repository, 'tools/hia_current_caller_source_history.py'))
                require(pin(helper) == {'bytes': 3838, 'sha256':
                            '9f773647bacc0a59f8ddff7b45e27f9d5474bb96a7f2368fa7e18a2a98141558'}
                        and Path(current_history.__file__).read_bytes() == helper,
                        'current caller source composition helper differs')
            raw, result_history = current_history.result_predecessor(
                repository, name, raw, take=captures.take)
            raw = reviewed_source(repository, name, raw, take=captures.take)
            successor_sources[name] = {'physical': pin(physical), 'reviewed': pin(raw),
                                      'fixed_complete_source_relation': True,
                                      **({'native_result_source_history': result_history}
                                         if result_history is not None else {})}
            if digest(raw) == expected:
                continue
        if name == _DIAGNOSTIC_PATH:
            diagnostic_sources[name] = diagnostic_source_admission(raw, expected,
                captures.take(relative(repository, _DIAGNOSTIC_FIXTURE)))
            continue
        if name in terminal_sources:
            reviewed = terminal_sources[name]
            require(expected == reviewed['original']['sha256']
                    and pin(raw) == reviewed['current'], 'terminal admitted current test bytes differ')
            admitted_terminal_sources.add(name)
            continue
        require(name == 'tests/test_hia_worker_native_helpers.py'
                and raw.count(current_line) == 1
                and digest(raw.replace(current_line, old_line, 1)) == expected,
                'old complete caller bytes differ beyond the one exact registry count')
        adjustments.append({'path': name, 'original_sha256': expected,
            'current_sha256': digest(raw), 'original_helper_count': 37,
            'current_helper_count': len(keys),
            'sole_permitted_change': 'one exact registry-count assertion decimal literal',
            'all_other_source_bytes_unchanged': True})
    require([key for key in modules if not any(test.startswith(key + '.') for test in planned)] == [],
            'ordinary caller module has no original declared method')
    require(admitted_terminal_sources == set(terminal_sources),
            'terminal complete reviewed test-source consumption differs')
    terminal_proof['actual_original_source_sha256'] = dict(caller_sources)
    terminal_proof['reviewed_diagnostic_source_adjustments'] = diagnostic_sources
    if successor_sources:
        terminal_proof['complete_physical_source_successors'] = successor_sources
    if terminal_evidence is not None:
        terminal_evidence.append(terminal_proof)
    return original, planned, caller_sources, adjustments


def raw_method_log(repository, captures, path, planned):
    lines = []
    parsed = {}
    for test_id in planned:
        module_name, class_name, method_name = test_id.rsplit('.', 2)
        if module_name not in parsed:
            source = captures.take(relative(repository, module_name.replace('.', '/') + '.py'))
            parsed[module_name] = ast.parse(source)
        classes = [node for node in parsed[module_name].body
                   if isinstance(node, ast.ClassDef) and node.name == class_name]
        require(len(classes) == 1, 'original caller class is not unique')
        methods = [node for node in classes[0].body
                   if isinstance(node, ast.FunctionDef) and node.name == method_name]
        if not methods:
            inherited_module = 'tests.test_hia_agent_native_tools'
            require(module_name == 'tests.test_hia_agent_native_machine_choices'
                    and class_name in ('ExplicitMachineChoicesTests', 'ScalarRegisterChoicesTests')
                    and method_name in (
                        'test_explicit_layout_changes_bytes_preserves_observations_and_core_anchor',
                        'test_one_plan_receipt_cannot_authorize_different_layout',
                        'test_plan_with_duplicate_missing_unknown_blocks_and_machine_bytes_is_refused')
                    and [ast.unparse(base) for base in classes[0].bases] == ['existing.MachinePlanTests']
                    and any(isinstance(node, ast.ImportFrom) and node.level == 0
                            and node.module == 'tests'
                            and [(item.name, item.asname) for item in node.names] ==
                                [('test_hia_agent_native_tools', 'existing')]
                            for node in parsed[module_name].body),
                    'original inherited caller method binding differs')
            if inherited_module not in parsed:
                parsed[inherited_module] = ast.parse(captures.take(relative(repository,
                    inherited_module.replace('.', '/') + '.py')))
            parent = [node for node in parsed[inherited_module].body
                      if isinstance(node, ast.ClassDef) and node.name == 'MachinePlanTests']
            require(len(parent) == 1, 'original MachinePlanTests base differs')
            methods = [node for node in parent[0].body
                       if isinstance(node, ast.FunctionDef) and node.name == method_name]
        require(len(methods) == 1, 'original caller method definition is not unique')
        method = methods[0]
        doc = (method.body[0].value.value if method.body and isinstance(method.body[0], ast.Expr)
               and isinstance(method.body[0].value, ast.Constant)
               and type(method.body[0].value.value) is str else None)
        description = method_name + ' (' + test_id + ')'
        if doc:
            description += '\n' + doc.strip().split('\n')[0]
        lines.append(description + ' ... ok\n')
    raw = captures.take(path)
    text = raw.decode('utf-8')
    prefix = ''.join(lines) + '\n' + '-' * 70 + '\n'
    require(text.startswith(prefix), 'raw unittest log does not contain every original ID in order')
    tail = text[len(prefix):]
    require(re.fullmatch(r'Ran 112 tests in [0-9]+\.[0-9]+s\n\nOK\n', tail) is not None,
            'raw unittest terminal differs or contains abnormal outcomes')
    return pin(raw)


def counters(report, planned):
    frames = report['frames_by_original_test']
    per_test = report['native_event_counts_by_original_test']
    events = report['actual_native_event_counts']
    allowed = set(planned) | {'outside-test'}
    require(type(frames) is dict and type(per_test) is dict and type(events) is dict
            and set(frames) <= allowed and set(per_test) <= allowed,
            'caller native counts name an undeclared test')
    for value in frames.values():
        integer(value)
    integer(report['actual_file_capture_frames'], minimum=1,
            expected=sum(frames.values()))
    for key, value in events.items():
        require(type(key) is str and re.fullmatch(r'0|[1-9][0-9]*', key) is not None,
                'native event key is not an exact protocol event integer')
        integer(value, minimum=1)
    sums = {}
    for values in per_test.values():
        require(type(values) is dict, 'per-test native events are not a mapping')
        for event, count in values.items():
            require(event in events, 'per-test native event is missing from the complete total')
            integer(count, minimum=1)
            sums[event] = sums.get(event, 0) + count
    require(canonical(sums) == canonical(events)
            and all(integer(events.get(str(event)), minimum=1) for event in (0, 1, 2)),
            'actual native event totals or the original three required events differ')


def read_callers(repository, evidence, cold_path, producer_log):
    repository, evidence = absolute(repository), absolute(evidence)
    cold_path, producer_log = absolute(cold_path), absolute(producer_log)
    require(producer_log.parent == evidence.parent, 'producer CLI log is outside the owned sibling root')
    captured = Captures()
    report = captured.json(evidence / 'report.json')
    report_raw = captured.raw[absolute(evidence / 'report.json')]
    terminal_evidence = []
    original, planned, caller_sources, adjustments = original_callers(
        repository, captured, terminal_evidence=terminal_evidence)
    cold = captured.json(cold_path)
    native = cold.get('schema') == NATIVE_COLD_SCHEMA
    native_sources = None
    if native:
        current = hosted_source_map(repository, captured, original)
        admitted = native_cold_inputs(repository, cold_path, read=captured.take)
        compiler, native_sources = admitted.compiler_bytes, admitted.sources
        authoring = {name: captured.take(relative(repository, name))
                     for name in sorted(set(current) | set(NATIVE_CUSTODY_INPUTS))}
        host_custody = admitted.capture_custody(authoring, root=repository)
        cold_sha = digest(captured.raw[cold_path])
    else:
        current = source_map(repository, captured)
        compiler, cold_sha = cold_build(cold_path, captured, current)
    directory, manifest = component_build(
        repository, evidence, captured, current, compiler, cold_sha,
        native_cold_path=cold_path if native else None, native_sources=native_sources)
    require(report['schema'] == 'hepta.hia.store-file-capture-nine-ordinary-callers.v1'
            and report['status'] == 'PASS'
            and report['scope'] == 'MATCHING_SOURCE_COLD_NINE_ORDINARY_STORE_FILE_CAPTURE_CALLER_MODULES',
            'complete file-capture caller result is not a matching-cold pass')
    integer(report['actual_tests'], expected=112)
    require(type(report['wall_seconds']) in (int, float)
            and math.isfinite(report['wall_seconds']) and 0 <= report['wall_seconds'] <= 1800,
            'caller elapsed wall observation exceeds the unchanged outer gate')
    for name in ('planned', 'started', 'stopped'):
        require(report[name] == planned, 'complete original caller identities differ: ' + name)
    for name in ('errors', 'failures', 'skipped', 'expected_failures', 'unexpected_successes', 'reference_calls'):
        require(type(report[name]) is list and report[name] == [], 'caller anomaly is present: ' + name)
    for name in ('retained_stable_and_capture_forbidden', 'all_nine_ordinary_modules_unfiltered',
                 'source_and_bundle_unchanged', 'complete_stable_read_and_capture_path_control_selected',
                 'opaque_Path_stream_and_OS_effects_hosted'):
        require(report[name] is True, 'required original producer predicate differs: ' + name)
    for name in ('original_test_budgets_changed', 'other_owner_or_artifact_provider_gates_replaced_by_112',
                 'raw_descriptor_primitive_substituted_by_caller_gate',
                 'resource_qualification_inferred_from_caller_success',
                 'whole_project_dynamic_caller_closure_claimed', 'whole_native_delivery_qualified'):
        require(report[name] is False, 'producer scope or original budget predicate differs: ' + name)
    expected_sources = (dict(current) if native else
                        {key: value for key, value in current.items() if key != CONTRACT})
    expected_sources.update(caller_sources)
    require(canonical(report['source_pins']) == canonical(expected_sources)
            and report['original_baseline_commit'] == original['base_commit']
            and report['original_modules'] == original['ordinary_modules']
            and report['separate_original_administrator_scope_gates'] == original['separate_scope_modules']
            and canonical(report['original_registry_count_assertion_adjustments']) == canonical(adjustments)
            and report['native_image_sha256'] == manifest['image_sha256']
            and report['reference_poison_scope'] ==
                'test process; subprocesses inherit selector, not Python patches',
            'caller original, source, image or exact count-adjustment binding differs')
    files = {str(absolute(path)): path for path in directory.rglob('*') if path.is_file()}
    require(set(report['bundle_pins']) == set(files), 'caller bundle member list differs')
    for name, path in files.items():
        captured.take(path, report['bundle_pins'][name])
    counters(report, planned)
    log_pin = raw_method_log(repository, captured, evidence / 'tests.log', planned)
    cli_raw = captured.take(producer_log)
    terminal_line = cli_raw.decode('utf-8').splitlines()[-1]
    terminal = json.loads(terminal_line, object_pairs_hook=pairs,
                          parse_constant=lambda name: (_ for _ in ()).throw(ValueError(name)))
    terminal_keys = ('status', 'scope', 'actual_tests', 'wall_seconds', 'actual_file_capture_frames')
    require(canonical(terminal) == canonical({key: report[key] for key in terminal_keys}),
            'original CLI terminal does not match the consumed complete report')
    captured.unchanged()
    require({str(absolute(path)) for path in directory.rglob('*') if path.is_file()} == set(files),
            'caller bundle membership changed during readback')
    terminal_sources = (hosted_source_map(repository, captured, original) if native
                        else source_map(repository, captured))
    require(terminal_sources == current, 'complete hosted source membership changed at terminal')
    if native:
        _, terminal_compiler, terminal_native = native_cold_compiler(
            repository, cold_path, read=captured.take)
        require(terminal_compiler == compiler and terminal_native == native_sources,
                'complete native cold authority changed at terminal')
        require(canonical(admitted.capture_custody(authoring, root=repository))
                == canonical(host_custody), 'native caller authoring Git custody changed at terminal')
    captured.unchanged()
    return {'schema': 'hepta.hia.store-file-capture-caller-readback.v1',
        'status': 'PASS_READBACK_ONLY', 'scope': report['scope'],
        'planned': planned, 'actual_tests': 112,
        'report': pin(report_raw), 'tests_log': log_pin, 'producer_cli_log': pin(cli_raw),
        'same_current_cold_report_sha256': cold_sha,
        'compiler_sha256': digest(compiler), 'native_image_sha256': manifest['image_sha256'],
        'complete_source_files': len(current),
        'cold_source_domain': 'NATIVE_CORE_AUTHORITY' if native else 'LEGACY_COMPLETE_SOURCE',
        'native_authority_source_files': None if native_sources is None else len(native_sources),
        'native_component_host_custody_independently_verified': native,
        'original_registry_count_assertion_adjustments': adjustments,
        'original_terminal_test_source_admission': [
            {**value, 'terminal_reread_deferred_to_outer_captures': False,
             'terminal_reread_identical': True} for value in terminal_evidence],
        'consumed_files': {str(path): pin(raw) for path, raw in sorted(captured.raw.items())},
        'original_complete_unfiltered_112': True, 'original_test_budgets_changed': False,
        'raw_bytes_captured_before_parse_and_terminal_reread': True,
        'original_CI_command_exit_owned_by_workflow': True,
        'producer_pid_argv_or_child_ownership_not_independently_recorded': True,
        'selected_resource_controls_inferred_from_callers': False,
        'whole_native_delivery_qualified': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--cold-report', type=Path, required=True)
    parser.add_argument('--producer-log', type=Path, required=True)
    args = parser.parse_args()
    target = args.evidence / 'caller-readback.json'
    require(not target.exists(), 'caller readback output already exists')
    try:
        value = read_callers(args.repository, args.evidence, args.cold_report, args.producer_log)
    except Exception as error:
        value = {'schema': 'hepta.hia.store-file-capture-caller-readback.v1',
                 'status': 'HOLD', 'error_type': type(error).__name__, 'error': str(error),
                 'whole_native_delivery_qualified': False}
        with target.open('xb') as stream:
            stream.write(canonical(value) + b'\n')
        raise
    with target.open('xb') as stream:
        stream.write(canonical(value) + b'\n')
    print(json.dumps({key: value[key] for key in ('status', 'scope', 'actual_tests')}, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
