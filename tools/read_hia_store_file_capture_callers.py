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
    nodes = [node for node in ast.parse(raw).body if isinstance(node, ast.Assign)
             and any(isinstance(target, ast.Name) and target.id == name for target in node.targets)]
    require(len(nodes) == 1, 'source declaration is not unique: ' + name)
    return ast.literal_eval(nodes[0].value)

def source_map(repository, captures):
    contract = captures.json(repository / CONTRACT)
    contract_raw = captures.raw[absolute(repository / CONTRACT)]
    files = contract['source_identity']['files']
    require(type(files) is dict and files, 'current source contract is empty')
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


def cold_build(cold_path, captures, current):
    cold = captures.json(cold_path)
    cold_raw = captures.raw[absolute(cold_path)]
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


def component_build(repository, evidence, captures, current, compiler, cold_sha):
    directory = absolute(evidence / 'qualified')
    manifest = captures.json(directory / 'manifest.json')
    build = captures.json(directory / 'build.json')
    require(manifest['schema'] == 'hepta.hia.store-file-capture.v1'
            and build['schema'] == 'hepta.hia.store-file-capture-build.v1'
            and build['scope'] == 'MATCHING_SOURCE_COLD_COMPONENT'
            and build['cold_report_sha256'] == cold_sha
            and canonical(build['source_manifest']) == canonical(current)
            and canonical(build['manifest']) == canonical(manifest),
            'caller build is not the same current cold component')
    inputs = builder_inputs(repository, captures)
    require(canonical(build['component_inputs']) == canonical({name: current[name] for name in inputs}),
            'complete component inputs are not the same frozen source')
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

def original_callers(repository, captures):
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
    adjustments, caller_sources = [], {}
    for record in original['callers'].values():
        name, expected = record['path'], record['sha256']
        raw = captures.take(relative(repository, name))
        caller_sources[name] = digest(raw)
        if digest(raw) == expected:
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
    original, planned, caller_sources, adjustments = original_callers(repository, captured)
    current = source_map(repository, captured)
    compiler, cold_sha = cold_build(cold_path, captured, current)
    directory, manifest = component_build(repository, evidence, captured, current, compiler, cold_sha)
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
    expected_sources = {key: value for key, value in current.items() if key != CONTRACT}
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
    require(source_map(repository, captured) == current, 'complete source membership changed at terminal')
    captured.unchanged()
    return {'schema': 'hepta.hia.store-file-capture-caller-readback.v1',
        'status': 'PASS_READBACK_ONLY', 'scope': report['scope'],
        'planned': planned, 'actual_tests': 112,
        'report': pin(report_raw), 'tests_log': log_pin, 'producer_cli_log': pin(cli_raw),
        'same_current_cold_report_sha256': cold_sha,
        'compiler_sha256': digest(compiler), 'native_image_sha256': manifest['image_sha256'],
        'complete_source_files': len(current),
        'original_registry_count_assertion_adjustments': adjustments,
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
