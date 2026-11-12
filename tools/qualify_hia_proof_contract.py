"""Fresh HIA proof policy through all 22 Proof and 18 machine-validation callers.

The cold route admits the complete current source contract before creating its
exclusive evidence directory. The mutually exclusive development route builds
with an explicitly supplied compiler and grants no cold authority. Both execute
the same original tests, eight reference-owner poisons and actual machine-entry
observations. Their original per-test budgets and 1800-second group limit stay
unchanged. This is a selected component gate, not default or whole-stack closure.
"""
from __future__ import annotations

import argparse
from collections import Counter
from contextlib import ExitStack
import ctypes
from hashlib import sha256
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import struct
import subprocess
import sys
import time
import traceback
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ''}:
    sys.path.insert(0, str(ROOT))

SELECTOR = 'HEPTA_HIA_PROOF_CONTRACT_MANIFEST'
GROUP_SECONDS = 1800
EXPECTED_COUNT = 40
REFERENCE_METHODS = ()
REFERENCE_FUNCTIONS = ('_item_reference', '_require_reference', '_safe_core_method_reference', 'proof_subject_reference', '_method_reference', 'proof_result_reference', 'assumptions_document_reference', 'proof_contract_description_reference',)
SELF_SOURCES = ('tools/qualify_hia_proof_contract.py',
                'tests/test_hia_proof_contract_qualifier.py')
# Exact original 22 Proof + 18 machine-validation caller IDs and supporting source.
ORIGINAL_MODULES = ("tests.test_hia_agent_native_proof_contract","tests.test_hia_agent_native_machine_validation",)
ORIGINAL_FILES = {
    "tests/test_hia_agent_native_proof_contract.py": {
        "bytes": 23396,
        "git_blob_sha": "cff64347e6d7fa02569da55032caddf264859e1a",
        "mode": "100644",
        "sha256": "0a9a3feb8444d33ec97afb4259a847cd6b738fc3a77cf07980b4772096c112a6",
        "expected_ids": [
            "tests.test_hia_agent_native_proof_contract.ProofContractTests.test_a_matching_workload_example_does_not_hide_a_counterexample",
            "tests.test_hia_agent_native_proof_contract.ProofContractTests.test_actual_object_encoding_proof_exposes_same_implementation_limit",
            "tests.test_hia_agent_native_proof_contract.ProofContractTests.test_admission_is_self_contained_even_when_detached_from_response",
            "tests.test_hia_agent_native_proof_contract.ProofContractTests.test_cached_legacy_result_cannot_bypass_the_current_output_contract",
            "tests.test_hia_agent_native_proof_contract.ProofContractTests.test_cached_valid_shape_cannot_change_the_retained_checker_conclusion",
            "tests.test_hia_agent_native_proof_contract.ProofContractTests.test_canonical_lowering_unsupported_keeps_explicit_open_obligations",
            "tests.test_hia_agent_native_proof_contract.ProofContractTests.test_changed_reemitted_bytes_are_refuted_without_a_semantic_safety_claim",
            "tests.test_hia_agent_native_proof_contract.ProofContractTests.test_changed_subject_profile_checker_assumptions_and_obligations_are_rejected",
            "tests.test_hia_agent_native_proof_contract.ProofContractTests.test_compositional_proof_names_the_actual_solver_and_excluded_vm_ticks",
            "tests.test_hia_agent_native_proof_contract.ProofContractTests.test_conditional_machine_plan_preserves_scope_at_emission",
            "tests.test_hia_agent_native_proof_contract.ProofContractTests.test_discovery_teaches_scope_before_verification",
            "tests.test_hia_agent_native_proof_contract.ProofContractTests.test_exact_verification_replay_preserves_the_original_scoped_result",
            "tests.test_hia_agent_native_proof_contract.ProofContractTests.test_finite_domain_is_complete_despite_single_case_workload",
            "tests.test_hia_agent_native_proof_contract.ProofContractTests.test_incomplete_reference_enumeration_remains_unknown_with_full_scope",
            "tests.test_hia_agent_native_proof_contract.ProofContractTests.test_missing_scope_fields_and_legacy_receipts_are_rejected_by_emission",
            "tests.test_hia_agent_native_proof_contract.ProofContractTests.test_rebound_assumptions_or_evidence_cannot_be_substituted",
            "tests.test_hia_agent_native_proof_contract.ProofContractTests.test_reflexivity_retains_both_exact_program_references",
            "tests.test_hia_agent_native_proof_contract.ProofContractTests.test_required_acceptance_claims_reject_valid_status_with_missing_scope",
            "tests.test_hia_agent_native_proof_contract.ProofContractTests.test_restamping_metadata_cannot_turn_unsupported_lowering_into_a_proof",
            "tests.test_hia_agent_native_proof_contract.ProofContractTests.test_restamping_metadata_cannot_upgrade_incomplete_evidence",
            "tests.test_hia_agent_native_proof_contract.ProofContractTests.test_unsupported_scope_cannot_satisfy_a_required_lowering_property",
            "tests.test_hia_agent_native_proof_contract.ProofContractTests.test_verification_replay_rejects_changed_installed_checker_source"
        ]
    },
    "tests/test_hia_agent_native_machine_validation.py": {
        "bytes": 22171,
        "git_blob_sha": "fa9a45e479c448ff8eddd9134cb7797bdd751f97",
        "mode": "100644",
        "sha256": "f8e60f923d5b462c3a98f11cb00b0e5a65fb9bc1db2a17a03d55933eb944aada",
        "expected_ids": [
            "tests.test_hia_agent_native_machine_validation.AgentNativeMachineValidationTests.test_a_proof_for_another_issued_native_artifact_does_not_satisfy_the_gate",
            "tests.test_hia_agent_native_machine_validation.AgentNativeMachineValidationTests.test_a_self_consistent_wrong_backend_passes_encoding_but_fails_native_semantics",
            "tests.test_hia_agent_native_machine_validation.AgentNativeMachineValidationTests.test_changed_candidate_core_bytes_are_rejected_before_a_proof_is_issued",
            "tests.test_hia_agent_native_machine_validation.AgentNativeMachineValidationTests.test_changed_final_image_bytes_are_rejected_before_a_proof_is_issued",
            "tests.test_hia_agent_native_machine_validation.AgentNativeMachineValidationTests.test_changed_retained_object_bytes_are_not_replaced_by_reemission",
            "tests.test_hia_agent_native_machine_validation.AgentNativeMachineValidationTests.test_completed_queries_cannot_be_published_after_the_frozen_deadline",
            "tests.test_hia_agent_native_machine_validation.AgentNativeMachineValidationTests.test_incomplete_duplicate_or_wrong_solver_obligations_cannot_be_restamped",
            "tests.test_hia_agent_native_machine_validation.AgentNativeMachineValidationTests.test_less_than_minimum_budget_does_not_start_a_machine_proof",
            "tests.test_hia_agent_native_machine_validation.AgentNativeMachineValidationTests.test_missing_or_rebound_retained_object_identity_is_rejected",
            "tests.test_hia_agent_native_machine_validation.AgentNativeMachineValidationTests.test_multiple_functions_remain_outside_the_native_proof_profile",
            "tests.test_hia_agent_native_machine_validation.AgentNativeMachineValidationTests.test_native_proof_flows_through_evaluation_adoption_and_a_consumer_lease",
            "tests.test_hia_agent_native_machine_validation.AgentNativeMachineValidationTests.test_object_output_is_unsupported_by_the_shared_image_proof_profile",
            "tests.test_hia_agent_native_machine_validation.AgentNativeMachineValidationTests.test_raw_proof_artifact_binding_cannot_be_transplanted_or_weakened",
            "tests.test_hia_agent_native_machine_validation.AgentNativeMachineValidationTests.test_refuted_machine_evidence_cannot_be_relabelled_as_proved",
            "tests.test_hia_agent_native_machine_validation.AgentNativeMachineValidationTests.test_restamped_consumer_source_digest_must_match_current_checker_files",
            "tests.test_hia_agent_native_machine_validation.AgentNativeMachineValidationTests.test_reverification_and_consumption_do_not_call_the_emitter_or_linker",
            "tests.test_hia_agent_native_machine_validation.AgentNativeMachineValidationTests.test_shared_scalar_proof_binds_the_actual_core_object_final_and_solver",
            "tests.test_hia_agent_native_machine_validation.AgentNativeMachineValidationTests.test_true_solver_version_with_false_library_or_bindings_is_not_a_checker_identity"
        ]
    },
    "tests/test_hia_agent_native_tools.py": {
        "bytes": 42664,
        "git_blob_sha": "0f30ac1762ced2c88fabbea86451ee205921e43e",
        "mode": "100644",
        "sha256": "fe9f54d7132432bc7514ee58451111897ac06907f44e724c502f51028da5d901",
        "expected_ids": []
    },
    "tools/hia_agent_native_qualification.py": {
        "bytes": 21980,
        "git_blob_sha": "198912e5a1f32c9fe83ac808a0de69ad3e8a9c44",
        "mode": "100644",
        "sha256": "edd4f6c4347febb929b3f9f858da4eeb399a76e154418d08b1c3609c3a7c49f8",
        "expected_ids": []
    }
}


def _require(value, message):
    if not value:
        raise ValueError(message)


def _pairs(items):
    value = {}
    for key, item in items:
        _require(key not in value, 'duplicate verification qualification field')
        value[key] = item
    return value


def _json(raw):
    return json.loads(raw, object_pairs_hook=_pairs)


def _wire(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def _publish(path, raw):
    with path.open('xb') as stream:
        stream.write(raw)
        stream.flush()
    _require(path.read_bytes() == raw, 'verification qualification publication differs')


def _file(path):
    path = Path(path).resolve(strict=True)
    raw = path.read_bytes()
    return {'path': str(path), 'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


def original_ids():
    return [name for module in ORIGINAL_MODULES
            for name in ORIGINAL_FILES[module.replace('.', '/') + '.py']['expected_ids']]


def admit_original_files(root=ROOT):
    for name, expected in ORIGINAL_FILES.items():
        raw = (root / name).read_bytes()
        _require(len(raw) == expected['bytes'] and sha256(raw).hexdigest() == expected['sha256'],
                 'original Agent test bytes differ: ' + name)
    ids = original_ids()
    _require(len(ids) == len(set(ids)) == EXPECTED_COUNT, 'original Agent denominator differs')


def flatten(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from flatten(item)
        else:
            yield item


def load_original_suite():
    admit_original_files()
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromNames(ORIGINAL_MODULES)
    loaded = [test.id() for test in flatten(suite)]
    _require(not loader.errors and loaded == original_ids(), 'original ordered Agent discovery differs')
    for module in ORIGINAL_MODULES:
        _require(Path(sys.modules[module].__file__).resolve() == ROOT / (module.replace('.', '/') + '.py'),
                 'original Agent module was imported from a different source')
    return suite, loaded


def _snapshot():
    from tools import build_hia_proof_contract as builder
    from tools.build_hia_json_preflight import current_sources
    return {**current_sources(), **{name: sha256((ROOT / name).read_bytes()).hexdigest()
                                   for name in (*builder.DEVELOPMENT_INPUT_NAMES, *SELF_SOURCES, *ORIGINAL_FILES)}}


def _admit_selection(cold_report, development_compiler):
    """No output writes; every cold input is bound before a builder can run."""
    from tools import build_hia_proof_contract as builder
    _require((cold_report is None) != (development_compiler is None), 'one explicit verification compiler selection required')
    admit_original_files()
    held = {}
    if cold_report is not None:
        cold_path = Path(cold_report).resolve(strict=True)
        cold_raw = cold_path.read_bytes()
        outer = _json(cold_raw)
        nested_path = Path(outer['nested_report']).resolve(strict=True)
        nested_raw = nested_path.read_bytes()
        _require(sha256(nested_raw).hexdigest() == outer.get('nested_report_sha256'),
                 'verification caller nested cold receipt identity differs')
        nested = _json(nested_raw)
        generations = nested['generations']
        _require(type(generations) is list and len(generations) == 3
                 and all(type(row) is dict for row in generations), 'three actual cold generations required')
        compiler = Path(generations[-1]['produced_image']).resolve(strict=True)
        compiler_raw = compiler.read_bytes()
        sources = builder.admit_cold_build(compiler_raw, cold_raw)
        _require(type(outer.get('qualification_wall_limit_seconds')) is int
                 and outer['qualification_wall_limit_seconds'] == 180
                 and type(outer.get('cleanup_wall_limit_seconds')) is int
                 and outer['cleanup_wall_limit_seconds'] == 3,
                 'verification caller cold limits must remain 180+3')
        _require(nested.get('source_manifest') == sources
                 and [row.get('produced_sha256') for row in generations] == outer['generation_sha256'],
                 'verification caller cold source or generation custody differs')
        for name in (*builder.REQUIRED_SOURCE_NAMES, *SELF_SOURCES, *ORIGINAL_FILES):
            _require(sources.get(name) == sha256((ROOT / name).read_bytes()).hexdigest(),
                     'verification caller input is outside the current cold contract: ' + name)
        held.update({cold_path: cold_raw, nested_path: nested_raw, compiler: compiler_raw})
        scope = 'MATCHING_SOURCE_COLD_SELECTED_CALLERS'
    else:
        compiler = Path(development_compiler).resolve(strict=True)
        held[compiler] = compiler.read_bytes()
        scope = 'EXPLICIT_COMPILER_DEVELOPMENT_ONLY'
    return compiler, held, _snapshot(), scope


def _guard(held, sources):
    _require(all(path.read_bytes() == raw for path, raw in held.items()), 'held verification qualification input changed')
    _require(_snapshot() == sources, 'verification qualification source identity changed')


def _clean_environment(environment):
    env = dict(environment)
    clang = env.get('HEPTA_CLANG') or env.get('CLANG') or shutil.which('clang-20')
    removed = sorted(name for name in env if name.startswith('HEPTA_'))
    for name in removed:
        del env[name]
    env['PYTHONDONTWRITEBYTECODE'] = '1'
    if clang:
        env.update(CLANG=clang, HEPTA_CLANG=clang)
    return env, removed


def _prerequisites(environment):
    _require(platform.system() == 'Linux' and platform.machine().lower() in ('x86_64', 'amd64'),
             'original Agent callers require Linux x86-64')
    import z3
    _require(z3.get_version() == (4, 15, 4, 0), 'original actual Z3 4.15.4.0 required')
    tools = {}
    for role, candidate in (('clang', environment.get('HEPTA_CLANG') or 'clang-20'), ('ld', 'ld')):
        path = shutil.which(candidate, path=environment.get('PATH'))
        _require(path is not None, 'original real tool is missing: ' + candidate)
        result = subprocess.run([path, '--version'], env=environment, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, check=True, timeout=30)
        text = result.stdout.decode('utf-8', 'strict')
        _require(('clang version 20.' if role == 'clang' else 'GNU ld') in text,
                 'original real tool version differs: ' + role)
        tools[role] = {**_file(path), 'version': text}
    return {'python': sys.version, 'z3': list(z3.get_version()), 'tools': tools,
            'jsonschema': importlib.metadata.version('jsonschema')}


def _strict_result(result, loaded, executed, references, modes, native_modes):
    return bool(loaded == original_ids() and executed == loaded
                and type(result.testsRun) is int and result.testsRun == EXPECTED_COUNT
                and not any(getattr(result, name) for name in (
                    'failures', 'errors', 'skipped', 'expectedFailures', 'unexpectedSuccesses'))
                and not references and set(range(1, 9)) <= set(modes) <= set(range(1, 17))
                and set(range(1, 9)) <= set(native_modes) <= set(range(1, 17))
                and all(type(mode) is int for mode in (*modes, *native_modes))
                and all(type(count) is int and count > 0 for count in (*modes.values(), *native_modes.values())))


def _admit_child_observations(child, request_sha256):
    _require(type(child) is dict and child.get('schema') == 'hepta.hia.proof-contract-caller-observations.v1'
             and child.get('scope') == 'OBSERVATIONS_ONLY_NO_COLD_AUTHORITY'
             and child.get('status') == 'PASS' and child.get('request_sha256') == request_sha256
             and child.get('loaded_ids') == child.get('executed_ids') == original_ids()
             and type(child.get('tests_run')) is int and child['tests_run'] == EXPECTED_COUNT
             and child.get('source_and_inputs_unchanged') is True,
             'original verification caller observation custody differs')
    for name in ('failures', 'errors', 'skips', 'expected_failures', 'unexpected_successes', 'reference_calls'):
        _require(type(child.get(name)) is list and not child[name], 'original caller anomaly: ' + name)
    for name in ('native_mode_calls', 'actual_machine_mode_returns'):
        counts = child.get(name)
        _require(type(counts) is dict and {str(mode) for mode in range(1, 9)} <= set(counts) <= {str(mode) for mode in range(1, 17)}
                 and all(type(value) is int and value > 0 for value in counts.values()),
                 'eight actual proof policy roots or their admitted lazy machine modes were not observed')
    _require(type(child.get('actual_mappings')) is int and child['actual_mappings'] > 0
             and type(child.get('actual_machine_returns')) is int
             and child['actual_machine_returns'] == sum(child['actual_machine_mode_returns'].values()),
             'actual verification machine-return accounting differs')


def _child(request_path):
    request_raw = request_path.read_bytes()
    request = _json(request_raw)
    output = Path(request['output'])
    report = {'schema': 'hepta.hia.proof-contract-caller-observations.v1', 'status': 'STARTED',
              'scope': 'OBSERVATIONS_ONLY_NO_COLD_AUTHORITY', 'python': sys.version,
              'request_sha256': sha256(request_raw).hexdigest(), 'expected_count': EXPECTED_COUNT,
              'reference_poison_scope': 'test process; child processes inherit the selector, not Python patches',
              'existing_verifier_emitter_linker_store_providers_replaced': False, 'original_test_budgets_changed': False}
    started = time.monotonic_ns()
    references, images, executed = [], [], []
    modes, entries, per_test = Counter(), Counter(), Counter()
    active = ['outside-test']
    try:
        _require(request['schema'] == 'hepta.hia.proof-contract-caller-request.v1', 'unknown caller request')
        _require(_snapshot() == request['source_manifest'], 'child source identity differs')
        for row in request['input_bindings']:
            _require(_file(row['path']) == row, 'child executable or receipt identity differs')
        manifest_path = Path(request['manifest'])
        manifest = _json(manifest_path.read_bytes())
        _require(os.environ.get(SELECTOR) == str(manifest_path), 'child explicit selector differs')
        from hepta import hia_proof_contract as service_api
        from hepta.hia_proof_contract_native import (
            NativeProofContractImage, ProofContractFrame, _mapped_proof_contract)
        from hepta.hia_machine_plan_control_native import MAGIC
        _require(_mapped_proof_contract.cache_info().currsize == 0, 'caller observer requires fresh process image custody')
        original_init, original_frame_init = NativeProofContractImage.__init__, ProofContractFrame.__init__

        def counted_init(image, raw, expected, namespace=None):
            _require(expected == manifest['image_sha256'] and sha256(raw).hexdigest() == expected,
                     'caller image differs from its own fresh build')
            original_init(image, raw, expected, namespace)
            _require(sha256(image._mapping[:]).hexdigest() == expected, 'actual executable mapping differs')
            actual_entry = image._entry
            images.append(image)

            def counted_entry(source, size, result, result_size, state, state_size):
                returned = actual_entry(source, size, result, result_size, state, state_size)
                if size == len(image.table):
                    _require(result_size == 2048 and state_size == image.workspace_bytes
                             and type(returned) is int and returned in (0, 1, 2, 3, 4, 5),
                             'actual verification machine entry did not return its complete ABI receipt')
                    words = struct.unpack('<21Q', ctypes.string_at(state, 168))
                    _require(words[16] == MAGIC and words[19] in range(1, 17)
                             and struct.unpack('<2Q', ctypes.string_at(result, 16)) == (MAGIC, words[17]),
                             'actual verification machine state/output identity differs')
                    entries[words[19]] += 1
                    per_test[active[0]] += 1
                return returned
            image._entry = counted_entry

        def counted_frame(frame, image, mode, arguments, captures=(), *, witness=None):
            original_frame_init(frame, image, mode, arguments, captures, witness=witness)
            modes[mode] += 1

        def forbidden(*unused, **ignored):
            references.append(active[0])
            raise AssertionError('selected verification invoked retained policy')

        class Result(unittest.TextTestResult):
            def startTest(self, test):
                active[0] = test.id()
                executed.append(test.id())
                super().startTest(test)

        with ExitStack() as stack:
            stack.enter_context(patch.object(NativeProofContractImage, '__init__', counted_init))
            stack.enter_context(patch.object(ProofContractFrame, '__init__', counted_frame))
            for name in REFERENCE_FUNCTIONS:
                stack.enter_context(patch.object(service_api, name, forbidden))
            suite, loaded = load_original_suite()
            report['loaded_ids'] = loaded
            result = unittest.TextTestRunner(verbosity=2, resultclass=Result).run(suite)
        report.update(tests_run=result.testsRun, executed_ids=executed,
                      failures=[(test.id(), trace) for test, trace in result.failures],
                      errors=[(test.id(), trace) for test, trace in result.errors],
                      skips=[(test.id(), why) for test, why in result.skipped],
                      expected_failures=[(test.id(), trace) for test, trace in result.expectedFailures],
                      unexpected_successes=[test.id() for test in result.unexpectedSuccesses])
        _require(images and all(image.image_sha256 == manifest['image_sha256']
                 and sha256(image._mapping[:]).hexdigest() == manifest['image_sha256'] for image in images),
                 'actual held verification image changed')
        report['status'] = 'PASS' if _strict_result(result, loaded, executed, references, modes, entries) else 'FAIL'
    except BaseException:
        report.update(status='FAIL', traceback=traceback.format_exc())
    finally:
        report.update(elapsed_ns=time.monotonic_ns() - started, reference_calls=references,
                      native_mode_calls=dict(modes), actual_machine_mode_returns=dict(entries),
                      actual_machine_returns=sum(entries.values()), per_test_machine_returns=dict(per_test),
                      actual_mappings=len(images), mechanism_verification_excluded_from_mode_counts=True)
        try:
            _require(_snapshot() == request['source_manifest'], 'child source changed during original callers')
            for row in request['input_bindings']:
                _require(_file(row['path']) == row, 'child input changed during original callers')
            report['source_and_inputs_unchanged'] = True
        except BaseException:
            report.update(status='FAIL', source_and_inputs_unchanged=False, final_guard_error=traceback.format_exc())
        _publish(output, _wire(report))
    return 0 if report['status'] == 'PASS' else 1


def _run_child(request_path, output, environment):
    command = [sys.executable, '-I', '-B', str(Path(__file__).resolve()), '--_child-request', str(request_path)]
    terminal = {'argv': command, 'timeout_seconds': GROUP_SECONDS, 'timed_out': False}
    started = time.monotonic_ns()
    try:
        with (output / 'original-agent.stdout.log').open('xb') as stdout, (output / 'original-agent.stderr.log').open('xb') as stderr:
            child = subprocess.Popen(command, cwd=ROOT, env=environment, stdin=subprocess.DEVNULL,
                                     stdout=stdout, stderr=stderr, start_new_session=True)
            terminal['pid'] = child.pid
            try:
                terminal['returncode'] = child.wait(timeout=GROUP_SECONDS)
            except subprocess.TimeoutExpired:
                terminal['timed_out'] = True
                os.killpg(child.pid, signal.SIGKILL)
                terminal['returncode'] = child.wait()
    finally:
        terminal['elapsed_ns'] = time.monotonic_ns() - started
        _publish(output / 'original-agent.terminal.json', _wire(terminal))
    return terminal


def qualify(output, *, cold_report=None, development_compiler=None):
    from tools import build_hia_proof_contract as builder
    output = Path(output).absolute()
    _require(not output.exists() and not output.is_symlink(), 'new exclusive verification caller evidence directory required')
    environment, removed = _clean_environment(os.environ)
    with patch.dict(os.environ, environment, clear=True):
        compiler, held, sources, scope = _admit_selection(cold_report, development_compiler)
        prerequisites = _prerequisites(environment)
        _guard(held, sources)
        output.mkdir(mode=0o700)
        report = {'schema': 'hepta.hia.proof-contract-callers.v1', 'status': 'STARTED', 'scope': scope,
                  'source_manifest': sources, 'prerequisites': prerequisites, 'original_modules': ORIGINAL_MODULES,
                  'expected_count': EXPECTED_COUNT, 'original_test_sources': ORIGINAL_FILES,
                  'cleared_inherited_selector_names': removed, 'group_limit_seconds': GROUP_SECONDS,
                  'compiler_child_limit_seconds': 20, 'original_test_budgets_changed': False,
                  'default_changed': False, 'whole_stack_native': False}
        try:
            manifest = (builder.build(output / 'build', compiler, cold_report) if cold_report is not None
                        else builder.build_development(output / 'build', compiler))
            for path in (output / 'build').iterdir():
                if path.is_file():
                    held[path] = path.read_bytes()
            _guard(held, sources)
            request = {'schema': 'hepta.hia.proof-contract-caller-request.v1', 'manifest': str(manifest),
                       'source_manifest': sources, 'input_bindings': [_file(path) for path in held],
                       'output': str(output / 'original-agent-40.json')}
            request_path = output / 'caller-request.json'
            _publish(request_path, _wire(request))
            held[request_path] = request_path.read_bytes()
            report['selected_manifest'] = str(manifest)
            report['input_bindings'] = request['input_bindings']
            environment[SELECTOR] = str(manifest)
            terminal = _run_child(request_path, output, environment)
            report['terminal'] = terminal
            child = _json((output / 'original-agent-40.json').read_bytes())
            report['original_agent'] = child
            _admit_child_observations(child, sha256(held[request_path]).hexdigest())
            _require(type(terminal.get('returncode')) is int and terminal['returncode'] == 0
                     and terminal['timed_out'] is False,
                     'complete original verification caller gate failed')
            report['status'] = 'MATCHING_SOURCE_COLD_CALLERS_PASS' if cold_report is not None else 'DEVELOPMENT_CALLERS_PASS'
        except BaseException:
            report.update(status='FAIL', traceback=traceback.format_exc())
        finally:
            try:
                _guard(held, sources)
                report['source_and_inputs_unchanged'] = True
            except BaseException:
                report.update(status='FAIL', source_and_inputs_unchanged=False, final_guard_error=traceback.format_exc())
            _publish(output / 'report.json', _wire(report))
    return report


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) == 2 and argv[0] == '--_child-request':
        return _child(Path(argv[1]).resolve(strict=True))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path, required=True)
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument('--cold-report', type=Path)
    selection.add_argument('--development-compiler', type=Path)
    args = parser.parse_args(argv)
    report = qualify(args.evidence, cold_report=args.cold_report, development_compiler=args.development_compiler)
    print(json.dumps({name: report.get(name) for name in ('status', 'scope', 'expected_count', 'source_and_inputs_unchanged')}))
    return 0 if report['status'].endswith('_PASS') else 1


if __name__ == '__main__':
    raise SystemExit(main())
