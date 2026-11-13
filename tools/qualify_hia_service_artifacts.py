"""Fresh HIA artifacts image through all 48 unchanged original Agent callers.

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

SELECTOR = 'HEPTA_HIA_SERVICE_ARTIFACTS_MANIFEST'
GROUP_SECONDS = 1800
EXPECTED_COUNT = 48
REFERENCE_METHODS = ('_profile_reference', '_program_reference', '_signature_values_reference', '_native_reference', '_build_receipt_reference', '_build_inputs_reference')
REFERENCE_FUNCTIONS = ('_NATIVE_ARTIFACTS_PROFILE_REFERENCE', '_NATIVE_ARTIFACTS_PROGRAM_REFERENCE', '_NATIVE_ARTIFACTS_SIGNATURE_VALUES_REFERENCE', '_NATIVE_ARTIFACTS_NATIVE_REFERENCE', '_NATIVE_ARTIFACTS_BUILD_RECEIPT_REFERENCE', '_NATIVE_ARTIFACTS_BUILD_INPUTS_REFERENCE')
SELF_SOURCES = ('tools/qualify_hia_service_artifacts.py', 'tests/test_hia_service_artifacts_qualifier.py', 'tools/hia_retained_agent_callers.py', 'tests/fixtures/hia_original_agent_callers_v1/test_hia_agent_native_tools.py.txt', 'tests/test_hia_retained_agent_callers.py', 'tests/fixtures/hia_original_agent_callers_v1/test_hia_artifact_namespace_native.py.txt', 'tests/fixtures/hia_original_agent_callers_v1/test_hia_slot_ledger_native.py.txt', 'tests/test_hia_slot_ledger_continuation_native.py')
# Frozen original IDs and bytes are inserted below from the retained r3 input.
ORIGINAL_MODULES = ('tests.test_hia_agent_native_tools', 'tests.test_hia_agent_native_campaign', 'tests.test_hia_agent_buffer_lifecycle', 'tests.test_hia_agent_native_lease_snapshot')
ORIGINAL_FILES = {'tests/test_hia_agent_buffer_lifecycle.py': {'bytes': 16921,
                                              'expected_ids': ['tests.test_hia_agent_buffer_lifecycle.BufferLifecycleTests.test_abort_snapshot_preserves_writes_and_detects_a_changed_prefix',
                                                               'tests.test_hia_agent_buffer_lifecycle.BufferLifecycleTests.test_adoption_consumer_bytes_survive_rollback_and_release_fences',
                                                               'tests.test_hia_agent_buffer_lifecycle.BufferLifecycleTests.test_cold_consumer_processes_preserve_lease_and_release_across_rollback',
                                                               'tests.test_hia_agent_buffer_lifecycle.BufferLifecycleTests.test_every_warmup_and_repetition_starts_with_fresh_owned_bytes',
                                                               'tests.test_hia_agent_buffer_lifecycle.BufferLifecycleTests.test_explicit_profile_exports_real_bytes_and_retains_abi_in_build',
                                                               'tests.test_hia_agent_buffer_lifecycle.BufferLifecycleTests.test_invalid_byte_shapes_and_extent_never_enter_native_execution',
                                                               'tests.test_hia_agent_buffer_lifecycle.BufferLifecycleTests.test_mixed_register_stack_scalars_and_empty_buffers_are_exact',
                                                               'tests.test_hia_agent_buffer_lifecycle.BufferLifecycleTests.test_normal_scalar_workload_does_not_opt_into_buffer_exports',
                                                               'tests.test_hia_agent_buffer_lifecycle.BufferLifecycleTests.test_refinement_stays_unsupported_and_required_proof_blocks_adoption',
                                                               'tests.test_hia_agent_buffer_lifecycle.BufferLifecycleTests.test_same_output_status_cannot_hide_changed_buffer_bytes',
                                                               'tests.test_hia_agent_buffer_lifecycle.BufferLifecycleTests.test_timeout_retains_partial_external_write_but_never_success',
                                                               'tests.test_hia_agent_buffer_lifecycle.BufferLifecycleTests.test_workload_byte_budget_and_duplicate_exports_are_rejected_at_context'],
                                              'git_blob_sha': '67397c16e489a73ade82616bf5dd9318b127d5e9',
                                              'sha256': 'b3f23d740436ae90c909b65a2fbca150459fe16807cf788f17825832964302bf'},
 'tests/test_hia_agent_native_campaign.py': {'bytes': 9345,
                                             'expected_ids': ['tests.test_hia_agent_native_campaign.QualificationCampaignTests.test_cli_requires_explicit_campaign_before_any_transport_or_evidence',
                                                              'tests.test_hia_agent_native_campaign.QualificationCampaignTests.test_committed_but_lost_reply_retains_original_intent_for_recovery',
                                                              'tests.test_hia_agent_native_campaign.QualificationCampaignTests.test_existing_output_is_preserved_and_refused_before_dispatch',
                                                              'tests.test_hia_agent_native_campaign.QualificationCampaignTests.test_invalid_campaign_cannot_start_a_transport_or_use_an_arbitrary_slot',
                                                              'tests.test_hia_agent_native_campaign.QualificationCampaignTests.test_two_campaigns_share_store_but_not_slot_and_reconnect_does_not_reexecute'],
                                             'git_blob_sha': '15a12392cae76a4fddd3ed22c52436037f180a0d',
                                             'sha256': '472e3a0020c1532c217db21a9d087f128dcc0aec1902425698bd5c1d869b765b'},
 'tests/test_hia_agent_native_lease_snapshot.py': {'bytes': 2785,
                                                   'expected_ids': ['tests.test_hia_agent_native_lease_snapshot.LeaseSnapshotTests.test_caller_mutation_during_native_call_cannot_relabel_result_or_buffers'],
                                                   'git_blob_sha': '15be054a47985d38486f16c586b5d73bd265728d',
                                                   'sha256': '476e49225ad1b2215f08323079f3521b5b9dbcdb33edc8b619013f426643e823'},
 'tests/test_hia_agent_native_tools.py': {'bytes': 42664,
                                          'expected_ids': ['tests.test_hia_agent_native_tools.AgentStoreDirectoryPermissionTests.test_preexisting_world_writable_artifact_directory_is_rejected',
                                                           'tests.test_hia_agent_native_tools.ArtifactContractTests.test_discovery_is_readable_and_source_bound',
                                                           'tests.test_hia_agent_native_tools.ArtifactContractTests.test_exact_request_replay_survives_restart_and_changed_body_rejects',
                                                           'tests.test_hia_agent_native_tools.ArtifactContractTests.test_file_capture_enforces_roots_regular_identity_and_expected_hash',
                                                           'tests.test_hia_agent_native_tools.ArtifactContractTests.test_high_escape_pages_obey_serialized_response_bound',
                                                           'tests.test_hia_agent_native_tools.ArtifactContractTests.test_issued_reference_fields_and_actual_bytes_are_verified',
                                                           'tests.test_hia_agent_native_tools.ArtifactContractTests.test_process_killed_after_effect_leaves_unknown_intent_and_never_replays',
                                                           'tests.test_hia_agent_native_tools.ArtifactContractTests.test_unknown_fields_stale_catalog_and_profile_do_not_gain_admission',
                                                           'tests.test_hia_agent_native_tools.ArtifactContractTests.test_utf8_pagination_preserves_bytes_and_rejects_cross_artifact_cursor',
                                                           'tests.test_hia_agent_native_tools.CandidateAndVerificationTests.test_allocation_resource_trace_difference_is_not_value_equivalence',
                                                           'tests.test_hia_agent_native_tools.CandidateAndVerificationTests.test_changed_cfg_and_alpha_names_do_not_implicitly_expand_validator_domain',
                                                           'tests.test_hia_agent_native_tools.CandidateAndVerificationTests.test_encoding_receipt_for_another_candidate_does_not_authorize_evaluation',
                                                           'tests.test_hia_agent_native_tools.CandidateAndVerificationTests.test_equivalence_search_uses_remaining_frozen_context_budget',
                                                           'tests.test_hia_agent_native_tools.CandidateAndVerificationTests.test_invalid_candidate_is_repaired_with_an_explicit_new_request',
                                                           'tests.test_hia_agent_native_tools.CandidateAndVerificationTests.test_matching_return_values_do_not_hide_different_first_trap',
                                                           'tests.test_hia_agent_native_tools.CandidateAndVerificationTests.test_patch_binds_canonical_base_and_whole_candidate_is_rechecked',
                                                           'tests.test_hia_agent_native_tools.CandidateAndVerificationTests.test_stale_context_and_foreign_validation_profile_are_rejected',
                                                           'tests.test_hia_agent_native_tools.CandidateAndVerificationTests.test_unknown_or_refuted_equivalence_cannot_be_reported_as_core_admission',
                                                           'tests.test_hia_agent_native_tools.MachinePlanTests.test_explicit_layout_changes_bytes_preserves_observations_and_core_anchor',
                                                           'tests.test_hia_agent_native_tools.MachinePlanTests.test_one_plan_receipt_cannot_authorize_different_layout',
                                                           'tests.test_hia_agent_native_tools.MachinePlanTests.test_plan_with_duplicate_missing_unknown_blocks_and_machine_bytes_is_refused',
                                                           'tests.test_hia_agent_native_tools.NativeLifecycleTests.test_all_eleven_tools_and_full_u8_native_workload',
                                                           'tests.test_hia_agent_native_tools.NativeLifecycleTests.test_expired_evaluation_is_rejected_before_any_reference_or_native_runner',
                                                           'tests.test_hia_agent_native_tools.NativeLifecycleTests.test_fresh_context_can_advance_existing_slot_and_stale_error_is_readable',
                                                           'tests.test_hia_agent_native_tools.NativeLifecycleTests.test_native_timeout_is_incomplete_terminated_and_not_adoptable',
                                                           'tests.test_hia_agent_native_tools.NativeLifecycleTests.test_published_version_lease_survives_rollback_and_release_is_checked',
                                                           'tests.test_hia_agent_native_tools.NativeLifecycleTests.test_real_native_wrong_answer_is_incorrect_and_cannot_be_adopted',
                                                           'tests.test_hia_agent_native_tools.NativeLifecycleTests.test_reference_loop_cannot_restart_or_overrun_frozen_context_deadline',
                                                           'tests.test_hia_agent_native_tools.NativeLifecycleTests.test_tool_object_emission_needs_no_llvm_import_or_external_process',
                                                           'tests.test_hia_agent_native_tools.NativeLifecycleTests.test_u64_generation_boundary_rejects_out_of_range_strings'],
                                          'git_blob_sha': '0f30ac1762ced2c88fabbea86451ee205921e43e',
                                          'sha256': 'fe9f54d7132432bc7514ee58451111897ac06907f44e724c502f51028da5d901'}}


_AGENT_MODULES = ORIGINAL_MODULES
_AGENT_FILES = dict(ORIGINAL_FILES)
ORIGINAL_FILES.update({
    "tests/test_hia_artifact_namespace_native.py": {
        "bytes": 59174,
        "sha256": "1873ab3d845230813effa1b3db38f729f1bbdcaa713ac0669d3d3730797f17fa",
        "expected_ids": []
    },
    "tests/test_hia_slot_ledger_native.py": {
        "bytes": 77450,
        "sha256": "59a8d0b712fe61f2a84b2ea11edea99c0e0a6201612452b3ee4683e9dea2485f",
        "expected_ids": []
    }
})
GROUPS = {
    'agent': {'selector': None, 'expected': 48, 'nested': None},
    'namespace': {'selector': 'tests.test_hia_artifact_namespace_native.ArtifactNamespaceNativeTests.test_original_agent_tools_and_campaign_with_all_three_owners_and_no_namespace_reference',
                  'expected': 1, 'nested': 35},
    'ledger': {'selector': 'tests.test_hia_slot_ledger_native.SlotLedgerNativeTests.test_original_tools_campaign_buffers_and_lease_snapshot_with_four_native_owners',
               'expected': 1, 'nested': 48},
}
SELECTED_GROUP = 'agent'
REQUIRED_MODES = frozenset(range(1, 8))


def configure_group(name):
    global SELECTED_GROUP, ORIGINAL_MODULES, EXPECTED_COUNT, REQUIRED_MODES
    _require(name in GROUPS, 'unknown original artifacts caller group')
    SELECTED_GROUP = name
    descriptor = GROUPS[name]
    ORIGINAL_MODULES = _AGENT_MODULES if name == 'agent' else (descriptor['selector'],)
    EXPECTED_COUNT = descriptor['expected']
    REQUIRED_MODES = frozenset(range(1, 8))


def valid_modes(counts):
    from hepta.hia_service_artifacts_foreign import FUNCTION_LAYOUT
    return (type(counts) is dict and REQUIRED_MODES <= set(counts)
            and set(counts) <= {row[0] for row in FUNCTION_LAYOUT}
            and all(type(mode) is int for mode in counts)
            and all(type(count) is int and count > 0 for count in counts.values()))


def nested_ids():
    if SELECTED_GROUP == 'agent':
        return []
    classes = ('ArtifactContractTests', 'CandidateAndVerificationTests', 'MachinePlanTests',
               'NativeLifecycleTests', 'AgentStoreDirectoryPermissionTests', 'QualificationCampaignTests')
    if SELECTED_GROUP == 'ledger':
        classes += ('BufferLifecycleTests', 'LeaseSnapshotTests')
    available = [name for module in _AGENT_MODULES
                 for name in _AGENT_FILES[module.replace('.', '/')+'.py']['expected_ids']]
    return [name for cls in classes for name in available if name.split('.')[-2] == cls]


def _require(value, message):
    if not value:
        raise ValueError(message)


def _pairs(items):
    value = {}
    for key, item in items:
        _require(key not in value, 'duplicate artifacts qualification field')
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
    _require(path.read_bytes() == raw, 'artifacts qualification publication differs')


def _file(path):
    path = Path(path).resolve(strict=True)
    raw = path.read_bytes()
    return {'path': str(path), 'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


def original_ids():
    if SELECTED_GROUP != 'agent':
        return [GROUPS[SELECTED_GROUP]['selector']]
    return [name for module in _AGENT_MODULES
            for name in _AGENT_FILES[module.replace('.', '/') + '.py']['expected_ids']]


EXECUTION_SOURCE_FILES = ('tests/test_hia_slot_ledger_continuation_native.py',)


def execution_ids():
    from tools.hia_retained_agent_callers import execution_id
    return [execution_id(name) for name in original_ids()]


def caller_id_map():
    return [{'original': old, 'executed': actual}
            for old, actual in zip(original_ids(), execution_ids())]


def admit_original_files(root=ROOT):
    from tools.hia_retained_agent_callers import admit_source
    admitted = {name: admit_source(root, name, expected) for name, expected in ORIGINAL_FILES.items()}
    ids = original_ids()
    _require(len(ids) == len(set(ids)) == EXPECTED_COUNT, 'original Agent denominator differs')
    return admitted


def flatten(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from flatten(item)
        else:
            yield item


def load_original_suite():
    admit_original_files()
    loader = unittest.TestLoader()
    from tools.hia_retained_agent_callers import execution_id
    execution_modules = tuple(execution_id(name) for name in ORIGINAL_MODULES)
    suite = loader.loadTestsFromNames(execution_modules)
    loaded = [test.id() for test in flatten(suite)]
    _require(not loader.errors and loaded == execution_ids(), 'original ordered Agent discovery differs')
    for name in execution_modules:
        module = '.'.join(name.split('.')[:2])
        _require(Path(sys.modules[module].__file__).resolve() == ROOT / (module.replace('.', '/') + '.py'),
                 'original Agent module was imported from a different source')
    return suite, loaded


def _snapshot():
    from tools import build_hia_service_artifacts as builder
    from tools.build_hia_json_preflight import current_sources
    return {**current_sources(), **{name: sha256((ROOT / name).read_bytes()).hexdigest()
                                   for name in (*builder.DEVELOPMENT_INPUT_NAMES, *SELF_SOURCES, *ORIGINAL_FILES)}}


def _admit_selection(cold_report, development_compiler):
    """No output writes; every cold input is bound before a builder can run."""
    from tools import build_hia_service_artifacts as builder
    _require((cold_report is None) != (development_compiler is None), 'one explicit artifacts compiler selection required')
    admit_original_files()
    held = {}
    if cold_report is not None:
        cold_path = Path(cold_report).resolve(strict=True)
        cold_raw = cold_path.read_bytes()
        outer = _json(cold_raw)
        nested_path = Path(outer['nested_report']).resolve(strict=True)
        nested_raw = nested_path.read_bytes()
        _require(sha256(nested_raw).hexdigest() == outer.get('nested_report_sha256'),
                 'artifacts caller nested cold receipt identity differs')
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
                 'artifacts caller cold limits must remain 180+3')
        _require(nested.get('source_manifest') == sources
                 and [row.get('produced_sha256') for row in generations] == outer['generation_sha256'],
                 'artifacts caller cold source or generation custody differs')
        for name in (*builder.REQUIRED_SOURCE_NAMES, *SELF_SOURCES, *ORIGINAL_FILES):
            _require(sources.get(name) == sha256((ROOT / name).read_bytes()).hexdigest(),
                     'artifacts caller input is outside the current cold contract: ' + name)
        held.update({cold_path: cold_raw, nested_path: nested_raw, compiler: compiler_raw})
        scope = 'MATCHING_SOURCE_COLD_SELECTED_CALLERS'
    else:
        compiler = Path(development_compiler).resolve(strict=True)
        held[compiler] = compiler.read_bytes()
        scope = 'EXPLICIT_COMPILER_DEVELOPMENT_ONLY'
    return compiler, held, _snapshot(), scope


def _guard(held, sources):
    _require(all(path.read_bytes() == raw for path, raw in held.items()), 'held artifacts qualification input changed')
    _require(_snapshot() == sources, 'artifacts qualification source identity changed')


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
    return bool(loaded == execution_ids() and executed == loaded
                and type(result.testsRun) is int and result.testsRun == EXPECTED_COUNT
                and not any(getattr(result, name) for name in (
                    'failures', 'errors', 'skipped', 'expectedFailures', 'unexpectedSuccesses'))
                and not references and valid_modes(dict(modes)) and valid_modes(dict(native_modes)))


def _admit_child_observations(child, request_sha256):
    _require(type(child) is dict and child.get('schema') == 'hepta.hia.service-artifacts-caller-observations.v1'
             and child.get('scope') == 'OBSERVATIONS_ONLY_NO_COLD_AUTHORITY'
             and child.get('status') == 'PASS' and child.get('request_sha256') == request_sha256
             and child.get('loaded_ids') == child.get('executed_ids') == execution_ids()
             and type(child.get('tests_run')) is int and child['tests_run'] == EXPECTED_COUNT
             and child.get('source_and_inputs_unchanged') is True,
             'original artifacts caller observation custody differs')
    if SELECTED_GROUP == 'ledger':
        _require(child.get('original_to_executed_ids') == caller_id_map(),
                 'original ledger to continuation caller identity differs')
    for name in ('failures', 'errors', 'skips', 'expected_failures', 'unexpected_successes', 'reference_calls'):
        _require(type(child.get(name)) is list and not child[name], 'original caller anomaly: ' + name)
    for name in ('native_mode_calls', 'actual_machine_mode_returns'):
        counts = child.get(name)
        _require(type(counts) is dict
                 and all(type(key) is str and key.isascii() and key.isdigit() and str(int(key)) == key for key in counts)
                 and valid_modes({int(key): value for key, value in counts.items()}),
                 'actual artifacts public/helper/lexical routes or machine modes were not observed')
    _require(type(child.get('actual_mappings')) is int and child['actual_mappings'] > 0
             and type(child.get('actual_machine_returns')) is int
             and child['actual_machine_returns'] == sum(child['actual_machine_mode_returns'].values()),
             'actual artifacts machine-return accounting differs')


def _child(request_path):
    request_raw = request_path.read_bytes()
    request = _json(request_raw)
    configure_group(request.get('caller_group', 'agent'))
    output = Path(request['output'])
    report = {'schema': 'hepta.hia.service-artifacts-caller-observations.v1', 'status': 'STARTED',
              'scope': 'OBSERVATIONS_ONLY_NO_COLD_AUTHORITY', 'python': sys.version,
              'request_sha256': sha256(request_raw).hexdigest(), 'expected_count': EXPECTED_COUNT, 'caller_group': SELECTED_GROUP,
              'reference_poison_scope': 'test process; child processes inherit the selector, not Python patches',
              'existing_verifier_emitter_linker_store_providers_replaced': False, 'original_test_budgets_changed': False}
    started = time.monotonic_ns()
    references, images, executed = [], [], []
    modes, entries, per_test = Counter(), Counter(), Counter()
    active = ['outside-test']
    all_execution, nested_results = [], []
    try:
        _require(request['schema'] == 'hepta.hia.service-artifacts-caller-request.v1', 'unknown caller request')
        _require(_snapshot() == request['source_manifest'], 'child source identity differs')
        for row in request['input_bindings']:
            _require(_file(row['path']) == row, 'child executable or receipt identity differs')
        manifest_path = Path(request['manifest'])
        manifest = _json(manifest_path.read_bytes())
        _require(os.environ.get(SELECTOR) == str(manifest_path), 'child explicit selector differs')
        from hepta import hia_agent_service as service_api
        HIAAgentService = service_api.HIAAgentService
        from hepta.hia_service_artifacts_native import (
            NativeArtifactsImage, ArtifactsFrame, _mapped_artifacts)
        from hepta.hia_machine_plan_control_native import MAGIC
        _require(_mapped_artifacts.cache_info().currsize == 0, 'caller observer requires fresh process image custody')
        original_init, original_frame_init = NativeArtifactsImage.__init__, ArtifactsFrame.__init__

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
                             'actual artifacts machine entry did not return its complete ABI receipt')
                    words = struct.unpack('<21Q', ctypes.string_at(state, 168))
                    _require(words[16] == MAGIC and words[19] in range(1, image.function_count + 1)
                             and struct.unpack('<2Q', ctypes.string_at(result, 16)) == (MAGIC, words[17]),
                             'actual artifacts machine state/output identity differs')
                    entries[words[19]] += 1
                    per_test[active[0]] += 1
                return returned
            image._entry = counted_entry

        def counted_frame(frame, image, mode, arguments, captures=(), *, witness=None):
            original_frame_init(frame, image, mode, arguments, captures, witness=witness)
            modes[mode] += 1

        def forbidden(*unused, **ignored):
            references.append(active[0])
            raise AssertionError('selected artifacts invoked retained policy')

        base_start = unittest.TextTestResult.startTest
        base_run = unittest.TextTestRunner.run
        def observed_start(result, test):
            active[0] = test.id()
            all_execution.append(test.id())
            return base_start(result, test)
        def observed_run(runner, suite):
            selected = [test.id() for test in flatten(suite)]
            result = base_run(runner, suite)
            if selected == nested_ids() and SELECTED_GROUP != 'agent':
                nested_results.append({'loaded_ids': selected, 'tests_run': result.testsRun,
                    'failures': [(test.id(), trace) for test, trace in result.failures],
                    'errors': [(test.id(), trace) for test, trace in result.errors],
                    'skips': [(test.id(), why) for test, why in result.skipped],
                    'expected_failures': [(test.id(), trace) for test, trace in result.expectedFailures],
                    'unexpected_successes': [test.id() for test in result.unexpectedSuccesses]})
            return result

        class Result(unittest.TextTestResult):
            def startTest(self, test):
                active[0] = test.id()
                executed.append(test.id())
                super().startTest(test)

        with ExitStack() as stack:
            stack.enter_context(patch.object(unittest.TextTestResult, 'startTest', observed_start))
            stack.enter_context(patch.object(unittest.TextTestRunner, 'run', observed_run))
            stack.enter_context(patch.object(NativeArtifactsImage, '__init__', counted_init))
            stack.enter_context(patch.object(ArtifactsFrame, '__init__', counted_frame))
            for name in REFERENCE_METHODS:
                stack.enter_context(patch.object(HIAAgentService, name, forbidden))
            for name in REFERENCE_FUNCTIONS:
                stack.enter_context(patch.object(service_api, name, forbidden))
            suite, loaded = load_original_suite()
            report['loaded_ids'] = loaded
            report['executed_test_source_admission'] = admit_original_files()
            report['original_to_executed_ids'] = caller_id_map()
            result = unittest.TextTestRunner(verbosity=2, resultclass=Result).run(suite)
        report.update(tests_run=result.testsRun, executed_ids=executed,
                      failures=[(test.id(), trace) for test, trace in result.failures],
                      errors=[(test.id(), trace) for test, trace in result.errors],
                      skips=[(test.id(), why) for test, why in result.skipped],
                      expected_failures=[(test.id(), trace) for test, trace in result.expectedFailures],
                      unexpected_successes=[test.id() for test in result.unexpectedSuccesses])
        _require(images and all(image.image_sha256 == manifest['image_sha256']
                 and sha256(image._mapping[:]).hexdigest() == manifest['image_sha256'] for image in images),
                 'actual held artifacts image changed')
        report['status'] = 'PASS' if _strict_result(result, loaded, executed, references, modes, entries) else 'FAIL'
        if SELECTED_GROUP != 'agent':
            expected_nested = nested_ids()
            nested_executed = [name for name in all_execution if name in set(expected_nested)]
            _require(len(expected_nested) == GROUPS[SELECTED_GROUP]['nested']
                     and nested_executed == expected_nested and len(nested_results) == 1,
                     'original nested ordered caller denominator differs')
            nested = nested_results[0]
            _require(nested['tests_run'] == len(expected_nested) and type(nested['tests_run']) is int
                     and not any(nested[key] for key in ('failures', 'errors', 'skips',
                         'expected_failures', 'unexpected_successes')),
                     'complete original nested caller gate failed')
    except BaseException:
        report.update(status='FAIL', traceback=traceback.format_exc())
    finally:
        report.update(elapsed_ns=time.monotonic_ns() - started, reference_calls=references,
                      all_executed_ids=all_execution, nested_results=nested_results,
                      native_mode_calls=dict(modes), actual_machine_mode_returns=dict(entries),
                      actual_machine_returns=sum(entries.values()), per_test_machine_returns=dict(per_test),
                      actual_mappings=len(images), mechanism_artifacts_excluded_from_mode_counts=True)
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


def qualify(output, *, cold_report=None, development_compiler=None, caller_group='agent'):
    from tools import build_hia_service_artifacts as builder
    configure_group(caller_group)
    output = Path(output).absolute()
    _require(not output.exists() and not output.is_symlink(), 'new exclusive artifacts caller evidence directory required')
    environment, removed = _clean_environment(os.environ)
    with patch.dict(os.environ, environment, clear=True):
        compiler, held, sources, scope = _admit_selection(cold_report, development_compiler)
        prerequisites = _prerequisites(environment)
        _guard(held, sources)
        output.mkdir(mode=0o700)
        report = {'schema': 'hepta.hia.service-artifacts-callers.v1', 'status': 'STARTED', 'scope': scope,
                  'source_manifest': sources, 'prerequisites': prerequisites, 'original_modules': ORIGINAL_MODULES,
                  'expected_count': EXPECTED_COUNT, 'caller_group': SELECTED_GROUP, 'nested_expected_count': GROUPS[SELECTED_GROUP]['nested'], 'original_test_sources': ORIGINAL_FILES,
                  'executed_test_source_admission': admit_original_files(),
                  'original_to_executed_ids': caller_id_map(),
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
            request = {'schema': 'hepta.hia.service-artifacts-caller-request.v1', 'manifest': str(manifest), 'caller_group': SELECTED_GROUP,
                       'source_manifest': sources, 'input_bindings': [_file(path) for path in held],
                       'output': str(output / 'original-agent-48.json')}
            request_path = output / 'caller-request.json'
            _publish(request_path, _wire(request))
            held[request_path] = request_path.read_bytes()
            report['selected_manifest'] = str(manifest)
            report['input_bindings'] = request['input_bindings']
            environment[SELECTOR] = str(manifest)
            if SELECTED_GROUP != 'agent':
                prefix = 'HEPTA_HIA_ARTIFACT_NAMESPACE' if SELECTED_GROUP == 'namespace' else 'HEPTA_HIA_SLOT_LEDGER_CONTINUATION'
                environment[prefix+'_EVIDENCE'] = str(output/'original-nested-evidence')
                if cold_report is not None:
                    environment[prefix+'_COLD_REPORT'] = str(Path(cold_report).resolve())
                else:
                    environment[prefix+'_DEVELOPMENT_COMPILER'] = str(compiler)
            terminal = _run_child(request_path, output, environment)
            report['terminal'] = terminal
            child = _json((output / 'original-agent-48.json').read_bytes())
            report['original_agent'] = child
            _admit_child_observations(child, sha256(held[request_path]).hexdigest())
            _require(type(terminal.get('returncode')) is int and terminal['returncode'] == 0
                     and terminal['timed_out'] is False,
                     'complete original artifacts caller gate failed')
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
    parser.add_argument('--caller-group', choices=tuple(GROUPS), default='agent')
    args = parser.parse_args(argv)
    report = qualify(args.evidence, cold_report=args.cold_report, development_compiler=args.development_compiler,
                     caller_group=args.caller_group)
    print(json.dumps({name: report.get(name) for name in ('status', 'scope', 'expected_count', 'source_and_inputs_unchanged')}))
    return 0 if report['status'].endswith('_PASS') else 1


if __name__ == '__main__':
    raise SystemExit(main())
