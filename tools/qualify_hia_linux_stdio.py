"""Qualify the public fixed-fd Linux profile with original current-source cold inputs.

Preparation and the complete fixed caller group each use an owned 180+3-second
process. Every compiler/packer call retains 20 seconds and 1 MiB. The qualifier
accepts no caller-pinned development compiler or preexisting fixture override.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import platform
import sys
import time
import traceback
import unittest

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ''}:
    sys.path.insert(0, str(ROOT))

from hepta.hia_agent_assembly import assemble_program
from hepta.hia_linux_stdio import PROFILE
from tools.hia_linux_stdio_cold import (
    CAPACITY, CASE_NAMES, CASE_SOURCES, admit_cold, check_bindings, decode,
    digest, guard_authority, pin, publish, re_admit_authority, require,
)
from tools.build_hia_linux_stdio_cold import (
    admit_program, admit_toolchain, build_program, build_toolchain,
)

COLD_FIXTURE_ENV = 'HEPTA_HIA_LINUX_STDIO_COLD_FIXTURE'
EVIDENCE_ENV = 'HEPTA_HIA_LINUX_STDIO_TEST_EVIDENCE'
FIXTURE_SCHEMA = 'hepta.hia.linux-stdio-cold-fixture.v1'
FIXTURE_STATUS = 'MATCHING_CURRENT_SOURCE_COLD_FIXTURE_BUILT'
GROUP_SECONDS = 180
CLEANUP_SECONDS = 3
COMPILE_SECONDS = 20
ANOMALIES = ('failures', 'errors', 'skipped', 'expected_failures', 'unexpected_successes')
SELECTORS = ('tests.test_hia_linux_stdio.LinuxStdioPublicSourceTests',
             'tests.test_hia_program', 'tests.test_hia_agent_assembly',
             'tests.test_hia_linux_stdio_cold.LinuxStdioMatchingColdNativeTests')
EXPECTED_IDS = ('tests.test_hia_linux_stdio.LinuxStdioPublicSourceTests.test_bounds_proven_before_provider_including_overflow_and_zero_count',
 'tests.test_hia_linux_stdio.LinuxStdioPublicSourceTests.test_callee_effect_propagation_and_unknown_host_target_are_closed',
 'tests.test_hia_linux_stdio.LinuxStdioPublicSourceTests.test_default_assembly_core_vm_and_code_still_refuse_extended_input',
 'tests.test_hia_linux_stdio.LinuxStdioPublicSourceTests.test_default_global_opcode_and_effect_tables_are_not_extended',
 'tests.test_hia_linux_stdio.LinuxStdioPublicSourceTests.test_exact_negative_errno_short_read_and_zero_still_issue_one_effect',
 'tests.test_hia_linux_stdio.LinuxStdioPublicSourceTests.test_exact_one_mib_read_and_write_buffers_are_preserved',
 'tests.test_hia_linux_stdio.LinuxStdioPublicSourceTests.test_exact_types_effects_and_empty_attributes_are_mandatory',
 'tests.test_hia_linux_stdio.LinuxStdioPublicSourceTests.test_explicit_profile_is_exact_and_never_guessed_from_module',
 'tests.test_hia_linux_stdio.LinuxStdioPublicSourceTests.test_forged_or_modified_verified_bytes_are_rechecked',
 'tests.test_hia_linux_stdio.LinuxStdioPublicSourceTests.test_original_compiler_bounds_and_entry_schema_are_not_widened',
 'tests.test_hia_linux_stdio.LinuxStdioPublicSourceTests.test_parent_suspend_and_loan_end_use_the_real_capability_checker',
 'tests.test_hia_linux_stdio.LinuxStdioPublicSourceTests.test_provider_domain_and_foreign_exception_identity_are_preserved',
 'tests.test_hia_linux_stdio.LinuxStdioPublicSourceTests.test_public_builder_rejects_bad_profile_and_compiler_pin_before_execution',
 'tests.test_hia_linux_stdio.LinuxStdioPublicSourceTests.test_public_byte_boundary_exact_types_and_original_extent_limits',
 'tests.test_hia_linux_stdio.LinuxStdioPublicSourceTests.test_public_roundtrip_checks_actual_io_opcodes_without_proxy_calls',
 'tests.test_hia_linux_stdio.LinuxStdioPublicSourceTests.test_reference_signal_is_explicit_exact_and_retains_full_state',
 'tests.test_hia_linux_stdio.LinuxStdioPublicSourceTests.test_request_carries_no_mutable_owner_or_implicit_real_fd_provider',
 'tests.test_hia_linux_stdio.LinuxStdioPublicSourceTests.test_step_stop_is_not_errno_and_runs_no_provider',
 'tests.test_hia_program.CanonicalInputAndCFGTests.test_canonical_input_and_duplicate_keys',
 'tests.test_hia_program.CanonicalInputAndCFGTests.test_immutable_snapshot_and_rechecked_public_constructor',
 'tests.test_hia_program.CanonicalInputAndCFGTests.test_malformed_values_reject_with_controlled_errors',
 'tests.test_hia_program.CanonicalInputAndCFGTests.test_ssa_cfg_effect_and_unknown_claim_rejections',
 'tests.test_hia_program.CanonicalInputAndCFGTests.test_wrong_json_container_at_each_schema_position_is_rejected',
 'tests.test_hia_program.ResourceExecutionTests.test_allocation_failure_empty_owner_multireturn_and_error_cleanup',
 'tests.test_hia_program.ResourceExecutionTests.test_borrowed_call_reborrow_and_resume_parent',
 'tests.test_hia_program.ResourceExecutionTests.test_local_stored_view_and_owner_cross_blocks_together',
 'tests.test_hia_program.ResourceExecutionTests.test_loop_carries_owner_and_mutable_loan_identity',
 'tests.test_hia_program.ResourceExecutionTests.test_write_read_move_drop_and_bounds',
 'tests.test_hia_program.ScalarExecutionTests.test_checked_and_wrapping_at_every_integer_width',
 'tests.test_hia_program.ScalarExecutionTests.test_closed_block_loop_and_calls',
 'tests.test_hia_program.ScalarExecutionTests.test_exact_arguments_and_no_host_fabricated_capabilities',
 'tests.test_hia_program.ScalarExecutionTests.test_signed_division_remainder_and_shift_semantics',
 'tests.test_hia_program.ScalarExecutionTests.test_step_heap_and_call_budgets_are_not_semantic_traps',
 'tests.test_hia_program.StaticRejectionTests.test_callee_cannot_end_or_return_external_loan',
 'tests.test_hia_program.StaticRejectionTests.test_consumed_owners_borrows_and_silent_loss',
 'tests.test_hia_program.StaticRejectionTests.test_duplicate_edge_owner_and_missing_parent_reject',
 'tests.test_hia_program.StaticRejectionTests.test_exclusive_call_arguments_must_not_alias',
 'tests.test_hia_program.StaticRejectionTests.test_join_cannot_change_loan_root_despite_matching_types',
 'tests.test_hia_program.StaticRejectionTests.test_suspended_parent_cannot_be_accessed_or_ended_first',
 'tests.test_hia_agent_assembly.HIAAgentAssemblyTests.test_accepted_diagnostic_is_not_a_deployment_receipt',
 'tests.test_hia_agent_assembly.HIAAgentAssemblyTests.test_actual_mathematical_wide_sum_and_canonical_rerender',
 'tests.test_hia_agent_assembly.HIAAgentAssemblyTests.test_atomic_cross_function_interface_upgrade_needs_both_changes',
 'tests.test_hia_agent_assembly.HIAAgentAssemblyTests.test_byte_line_and_inventory_limits_apply_before_core_verification',
 'tests.test_hia_agent_assembly.HIAAgentAssemblyTests.test_checked_overflow_and_declared_trap_are_not_dropped',
 'tests.test_hia_agent_assembly.HIAAgentAssemblyTests.test_dropped_owner_is_not_synthesized_to_repair_a_leak',
 'tests.test_hia_agent_assembly.HIAAgentAssemblyTests.test_duplicate_json_keys_nonfinite_and_nesting_are_not_accepted',
 'tests.test_hia_agent_assembly.HIAAgentAssemblyTests.test_duplicate_ssa_keeps_core_error_without_guessing_a_location',
 'tests.test_hia_agent_assembly.HIAAgentAssemblyTests.test_explicit_empty_exports_and_absence_are_distinct',
 'tests.test_hia_agent_assembly.HIAAgentAssemblyTests.test_missing_terminator_end_extra_text_and_duplicate_exports_reject',
 'tests.test_hia_agent_assembly.HIAAgentAssemblyTests.test_owner_move_loans_and_cleanup_execute_in_existing_vm',
 'tests.test_hia_agent_assembly.HIAAgentAssemblyTests.test_real_joined_loans_cfg_parameters_preserve_origin',
 'tests.test_hia_agent_assembly.HIAAgentAssemblyTests.test_recursive_chain_v7_roundtrip_and_failure_paths',
 'tests.test_hia_agent_assembly.HIAAgentAssemblyTests.test_unknown_header_historical_and_nominal_profiles_reject',
 'tests.test_hia_agent_assembly.HIAAgentAssemblyTests.test_unsafe_loan_overlap_is_rejected_by_original_verifier',
 'tests.test_hia_agent_assembly.HIAAgentAssemblyTests.test_use_after_move_is_rejected_by_original_verifier',
 'tests.test_hia_agent_assembly.HIAAgentAssemblyTests.test_utf8_controls_and_explicit_line_diagnostic',
 'tests.test_hia_agent_assembly.HIAAgentAssemblyTests.test_wrong_signature_unknown_operation_and_missing_attribute_reject',
 'tests.test_hia_linux_stdio_cold.LinuxStdioMatchingColdNativeTests.test_01_empty_input',
 'tests.test_hia_linux_stdio_cold.LinuxStdioMatchingColdNativeTests.test_02_short_binary_input',
 'tests.test_hia_linux_stdio_cold.LinuxStdioMatchingColdNativeTests.test_03_zero_count_open',
 'tests.test_hia_linux_stdio_cold.LinuxStdioMatchingColdNativeTests.test_04_zero_count_closed_read',
 'tests.test_hia_linux_stdio_cold.LinuxStdioMatchingColdNativeTests.test_05_zero_count_closed_write',
 'tests.test_hia_linux_stdio_cold.LinuxStdioMatchingColdNativeTests.test_06_full_signed_read_ebadf',
 'tests.test_hia_linux_stdio_cold.LinuxStdioMatchingColdNativeTests.test_07_full_signed_write_ebadf',
 'tests.test_hia_linux_stdio_cold.LinuxStdioMatchingColdNativeTests.test_08_sigpipe_default',
 'tests.test_hia_linux_stdio_cold.LinuxStdioMatchingColdNativeTests.test_09_sigpipe_inherited_ignore_epipe',
 'tests.test_hia_linux_stdio_cold.LinuxStdioMatchingColdNativeTests.test_10_exact_one_mib',
 'tests.test_hia_linux_stdio_cold.LinuxStdioMatchingColdNativeTests.test_11_over_one_mib_rejected_before_write',
 'tests.test_hia_linux_stdio_cold.LinuxStdioMatchingColdNativeTests.test_12_bounds_before_read')
TEST_SOURCE_PINS = {'tests/test_hia_linux_stdio.py': 'fd406365f9d846f7c90471e9054653dd53f77918d05d27d37792914c8ee53cd8',
 'tests/test_hia_program.py': '73de53638397a1d564b3580551c83fa0ecf936c79af3ba1c5334b929aad45d3c',
 'tests/test_hia_agent_assembly.py': '2f429e970da879bb5e4e65f414c415cfe4df6577cfb3d9618a9c8a64d992c7f7',
 'tests/test_hia_linux_stdio_cold.py': 'a483f7344b4362eadaa5a87d4c258d834a2026e7e8f5621bc23adfbd47485019',
 'tests/hia_linux_stdio_cases.py': 'c7085e1660cb04b54db46058e10ea1ef953261acc1d60c3b72499554b7c0a1ef'}
CASE_SOURCE_SHA256 = {
    'bounded-copy': 'ff2cfe22ecb8b54677a1f6820c0618feb6c4e9d857c70a2071559cbe12076e91',
    'zero-transfer': '8d208dd89553443c4d3866e64db714245bdea6d4b0a7ec7d0ca346a4cfce106e',
    'read-ebadf-exact': 'fc50d996c4dfdc6693b16c9c223d768c26666210e4c79c7daf99e516d41b66f4',
    'write-ebadf-exact': '77459de4cba8cc80a79fe0d8c7b7ae25f61bec78a7f616e4df391d0489d92420',
    'out-of-bounds': 'c51d080ba7d529f04a16792323a6c5f77a56ba1e81b28d9fdea8a0df239d63ea',
}


def _case_source(name):
    require(name in CASE_NAMES, 'unknown retained Linux stdio test program')
    path = ROOT / CASE_SOURCES[CASE_NAMES.index(name)]
    raw = path.read_bytes()
    require(digest(raw) == CASE_SOURCE_SHA256[name], 'retained test HIA source changed: ' + name)
    return raw


def _check_test_sources():
    require(len(TEST_SOURCE_PINS) == 5, 'complete caller/module/helper source pins required')
    for name, expected in TEST_SOURCE_PINS.items():
        require(digest((ROOT / name).read_bytes()) == expected, 'frozen original caller source changed: ' + name)


def prepare_fixture(output, cold_report):
    authority = admit_cold(cold_report)
    _check_test_sources()
    folder = Path(output).absolute()
    folder.mkdir(mode=0o700, parents=False, exist_ok=False)
    report = {'schema': 'hepta.hia.linux-stdio-cold-fixture-preparation.v1',
        'status': 'FAIL', 'matching_cold': False, 'qualification_complete': False,
        'whole_native': False, 'authority': authority, 'programs': {}}
    try:
        toolchain = build_toolchain(folder / 'toolchain', cold_report,
                                    compiler=authority['compiler'])
        admit_toolchain(toolchain, authority=authority)
        for name in CASE_NAMES:
            raw = _case_source(name)
            checked = assemble_program(raw, profile=PROFILE)
            path = build_program(checked, folder / name, profile=PROFILE,
                cold_report=cold_report, compiler=authority['compiler'], toolchain=toolchain)
            built = admit_program(path, authority=authority)
            report['programs'][name] = {'build': pin(path), 'source_sha256': digest(raw),
                'program_sha256': checked.sha256,
                'executable': built['executable']['path'],
                'executable_sha256': built['executable']['sha256']}
        fixture = {'schema': FIXTURE_SCHEMA, 'status': FIXTURE_STATUS,
            'profile': PROFILE, 'authority': authority, 'toolchain': pin(toolchain),
            'programs': report['programs'], 'matching_cold': True,
            'qualification_complete': False, 'whole_native': False,
            'test_source_pins': TEST_SOURCE_PINS}
        guard_authority(authority)
        publish(folder / 'FIXTURE.json', fixture)
        admit_fixture(folder / 'FIXTURE.json')
        report.update(status='PASS', matching_cold=True, fixture=pin(folder / 'FIXTURE.json'))
    except BaseException:
        report.update(status='FAIL', matching_cold=False, traceback=traceback.format_exc())
        raise
    finally:
        publish(folder / 'PREPARATION.json', report)
    return folder / 'FIXTURE.json'


def admit_fixture(path):
    path = Path(path).resolve(strict=True)
    raw = path.read_bytes()
    fixture = decode(raw)
    require(type(fixture) is dict and set(fixture) == {'schema', 'status', 'profile',
            'authority', 'toolchain', 'programs', 'matching_cold',
            'qualification_complete', 'whole_native', 'test_source_pins'}
            and fixture.get('schema') == FIXTURE_SCHEMA
            and fixture.get('status') == FIXTURE_STATUS and fixture.get('profile') == PROFILE
            and fixture.get('matching_cold') is True
            and fixture.get('qualification_complete') is False and fixture.get('whole_native') is False,
            'explicit current-cold fixture required; development results are not authority')
    _check_test_sources()
    require(fixture['test_source_pins'] == TEST_SOURCE_PINS, 'fixture caller source pins differ')
    authority = re_admit_authority(fixture['authority'])
    check_bindings([fixture['toolchain']])
    chain = admit_toolchain(fixture['toolchain']['path'], authority=authority)
    require(type(fixture['programs']) is dict and set(fixture['programs']) == set(CASE_NAMES),
            'complete five actual test programs required')
    for name in CASE_NAMES:
        item = fixture['programs'][name]
        require(type(item) is dict and set(item) == {'build', 'source_sha256', 'program_sha256',
                'executable', 'executable_sha256'}, 'unknown program fixture fields')
        check_bindings([item['build']])
        program = admit_program(item['build']['path'], authority=authority)
        source = _case_source(name)
        require(program['toolchain'] == fixture['toolchain']
                and program['source_sha256'] == digest(source) == item['source_sha256']
                and program['program_sha256'] == assemble_program(source, profile=PROFILE).sha256
                    == item['program_sha256']
                and item['executable'] == program['executable']['path']
                and item['executable_sha256'] == program['executable']['sha256'],
                'actual compiler/packer/program binding differs: ' + name)
    guard_authority(authority)
    require(path.read_bytes() == raw, 'fixture changed during complete fresh admission')
    return fixture


def load_fixture(environment=None):
    environment = os.environ if environment is None else environment
    require(type(environment.get(COLD_FIXTURE_ENV)) is str and environment[COLD_FIXTURE_ENV]
            and type(environment.get(EVIDENCE_ENV)) is str and environment[EVIDENCE_ENV],
            'explicit cold fixture and evidence output are required; no development fallback')
    path = Path(environment[COLD_FIXTURE_ENV]).resolve(strict=True)
    return path, admit_fixture(path), Path(environment[EVIDENCE_ENV]).absolute()


def flatten(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from flatten(item)
        else:
            yield item


def load_suite():
    _check_test_sources()
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromNames(SELECTORS)
    ids = [test.id() for test in flatten(suite)]
    require(not loader.errors and ids == list(EXPECTED_IDS) and len(ids) == len(set(ids)) == 69,
            'complete original57 plus fixed12 discovery differs')
    return suite, ids


def admit_child_report(report, request_sha):
    require(type(report) is dict and report.get('schema') == 'hepta.hia.linux-stdio-cold-observations.v1'
            and report.get('scope') == 'OBSERVATIONS_ONLY_NO_COLD_AUTHORITY'
            and report.get('status') == 'PASS' and report.get('request_sha256') == request_sha
            and report.get('loaded_ids') == list(EXPECTED_IDS)
            and report.get('started_ids') == list(EXPECTED_IDS)
            and report.get('stopped_ids') == list(EXPECTED_IDS)
            and type(report.get('tests_run')) is int and report['tests_run'] == 69
            and report.get('source_and_inputs_unchanged') is True,
            'complete 69-case observations and source guards required')
    anomalies = report.get('anomalies')
    require(type(anomalies) is dict and set(anomalies) == set(ANOMALIES)
            and all(type(anomalies[name]) is list and not anomalies[name] for name in ANOMALIES),
            'failure/error/skip/expected-failure cannot qualify')


def verify_actual_observations(directory, fixture):
    from tests.hia_linux_stdio_cases import case_definitions, case_checks
    directory = Path(directory)
    definitions = case_definitions()
    require(len(definitions) == 12, 'original twelve cases required')
    require({p.name for p in directory.iterdir()} == {row[0] for row in definitions},
            'actual direct-control inventory differs')
    records = []
    for name, program, payload, mode, ignored, rc, expected in definitions:
        folder = directory / name
        actual = decode((folder / 'kernel/OBSERVATION.json').read_bytes())
        reference = decode((folder / 'PUBLIC-VM.json').read_bytes())
        row = decode((folder / 'RESULT.json').read_bytes())
        build = fixture['programs'][program]
        checks = case_checks(name, build, reference, actual, rc, expected)
        require(row == {'id': name, 'program': program, 'checks': checks,
                        'status': 'PASS' if all(checks.values()) else 'FAIL', 'actual': actual}
                and all(value is True for value in checks.values()),
                'retained complete case comparisons differ: ' + name)
        require(actual.get('command') == [str(Path(build['executable']).resolve())]
                and actual.get('runtime_payload_python_or_ctypes') is False
                and actual.get('timed_out') is False and actual.get('reaped_ECHILD') is True
                and type(actual.get('returncode')) is int and actual['returncode'] == rc
                and (folder / 'kernel/stdin.bin').read_bytes() == payload
                and (folder / 'kernel/stdout.bin').read_bytes() == expected
                and (folder / 'kernel/stderr.bin').read_bytes() == b''
                and actual.get('limits') == {'wall': 20, 'cleanup': 3, 'cpu': 10,
                    'address': 256 << 20, 'stack': 8 << 20, 'filesize': 16 << 20, 'fds': 32, 'core': 0}
                and all(type(value) is int for value in actual['limits'].values())
                and reference.get('program_sha256') == build['program_sha256']
                and reference.get('actual_kernel_execution') is False,
                'actual direct process/VM inputs, limits or source differ: ' + name)
        records.append({'id': name, 'kernel': pin(folder / 'kernel/OBSERVATION.json'),
                        'reference': pin(folder / 'PUBLIC-VM.json'), 'result': pin(folder / 'RESULT.json')})
    return records


def _child(request_path):
    raw = Path(request_path).read_bytes()
    request = decode(raw)
    output = Path(request['output'])
    output.mkdir(mode=0o700)
    report = {'schema': 'hepta.hia.linux-stdio-cold-observations.v1',
        'scope': 'OBSERVATIONS_ONLY_NO_COLD_AUTHORITY', 'status': 'FAIL',
        'request_sha256': digest(raw), 'python': sys.version,
        'loaded_ids': [], 'started_ids': [], 'stopped_ids': [], 'tests_run': 0,
        'anomalies': {name: [] for name in ANOMALIES}}
    fixture = None
    try:
        require(request.get('schema') == 'hepta.hia.linux-stdio-cold-request.v1', 'unknown child request')
        selected, fixture, observations = load_fixture()
        require(str(selected) == request['fixture'] and pin(selected) == request['fixture_binding']
                and str(observations) == str(output / 'observations')
                and fixture['authority']['source_manifest'] == request['source_manifest'],
                'child source or fixture selection differs')
        suite, ids = load_suite()
        report['loaded_ids'] = ids
        class Result(unittest.TextTestResult):
            def startTest(self, test):
                report['started_ids'].append(test.id())
                super().startTest(test)
            def stopTest(self, test):
                report['stopped_ids'].append(test.id())
                super().stopTest(test)
        result = unittest.TextTestRunner(verbosity=2, resultclass=Result).run(suite)
        report['tests_run'] = result.testsRun
        report['anomalies'] = {
            'failures': [(test.id(), trace) for test, trace in result.failures],
            'errors': [(test.id(), trace) for test, trace in result.errors],
            'skipped': [(test.id(), why) for test, why in result.skipped],
            'expected_failures': [(test.id(), trace) for test, trace in result.expectedFailures],
            'unexpected_successes': [test.id() for test in result.unexpectedSuccesses]}
        if report['started_ids'] == report['stopped_ids'] == ids and result.testsRun == 69 and not any(report['anomalies'].values()):
            verify_actual_observations(observations, fixture)
            report['status'] = 'PASS'
    except BaseException:
        report.update(status='FAIL', traceback=traceback.format_exc())
    finally:
        try:
            require(fixture is not None, 'child never admitted strict cold fixture')
            guard_authority(fixture['authority'])
            require(admit_fixture(request['fixture']) == fixture
                    and pin(request['fixture']) == request['fixture_binding']
                    and Path(request_path).read_bytes() == raw, 'child inputs changed')
            report['source_and_inputs_unchanged'] = True
        except BaseException:
            report.update(status='FAIL', source_and_inputs_unchanged=False,
                          final_guard_error=traceback.format_exc())
        publish(output / 'RESULT.json', report)
    return 0 if report['status'] == 'PASS' else 1


def _prepare(output, cold_report):
    report = {'schema': 'hepta.hia.linux-stdio-preparation-terminal.v1', 'status': 'FAIL'}
    try:
        selected = prepare_fixture(Path(output) / 'fixture', cold_report)
        report.update(status='PASS', fixture=str(selected), fixture_binding=pin(selected))
    except BaseException:
        report['traceback'] = traceback.format_exc()
    publish(Path(output) / 'PREPARE.json', report)
    return 0 if report['status'] == 'PASS' else 1


def _owner(command, environment, folder):
    from tools.hia_selfhost_process_owner import run_owned
    folder.mkdir(mode=0o700)
    result = run_owned(command, cwd=ROOT, env=environment,
        stdout_path=folder / 'stdout.log', stderr_path=folder / 'stderr.log',
        receipt_path=folder / 'OWNER.json',
        qualification_seconds=GROUP_SECONDS, cleanup_seconds=CLEANUP_SECONDS)
    return result


def _owner_pass(owner):
    return (type(owner) is dict and owner.get('schema') == 'hepta.hia.selfhost-process-owner.v1'
        and owner.get('status') == 'OWNED_PROCESS_COMPLETED'
        and type(owner.get('returncode')) is int and owner['returncode'] == 0
        and type(owner.get('qualification_seconds')) is int and owner['qualification_seconds'] == GROUP_SECONDS
        and type(owner.get('cleanup_seconds')) is int and owner['cleanup_seconds'] == CLEANUP_SECONDS
        and owner.get('timed_out') is False and owner.get('exit_observed_before_deadline') is True
        and type(owner.get('cleanup')) is dict and owner['cleanup'].get('complete') is True)


def qualify(cold_report, evidence):
    require(COLD_FIXTURE_ENV not in os.environ and EVIDENCE_ENV not in os.environ,
            'standalone qualifier accepts its explicit cold report, not ambient fixture selections')
    authority = admit_cold(cold_report)
    require(sys.platform == 'linux' and platform.machine().lower() in ('x86_64', 'amd64'),
            'Linux x86-64 required; no skip fallback')
    _check_test_sources()
    folder = Path(evidence).absolute()
    folder.mkdir(mode=0o700, parents=False, exist_ok=False)
    report = {'schema': 'hepta.hia.linux-stdio-cold-qualification.v1', 'status': 'FAIL',
        'scope': 'MATCHING_CURRENT_SOURCE_COLD', 'authority': authority,
        'matching_cold': False, 'qualification_complete': False, 'whole_native': False,
        'default_activated': False, 'expected_ids': list(EXPECTED_IDS),
        'expected_count': 69, 'group_seconds': GROUP_SECONDS,
        'cleanup_seconds': CLEANUP_SECONDS, 'compile_seconds': COMPILE_SECONDS,
        'compiler_output_and_workspace_bytes': CAPACITY,
        'direct_control_wall_seconds': 20, 'direct_control_cleanup_seconds': 3,
        'python': sys.version, 'source_before': authority['source_manifest']}
    environment = {'PATH': os.environ.get('PATH', ''), 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
                   'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONHASHSEED': '0'}
    started = time.monotonic_ns()
    fixture = None
    try:
        command = [sys.executable, '-I', '-B', str(Path(__file__).resolve()),
                   '--prepare-output', str(folder), '--cold-report', authority['cold_report']]
        report['prepare_owner'] = _owner(command, environment, folder / 'prepare-command')
        preparation = decode((folder / 'PREPARE.json').read_bytes())
        report['preparation'] = preparation
        require(_owner_pass(report['prepare_owner']) and preparation.get('status') == 'PASS',
                'strict cold fixture preparation did not complete')
        selected = Path(preparation['fixture'])
        require(pin(selected) == preparation['fixture_binding'], 'prepared fixture changed')
        fixture = admit_fixture(selected)
        request = {'schema': 'hepta.hia.linux-stdio-cold-request.v1',
            'fixture': str(selected), 'fixture_binding': pin(selected),
            'source_manifest': authority['source_manifest'], 'output': str(folder / 'components')}
        request_path = folder / 'REQUEST.json'
        publish(request_path, request)
        request_raw = request_path.read_bytes()
        child_env = {**environment, COLD_FIXTURE_ENV: str(selected),
                     EVIDENCE_ENV: str(folder / 'components/observations')}
        command = [sys.executable, '-I', '-B', str(Path(__file__).resolve()),
                   '--child-request', str(request_path)]
        report['component_owner'] = _owner(command, child_env, folder / 'component-command')
        child = decode((folder / 'components/RESULT.json').read_bytes())
        report['observations'] = child
        require(_owner_pass(report['component_owner']), 'owned caller deadline/exit/cleanup failed')
        admit_child_report(child, digest(request_raw))
        actual = verify_actual_observations(folder / 'components/observations', fixture)
        require(request_path.read_bytes() == request_raw and pin(selected) == request['fixture_binding']
                and admit_fixture(selected) == fixture, 'final request or fixture changed')
        guard_authority(authority)
        report.update(status='MATCHING_CURRENT_SOURCE_COLD_LINUX_STDIO_PASS',
            matching_cold=True, qualification_complete=True, actual=actual,
            loaded_ids=child['loaded_ids'], started_ids=child['started_ids'],
            stopped_ids=child['stopped_ids'], tests_run=child['tests_run'])
    except BaseException:
        report.update(status='FAIL', matching_cold=False, qualification_complete=False,
                      traceback=traceback.format_exc())
    finally:
        try:
            guard_authority(authority)
            if fixture is not None:
                require(admit_fixture(folder / 'fixture/FIXTURE.json') == fixture, 'final fixture differs')
            report.update(source_and_inputs_unchanged=True, source_after=authority['source_manifest'])
        except BaseException:
            report.update(status='FAIL', matching_cold=False, qualification_complete=False,
                source_and_inputs_unchanged=False, final_guard_error=traceback.format_exc())
        report['wall_ns'] = time.monotonic_ns() - started
        publish(folder / 'QUALIFICATION.json', report)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cold-report', type=Path)
    parser.add_argument('--evidence', type=Path)
    parser.add_argument('--prepare-output', type=Path)
    parser.add_argument('--child-request', type=Path)
    args = parser.parse_args(argv)
    if args.child_request is not None:
        require(args.cold_report is None and args.evidence is None and args.prepare_output is None,
                'child invocation cannot mix qualifier inputs')
        return _child(args.child_request)
    if args.prepare_output is not None:
        require(args.cold_report is not None and args.evidence is None, 'explicit cold preparation required')
        return _prepare(args.prepare_output, args.cold_report)
    require(args.cold_report is not None and args.evidence is not None, '--cold-report and --evidence required')
    report = qualify(args.cold_report, args.evidence)
    print(json.dumps({key: report[key] for key in ('status', 'scope', 'matching_cold', 'qualification_complete', 'whole_native')}))
    return 0 if report['status'] == 'MATCHING_CURRENT_SOURCE_COLD_LINUX_STDIO_PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
