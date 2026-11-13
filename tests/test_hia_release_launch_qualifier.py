"""Source/admission controls; these tests do not manufacture cold authority."""
from __future__ import annotations

import ast
from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tools import qualify_hia_release_launch as qualification

ROOT = Path(__file__).resolve().parents[1]
ORIGINAL_METHOD_SHA256 = {'tests.test_hia_release_launch.ReleaseLaunchFrameTests.test_argument_result_and_refusals_match_complete_vm_and_native_frames': '351f8a28ee5cf722f0f2001f9c825479aaabe1fe22f7bf7e188f36c8a78fe666',
 'tests.test_hia_release_launch.ReleaseLaunchFrameTests.test_exact_entry_and_elf_refusal_match_complete_vm_and_native_frames': '3e59ca7a9a6247bb408307fcb8eadb97f69d4a456daec21e8615145040d8b614',
 'tests.test_hia_release_launch.ReleaseLaunchFrameTests.test_seal_digest_terminal_and_replay_match_complete_vm_and_native_frames': 'd85b7e1505c90bc923f45b0fc2b23d053852c7044e2ccc42852a64547567c2bc',
 'tests.test_hia_release_launch.ReleaseLaunchKernelTests.test_actual_trace_seals_readback_single_exec_and_descriptor_cleanup': '9a8fe5b4b143ab11818cc0f57263b5bf3b8b6339de2f8713af4acb07265b0aa1',
 'tests.test_hia_release_launch.ReleaseLaunchKernelTests.test_business_stdin_stdout_and_same_process_native_pid': '5d6d63209e41e5e2e943e3b5e91ca7a5d368a6841e739c5017698d4b839c08e4',
 'tests.test_hia_release_launch.ReleaseLaunchKernelTests.test_changed_installed_permissions_bytes_and_symlink_refuse': '9e02ead103cabe650b0ad8c88e944f18fc938ac1fd1576e080406c83c1a4072f',
 'tests.test_hia_release_launch.ReleaseLaunchKernelTests.test_exact_native_exit_and_original_verify_remains_nonexecuting': '723ab7eef4bdae686554faf3faf51795054a03fc018457eebb781e44fce80d9e',
 'tests.test_hia_release_launch.ReleaseLaunchKernelTests.test_explicit_native_text_and_dynamic_elf_profile_refuse_only_execution': '9863702447b25daec513ce9a507015f689175482f0fa04ffecdc7595fe09777a',
 'tests.test_hia_release_launch.ReleaseLaunchKernelTests.test_hardlinked_entry_and_replaced_selection_during_actual_read_refuse': 'ebd5ecea947abcbd4f2ed1846080faf2f92484493b85a24b5554938f3045318c',
 'tests.test_hia_release_launch.ReleaseLaunchKernelTests.test_inherited_sigpipe_is_preserved_across_in_place_exec': 'b0df4ac8d555c0dbf27f8a7f41dcad27a8ebde656fee50688354a910b5be54b9',
 'tests.test_hia_release_launch.ReleaseLaunchKernelTests.test_missing_package_descriptor_and_wrong_arity_never_execute': '63ba54295b547c10b9efb9cfcc4cc2d03576667b8d39a1c697bfc9232db54137',
 'tests.test_hia_release_launch.ReleaseLaunchKernelTests.test_native_signal_termination_is_not_relabelled_a_launcher_success': 'fa33b1d6d431d36692d030d6b67d8ad0d1fffc68a26a9f5e204aa1cb37f279e5',
 'tests.test_hia_release_launch.ReleaseLaunchKernelTests.test_nonexecuting_mode_and_noncanonical_elf_are_not_old_verify_refusals': 'a534ea87567e35fe0510eed19388b6aae3873a1c4e83634a91ac86508b953cef',
 'tests.test_hia_release_launch.ReleaseLaunchKernelTests.test_signal_cancellation_keeps_process_group_and_releases_selection_lock': 'fe1ff82ee2b6c3db4adb65403c2d722c364ca32512df32ab4a11ebb99a61e634',
 'tests.test_hia_release_launch.ReleaseLaunchKernelTests.test_stale_sequence_release_and_separate_execution_digest_refuse': '8ddc96a7a97a89610c151510577a454c2d8d2fe10b2e920bd4c1aca1b438f07c',
 'tests.test_hia_release_launch.ReleaseLaunchKernelTests.test_target_observes_all_seals_no_private_descriptors_and_empty_environment': '4718219936e0682170f954c68076b28bc49700758f750b57af85884bd794d5c3',
 'tests.test_hia_release_launch.ReleaseLaunchSourceTests.test_builder_rejects_unqualified_cold_before_output': '5115becf99db7a6b2968c7fc26db0a2c9732dad1734359f6e01cc213a1d3d5a8',
 'tests.test_hia_release_launch.ReleaseLaunchSourceTests.test_generated_hia_and_verifier_transport_preimages_are_exact': '088b66dadbb3c0cc87693d63d0737867b7d539c0843279ae359b716745d63394',
 'tests.test_hia_release_launch.ReleaseLaunchSourceTests.test_independent_vm_actual_seal_metadata_digest_and_one_terminal': '5519efa877c910e5cecdb1f4cc5c38e187785df7fb83c0fdb2d70445c01d258e',
 'tests.test_hia_release_launch.ReleaseLaunchSourceTests.test_independent_vm_arguments_complete_buffers_and_bounds': '606a24149662fe2d5c641838acbf5b562c39fdfea160d6971d9f3d1ea7fe24f2',
 'tests.test_hia_release_launch.ReleaseLaunchSourceTests.test_independent_vm_entry_and_exact_canonical_elf': '2216caa8df12865ea8d987318f0e7c99f79322b1785006b87dca62b60502a71e',
 'tests.test_hia_release_launch.ReleaseLaunchSyscallFaultTests.test_actual_eintr_preserves_capture_memfd_write_and_seal_operations': '31a2cd02a4a748a02b14f272f7f523ac6fa91191adaa3ae822cb5548e1be5ae4',
 'tests.test_hia_release_launch.ReleaseLaunchSyscallFaultTests.test_exec_refusal_returns_once_without_retry_or_path_execution': '0f340cc1deeacfc4b413732400d06f0481cb6cac7569517a9b50d76508d3d0f0',
 'tests.test_hia_release_launch.ReleaseLaunchSyscallFaultTests.test_false_short_write_and_incomplete_seal_readback_cannot_execute': '77a07af70dfd98f6118577f81162cae34b0dc907099826b950c1a1c328a4b503',
 'tests.test_hia_release_launch.ReleaseLaunchSyscallFaultTests.test_memfd_seal_and_descriptor_cleanup_feature_refusals_have_no_fallback': '1edd61ce69d759ba808feef3c6ecbf86ecaa78f1f28bd513cd1ddc31ba5f56f0'}
AGENT_BUSINESS_SUFFIX_SHA256 = 'fc91e23bd642b12dffde9419eded051398e65d24270c89f78726f0238949005d'


class ReleaseLaunchQualifierSourceTests(unittest.TestCase):
    def test_exact_original_26_ids_and_21_plus_5_groups_are_retained(self):
        ids = []
        for group, expected in zip(qualification.GROUPS, (21, 5)):
            suite, loaded = qualification.load_suite(group)
            self.assertEqual(len(loaded), expected)
            self.assertEqual([test.id() for test in qualification.flatten(suite)], loaded)
            ids.extend(loaded)
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(set(ids), set(qualification.EXPECTED_IDS))
        self.assertEqual(tuple(qualification.GROUPS), ('local-observations', 'required-ptrace'))
        self.assertEqual((qualification.GROUP_SECONDS, qualification.CLEANUP_SECONDS,
                          qualification.COMPILE_SECONDS, qualification.CAPACITY), (1800, 5, 20, 1048576))

    def test_all_original_business_assertions_and_limits_are_byte_preserved(self):
        raw = (ROOT / qualification.TEST_SOURCE).read_bytes()
        lines = raw.splitlines(keepends=True)
        observed = {}
        for cls in ast.parse(raw).body:
            if not isinstance(cls, ast.ClassDef):
                continue
            for method in cls.body:
                if not isinstance(method, ast.FunctionDef) or not method.name.startswith('test_'):
                    continue
                name = qualification.MODULE + '.' + cls.name + '.' + method.name
                body = b''.join(lines[method.lineno - 1:method.end_lineno])
                if cls.name == 'ReleaseLaunchInstalledAgentTests':
                    suffix = body[body.index(b'        image=Path(data[\'path\']).read_bytes();'):]
                    self.assertEqual(sha256(suffix).hexdigest(), AGENT_BUSINESS_SUFFIX_SHA256)
                else:
                    observed[name] = sha256(body).hexdigest()
        self.assertEqual(observed, ORIGINAL_METHOD_SHA256)
        self.assertEqual(sha256(raw).hexdigest(), qualification.TEST_SOURCE_SHA256)

    def test_qualifier_rejects_real_absent_and_unqualified_cold_before_output(self):
        with tempfile.TemporaryDirectory(prefix='hia-launch-cold-refusal-') as temporary:
            folder = Path(temporary)
            cold = folder / 'cold.json'
            with self.assertRaises(FileNotFoundError):
                qualification.qualify(folder / 'absent-output', cold)
            self.assertFalse((folder / 'absent-output').exists())
            for index, value in enumerate(({}, {'status': 'DEVELOPMENT_IMAGES_BUILT', 'matching_cold': True},
                                           {'schema': 'hepta.hia.selfhost-cold-replay.v1', 'status': 'FAIL'})):
                cold.write_text(json.dumps(value))
                with self.subTest(value=value), self.assertRaises(ValueError):
                    qualification.qualify(folder / str(index), cold)
                self.assertFalse((folder / str(index)).exists())

    def test_all_four_actual_production_builders_refuse_unqualified_input_before_output(self):
        from tools import build_hia_release_install, build_hia_release_selection, build_hia_release_launch, build_hia_agent_stdio
        with tempfile.TemporaryDirectory(prefix='hia-launch-build-refusal-') as temporary:
            folder = Path(temporary)
            compiler, cold = folder / 'compiler', folder / 'cold.json'
            compiler.write_bytes(b'unqualified')
            cold.write_text('{}')
            for index, builder in enumerate((build_hia_release_install, build_hia_release_selection,
                                             build_hia_release_launch, build_hia_agent_stdio)):
                with self.subTest(builder=builder.__name__), self.assertRaises(ValueError):
                    builder.build(folder / str(index), compiler, cold)
                self.assertFalse((folder / str(index)).exists())

    def test_cold_deadline_cleanup_boolean_and_terminal_refusals_remain_strict(self):
        # This object tests only the negative shape gate, never admit_cold or a builder.
        seed = {'schema': 'hepta.hia.selfhost-cold-replay.v1', 'status': 'COLD_SELFHOST_REPLAY_PASS',
                'returncode': 0, 'qualification_wall_limit_seconds': 180, 'cleanup_wall_limit_seconds': 3,
                'nested_report': '/not-opened-by-this-shape-test', 'nested_report_sha256': '0' * 64,
                'process_owner': {'status': 'OWNED_PROCESS_COMPLETED', 'returncode': 0, 'timed_out': False,
                                  'exit_observed_before_deadline': True, 'cleanup': {'complete': True}}}
        changes = ((('status',), 'FAIL'), (('returncode',), False),
                   (('qualification_wall_limit_seconds',), 181), (('cleanup_wall_limit_seconds',), 4),
                   (('process_owner', 'timed_out'), True),
                   (('process_owner', 'exit_observed_before_deadline'), False),
                   (('process_owner', 'cleanup', 'complete'), False),
                   (('process_owner', 'returncode'), False))
        for path, value in changes:
            modified = deepcopy(seed)
            target = modified
            for name in path[:-1]:
                target = target[name]
            target[path[-1]] = value
            with self.subTest(path=path), self.assertRaises(ValueError):
                qualification._outer_shape(modified)

    def test_missing_required_source_and_changed_bytes_cannot_be_added_by_fixture_metadata(self):
        # Pure source-binding mechanism control; no cold report is constructed.
        with tempfile.TemporaryDirectory(prefix='hia-launch-source-binding-') as temporary:
            folder = Path(temporary)
            (folder / 'required.py').write_bytes(b'original\n')
            expected = {'required.py': sha256(b'original\n').hexdigest()}
            with self.assertRaisesRegex(ValueError, 'missing from cold source contract'):
                qualification._admit_required_sources({}, folder, ('required.py',))
            (folder / 'required.py').write_bytes(b'changed\n')
            with self.assertRaisesRegex(ValueError, 'source identity differs'):
                qualification._admit_required_sources(expected, folder, ('required.py',))
        from tools import build_hia_release_install, build_hia_release_selection, build_hia_release_launch
        names = qualification.required_source_names()
        self.assertEqual(names, tuple(sorted(set(names))))
        for builder in (build_hia_release_install, build_hia_release_selection, build_hia_release_launch):
            self.assertTrue(set(builder.SOURCES).issubset(names))
        for name in names:
            self.assertTrue((ROOT / name).is_file(), name)

    def test_explicit_cold_selection_never_falls_back_or_mixes_development_records(self):
        self.assertIsNone(qualification.selected_cold_fixture({}))
        self.assertEqual(qualification.selected_cold_fixture({qualification.COLD_FIXTURE_ENV: '/cold'}), Path('/cold'))
        with self.assertRaises(ValueError):
            qualification.selected_cold_fixture({qualification.COLD_FIXTURE_ENV: ''})
        for old in qualification.DEVELOPMENT_ENV:
            with self.subTest(old=old), self.assertRaises(ValueError):
                qualification.selected_cold_fixture({qualification.COLD_FIXTURE_ENV: '/cold', old: ''})
        with tempfile.TemporaryDirectory(prefix='hia-launch-not-cold-') as temporary:
            path = Path(temporary) / 'BUILD.json'
            for flag in (False, True):
                path.write_text(json.dumps({'schema': 'hia.release-launch.development-build.v1',
                                            'status': 'DEVELOPMENT_IMAGES_BUILT', 'matching_cold': flag}))
                with self.subTest(flag=flag), self.assertRaisesRegex(ValueError, 'development records are not cold authority'):
                    qualification.admit_fixture(path)

    def test_input_pins_detect_same_path_content_mode_and_duplicate_binding_changes(self):
        with tempfile.TemporaryDirectory(prefix='hia-launch-input-binding-') as temporary:
            path = Path(temporary) / 'input'
            path.write_bytes(b'held')
            path.chmod(0o600)
            held = qualification._pin(path)
            with self.assertRaisesRegex(ValueError, 'duplicate'):
                qualification._check_bindings([held, held])
            path.write_bytes(b'other')
            with self.assertRaisesRegex(ValueError, 'changed'):
                qualification._check_bindings([held])
            path.write_bytes(b'held')
            path.chmod(0o400)
            with self.assertRaisesRegex(ValueError, 'changed'):
                qualification._check_bindings([held])

    def test_partial_reordered_skipped_expected_failed_or_unbound_child_never_qualifies(self):
        group = 'required-ptrace'
        ids = qualification.group_ids(group)
        # Parser-only observation fixture. It is never written as a qualification report.
        seed = {'schema': 'hepta.hia.release-launch-observations.v1', 'scope': 'OBSERVATIONS_ONLY_NO_COLD_AUTHORITY',
                'status': 'PASS', 'request_sha256': 'fixture-request', 'group': group,
                'loaded_ids': ids, 'executed_ids': ids, 'tests_run': len(ids),
                'source_and_inputs_unchanged': True, 'anomalies': {name: [] for name in qualification.ANOMALIES}}
        modifications = [('status', 'FAIL'), ('request_sha256', 'other'), ('tests_run', True),
                         ('executed_ids', ids[:-1]), ('loaded_ids', list(reversed(ids))),
                         ('source_and_inputs_unchanged', False), ('scope', 'MATCHING_SOURCE_COLD_RELEASE_LAUNCH')]
        for field, value in modifications:
            row = deepcopy(seed)
            row[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                qualification.admit_child_observations(row, 'fixture-request', group)
        for name in qualification.ANOMALIES:
            row = deepcopy(seed)
            row['anomalies'][name] = ['retained failure']
            with self.subTest(anomaly=name), self.assertRaises(ValueError):
                qualification.admit_child_observations(row, 'fixture-request', group)

    def test_actual_request_input_identity_is_checked_before_native_receipt_admission(self):
        with tempfile.TemporaryDirectory(prefix='hia-launch-receipt-refusal-') as temporary:
            folder = Path(temporary)
            image = folder / 'image'
            image.write_bytes(b'not-executed')
            (folder / 'probe.input.bin').write_bytes(b'changed')
            (folder / 'probe.output.bin').write_bytes(b'')
            (folder / 'probe.receipt.json').write_text('{}')
            (folder / 'probe.request.json').write_text('{}')
            with self.assertRaisesRegex(ValueError, 'actual native request differs'):
                qualification._observation(folder, 'probe', image, b'captured')

    def test_unrequested_observer_options_and_noninteger_limits_are_rejected(self):
        from tools.qualify_hia_selfhost import CHILD
        # Negative-only metadata controls with opaque bytes; no byte is executed,
        # no cold record is made and no positive qualification is asserted.
        with tempfile.TemporaryDirectory(prefix='hia-launch-receipt-shape-') as temporary:
            folder = Path(temporary)
            image, source, output = folder / 'image', folder / 'probe.input.bin', folder / 'probe.output.bin'
            image.write_bytes(b'never-executed')
            source.write_bytes(b'captured')
            output.write_bytes(bytes(qualification.CAPACITY))
            image_sha, source_sha = sha256(image.read_bytes()).hexdigest(), sha256(source.read_bytes()).hexdigest()
            request = {'format': 'flat-x86-64', 'image': str(image), 'image_sha256': image_sha,
                       'source': str(source), 'source_sha256': source_sha, 'output': str(output),
                       'capacity': qualification.CAPACITY, 'workspace_size': qualification.CAPACITY, 'workspace_fill': 0}
            receipt = {'case': 'probe', 'status': 'returned', 'abi_status': 0, 'core_u32': 1, 'result_u64': 1,
                       'format': 'flat-x86-64', 'return_encoding': 'zero-extended-u32', 'source_unchanged': True,
                       'forbidden_compiler_modules_loaded': [], 'image_sha256': image_sha, 'artifact_sha256': image_sha,
                       'source_sha256': source_sha, 'input_sha256': source_sha, 'input_bytes': len(source.read_bytes()),
                       'output_sha256': sha256(output.read_bytes()).hexdigest(),
                       'runner_sha256': sha256(CHILD.read_bytes()).hexdigest(),
                       'limits': {'address_bytes': 268435456, 'core_dumpable': False, 'cpu_seconds': 10,
                                  'output_capacity': qualification.CAPACITY, 'stack_bytes': 8388608,
                                  'workspace_bytes': qualification.CAPACITY}}
            for field, value in (('workspace_fill', 1), ('workspace_fill', False),
                                 ('observe_trap_writes', True), ('output_initial_hex', '')):
                changed = {**request, field: value}
                (folder / 'probe.request.json').write_text(json.dumps(changed))
                (folder / 'probe.receipt.json').write_text(json.dumps(receipt))
                with self.subTest(request_field=field, value=value), self.assertRaisesRegex(ValueError, 'actual native request differs'):
                    qualification._observation(folder, 'probe', image, source.read_bytes())
            (folder / 'probe.request.json').write_text(json.dumps(request))
            for field in ('address_bytes', 'cpu_seconds', 'stack_bytes', 'core_dumpable'):
                changed = deepcopy(receipt)
                changed['limits'][field] = 0 if field == 'core_dumpable' else float(changed['limits'][field])
                (folder / 'probe.receipt.json').write_text(json.dumps(changed))
                with self.subTest(limit=field), self.assertRaisesRegex(ValueError, 'original native child limits differ'):
                    qualification._observation(folder, 'probe', image, source.read_bytes())

    def test_cli_has_no_development_option_and_refusal_does_not_prepare_images(self):
        with patch.object(qualification, 'prepare_fixture', side_effect=AssertionError('must not build')):
            with self.assertRaises(ValueError):
                qualification.main([])
            with self.assertRaises(SystemExit) as failure:
                qualification.main(['--development-compiler', '/not-a-cold-input'])
            self.assertEqual(failure.exception.code, 2)

    def test_agent_frontend_consumer_uses_actual_catalog_protocol(self):
        # Compare the real producer route with its consumer, without executing
        # a compiler or constructing any positive cold-authority fixture.
        agent = ast.parse((ROOT / 'tools/build_hia_agent_stdio.py').read_bytes())
        routes = [node for node in ast.walk(agent) if isinstance(node, ast.Call)
                  and isinstance(node.func, ast.Name) and node.func.id == 'build_frontend']
        self.assertEqual(len(routes), 1)
        candidates = [ast.literal_eval(item.value) for item in routes[0].keywords
                      if item.arg == 'candidate']
        self.assertEqual(len(candidates), 1)
        candidate = candidates[0]
        producer = ast.parse((ROOT / 'tools/build_hia_json_preflight.py').read_bytes())
        mappings = [node for node in ast.walk(producer) if isinstance(node, ast.Dict)
                    and any(isinstance(key, ast.Constant) and key.value == candidate
                            for key in node.keys)]
        self.assertEqual(len(mappings), 1)
        source_name, protocol = ast.literal_eval(mappings[0])[candidate]
        consumer = next(node for node in ast.parse(
            (ROOT / 'tools/qualify_hia_release_launch.py').read_bytes()).body
            if isinstance(node, ast.FunctionDef) and node.name == '_agent_build')
        observations = [node for node in ast.walk(consumer) if isinstance(node, ast.Call)
                        and isinstance(node.func, ast.Name) and node.func.id == '_compile_observation'
                        and len(node.args) == 4 and isinstance(node.args[3], ast.Subscript)
                        and isinstance(node.args[3].slice, ast.Constant)
                        and node.args[3].slice.value == source_name]
        self.assertEqual(len(observations), 1)
        manifests = [value.value for node in ast.walk(consumer) if isinstance(node, ast.Dict)
                     for key, value in zip(node.keys, node.values)
                     if isinstance(key, ast.Constant) and key.value == 'schema'
                     and isinstance(value, ast.Constant) and type(value.value) is str]
        self.assertEqual(len(manifests), 1)
        build_schemas = [node.comparators[0].value for node in ast.walk(consumer)
                         if isinstance(node, ast.Compare) and len(node.ops) == 1
                         and isinstance(node.ops[0], ast.Eq) and isinstance(node.left, ast.Call)
                         and isinstance(node.left.func, ast.Attribute)
                         and isinstance(node.left.func.value, ast.Name)
                         and node.left.func.value.id == 'front_build' and node.left.func.attr == 'get'
                         and len(node.left.args) == 1 and isinstance(node.left.args[0], ast.Constant)
                         and node.left.args[0].value == 'schema'
                         and isinstance(node.comparators[0], ast.Constant)]
        self.assertEqual(len(build_schemas), 1)
        observed = {'receipt_label': ast.literal_eval(observations[0].args[1]),
                    'manifest_schema': manifests[0], 'build_schema': build_schemas[0]}
        expected = {'receipt_label': protocol,
                    'manifest_schema': 'hepta.hia.' + protocol + '-native.v1',
                    'build_schema': 'hepta.hia.' + protocol + '-build.v1'}
        for field in expected:
            with self.subTest(field=field, candidate=candidate, protocol=protocol):
                self.assertEqual(observed[field], expected[field])

    def test_cleanup_timeout_is_retained_without_a_second_five_second_allowance(self):
        # Supervisor mechanism only; no native test or actual process is started.
        class Child:
            pid = 12345
            def __init__(self):
                self.waits = []
            def wait(self, timeout):
                self.waits.append(timeout)
                raise subprocess.TimeoutExpired(['unstarted-test-child'], timeout)
            def poll(self):
                return None
        child = Child()
        with tempfile.TemporaryDirectory(prefix='hia-launch-owner-timeout-') as temporary:
            with patch.object(qualification.subprocess, 'Popen', return_value=child), \
                    patch.object(qualification.os, 'killpg') as kill:
                report = qualification.run_stage(['unstarted-test-child'], Path(temporary) / 'stage', {})
            self.assertEqual(child.waits, [1800, 5])
            self.assertEqual(kill.call_count, 1)
            self.assertEqual(report['status'], 'FAIL')
            self.assertIs(report['timed_out'], True)
            self.assertIs(report['cleanup_attempted'], True)
            self.assertIs(report['direct_child_reaped'], False)


if __name__ == '__main__':
    unittest.main()
