"""Explicit D0--D3 native-delivery causality; original gates remain separate.

Deliberately unknown objects live in disposable child processes until actual
process exit. No control clears a custody registry or converts DEV into cold.
"""
from __future__ import annotations

import ast
from hashlib import sha256
import importlib
import inspect
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
COLD = 'HEPTA_HIA_NATIVE_DELIVERY_COLD_REPORT'
DEVELOPMENT = 'HEPTA_HIA_NATIVE_DELIVERY_DEVELOPMENT_COMPILER'
EVIDENCE = 'HEPTA_HIA_NATIVE_DELIVERY_EVIDENCE'
ORIGINAL = ROOT / 'tests/fixtures/native_delivery_original_9c46166.json'
ORIGINAL_SHA256 = 'a1f82e1c955ece21319cc49a0e3834658a2eeb0be7636d6f13690e1d6b83dea7'
OWNERS = ('service_context', 'store_lifecycle', 'cost_ledger', 'evaluation',
          'native_build_admission', 'emission', 'execution_budget', 'candidate_budget', 'agent_journal')


def encoded(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False,
                      separators=(',', ':')).encode()


def clean_environment():
    return {key: value for key, value in os.environ.items()
            if key not in ('PYTHONPATH', 'PYTHONHOME') and not key.startswith('HEPTA_HIA_')}


def source_pins():
    from tools.hia_selfhost_contract import file_digests
    return {**file_digests(), **{name: sha256((ROOT / name).read_bytes()).hexdigest()
        for name in ('tests/test_hia_native_delivery.py', 'tests/hia_native_delivery_cases.py',
                     'tests/hia_native_delivery_sql.py',
                     'tests/fixtures/native_delivery_original_9c46166.json',
                     'tools/qualify_hia_native_delivery.py')}}


def admit_originals():
    raw = ORIGINAL.read_bytes()
    if sha256(raw).hexdigest() != ORIGINAL_SHA256:
        raise AssertionError('independent original inventory changed')
    value = json.loads(raw)
    if value['base_commit'] != '9c461664adc27e576d33fba6618b3764672eea9d':
        raise AssertionError('native-delivery original source identity differs')
    from tests.hia_native_transport_worker_successor import admit_terminal_sources
    terminal = admit_terminal_sources(value, original_kind='native')
    adjustments = []
    for name, record in value['unchanged_files'].items():
        raw = (ROOT / name).read_bytes()
        if name in terminal['source_adjustments']:
            reviewed = terminal['source_adjustments'][name]
            if (len(raw) != reviewed['current_bytes']
                    or sha256(raw).hexdigest() != reviewed['current_sha256']):
                raise AssertionError('reviewed transport terminal control changed: ' + name)
            continue
        if len(raw) != record['bytes'] or sha256(raw).hexdigest() != record['sha256']:
            from hepta.hia_native_helpers import HELPERS
            old_line = b'        self.assertEqual(len(HELPERS), 38)\n'
            new_line = ('        self.assertEqual(len(HELPERS), ' + str(len(HELPERS)) + ')\n').encode()
            restored = raw.replace(new_line, old_line, 1)
            if (name != 'tests/test_hia_worker_native_helpers.py' or len(HELPERS) < 38
                    or raw.count(new_line) != 1 or len(restored) != record['bytes']
                    or sha256(restored).hexdigest() != record['sha256']):
                raise AssertionError('original source or caller changed: ' + name)
            adjustments.append({'path': name, 'original_sha256': record['sha256'],
                'current_sha256': sha256(raw).hexdigest(), 'original_helper_count': 38,
                'current_helper_count': len(HELPERS),
                'sole_permitted_change': 'one exact registry-count assertion decimal literal',
                'all_other_source_bytes_unchanged': True})
    value['registry_count_adjustments'] = adjustments
    value['transport_terminal_successor'] = terminal
    return value


class NativeDeliverySourceTests(unittest.TestCase):
    def test_original_component_modules_fixtures_and_callers_remain_exact(self):
        value = admit_originals()
        self.assertEqual(len(value['component_modules']), 11)
        self.assertEqual(len(value['ordinary_ordered_ids']), 112)
        self.assertFalse(value['runtime_execution_before_freeze'])

    def test_sql_calls_keep_original_method_binding_and_argument_order(self):
        value = admit_originals()
        from tests.hia_native_delivery_sql import check_store_delegation, delivery_sql_calls
        check_store_delegation(self)
        for name, expected in value['sql_call_asts'].items():
            tree = ast.parse((ROOT / name).read_bytes())
            calls = []
            for node in delivery_sql_calls(tree, name, ROOT):
                if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                        and node.func.attr in ('execute', '_execute')):
                    for index, arg in enumerate(node.args):
                        if (isinstance(arg, ast.Call) and isinstance(arg.func, ast.Name)
                                and arg.func.id == '_delivery_guard'):
                            self.assertEqual(len(arg.args), 1)
                            self.assertFalse(arg.keywords)
                            node.args[index] = arg.args[0]
                    options = {'show_empty': True} if 'show_empty' in inspect.signature(ast.dump).parameters else {}
                    calls.append((node.lineno, ast.dump(node, include_attributes=False, **options)))
            self.assertEqual([raw for _, raw in sorted(calls)], expected, name)

    def test_shared_tracking_is_part_of_each_component_build_input(self):
        for owner in OWNERS[:6]:
            module = importlib.import_module('tools.build_hia_' + owner)
            self.assertIn('hepta/hia_native_delivery.py', module.INPUTS)
        for owner in ('emission', 'native_build_admission'):
            tree = ast.parse((ROOT / ('hepta/hia_' + owner + '_native.py')).read_bytes())
            self.assertFalse(any(isinstance(node, ast.Name) and node.id == 'ContextVar'
                                 for node in ast.walk(tree)))


class NativeDeliveryNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cold, development, evidence = (os.environ.get(name) for name in (COLD, DEVELOPMENT, EVIDENCE))
        if (cold is None) == (development is None) or cold == '' or development == '' or evidence == '':
            raise ValueError('choose one nonempty matching cold report or explicit development compiler')
        admit_originals()
        cls.temporary = None
        if evidence is None:
            cls.temporary = tempfile.TemporaryDirectory(prefix='hia-native-delivery-')
            cls.root = Path(cls.temporary.name)
        else:
            cls.root = Path(evidence).absolute()
            cls.root.mkdir(mode=0o700, parents=True, exist_ok=False)
        if cold is None:
            compiler = Path(development)
        else:
            from tools.hia_cold_compiler import compiler_from_cold_report
            compiler = compiler_from_cold_report(Path(cold))
        cls.compiler, cls.compiler_raw, cls.cold = compiler, compiler.read_bytes(), cold
        cls.before, cls.manifests = source_pins(), {}
        for owner in OWNERS:
            directory = cls.root / ('build-' + owner)
            if owner in OWNERS[:6]:
                builder = importlib.import_module('tools.build_hia_' + owner).build
                manifest = builder(directory, compiler, cold, development=cold is None)
            elif cold is not None:
                if owner == 'agent_journal':
                    from tools.build_hia_json_preflight import build
                    manifest = build(directory, compiler, Path(cold), candidate='agent-journal')
                else:
                    builder = importlib.import_module('tools.build_hia_' + owner).build
                    manifest = builder(directory, compiler, Path(cold))
            else:
                # Strict release builders remain strict. This is the same
                # explicit DEV construction used by the original composition.
                from tools.qualify_hia_selfhost import compile_stage
                from tools.build_hia_source_build import _check_pack_output
                module = importlib.import_module('hepta.hia_' + owner + '_native')
                directory.mkdir(mode=0o700)
                source = module.SOURCE.read_bytes()
                label = 'agent-journal' if owner == 'agent_journal' else owner
                image, receipt = compile_stage(directory, label, compiler, source)
                raw = image.read_bytes()
                packed = _check_pack_output(receipt, (directory / (label + '.output.bin')).read_bytes(),
                                            artifact=cls.compiler_raw, source=source)
                if packed != raw or module.SOURCE.read_bytes() != source:
                    raise AssertionError('development output or source differs')
                value = {'schema': module.SCHEMA, 'source_sha256': sha256(source).hexdigest(),
                         'image_path': image.name, 'image_sha256': sha256(raw).hexdigest(),
                         'compiler_sha256': sha256(cls.compiler_raw).hexdigest()}
                manifest = directory / 'manifest.json'
                manifest.write_bytes(encoded(value) + b'\n')
                (directory / 'development-build.json').write_bytes(encoded({
                    'scope': 'DEVELOPMENT_COMPONENT', 'manifest': value,
                    'native_compile_receipt': receipt, 'matching_current_source_cold_qualified': False}) + b'\n')
            cls.manifests[owner] = str(manifest.resolve())
        cls.built = {str(path): sha256(path.read_bytes()).hexdigest()
                     for owner in OWNERS for path in sorted((cls.root / ('build-' + owner)).rglob('*'))
                     if path.is_file()}
        (cls.root / 'manifests.json').write_bytes(encoded(cls.manifests) + b'\n')

    @classmethod
    def tearDownClass(cls):
        after = source_pins()
        stable = (cls.before == after and cls.compiler.read_bytes() == cls.compiler_raw
                  and all(sha256(Path(path).read_bytes()).hexdigest() == digest
                          for path, digest in cls.built.items()))
        record = {'schema': 'hepta.hia.native-delivery-custody.v1',
                  'scope': 'DEVELOPMENT_COMPONENT' if cls.cold is None else 'MATCHING_SOURCE_COLD_COMPONENT',
                  'matching_cold_report': cls.cold, 'compiler_sha256': sha256(cls.compiler_raw).hexdigest(),
                  'manifests': cls.manifests, 'build_files': cls.built,
                  'source_before': cls.before, 'source_after': after,
                  'source_compiler_and_build_unchanged': stable,
                  'implemented_scope': ['D0', 'D1', 'D2', 'D3'],
                  'store_artifact_profile_D4_integrated': False, 'remaining_D5_integrated': False,
                  'test_result_owned_by_outer_runner': True,
                  'whole_native_delivery_qualified': False}
        (cls.root / 'component-custody.json').write_bytes(encoded(record) + b'\n')
        if cls.temporary is not None:
            cls.temporary.cleanup()
        if not stable:
            raise AssertionError('native-delivery source, compiler or build changed')

    def child(self, kind, *, timeout=120):
        directory = self.root / self._testMethodName
        directory.mkdir()
        script = ('import sys;sys.path.insert(0,sys.argv.pop(1));'
                  'from tests.hia_native_delivery_cases import run_child;run_child(*sys.argv[1:])')
        result = subprocess.run([sys.executable, '-I', '-B', '-c', script, str(ROOT), kind,
                                 str(directory), json.dumps(self.manifests)],
                                cwd=directory, env=clean_environment(), capture_output=True, timeout=timeout)
        (directory / 'stdout.log').write_bytes(result.stdout)
        (directory / 'stderr.log').write_bytes(result.stderr)
        self.assertEqual(result.returncode, 0, result.stdout.decode(errors='replace') + result.stderr.decode(errors='replace'))
        record = json.loads((directory / 'observations.json').read_bytes())
        self.assertEqual(record['status'], 'PASS')
        return record

    def test_six_real_frames_block_swallowed_and_replaced_cross_owner_loss(self):
        self.child('frames')

    def test_active_except_cleanup_cannot_suppress_cross_owner_loss(self):
        self.child('cleanup')

    def test_safe_preentry_confirmed_refusal_and_foreign_unknown_do_not_publish(self):
        self.child('safe')

    def test_both_journals_keep_running_intent_after_swallowed_and_replaced_loss(self):
        self.child('requests')

    def test_final_serialization_and_sql_before_ack_cannot_hide_loss(self):
        self.child('journal_gaps')

    def test_budget_invocations_follow_actual_parent_and_keep_original_sql_refusals(self):
        self.child('budgets')

    def test_stale_thread_and_fork_contexts_do_not_adopt_inherited_custody(self):
        self.child('ancestry')

    def test_actual_installed_worker_pinned_bundle_blocks_cross_owner_loss(self):
        self.child('installed', timeout=180)


if __name__ == '__main__':
    unittest.main()
