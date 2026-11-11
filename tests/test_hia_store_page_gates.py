"""Adversarial CI receipt controls; all constructed receipts are synthetic."""
from __future__ import annotations

import ast
from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from tools import hia_store_page_gates as gates
from tests.test_hia_integrated_workflow import script, step

ROOT = Path(__file__).resolve().parents[1]


def save(path, value):
    path.write_text(json.dumps(value, sort_keys=True) + '\n')


def synthetic_build(root, owner):
    """Exercise real file/hash admission without a compiler or native execution."""
    config = gates.OWNERS[owner]
    names = set(config['caller_sources']) | {config['source'], 'examples/hia_bootstrap/json_wire.hiaasm'}
    sources = {name: sha256(name.encode()).hexdigest() for name in names}
    context = {'source_manifest': sources, 'compiler_sha256': 'c' * 64, 'cold_sha256': 'd' * 64,
               'identities': [{'fixture': 'SYNTHETIC_NOT_PRODUCT_EXECUTION'}]}
    root.mkdir()
    def image(folder, name, source, schema):
        folder.mkdir(exist_ok=True)
        path = folder / (name + '.bin'); path.write_bytes(('synthetic image ' + name).encode())
        manifest = {'schema': schema, 'source_sha256': sources[source], 'compiler_sha256': 'c' * 64,
                    'image_path': path.name, 'image_sha256': sha256(path.read_bytes()).hexdigest()}
        save(folder / 'manifest.json', manifest)
        receipt = {'status': 'returned', 'abi_status': 0, 'source_sha256': sources[source],
                   'input_sha256': sources[source], 'produced_sha256': manifest['image_sha256'],
                   'image_sha256': 'c' * 64, 'artifact_sha256': 'c' * 64,
                   'source_unchanged': True, 'forbidden_compiler_modules_loaded': [],
                   'produced_bytes': path.stat().st_size,
                   'limits': {'address_bytes': 268435456, 'core_dumpable': False, 'cpu_seconds': 10,
                              'output_capacity': 1048576, 'stack_bytes': 8388608, 'workspace_bytes': 1048576}}
        return manifest, receipt
    common = {'schema': config['build_schema'], 'scope': 'MATCHING_SOURCE_COLD_BUILD',
              'source_manifest': sources, 'cold_report_sha256': 'd' * 64,
              'compiler_sha256': 'c' * 64, 'production_activated': False}
    if owner == 'authority':
        manifest, receipt = image(root, 'authority', config['source'], config['manifest_schema'])
        save(root / 'build.json', dict(common, manifest=manifest, native_compile_receipt=receipt))
    else:
        policy, receipt = image(root / 'policy', 'policy', config['source'], config['manifest_schema'])
        wire, wire_receipt = image(root / 'wire', 'wire', 'examples/hia_bootstrap/json_wire.hiaasm', 'hepta.hia.json-wire-native.v1')
        wire_build = dict(common, schema='hepta.hia.json-wire-build.v1', manifest=wire, native_compile_receipt=wire_receipt)
        save(root / 'wire/build.json', wire_build)
        bundle = {'schema': 'hepta.hia.artifact-page-bundle.v2', 'policy_manifest': 'policy/manifest.json',
                  'policy_manifest_sha256': sha256((root / 'policy/manifest.json').read_bytes()).hexdigest(),
                  'wire_manifest': 'wire/manifest.json',
                  'wire_manifest_sha256': sha256((root / 'wire/manifest.json').read_bytes()).hexdigest()}
        save(root / 'manifest.json', bundle)
        save(root / 'build.json', dict(common, bundle=bundle, policy_manifest=policy,
                                      policy_compile_receipt=receipt, wire_build=wire_build))
    return context


def synthetic_component(owner, context, binding):
    config = gates.OWNERS[owner]
    ids = [config['module'] + '.Synthetic.test_%02d' % i for i in range(config['component_tests'])]
    report = {'schema': 'hepta.hia.store-page-component.v1', 'owner': owner, 'status': 'PASS',
              'scope': 'MATCHING_SOURCE_COLD_COMPONENT', 'modules': [config['module']], 'loader_errors': [],
              'unittest_successful': True, 'source_before': context['source_manifest'],
              'source_after': context['source_manifest'], 'source_preserved': True, 'cold_inputs_preserved': True,
              'build_binding': binding, 'cold_inputs': context['identities'],
              'runtime_observations': {'fixture': 'synthetic validator control, no runtime claim'},
              'loaded_test_ids': ids, 'chosen_test_ids': ids, 'executed_test_ids': ids,
              'tests_loaded': len(ids), 'tests_chosen': len(ids), 'tests_run': len(ids)}
    report.update({k: [] for k in gates.ANOMALIES})
    return report, ids


def synthetic_callers(owner, context, binding):
    config = gates.OWNERS[owner]
    ids = [gates.CALLER_MODULES[i % 5] + '.Synthetic.test_%02d' % i for i in range(67)]
    source = {n: context['source_manifest'][n] for n in config['caller_sources']}
    manifest = Path(binding['files'][1]['path'])
    report = {'schema': config['caller_schema'], 'status': 'PASS', 'scope': 'MATCHING_SOURCE_COLD_SELECTED_CALLERS',
              'modules': list(gates.CALLER_MODULES), 'explicit_development_exclusions': {},
              'loaded_test_ids': ids, 'chosen_test_ids': ids, 'executed_test_ids': ids,
              'tests_loaded': 67, 'tests_chosen': 67, 'tests_run': 67,
              'retained_owner_forbidden': True, 'retained_owner_entries': [],
              'all_eleven_agent_tools_exercised': True, 'source_manifest': context['source_manifest'],
              'matching_cold_source_closure_stable': True, 'source_sha256': source, 'source_after_sha256': source,
              'evidence_dir_retained': True, 'evidence_dir': str(manifest.parent.parent), 'manifest_path': str(manifest)}
    report.update({k: [] for k in gates.ANOMALIES})
    suffix = 'store' if owner == 'authority' else 'page'
    report['agent_tools_with_native_' + suffix] = dict.fromkeys(gates.TOOLS, 1)
    report['agent_tools_without_native_' + suffix] = {}
    if owner == 'authority':
        report.update(all_six_store_modes_entered_native=True,
            actual_native_modes=dict.fromkeys(('ref', 'get', 'resolve_uri', 'profile', 'check_profile', 'put'), 1),
            independent_uri_control={'status': 'PASS', 'part_of_original_loaded_ids': False, 'failure': None,
                                     'reference': {'synthetic': True}, 'native': {'synthetic': True}},
            source_manifest_image_stable=True, manifest=binding['manifests']['authority'],
            image_sha256=binding['manifests']['authority']['image_sha256'])
    else:
        files = {v['path']: {'size': v['bytes'], 'sha256': v['sha256']} for v in binding['files']
                 if Path(v['path']).name != 'build.json'}
        report.update(ordinary_hia_read_entered_native=True, actual_native_entries={'read': 1},
            actual_native_step_returns={'2': 1}, source_manifest_images_stable=True,
            policy_image_sha256=binding['manifests']['policy']['image_sha256'],
            wire_image_sha256=binding['manifests']['wire']['image_sha256'],
            bundle_manifest=binding['bundle'], bundle_files_before=files, bundle_files_after=files)
    return report, ids


class StorePageCIGateTests(unittest.TestCase):
    def test_successor_retains_all_17_old_gates_and_requires_all_four_new_gates(self):
        tree = ast.parse((ROOT / 'experiments/hia_v67_qualification_runner_20261111/run_hia_qualification_v8.py').read_bytes())
        def keys(name):
            node = next(v for v in tree.body if isinstance(v, ast.Assign)
                        and any(isinstance(t, ast.Name) and t.id == name for t in v.targets))
            return [ast.literal_eval(k) for k in node.value.keys if k is not None]
        self.assertEqual(tuple(keys('mandatory_gates') + keys('mandatory_v8_gates')), gates.LEGACY_V8_GATES)
        self.assertEqual(len(gates.LEGACY_V8_GATES), 17); self.assertEqual(len(gates.SUCCESSOR_GATES), 21)
        ledger = gates.json_file(ROOT / 'docs/HIA_STORE_PAGE_QUALIFICATION_GATES.json')
        self.assertEqual(ledger['required_gates'], list(gates.SUCCESSOR_GATES))
        self.assertEqual(ledger['cold_seconds'], 180); self.assertEqual(ledger['full_retained_seconds'], 10800)
        self.assertFalse(ledger['v8_PASS_qualifies_new_owners']); self.assertFalse(ledger['actual_successor_run_completed'])
        clean = dict.fromkeys(gates.SUCCESSOR_GATES, True)
        self.assertTrue(gates.require_successor_gates(clean))
        for name in gates.SUCCESSOR_GATES:
            for value in (False, 1, None):
                with self.subTest(gate=name, value=value), self.assertRaises(ValueError):
                    gates.require_successor_gates(dict(clean, **{name: value}))
            removed = dict(clean); removed.pop(name)
            with self.assertRaises(ValueError): gates.require_successor_gates(removed)
        with self.assertRaises(ValueError): gates.require_successor_gates(dict.fromkeys(gates.LEGACY_V8_GATES, True))

    def test_workflow_preserves_d03_seven_module_step_and_adds_four_cold_steps_and_artifacts(self):
        old_step = '\n'.join(step('Native graph wire worker machine-plan and linked observer')).encode()
        self.assertEqual(sha256(old_step).hexdigest(), 'db3e0064c8de5b138bac1842a36d9a923f574893ad558064c03312c7769c09eb')
        workflow = (ROOT / '.github/workflows/hia-core.yml').read_text()
        generators = script('Regenerate actual HIA sources').split('for component in ', 1)[1].split('; do', 1)[0].split()
        self.assertEqual(len(generators), len(set(generators)))
        self.assertEqual(generators[-2:], ['agent_store_authority', 'artifact_page'])
        archive = step('Preserve actual cold failure and stage evidence')
        for owner, label, slug in [('authority', 'Store reference URI and profile authority', 'store-authority'),
                                  ('page', 'ordinary artifact read and complete page boundaries', 'artifact-read')]:
            config = gates.OWNERS[owner]
            component = 'Native ' + label + ' with retained cold fixtures'
            callers = 'Ordinary ' + label + ' callers with retained owners forbidden'
            self.assertIn('qualify_hia_store_page_ci.py component', script(component))
            self.assertIn('--owner ' + owner + ' --cold-report "$RUNNER_TEMP/hia-cold.json"', script(component))
            self.assertIn(config['prefix'] + '_COLD_REPORT: ${{ runner.temp }}/hia-cold.json', '\n'.join(step(component)))
            self.assertIn('set -eu', script(callers)); self.assertIn(config['caller_driver'], script(callers))
            self.assertIn('qualify_hia_store_page_ci.py check-callers', script(callers))
            self.assertNotIn('--development', script(component) + script(callers))
            self.assertLess(workflow.index('tools/replay_hia_selfhost_cold.py'), workflow.index('      - name: ' + component))
            for suffix in ('components.json', 'component-evidence/', 'callers.json', 'callers-evidence/', 'caller-gate.json'):
                self.assertIn('            ${{ runner.temp }}/hia-' + slug + '-' + suffix, archive)
        source = script('Core source and independent reference controls')
        for name in ('tests.test_hia_agent_store_authority_native.StoreAuthoritySourceTests',
                     'tests.test_hia_artifact_read_native.ArtifactReadSourceTests', 'tests.test_hia_store_page_gates'):
            self.assertIn(repr(name), source)

    def test_actual_build_reader_refuses_changed_images_sources_compilers_and_limits(self):
        for owner in gates.OWNERS:
            for mode in ('clean', 'image', 'source', 'compiler', 'cold', 'closure', 'development',
                         'forbidden_author', 'status', 'limit', 'extent', 'wire_child'):
                if owner == 'authority' and mode == 'wire_child': continue
                with self.subTest(owner=owner, mode=mode), tempfile.TemporaryDirectory() as temporary:
                    folder = Path(temporary) / 'build'; context = synthetic_build(folder, owner)
                    build = gates.json_file(folder / 'build.json')
                    manifest_path = folder / ('manifest.json' if owner == 'authority' else 'policy/manifest.json')
                    manifest = gates.json_file(manifest_path)
                    receipt = build['native_compile_receipt' if owner == 'authority' else 'policy_compile_receipt']
                    if mode == 'image': (manifest_path.parent / manifest['image_path']).write_bytes(b'changed')
                    elif mode == 'source': manifest['source_sha256'] = '0' * 64; save(manifest_path, manifest)
                    elif mode == 'compiler': build['compiler_sha256'] = '0' * 64
                    elif mode == 'cold': build['cold_report_sha256'] = '0' * 64
                    elif mode == 'closure': build['source_manifest'] = {}
                    elif mode == 'development': build['scope'] = 'DEVELOPMENT_ONLY_NOT_MATCHING_SOURCE_COLD'
                    elif mode == 'forbidden_author': receipt['forbidden_compiler_modules_loaded'] = ['hosted compiler']
                    elif mode == 'status': receipt['status'] = 'failed'
                    elif mode == 'limit': receipt['limits']['cpu_seconds'] = 11
                    elif mode == 'extent': receipt['produced_bytes'] += 1
                    elif mode == 'wire_child': (folder / 'wire/manifest.json').write_bytes(b'{}')
                    save(folder / 'build.json', build)
                    if mode == 'clean': gates.inspect_build(owner, folder, context)
                    else:
                        with self.assertRaises((ValueError, KeyError, OSError)): gates.inspect_build(owner, folder, context)

    def test_component_receipts_refuse_all_anomalies_denominator_drift_and_non_cold_scope(self):
        for owner in gates.OWNERS:
            with tempfile.TemporaryDirectory() as temporary:
                folder = Path(temporary) / 'build'; context = synthetic_build(folder, owner)
                binding = gates.inspect_build(owner, folder, context); report, ids = synthetic_component(owner, context, binding)
                self.assertTrue(gates.validate_component(owner, report, ids, binding, context))
                mutations = [(k, ['fixture anomaly']) for k in gates.ANOMALIES]
                mutations += [('tests_run', len(ids) - 1), ('tests_loaded', True), ('chosen_test_ids', []),
                    ('executed_test_ids', ids[::-1]), ('loaded_test_ids', [ids[0]] * len(ids)),
                    ('scope', 'DEVELOPMENT_ONLY'), ('unittest_successful', False), ('loader_errors', ['missing']),
                    ('source_after', {}), ('source_preserved', False), ('cold_inputs_preserved', False),
                    ('build_binding', {}), ('runtime_observations', {})]
                for key, value in mutations:
                    with self.subTest(owner=owner, key=key), self.assertRaises(ValueError):
                        gates.validate_component(owner, dict(report, **{key: value}), ids, binding, context)

    def test_original_67_caller_receipts_refuse_omissions_legacy_entries_and_missing_native_evidence(self):
        for owner in gates.OWNERS:
            with tempfile.TemporaryDirectory() as temporary:
                folder = Path(temporary) / gates.OWNERS[owner]['caller_build']
                context = synthetic_build(folder, owner); binding = gates.inspect_build(owner, folder, context)
                report, ids = synthetic_callers(owner, context, binding)
                self.assertTrue(gates.validate_callers(owner, report, ids, binding, context))
                mutations = [(k, ['fixture anomaly']) for k in gates.ANOMALIES]
                mutations += [('tests_run', 66), ('tests_chosen', 0), ('executed_test_ids', ids[:-1]),
                    ('scope', 'DEVELOPMENT_SELECTED_CALLERS_NOT_COLD_QUALIFICATION'), ('modules', []),
                    ('explicit_development_exclusions', {'test': 'excluded'}), ('retained_owner_entries', ['old owner']),
                    ('all_eleven_agent_tools_exercised', False), ('source_manifest', {}), ('source_sha256', {}),
                    ('matching_cold_source_closure_stable', False), ('evidence_dir_retained', False),
                    ('manifest_path', '/unrelated/manifest.json')]
                mutations += ([('actual_native_modes', {}), ('independent_uri_control', {}), ('manifest', {})]
                              if owner == 'authority' else [('actual_native_entries', {}),
                                  ('agent_tools_with_native_page', {}), ('bundle_files_after', {}), ('bundle_manifest', {})])
                for key, value in mutations:
                    with self.subTest(owner=owner, key=key), self.assertRaises(ValueError):
                        gates.validate_callers(owner, dict(report, **{key: value}), ids, binding, context)

    def test_real_command_rejects_bad_cold_and_development_before_creating_evidence(self):
        for owner in gates.OWNERS:
            for development in (False, True):
                with self.subTest(owner=owner, development=development), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary); cold = root / 'cold.json'; cold.write_text('{}')
                    output, evidence = root / 'report.json', root / 'evidence'
                    env = {'PATH': '', 'LANG': 'C', 'LC_ALL': 'C'}
                    if development: env[gates.OWNERS[owner]['prefix'] + '_DEVELOPMENT_MANIFEST'] = '/old/development'
                    command = [sys.executable, '-I', '-S', '-B', str(ROOT / 'tools/qualify_hia_store_page_ci.py'),
                               'component', '--owner', owner, '--cold-report', str(cold), '--output', str(output),
                               '--evidence-dir', str(evidence)]
                    observed = subprocess.run(command, cwd=root, env=env, capture_output=True, timeout=10)
                    self.assertNotEqual(observed.returncode, 0)
                    self.assertIn(b'development selection' if development else b'nested_report', observed.stderr)
                    self.assertFalse(evidence.exists()); self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()
