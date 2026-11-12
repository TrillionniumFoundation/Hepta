"""Finite controller-only checks, without a compiler, HIA entry or product suite.

The original Core39 validator is stubbed only in the focused synthetic wrapper
tests. Those controls test new report predicates, never claim native evidence.
"""
from __future__ import annotations
import argparse
import ast
from copy import deepcopy
from hashlib import sha1, sha256
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import time
import traceback
from unittest.mock import patch


def filepin(path):
    raw = path.read_bytes()
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
            'git_blob_sha1': sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--control', type=Path, required=True)
    parser.add_argument('--reference', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    args = parser.parse_args()
    args.evidence.mkdir(mode=0o700)
    report = {'schema': 'hia.core-unpack-capsule-controller-checks.v1', 'status': 'HOLD',
              'product_executed': False, 'native_or_cold_claimed': False, 'checks': []}
    before = {p.name: filepin(p) for p in sorted(args.control.iterdir()) if p.is_file()}
    started = time.monotonic()
    def check(name, value):
        if not value:
            raise AssertionError(name)
        report['checks'].append(name)
    try:
        for path in args.control.glob('*.py'):
            compile(path.read_bytes(), str(path), 'exec')
        check('all frozen controller Python sources compile without execution', True)
        sys.path.insert(0, str(args.control))
        common = load('common', args.control / 'common.py')
        verify = load('verify', args.control / 'verify.py')
        controller = load('controller', args.control / 'controller.py')
        small = load('small_diagnostics', args.control / 'small_diagnostics.py')
        policy = json.loads((args.control / 'policy.json').read_bytes())
        original = json.loads((args.reference / 'policy.json').read_bytes())
        check('all twelve controller source pins match actual fixed files',
              len(policy['controls']) == 12 and all(
                  filepin(args.control / name) == wanted for name, wanted in policy['controls'].items()))
        check('original complete116 module/ID/order/count mapping is unchanged',
              policy['test_groups'] == original['test_groups']
              and sum(group['count'] for group in policy['test_groups'].values()) == 116)
        check('three phases keep the original180 and3 cleanup boundaries',
              controller.PHASES == ('preparation', 'components', 'tests')
              and policy['phase_controller_seconds'] == 180 and policy['cleanup_seconds'] == 3)
        check('extra finite and ordinary18 keep separate exact denominators',
              [policy['component_groups'][label]['count'] for label in ('shim', 'finite-native', 'ordinary')]
              == [4, 6, 8]
              and all(len(value['ids']) == len(set(value['ids'])) == value['count']
                      for value in policy['component_groups'].values()))
        for name, wanted in (('guardian.py', 'd0b56d24905895ad59120f401d006badfdb1df5b3e0ab17a80e8414da78a1023'),
                             ('process_owner_impl.py', '36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2')):
            check('original exact owned-process implementation: ' + name,
                  filepin(args.control / name)['sha256'] == wanted)
        check('original compile limits and six original-file suffixes retained',
              common.LIMITS == {'source_bytes': 1048576, 'source_lines': 16384, 'functions': 128,
                'blocks_total': 1536, 'blocks_per_function': 256, 'instructions': 8192,
                'ssa_names_per_function': 2048, 'parameters_or_arguments': 16}
              and common.COMPILE_SUFFIXES == ('.receipt.json', '.stdout.log', '.stderr.log',
                   '.request.json', '.input.bin', '.output.bin'))
        old_ast, new_ast = ast.parse((args.reference / 'common.py').read_bytes()), ast.parse((args.control / 'common.py').read_bytes())
        old_funcs = {n.name: ast.dump(n) for n in old_ast.body if isinstance(n, (ast.FunctionDef, ast.ClassDef))}
        new_funcs = {n.name: ast.dump(n) for n in new_ast.body if isinstance(n, (ast.FunctionDef, ast.ClassDef))}
        check('all original descriptor/source/guardian helper ASTs unchanged', old_funcs == new_funcs)
        root, source = Path('/fixed/private-operation'), Path('/fixed/source')
        context = {'python': {'resolved': '/fixed/python'}, 'policy_sha256': '1' * 64}
        command = controller.phase_command('tests', root, source, context)
        rows = [dict(path=name, mode='100644', posix_mode=0o644, bytes=1,
                     sha256=str(index) * 64, git_blob_sha1=str(index) * 40)
                for index, name in enumerate([*common.GENERATED, 'hepta/fixed.py'], 1)]
        tree = common.tree_identity(rows)
        fixed = {'rows': rows, 'metadata': {'HEAD': 'a' * 40},
                 'physical': {'files': [row['path'] for row in rows]}, 'actual_worktree_tree': tree}
        gate_policy = {'candidate': {'tree': tree, 'leaves': len(rows)}}
        gate_report = {'derived_worktree_tree': tree, 'derived_source_delta': [],
                       'mutable_source_paths': [], 'regenerated_source_paths': list(common.GENERATED),
                       'source_derivation_idempotent': True, 'derived_tree_has_published_commit': True}
        verify.source_idempotence(fixed, deepcopy(fixed), deepcopy(fixed), deepcopy(fixed), gate_policy, gate_report)
        check('complete exact candidate accepts idempotent inventory regeneration', True)
        mutations = [
            ('coverage bytes changed', lambda s, r: s['rows'][0].update(sha256='9' * 64)),
            ('support bytes changed', lambda s, r: s['rows'][1].update(sha256='9' * 64)),
            ('source mode changed', lambda s, r: s['rows'][2].update(posix_mode=0o755)),
            ('physical namespace changed', lambda s, r: s['physical']['files'].append('extra')),
            ('Git metadata changed', lambda s, r: s['metadata'].update(HEAD='b' * 40)),
            ('old two-change record', lambda s, r: r['derived_source_delta'].append({'path': common.GENERATED[0]})),
            ('mutable JSON exception', lambda s, r: r['mutable_source_paths'].append(common.GENERATED[1])),
            ('missing source idempotence claim', lambda s, r: r.update(source_derivation_idempotent=False)),
            ('unpublished derived tree', lambda s, r: r.update(derived_tree_has_published_commit=False)),
        ]
        for label, mutate in mutations:
            changed_source, changed_report = deepcopy(fixed), deepcopy(gate_report)
            mutate(changed_source, changed_report)
            refused = False
            try:
                verify.source_idempotence(fixed, deepcopy(fixed), changed_source, deepcopy(fixed),
                                          gate_policy, changed_report)
            except (RuntimeError, KeyError, TypeError, ValueError):
                refused = True
            check('idempotence gate refuses: ' + label, refused)
        with tempfile.TemporaryDirectory(prefix='unpack-owner-binding-control-') as temporary:
            operation = Path(temporary)
            declaration = {str(source / name): str(index) * 64
                           for index, name in enumerate(common.GENERATED, 1)}
            with patch.object(controller, 'fixed_inputs', return_value={}), \
                 patch.object(controller, 'declared_inputs', return_value=declaration):
                setup = controller.create_phase('preparation', args.control, policy, operation, source,
                                                context, rows)
            request = json.loads((operation / 'preparation-guard/request.json').read_bytes())
            check('outer preparation owner binds both immutable generated JSON files',
                  setup['source_identities'] == declaration == request['source_identities']
                  and setup['intentionally_mutable_source_paths'] == [])
        check('the full116 command is unsplit and binds both actual manifests',
              command == ['/fixed/python', '-I', '-B', '/fixed/source/tools/qualify_hia_core_unpack_callers.py',
                '--core-development-manifest', '/fixed/private-operation/preparation/bundle/manifest.json',
                '--unpack-development-manifest', '/fixed/private-operation/preparation/unpack/manifest.json',
                '--evidence', '/fixed/private-operation/callers'])
        rejected = False
        try:
            controller.phase_command('not-a-phase', root, source, context)
        except RuntimeError:
            rejected = True
        check('unknown phase cannot create another product command', rejected)
        names = small.fixed_names()
        check('the full diagnostic fixed set has56 unique names', len(names) == len(set(names)) == 56)
        check('component and nested116 child originals require their own closed phase',
              all(small.gated_phase(name) == 'components' for name in names if name.startswith('components/'))
              and all(small.gated_phase(name) == 'tests' for name in names if name.startswith('callers/')))
        check('whole-file small stdout and raw caps remain unchanged',
              (small.MAX_RAW, small.MAX_STDOUT, small.MAX_DERIVED) == (524288, 1048576, 131072))
        check('every diagnostic priority names an actual fixed original once',
              len(small.priority()) == len(set(small.priority())) == 56
              and set(small.priority()) == set(names))
        with tempfile.TemporaryDirectory(prefix='unpack-report-control-') as temporary:
            root = Path(temporary)
            companion = root / 'preparation/unpack'
            companion.mkdir(parents=True)
            case = root / 'callers/core-callers/component-fixture/installed-control'
            case.mkdir(parents=True)
            source = root / 'source'
            source.mkdir()
            def save(path, value):
                path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')
                return common.read(path)[1]
            image = companion / 'core-unpack.image.bin'
            image.write_bytes(b'synthetic-image-never-executed')
            image_pin = common.read(image)[1]
            manifest = {'schema': 'hepta.hia.core-unpack-native.v1', 'image_path': image.name,
                'image_sha256': image_pin['sha256'], 'compiler_sha256': '2' * 64,
                'source_sha256': policy['unpack_inputs']['examples/hia_bootstrap/core_unpack.hiaasm']['sha256'],
                'abi_sha256': policy['unpack_inputs']['hepta/hia_core_unpack_abi.json']['sha256'],
                'bridge_sha256': policy['unpack_inputs']['hepta/hia_core_unpack_native.py']['sha256'],
                'selection_sha256': policy['unpack_inputs']['hepta/hia_core_unpack_selection.py']['sha256']}
            manifest_pin = save(companion / 'manifest.json', manifest)
            build_pin = save(companion / 'build.json', {'synthetic': True})
            source_pins = {name: value['sha256'] for name, value in policy['unpack_inputs'].items()}
            prepared = {'companion': {'manifest': manifest, 'manifest_original': manifest_pin,
                         'image_original': image_pin, 'build_original': build_pin},
                        'report': {'development_source_manifest': source_pins}}
            core_pin = save(root / 'callers/core-callers/report.json', {'synthetic': True})
            core_result = {'report_original': core_pin}
            simple = lambda p: {'path': p['path'], 'size': p['bytes'], 'sha256': p['sha256']}
            admitted = {name: manifest[name] for name in ('source_sha256', 'abi_sha256', 'bridge_sha256',
                'selection_sha256', 'image_sha256', 'compiler_sha256')}
            admitted.update(manifest_sha256=manifest_pin['sha256'],
                            transaction_sha256=policy['unpack_transaction']['sha256'], runtime_profile=31404)
            identity_parts = [manifest['schema'], manifest_pin['sha256'], manifest['compiler_sha256'],
                              manifest['image_sha256'], admitted['transaction_sha256'], '31404']
            for name in sorted(source_pins):
                identity_parts.extend((name, source_pins[name]))
            identity = sha256('\0'.join(identity_parts).encode('ascii')).hexdigest()
            installed = {'schema': 'hepta.hia.core-unpack-installed-observation.v1',
                'retained_unpack_forbidden': True, 'runtime_profile': 31404,
                'transaction_sha256': admitted['transaction_sha256'],
                'actual_statuses': [0, 1], 'actual_step_returns': 2,
                'refusals': [name + suffix for name in ('hepta/hia_core_unpack_abi.json',
                    'examples/hia_bootstrap/core_unpack.hiaasm') for suffix in (':changed', ':missing')],
                **{name: admitted[name] for name in ('source_sha256', 'abi_sha256', 'bridge_sha256',
                    'selection_sha256', 'image_sha256', 'compiler_sha256')}}
            installed_pin = save(case / 'report.json', {'unpack_observations': installed})
            processes = [{}, {}, {'argv': ['python', '-I', '-S', '-B', 'script', 'installed',
                          'core-manifest', 'expected', str(companion / 'manifest.json')]}]
            save(case / 'processes.json', processes)
            rows = [dict(group=label, test=group['ids'][0], arity=1,
                         image_sha256=manifest['image_sha256'], count=1)
                    for label, group in policy['test_groups'].items()]
            report_fixture = {'schema': 'hepta.hia.core-unpack-selected-callers.v1',
                'status': 'PASS', 'scope': 'EXPLICIT_DEVELOPMENT_ONLY',
                'original_groups': [15, 51, 50], 'original_complete_methods': 116,
                'original_Core_image_count': 39, 'additional_UNPACK_image_count': 1,
                'complete_116_passed': True, 'stable': True,
                'outer_opcode14_permission_still_consumed_once': True,
                'old_complete_unpack_entries': [], 'CPython_object_runtime_still_hosted': True,
                'whole_stack_rewritten_in_hia': False, 'default_activated': False,
                'transaction_ABI': policy['unpack_transaction']['abi'],
                'transaction_sha256': admitted['transaction_sha256'], 'admitted_companion': admitted,
                'identity_before': identity, 'identity_after': identity,
                'source_before': source_pins, 'source_after': source_pins,
                'companion_inputs_before': [simple(p) for p in (manifest_pin, image_pin, build_pin)],
                'companion_inputs_after': [simple(p) for p in (manifest_pin, image_pin, build_pin)],
                'original_report': simple(core_pin),
                'original_qualifier_argv': ['qualify_hia_core_lowering_callers.py', '--development-manifest',
                    str(root / 'preparation/bundle/manifest.json'), '--evidence', str(root / 'callers/core-callers')],
                'outer_opcode14_attempts': deepcopy(rows), 'outer_opcode14_normal_returns': deepcopy(rows),
                'outer_opcode14_exceptions': [],
                'actual_UNPACK_step_returns': [dict(row, status=status) for row in rows for status in (0, 1)],
                'installed_report': simple(installed_pin), 'installed_observation': installed}
            def invoke(value):
                save(root / 'callers/report.json', value)
                with patch.object(verify, 'selected_callers_core39', return_value=core_result):
                    return verify.selected_callers(root, source, context, policy, prepared)
            good = invoke(report_fixture)
            check('synthetic independent wrapper conjunction accepts its exact finite seed',
                  good['actual_UNPACK_step_total'] == 6 and good['complete_original_method_count'] == 116)
            mutations = []
            def changed(name, update):
                value = deepcopy(report_fixture); update(value); mutations.append((name, value))
            changed('old complete host policy entered', lambda x: x['old_complete_unpack_entries'].append(['x']))
            changed('wrong total116', lambda x: x.update(original_complete_methods=115))
            changed('wrong Core image denominator', lambda x: x.update(original_Core_image_count=40))
            changed('missing complete original flag', lambda x: x.update(complete_116_passed=False))
            changed('unbalanced outer attempts', lambda x: x['outer_opcode14_attempts'][0].update(count=2))
            changed('Boolean actual-step arity', lambda x: x['actual_UNPACK_step_returns'][0].update(arity=True))
            changed('Boolean actual-step status', lambda x: x['actual_UNPACK_step_returns'][0].update(status=False))
            changed('nonpositive actual-step count', lambda x: x['actual_UNPACK_step_returns'][0].update(count=0))
            changed('wrong actual image', lambda x: x['actual_UNPACK_step_returns'][0].update(image_sha256='3' * 64))
            changed('duplicate actual-step row', lambda x: x['actual_UNPACK_step_returns'].append(deepcopy(x['actual_UNPACK_step_returns'][0])))
            changed('missing all one-group actual returns', lambda x: x.update(actual_UNPACK_step_returns=x['actual_UNPACK_step_returns'][2:]))
            changed('wrong observed ABI profile', lambda x: x['admitted_companion'].update(runtime_profile=31214))
            changed('matched but false identity digests', lambda x: x.update(identity_before='4' * 64, identity_after='4' * 64))
            changed('source-after drift', lambda x: x['source_after'].update({'extra': '5' * 64}))
            changed('split original qualifier argument', lambda x: x['original_qualifier_argv'].extend(['--development-group', 'component']))
            changed('missing installed refusal', lambda x: x['installed_observation']['refusals'].pop())
            for name, value in mutations:
                refused = False
                try:
                    invoke(value)
                except (RuntimeError, KeyError, TypeError, ValueError):
                    refused = True
                check('synthetic wrapper refuses: ' + name, refused)
        report['status'] = 'CONTROLLER_ONLY_CHECKS_PASS'
    except BaseException:
        report['status'] = 'HOLD'; report['error'] = traceback.format_exc()
        traceback.print_exc()
    finally:
        after = {p.name: filepin(p) for p in sorted(args.control.iterdir()) if p.is_file()}
        report['source_before'], report['source_after'], report['source_stable'] = before, after, before == after
        if before != after:
            report['status'] = 'HOLD'
        report['seconds'] = time.monotonic() - started
        (args.evidence / 'report.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'status': report['status'], 'checks': len(report['checks']),
                      'seconds': report['seconds'], 'error': report.get('error')}, sort_keys=True))
    return 0 if report['status'] == 'CONTROLLER_ONLY_CHECKS_PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
