"""Derive two inventories and build all 39 original HIA units under one 180/3 owner.

This is a new development bootstrap, not a cold qualification. B0 is the explicit
retained trust boundary; B1/B2 and every new unit are actual HIA executions using
the unchanged compile_stage child, 20-second wall and 10-second CPU bounds.
"""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import traceback

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import (GENERATED, LIMITS, compile_originals, create, document, inventory, metadata,
                    physical_source, read, require, save, snapshot, tree_identity, wire)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--policy-sha256', required=True)
    args = parser.parse_args()
    root, source = args.root, args.source
    context, context_pin = document(root / 'context.json')
    policy_raw, policy_pin = read(root / 'control/policy.json', 1 << 20)
    policy = json.loads(policy_raw)
    require(policy_pin['sha256'] == args.policy_sha256 == context['policy_sha256']
            and context['schema'] == 'hia.core-emitter-native-actions-context.v1'
            and context['source'] == str(source) and context['root'] == str(root)
            and context['candidate'] == policy['candidate'],
            'exact native preparation context differs')
    initial, initial_pin = document(root / 'initial-source.json', 8 << 20)
    require(initial_pin['sha256'] == context['initial_source_sha256'], 'complete initial snapshot differs')
    evidence = root / 'preparation'
    require(not os.path.lexists(evidence), 'create-only native preparation evidence already exists')
    evidence.mkdir(mode=0o700)
    report = {'schema': 'hia.core-emitter-native-preparation.v1', 'status': 'HOLD',
              'scope': 'NEW_SOURCE_DEVELOPMENT_B0_B1_B2_AND_39_UNITS',
              'candidate': policy['candidate'], 'context_sha256': context_pin['sha256'],
              'policy_sha256': policy_pin['sha256'],
              'initial_source_original': initial_pin,
              'controller_seconds': 180, 'cleanup_seconds': 3,
              'compile_child_wall_seconds': 20, 'compile_child_CPU_seconds': 10,
              'original_compile_capacity_bytes': 1048576,
              'generated_HIA_sources_recreated': False, 'cold_qualified': False,
              'old_compiler_image_reused': False, 'B3_or_mutation_qualified': False,
              'complete_116_tests_executed': False, 'whole_native_claimed': False,
              'original_limits_changed': False, 'production_activated': False,
              'mutable_source_paths': list(GENERATED), 'unit_receipts': [], 'compile_originals': [],
              'source_preserved_except_declared_derivations': False,
              'source_stable_after_derivation': False,
              'desktop_interpreter_identity_claimed': False}
    derived = None
    compiler_bytes = None
    started = time.monotonic()
    try:
        require(not any(value for name, value in os.environ.items()
                        if name.startswith(('GIT_', 'LD_', 'HEPTA_HIA_'))),
                'preparation inherited selector or execution redirection')
        require(sys.version_info[:3] == (3, 14, 4)
                and str(Path(sys.executable).resolve()) == context['python']['resolved'],
                'actual preparation interpreter differs')
        current = snapshot(source, context['git']['resolved'], policy['candidate'], initial['rows'])
        require(current == initial, 'complete source changed before native preparation')
        report['source_before'] = save(evidence / 'source-before.json', current)
        before_contract, _ = document(source / GENERATED[1])
        old_limits = before_contract['limits']
        require({key: old_limits[key] for key in LIMITS if key != 'source_lines'} ==
                {key: value for key, value in LIMITS.items() if key != 'source_lines'}
                and old_limits['ssa_index_max_is_internal_only'] is True
                and before_contract['abi']['core_return'] == 'u32', 'original compiler limits differ')
        report['unchanged_limits'] = dict(LIMITS)
        commands = [
            [sys.executable, '-I', '-S', '-B',
             str(source / 'tests/test_hia_selfhost_language_coverage.py'), '--generate-inventory'],
            [sys.executable, '-I', '-S', '-B',
             str(source / 'tools/generate_hia_selfhost_contract.py')],
            [sys.executable, '-I', '-S', '-B',
             str(source / 'tools/generate_hia_selfhost_contract.py'), '--check'],
        ]
        report['derived_commands'] = []
        for index, command in enumerate(commands):
            at = time.monotonic()
            process = subprocess.run(command, cwd=source, stdin=subprocess.DEVNULL,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            prefix = 'derive-%02d' % index
            row = {'command': command, 'returncode': process.returncode,
                   'seconds': time.monotonic() - at,
                   'stdout': create(evidence / (prefix + '.stdout.log'), process.stdout),
                   'stderr': create(evidence / (prefix + '.stderr.log'), process.stderr)}
            report['derived_commands'].append(row)
            require(process.returncode == 0, 'declared inventory derivation/check failed')
        derived = snapshot(source, context['git']['resolved'], policy['candidate'],
                           initial['rows'], mutable=GENERATED)
        changed = [before['path'] for before, after in zip(initial['rows'], derived['rows'])
                   if before != after]
        require(changed == sorted(GENERATED), 'actual tracked source delta is not exactly the two inventories')
        before_rows = {row['path']: row for row in initial['rows']}
        after_rows = {row['path']: row for row in derived['rows']}
        require(all(before_rows[name]['mode'] == after_rows[name]['mode']
                    and before_rows[name]['posix_mode'] == after_rows[name]['posix_mode']
                    for name in GENERATED), 'generated inventory file mode changed')
        require(derived['metadata'] == initial['metadata']
                and derived['physical'] == initial['physical'],
                'Git metadata or complete physical namespace changed during derivation')
        report['derived_source'] = save(evidence / 'derived-source.json', derived)
        report['derived_worktree_tree'] = derived['actual_worktree_tree']
        report['actual_HEAD_remains_initial_candidate'] = True
        report['derived_tree_has_published_commit'] = False
        report['derived_source_delta'] = [
            {'path': name, 'before': before_rows[name], 'after': after_rows[name]}
            for name in sorted(GENERATED)]
        generated_dir = evidence / 'derived'
        generated_dir.mkdir(mode=0o700)
        report['derived_originals'] = {}
        for name in GENERATED:
            raw, pin = read(source / name)
            require(pin['sha256'] == after_rows[name]['sha256'], 'derived original drifted')
            report['derived_originals'][name] = create(generated_dir / Path(name).name, raw)
        report['source_preserved_except_declared_derivations'] = True
        after_contract, _ = document(source / GENERATED[1])
        require(after_contract['limits'] == old_limits and after_contract['abi'] == before_contract['abi'],
                'derivation changed compiler capability or ABI ceilings')

        sys.path.insert(0, str(source))
        from tools.hia_selfhost_contract import validate_contract, file_digests, CONTRACT_PATH
        from hepta.hia_core_lowering_selection import checked_abi, ABI_SOURCE, SCHEMA, UNIT_SCHEMA
        from tools.qualify_hia_selfhost import build_seed, compile_stage
        admitted_contract = validate_contract()
        require(admitted_contract == after_contract, 'derived source contract is not exact')
        source_manifest = file_digests()
        source_manifest[CONTRACT_PATH] = sha256((source / CONTRACT_PATH).read_bytes()).hexdigest()
        report['development_source_manifest'] = source_manifest
        report['profile'] = admitted_contract['profile']
        abi_raw, abi_pin = read(source / ABI_SOURCE, 1 << 20)
        abi = checked_abi(abi_raw)
        names = ['core_lowering_pool', *abi['units']]
        require(len(names) == len(set(names)) == 39
                and names == policy['unit_names']
                and abi_pin['sha256'] == policy['original_generated_assets']['abi_sha256'],
                'exact 39 original generated units/ABI differ')
        inputs = {}
        for name in names:
            relative_name = 'examples/hia_bootstrap/' + name + '.hiaasm'
            raw, pin = read(source / relative_name, 1 << 20)
            wanted = policy['original_generated_assets']['sources'][relative_name]
            require(pin['bytes'] == wanted['bytes'] and pin['sha256'] == wanted['sha256']
                    and pin['git_blob_sha1'] == wanted['git_blob_sha1'],
                    'actual historical HIA source differs: ' + name)
            inputs[name] = raw
        report['original_generated_asset_identity_verified'] = True
        report['abi_original'] = create(evidence / 'hia_core_lowering_abi.json', abi_raw)
        native = evidence / 'bootstrap'
        native.mkdir(mode=0o700)
        selfhost_raw, selfhost_pin = read(source / 'examples/hia_bootstrap/selfhost.hiaasm', 1 << 20)
        report['selfhost_source'] = selfhost_pin
        report['development_bootstrap_attempted'] = True
        seed, seed_receipt = build_seed(native)
        report['B0'] = seed_receipt
        original_seed, seed_pin = document(native / 'B0.receipt.json', 2 << 20)
        require(original_seed == seed_receipt, 'actual B0 receipt differs from the returned original')
        report['B0_originals'] = {'receipt': seed_pin, 'image': read(seed, 64 << 20)[1]}
        first, first_receipt = compile_stage(native, 'B1', seed, selfhost_raw,
                                             image_format='seed-shared')
        report['B1'] = first_receipt
        report['compile_originals'].append(compile_originals(native, 'B1'))
        second, second_receipt = compile_stage(native, 'B2', first, selfhost_raw)
        report['B2'] = second_receipt
        report['compile_originals'].append(compile_originals(native, 'B2'))
        first_bytes, _ = read(first, 1 << 20)
        compiler_bytes, compiler_pin = read(second, 1 << 20)
        require(first_bytes == compiler_bytes, 'actual new development B1 and B2 differ')
        report['compiler_original'] = compiler_pin
        report['B1_equals_B2'] = True
        compiler_sha = compiler_pin['sha256']
        output = evidence / 'bundle'
        output.mkdir(mode=0o700)
        manifests, result_files = {}, []
        for name in names:
            folder = output / name
            folder.mkdir(mode=0o700)
            image, receipt = compile_stage(folder, name, second, inputs[name])
            report['compile_originals'].append(compile_originals(folder, name))
            image_bytes, image_pin = read(image, 1 << 20)
            require(receipt['status'] == 'returned' and receipt['abi_status'] == 0
                    and receipt['source_unchanged'] is True
                    and receipt['forbidden_compiler_modules_loaded'] == []
                    and receipt['input_sha256'] == sha256(inputs[name]).hexdigest()
                    and receipt['artifact_sha256'] == compiler_sha
                    and receipt['format'] == 'flat-x86-64'
                    and receipt['produced_bytes'] == image_pin['bytes']
                    and receipt['produced_sha256'] == image_pin['sha256']
                    and 0 < image_pin['bytes'] <= 1048576,
                    'actual unchanged native compilation receipt differs')
            manifest = {'schema': UNIT_SCHEMA, 'source_sha256': sha256(inputs[name]).hexdigest(),
                        'image_path': image.name, 'image_sha256': image_pin['sha256'],
                        'compiler_sha256': compiler_sha}
            pin = save(folder / 'manifest.json', manifest)
            manifests[name] = name + '/manifest.json'
            result_files += [pin, image_pin]
            report['unit_receipts'].append({
                'name': name, 'source': 'examples/hia_bootstrap/' + name + '.hiaasm',
                'manifest': manifest, 'manifest_original': pin,
                'image_original': image_pin, 'native_compile_receipt': receipt})
        require(len(report['unit_receipts']) == 39 and len(report['compile_originals']) == 41,
                'complete native unit or original compile denominator differs')
        require(read(second, 1 << 20)[0] == compiler_bytes, 'development compiler changed')
        bundle = {'schema': SCHEMA, 'abi_sha256': sha256(abi_raw).hexdigest(),
                  'compiler_sha256': compiler_sha, 'unit_manifests': manifests}
        report['bundle_original'] = save(output / 'manifest.json', bundle)
        report['build_original'] = save(output / 'build.json', {
            'schema': 'hia.core-emitter-development-build.v1',
            'status': 'DEVELOPMENT_39_UNIT_BUNDLE_BUILT',
            'scope': 'CURRENT_SOURCE_B0_B1_B2_DEVELOPMENT_NOT_COLD',
            'candidate': policy['candidate'], 'derived_worktree_tree': derived['actual_worktree_tree'],
            'source_manifest': source_manifest, 'bundle': bundle,
            'abi_sha256': sha256(abi_raw).hexdigest(), 'compiler_sha256': compiler_sha,
            'units': report['unit_receipts'], 'expected_unit_count': 39, 'actual_unit_count': 39,
            'cold_qualified': False, 'native_persistence_or_linking_claimed': False,
            'whole_stack_rewritten_in_hia': False, 'production_activated': False})
        report['build_files'] = result_files + [report['bundle_original'], report['build_original']]
        report['status'] = 'DEVELOPMENT_B0_B1_B2_39_BUILT'
    except BaseException as error:
        report['status'] = 'HOLD'
        report['error'] = {'type': type(error).__name__, 'message': str(error),
                           'traceback': traceback.format_exc()}
        traceback.print_exc()
    finally:
        try:
            after = snapshot(source, context['git']['resolved'], policy['candidate'],
                             derived['rows'] if derived is not None else initial['rows'],
                             mutable=() if derived is not None else GENERATED)
            report['source_after'] = save(evidence / 'source-after.json', after)
            if derived is not None:
                require(after == derived, 'complete derived source changed during native preparation')
                report['source_stable_after_derivation'] = True
            original_pins = [pin for item in report['compile_originals'] for pin in item['files']]
            original_pins += list(report.get('B0_originals', {}).values())
            for pin in original_pins:
                _, actual = read(Path(pin['path']), max(pin['bytes'], 1))
                require(actual == pin, 'actual completed compile original changed')
            for pin in report.get('build_files', []):
                raw, actual = read(Path(pin['path']), max(pin['bytes'], 1))
                require(actual['sha256'] == pin['sha256'] and actual['bytes'] == pin['bytes']
                        and actual['git_blob_sha1'] == pin['git_blob_sha1'],
                        'actual completed bundle file changed')
            if compiler_bytes is not None:
                require(read(Path(report['compiler_original']['path']), 1 << 20)[0] == compiler_bytes,
                        'development compiler changed at final observation')
        except BaseException as error:
            report['status'] = 'HOLD'
            report['preservation_error'] = {'type': type(error).__name__, 'message': str(error),
                                           'traceback': traceback.format_exc()}
        report['final_inventory_originals'] = {}
        for name in GENERATED:
            try:
                target = evidence / ('final-' + Path(name).name)
                raw, _ = read(source / name, 32 << 20)
                report['final_inventory_originals'][name] = create(target, raw)
            except BaseException as error:
                report['status'] = 'HOLD'
                report['final_inventory_originals'][name] = {
                    'status': 'ORIGINAL_NOT_RETAINED', 'type': type(error).__name__,
                    'message': str(error)}
        report['seconds'] = time.monotonic() - started
        save(evidence / 'report.json', report)
    print(json.dumps({'status': report['status'], 'seconds': report['seconds'],
                      'actual_units': len(report['unit_receipts']),
                      'report': str(evidence / 'report.json')}, sort_keys=True), flush=True)
    return 0 if report['status'] == 'DEVELOPMENT_B0_B1_B2_39_BUILT' else 1

if __name__ == '__main__':
    raise SystemExit(main())
