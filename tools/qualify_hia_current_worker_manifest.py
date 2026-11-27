"""Qualify protocol-02 current Worker records against an actual installed Worker.

This is an external qualification driver. It never supplies a Python callback to
the native framer. Each HIA source image is freshly compiled by the supplied
native source builder; existing installed records are the independent format
authority. This component check does not claim a complete Worker installation.
"""
from __future__ import annotations

import argparse
import copy
from hashlib import sha256
import importlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import time
import traceback


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def frame(mode, role, pieces):
    return b'HIAWMF02' + struct.pack('<3Q', mode, role, len(pieces)) + b''.join(
        struct.pack('<Q', len(raw)) + raw for raw in pieces)


def source_inventory(rows):
    return b'HIASPI01' + struct.pack('<Q', len(rows)) + b''.join(
        struct.pack('<Q', len(name.encode('ascii'))) + bytes.fromhex(pin) + name.encode('ascii')
        for name, pin in rows)


def qualify(args):
    root = args.source.resolve(strict=True)
    worker = args.worker.resolve(strict=True)
    output = args.output.absolute()
    output.mkdir(mode=0o700)
    sys.path.insert(0, str(root))
    from tools.build_hia_worker_release import (INSTALLED_HELPERS, ADDITIONAL_HELPERS,
                                               EXTENDED_INSTALLED_HELPERS, CURRENT_INSTALLED_HELPERS)
    from tools.build_hia_json_preflight import CANDIDATES
    from tools.build_hia_worker_report import SOURCES as REPORT_SOURCES
    from tools.build_hia_native_continuation import pack_input
    from hepta.hia_worker_scheduling_bundle import FAMILIES
    from hepta.hia_agent_contract import CONTINUATION_BUILD_FILES
    from tools.hia_selfhost_contract import file_digests, CONTRACT_PATH

    compiler = args.compiler.read_bytes()
    generated = args.generated.resolve(strict=True) if getattr(args, 'generated', None) else root
    native_authority = getattr(args, 'native_source_authority', None)
    source_pin_file = getattr(args, 'source_pins', None)
    if bool(native_authority) != bool(source_pin_file):
        raise ValueError('native source authority and independent captured source pins must be supplied together')
    native_paths = None
    if native_authority:
        from tools.hia_native_worker_source_authority import load_native_source_authority, CONTINUATION_RUNTIME, SOURCE_SUFFIXES
        native_paths = load_native_source_authority(native_authority)
    table = (generated / 'examples/hia_bootstrap/worker_manifest_current_tables.hiastd').read_bytes()
    elf = args.executable.resolve(strict=True)
    builder = args.source_builder.resolve(strict=True)
    pins_before = {str(p): sha256(p.read_bytes()).hexdigest() for p in (elf, builder, args.compiler,
        generated / 'examples/hia_bootstrap/source_worker_manifest_current.hepta',
        generated / 'examples/hia_bootstrap/worker_manifest_current_tables.hiastd')}
    if native_authority:
        pins_before.update({str(p): sha256(p.read_bytes()).hexdigest() for p in (native_authority, source_pin_file)})
    record = dict(schema='hepta.hia.current-worker-manifest-qualification.v1',
        scope='Native component framing; full Worker publication is a separate gate',
        source_root=str(root), worker_format_authority=str(worker),
        executable_sha256=pins_before[str(elf)], compiler_sha256=sha256(compiler).hexdigest(),
        source_builder_sha256=pins_before[str(builder)], table_sha256=sha256(table).hexdigest(),
        positive=[], negative=[], native_compiles=[], success=False)
    started = time.monotonic()
    images = {}
    cases = {}
    outputs = {}

    def save():
        (output / 'qualification.json').write_bytes(encoded(record))

    def run(label, mode, role, pieces, expected=None, *, raw=None, argv=('build',)):
        request = frame(mode, role, [*pieces, table]) if raw is None else raw
        result = subprocess.run([str(elf), *argv], input=request, capture_output=True,
            env={'PATH': ''}, timeout=30)
        good = (result.returncode == (0 if expected is not None else 16)
                and not result.stderr
                and result.stdout == (expected if expected is not None else b''))
        receipt = dict(label=label, mode=mode, role=role, rc=result.returncode,
            input_bytes=len(request), input_sha256=sha256(request).hexdigest(),
            stdout_bytes=len(result.stdout), stdout_sha256=sha256(result.stdout).hexdigest(),
            stderr_bytes=len(result.stderr), passed=good)
        record['positive' if expected is not None else 'negative'].append(receipt)
        if not good:
            stem = output / ('failure-' + label)
            stem.with_suffix('.input').write_bytes(request)
            stem.with_suffix('.stdout').write_bytes(result.stdout)
            stem.with_suffix('.stderr').write_bytes(result.stderr)
            if expected is not None:
                stem.with_suffix('.expected').write_bytes(expected)
            save()
            raise AssertionError(receipt)
        if expected is not None:
            cases[mode, role] = list(pieces)
            outputs[mode, role] = result.stdout
        return result.stdout

    def compile_image(relative, old_image=None, old_source_pin=None):
        source = (root / relative).read_bytes()
        source_pin = sha256(source).hexdigest()
        if relative not in images:
            result = subprocess.run([str(builder), 'compile'], input=source,
                capture_output=True, env={'PATH': ''}, timeout=120)
            if result.returncode or result.stderr or not result.stdout:
                raise AssertionError(('native compiler refused', relative, result.returncode,
                                      result.stderr.decode(errors='replace')))
            images[relative] = result.stdout
            receipt = dict(source=relative, source_sha256=source_pin,
                image_bytes=len(result.stdout), image_sha256=sha256(result.stdout).hexdigest())
            record['native_compiles'].append(receipt)
        image = images[relative]
        if old_source_pin == source_pin:
            if image != old_image:
                raise AssertionError('unchanged source differs from independent installed image: ' + relative)
        return source, image

    def leaf(mode, role, manifest_path, source_path):
        raw = manifest_path.read_bytes()
        value = json.loads(raw)
        assert set(value) == {'schema', 'source_sha256', 'image_path', 'image_sha256', 'compiler_sha256'}
        old_image = (manifest_path.parent / value['image_path']).read_bytes()
        assert sha256(old_image).hexdigest() == value['image_sha256']
        source, image = compile_image(source_path, old_image, value['source_sha256'])
        expected = dict(value, source_sha256=sha256(source).hexdigest(),
                        image_sha256=sha256(image).hexdigest(), compiler_sha256=sha256(compiler).hexdigest())
        return run('leaf-%d-%d' % (mode, role), mode, role, [source, image, compiler], encoded(expected)), image

    try:
        original_helpers = json.loads((worker / 'helpers.json').read_bytes())
        original_names = (*INSTALLED_HELPERS, *ADDITIONAL_HELPERS)
        assert len(original_names) == 37
        names = (*original_names, *(name for _, name in EXTENDED_INSTALLED_HELPERS))
        assert len(names) == 41 and len(original_helpers['helpers']) == len(names)
        helper_manifests = []
        new_helpers = copy.deepcopy(original_helpers)
        package_pins = set()
        for role, (name, old_row, row) in enumerate(zip(names, original_helpers['helpers'],
                                                        new_helpers['helpers']), 1):
            assert old_row['selector'] == 'HEPTA_HIA_' + name.replace('-', '_').upper() + '_MANIFEST'
            if name in CURRENT_INSTALLED_HELPERS:
                package_pins.add(Path(old_row['manifest_path']).parts[1])
            source_name = CANDIDATES.get(name, (name.replace('-', '_'), name))[0]
            raw, _ = leaf(1, role, worker / old_row['manifest_path'],
                          'examples/hia_bootstrap/' + source_name + '.hepta')
            helper_manifests.append(raw)
            row['manifest_sha256'] = sha256(raw).hexdigest()
        assert len(package_pins) == 1
        package_pin = next(iter(package_pins))
        helpers = run('helpers', 2, 0, [bytes.fromhex(package_pin), *helper_manifests], encoded(new_helpers))

        report_leaves = []
        for role, name in enumerate(('policy', 'wire'), 1):
            raw, _ = leaf(3, role, worker / 'report' / name / 'manifest.json', REPORT_SOURCES[name])
            report_leaves.append(raw)
        report_value = json.loads((worker / 'report/manifest.json').read_bytes())
        for name, raw in zip(('policy', 'wire'), report_leaves):
            report_value[name + '_manifest_sha256'] = sha256(raw).hexdigest()
        report = run('report', 4, 0, report_leaves, encoded(report_value))
        wrapped_value = json.loads((worker / 'report.json').read_bytes())
        wrapped_value.update(helpers_bundle_sha256=sha256(helpers).hexdigest(),
                             report_bundle_sha256=sha256(report).hexdigest())
        wrapped = run('report-wrapper', 5, 0, [helpers, report], encoded(wrapped_value))

        if native_paths is None:
            source_pins = file_digests(root)
            source_pins[CONTRACT_PATH] = sha256((root / CONTRACT_PATH).read_bytes()).hexdigest()
        else:
            source_pins = json.loads(source_pin_file.read_bytes())
            if (type(source_pins) is not dict or set(source_pins) != set(native_paths)
                    or any(type(pin) is not str or len(pin) != 64 or pin != bytes.fromhex(pin).hex()
                           for pin in source_pins.values())):
                raise ValueError('captured native source pin inventory differs from its explicit authority')
        rows = sorted(source_pins.items())
        inventory = source_inventory(rows)
        record['source_inventory_rows'] = len(rows)
        record['source_inventory_sha256'] = sha256(inventory).hexdigest()
        policy_source, continuation = compile_image('examples/hia_bootstrap/continuation_policy.hepta')
        aggregate_manifests = []
        unit_role = 0
        for family_role, (kind, (module, _)) in enumerate(FAMILIES.items(), 1):
            selected = importlib.import_module('hepta.hia_' + module + '_selection')
            abi_raw = (root / selected.ABI_SOURCE).read_bytes()
            abi = selected.checked_abi(abi_raw)
            old_policy_path = worker / kind / 'policy/manifest.json'
            policy_value = json.loads(old_policy_path.read_bytes())
            unit_manifests = []
            unit_images = []
            for name in (module + '_pool', *abi['units']):
                unit_role += 1
                raw, image = leaf(6, unit_role, old_policy_path.parent / policy_value['unit_manifests'][name],
                                  'examples/hia_bootstrap/' + name + '.hepta')
                unit_manifests.append(raw)
                unit_images.append(image)
            policy_value.update(abi_sha256=sha256(abi_raw).hexdigest(),
                                compiler_sha256=sha256(compiler).hexdigest())
            policy = run('policy-' + kind, 7, family_role, [abi_raw, compiler, *unit_manifests],
                         encoded(policy_value))
            aggregate_path = worker / kind / 'inprocess-manifest.json'
            aggregate_value = json.loads(aggregate_path.read_bytes())
            image = (aggregate_path.parent / aggregate_value['image_path']).read_bytes()
            assert sha256(image).hexdigest() == aggregate_value['image_sha256']
            assert set(aggregate_value['resource_sha256']) == set(CONTINUATION_BUILD_FILES)
            aggregate_value.update(compiler_sha256=sha256(compiler).hexdigest(),
                                   policy_bundle_sha256=sha256(policy).hexdigest())
            for field in ('resource_sha256', 'runtime_sha256'):
                selected = CONTINUATION_RUNTIME if native_paths is not None and field == 'runtime_sha256' else aggregate_value[field]
                aggregate_value[field] = {name: source_pins[name] for name in selected}
            raw = run('aggregate-' + kind, 8, family_role, [policy, compiler, image, inventory],
                      encoded(aggregate_value))
            aggregate_manifests.append(raw)
            expected_frame = pack_input(continuation, unit_images[0], unit_images[1:], abi)
            run('pack-' + kind, 10, family_role, [abi_raw, continuation, *unit_images], expected_frame)
            save()
        assert unit_role == 72
        scheduled_value = json.loads((worker / 'schedulers.json').read_bytes())
        runtime_paths = (sorted('hepta/' + p.name for p in (root / 'hepta').glob('*.py')) if native_paths is None
                         else [p for p in native_paths if Path(p).suffix in SOURCE_SUFFIXES])
        scheduled_value['runtime_sha256'] = {name: source_pins[name] for name in runtime_paths}
        scheduled_value['base_bundle_sha256'] = sha256(wrapped).hexdigest()
        assert len(scheduled_value['schedulers']) == len(aggregate_manifests) == 5
        for row, kind, raw in zip(scheduled_value['schedulers'], FAMILIES, aggregate_manifests):
            assert row['kind'] == kind
            row['manifest_sha256'] = sha256(raw).hexdigest()
        run('schedulers', 9, 0, [wrapped, *aggregate_manifests, inventory], encoded(scheduled_value))
        assert len(record['positive']) == 134

        sample = frame(1, 1, [*cases[1, 1], table])
        for label, raw in [('magic', b'X' + sample[1:]), ('empty', b''), ('header-short', sample[:31]),
                           ('truncated', sample[:-1]), ('trailing', sample + b'x'),
                           ('count-zero', sample[:24] + struct.pack('<Q', 0) + sample[32:]),
                           ('count-overflow', sample[:24] + struct.pack('<Q', 65) + sample[32:]),
                           ('length-overflow', sample[:32] + b'\xff' * 8 + sample[40:])]:
            run('bad-' + label, 1, 1, [], raw=raw)
        run('missing-build-argv', 1, 1, cases[1, 1], argv=())
        run('extra-build-argv', 1, 1, cases[1, 1], argv=('build', 'extra'))
        run('unknown-mode', 11, 0, cases[1, 1])
        run('unknown-role', 1, 42, cases[1, 1])
        for mode, role in [(1, 1), (2, 0), (3, 1), (4, 0), (5, 0), (6, 1), (7, 1), (8, 1), (9, 0), (10, 1)]:
            pieces = cases[mode, role]
            run('missing-piece-%d' % mode, mode, role, pieces[:-1])
            run('extra-piece-%d' % mode, mode, role, [*pieces, b'extra'])
            wrong_table = bytearray(table)
            wrong_table[32 + mode] ^= 1
            run('table-pin-%d' % mode, mode, role, [], raw=frame(mode, role, [*pieces, bytes(wrong_table)]))
        for mode, role, child_index in [(2, 0, 1), (4, 0, 0), (5, 0, 0), (7, 1, 2), (8, 1, 0), (9, 0, 1)]:
            pieces = list(cases[mode, role])
            pieces[child_index] = pieces[child_index].replace(b'  "', b'   "', 1)
            run('child-canonical-%d' % mode, mode, role, pieces)
        for mode, role, child_index in [(2, 0, 2), (4, 0, 1), (7, 1, 2), (8, 1, 0), (9, 0, 2)]:
            pieces = list(cases[mode, role])
            child = json.loads(pieces[child_index])
            child['compiler_sha256'] = 'a' * 64
            pieces[child_index] = encoded(child)
            run('compiler-disagreement-%d' % mode, mode, role, pieces)
        for mode in (8, 9):
            role = 1 if mode == 8 else 0
            index = 3 if mode == 8 else 6
            needed = 'hepta/hia_native_helpers.py' if native_paths is None else CONTINUATION_RUNTIME[0]
            mutations = {
                'missing-source': [(n, p) for n, p in rows if n != needed],
                'duplicate-source': sorted([*rows, (needed, source_pins[needed])]),
                'unsorted-source': list(reversed(rows)),
                'parent-path': sorted([*rows, ('../escape', '0' * 64)]),
            }
            for label, changed in mutations.items():
                pieces = list(cases[mode, role]); pieces[index] = source_inventory(changed)
                run(label + '-' + str(mode), mode, role, pieces)
        pieces = list(cases[8, 1]); pieces[2] = b'X' + pieces[2][1:]
        run('aggregate-magic', 8, 1, pieces)
        pieces = list(cases[8, 1]); pieces[2] = pieces[2][:-1]
        run('aggregate-length', 8, 1, pieces)
        pieces = list(cases[7, 1]); pieces[0] = b'X' + pieces[0][1:]
        run('policy-abi-pin', 7, 1, pieces)
        pieces = list(cases[10, 1]); pieces[0] = b'X' + pieces[0][1:]
        run('pack-abi-pin', 10, 1, pieces)
        pieces = list(cases[1, 1]); pieces[0] = b'x' * ((1 << 20) + 1)
        run('source-over-budget', 1, 1, pieces)
        pieces = list(cases[1, 1]); pieces[1] = b''
        run('empty-image', 1, 1, pieces)
        after = {name: sha256(Path(name).read_bytes()).hexdigest() for name in pins_before}
        assert after == pins_before
        record.update(success=True, positive_count=len(record['positive']),
                      negative_count=len(record['negative']),
                      native_compile_count=len(record['native_compiles']),
                      pinned_inputs_unchanged=True, seconds=time.monotonic() - started)
        save()
        return record
    except BaseException:
        record.update(error=traceback.format_exc(), seconds=time.monotonic() - started)
        save()
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'worker', 'compiler', 'executable', 'source-builder', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('generated', 'native-source-authority', 'source-pins'):
        parser.add_argument('--' + name, type=Path)
    result = qualify(parser.parse_args())
    print(json.dumps({key: result[key] for key in ('success', 'positive_count', 'negative_count',
                                                 'native_compile_count', 'seconds')}, sort_keys=True))


if __name__ == '__main__':
    main()
