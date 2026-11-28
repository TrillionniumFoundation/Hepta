"""Qualify all protocol-03 Worker records against an actual native installation.

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
    return b'HIAWMF03' + struct.pack('<3Q', mode, role, len(pieces)) + b''.join(
        struct.pack('<Q', len(raw)) + raw for raw in pieces)


def source_inventory(rows):
    return b'HIASPI01' + struct.pack('<Q', len(rows)) + b''.join(
        struct.pack('<Q', len(name.encode('ascii'))) + bytes.fromhex(pin) + name.encode('ascii')
        for name, pin in rows)


def check_original_aggregate(value, *, policy, image, compiler, schema,
                             resource_pins, runtime_pins):
    """Reject rebinding an independently installed aggregate to new inputs."""
    wanted = {
        'schema': schema,
        'policy_bundle_sha256': sha256(policy).hexdigest(),
        'image_sha256': sha256(image).hexdigest(),
        'compiler_sha256': sha256(compiler).hexdigest(),
        'resource_sha256': resource_pins,
        'runtime_sha256': runtime_pins,
    }
    if type(value) is not dict or any(value.get(k) != v for k,v in wanted.items()):
        raise ValueError('independent installed aggregate binding differs')


def qualify(args):
    root = args.source.resolve(strict=True)
    worker = args.worker.resolve(strict=True)
    output = args.output.absolute()
    output.mkdir(mode=0o700)
    sys.path.insert(0, str(root))
    from tools.build_hia_worker_release import (INSTALLED_HELPERS, ADDITIONAL_HELPERS,
                                               EXTENDED_INSTALLED_HELPERS, CURRENT_INSTALLED_HELPERS, AGENT_INSTALLED_HELPERS)
    from tools.build_hia_json_preflight import CANDIDATES
    from tools.build_hia_worker_report import SOURCES as REPORT_SOURCES
    from tools.build_hia_native_continuation import pack_input
    from hepta.hia_worker_scheduling_bundle import FAMILIES
    from hepta.hia_native_continuation_selection import resource_names
    from tools.hia_selfhost_contract import file_digests, CONTRACT_PATH

    captured = {}
    def read(path):
        path = Path(path).resolve(strict=True)
        raw = path.read_bytes()
        pin = (len(raw), sha256(raw).hexdigest())
        name = str(path)
        if name in captured and captured[name] != pin:
            raise ValueError("qualification input changed: " + name)
        captured[name] = pin
        return raw

    compiler = read(args.compiler)
    generated = args.generated.resolve(strict=True) if getattr(args, 'generated', None) else root
    native_authority = getattr(args, 'native_source_authority', None)
    source_pin_file = getattr(args, 'source_pins', None)
    if native_authority is None or source_pin_file is None:
        raise ValueError('protocol 03 requires explicit native source authority and independent captured source pins')
    native_paths = None
    if native_authority:
        from tools.hia_native_worker_source_authority import (parse_native_source_authority,
            CONTINUATION_RUNTIME, CONTINUATION_RUNTIME_V2, SOURCE_SUFFIXES)
        native_paths = parse_native_source_authority(read(native_authority))
    table = read(generated / 'examples/hia_bootstrap/worker_manifest_default_tables.hiastd')
    elf = args.executable.resolve(strict=True)
    builder = args.source_builder.resolve(strict=True)
    pins_before = {str(p): sha256(read(p)).hexdigest() for p in (elf, builder, args.compiler,
        generated / 'examples/hia_bootstrap/source_worker_manifest_default.hepta',
        generated / 'examples/hia_bootstrap/worker_manifest_default_tables.hiastd')}
    if native_authority:
        pins_before.update({str(p): sha256(read(p)).hexdigest() for p in (native_authority, source_pin_file)})
    record = dict(schema='hepta.hia.default-worker-manifest-qualification.v1',
        scope='All protocol-03 native records against an independently installed complete Worker; public runtime remains a separate gate',
        source_root=str(root), worker_format_authority=str(worker),
        executable_sha256=pins_before[str(elf)], compiler_sha256=sha256(compiler).hexdigest(),
        source_builder_sha256=pins_before[str(builder)], table_sha256=sha256(table).hexdigest(),
        positive=[], negative=[], native_compiles=[], success=False)
    started = time.monotonic()
    images = {}
    cases = {}
    outputs = {}
    source_pins = json.loads(read(source_pin_file))
    if (type(source_pins) is not dict or set(source_pins) != set(native_paths)
            or any(type(pin) is not str or len(pin) != 64 or pin != bytes.fromhex(pin).hex()
                   for pin in source_pins.values())):
        raise ValueError('captured native source pin inventory differs from its explicit authority')
    read(native_authority)
    for name in native_paths:
        if sha256(read(root / name)).hexdigest() != source_pins[name]:
            raise ValueError('physical source differs from independent native source capture: ' + name)
    record['native_source_paths'] = len(native_paths)
    record['fixed_protocol'] = '03'

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
        source = read(root / relative)
        source_pin = sha256(source).hexdigest()
        if source_pins.get(relative) != source_pin:
            raise ValueError('compiled source is outside the captured native authority: ' + relative)
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
        if old_source_pin is not None:
            if old_source_pin != source_pin or image != old_image:
                raise AssertionError('current source/image differs from independent installed image: ' + relative)
        return source, image

    def leaf(mode, role, manifest_path, source_path):
        raw = read(manifest_path)
        value = json.loads(raw)
        assert set(value) == {'schema', 'source_sha256', 'image_path', 'image_sha256', 'compiler_sha256'}
        if value['compiler_sha256'] != sha256(compiler).hexdigest():
            raise ValueError('installed image compiler differs from current qualification compiler')
        old_image = read(manifest_path.parent / value['image_path'])
        assert sha256(old_image).hexdigest() == value['image_sha256']
        source, image = compile_image(source_path, old_image, value['source_sha256'])
        expected = dict(value, source_sha256=sha256(source).hexdigest(),
                        image_sha256=sha256(image).hexdigest(), compiler_sha256=sha256(compiler).hexdigest())
        return run('leaf-%d-%d' % (mode, role), mode, role, [source, image, compiler], encoded(expected)), image

    try:
        original_helpers = json.loads(read(worker / 'helpers.json'))
        original_names = (*INSTALLED_HELPERS, *ADDITIONAL_HELPERS)
        assert len(original_names) == 37
        names = (*original_names, *(name for _, name in EXTENDED_INSTALLED_HELPERS),
                 *(name for _, name in AGENT_INSTALLED_HELPERS))
        installed_names = (*CURRENT_INSTALLED_HELPERS, *(name for _, name in AGENT_INSTALLED_HELPERS))
        assert len(names) == 45 and len(set(names)) == 45
        assert len(original_helpers['helpers']) == len(names)
        helper_manifests = []
        new_helpers = copy.deepcopy(original_helpers)
        package_pins = set()
        for role, (name, old_row, row) in enumerate(zip(names, original_helpers['helpers'],
                                                        new_helpers['helpers']), 1):
            assert old_row['selector'] == 'HEPTA_HIA_' + name.replace('-', '_').upper() + '_MANIFEST'
            if name in installed_names:
                package_pins.add(Path(old_row['manifest_path']).parts[1])
            source_name = CANDIDATES.get(name, (name.replace('-', '_'), name))[0]
            raw, _ = leaf(1, role, worker / old_row['manifest_path'],
                          'examples/hia_bootstrap/' + source_name + '.hepta')
            helper_manifests.append(raw)
            if old_row['manifest_sha256'] != sha256(raw).hexdigest():
                raise ValueError('installed helper child pin differs')
            row['manifest_sha256'] = sha256(raw).hexdigest()
        assert len(package_pins) == 1
        package_pin = next(iter(package_pins))
        helpers = run('helpers', 2, 0, [bytes.fromhex(package_pin), *helper_manifests], encoded(new_helpers))

        report_leaves = []
        for role, name in enumerate(('policy', 'wire'), 1):
            raw, _ = leaf(3, role, worker / 'report' / name / 'manifest.json', REPORT_SOURCES[name])
            report_leaves.append(raw)
        report_value = json.loads(read(worker / 'report/manifest.json'))
        for name, raw in zip(('policy', 'wire'), report_leaves):
            if report_value[name + '_manifest_sha256'] != sha256(raw).hexdigest():
                raise ValueError('installed report child pin differs')
            report_value[name + '_manifest_sha256'] = sha256(raw).hexdigest()
        report = run('report', 4, 0, report_leaves, encoded(report_value))
        wrapped_value = json.loads(read(worker / 'report.json'))
        if (wrapped_value['helpers_bundle_sha256'] != sha256(helpers).hexdigest()
                or wrapped_value['report_bundle_sha256'] != sha256(report).hexdigest()):
            raise ValueError('installed report wrapper pin differs')
        wrapped_value.update(helpers_bundle_sha256=sha256(helpers).hexdigest(),
                             report_bundle_sha256=sha256(report).hexdigest())
        wrapped = run('report-wrapper', 5, 0, [helpers, report], encoded(wrapped_value))

        # The full physical native inventory was captured before the first
        # native call. No hosted-source fallback or projected pin map is used.
        rows = sorted(source_pins.items())
        inventory = source_inventory(rows)
        record['source_inventory_rows'] = len(rows)
        record['source_inventory_sha256'] = sha256(inventory).hexdigest()
        _, continuation_v1 = compile_image('examples/hia_bootstrap/continuation_policy.hepta')
        _, continuation_v2 = compile_image('examples/hia_bootstrap/continuation_policy_v2.hepta')
        aggregate_manifests = []
        unit_role = 0
        for family_role, (kind, (module, _)) in enumerate(FAMILIES.items(), 1):
            selected = importlib.import_module('hepta.hia_' + module + '_selection')
            core_v2 = kind == 'core-lowering'
            abi_path = selected.ABI_SOURCE_V2 if core_v2 else selected.ABI_SOURCE
            abi_raw = read(root / abi_path)
            abi = selected.checked_abi_v2(abi_raw) if core_v2 else selected.checked_abi(abi_raw)
            continuation = continuation_v2 if core_v2 else continuation_v1
            expected_resources = resource_names(kind, core_v2=core_v2)
            expected_runtime = (CONTINUATION_RUNTIME + CONTINUATION_RUNTIME_V2
                                if core_v2 else CONTINUATION_RUNTIME)
            old_policy_path = worker / kind / 'policy/manifest.json'
            policy_value = json.loads(read(old_policy_path))
            unit_manifests = []
            unit_images = []
            for name in (('core_lowering_v2_pool' if core_v2 else module + '_pool'), *abi['units']):
                unit_role += 1
                raw, image = leaf(6, unit_role, old_policy_path.parent / policy_value['unit_manifests'][name],
                                  'examples/hia_bootstrap/' + name + '.hepta')
                unit_manifests.append(raw)
                unit_images.append(image)
            if (policy_value['abi_sha256'] != sha256(abi_raw).hexdigest()
                    or policy_value['compiler_sha256'] != sha256(compiler).hexdigest()):
                raise ValueError('installed family policy source/compiler differs')
            policy_value.update(abi_sha256=sha256(abi_raw).hexdigest(),
                                compiler_sha256=sha256(compiler).hexdigest())
            policy = run('policy-' + kind, 7, family_role, [abi_raw, compiler, *unit_manifests],
                         encoded(policy_value))
            aggregate_path = worker / kind / 'inprocess-manifest.json'
            aggregate_value = json.loads(read(aggregate_path))
            image = read(aggregate_path.parent / aggregate_value['image_path'])
            assert sha256(image).hexdigest() == aggregate_value['image_sha256']
            assert set(aggregate_value['resource_sha256']) == set(expected_resources)
            assert set(aggregate_value['runtime_sha256']) == set(expected_runtime)
            assert aggregate_value['schema'] == ('hepta.hia.native-continuation-inprocess.v2'
                                                  if core_v2 else 'hepta.hia.native-continuation-inprocess.v1')
            check_original_aggregate(
                aggregate_value, policy=policy, image=image, compiler=compiler,
                schema='hepta.hia.native-continuation-inprocess.v2' if core_v2 else 'hepta.hia.native-continuation-inprocess.v1',
                resource_pins={name:source_pins[name] for name in expected_resources},
                runtime_pins={name:source_pins[name] for name in expected_runtime})
            aggregate_value.update(compiler_sha256=sha256(compiler).hexdigest(),
                                   policy_bundle_sha256=sha256(policy).hexdigest())
            for field in ('resource_sha256', 'runtime_sha256'):
                selected = expected_runtime if field == 'runtime_sha256' else expected_resources
                aggregate_value[field] = {name: source_pins[name] for name in selected}
            raw = run('aggregate-' + kind, 8, family_role, [policy, compiler, image, inventory],
                      encoded(aggregate_value))
            aggregate_manifests.append(raw)
            expected_frame = pack_input(continuation, unit_images[0], unit_images[1:], abi)
            run('pack-' + kind, 10, family_role, [abi_raw, continuation, *unit_images], expected_frame)
            save()
        assert unit_role == 79
        scheduled_value = json.loads(read(worker / 'schedulers.json'))
        runtime_paths = [p for p in native_paths if Path(p).suffix in SOURCE_SUFFIXES]
        assert set(scheduled_value['runtime_sha256']) == set(runtime_paths)
        expected_runtime_pins = {name:source_pins[name] for name in runtime_paths}
        if (scheduled_value['runtime_sha256'] != expected_runtime_pins
                or scheduled_value['base_bundle_sha256'] != sha256(wrapped).hexdigest()):
            raise ValueError('installed scheduler root source/profile differs')
        scheduled_value['runtime_sha256'] = expected_runtime_pins
        scheduled_value['base_bundle_sha256'] = sha256(wrapped).hexdigest()
        assert len(scheduled_value['schedulers']) == len(aggregate_manifests) == 5
        for row, kind, raw in zip(scheduled_value['schedulers'], FAMILIES, aggregate_manifests):
            assert row['kind'] == kind
            if row['manifest_sha256'] != sha256(raw).hexdigest():
                raise ValueError('installed scheduler child pin differs')
            row['manifest_sha256'] = sha256(raw).hexdigest()
        run('schedulers', 9, 0, [wrapped, *aggregate_manifests, inventory], encoded(scheduled_value))
        assert len(record['positive']) == 145

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
        run('unknown-role', 1, 46, cases[1, 1])
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
            needed = CONTINUATION_RUNTIME[0]
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
        # Retain the entire original refusal matrix above, then add explicit
        # cross-version and Core-v2 source-domain negatives.
        for prior in (b'HIAWMF01', b'HIAWMF02'):
            run('cross-protocol-' + prior.decode(), 1, 1, [], raw=prior + sample[8:])
        core_role = tuple(FAMILIES).index('core-lowering') + 1
        for name in CONTINUATION_RUNTIME_V2:
            pieces = list(cases[8, core_role])
            pieces[3] = source_inventory([(n,p) for n,p in rows if n != name])
            run('core-v2-missing-' + Path(name).stem, 8, core_role, pieces)
        pieces = list(cases[10, core_role])
        run('core-v2-v1-unit-count', 10, core_role, pieces[:-7])
        for name, expected in captured.items():
            raw = Path(name).read_bytes()
            if (len(raw),sha256(raw).hexdigest()) != expected:
                raise ValueError('qualification input changed at terminal readback: ' + name)
        record['complete_captured_inputs'] = {
            name: dict(bytes=pin[0],sha256=pin[1]) for name,pin in sorted(captured.items())}
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
