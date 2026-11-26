"""Execute the complete native-v2 cold admission contract and refusal domain.

This development fixture drives an actual native executable. Synthetic reports
exercise admission semantics only. --cold-report instead admits the exact
unchanged report and frozen source contract from a separately completed replay;
this program never runs that replay or promotes fixture data to whole-cold proof.
"""
from __future__ import annotations

import argparse
import copy
from hashlib import sha256
import json
from pathlib import Path
import struct
import subprocess
import time

from tools.generate_hia_cold_report_admit import CHECKS, FAMILIES, metadata, native_catalog
from tools.generate_hia_native_observer import reference_image
from tools.generate_hia_source_release_cold_admit import CONTRACT_PATH, _object

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = 'hepta.hia.selfhost-cold-replay.v2'
STATUS = 'NATIVE_COLD_SELFHOST_REPLAY_PASS'


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + '\n').encode()


def inventory_wire(pins):
    rows = sorted(pins.items())
    return b'HIASPI01' + struct.pack('<Q', len(rows)) + b''.join(
        struct.pack('<Q', len(name.encode('ascii'))) + bytes.fromhex(pin) + name.encode('ascii')
        for name, pin in rows)


def frame(cold, inventory, contract, compiler_pin):
    return b'HIACLD01' + struct.pack('<3Q', len(cold), len(inventory), len(contract)) + compiler_pin + cold + inventory + contract


def reverse(value):
    if isinstance(value, dict):
        return {key: reverse(value[key]) for key in reversed(value)}
    if isinstance(value, list):
        return [reverse(item) for item in value]
    return value


def integral_booleans(value):
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, dict):
        return {key: integral_booleans(item) for key, item in value.items()}
    if isinstance(value, list):
        return [integral_booleans(item) for item in value]
    return value


def change(path, value=None, *, remove=False):
    def edit(document):
        item = document
        for key in path[:-1]:
            item = item[key]
        if remove:
            del item[path[-1]]
        else:
            item[path[-1]] = value
    return edit


def fixture(contract, compiler_pin):
    catalog = contract['native_cold_qualification']['phase_plan_catalog']
    phases = []
    for row in sorted(catalog, key=lambda row: {'reference': 0, 'base': 1, 'qualification': 2}[row['kind']]):
        phases.append({**row, 'returncode': 0, 'nodes_retained': row['node_count'],
                       'cleanup_complete': True, 'sealed': True,
                       'journal_sha256': sha256(('fixture-journal-' + row['id']).encode()).hexdigest(),
                       'archive_sha256': sha256(('fixture-archive-' + row['id']).encode()).hexdigest()})
    first = sha256(b'explicit component fixture modified generation one').hexdigest()
    fixed = sha256(b'explicit component fixture modified generation fixed point').hexdigest()
    assert compiler_pin.hex() not in (first, fixed) and first != fixed
    return {'schema': SCHEMA, 'profile': contract['profile'], 'status': STATUS,
            'returncode': 0, 'checks': {name: True for name in CHECKS},
            'generation_sha256': [compiler_pin.hex()] * 3,
            'modified_generation_sha256': [first, fixed, fixed],
            'seed_sha256': sha256(b'explicit component fixture independent seed').hexdigest(),
            'qualification_wall_limit_seconds': 180, 'cleanup_wall_limit_seconds': 3,
            'nested_wall_elapsed_ns': 1, 'cleanup_wall_elapsed_ns': 0,
            'scheduler': {'phase_workers': 2, 'archive_workers': 1, 'max_pending_archives': 2,
                          'max_unsealed_phases': 4, 'peak_phase_workers': 2, 'peak_archive_workers': 1,
                          'peak_pending_archives': 2, 'peak_unsealed_phases': 4},
            'qualification_families': {family: {'original': True, 'modified': True} for family in FAMILIES},
            'phases': phases, 'native_flat_observer_hex': reference_image().hex()}


def cases(contract, report, compiler_pin, *, contract_raw=None, report_raw=None):
    files = contract['source_identity']['files']
    first_source = next(iter(files))
    output = []

    def add(name, accepted=False, *, edit=None, contract_edit=None, inventory_edit=None,
            cold_text=None, contract_text=None, raw_inventory=None, wire_edit=None, mirror=False):
        c = copy.deepcopy(contract)
        if contract_edit:
            contract_edit(c)
        cr = contract_raw if contract_raw is not None and contract_edit is None else encode(c)
        if contract_text:
            cr = contract_text(encode(c), c)
        pins = dict(c['source_identity']['files'] if mirror else files)
        pins[CONTRACT_PATH] = sha256(cr).hexdigest()
        q = copy.deepcopy(report)
        q['source_manifest'] = dict(pins)
        if edit:
            edit(q)
        qr = report_raw if report_raw is not None and q == report else encode(q)
        if cold_text:
            qr = cold_text(encode(q), q)
        if inventory_edit:
            inventory_edit(pins)
        ir = inventory_wire(pins)
        if raw_inventory:
            ir = raw_inventory(ir, pins)
        wire = frame(qr, ir, cr, compiler_pin)
        if wire_edit:
            wire = wire_edit(wire)
        output.append((name, wire, accepted))

    add('valid-current-v2', True)
    add('valid-reordered-json', True,
        cold_text=lambda raw, q: json.dumps(reverse(q), ensure_ascii=False, separators=(',', ':')).encode(),
        contract_text=lambda raw, c: json.dumps(reverse(c), ensure_ascii=False, separators=(',', ':')).encode())
    add('valid-escaped-keys', True,
        cold_text=lambda raw, q: raw.replace(b'"schema"', b'"\\u0073chema"'),
        contract_text=lambda raw, c: raw.replace(b'"source_identity"', b'"source_\\u0069dentity"'))
    add('valid-ascii-escapes', True,
        contract_text=lambda raw, c: json.dumps(c, ensure_ascii=True, sort_keys=True, separators=(',', ':')).encode())
    add('valid-extra-observations', True,
        edit=lambda q: q.update(extra={'unicode': '中文', 'nested': [None, True, False, -17], 'float': 1.25e-10}))
    add('valid-contract-boolean-numeric-equality', True,
        contract_text=lambda raw, c: encode(integral_booleans(c)))
    add('valid-original-wall-limits', True,
        edit=lambda q: q.update(nested_wall_elapsed_ns=180000000000, cleanup_wall_elapsed_ns=3000000000))
    add('valid-minimum-peak-counts', True,
        edit=lambda q: q['scheduler'].update(peak_phase_workers=1, peak_archive_workers=1,
                                            peak_pending_archives=0, peak_unsealed_phases=1))

    for key, bad in (('schema', 'hepta.hia.selfhost-cold-replay.v1'),
                     ('status', 'COLD_SELFHOST_REPLAY_PASS'), ('profile', 'foreign-profile'),
                     ('returncode', 1), ('returncode', False), ('returncode', 0.0)):
        add('invalid-' + key + '-' + str(bad), edit=change((key,), bad))
    add('legacy-hosted-checks-refused', edit=lambda q: q['checks'].update(isolated_python_without_site=True))
    add('missing-native-observer', edit=change(('native_flat_observer_hex',), remove=True))
    add('wrong-native-observer', edit=change(('native_flat_observer_hex',), '00' * len(reference_image())))
    add('truncated-native-observer', edit=change(('native_flat_observer_hex',), reference_image().hex()[:-2]))
    add('noncanonical-native-observer', edit=change(('native_flat_observer_hex',), reference_image().hex().upper()))
    for name in CHECKS:
        for label, value in (('false', False), ('numeric', 1)):
            add('check-' + name + '-' + label, edit=change(('checks', name), value))
        add('check-' + name + '-missing', edit=change(('checks', name), remove=True))
    add('extra-check-refused', edit=lambda q: q['checks'].update(unrelated=True))
    add('duplicate-root-key', cold_text=lambda raw, q: b'{"returncode":0,' + raw.lstrip()[1:])
    add('duplicate-check-key', cold_text=lambda raw, q:
        raw.replace(b'"checks": {', b'"checks": {"native_hia_toolchain_only":true,', 1))
    for name in ('generation_sha256', 'modified_generation_sha256'):
        for count in (0, 2, 4):
            add(name + '-count-' + str(count), edit=change((name,), (report[name] * 2)[:count]))
        add(name + '-zero-pin', edit=change((name, 1), '0' * 64))
        add(name + '-invalid-pin', edit=change((name, 1), 'g' * 64))
    add('wrong-current-compiler-generation', edit=change(('generation_sha256', 2), '1' * 64))
    add('modified-initial-already-fixed', edit=change(('modified_generation_sha256', 0), report['modified_generation_sha256'][1]))
    add('modified-not-fixed', edit=change(('modified_generation_sha256', 2), report['modified_generation_sha256'][0]))
    add('modified-equals-original', edit=change(('modified_generation_sha256',),
        [report['modified_generation_sha256'][0], compiler_pin.hex(), compiler_pin.hex()]))
    for bad in ('0' * 64, 'a' * 63, 'A' * 64, 'g' * 64):
        add('invalid-seed-pin-' + bad[0] + '-' + str(len(bad)), edit=change(('seed_sha256',), bad))

    for key, low, high in (('qualification_wall_limit_seconds', 180, 180),
                           ('cleanup_wall_limit_seconds', 3, 3),
                           ('nested_wall_elapsed_ns', 1, 180000000000),
                           ('cleanup_wall_elapsed_ns', 0, 3000000000)):
        for label, value in (('below', low - 1), ('above', high + 1), ('bool', True), ('float', float(low))):
            add(key + '-' + label, edit=change((key,), value))
        add(key + '-missing', edit=change((key,), remove=True))
    scheduler = {'phase_workers': (2, 2), 'archive_workers': (1, 1),
                 'max_pending_archives': (2, 2), 'max_unsealed_phases': (4, 4),
                 'peak_phase_workers': (1, 2), 'peak_archive_workers': (1, 1),
                 'peak_pending_archives': (0, 2), 'peak_unsealed_phases': (1, 4)}
    for key, (low, high) in scheduler.items():
        for label, value in (('below', low - 1), ('above', high + 1), ('bool', True), ('float', float(low))):
            add('scheduler-' + key + '-' + label, edit=change(('scheduler', key), value))
        add('scheduler-' + key + '-missing', edit=change(('scheduler', key), remove=True))
    add('scheduler-extra-field', edit=lambda q: q['scheduler'].update(unrelated=0))
    add('scheduler-duplicate-field', cold_text=lambda raw, q:
        raw.replace(b'"scheduler": {', b'"scheduler": {"phase_workers":2,', 1))

    for family in FAMILIES:
        add('family-' + family + '-missing', edit=change(('qualification_families', family), remove=True))
        add('family-' + family + '-extra-field',
            edit=lambda q, family=family: q['qualification_families'][family].update(unrelated=True))
        for variant in ('original', 'modified'):
            for label, value in (('false', False), ('numeric', 1)):
                add('family-' + family + '-' + variant + '-' + label,
                    edit=change(('qualification_families', family, variant), value))
            add('family-' + family + '-' + variant + '-missing',
                edit=change(('qualification_families', family, variant), remove=True))
    add('extra-family', edit=lambda q: q['qualification_families'].update(unrelated={'original': True, 'modified': True}))
    add('duplicate-family', cold_text=lambda raw, q:
        raw.replace(b'"qualification_families": {', b'"qualification_families": {"capacity":{"original":true,"modified":true},', 1))

    for index, row in enumerate(report['phases']):
        identity = row['id']
        add('phase-' + identity + '-missing', edit=change(('phases', index), remove=True))
        for key, bad in (('plan_sha256', '0' * 64), ('node_count', row['node_count'] + 1),
                         ('nodes_retained', row['node_count'] - 1), ('returncode', 1),
                         ('cleanup_complete', False), ('sealed', False),
                         ('journal_sha256', '0' * 64), ('archive_sha256', '0' * 64),
                         ('kind', 'unknown'), ('family', 'unknown'), ('label', 'unknown')):
            add('phase-' + identity + '-' + key, edit=change(('phases', index, key), bad))
    add('duplicate-phase-id', edit=lambda q: q['phases'].__setitem__(1, copy.deepcopy(q['phases'][0])))
    add('unknown-phase-id', edit=change(('phases', 0, 'id'), 'foreign-phase'))
    add('extra-phase', edit=lambda q: q['phases'].append(copy.deepcopy(q['phases'][0])))
    reference_index = next(i for i, row in enumerate(report['phases']) if row['kind'] == 'reference')
    base_index = next(i for i, row in enumerate(report['phases']) if row['kind'] == 'base')
    qualification_index = next(i for i, row in enumerate(report['phases']) if row['kind'] == 'qualification')
    def swap(first, second):
        def edit(q):
            q['phases'][first], q['phases'][second] = q['phases'][second], q['phases'][first]
        return edit
    add('reference-after-base', edit=swap(reference_index, base_index))
    add('qualification-before-base', edit=swap(base_index, qualification_index))
    add('phase-duplicate-key', cold_text=lambda raw, q:
        raw.replace(b'"phases": [\n    {', b'"phases": [\n    {"sealed":true,', 1))

    add('missing-report-source', edit=change(('source_manifest', first_source), remove=True))
    add('extra-report-source', edit=lambda q: q['source_manifest'].update(unrelated='1' * 64))
    add('wrong-report-source-pin', edit=change(('source_manifest', first_source), '0' * 64))
    add('missing-inventory-source', inventory_edit=change((first_source,), remove=True))
    add('missing-inventory-contract', inventory_edit=change((CONTRACT_PATH,), remove=True))
    add('extra-inventory-source', inventory_edit=lambda pins: pins.update(unrelated='1' * 64))
    add('wrong-inventory-source-pin', inventory_edit=change((first_source,), '0' * 64))
    add('wrong-inventory-contract-pin', inventory_edit=change((CONTRACT_PATH,), '0' * 64))
    add('inventory-count-zero', raw_inventory=lambda raw, pins: raw[:8] + bytes(8) + raw[16:])
    add('inventory-count-over-bound', raw_inventory=lambda raw, pins: raw[:8] + struct.pack('<Q', 4097) + raw[16:])
    add('inventory-unsorted', raw_inventory=lambda raw, pins: b'HIASPI01' + struct.pack('<Q', len(pins)) + b''.join(
        struct.pack('<Q', len(name)) + bytes.fromhex(pin) + name.encode('ascii')
        for name, pin in reversed(sorted(pins.items()))))
    add('duplicate-report-source', cold_text=lambda raw, q: raw.replace(b'"source_manifest": {',
        b'"source_manifest": {' + json.dumps(first_source).encode() + b':' + json.dumps(files[first_source]).encode() + b',', 1))
    add('wrong-contract-metadata', contract_edit=lambda c: c.update(profile='foreign-profile'))
    add('extra-contract-metadata', contract_edit=lambda c: c.update(unrelated='foreign-metadata'))
    add('wrong-contract-source-pin', contract_edit=change(('source_identity', 'files', first_source), '0' * 64))
    add('coherently-truncated-path-set', contract_edit=change(('source_identity', 'files', first_source), remove=True), mirror=True)
    add('coherently-expanded-path-set', contract_edit=lambda c: c['source_identity']['files'].update(unrelated='1' * 64), mirror=True)
    add('duplicate-contract-source', contract_text=lambda raw, c: raw.replace(b'"files": {',
        b'"files": {' + json.dumps(first_source).encode() + b':' + json.dumps(files[first_source]).encode() + b',', 1))
    add('wrong-contract-plan', contract_edit=change(('native_cold_qualification', 'phase_plan_catalog', 0, 'plan_sha256'), '0' * 64))
    add('wrong-contract-budget', contract_edit=change(('native_cold_qualification', 'qualification_wall_limit_seconds'), 181))
    add('wrong-frame-magic', wire_edit=lambda raw: b'BADCLD01' + raw[8:])
    add('wrong-compiler-pin', wire_edit=lambda raw: raw[:32] + bytes(32) + raw[64:])
    add('zero-cold-extent', wire_edit=lambda raw: raw[:8] + bytes(8) + raw[16:])
    add('truncated-frame', wire_edit=lambda raw: raw[:-1])
    add('trailing-frame', wire_edit=lambda raw: raw + b'x')
    add('invalid-cold-json', cold_text=lambda raw, q: raw + b'null')
    add('cold-root-array', cold_text=lambda raw, q: b'[]')
    add('invalid-contract-json', contract_text=lambda raw, c: raw + b'null')
    add('contract-root-array', contract_text=lambda raw, c: b'[]')
    assert len({name for name, _, _ in output}) == len(output)
    return output


def qualify(args):
    root = args.contract_root.resolve(strict=True)
    authority = args.native_source_authority.resolve(strict=True)
    authority_raw = authority.read_bytes()
    catalog = native_catalog(root, authority)
    contract = metadata(root, catalog, native_source_authority=authority)
    image = args.image.resolve(strict=True)
    image_raw = image.read_bytes()
    compiler = args.compiler.resolve(strict=True)
    compiler_raw = compiler.read_bytes()
    compiler_pin = sha256(compiler_raw).digest()
    report_raw = contract_raw = None
    if args.cold_report is not None:
        report_raw = args.cold_report.read_bytes()
        report = json.loads(report_raw, object_pairs_hook=_object)
        contract_raw = (root / CONTRACT_PATH).read_bytes()
        actual_contract = json.loads(contract_raw, object_pairs_hook=_object)
        if actual_contract != contract:
            raise ValueError('actual cold admission requires the exact frozen current source contract')
        pins = {**contract['source_identity']['files'], CONTRACT_PATH: sha256(contract_raw).hexdigest()}
        if type(report) is not dict or report.get('source_manifest') != pins:
            raise ValueError('actual cold report does not bind the exact current source inventory')
    else:
        report = fixture(contract, compiler_pin)
    output = args.output.resolve()
    output.mkdir(mode=0o700)
    record = {'schema': 'hepta.hia.native-v2-cold-admission-qualification.v1',
              'scope': 'actual native admission semantics and complete positive/refusal fixtures',
              'input_kind': 'actual-unchanged-cold-report' if report_raw is not None else 'synthetic-component-fixture',
              'passed': False, 'whole_cold_passed': False, 'whole_native_delivery_qualified': False,
              'actual_cold_report_admitted': False, 'source_catalog': 'explicit-native-authority',
              'native_source_authority_sha256': sha256(authority_raw).hexdigest(),
              'image_sha256': sha256(image_raw).hexdigest(), 'compiler_sha256': compiler_pin.hex(),
              'source_count': len(contract['source_identity']['files']) + 1,
              'phase_count': len(catalog), 'qualification_families': len(FAMILIES), 'native_checks': len(CHECKS),
              'original_qualification_limit_seconds': 180, 'original_cleanup_limit_seconds': 3,
              'cases': []}
    if report_raw is not None:
        record['actual_cold_report_sha256'] = sha256(report_raw).hexdigest()
        record['actual_contract_sha256'] = sha256(contract_raw).hexdigest()
        (output / 'actual-cold-report.json').write_bytes(report_raw)
        (output / 'actual-contract.json').write_bytes(contract_raw)
    else:
        (output / 'fixture-contract.json').write_bytes(encode(contract))
    def save():
        (output / 'results.json').write_text(json.dumps(record, indent=2) + '\n')
    save()
    all_cases = cases(contract, report, compiler_pin, contract_raw=contract_raw, report_raw=report_raw)
    receipt = b'HIAADC01' + compiler_pin + struct.pack('<Q', record['source_count'])
    try:
        for index, (name, wire, expected) in enumerate(all_cases):
            started = time.monotonic()
            process = subprocess.run([str(image), 'build'], input=wire, capture_output=True,
                                     env={'PATH': ''}, timeout=30)
            accepted = process.returncode == 0 and process.stdout == receipt and not process.stderr
            passed = accepted if expected else process.returncode == 16 and not process.stdout and not process.stderr
            item = {'case': name, 'expected_accept': expected, 'passed': passed,
                    'returncode': process.returncode, 'stdout_hex': process.stdout.hex(),
                    'stderr': process.stderr.decode(errors='replace'),
                    'request_sha256': sha256(wire).hexdigest(), 'seconds': time.monotonic() - started}
            record['cases'].append(item)
            if index == 0:
                (output / 'baseline-request.bin').write_bytes(wire)
                (output / 'baseline-receipt.bin').write_bytes(process.stdout)
            if not passed:
                (output / 'failed-request.bin').write_bytes(wire)
                save()
                raise AssertionError(item)
            if index % 25 == 0:
                save()
                print(json.dumps({'completed': index + 1, 'total': len(all_cases), 'last_case': name}), flush=True)
        if image.read_bytes() != image_raw or compiler.read_bytes() != compiler_raw or authority.read_bytes() != authority_raw:
            raise ValueError('admission executable, compiler or native authority changed during qualification')
        if report_raw is not None:
            if args.cold_report.read_bytes() != report_raw or (root / CONTRACT_PATH).read_bytes() != contract_raw:
                raise ValueError('actual cold report or frozen contract changed during qualification')
            if metadata(root, catalog, native_source_authority=authority) != contract:
                raise ValueError('actual frozen source bytes changed during admission qualification')
            record['actual_cold_report_admitted'] = True
        record.update(passed=True, case_count=len(all_cases))
    finally:
        save()
    print(json.dumps({key: value for key, value in record.items() if key != 'cases'}, sort_keys=True), flush=True)
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--compiler', type=Path, required=True)
    parser.add_argument('--native-source-authority', type=Path, required=True)
    parser.add_argument('--contract-root', type=Path, default=ROOT)
    parser.add_argument('--output', type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--fixture', action='store_true', help='component-only synthetic report; never whole-cold evidence')
    mode.add_argument('--cold-report', type=Path, help='exact unchanged current-source report from a separate complete replay')
    qualify(parser.parse_args())


if __name__ == '__main__':
    main()
