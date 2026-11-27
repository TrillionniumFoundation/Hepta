"""Build a real wheel and run the separate explicit-v5 installed control.

All six original Native methods and their v1 bundle remain mandatory; their
worker terminal expectation is bound to an exact, independently retained source.
This driver gives the new ABI its own wheel, administrator digest, raw command
records and complete original worker/journal scenarios.
"""
from __future__ import annotations
import argparse
import ast
import base64
import csv
from hashlib import sha256
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import sys
import zipfile
ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ''):
    sys.path.insert(0, str(ROOT))
from tests.hia_slot_operations_qualification_support import (
    canonical, clean_environment, regular_bytes, pin, run_owned,
    successful_exit, write_json, admit_product)
from tools.build_hia_slot_mechanical_bundle import create


def additional_package_resources(root):
    """Read the package's explicit extra tuples without importing setup.py.

    These are source inputs to the current wheel, separate from the unchanged
    Agent installation_manifest catalogue and original worker scenarios.
    """
    declarations = {
        'hepta/hia_executable_capture.py': ('PACKAGE_RESOURCES',),
        'hepta/hia_nominal_program_native.py': ('PACKAGE_RESOURCES',),
        'setup.py': ('VM_INTEGER_DIVREM_RESOURCES', 'VM_INTEGER_ARITHMETIC_RESOURCES',
                     'VM_INTEGER_SCALAR_RESOURCES', 'NOMINAL_BYTE_BOUNDARY_RESOURCES'),
    }
    names, inputs = [], {}
    for path, symbols in declarations.items():
        raw = regular_bytes(root / path)
        inputs[path] = {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}
        tree = ast.parse(raw, filename=path)
        for symbol in symbols:
            rows = [node for node in tree.body if isinstance(node, ast.Assign)
                    and any(isinstance(target, ast.Name) and target.id == symbol
                            for target in node.targets)]
            if len(rows) != 1:
                raise ValueError('one explicit extra package resource tuple required: ' + symbol)
            values = ast.literal_eval(rows[0].value)
            if (type(values) is not tuple or len(values) != len(set(values))
                    or any(type(name) is not str or not name
                           or PurePosixPath(name).is_absolute()
                           or any(part in ('', '.', '..') for part in name.split('/'))
                           for name in values)):
                raise ValueError('invalid explicit extra package resource tuple: ' + symbol)
            names.extend(values)
    if len(names) != len(set(names)):
        raise ValueError('duplicate extra package resource')
    return tuple(names), inputs


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('controller', 'decision', 'product-freeze', 'evidence'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--product-freeze-sha256', required=True)
    args = parser.parse_args()
    before = admit_product(ROOT, args.product_freeze, args.product_freeze_sha256)
    from tests.hia_slot_worker_terminal import SourceAuthority
    authority = SourceAuthority(ROOT)
    args.evidence.mkdir(mode=0o700, parents=True, exist_ok=False)
    environment = clean_environment()
    environment['PYTHONDONTWRITEBYTECODE'] = '1'
    commands = []
    def run(label, command, seconds=60, *, cwd=ROOT):
        result = run_owned(command, cwd=cwd, directory=args.evidence / label,
                           timeout_seconds=seconds, environment=environment)
        commands.append({'label': label, 'result': result})
        if not successful_exit(result):
            raise AssertionError('v5 installed child did not naturally succeed: ' + label)
        return result
    # The original identity catalogue is unchanged. Current setup.py also has
    # explicit package data, which must reach staging before a real wheel build.
    from tests.test_hia_agent_installed_resources import RESOURCES, SDIST_SUPPORT_FILES
    from hepta.hia_agent_contract import installation_manifest
    source_identity = installation_manifest()
    if 'native_helpers_sha256' in source_identity:
        raise ValueError('installed driver must start outside any selected worker scope')
    extra_resources, declarations = additional_package_resources(ROOT)
    extra_pins = {name: pin(ROOT / name) for name in extra_resources}
    staging = args.evidence / 'source'
    staging.mkdir()
    shutil.copytree(ROOT / 'hepta', staging / 'hepta', ignore=shutil.ignore_patterns('__pycache__'))
    for name in (*RESOURCES, *SDIST_SUPPORT_FILES, *extra_resources,
                 'setup.py', 'pyproject.toml', 'MANIFEST.in'):
        target = staging / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, target)
    started = {'schema': 'hepta.slot.mechanical.installed-driver.v2',
        'package_resource_declarations': declarations, 'extra_package_resources': extra_pins,
        'terminal_source_authority': authority.summary(),
        'product_freeze': pin(args.product_freeze), 'source_before': before,
        'original_scope_replaced': False, 'new_version': 5,
               'wheel_profile': 'explicit-slot-mechanical-cpython-extension', 'source_identity': source_identity}
    write_json(args.evidence / 'started.json', started)
    failure = None
    try:
        # This fixture exercises the separately selected CPython mechanical extension.
        # Build the same Python import-library component used by the release builder.
        wheels = args.evidence / 'wheels'
        wheels.mkdir()
        run('wheel', [sys.executable, '-B', '-c',
                      'from setuptools.build_meta import build_wheel; import sys; print(build_wheel(sys.argv[1]))',
                      str(wheels.resolve())], cwd=staging)
        wheel, = (args.evidence / 'wheels').glob('*.whl')
        installed = args.evidence / 'installed'
        run('install', [sys.executable, '-B', '-m', 'pip', 'install', '--no-deps', '--no-index',
            '--no-compile', '--target', str(installed), str(wheel)])
        wheel_raw = regular_bytes(wheel)
        files = {}
        with zipfile.ZipFile(io.BytesIO(wheel_raw)) as archive:
            names = archive.namelist()
            if len(names) != len(set(names)) or any(
                    PurePosixPath(name).is_absolute() or '..' in PurePosixPath(name).parts for name in names):
                raise ValueError('wheel has duplicate or unsafe members')
            record_name, = [name for name in names if name.endswith('.dist-info/RECORD')]
            records = list(csv.reader(io.StringIO(archive.read(record_name).decode())))
            if len(records) != len({row[0] for row in records}):
                raise ValueError('wheel RECORD repeats an input')
            for name, digest, size in records:
                raw = archive.read(name)
                if digest:
                    expected = 'sha256=' + base64.urlsafe_b64encode(sha256(raw).digest()).rstrip(b'=').decode()
                    if digest != expected or size != str(len(raw)):
                        raise ValueError('wheel RECORD differs')
                if name != record_name:
                    if (installed / name).read_bytes() != raw:
                        raise ValueError('actual installed wheel bytes differ')
                    files[name] = {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}
        # A real ordinary worker manifest, with no bundle selected, preserves
        # the original source/wheel equality separately from the executable pin.
        statement = ("import sys;sys.path.insert(0," + repr(str(installed)) + ");"
                     "from hepta.hia_agent_worker import main;"
                     "raise SystemExit(main(['--installation-manifest']))")
        run('ordinary-installed-identity', [sys.executable, '-I', '-B', '-c', statement])
        installed_identity = json.loads(regular_bytes(args.evidence / 'ordinary-installed-identity/stdout.log'))
        if installed_identity != source_identity:
            raise AssertionError('source/wheel installation_manifest equality changed')
        base = args.evidence / 'base-v1.json'
        write_json(base, {'schema': 'hepta.hia.native-helpers.v1', 'target': 'linux-x86_64-lp64',
            'abi': 'hia-byte-six-argument-v1', 'helpers': [
                {'selector': 'HEPTA_HIA_SLOT_LEDGER_MANIFEST',
                 'manifest_path': str(args.decision.resolve(strict=True)),
                 'manifest_sha256': pin(args.decision)['sha256']},
                {'selector': 'HEPTA_HIA_SLOT_OPERATIONS_MANIFEST',
                 'manifest_path': str(args.controller.resolve(strict=True)),
                 'manifest_sha256': pin(args.controller)['sha256']}]})
        receipt = installed / 'hepta/_slot_mechanical_build.json'
        if pin(receipt) != files['hepta/_slot_mechanical_build.json']:
            raise AssertionError('administrator receipt is not the actual RECORD-verified wheel receipt')
        capsule = args.evidence / 'v5-bundle.json'
        administrator = create(installed / 'hepta', base, pin(base)['sha256'],
                               files['hepta/_slot_mechanical_build.json']['sha256'], capsule)
        # This test explicitly acts as the administrator of the just verified
        # wheel. Production never computes an expected digest for its caller.
        reference_probe = args.evidence / 'current-v1-probe'
        run('current-v1-scenarios', [sys.executable, '-I', '-B',
            str(ROOT / 'tests/hia_slot_mechanical_installed_probe.py'),
            '--root', str(ROOT), '--installed', str(installed), '--bundle', str(base),
            '--expected-bundle-sha256', pin(base)['sha256'], '--lane', 'current-v1',
            '--evidence', str(reference_probe)], 1800)
        reference_raw = regular_bytes(reference_probe / 'report.json')
        reference_value = json.loads(reference_raw)
        if (reference_value['schema'] != 'hepta.slot.mechanical.installed-worker.v2'
                or reference_value['lane'] != 'current-v1' or reference_value['status'] != 'PASS'
                or reference_value['capsule']['sha256'] != pin(base)['sha256']):
            raise AssertionError('current original-v1 helper controls did not complete')
        probe = args.evidence / 'installed-probe'
        run('installed-scenarios', [sys.executable, '-I', '-B',
            str(ROOT / 'tests/hia_slot_mechanical_installed_probe.py'),
            '--root', str(ROOT), '--installed', str(installed), '--bundle', str(capsule),
            '--expected-bundle-sha256', administrator['sha256'], '--evidence', str(probe)], 1800)
        raw = regular_bytes(probe / 'report.json')
        value = json.loads(raw)
        if (value['schema'] != 'hepta.slot.mechanical.installed-worker.v2'
                or value['lane'] != 'current-v5'
                or value['status'] != 'PASS' or value['capsule']['sha256'] != administrator['sha256']):
            raise AssertionError('actual v5 installed controls did not complete')
        if (regular_bytes(wheel) != wheel_raw or regular_bytes(probe / 'report.json') != raw
                or regular_bytes(reference_probe / 'report.json') != reference_raw):
            raise AssertionError('v5 installed evidence changed during readback')
        details = {'wheel': {'path': str(wheel), **pin(wheel)}, 'wheel_files': files,
            'installed': str(installed), 'wheel_record': record_name,
            'installed_record': pin(installed / record_name),
            'ordinary_installed_identity': installed_identity, 'administrator': administrator,
            'current_v1_probe_report': {'path': str(reference_probe / 'report.json'),
                'bytes': len(reference_raw), 'sha256': sha256(reference_raw).hexdigest()},
            'probe_report': {'path': str(probe / 'report.json'), 'bytes': len(raw),
                             'sha256': sha256(raw).hexdigest()}}
    except BaseException as error:
        import traceback
        failure = {'type': type(error).__module__ + '.' + type(error).__qualname__,
                   'message': str(error), 'traceback': traceback.format_exc()}
        details = {}
    authority.finish()
    stable = (admit_product(ROOT, args.product_freeze, args.product_freeze_sha256) == before
              and additional_package_resources(ROOT) == (extra_resources, declarations)
              and all(pin(ROOT / name) == expected for name, expected in extra_pins.items()))
    report = {**started, 'status': 'PASS' if failure is None and stable else 'HOLD',
        'failure': failure, 'source_stable': stable, 'commands': commands, 'details': details,
        'new_v5_scope_not_old_Native6_qualification': True,
        'whole_native_stack_qualified': False}
    write_json(args.evidence / 'report.json', report)
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
