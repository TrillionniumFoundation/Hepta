"""Construct a platform-tagged wheel whose full-cost owner defaults to HIA.

This constructs a candidate artifact; ordinary source/portable builds remain
unchanged. Strict mode requires the complete current cold source identity.
The data-only pin, image and wheel are derived outputs, never circular cold
inputs. Explicit development construction is reported separately throughout.
"""
from __future__ import annotations

import argparse
import base64
import csv
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ''}:
    sys.path.insert(0, str(ROOT))

from hepta.hia_default_native import (BUNDLE_RESOURCE, PIN_SCHEMA, SCOPES,
                                     SELECTOR, TARGET, render_pin)
from tools.build_hia_json_preflight import admit_cold_build, current_sources

PIN_FILE = 'hepta/hia_default_native_pin.py'
PACKAGE_DIRECTORY = 'hepta/' + str(Path(BUNDLE_RESOURCE).parent)
SCHEMA = 'hepta.hia.default-native-wheel-build.v1'
WHEEL_TAG = 'py3-none-linux_x86_64'


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'),
                       ensure_ascii=False, allow_nan=False) + '\n').encode()


def source_identity(sources):
    return sha256(encoded(sources)).hexdigest()


def _inputs(sources):
    names = {name for name in sources if name.startswith('hepta/') and name.endswith('.py')}
    names.update(('setup.py', 'pyproject.toml', 'MANIFEST.in'))
    for line in (ROOT / 'MANIFEST.in').read_text().splitlines():
        if line.startswith('include '):
            names.add(line.removeprefix('include '))
        elif line.strip() and not line.startswith('#'):
            raise ValueError('candidate wheel requires the existing explicit source manifest')
    if any(name not in sources or Path(name).is_absolute() or '..' in Path(name).parts for name in names):
        raise ValueError('candidate package input is not in the complete cold source contract')
    captured = {name: (ROOT / name).read_bytes() for name in sorted(names)}
    if any(sha256(raw).hexdigest() != sources[name] for name, raw in captured.items()):
        raise ValueError('candidate package source changed before capture')
    if captured.get(PIN_FILE) != render_pin(None):
        raise ValueError('candidate construction requires the unchanged portable pin template')
    return captured


def _base_wheel(stage, output, captured):
    for name, raw in captured.items():
        path = stage / name
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_bytes(raw)
    environment = {key: value for key, value in os.environ.items()
                   if key not in ('PYTHONPATH', 'PYTHONHOME') and not key.startswith('HEPTA_HIA_')}
    environment['PYTHONDONTWRITEBYTECODE'] = '1'
    command = [sys.executable, '-B', '-m', 'pip', 'wheel', '--no-deps', '--no-build-isolation',
               '--no-index', '--wheel-dir', str(output), str(stage)]
    run = subprocess.run(command, cwd=stage, env=environment, capture_output=True, timeout=60)
    (stage.parent / 'wheel-build.stdout').write_bytes(run.stdout)
    (stage.parent / 'wheel-build.stderr').write_bytes(run.stderr)
    if run.returncode:
        raise ValueError('ordinary wheel construction failed; see captured wheel-build output')
    wheels = list(output.glob('*.whl'))
    if len(wheels) != 1:
        raise ValueError('candidate construction requires one ordinary base wheel')
    return wheels[0], command


def _wheel_contents(path, sources, captured):
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        if (len(names) != len(set(names))
                or any(Path(name).is_absolute() or '..' in Path(name).parts for name in names)):
            raise ValueError('invalid ordinary wheel member inventory')
        files = {name: archive.read(name) for name in names}
    for name, raw in captured.items():
        if name.startswith('hepta/') and name.endswith('.py') and files.get(name) != raw:
            raise ValueError('ordinary wheel changed or omitted a production Python input')
    for name, raw in files.items():
        if name.startswith('hepta/_data/'):
            source = name.removeprefix('hepta/_data/')
            if source not in sources or sha256(raw).hexdigest() != sources[source]:
                raise ValueError('ordinary wheel resource is not bound by current source')
        elif name.startswith('hepta/'):
            if captured.get(name) != raw:
                raise ValueError('ordinary wheel contains unbound production bytes')
        elif '.dist-info/' not in name:
            raise ValueError('unexpected ordinary wheel file')
    records = [name for name in files if name.endswith('.dist-info/RECORD')]
    if len(records) != 1:
        raise ValueError('one wheel distribution inventory is required')
    return files, records[0].removesuffix('/RECORD')


def _write_wheel(path, files, distribution):
    record = distribution + '/RECORD'
    entries = io.StringIO(newline='')
    writer = csv.writer(entries, lineterminator='\n')
    for name, raw in sorted(files.items()):
        if name == record:
            continue
        digest = base64.urlsafe_b64encode(sha256(raw).digest()).rstrip(b'=').decode('ascii')
        writer.writerow((name, 'sha256=' + digest, str(len(raw))))
    writer.writerow((record, '', ''))
    files = {**files, record: entries.getvalue().encode()}
    with zipfile.ZipFile(path, 'x', compression=zipfile.ZIP_DEFLATED) as archive:
        for name, raw in sorted(files.items()):
            item = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            item.create_system = 3
            item.external_attr = 0o100644 << 16
            item.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(item, raw)
    return {name: sha256(raw).hexdigest() for name, raw in sorted(files.items())}


def build(output, compiler, cold_report=None, *, development=False):
    if type(development) is not bool or development == (cold_report is not None):
        raise ValueError('choose one matching cold report or explicit development construction')
    import ctypes
    import platform
    if (platform.system() != 'Linux' or platform.machine() != 'x86_64'
            or ctypes.sizeof(ctypes.c_void_p) != 8):
        raise ValueError('native candidate construction requires Linux x86-64 LP64')
    output, compiler = Path(output).absolute(), Path(compiler).resolve(strict=True)
    compiler_bytes = compiler.read_bytes()
    cold_bytes = None if development else Path(cold_report).read_bytes()
    sources = current_sources() if development else admit_cold_build(compiler_bytes, cold_bytes)
    captured = _inputs(sources)
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    from tools.build_hia_full_cost import build as build_owner
    manifest_path = build_owner(output / 'component', compiler, cold_report, development=development)
    manifest_raw = manifest_path.read_bytes()
    manifest = json.loads(manifest_raw)
    image_name = manifest['image_path']
    image_raw = (manifest_path.parent / image_name).read_bytes()
    component_report = (manifest_path.parent / 'build.json').read_bytes()
    scope = SCOPES[1] if development else SCOPES[0]
    bundle = encoded({'schema': 'hepta.hia.native-helpers.v1', 'target': TARGET,
        'abi': 'hia-byte-six-argument-v1', 'helpers': [{
            'selector': SELECTOR, 'manifest_path': 'manifest.json',
            'manifest_sha256': sha256(manifest_raw).hexdigest()}]})
    pin = (PIN_SCHEMA, TARGET, BUNDLE_RESOURCE, sha256(bundle).hexdigest(), scope,
           '-' if cold_bytes is None else sha256(cold_bytes).hexdigest(), source_identity(sources))
    pin_raw = render_pin(pin)
    staging = output / 'source'
    staging.mkdir(mode=0o700)
    base_wheel, command = _base_wheel(staging, output / 'base-wheel', captured)
    files, distribution = _wheel_contents(base_wheel, sources, captured)
    if (files.get('hepta/_data/examples/hia_bootstrap/full_cost.hepta')
            != captured['examples/hia_bootstrap/full_cost.hepta']):
        raise ValueError('native candidate wheel does not own its exact HIA source')
    build_tag = '1hiafullcostdev' if development else '1hiafullcostcold'
    wheel_meta = ('Wheel-Version: 1.0\nGenerator: hepta.default-native-candidate.v1\n'
                  'Root-Is-Purelib: false\nBuild: ' + build_tag + '\nTag: ' + WHEEL_TAG + '\n').encode()
    provenance = encoded({'schema': 'hepta.hia.default-native-package-provenance.v1',
        'scope': scope, 'target': TARGET, 'source_identity_sha256': source_identity(sources),
        'source_manifest': sources, 'compiler_sha256': sha256(compiler_bytes).hexdigest(),
        'cold_report_sha256': None if cold_bytes is None else sha256(cold_bytes).hexdigest(),
        'component_build_sha256': sha256(component_report).hexdigest(),
        'default_bundle_sha256': pin[3], 'pin_template_sha256': sha256(captured[PIN_FILE]).hexdigest(),
        'derived_pin_sha256': sha256(pin_raw).hexdigest(),
        'runtime_source_transformations': {PIN_FILE: 'data-only pin derived by the cold-bound builder'},
        'retained_reference_bodies_removed': False, 'whole_native_delivery_qualified': False,
        'production_activated': False})
    derived = {PIN_FILE: pin_raw, PACKAGE_DIRECTORY + '/bundle.json': bundle,
        PACKAGE_DIRECTORY + '/manifest.json': manifest_raw,
        PACKAGE_DIRECTORY + '/' + image_name: image_raw,
        PACKAGE_DIRECTORY + '/component-build.json': component_report,
        PACKAGE_DIRECTORY + '/provenance.json': provenance,
        distribution + '/WHEEL': wheel_meta}
    if not development:
        derived[PACKAGE_DIRECTORY + '/cold-report.json'] = cold_bytes
    files.update(derived)
    prefix = base_wheel.name.removesuffix('.whl').rsplit('-', 3)[0]
    wheel = output / (prefix + '-' + build_tag + '-' + WHEEL_TAG + '.whl')
    if (current_sources() != sources or compiler.read_bytes() != compiler_bytes
            or (cold_bytes is not None and Path(cold_report).read_bytes() != cold_bytes)
            or any((ROOT / name).read_bytes() != raw for name, raw in captured.items())
            or manifest_path.read_bytes() != manifest_raw
            or (manifest_path.parent / image_name).read_bytes() != image_raw
            or (manifest_path.parent / 'build.json').read_bytes() != component_report):
        raise ValueError('default candidate inputs changed before wheel publication')
    members = _write_wheel(wheel, files, distribution)
    report = {'schema': SCHEMA, 'scope': scope, 'target': TARGET, 'wheel_tag': WHEEL_TAG,
        'wheel': str(wheel), 'wheel_sha256': sha256(wheel.read_bytes()).hexdigest(),
        'base_wheel_sha256': sha256(base_wheel.read_bytes()).hexdigest(),
        'ordinary_wheel_command': command, 'source_manifest': sources,
        'source_identity_sha256': source_identity(sources), 'compiler_sha256': sha256(compiler_bytes).hexdigest(),
        'cold_report_sha256': None if cold_bytes is None else sha256(cold_bytes).hexdigest(),
        'default_bundle_sha256': pin[3], 'pin': pin, 'members': members,
        'derived_package_members': sorted(derived),
        'ordinary_source_default_changed': False, 'retained_reference_bodies_removed': False,
        'matching_source_cold_component': not development,
        'installed_default_qualification_completed': False,
        'whole_native_delivery_qualified': False, 'production_activated': False}
    (output / 'build.json').write_bytes(encoded(report))
    return wheel


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compiler', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument('--cold-report', type=Path)
    choice.add_argument('--development', action='store_true')
    args = parser.parse_args()
    print(build(args.output, args.compiler, args.cold_report, development=args.development))


if __name__ == '__main__':
    main()
