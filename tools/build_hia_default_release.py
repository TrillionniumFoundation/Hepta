"""Construct a platform-tagged wheel with packaged HIA cost and Core ELF owners.

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

from hepta.hia_default_native import (BUNDLE_RESOURCE, CLI_BUNDLE_RESOURCE, CORE_ELF_OWNERS, CORE_PROOF_OWNERS,
                                     CORE_WIRE_OWNER,
                                     PIN_SCHEMA, PROOF_BUNDLE_RESOURCE, SCOPES, SELECTOR,
                                     TARGET, render_pin)
from tools.build_hia_json_preflight import admit_cold_build, build_batch, current_sources

PIN_FILE = 'hepta/hia_default_native_pin.py'
PACKAGE_DIRECTORY = 'hepta/' + str(Path(BUNDLE_RESOURCE).parent)
SCHEMA = 'hepta.hia.default-native-wheel-build.v1'
WHEEL_TAG = 'py3-none-linux_x86_64'
SLOT_RECEIPT = 'hepta/_slot_mechanical_build.json'


def _wheel_tag(path, metadata):
    tag = '-'.join(path.stem.rsplit('-', 3)[-3:])
    tags = [line.removeprefix('Tag: ') for line in metadata.decode().splitlines()
            if line.startswith('Tag: ')]
    if tags != [tag]:
        raise ValueError('wheel filename and metadata disagree on ABI tag')
    return tag


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


def _base_wheel(stage, output, captured, *, native_store_only):
    for name, raw in captured.items():
        path = stage / name
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_bytes(raw)
    environment = {key: value for key, value in os.environ.items()
                   if key not in ('PYTHONPATH', 'PYTHONHOME') and not key.startswith('HEPTA_HIA_')}
    environment['PYTHONDONTWRITEBYTECODE'] = '1'
    if native_store_only:
        environment['HEPTA_HIA_STRICT_NATIVE_STORE_WHEEL'] = '1'
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


def _slot_wheel_members(files, captured, tag):
    if SLOT_RECEIPT not in files:
        if tag != 'py3-none-any':
            raise ValueError('unexpected ordinary wheel ABI without Slot transport')
        return set(), WHEEL_TAG

    from hepta.hia_slot_mechanical import ABI, SCHEMA, SOURCES, _pairs, _profile
    profile = _profile()
    binary = '_hia_slot_mechanical' + profile['extension_suffix']
    path = 'hepta/' + binary
    raw = files.get(path)
    receipt = json.loads(files[SLOT_RECEIPT], object_pairs_hook=_pairs)
    source_pins = {name: {'bytes': len(captured[name]), 'sha256': sha256(captured[name]).hexdigest()}
                   for name in SOURCES}
    receipt_keys = {'schema', 'abi', 'profile', 'binary', 'sources', 'compiler_commands',
                    'compiler_executables', 'build_scope', 'product_qualification_claimed'}
    if (not raw or not isinstance(receipt, dict)
            or set(receipt) != receipt_keys
            or receipt.get('schema') != SCHEMA or receipt.get('abi') != ABI
            or receipt.get('profile') != profile or receipt.get('sources') != source_pins
            or receipt.get('binary') != {'name': binary, 'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}
            or not receipt.get('compiler_commands') or not receipt.get('compiler_executables')
            or receipt.get('build_scope') != 'CPYTHON_MECHANICAL_EXTENSION_ONLY'
            or receipt.get('product_qualification_claimed') is not False):
        raise ValueError('ordinary wheel Slot transport differs from its exact build receipt')
    python_tag = f'cp{sys.version_info.major}{sys.version_info.minor}'
    abi_tag = 'cp' + profile['soabi'].split('-')[1]
    if tag != f'{python_tag}-{abi_tag}-linux_x86_64':
        raise ValueError('ordinary wheel Slot transport needs its exact CPython ABI tag')
    return {path, SLOT_RECEIPT}, tag


def _wheel_contents(path, sources, captured):
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        if (len(names) != len(set(names))
                or any(Path(name).is_absolute() or '..' in Path(name).parts for name in names)):
            raise ValueError('invalid ordinary wheel member inventory')
        files = {name: archive.read(name) for name in names}
    records = [name for name in files if name.endswith('.dist-info/RECORD')]
    if len(records) != 1:
        raise ValueError('one wheel distribution inventory is required')
    distribution = records[0].removesuffix('/RECORD')
    tag = _wheel_tag(path, files[distribution + '/WHEEL'])
    slot_files, release_tag = _slot_wheel_members(files, captured, tag)
    for name, raw in captured.items():
        if name.startswith('hepta/') and name.endswith('.py') and files.get(name) != raw:
            raise ValueError('ordinary wheel changed or omitted a production Python input')
    for name, raw in files.items():
        if name.startswith('hepta/_data/'):
            source = name.removeprefix('hepta/_data/')
            if source not in sources or sha256(raw).hexdigest() != sources[source]:
                raise ValueError('ordinary wheel resource is not bound by current source')
        elif name.startswith('hepta/'):
            if name not in slot_files and captured.get(name) != raw:
                raise ValueError('ordinary wheel contains unbound production bytes')
        elif '.dist-info/' not in name:
            raise ValueError('unexpected ordinary wheel file')
    return files, distribution, release_tag


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


def _cli_package_members(output, compiler, cold_report):
    from hepta.hia_cli_native import DISCOVERY_BUNDLE_SCHEMA
    from tools.build_hia_cli_discovery_json import build as build_discovery
    from tools.build_hia_cli_native import build as build_cli

    manifest = build_cli(output, compiler, cold_report)
    original = manifest.read_bytes()
    bundle = json.loads(original)
    discovery = build_discovery(output / 'discovery', compiler, cold_report)
    bundle.update(schema=DISCOVERY_BUNDLE_SCHEMA,
                  discovery_manifest=discovery.relative_to(output).as_posix(),
                  discovery_manifest_sha256=sha256(discovery.read_bytes()).hexdigest())
    raw = encoded(bundle)
    inputs = {manifest: original, output / 'build.json': (output / 'build.json').read_bytes()}
    for role in ('control', 'format', 'discovery'):
        child = output / bundle[role + '_manifest']
        child_raw = child.read_bytes()
        if sha256(child_raw).hexdigest() != bundle[role + '_manifest_sha256']:
            raise ValueError('packaged CLI companion manifest changed')
        metadata = json.loads(child_raw)
        image = child.parent / metadata['image_path']
        image_raw = image.read_bytes()
        if sha256(image_raw).hexdigest() != metadata['image_sha256']:
            raise ValueError('packaged CLI companion image changed')
        inputs.update({child: child_raw, image: image_raw})
    directory = Path('hepta') / Path(CLI_BUNDLE_RESOURCE).parent
    members = {(directory / path.relative_to(output)).as_posix(): contents
               for path, contents in inputs.items() if path not in (manifest, output / 'build.json')}
    members['hepta/' + CLI_BUNDLE_RESOURCE] = raw
    return members, inputs, sha256(raw).hexdigest()



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
    cold_report = None if development else Path(cold_report).resolve(strict=True)
    cold_bytes = None if cold_report is None else cold_report.read_bytes()
    sources = current_sources() if development else admit_cold_build(compiler_bytes, cold_bytes)
    captured = _inputs(sources)
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    from tools.build_hia_full_cost import build as build_owner
    manifest_path = build_owner(output / 'component', compiler, cold_report, development=development)
    owners = [(SELECTOR, '', manifest_path)]
    proof_owners = (*CORE_PROOF_OWNERS, CORE_WIRE_OWNER)
    proof_selectors = {selector for selector, _ in proof_owners}
    if not development:
        cold_owners = CORE_ELF_OWNERS + proof_owners
        native_manifests = build_batch(output / 'core-elf', compiler, cold_report,
                                       candidates=[candidate for _, candidate in cold_owners])
        owners.extend((selector, candidate + '/', native_manifests[candidate])
                      for selector, candidate in cold_owners)
    owner_members, manifests, proof_manifests, owner_inputs = {}, [], [], {}
    for selector, directory, path in owners:
        manifest_raw = path.read_bytes()
        manifest = json.loads(manifest_raw)
        image_path = path.parent / manifest['image_path']
        image_raw = image_path.read_bytes()
        if sha256(image_raw).hexdigest() != manifest['image_sha256']:
            raise ValueError('candidate native default image differs from its build manifest')
        owner_inputs.update({path: manifest_raw, image_path: image_raw})
        relative_path = directory + 'manifest.json'
        owner_members[PACKAGE_DIRECTORY + '/' + relative_path] = manifest_raw
        owner_members[PACKAGE_DIRECTORY + '/' + directory + image_path.name] = image_raw
        inventory = proof_manifests if selector in proof_selectors else manifests
        inventory.append({'selector': selector, 'manifest_path': relative_path,
                          'manifest_sha256': sha256(manifest_raw).hexdigest()})
    component_path = manifest_path.parent / 'build.json'
    component_report = component_path.read_bytes()
    owner_inputs[component_path] = component_report
    scope = SCOPES[1] if development else SCOPES[0]
    bundle_header = {'schema': 'hepta.hia.native-helpers.v1', 'target': TARGET,
                     'abi': 'hia-byte-six-argument-v1'}
    bundle = encoded({**bundle_header, 'helpers': manifests})
    pin = (PIN_SCHEMA, TARGET, BUNDLE_RESOURCE, sha256(bundle).hexdigest(), scope,
           '-' if cold_bytes is None else sha256(cold_bytes).hexdigest(), source_identity(sources))
    if proof_manifests:
        proof_bundle = encoded({**bundle_header, 'helpers': proof_manifests})
        owner_members['hepta/' + PROOF_BUNDLE_RESOURCE] = proof_bundle
        pin += (sha256(proof_bundle).hexdigest(),)
    if not development:
        cli_members, cli_inputs, cli_pin = _cli_package_members(output / 'cli-owner', compiler, cold_report)
        owner_members.update(cli_members)
        owner_inputs.update(cli_inputs)
        pin += (cli_pin,)
    pin_raw = render_pin(pin)
    staging = output / 'source'
    staging.mkdir(mode=0o700)
    base_wheel, command = _base_wheel(staging, output / 'base-wheel', captured, native_store_only=not development)
    files, distribution, wheel_tag = _wheel_contents(base_wheel, sources, captured)
    if (files.get('hepta/_data/examples/hia_bootstrap/full_cost.hepta')
            != captured['examples/hia_bootstrap/full_cost.hepta']):
        raise ValueError('native candidate wheel does not own its exact HIA source')
    build_tag = '1hiafullcostdev' if development else '1hiafullcostcold'
    wheel_meta = ('Wheel-Version: 1.0\nGenerator: hepta.default-native-candidate.v1\n'
                  'Root-Is-Purelib: false\nBuild: ' + build_tag + '\nTag: ' + wheel_tag + '\n').encode()
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
    derived = {**owner_members, PIN_FILE: pin_raw, PACKAGE_DIRECTORY + '/bundle.json': bundle,
        PACKAGE_DIRECTORY + '/component-build.json': component_report,
        PACKAGE_DIRECTORY + '/provenance.json': provenance,
        distribution + '/WHEEL': wheel_meta}
    if not development:
        derived[PACKAGE_DIRECTORY + '/cold-report.json'] = cold_bytes
    files.update(derived)
    prefix = base_wheel.name.removesuffix('.whl').rsplit('-', 3)[0]
    wheel = output / (prefix + '-' + build_tag + '-' + wheel_tag + '.whl')
    if (current_sources() != sources or compiler.read_bytes() != compiler_bytes
            or (cold_bytes is not None and cold_report.read_bytes() != cold_bytes)
            or any((ROOT / name).read_bytes() != raw for name, raw in captured.items())
            or any(path.read_bytes() != raw for path, raw in owner_inputs.items())):
        raise ValueError('default candidate inputs changed before wheel publication')
    members = _write_wheel(wheel, files, distribution)
    report = {'schema': SCHEMA, 'scope': scope, 'target': TARGET, 'wheel_tag': wheel_tag,
        'wheel': str(wheel), 'wheel_sha256': sha256(wheel.read_bytes()).hexdigest(),
        'base_wheel_sha256': sha256(base_wheel.read_bytes()).hexdigest(),
        'ordinary_wheel_command': command, 'source_manifest': sources,
        'source_identity_sha256': source_identity(sources), 'compiler_sha256': sha256(compiler_bytes).hexdigest(),
        'cold_report_sha256': None if cold_bytes is None else sha256(cold_bytes).hexdigest(),
        'default_bundle_sha256': pin[3], 'pin': pin, 'members': members,
        'default_selectors': [entry['selector'] for entry in manifests],
        'safe_core_proof_selectors': [entry['selector'] for entry in proof_manifests],
        'default_native_cli_control': not development,
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
