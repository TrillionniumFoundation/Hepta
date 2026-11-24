"""Construct a platform-tagged wheel with packaged HIA cost and Core ELF owners.

The ordinary wheel installs a compiled HIA command and its sibling executables.
Strict mode requires the complete current cold source identity.
The data-only pin, image and wheel are derived outputs, never circular cold
inputs. Explicit development construction is reported separately throughout.
"""
from __future__ import annotations

import argparse
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import subprocess
from tempfile import TemporaryDirectory
import sys
import zipfile
import zlib

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ''}:
    sys.path.insert(0, str(ROOT))

from hepta.hia_default_native import (ADMISSION_BUNDLE_RESOURCE, ADMISSION_OWNER, ASSEMBLY_RENDER_RESOURCE, ASSEMBLY_SYNTAX_RESOURCE, ASSEMBLY_DIAGNOSTIC_RESOURCE, BINDER_RESOURCE, BUNDLE_RESOURCE, CLI_BUNDLE_RESOURCE, CORE_ELF_OWNERS, CORE_PROOF_OWNERS,
                                     CORE_WIRE_OWNER, INTEGER_BUNDLE_RESOURCE, INTEGER_OWNER,
                                     LEDGER_BUNDLE_RESOURCE, LEDGER_OWNER, GRAPH_BUNDLE_RESOURCE, GRAPH_OWNER, OWNED_VM_RESOURCE,
                                     PIN_RESOURCE, PIN_SCHEMA, PROOF_BUNDLE_RESOURCE, SCOPES, SELECTOR,
                                     TARGET, render_pin, render_pin_data)
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
    # This is the Python import library for the native wheel. Call its packaging
    # backend directly so it cannot recursively dispatch the public wheel build.
    output.mkdir(mode=0o700)
    command = [sys.executable, '-B', '-c',
               'from setuptools.build_meta import build_wheel; import sys; print(build_wheel(sys.argv[1]))',
               str(output)]
    if 'PYTHONPATH' in os.environ:
        # pip puts its isolated build requirements on this path.
        environment['PYTHONPATH'] = os.environ['PYTHONPATH']
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


def _wheel_contents(path, sources, captured, images):
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        if (len(names) != len(set(names))
                or any(Path(name).is_absolute() or '..' in Path(name).parts for name in names)):
            raise ValueError('invalid ordinary wheel member inventory')
        workspace = ctypes.create_string_buffer(2048)
        files = {name: _wheel_member(archive, name, images, workspace) for name in names}
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


def _native_cli_scripts(directory, compiler, cold_report, distribution, *, sources):
    """Produce pip's scripts directly from the authenticated public Core build."""
    from hepta.hia_program_selfhost import SOURCE_FILES
    from tools.build_hia_core_edit import DISPATCH_ROLES, PROGRAMS, build as build_core

    applications = {
        'examples/hia_bootstrap/core_cli/assembly_render.hepta': ('hia-render-assembly', ASSEMBLY_RENDER_RESOURCE),
        'examples/hia_bootstrap/core_cli/assembly_syntax_diagnostics.hepta': ('hia-import-assembly', ASSEMBLY_SYNTAX_RESOURCE),
        'examples/hia_bootstrap/core_cli/assembly_diagnostic_report.hepta': ('hia-import-assembly', ASSEMBLY_DIAGNOSTIC_RESOURCE),
    }
    captured = {}
    def retain(source, image):
        if source in applications:
            captured[source] = image
    build_core(directory, compiler, cold_report, release_only=True, wheel_layout=True, retain_compiled_image=retain)
    receipt = json.loads((directory / 'build.json').read_bytes())
    paths = {name: directory / name for kind, (name, _) in PROGRAMS.items() if kind != 'emit_object'}
    paths['hia-nominal-constructor'] = directory / 'nominal-constructor/hia-nominal-constructor'
    binaries = {path: path.read_bytes() for path in paths.values()}
    identities = {name: sha256(binaries[path]).hexdigest() for name, path in paths.items()}
    pins = receipt['executables']['hia']['role_sha256']
    if (set(pins) != DISPATCH_ROLES or any(identities[role] != value for role, value in pins.items())
            or any(not raw.startswith(b'\x7fELF\x02\x01\x01') for raw in binaries.values())):
        raise ValueError('wheel CLI differs from the executables authenticated by its native dispatcher')
    scripts = distribution.removesuffix('.dist-info') + '.data/scripts/'
    members = {scripts + name: binaries[path] for name, path in paths.items()}
    for relative in SOURCE_FILES:
        path = ROOT / relative
        raw = path.read_bytes()
        if sha256(raw).hexdigest() != sources[relative]:
            raise ValueError(f'selfhost CLI resource differs from cold source {relative}')
        members[scripts + path.name] = raw
        binaries[path] = raw
    assembly_images = {}
    for source, (role, resource) in applications.items():
        raw = captured[source]
        compiled = receipt['compile_receipts'][source]
        linked = receipt['executables'][role]['native_image_sha256'][Path(source).name]
        if (compiled['source_sha256'] != sources[source] or compiled['compiler_sha256'] != receipt['compiler_sha256']
                or compiled['produced_bytes'] != len(raw) or compiled['produced_sha256'] != linked
                or sha256(raw).hexdigest() != linked or binaries[paths[role]].count(raw) != 1):
            raise ValueError('public assembly role differs from its source-bound HIA image: ' + source)
        assembly_images[resource] = raw
    return members, binaries, assembly_images


def _wheel_record_images(directory, compiler, sources, cold_bytes):
    """Compile and bind the HIA programs for the wheel inventory and ZIP directory."""
    from hepta.hia_json_preflight_native import NativeHiaJsonImage
    from hepta.hia_sha256_stream_native import NativeSha256Stream
    from tools.build_hia_source_build import _check_compile_receipt
    from tools.qualify_hia_selfhost import compile_stage
    from tools.replay_hia_selfhost_cold import cold_compiler_observer

    observer = None if cold_bytes is None else cold_compiler_observer(cold_bytes)
    compiler_raw = compiler.read_bytes()
    directory.mkdir(mode=0o700)
    images = []
    programs = (('sha256_stream', NativeSha256Stream), ('wheel_record_row', NativeHiaJsonImage),
                ('wheel_zip_directory', NativeHiaJsonImage), ('wheel_inflate', NativeHiaJsonImage),
                ('wheel_zip_local', NativeHiaJsonImage))
    for name, image_type in programs:
        relative = 'examples/hia_bootstrap/' + name + '.hepta'
        path = ROOT / relative
        raw = path.read_bytes()
        if sha256(raw).hexdigest() != sources.get(relative):
            raise ValueError('wheel record source differs from its admitted identity: ' + name)
        image, receipt = compile_stage(directory, name, compiler, raw, flat_observer=observer)
        compiled = image.read_bytes()
        _check_compile_receipt(receipt, compiler=compiler_raw, source=raw, produced=compiled)
        if path.read_bytes() != raw or compiler.read_bytes() != compiler_raw:
            raise ValueError('wheel record compiler inputs changed')
        images.append(image_type(compiled, receipt['produced_sha256']))
    return tuple(images)


def _wheel_record_row(encoder, name, size, digest=None):
    path = name.encode('utf-8')
    if len(path) > 65535 or (digest is not None and len(digest) != 32):
        raise ValueError('invalid wheel record member')
    wire = struct.pack('<8s3Q', b'HIAWROW1', int(digest is None), len(path), size) + path + (digest or b'')
    source = ctypes.create_string_buffer(wire, len(wire))
    output = ctypes.create_string_buffer(2 * len(path) + 80)
    used = encoder._entry(source, len(wire), output, len(output), None, 0)
    if not 0 < used <= len(output):
        raise ValueError('HIA refused a wheel inventory row')
    return output.raw[:used]


ZIP_LOCAL_MEMBER, ZIP_CENTRAL_MEMBER, ZIP_END_DIRECTORY, ZIP_CRC_UPDATE = range(4)


def _zip_frame(encoder, action, *, size, compressed=0, offset=0, crc=0, executable=False,
               name=b'', payload=b'', workspace=None):
    prefix = struct.pack('<8s7Q', b'HIAWZIP1', action, size, compressed, offset, crc, int(executable), len(name))
    wire = prefix + name + payload
    source = ctypes.create_string_buffer(wire, len(wire))
    output = ctypes.create_string_buffer(4 if workspace is not None else len(name) + 128)
    work_size = len(workspace) if workspace is not None else 0
    used = encoder._entry(source, len(wire), output, len(output), workspace, work_size)
    if not 0 < used <= len(output) or (action == ZIP_CRC_UPDATE and used != 4):
        raise ValueError('HIA refused the wheel ZIP frame')
    return output.raw[:used]


def _wheel_crc(encoder, raw, workspace):
    crc = 0
    chunk_bytes = 1 << 20
    for start in range(0, len(raw), chunk_bytes):
        chunk = raw[start:start + chunk_bytes]
        encoded = _zip_frame(encoder, ZIP_CRC_UPDATE, size=len(chunk), crc=crc, payload=chunk, workspace=workspace)
        crc = int.from_bytes(encoded, 'little')
    return crc


def _inflate_wheel_member(image, compressed, size):
    """Walk the entire stream and check its extent before allocating from the ZIP metadata."""
    source = ctypes.create_string_buffer(compressed, max(1, len(compressed)))
    measurement = ctypes.create_string_buffer(4112)
    measurement[4096:] = struct.pack('<8sQ', b'HIACOUNT', size)
    length = ctypes.create_string_buffer(8)
    if (image._entry(source, len(compressed), length, 8, measurement, len(measurement)) != 0
            or int.from_bytes(length.raw, 'little') != size):
        raise zipfile.BadZipFile('invalid DEFLATE stream or declared wheel member size')
    output = ctypes.create_string_buffer(size)
    workspace = ctypes.create_string_buffer(4096)
    if image._entry(source, len(compressed), output, size, workspace, len(workspace)) != 0:
        raise zipfile.BadZipFile('invalid wheel DEFLATE payload')
    return output.raw


def _wheel_member(archive, name, images, crc_workspace):
    _, _, zipper, inflater, locator = images
    info = archive.getinfo(name)
    limit = getattr(info, '_end_offset', None)
    # Preserve optional codec, encryption and duplicate-offset behavior of the supplied ZipFile.
    if (info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED) or info.flag_bits & 0x61
            or limit is None or limit == info.header_offset):
        return archive.read(info)
    stream = archive.fp
    stream.seek(info.header_offset)
    header = stream.read(30)
    if len(header) != 30:
        raise zipfile.BadZipFile('Truncated file header')
    request = struct.pack('<8s3Q', b'HIAZLOC1', info.header_offset, info.compress_size, limit) + header
    source = ctypes.create_string_buffer(request, len(request))
    extent = ctypes.create_string_buffer(32)
    status = locator._entry(source, len(request), extent, len(extent), None, 0)
    if status == 2:
        raise zipfile.BadZipFile('Bad magic number for file header')
    if status == 3:
        raise zipfile.BadZipFile('Overlapped entries: %r (possible zip bomb)' % info.orig_filename)
    if status:
        raise zipfile.BadZipFile('invalid HIA wheel local header')
    flags, name_size, start, end = struct.unpack('<4Q', extent.raw)
    filename = stream.read(name_size)
    encoding = 'utf-8' if flags & 0x800 else archive.metadata_encoding or 'cp437'
    if filename.decode(encoding) != info.orig_filename:
        raise zipfile.BadZipFile('File name in directory %r and header %r differ.' % (info.orig_filename, filename))
    stream.seek(start)
    compressed = stream.read(end - start)
    if len(compressed) != info.compress_size:
        raise zipfile.BadZipFile('truncated wheel member')
    raw = compressed if info.compress_type == zipfile.ZIP_STORED else _inflate_wheel_member(
        inflater, compressed, info.file_size)
    if len(raw) != info.file_size or _wheel_crc(zipper, raw, crc_workspace) != info.CRC:
        raise zipfile.BadZipFile('wheel member length or CRC differs')
    return raw


def _write_zip(stream, files, distribution, encoder):
    directory = bytearray()
    prefix = distribution.removesuffix('.dist-info') + '.data/scripts/'
    workspace = ctypes.create_string_buffer(2048)
    for name, raw in sorted(files.items()):
        crc = _wheel_crc(encoder, raw, workspace)
        compressor = zlib.compressobj(zlib.Z_DEFAULT_COMPRESSION, zlib.DEFLATED, -15)
        compressed = compressor.compress(raw) + compressor.flush()
        metadata = dict(name=name.partition('\0')[0].encode('utf-8'), size=len(raw),
                        compressed=len(compressed), crc=crc, offset=stream.tell(),
                        executable=name.startswith(prefix) and raw.startswith(b'\x7fELF'))
        stream.write(_zip_frame(encoder, ZIP_LOCAL_MEMBER, **metadata))
        stream.write(compressed)
        directory.extend(_zip_frame(encoder, ZIP_CENTRAL_MEMBER, **metadata))
    offset = stream.tell()
    stream.write(directory)
    stream.write(_zip_frame(encoder, ZIP_END_DIRECTORY, size=len(files), compressed=len(directory), offset=offset))


def _write_wheel(path, files, distribution, record_images):
    if os.path.lexists(path):
        raise FileExistsError(path)
    hasher, encoder, zipper = record_images[:3]
    record = distribution + '/RECORD'
    entries = bytearray()
    digests = {}
    for name, raw in sorted(files.items()):
        if name != record:
            digest = hasher.digest(raw)
            digests[name] = digest.hex()
            entries.extend(_wheel_record_row(encoder, name, len(raw), digest))
    entries.extend(_wheel_record_row(encoder, record, 0))
    record_bytes = bytes(entries)
    digests[record] = hasher.digest(record_bytes).hex()
    files = {**files, record: record_bytes}
    with TemporaryDirectory(prefix='.hia-wheel-', dir=path.parent) as folder:
        staged = Path(folder) / path.name
        with staged.open('xb') as stream:
            _write_zip(stream, files, distribution, zipper)
        os.link(staged, path)
    return {name: digests[name] for name in sorted(files)}


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
        cold_owners = (*CORE_ELF_OWNERS, *proof_owners, INTEGER_OWNER, LEDGER_OWNER, GRAPH_OWNER, ADMISSION_OWNER)
        native_manifests = build_batch(output / 'core-elf', compiler, cold_report,
                                       candidates=[candidate for _, candidate in cold_owners])
        owners.extend((selector, candidate + '/', native_manifests[candidate])
                      for selector, candidate in cold_owners)
    owner_members, manifests, proof_manifests, owner_inputs = {}, [], [], {}
    vm_manifests = {owner[0]: [] for owner in (INTEGER_OWNER, LEDGER_OWNER, GRAPH_OWNER, ADMISSION_OWNER)}
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
        inventory = vm_manifests.get(selector, inventory)
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
        from tools.build_hia_safe_core_binder import build as build_binder
        executable = build_binder(output / 'elf-binder', compiler, cold_report)
        native_binder = executable.read_bytes()
        owner_inputs[executable] = native_binder
        owner_members['hepta/' + BINDER_RESOURCE] = native_binder
        pin += (sha256(native_binder).hexdigest(),)
        for owner, resource in ((INTEGER_OWNER, INTEGER_BUNDLE_RESOURCE), (LEDGER_OWNER, LEDGER_BUNDLE_RESOURCE),
                                (GRAPH_OWNER, GRAPH_BUNDLE_RESOURCE), (ADMISSION_OWNER, ADMISSION_BUNDLE_RESOURCE)):
            vm_bundle = encoded({**bundle_header, 'helpers': vm_manifests[owner[0]]})
            owner_members['hepta/' + resource] = vm_bundle
        from tools.build_hia_core_static import cold_tools
        from tools.build_hia_native_store_release import source_owned_reference
        owned_dir = output / 'owned-reference'
        owned_dir.mkdir(mode=0o700)
        native_tools = cold_tools(owned_dir, compiler, cold_report, sources)
        executable = source_owned_reference(*native_tools, compiler_bytes, sources)
        owner_members['hepta/' + OWNED_VM_RESOURCE] = executable
        pin += tuple(sha256(owner_members['hepta/' + resource]).hexdigest() for resource in (
            INTEGER_BUNDLE_RESOURCE, LEDGER_BUNDLE_RESOURCE, GRAPH_BUNDLE_RESOURCE,
            OWNED_VM_RESOURCE, ADMISSION_BUNDLE_RESOURCE))
    staging = output / 'source'
    staging.mkdir(mode=0o700)
    base_wheel, command = _base_wheel(staging, output / 'base-wheel', captured, native_store_only=not development)
    record_images = _wheel_record_images(output / 'wheel-record', compiler, sources, cold_bytes)
    files, distribution, wheel_tag = _wheel_contents(base_wheel, sources, captured, record_images)
    if (files.get('hepta/_data/examples/hia_bootstrap/full_cost.hepta')
            != captured['examples/hia_bootstrap/full_cost.hepta']):
        raise ValueError('native candidate wheel does not own its exact HIA source')
    if not development:
        cli_scripts, cli_inputs, assembly_images = _native_cli_scripts(
            output / 'native-cli', compiler, cold_report, distribution, sources=sources)
        owner_members.update(cli_scripts)
        owner_inputs.update(cli_inputs)
        for resource in (ASSEMBLY_RENDER_RESOURCE, ASSEMBLY_SYNTAX_RESOURCE, ASSEMBLY_DIAGNOSTIC_RESOURCE):
            raw = assembly_images[resource]
            owner_members['hepta/' + resource] = raw
            pin += (sha256(raw).hexdigest(),)
        owner_members[PACKAGE_DIRECTORY + '/cold-report.json'] = cold_bytes
    pin_raw = render_pin_data(pin)
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
        'derived_pin_resource': 'hepta/' + PIN_RESOURCE, 'runtime_source_transformations': {},
        'retained_reference_bodies_removed': False, 'whole_native_delivery_qualified': False,
        'production_activated': False})
    derived = {**owner_members, 'hepta/' + PIN_RESOURCE: pin_raw, PACKAGE_DIRECTORY + '/bundle.json': bundle,
        PACKAGE_DIRECTORY + '/component-build.json': component_report,
        PACKAGE_DIRECTORY + '/provenance.json': provenance,
        distribution + '/WHEEL': wheel_meta}
    files.update(derived)
    prefix = base_wheel.name.removesuffix('.whl').rsplit('-', 3)[0]
    wheel = output / (prefix + '-' + build_tag + '-' + wheel_tag + '.whl')
    if (current_sources() != sources or compiler.read_bytes() != compiler_bytes
            or (cold_bytes is not None and cold_report.read_bytes() != cold_bytes)
            or any((ROOT / name).read_bytes() != raw for name, raw in captured.items())
            or any(path.read_bytes() != raw for path, raw in owner_inputs.items())):
        raise ValueError('default candidate inputs changed before wheel publication')
    members = _write_wheel(wheel, files, distribution, record_images)
    report = {'schema': SCHEMA, 'scope': scope, 'target': TARGET, 'wheel_tag': wheel_tag,
        'wheel': str(wheel), 'wheel_sha256': sha256(wheel.read_bytes()).hexdigest(),
        'base_wheel_sha256': sha256(base_wheel.read_bytes()).hexdigest(),
        'python_library_wheel_command': command, 'source_manifest': sources,
        'source_identity_sha256': source_identity(sources), 'compiler_sha256': sha256(compiler_bytes).hexdigest(),
        'cold_report_sha256': None if cold_bytes is None else sha256(cold_bytes).hexdigest(),
        'default_bundle_sha256': pin[3], 'pin': pin, 'members': members,
        'default_selectors': [entry['selector'] for entry in manifests],
        'safe_core_proof_selectors': [entry['selector'] for entry in proof_manifests],
        'default_native_cli_control': not development,
        'derived_package_members': sorted(derived),
        'public_cli_entry': None if development else 'native-elf',
        'ordinary_source_default_changed': not development, 'retained_reference_bodies_removed': False,
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
