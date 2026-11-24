"""Build the native production distribution or an explicit hosted reference wheel.

The ordinary wheel contains HIA ELF commands and required data only. Reference
and development construction retain the hosted APIs for independent controls.
Both cold profiles require the complete current cold source identity.
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
NATIVE_BUILD_TAG = '2hianative'
NATIVE_BUILD_SCHEMA = 'hepta.hia.native-production-wheel-build.v1'
NATIVE_DISTRIBUTION_SCHEMA = 'hepta.hia.native-runtime-distribution.v1'
MCP_PROGRAMS = ('hia-mcp-request-audit', 'hia-mcp-job-bridge', 'hia-mcp-service')
JOBCTL_PROGRAM = 'hepta-runtime-jobctl'


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
    # This library exists only in an explicitly requested reference/development
    # distribution. Its backend must not recursively dispatch production.
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


def _native_ndu_members(directory, compiler, cold_report, *, sources, distribution=None):
    """Ship the actual HIA scalar evaluator and its exact source/build custody."""
    from hepta.hia_ndu_native import BINARY_RESOURCE, RECEIPT_RESOURCE, SOURCES
    from tools.build_hia_ndu_scalar import build as build_ndu

    executable = build_ndu(directory, compiler, cold_report)
    receipt = directory / 'build-receipt.json'
    inputs = {path: path.read_bytes() for path in (executable, receipt)}
    members = {'hepta/' + BINARY_RESOURCE: inputs[executable],
               'hepta/' + RECEIPT_RESOURCE: inputs[receipt]}
    if distribution is not None:
        members[distribution.removesuffix('.dist-info') + '.data/scripts/hia-ndu-scalar'] = inputs[executable]
    for name in SOURCES:
        path = ROOT / name
        raw = path.read_bytes()
        if sha256(raw).hexdigest() != sources.get(name):
            raise ValueError('packaged HIA NDU source differs from matching cold inputs')
        inputs[path] = raw
        members['hepta/_data/' + name] = raw
    return members, inputs


def _native_mcp_members(directory, compiler, cold_report, distribution, *, sources):
    """Ship all three source-built MCP programs and their unchanged receipt."""
    from tools.build_hia_mcp_service import build as build_mcp
    from tools.generate_hia_mcp_release import PRODUCTS, source_paths
    from tools.qualify_hia_selfhost_cli import inspect_executable

    if tuple(PRODUCTS) != MCP_PROGRAMS:
        raise ValueError('native MCP release roles differ from the production distribution')
    build_mcp(directory, compiler, cold_report)
    receipt = directory / 'build.json'
    raw = receipt.read_bytes()
    report = json.loads(raw)
    captured = {ROOT / name: (ROOT / name).read_bytes() for name in source_paths()}
    pins = {str(path.relative_to(ROOT)): sha256(data).hexdigest() for path, data in captured.items()}
    if (report.get('schema') != 'hepta.hia.mcp-service-source-build.v1'
            or report.get('matching_source_cold_build') is not True
            or report.get('source_sha256') != pins
            or any(sources.get(name) != digest for name, digest in pins.items())
            or report.get('compiler_sha256') != sha256(Path(compiler).read_bytes()).hexdigest()
            or report.get('cold_report_sha256') != sha256(Path(cold_report).read_bytes()).hexdigest()
            or set(report.get('products', {})) != set(MCP_PROGRAMS)):
        raise ValueError('native MCP build differs from the admitted source and compiler')
    prefix = distribution.removesuffix('.dist-info') + '.data/scripts/'
    members = {distribution + '/native-components/mcp-build.json': raw}
    inputs = {receipt: raw, **captured}
    for name in MCP_PROGRAMS:
        path = directory / name
        data = path.read_bytes()
        inspect_executable(data)
        if report['products'][name] != {'bytes': len(data), 'sha256': sha256(data).hexdigest()}:
            raise ValueError('native MCP program differs from its source build: ' + name)
        members[prefix + name] = data
        inputs[path] = data
    return members, inputs


def _native_jobctl_members(directory, compiler, cold_report, distribution, *, sources):
    """Build the mandatory system job owner from the identical cold source set."""
    from tools.build_hia_system_jobctl import build as build_jobctl
    from tools.generate_hia_system_jobctl_release import PRODUCT, source_paths
    from tools.qualify_hia_selfhost_cli import inspect_executable

    if PRODUCT != JOBCTL_PROGRAM:
        raise ValueError('native Jobctl role differs from the production distribution')
    executable = build_jobctl(directory, compiler, cold_report)
    receipt = directory / 'build.json'
    raw, binary = receipt.read_bytes(), executable.read_bytes()
    report = json.loads(raw)
    captured = {ROOT / name: (ROOT / name).read_bytes() for name in source_paths()}
    pins = {str(path.relative_to(ROOT)): sha256(data).hexdigest() for path, data in captured.items()}
    product = {'bytes': len(binary), 'sha256': sha256(binary).hexdigest()}
    if (executable != directory / JOBCTL_PROGRAM
            or report.get('schema') != 'hepta.hia.system-jobctl-source-build.v1'
            or report.get('matching_source_cold_build') is not True
            or report.get('scope') != 'MATCHING_SOURCE_COLD_COMPONENT'
            or report.get('source_sha256') != pins
            or any(sources.get(name) != digest for name, digest in pins.items())
            or report.get('compiler_sha256') != sha256(Path(compiler).read_bytes()).hexdigest()
            or report.get('cold_report_sha256') != sha256(Path(cold_report).read_bytes()).hexdigest()
            or report.get('products') != {JOBCTL_PROGRAM: product}
            or report.get('executable_path') != JOBCTL_PROGRAM
            or report.get('executable_sha256') != product['sha256']
            or report.get('executable') != inspect_executable(binary)
            or report.get('build_inputs_unchanged') is not True):
        raise ValueError('native Jobctl build differs from the admitted source and executable')
    prefix = distribution.removesuffix('.dist-info') + '.data/scripts/'
    members = {prefix + JOBCTL_PROGRAM: binary,
               distribution + '/native-components/jobctl-build.json': raw}
    return members, {receipt: raw, executable: binary, **captured}


def _native_package_members(directory, compiler, cold_report, distribution, *, sources, runtime, core_receipt):
    """Attach the single complete native release and bind every public wheel role."""
    from tools.build_hia_native_distribution_package import build as build_package, regular_bytes, validate_build
    from tools.build_hia_core_edit import DISPATCH_ROLES

    package = build_package(directory, compiler, cold_report)
    package_raw = regular_bytes(package)
    receipt_path = directory / 'build.json'
    receipt_raw = regular_bytes(receipt_path)
    report = json.loads(receipt_raw)
    original = validate_build(package_raw, report, sources, regular_bytes(compiler), regular_bytes(cold_report))
    prefix = distribution.removesuffix('.dist-info') + '.data/scripts/'
    core = json.loads(core_receipt)
    if (core.get('compiler_sha256') != report['compiler_sha256']
            or core.get('cold_report_sha256') != report['cold_report_sha256']):
        raise ValueError('wheel dispatcher and complete native package have different cold inputs')
    layout = 'examples/hia_bootstrap/source_wheel_layout.hepta'
    layout_receipt = core.get('compile_receipts', {}).get(layout, {})
    if (layout_receipt.get('source_sha256') != sources.get(layout)
            or layout_receipt.get('compiler_sha256') != report['compiler_sha256']):
        raise ValueError('wheel dispatcher requires the admitted HIA layout owner')
    roles = {name: sha256(original[name][1]).hexdigest() for name in DISPATCH_ROLES}
    if core.get('executables', {}).get('hia', {}).get('role_sha256') != roles:
        raise ValueError('wheel dispatcher roles differ from the single complete native package')
    bindings = {}
    for name, raw in runtime.items():
        if not name.startswith(prefix):
            continue
        role = name.removeprefix(prefix)
        if role not in original:
            raise ValueError('wheel entry is not supplied by the complete native package: ' + role)
        original_raw = original[role][1]
        if role != 'hia' and raw != original_raw:
            raise ValueError('wheel entry differs from the complete native package: ' + role)
        binding = {'package_sha256': sha256(original_raw).hexdigest(),
                   'delivered_sha256': sha256(raw).hexdigest(),
                   'profile': 'byte-identical-native-package-member'}
        if role == 'hia':
            # Both executables authenticate exactly the same public roles. The
            # HIA author changes only the validated directory/file stat predicates
            # needed by pip's shared scripts directory; the private package stays intact.
            binding.update(profile='source-bound-pip-dispatch-layout',
                           layout_source=layout, layout_source_sha256=sources[layout],
                           layout_compile_receipt=layout_receipt)
        bindings[role] = binding
    installer = original['hia-release'][1]
    installer_path = prefix + 'hia-release'
    if installer_path in runtime:
        raise ValueError('native package installer duplicates another public role')
    members = {
        installer_path: installer,
        distribution.removesuffix('.dist-info') + '.data/data/share/hia/store.hiapack': package_raw,
        distribution + '/native-components/release-build.json': receipt_raw,
        distribution + '/native-components/release-finalize.json': regular_bytes(directory / 'native-release.stdout'),
        distribution + '/native-components/core-build.json': core_receipt,
        distribution + '/native-package-bindings.json': encoded({
            'schema': 'hepta.hia.native-wheel-package-bindings.v1',
            'package': report['package'], 'source_identity_sha256': source_identity(sources),
            'compiler_sha256': report['compiler_sha256'], 'cold_report_sha256': report['cold_report_sha256'],
            'public_roles': bindings, 'installer_sha256': sha256(installer).hexdigest(),
            'worker_and_controller_installation': 'original-private-depot-from-contained-package',
        }),
    }
    inputs = {package: package_raw, receipt_path: receipt_raw,
              directory / 'native-release.stdout': members[distribution + '/native-components/release-finalize.json']}
    return members, inputs, report


def _native_cli_scripts(directory, compiler, cold_report, distribution, *, sources):
    """Produce pip's scripts directly from the authenticated public Core build."""
    from hepta.hia_program_selfhost import SOURCE_FILES
    from tools.build_hia_core_edit import DISPATCH_ROLES, PROGRAMS, build as build_core
    from tools.qualify_hia_selfhost_cli import inspect_executable

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
    receipt_raw = (directory / 'build.json').read_bytes()
    receipt = json.loads(receipt_raw)
    paths = {name: directory / name for kind, (name, _) in PROGRAMS.items() if kind != 'emit_object'}
    paths['hia-nominal-constructor'] = directory / 'nominal-constructor/hia-nominal-constructor'
    paths['hia-safe-core-prove'] = directory / 'supplied-proof/hia-safe-core-prove'
    binaries = {path: path.read_bytes() for path in paths.values()}
    identities = {name: sha256(binaries[path]).hexdigest() for name, path in paths.items()}
    pins = receipt['executables']['hia']['role_sha256']
    if (identities['hia-safe-core-prove'] != receipt['supplied_proof_sha256']
            or set(pins) != DISPATCH_ROLES or any(identities[role] != value for role, value in pins.items())
            or any(not raw.startswith(b'\x7fELF\x02\x01\x01') for raw in binaries.values())):
        raise ValueError('wheel CLI differs from the executables authenticated by its native dispatcher')
    for kind, (name, _) in PROGRAMS.items():
        if kind != 'emit_object' and receipt['executables'][name]['elf'] != inspect_executable(binaries[paths[name]]):
            raise ValueError('wheel CLI executable differs from its complete build receipt: ' + name)
    binaries[directory / 'build.json'] = receipt_raw
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



def native_distribution_metadata(project_bytes):
    """Describe the native executable distribution without importing setuptools."""
    import re
    import tomllib

    project = tomllib.loads(project_bytes.decode('utf-8'))['project']
    name, version, summary = (project[key] for key in ('name', 'version', 'description'))
    if (type(name) is not str or not re.fullmatch(r'[A-Za-z0-9]+(?:[-_.][A-Za-z0-9]+)*', name)
            or type(version) is not str or not re.fullmatch(r'[0-9]+(?:\.[0-9]+)*', version)
            or type(summary) is not str or any(c in summary for c in '\r\n\0')):
        raise ValueError('native distribution needs exact non-injectable project metadata')
    normalized = re.sub(r'[-_.]+', '_', name)
    distribution = normalized + '-' + version + '.dist-info'
    metadata = ('Metadata-Version: 2.3\nName: ' + name + '\nVersion: ' + version
                + '\nSummary: ' + summary + '\n\n').encode('utf-8')
    wheel = ('Wheel-Version: 1.0\nGenerator: hepta.native-runtime-distribution.v1\n'
             'Root-Is-Purelib: false\nBuild: ' + NATIVE_BUILD_TAG + '\nTag: ' + WHEEL_TAG + '\n').encode()
    return distribution, {distribution + '/METADATA': metadata, distribution + '/WHEEL': wheel}


def inspect_native_runtime_executable(role, raw):
    """Use the producer's exact executable profile for each runtime role."""
    if role == 'hia-nominal-constructor':
        from tools.build_hia_sqlite_pager import inspect_static_executable
        return inspect_static_executable(raw)
    from tools.qualify_hia_selfhost_cli import inspect_executable
    return inspect_executable(raw)


def native_runtime_members(distribution, cli_members, auxiliary_members):
    """Keep only the closed native runtime roles; refuse executable substitutions.

    Source custody data for hosted adapters stays in the explicit reference
    distribution. Public native programs carry their own source-derived pins.
    """
    from hepta.hia_program_selfhost import SOURCE_FILES
    from tools.build_hia_core_edit import PROGRAMS
    from tools.qualify_hia_selfhost_cli import inspect_executable

    prefix = distribution.removesuffix('.dist-info') + '.data/scripts/'
    programs = {name for kind, (name, _) in PROGRAMS.items() if kind != 'emit_object'}
    programs.update(('hia-nominal-constructor', 'hia-safe-core-prove', 'hia-ndu-scalar', *MCP_PROGRAMS, JOBCTL_PROGRAM))
    resources = {Path(name).name for name in SOURCE_FILES}
    files = {}
    for members in (cli_members, auxiliary_members):
        for name, raw in members.items():
            if not name.startswith(prefix):
                continue
            role = name.removeprefix(prefix)
            if (Path(role).name != role or role not in programs | resources
                    or type(raw) is not bytes or not raw or name in files):
                raise ValueError('unbound, duplicate or invalid native runtime member: ' + name)
            if role in programs:
                inspect_native_runtime_executable(role, raw)
            files[name] = raw
    if {name.removeprefix(prefix) for name in files} != programs | resources:
        raise ValueError('native runtime distribution is missing a required program or HIA resource')
    receipt = auxiliary_members.get('hepta/_hia_ndu_scalar_build.json')
    if type(receipt) is not bytes:
        raise ValueError('native NDU runtime requires its source-bound build receipt')
    ndu = json.loads(receipt)
    binary = files[prefix + 'hia-ndu-scalar']
    if (type(ndu) is not dict or ndu.get('implementation') != 'HIA'
            or ndu.get('scope') != 'MATCHING_SOURCE_COLD_COMPONENT'
            or ndu.get('executable_path') != 'hia-ndu-scalar'
            or ndu.get('executable_sha256') != sha256(binary).hexdigest()
            or ndu.get('executable') != inspect_executable(binary)):
        raise ValueError('native NDU build receipt does not bind the actual runtime ELF')
    files[distribution + '/native-components/ndu-build.json'] = receipt
    mcp_path = distribution + '/native-components/mcp-build.json'
    mcp_raw = auxiliary_members.get(mcp_path)
    if type(mcp_raw) is not bytes:
        raise ValueError('native MCP runtime requires its complete source build receipt')
    mcp = json.loads(mcp_raw)
    products = {name: {'bytes': len(files[prefix + name]),
                       'sha256': sha256(files[prefix + name]).hexdigest()} for name in MCP_PROGRAMS}
    if (type(mcp) is not dict or mcp.get('schema') != 'hepta.hia.mcp-service-source-build.v1'
            or mcp.get('matching_source_cold_build') is not True or mcp.get('products') != products):
        raise ValueError('native MCP receipt does not bind all actual runtime programs')
    files[mcp_path] = mcp_raw
    jobctl_path = distribution + '/native-components/jobctl-build.json'
    jobctl_raw = auxiliary_members.get(jobctl_path)
    if type(jobctl_raw) is not bytes:
        raise ValueError('native Jobctl runtime requires its complete source build receipt')
    jobctl = json.loads(jobctl_raw)
    binary = files[prefix + JOBCTL_PROGRAM]
    product = {'bytes': len(binary), 'sha256': sha256(binary).hexdigest()}
    if (type(jobctl) is not dict or jobctl.get('schema') != 'hepta.hia.system-jobctl-source-build.v1'
            or jobctl.get('matching_source_cold_build') is not True
            or jobctl.get('scope') != 'MATCHING_SOURCE_COLD_COMPONENT'
            or jobctl.get('products') != {JOBCTL_PROGRAM: product}
            or jobctl.get('executable_path') != JOBCTL_PROGRAM
            or jobctl.get('executable_sha256') != product['sha256']
            or jobctl.get('executable') != inspect_executable(binary)
            or jobctl.get('build_inputs_unchanged') is not True):
        raise ValueError('native Jobctl receipt does not bind the actual runtime program')
    files[jobctl_path] = jobctl_raw
    if any(name.startswith('hepta/') or Path(name).suffix in {'.py', '.pyc', '.pyo', '.pth', '.rs', '.c', '.so', '.sh'}
           for name in files):
        raise ValueError('reference or development runtime escaped into the native distribution')
    return files


def _build_native_distribution(output, compiler, cold_report):
    """Build the ordinary production wheel from native programs and data only."""
    import platform

    if (platform.system() != 'Linux' or platform.machine() != 'x86_64'
            or ctypes.sizeof(ctypes.c_void_p) != 8):
        raise ValueError('native distribution requires Linux x86-64 LP64')
    output, compiler = Path(output).absolute(), Path(compiler).resolve(strict=True)
    cold_report = Path(cold_report).resolve(strict=True)
    compiler_bytes, cold_bytes = compiler.read_bytes(), cold_report.read_bytes()
    sources = admit_cold_build(compiler_bytes, cold_bytes)
    project = (ROOT / 'pyproject.toml').read_bytes()
    if sha256(project).hexdigest() != sources['pyproject.toml']:
        raise ValueError('native distribution metadata differs from its admitted source')
    distribution, metadata = native_distribution_metadata(project)
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    cli, inputs, _ = _native_cli_scripts(output / 'native-cli', compiler, cold_report,
                                        distribution, sources=sources)
    # This mandatory native owner is supplied by the NDU closure. No Python or
    # Rust evaluator may serve as a missing production entry.
    auxiliary, auxiliary_inputs = _native_ndu_members(output / 'native-ndu', compiler, cold_report,
                                                      sources=sources, distribution=distribution)
    inputs.update(auxiliary_inputs)
    mcp, mcp_inputs = _native_mcp_members(output / 'native-mcp', compiler, cold_report,
                                         distribution, sources=sources)
    if set(auxiliary) & set(mcp):
        raise ValueError('duplicate auxiliary native distribution role')
    auxiliary.update(mcp)
    inputs.update(mcp_inputs)
    jobctl, jobctl_inputs = _native_jobctl_members(output / 'native-jobctl', compiler, cold_report,
                                                  distribution, sources=sources)
    if set(auxiliary) & set(jobctl):
        raise ValueError('duplicate native Jobctl distribution role')
    auxiliary.update(jobctl)
    inputs.update(jobctl_inputs)
    runtime = native_runtime_members(distribution, cli, auxiliary)
    ndu = json.loads(auxiliary['hepta/_hia_ndu_scalar_build.json'])
    if (ndu['compiler_sha256'] != sha256(compiler_bytes).hexdigest()
            or ndu['cold_report_sha256'] != sha256(cold_bytes).hexdigest()
            or any(sources.get(name) != digest for name, digest in ndu['source_sha256'].items())):
        raise ValueError('native NDU receipt differs from the admitted compiler, cold report or source')
    package_members, package_inputs, package_report = _native_package_members(
        output / 'native-package', compiler, cold_report, distribution, sources=sources,
        runtime=runtime, core_receipt=inputs[output / 'native-cli/build.json'])
    if set(runtime) & set(package_members):
        raise ValueError('native package payload duplicates a distribution member')
    runtime.update(package_members)
    inputs.update(package_inputs)
    inventory = {name: {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}
                 for name, raw in sorted(runtime.items())}
    provenance = {'schema': NATIVE_DISTRIBUTION_SCHEMA, 'distribution_profile': 'native-production',
        'target': TARGET, 'source_manifest': sources, 'source_identity_sha256': source_identity(sources),
        'compiler_sha256': sha256(compiler_bytes).hexdigest(), 'cold_report_sha256': sha256(cold_bytes).hexdigest(),
        'runtime_members': inventory, 'python_runtime_members': [], 'native_entry_required': True,
        'complete_native_package': package_report['package'],
        'complete_native_package_member_count': len(package_report['members']),
        'complete_native_package_source_attested': True,
        'worker_controller_installer_supplied_by_contained_package': True,
        'retained_reference_bodies_removed': True, 'whole_native_delivery_qualified': False,
        'production_activated': False}
    files = {**metadata, **runtime, distribution + '/native-runtime.json': encoded(provenance)}
    images = _wheel_record_images(output / 'wheel-record', compiler, sources, cold_bytes)
    if (current_sources() != sources or compiler.read_bytes() != compiler_bytes
            or cold_report.read_bytes() != cold_bytes or (ROOT / 'pyproject.toml').read_bytes() != project
            or any(path.read_bytes() != raw for path, raw in inputs.items())):
        raise ValueError('native distribution inputs changed before publication')
    stem = distribution.removesuffix('.dist-info')
    wheel = output / (stem + '-' + NATIVE_BUILD_TAG + '-' + WHEEL_TAG + '.whl')
    members = _write_wheel(wheel, files, distribution, images)
    report = {**provenance, 'schema': NATIVE_BUILD_SCHEMA, 'wheel': str(wheel),
        'wheel_sha256': sha256(wheel.read_bytes()).hexdigest(), 'wheel_tag': WHEEL_TAG,
        'members': members, 'public_cli_entry': 'native-elf', 'ordinary_source_default_changed': True,
        'matching_source_cold_component': True, 'installed_default_qualification_completed': False,
        'python_library_wheel_command': None}
    (output / 'build.json').write_bytes(encoded(report))
    return wheel


def build_reference_wheel(output, compiler, cold_report):
    """Explicit hosted API/oracle distribution, excluded from ordinary production."""
    return build(output, compiler, cold_report, reference=True)


def build(output, compiler, cold_report=None, *, development=False, reference=False):
    if (type(development) is not bool or type(reference) is not bool
            or development and reference or development == (cold_report is not None)):
        raise ValueError('choose one matching cold report, explicit reference wheel, or development construction')
    if not development and not reference:
        return _build_native_distribution(output, compiler, cold_report)
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
        ndu_members, ndu_inputs = _native_ndu_members(
            output / 'native-ndu', compiler, cold_report, sources=sources, distribution=distribution)
        owner_members.update(ndu_members)
        owner_inputs.update(ndu_inputs)
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
        'distribution_profile': 'development-reference' if development else 'reference-only',
        'reference_only': True,
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
        'ordinary_source_default_changed': False, 'retained_reference_bodies_removed': False,
        'distribution_profile': 'development-reference' if development else 'reference-only',
        'reference_only': True,
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
    parser.add_argument('--reference', action='store_true',
                        help='explicit hosted API/oracle wheel; excluded from ordinary production')
    args = parser.parse_args()
    print(build(args.output, args.compiler, args.cold_report, development=args.development, reference=args.reference))


if __name__ == '__main__':
    main()
