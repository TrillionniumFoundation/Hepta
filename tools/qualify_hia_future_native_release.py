"""Rebuild the matching Future family from HIA sources, without a host linker.

This is a development qualification driver. It executes the sealed native HIA
compiler and the actual compiled HIA packers; production uses the HIASTD01 DAG.
"""
from __future__ import annotations
import argparse
import ctypes
import hashlib
import json
import mmap
from pathlib import Path
import struct
import subprocess

ROOT = Path(__file__).resolve().parents[1]
BOOT = 'examples/hia_bootstrap/'
COMPILER_SHA256 = '494833999e25ac74ea6ad1de41235c01bfa036951f212604026cb8be686c78af'
VALUE_ROLES = ('result_value_owner', 'result_value_core', 'result_value_import',
               'result_value_export', 'background_optimizer_json_capture',
               'agent_binary64_format', 'result_value_binary64')
PUBLIC_ROLES = ('background_optimizer_future_public_owner',
                'background_optimizer_future_public_carrier',
                'background_optimizer_future_public_timeout',
                'background_optimizer_future_public_log',
                'multiversion_background_future_cell', 'multiversion_future')
PRODUCTS = {
    'hia-result-value.core.bin': (990342, '6d769f3369ceaebed9602a784166548ed2cf48fed608a80a572b1a9c73cc3a7c'),
    'hia-future-notify.core.bin': (80226, '4a06fc521a47285685a6632e0f17b876364ee5e934bb81f5eb3f4195dc263580'),
    'hia-future-public.core.bin': (1991586, '6615552f0a51de92ae2eba6294339167089572fa8db61ecd71751637aae4838f'),
    'hia-future-observers.core.bin': (301031, '640bda6bf540218f7e8b02c33b5c48c37681c19b2c74363b3ae5ceb46ef642ba'),
    'hia-future-iterable.core.bin': (513782, '5b4c98c6325abb9b597e70574f8cc7136af7db8758a7e2fde5910c3cd8d0fb9f'),
}


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


class NativeFlat:
    def __init__(self, raw):
        self.mapping = mmap.mmap(-1, len(raw), prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
        self.mapping.write(raw)
        address = ctypes.addressof(ctypes.c_ubyte.from_buffer(self.mapping))
        abi = ctypes.CFUNCTYPE(ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint64,
                              ctypes.c_void_p, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_uint64)
        self.function = abi(address)

    def call(self, wire, *, capacity=8 << 20, work_capacity=16 << 20):
        source = ctypes.create_string_buffer(wire, max(1, len(wire)))
        output = ctypes.create_string_buffer(capacity)
        workspace = ctypes.create_string_buffer(work_capacity)
        result = self.function(source, len(wire), output, capacity, workspace, work_capacity)
        return result, output.raw, workspace.raw


def filter_executable(flat):
    from tools.generate_hia_native_filter import template
    prefix, calls = template(wire_bytes=8 << 20, output_bytes=8 << 20, workspace_bytes=16 << 20)
    assert len(calls) == 1
    image = bytearray(prefix + flat)
    struct.pack_into('<i', image, calls[0], len(prefix) - calls[0] - 4)
    struct.pack_into('<2Q', image, 96, len(image), len(image))
    return bytes(image)


def source_paths():
    inherited = json.loads((ROOT / 'docs/HIA_BACKGROUND_NATIVE_FUTURE_INHERITED.json').read_text())
    value = json.loads((ROOT / 'docs/HIA_RESULT_VALUE_NATIVE.json').read_text())
    rows = inherited['runtime_sources'] + value['source_authority']
    for row in rows:
        raw = (ROOT / row['path']).read_bytes()
        assert len(raw) == row['bytes'] and digest(raw) == row['sha256'], row['path']
    paths = {row['path'] for row in rows if row['path'].endswith('.hepta')}
    paths.add(BOOT + 'background_optimizer_future_release_packer.hepta')
    paths.update(BOOT + name for name in ('source_native_filter_pack.hepta', 'native_filter_packer.hepta',
                                        'selfhost.hepta', 'source_release_kit.hepta', 'source_build_packer.hepta'))
    return sorted(paths)


def qualify(compiler, output):
    compiler = Path(compiler).resolve()
    assert compiler.stat().st_size == 813129 and digest(compiler.read_bytes()) == COMPILER_SHA256
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    modules = []
    flats = {}
    for path in source_paths():
        raw = (ROOT / path).read_bytes()
        rounds = []
        for _ in range(2):
            result = subprocess.run([str(compiler), 'compile'], input=raw, capture_output=True, timeout=30)
            assert result.returncode == 0 and not result.stderr and result.stdout, (path, result.returncode, result.stderr)
            rounds.append(result.stdout)
        assert rounds[0] == rounds[1], path
        flat = rounds[0]
        name = Path(path).stem
        flats[name] = flat
        (output / (name + '.flat')).write_bytes(flat)
        modules.append(dict(source_path=path, source_bytes=len(raw), source_sha256=digest(raw),
                            flat_bytes=len(flat), flat_sha256=digest(flat), double_compile_identical=True))
    checks = []
    wrappers = {}

    def executable_file(name, image):
        path = output / name
        if path.exists():
            assert path.read_bytes() == image, name
        else:
            path.write_bytes(image)
            path.chmod(0o500)
        return path

    # Execute the same three-source kit construction used by the native DAG.
    # Both compilation and final ELF packing execute the retained HIA compiler.
    kit_sources = {alias: (ROOT / BOOT / name).read_bytes() for alias, name in (
        ('source_build_policy.hepta', 'source_native_filter_pack.hepta'),
        ('selfhost.hepta', 'selfhost.hepta'),
        ('source_build_packer.hepta', 'native_filter_packer.hepta'))}
    wire = bytearray(b'HIAREL01' + struct.pack('<2Q', len(kit_sources), 0))
    for alias, raw in kit_sources.items():
        wire += struct.pack('<3Q', len(alias), 0o400, len(raw)) + alias.encode('ascii') + raw
    kit_build = subprocess.run([str(compiler), 'build'], input=bytes(wire), capture_output=True, timeout=30)
    assert kit_build.returncode == 0 and not kit_build.stderr
    from tools.build_hia_source_build import _compiled_sources
    kit_images = _compiled_sources(kit_build.stdout, kit_sources)
    assert kit_images == {alias: flats[name] for alias, name in (
        ('source_build_policy.hepta', 'source_native_filter_pack'),
        ('selfhost.hepta', 'selfhost'), ('source_build_packer.hepta', 'native_filter_packer'))}
    kit_pack = subprocess.run([str(compiler), 'pack'], input=kit_build.stdout, capture_output=True, timeout=30)
    assert kit_pack.returncode == 0 and not kit_pack.stderr and kit_pack.stdout
    kit_path = executable_file('native-filter-source-kit', kit_pack.stdout)
    checks.append('native three-source kit compilation preserves every source and compiled image')
    # DAG node 3 retains the object-view footer. Digesting that handle means
    # digesting ELF + footer; only execution extracts the leading ELF extent.
    composer_sources = {alias: (ROOT / BOOT / name).read_bytes() for alias, name in (
        ('source_build_policy.hepta', 'source_release_kit.hepta'),
        ('selfhost.hepta', 'selfhost.hepta'),
        ('source_build_packer.hepta', 'source_build_packer.hepta'))}
    wire = bytearray(b'HIAREL01' + struct.pack('<2Q', len(composer_sources), 0))
    for alias, raw in composer_sources.items():
        wire += struct.pack('<3Q', len(alias), 0o400, len(raw)) + alias.encode('ascii') + raw
    built = subprocess.run([str(compiler), 'build'], input=bytes(wire), capture_output=True, timeout=30)
    assert built.returncode == 0 and not built.stderr
    assert _compiled_sources(built.stdout, composer_sources) == {alias: flats[name] for alias, name in (
        ('source_build_policy.hepta', 'source_release_kit'), ('selfhost.hepta', 'selfhost'),
        ('source_build_packer.hepta', 'source_build_packer'))}
    composer = subprocess.run([str(compiler), 'pack'], input=built.stdout, capture_output=True, timeout=30)
    assert composer.returncode == 0 and not composer.stderr and composer.stdout
    composer_path = executable_file('native-release-kit-composer', composer.stdout)
    request = bytearray(b'HIAKOBJ1' + struct.pack('<Q', len(kit_sources)))
    for alias, raw in kit_sources.items():
        request += struct.pack('<2Q', len(alias), len(raw)) + alias.encode('ascii') + raw
    framed = subprocess.run([str(composer_path), 'build'], input=bytes(request), capture_output=True, timeout=30)
    assert framed.returncode == 0 and not framed.stderr
    elf_size, *fields, magic = struct.unpack_from('<7Q8s', framed.stdout, len(framed.stdout) - 64)
    sizes, sites = fields[:3], fields[3:]
    assert magic == b'HIAKIMG1' and elf_size == len(framed.stdout) - 64
    assert framed.stdout[:elf_size] == kit_pack.stdout
    start = elf_size - sum(sizes)
    assert start >= 176 and len(set(sites)) == 3
    prefix_size = start
    for alias, size, site in zip(kit_sources, sizes, sites, strict=True):
        assert 176 < site <= prefix_size - 4 and framed.stdout[site - 1] == 0xe8
        assert site + 4 + struct.unpack_from('<i', framed.stdout, site)[0] == start
        assert framed.stdout[start:start + size] == kit_images[alias]
        start += size
    checks.append('actual native DAG kit frame binds the exact executable and all three object spans')

    def packed(name, wire, expected_status=False):
        native = NativeFlat(flats[name])
        status, image, work = native.call(wire)
        if expected_status:
            assert status == 0, (name, status)
            length = struct.unpack_from('<Q', work)[0]
        else:
            assert 0 < status < (8 << 20), (name, status)
            length = status
        return image[:length]

    def run_filter(name, wire):
        request = b'HIANPF01' + struct.pack('<2Q', 1, len(flats[name])) + flats[name]
        built = subprocess.run([str(kit_path), 'build'], input=request, capture_output=True, timeout=30)
        assert built.returncode == 0 and not built.stderr, (name, built.returncode, built.stderr)
        image = built.stdout
        assert image == filter_executable(flats[name]), name
        path = executable_file(name + '.filter', image)
        wrappers[name] = dict(bytes=len(image), sha256=digest(image))
        process = subprocess.run([str(path)], input=wire, capture_output=True, timeout=30)
        assert process.returncode == 0 and not process.stderr and process.stdout, (name, process.returncode, process.stderr)
        return process.stdout

    value_parts = [flats[name] for name in VALUE_ROLES]
    value_wire = b'HIABVP01' + struct.pack('<9Q', 7, *(len(part) for part in value_parts), 1) + b''.join(value_parts)
    value = run_filter('result_value_packer', value_wire)
    assert value == packed('result_value_packer', value_wire)
    checks.append('value native packer and native filter are byte-identical')
    notify_wire = b'HIABFNPK' + struct.pack('<3Q', len(flats['background_optimizer_future_public_observers_notify']), 0, 0) + flats['background_optimizer_future_public_observers_notify']
    notify = run_filter('background_optimizer_future_release_packer', notify_wire)
    assert notify == packed('background_optimizer_future_public_observers_notify_packer', notify_wire, True)
    checks.append('notify status-to-extent adapter preserves the original packed image')
    public_parts = [flats[name] for name in PUBLIC_ROLES] + [value, notify]
    public_wire = b'HIABFPP2' + struct.pack('<10Q', 8, *(len(part) for part in public_parts), 1) + b''.join(public_parts)
    public = run_filter('background_optimizer_future_public_packer', public_wire)
    assert public == packed('background_optimizer_future_public_packer', public_wire)
    checks.append('public native packer and native filter are byte-identical')
    array_parts = [flats['background_optimizer_future_public_observers'], flats['background_optimizer_future_public_observers_math']]
    array_wire = b'HIABFOPK' + struct.pack('<3Q', *(len(part) for part in array_parts), 0) + b''.join(array_parts)
    array = run_filter('background_optimizer_future_release_packer', array_wire)
    assert array == packed('background_optimizer_future_public_observers_packer', array_wire, True)
    checks.append('array status-to-extent adapter preserves the original packed image')
    iterable_parts = [flats['background_optimizer_future_public_observers_iterable'], array]
    iterable_wire = b'HIABFAPK' + struct.pack('<3Q', *(len(part) for part in iterable_parts), 0) + b''.join(iterable_parts)
    iterable = run_filter('background_optimizer_future_release_packer', iterable_wire)
    assert iterable == packed('background_optimizer_future_public_observers_iterable_packer', iterable_wire, True)
    checks.append('iterable status-to-extent adapter preserves the original packed image')
    products = {}
    for name, raw in zip(PRODUCTS, (value, notify, public, array, iterable)):
        expected = PRODUCTS[name]
        assert (len(raw), digest(raw)) == expected, (name, len(raw), digest(raw))
        (output / name).write_bytes(raw)
        products[name] = dict(bytes=len(raw), sha256=digest(raw))
    adapter = NativeFlat(flats['background_optimizer_future_release_packer'])
    for wire, label in ((b'', 'empty input'), (b'not-a-HIA-packer', 'unknown packer magic'),
                        (notify_wire[:-1], 'truncated notify'), (array_wire[:-1], 'truncated array'),
                        (iterable_wire[:-1], 'truncated iterable')):
        status, out, _ = adapter.call(wire)
        assert status == 4294967293 and not any(out), label
        checks.append(label + ' rejected without output')
    for wire, label in ((notify_wire, 'notify'), (array_wire, 'array'), (iterable_wire, 'iterable')):
        status, out, _ = adapter.call(wire, capacity=32)
        assert status == 4294967294 and not any(out), label
        status, out, _ = adapter.call(wire, work_capacity=63)
        assert status == 4294967293 and not any(out), label
        checks.append(label + ' output/workspace bounds preserve original errors')
        malformed = bytearray(wire)
        struct.pack_into('<Q', malformed, 24, 1)
        status, out, _ = adapter.call(bytes(malformed))
        assert status == 4294967293 and not any(out), label
        checks.append(label + ' nonzero reserved field rejected without output')
    source_files = {row['source_path']: row['source_sha256'] for row in modules}
    for row in modules:
        assert digest((ROOT / row['source_path']).read_bytes()) == row['source_sha256'], row['source_path']
    assert digest(compiler.read_bytes()) == COMPILER_SHA256
    for name in ('hia_result_value_bridge.S', 'hia_background_optimizer_future_public_bridge.S',
                 'hia_background_optimizer_future_public_observers_bridge.S',
                 'hia_background_optimizer_future_public_observers_iterable_bridge.S',
                 'hia_background_optimizer_future_public_observers_notify_bridge.S'):
        source_files['tools/' + name] = digest((ROOT / 'tools' / name).read_bytes())
    report = dict(schema='hepta.hia.future-native-release-build.v1', status='PASS',
                  source_base_commit='ecd688626409d1adcf4e04a7a535c1b2c45a13ce',
                  compiler=dict(bytes=813129, sha256=COMPILER_SHA256), modules=modules,
                  source_files=source_files,
                  native_filter_kit=dict(bytes=len(kit_pack.stdout), sha256=digest(kit_pack.stdout),
                                         source_bundle_sha256=digest(kit_build.stdout),
                                         dag_frame_bytes=len(framed.stdout), dag_frame_sha256=digest(framed.stdout),
                                         composer_bytes=len(composer.stdout), composer_sha256=digest(composer.stdout)),
                  wrappers=wrappers, products=products, checks=checks,
                  whole_public_future_closed=False, whole_background_optimizer_closed=False,
                  final_unified_dispatcher_qualified=False, production_activated=False)
    (output / 'build.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compiler', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    report = qualify(args.compiler, args.output)
    print(json.dumps({'status': report['status'], 'modules': len(report['modules']),
                      'products': report['products'], 'checks': len(report['checks'])}, indent=2))


if __name__ == '__main__':
    main()
