"""Rebuild the matching Future family from HIA sources, without a host linker.

This is a development qualification driver. It executes the sealed native HIA
compiler and the actual compiled HIA packers; production uses the HIASTD01 DAG.
"""
from __future__ import annotations
import argparse
import ctypes
import hashlib
import json
import importlib
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
RECORD_VALUE_ROLES = VALUE_ROLES + ('result_value_dict_iterator', 'result_value_classes',
                                  'native_class_mro', 'result_value_records')
RESOURCE_VALUE_ROLES = RECORD_VALUE_ROLES + ('result_value_resources',)
PUBLIC_ROLES = ('background_optimizer_future_public_owner',
                'background_optimizer_future_public_carrier',
                'background_optimizer_future_public_timeout',
                'background_optimizer_future_public_log',
                'multiversion_background_future_cell', 'multiversion_future')
CANCELLATION_ROLES = ('publication_cancellation_public', 'multiversion_runtime_handles',
                      'publication_cancellation_effects', 'multiversion_future')
PRODUCTS = {
    'hia-result-value.core.bin': (990342, '6d769f3369ceaebed9602a784166548ed2cf48fed608a80a572b1a9c73cc3a7c'),
    'hia-future-notify.core.bin': (80226, '4a06fc521a47285685a6632e0f17b876364ee5e934bb81f5eb3f4195dc263580'),
    'hia-future-public.core.bin': (1991586, '6615552f0a51de92ae2eba6294339167089572fa8db61ecd71751637aae4838f'),
    'hia-future-observers.core.bin': (301031, '640bda6bf540218f7e8b02c33b5c48c37681c19b2c74363b3ae5ceb46ef642ba'),
    'hia-future-iterable.core.bin': (513782, '5b4c98c6325abb9b597e70574f8cc7136af7db8758a7e2fde5910c3cd8d0fb9f'),
    'hia-publication-cancellation.core.bin': (364751, '6458c979f848747478e4fc0fdfb15d74adec63e849558a9e22c800cb3b94ffe0'),
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


def admitted_value_qualification(path):
    """Admit exact separately qualified records or resource-capable Value sources."""
    path = Path(path).resolve()
    receipt_bytes = path.read_bytes()
    receipt = json.loads(receipt_bytes)
    assert path.is_relative_to(ROOT) and receipt['component_qualified'] is True
    construction = receipt['construction']
    assert construction['compiler']['sha256'] == COMPILER_SHA256
    assert construction['compiler']['bytes'] == 813129
    protocol = receipt.get('value_protocol', 'HIABVP04')
    assert protocol in ('HIABVP04', 'HIABVP05')
    roles = RECORD_VALUE_ROLES
    packer = 'result_value_records_packer'
    bridge_path = 'tools/hia_result_value_records_bridge.S'
    if protocol == 'HIABVP05':
        assert receipt['original_six_campaigns_qualified'] is True
        assert receipt['value_roles'] == ['owner','core','import','export','capture','format','number','dict_iterator','classes','class_mro','records','resources']
        assert receipt['value_packer'] == BOOT + 'result_value_resources_packer.hepta'
        roles = RESOURCE_VALUE_ROLES
        packer = 'result_value_resources_packer'
        bridge_path = 'tools/hia_result_value_resources_bridge.S'
    rows = construction['roles']
    by_path = {row['source_path']: row for row in rows}
    assert len(by_path) == len(rows)
    required = {BOOT + name + '.hepta' for name in roles}
    required.add(BOOT + packer + '.hepta')
    assert required.issubset(by_path), sorted(required - set(by_path))
    admitted = []
    for name in sorted(required):
        row = by_path[name]
        assert row['two_compile_byteequal'] is True
        raw = (ROOT / name).read_bytes()
        assert len(raw) == row['source_bytes'] and digest(raw) == row['source_sha256'], name
        admitted.append(dict(path=name, bytes=len(raw), sha256=digest(raw)))
    product = construction['products']['value-component.flat']
    assert product['native_pack'] is True and product['independent_byte_comparison'] is True
    mechanical = {}
    assert bridge_path in receipt['source_files']
    for name, expected in receipt['source_files'].items():
        candidate = ROOT / name
        assert candidate.resolve().is_relative_to(ROOT) and not candidate.is_symlink(), name
        raw = candidate.read_bytes()
        if isinstance(expected, dict):
            assert set(expected) == {'bytes', 'sha256'}, name
            assert {'bytes': len(raw), 'sha256': digest(raw)} == expected, name
            mechanical[name] = expected['sha256']
        else:
            assert isinstance(expected, str) and digest(raw) == expected, name
            mechanical[name] = expected
    module_pins = {name: dict(bytes=by_path[name]['bytes'], sha256=by_path[name]['sha256'])
                   for name in required}
    return dict(path=path.relative_to(ROOT).as_posix(), sha256=digest(receipt_bytes),
                rows=admitted, product=product, receipt=receipt,
                module_pins=module_pins, protocol=protocol, roles=roles, packer=packer,
                bridge_path=bridge_path,
                mechanical_sources={name: pin for name, pin in mechanical.items() if name.endswith('.S')},
                development_sources={name: pin for name, pin in mechanical.items() if name.endswith('.py')})

def admitted_future_kind_qualification(path, value_qualification):
    path = Path(path).resolve()
    receipt_bytes = path.read_bytes()
    receipt = json.loads(receipt_bytes)
    assert path.is_relative_to(ROOT) and receipt['component_qualified'] is True
    assert receipt['compiler']['bytes'] == 813129
    assert receipt['compiler']['sha256'] == COMPILER_SHA256
    assert receipt['value_image_sha256'] == value_qualification['product']['sha256']
    retirement = receipt['schema'] == 'hepta.hia.future-retirement-qualification.v1'
    names = ('background_optimizer_future_public_owner',)
    packer = 'background_optimizer_future_public_packer'
    magic = 'HIABFPP2'
    bridge_path = 'tools/hia_background_optimizer_future_public_bridge.S'
    if retirement:
        assert receipt['roles'] == ['owner','carrier','timeout','log','cell','kernel','value','notify','cleanup']
        assert len(receipt['original_value_kind_cases']) == 62
        assert all(row['passed'] for row in receipt['original_value_kind_cases'])
        assert len(receipt['retirement_cases']) == 4 and all(row['passed'] for row in receipt['retirement_cases'])
        assert len(receipt['native_packer_controls']) == 50 and all(row['passed'] for row in receipt['native_packer_controls'])
        assert receipt.get('value_protocol','HIABVP04') == value_qualification['protocol']
        names = PUBLIC_ROLES + ('background_optimizer_future_public_cleanup',
                                'background_optimizer_future_public_cleanup_packer')
        packer = 'background_optimizer_future_public_cleanup_packer'
        magic = 'HIABFPP3'
        bridge_path = 'tools/hia_background_optimizer_future_public_cleanup_bridge.S'
    rows = {row['source_path']: row for row in receipt['modules']}
    assert len(rows) == len(receipt['modules'])
    admitted = {}
    module_pins = {}
    for name in names:
        source_path = BOOT + name + '.hepta'
        row = rows[source_path]
        assert row['double_compile_identical'] is True
        raw = (ROOT / source_path).read_bytes()
        assert (len(raw), digest(raw)) == (row['source_bytes'], row['source_sha256'])
        admitted[source_path] = dict(path=source_path, bytes=len(raw), sha256=digest(raw))
        module_pins[source_path] = dict(bytes=row['flat_bytes'], sha256=row['flat_sha256'])
    for name, expected in receipt.get('source_files', {}).items():
        candidate = ROOT / name
        assert candidate.resolve().is_relative_to(ROOT) and not candidate.is_symlink()
        assert digest(candidate.read_bytes()) == expected, name
    product = receipt['public_product']
    assert product['bytes'] > 0 and len(product['sha256']) == 64
    return dict(path=path.relative_to(ROOT).as_posix(), sha256=digest(receipt_bytes),
                rows=admitted, module_pins=module_pins, product=product,
                has_cleanup=retirement, public_packer=packer, public_protocol=magic,
                bridge_path=bridge_path,
                mechanical_sources={name: pin for name, pin in receipt.get('source_files', {}).items() if name.endswith('.S')},
                development_sources={name: pin for name, pin in receipt.get('source_files', {}).items() if name.endswith('.py')})

def source_paths(value_qualification=None, future_kind_qualification=None):
    inherited = json.loads((ROOT / 'docs/HIA_BACKGROUND_NATIVE_FUTURE_INHERITED.json').read_text())
    if value_qualification is None:
        value = json.loads((ROOT / 'docs/HIA_RESULT_VALUE_NATIVE.json').read_text())
        value_rows = value['source_authority']
    else:
        value_rows = value_qualification['rows']
    inherited_rows = inherited['runtime_sources']
    if future_kind_qualification is not None:
        replacements = future_kind_qualification['rows']
        existing = {row['path'] for row in inherited_rows}
        additional = set(replacements) - existing
        allowed = {BOOT + name + '.hepta' for name in ('background_optimizer_future_public_cleanup', 'background_optimizer_future_public_cleanup_packer')} if future_kind_qualification['has_cleanup'] else set()
        assert additional.issubset(allowed), sorted(additional - allowed)
        inherited_rows = [replacements.get(row['path'], row) for row in inherited_rows]
        inherited_rows += [replacements[name] for name in sorted(additional)]
    rows = inherited_rows + value_rows
    for row in rows:
        raw = (ROOT / row['path']).read_bytes()
        assert len(raw) == row['bytes'] and digest(raw) == row['sha256'], row['path']
    paths = {row['path'] for row in rows if row['path'].endswith('.hepta')}
    paths.add(BOOT + 'background_optimizer_future_release_packer.hepta')
    if future_kind_qualification is not None and future_kind_qualification['has_cleanup']:
        paths.discard(BOOT + 'background_optimizer_future_public_packer.hepta')
    cancellation = json.loads((ROOT / 'docs/HIA_PUBLICATION_CANCELLATION_NATIVE.json').read_text())
    assert cancellation['qualified'] and not cancellation['whole_native_runtime']
    assert not cancellation['final_aggregate_claimed'] and cancellation['compiler_sha256'] == COMPILER_SHA256
    for row in cancellation['build']:
        path = BOOT + row['role'] + '.hepta'
        raw = (ROOT / path).read_bytes()
        assert len(raw) == row['source_bytes'] and digest(raw) == row['source_sha256'], path
        paths.add(path)
    paths.update(BOOT + name for name in ('source_native_filter_pack.hepta', 'native_filter_packer.hepta',
                                        'selfhost.hepta', 'source_release_kit.hepta', 'source_build_packer.hepta'))
    return sorted(paths)


def qualify(compiler, output, *, value_qualification_path=None, future_kind_qualification_path=None,
            behavior_qualification_path=None):
    compiler = Path(compiler).resolve()
    assert compiler.stat().st_size == 813129 and digest(compiler.read_bytes()) == COMPILER_SHA256
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    value_qualification = (None if value_qualification_path is None
                           else admitted_value_qualification(value_qualification_path))
    future_kind_qualification = None
    if value_qualification is not None:
        assert future_kind_qualification_path is not None, 'complete Value requires actual Future type qualification'
        future_kind_qualification = admitted_future_kind_qualification(
            future_kind_qualification_path, value_qualification)
    else:
        assert future_kind_qualification_path is None
    if behavior_qualification_path is not None:
        assert value_qualification is not None, 'behavior requalification requires the exact Value receipt'
    modules = []
    flats = {}
    for path in source_paths(value_qualification, future_kind_qualification):
        raw = (ROOT / path).read_bytes()
        rounds = []
        for _ in range(2):
            result = subprocess.run([str(compiler), 'compile'], input=raw, capture_output=True, timeout=30)
            assert result.returncode == 0 and not result.stderr and result.stdout, (path, result.returncode, result.stderr)
            rounds.append(result.stdout)
        assert rounds[0] == rounds[1], path
        flat = rounds[0]
        if value_qualification is not None and path in value_qualification['module_pins']:
            pin = value_qualification['module_pins'][path]
            assert (len(flat), digest(flat)) == (pin['bytes'], pin['sha256']), path
        if future_kind_qualification is not None and path in future_kind_qualification['module_pins']:
            pin = future_kind_qualification['module_pins'][path]
            assert (len(flat), digest(flat)) == (pin['bytes'], pin['sha256']), path
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

    value_roles = VALUE_ROLES if value_qualification is None else value_qualification['roles']
    value_packer = 'result_value_packer' if value_qualification is None else value_qualification['packer']
    value_magic = b'HIABVP01' if value_qualification is None else value_qualification['protocol'].encode('ascii')
    value_parts = [flats[name] for name in value_roles]
    value_wire = (value_magic + struct.pack('<' + str(len(value_parts) + 2) + 'Q',
                  len(value_parts), *(len(part) for part in value_parts), 1) + b''.join(value_parts))
    value = run_filter(value_packer, value_wire)
    assert value == packed(value_packer, value_wire)
    if value_qualification is not None:
        expected = value_qualification['product']
        assert (len(value), digest(value)) == (expected['bytes'], expected['sha256'])
        checks.append('native Value matches its separately qualified exact role product')
    checks.append('value native packer and native filter are byte-identical')
    notify_wire = b'HIABFNPK' + struct.pack('<3Q', len(flats['background_optimizer_future_public_observers_notify']), 0, 0) + flats['background_optimizer_future_public_observers_notify']
    notify = run_filter('background_optimizer_future_release_packer', notify_wire)
    assert notify == packed('background_optimizer_future_public_observers_notify_packer', notify_wire, True)
    checks.append('notify status-to-extent adapter preserves the original packed image')
    public_parts = [flats[name] for name in PUBLIC_ROLES] + [value, notify]
    has_cleanup = future_kind_qualification is not None and future_kind_qualification['has_cleanup']
    public_packer = ('background_optimizer_future_public_packer' if future_kind_qualification is None
                     else future_kind_qualification['public_packer'])
    public_magic = ('HIABFPP2' if future_kind_qualification is None
                    else future_kind_qualification['public_protocol'])
    if has_cleanup:
        public_parts.append(flats['background_optimizer_future_public_cleanup'])
    def public_frame(mode):
        return public_magic.encode('ascii') + struct.pack('<' + str(len(public_parts) + 2) + 'Q',
            len(public_parts), *(len(part) for part in public_parts), mode) + b''.join(public_parts)
    public_wire = public_frame(1)
    public = run_filter(public_packer, public_wire)
    assert public == packed(public_packer, public_wire)
    public_author = importlib.import_module('tools.generate_hia_' + public_packer)
    assert public == public_author.reference_flat(public_parts)
    if future_kind_qualification is not None:
        expected = future_kind_qualification['product']
        assert (len(public), digest(public)) == (expected['bytes'], expected['sha256'])
        checks.append('complete Future product matches actual qualified native type semantics')
    checks.append('public native packer, native filter and independent relocation reference are byte-identical')
    object_wire = public_frame(0)
    public_object = run_filter(public_packer, object_wire)
    assert public_object == packed(public_packer, object_wire)
    assert public_object == public_author.reference_object(public_parts)
    (output / 'hia-future-public.o').write_bytes(public_object)
    checks.append('public ELF object is actually native packed and matches independent relocation reference')
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
    parts = [flats[name] for name in CANCELLATION_ROLES]
    cancellation_wire = b'HIAPCPK1' + struct.pack('<7Q', 4, *(len(part) for part in parts), 0, 0) + b''.join(parts)
    cancellation = run_filter('publication_cancellation_packer', cancellation_wire)
    assert cancellation == packed('publication_cancellation_packer', cancellation_wire)
    checks.append('public cancellation native packer and native filter are byte-identical')
    products = {}
    for name, raw in zip(PRODUCTS, (value, notify, public, array, iterable, cancellation), strict=True):
        if value_qualification is not None and name in ('hia-result-value.core.bin', 'hia-future-public.core.bin'):
            # These two products now capture the qualified complete Value implementation.
            # Their construction is checked above; a build alone cannot promote this family.
            assert raw
        else:
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
    value_bridge = ('hia_result_value_bridge.S' if value_qualification is None
                    else Path(value_qualification['bridge_path']).name)
    public_bridge = ('hia_background_optimizer_future_public_bridge.S' if future_kind_qualification is None
                     else Path(future_kind_qualification['bridge_path']).name)
    for name in (value_bridge, public_bridge,
                 'hia_background_optimizer_future_public_observers_bridge.S',
                 'hia_background_optimizer_future_public_observers_iterable_bridge.S',
                 'hia_background_optimizer_future_public_observers_notify_bridge.S',
                 'hia_publication_cancellation_bridge.S'):
        source_files['tools/' + name] = digest((ROOT / 'tools' / name).read_bytes())
    cancellation_receipt = 'docs/HIA_PUBLICATION_CANCELLATION_NATIVE.json'
    source_files[cancellation_receipt] = digest((ROOT / cancellation_receipt).read_bytes())
    status = 'PASS' if value_qualification is None else 'BUILT_PENDING_FUTURE_BEHAVIOR'
    behavior = None
    if value_qualification is not None:
        for name, pin in value_qualification['mechanical_sources'].items():
            assert digest((ROOT / name).read_bytes()) == pin, name
            assert name not in source_files or source_files[name] == pin, name
            source_files[name] = pin
        source_files[value_qualification['path']] = value_qualification['sha256']
        assert digest((ROOT / value_qualification['path']).read_bytes()) == value_qualification['sha256']
        assert future_kind_qualification is not None
        for name, pin in future_kind_qualification['mechanical_sources'].items():
            assert digest((ROOT / name).read_bytes()) == pin, name
            assert name not in source_files or source_files[name] == pin, name
            source_files[name] = pin
        source_files[future_kind_qualification['path']] = future_kind_qualification['sha256']
        assert digest((ROOT / future_kind_qualification['path']).read_bytes()) == future_kind_qualification['sha256']
        if behavior_qualification_path is not None:
            behavior_path = Path(behavior_qualification_path).resolve()
            behavior_bytes = behavior_path.read_bytes()
            behavior = json.loads(behavior_bytes)
            assert behavior['schema'] == 'hepta.hia.future-value-integration-qualification.v1'
            assert behavior['passed'] is True and behavior['groups'] == 27
            assert len(behavior['rows']) == 27 and all(row['returncode'] == 0 for row in behavior['rows'])
            assert behavior['products'] == products
            assert behavior['source_files'] == source_files
            assert behavior['compiler_sha256'] == COMPILER_SHA256
            assert behavior['source_frozen_through_campaigns'] is True
            assert behavior['original_domains_and_assertions_unchanged'] is True
            source_files[behavior_path.relative_to(ROOT).as_posix()] = digest(behavior_bytes)
            status = 'PASS'
    report = dict(schema='hepta.hia.future-native-release-build.v1', status=status,
                  source_base_commit=subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
                  compiler=dict(bytes=813129, sha256=COMPILER_SHA256), modules=modules,
                  source_files=source_files,
                  development_source_provenance=({} if value_qualification is None else
                      {**value_qualification['development_sources'], **future_kind_qualification['development_sources']}),
                  native_filter_kit=dict(bytes=len(kit_pack.stdout), sha256=digest(kit_pack.stdout),
                                         source_bundle_sha256=digest(kit_build.stdout),
                                         dag_frame_bytes=len(framed.stdout), dag_frame_sha256=digest(framed.stdout),
                                         composer_bytes=len(composer.stdout), composer_sha256=digest(composer.stdout)),
                  wrappers=wrappers, products=products, checks=checks,
                  value_protocol=value_magic.decode('ascii'), value_roles=list(value_roles),
                  value_packer=value_packer, public_protocol=public_magic, public_packer=public_packer,
                  public_has_cleanup=has_cleanup,
                  public_roles=['owner','carrier','timeout','log','cell','kernel','value','notify'] + (['cleanup'] if has_cleanup else []),
                  value_qualification=(None if value_qualification is None else
                      {key: value_qualification[key] for key in ('path', 'sha256')}),
                  future_kind_qualification=(None if future_kind_qualification is None else
                      {key: future_kind_qualification[key] for key in ('path', 'sha256')}),
                  value_class_queries_qualified=future_kind_qualification is not None,
                  inherited_behavior_requalified=behavior is not None,
                  whole_public_future_closed=False, whole_background_optimizer_closed=False,
                  final_unified_dispatcher_qualified=False, production_activated=False)
    (output / 'build.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compiler', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--value-qualification', type=Path,
                        help='exact qualified complete Value receipt; leaves family pending until all inherited gates rerun')
    parser.add_argument('--future-kind-qualification', type=Path,
                        help='matching actual tuple, record and native class Future semantics')
    parser.add_argument('--behavior-qualification', type=Path,
                        help='matching complete 27-group original Future qualification')
    args = parser.parse_args()
    report = qualify(args.compiler, args.output, value_qualification_path=args.value_qualification,
                     future_kind_qualification_path=args.future_kind_qualification,
                     behavior_qualification_path=args.behavior_qualification)
    print(json.dumps({'status': report['status'], 'modules': len(report['modules']),
                      'products': report['products'], 'checks': len(report['checks'])}, indent=2))


if __name__ == '__main__':
    main()
