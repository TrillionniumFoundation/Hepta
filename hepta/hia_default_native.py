"""Package-owned default image custody, separate from operator selections.

The checked-in module remains a portable source input. Linux wheels derive
a separate data-only pin after compiling the HIA owners. An installation uses
that fixed bundle without environment configuration. A cold wheel may also
bind Core ELF owners; an administrator scope is never supplemented.
"""
from __future__ import annotations

import os
from pathlib import Path

PIN_SCHEMA = 'hepta.hia.default-native-package.v1'
TARGET = 'linux-x86_64-lp64'
PIN_RESOURCE = '_data/native/default/full_cost/pin.json'
BUNDLE_RESOURCE = '_data/native/default/full_cost/bundle.json'
INTEGER_BUNDLE_RESOURCE = '_data/native/default/full_cost/integer-bundle.json'
INTEGER_OWNER = ('HEPTA_HIA_SCALAR_REFERENCE_MANIFEST', 'scalar-reference')
LEDGER_BUNDLE_RESOURCE = '_data/native/default/full_cost/ledger-bundle.json'
LEDGER_OWNER = ('HEPTA_HIA_EXECUTION_LEDGER_MANIFEST', 'execution-ledger')
GRAPH_BUNDLE_RESOURCE = '_data/native/default/full_cost/reference-graph-bundle.json'
GRAPH_OWNER = ('HEPTA_HIA_EVALUATE_REFERENCE_WIRE_MANIFEST', 'evaluate-reference-wire')
ADMISSION_BUNDLE_RESOURCE = '_data/native/default/full_cost/core-admission-bundle.json'
ADMISSION_OWNER = ('HEPTA_HIA_CORE_ADMISSION_MANIFEST', 'core-admission')
OWNED_VM_RESOURCE = '_data/native/default/full_cost/hia-owned-reference-wire'
PROOF_BUNDLE_RESOURCE = '_data/native/default/full_cost/proof-bundle.json'
BINDER_RESOURCE = '_data/native/default/full_cost/hia-safe-core-bind'
CLI_BUNDLE_RESOURCE = '_data/native/default/cli/manifest.json'
ASSEMBLY_RENDER_RESOURCE = '_data/native/default/cli/assembly-render.bin'
ASSEMBLY_SYNTAX_RESOURCE = '_data/native/default/cli/assembly-syntax.bin'
ASSEMBLY_DIAGNOSTIC_RESOURCE = '_data/native/default/cli/assembly-diagnostic.bin'
ASSEMBLY_CANONICAL_RESOURCE = '_data/native/default/cli/assembly-canonical.bin'
ASSEMBLY_CORE_JSON_RESOURCE = '_data/native/default/cli/assembly-core-json.bin'
SELECTOR = 'HEPTA_HIA_FULL_COST_MANIFEST'
CORE_ELF_OWNERS = (
    ('HEPTA_HIA_ELF_SHARED_LINKER_MANIFEST', 'elf-shared-linker'),
    ('HEPTA_HIA_ELF_VERIFIED_LINKER_MANIFEST', 'elf-verified-linker'),
    ('HEPTA_HIA_SAFE_CORE_ELF_INVENTORY_MANIFEST', 'safe-core-elf-inventory'),
)
CORE_PROOF_OWNERS = (
    ('HEPTA_HIA_SAFE_CORE_X64_DECODE_MANIFEST', 'safe-core-x64-decode'),
    ('HEPTA_HIA_CNF_MANIFEST', 'cnf'),
)
CORE_WIRE_OWNER = ('HEPTA_HIA_CORE_PROOF_WIRE_MANIFEST', 'core-proof-wire')
DEFAULT_OWNERS = frozenset((SELECTOR, *(selector for selector, _ in CORE_ELF_OWNERS)))
SCOPES = ('MATCHING_SOURCE_COLD_COMPONENT', 'DEVELOPMENT_COMPONENT')
MAX_PIN_BYTES = 4096
MAX_RECORD_BYTES = 1 << 20
PIN_HEADER = '"""Build-derived native default pin; None is the portable source profile."""\n\nRELEASE_PIN = '


def render_pin(value):
    """Canonical encoding of the portable module and legacy module-format pins."""
    return (PIN_HEADER + repr(value) + '\n').encode('ascii')


def render_pin_data(value):
    """Return the canonical contents of the wheel's package-owned pin file."""
    import json
    return (json.dumps(value, ensure_ascii=True, separators=(',', ':')) + '\n').encode('ascii')


def _verify_data_resources(directory, value):
    from hashlib import sha256
    import json

    from .hia_native_helpers import _read

    if len(value) not in ((10, 11, 12, 14, 15, 16, 18, 19, 20) if value[4] == SCOPES[0] else (7,)):
        raise ValueError('incomplete native-default data pin')
    contract_name = 'docs/HIA_SELFHOST_CORE_SUPPORT.json'
    contract = _read(directory / '_data' / contract_name, 4 << 20)
    contents = json.loads(contract.raw)
    files = {**contents['source_identity']['files'], contract_name: sha256(contract.raw).hexdigest()}
    encoded = (json.dumps(files, ensure_ascii=False, sort_keys=True, separators=(',', ':')) + '\n').encode()
    if sha256(encoded).hexdigest() != value[6]:
        raise ValueError('native-default pin differs from the package source contract')
    resources = [(BUNDLE_RESOURCE, value[3])]
    if value[4] == SCOPES[0]:
        resources.extend(((Path(BUNDLE_RESOURCE).with_name('cold-report.json'), value[5]),
                          (PROOF_BUNDLE_RESOURCE, value[7]), (CLI_BUNDLE_RESOURCE, value[8]),
                          (BINDER_RESOURCE, value[9])))
    if len(value) >= 11:
        resources.append((INTEGER_BUNDLE_RESOURCE, value[10]))
    if len(value) >= 12:
        resources.append((LEDGER_BUNDLE_RESOURCE, value[11]))
    if len(value) >= 14:
        resources.extend(((GRAPH_BUNDLE_RESOURCE, value[12]), (OWNED_VM_RESOURCE, value[13])))
    if len(value) >= 15:
        resources.append((ADMISSION_BUNDLE_RESOURCE, value[14]))
    if len(value) >= 16:
        resources.append((ASSEMBLY_RENDER_RESOURCE, value[15]))
    if len(value) >= 18:
        resources.extend(((ASSEMBLY_SYNTAX_RESOURCE, value[16]), (ASSEMBLY_DIAGNOSTIC_RESOURCE, value[17])))
    if len(value) >= 19:
        resources.append((ASSEMBLY_CANONICAL_RESOURCE, value[18]))
    if len(value) >= 20:
        resources.append((ASSEMBLY_CORE_JSON_RESOURCE, value[19]))
    for path, expected in resources:
        raw = _read(directory / path, 16 << 20).raw
        if sha256(raw).hexdigest() != expected:
            if path == BINDER_RESOURCE:
                raise ValueError('native-default binder identity mismatch')
            if path == PROOF_BUNDLE_RESOURCE:
                raise ValueError('native-default bundle identity mismatch')
            raise ValueError('native-default pin differs from package resource ' + str(path))


def _record_pin(pin_path, raw, data_raw):
    """Bind an installed declaration to its actual wheel RECORD inventory.

    A fresh process must also refuse replacing the candidate declaration with
    the valid portable None template. The independent installation inventory
    retains its expected pin hash and the presence of the default bundle.
    """
    from . import __version__
    record_path = pin_path.parent.parent / ('hia_core-' + __version__ + '.dist-info/RECORD')
    if not record_path.exists():
        return None
    import base64
    import csv
    from hashlib import sha256
    import io
    with record_path.open('rb', buffering=8192) as stream:
        captured = bytearray()
        while len(captured) <= MAX_RECORD_BYTES:
            chunk = stream.read(min(8192, MAX_RECORD_BYTES + 1 - len(captured)))
            if not chunk:
                break
            captured.extend(chunk)
        record = bytes(captured)
    if len(record) > MAX_RECORD_BYTES:
        raise ValueError('installed native-default RECORD exceeds package bound')
    pins, data_pins, has_default = [], [], False
    for row in csv.reader(io.StringIO(record.decode('utf-8'))):
        if len(row) != 3:
            raise ValueError('invalid native-default wheel RECORD')
        if row[0] == 'hepta/hia_default_native_pin.py':
            pins.append(row)
        if row[0] == 'hepta/' + PIN_RESOURCE:
            data_pins.append(row)
        if row[0] == 'hepta/' + BUNDLE_RESOURCE:
            has_default = True
    expected = 'sha256=' + base64.urlsafe_b64encode(sha256(raw).digest()).rstrip(b'=').decode('ascii')
    if len(pins) != 1 or pins[0][1:] != [expected, str(len(raw))]:
        raise ValueError('native-default declaration differs from installed wheel RECORD')
    if data_raw is None:
        if data_pins:
            raise ValueError('installed wheel RECORD names missing native-default pin data')
    else:
        expected = 'sha256=' + base64.urlsafe_b64encode(sha256(data_raw).digest()).rstrip(b'=').decode('ascii')
        if len(data_pins) != 1 or data_pins[0][1:] != [expected, str(len(data_raw))]:
            raise ValueError('native-default pin data differs from installed wheel RECORD')
    return record_path, record, has_default


def _capture_package():
    """Return a fixed package bundle and captured pin, or the portable profile.

    The pin module is always shipped. Missing or changed pin bytes are errors,
    including after its initial import; they cannot disable a candidate default.
    """
    from . import hia_default_native_pin
    value = hia_default_native_pin.RELEASE_PIN
    pin_path = Path(__file__).resolve().with_name('hia_default_native_pin.py')
    with pin_path.open('rb', buffering=8192) as stream:
        raw = stream.read(MAX_PIN_BYTES + 1)
    from .hia_native_helpers import _read
    try:
        data = _read(pin_path.parent / PIN_RESOURCE, MAX_PIN_BYTES)
    except FileNotFoundError:
        data = None
    record = _record_pin(pin_path, raw, None if data is None else data.raw)
    if data is not None:
        import json
        if value is not None or raw != render_pin(None):
            raise ValueError('native-default data accompanies a changed source pin module')
        decoded = json.loads(data.raw)
        if type(decoded) is not list or data.raw != render_pin_data(decoded):
            raise ValueError('invalid or changed native-default pin data')
        value = tuple(decoded)
    if value is None:
        if (raw != render_pin(None) or (record is not None and record[2])
                or (pin_path.parent / BUNDLE_RESOURCE).parent.exists()):
            raise ValueError('portable native-default pin bytes changed')
        return None
    if (type(value) is not tuple or len(value) not in (7, 8, 9, 10, 11, 12, 14, 15, 16, 18, 19, 20)
            or any(type(item) is not str for item in value)
            or value[:3] != (PIN_SCHEMA, TARGET, BUNDLE_RESOURCE)
            or value[4] not in SCOPES
            or any(len(value[index]) != 64 or any(c not in '0123456789abcdef' for c in value[index])
                   for index in (3, *range(6, len(value))))
            or (len(value) >= 8 and value[4] != SCOPES[0])
            or (value[4] == SCOPES[0] and (len(value[5]) != 64
                or any(c not in '0123456789abcdef' for c in value[5])))
            or (value[4] == SCOPES[1] and value[5] != '-')
            or (data is None and raw != render_pin(value))):
        raise ValueError('invalid or changed package native-default pin')
    import ctypes
    import platform
    if (platform.system() != 'Linux' or platform.machine() != 'x86_64'
            or ctypes.sizeof(ctypes.c_void_p) != 8):
        raise ValueError('default native candidate package requires Linux x86-64 LP64')
    captured = _read(pin_path, MAX_PIN_BYTES)
    if captured.raw != raw:
        raise ValueError('package native-default pin changed during capture')
    if record is None or not record[2]:
        raise ValueError('native candidate lacks its installed wheel RECORD binding')
    captured_record = _read(record[0], len(record[1]))
    if captured_record.raw != record[1]:
        raise ValueError('native-default wheel RECORD changed during capture')
    snapshots = [(captured, MAX_PIN_BYTES), (captured_record, len(record[1]))]
    if data is not None:
        _verify_data_resources(pin_path.parent, value)
        snapshots.append((data, MAX_PIN_BYTES))
    return pin_path.parent, value, tuple(snapshots)


def capture_default_bundle():
    captured = _capture_package()
    if captured is None:
        return None
    directory, value, pins = captured
    return directory / BUNDLE_RESOURCE, value[3], pins


def _package_cli():
    from .hia_cli_native import installed_cli

    captured = _capture_package()
    if captured is None:
        return None
    directory, value, pins = captured
    if len(value) < 9:
        return None
    from .hia_native_helpers import _read
    selected = installed_cli(directory / CLI_BUNDLE_RESOURCE, expected_sha256=value[8])
    if any(_read(snapshot.path, limit) != snapshot for snapshot, limit in pins):
        raise ValueError('installed native CLI default changed during admission')
    return selected


def default_cli():
    from .hia_cli_native import native_cli_profile

    profile = native_cli_profile()
    if profile is None:
        return None
    if profile == 3123:
        import argparse
        import gettext
        from . import hia_native_helpers as helpers

        # This interpreter's packaged parser owns ordinary English argv. A
        # worker must keep its own images, and argparse owns translated text.
        if helpers._SCOPE_OWNER is not None:
            return None
        domain = gettext.textdomain()
        if (argparse._ is not gettext.gettext or argparse.ngettext is not gettext.ngettext
                or gettext.find(domain, gettext.bindtextdomain(domain)) is not None):
            return None
    return _package_cli()


def default_assembly_text(canonical):
    from .hia_agent_assembly import _native_assembly_text
    return _package_assembly(_native_assembly_text, canonical, ((ASSEMBLY_RENDER_RESOURCE, 15),))


def default_assembly_document(source, *, verify=False):
    from . import hia_agent_assembly as assembly

    limits = (assembly.MAX_FUNCTIONS, assembly.MAX_BLOCKS, assembly.MAX_OPERATIONS)
    if any(type(value) is not int or not 0 <= value <= maximum
           for value, maximum in zip(limits, (256, 4096, 16384), strict=True)):
        return None
    if (assembly.MAX_SOURCE_BYTES, assembly.MAX_LINES, assembly.MAX_LINE_BYTES, assembly.MAX_LIST_ITEMS,
            assembly.MAX_ATTRIBUTE_NODES, assembly.MAX_ATTRIBUTE_DEPTH) != (1 << 20, 16384, 16384, 256, 2048, 16):
        return None
    result = _package_assembly(assembly._native_assembly_document, source,
                               ((ASSEMBLY_SYNTAX_RESOURCE, 16), (ASSEMBLY_DIAGNOSTIC_RESOURCE, 17)),
                               verify_wire=verify)
    if type(result) is bytes:
        import json
        return json.loads(result)
    return result


def _package_assembly(operation, argument, resources, *, verify_wire=False):
    """Use the exact images linked into the wheel's public assembly tools."""
    from hashlib import sha256
    from . import hia_native_helpers as helpers
    from .hia_json_preflight_native import MAX_IMAGE_BYTES, NativeHiaJsonImage

    helpers._check_scope_owner()
    if helpers._SCOPE_OWNER is not None:
        return None
    captured = _capture_package()
    if captured is None:
        return None
    directory, value, pins = captured
    if len(value) <= resources[-1][1]:
        return None
    snapshots = list(pins)
    images = []
    for resource, index in resources:
        item = helpers._read(directory / resource, MAX_IMAGE_BYTES)
        if sha256(item.raw).hexdigest() != value[index]:
            raise ValueError('installed assembly image differs from its package pin: ' + resource)
        snapshots.append((item, MAX_IMAGE_BYTES))
        images.append(NativeHiaJsonImage(item.raw, value[index]))
    try:
        result = operation(*images, argument)
        if verify_wire and len(value) >= 20:
            return _verify_assembly_wire(result, directory, value, pins, snapshots)
        return result
    finally:
        if any(helpers._read(item.path, limit) != item for item, limit in snapshots):
            raise ValueError('installed assembly image changed during the operation')


def _verify_assembly_wire(wire, directory, value, pins, snapshots):
    from . import hia_agent_assembly as assembly, hia_native_helpers as helpers, hia_program as core
    from .hia_core_json_bytes_native import NativeCoreJSONBytes
    from .hia_json_canonical_native import NativeJsonCanonicalizer
    from .hia_json_preflight_native import MAX_IMAGE_BYTES

    # Explicitly owned JSON/Core policies and customized verification retain
    # their original call path. The HIA canonicalizer accepts up to 8 MiB.
    if (len(value) < 20 or assembly.verify_program is not core.verify_program or (core.MAX_BYTES, core.MAX_NODES, core.MAX_DEPTH)
            != (8 << 20, 262144, 64) or len(wire) > core.MAX_BYTES
            or any(key.startswith('HEPTA_HIA_') and key.endswith('_MANIFEST') for key in os.environ)):
        return wire
    admission = default_core_admission()
    if admission is None:
        return wire
    binding = admission._default_package_binding
    if any(item not in binding.snapshots for item in pins):
        raise ValueError('assembly parser and Core verifier belong to different captures')
    canonical_item = helpers._read(directory / ASSEMBLY_CANONICAL_RESOURCE, MAX_IMAGE_BYTES)
    snapshots.append((canonical_item, MAX_IMAGE_BYTES))
    canonicalizer = NativeJsonCanonicalizer(canonical_item.raw, value[18])
    front_item = helpers._read(directory / ASSEMBLY_CORE_JSON_RESOURCE, MAX_IMAGE_BYTES)
    snapshots.append((front_item, MAX_IMAGE_BYTES))
    front = NativeCoreJSONBytes(front_item.raw, value[19])
    binding.check_files()
    try:
        try:
            guarded = front.canonicalize(wire).canonical_bytes
        except core.HIAProgramRejected:
            # The original package decoded this wire before Core admission.
            # Keep its exact integer ValueError and refusal ordering. Accepted
            # inputs stay native; this compatibility refusal route is hosted.
            return wire
        canonical = canonicalizer.canonicalize(wire, max_nodes=core.MAX_NODES, max_depth=core.MAX_DEPTH)
        if canonical != guarded:
            raise ValueError('assembly canonical images disagree on the admitted wire')
        admission.admit(canonical)
        return core.VerifiedProgram(canonical)
    finally:
        binding.check_files()


def default_cli_discovery():
    """Admit wheel-owned discovery independently of the CPython argparse profile."""
    import sys
    from . import hia_native_helpers as helpers

    if sys.implementation.name != 'cpython' or helpers._SCOPE_OWNER is not None:
        return None
    bundle = _package_cli()
    return bundle.discovery if bundle is not None else None


def default_image(selector):
    """Select a fixed package owner when no explicit scope owns the call."""
    if selector not in DEFAULT_OWNERS:
        raise ValueError('unregistered package native-default selector')
    from . import hia_native_helpers as helpers
    helpers._check_scope_owner()
    if helpers._SCOPE_OWNER is not None and selector != SELECTOR:
        return None  # An explicit Worker scope never acquires extra ELF owners.
    captured = capture_default_bundle()
    if captured is None:
        return None
    if helpers._SCOPE_OWNER is not None:
        raise ValueError('required package native owner is absent from the active worker bundle')
    bundle, expected, pins = captured
    binding = helpers.NativeHelpersBinding(str(bundle), expected)
    binding.snapshots.extend(pins)
    if set(binding.selections) not in ({SELECTOR}, DEFAULT_OWNERS):
        raise ValueError('default native candidate does not match a registered owner set')
    binding.check_files()
    if selector not in binding.selections:
        return None
    # One primary factory per package-owned selector; registered binding
    # keys include the resolved manifest and the exact package source path.
    selected_path = str(Path(binding.selections[selector]).resolve(strict=True))
    image, = (image for key, image in binding.images.items() if key[0] == selected_path)
    # Break the index back-edge; the selected image keeps the snapshots.
    binding.images.clear()
    image._default_package_binding = binding
    return image


def default_integer_image():
    """Select the scalar reference image for ordinary VM instructions outside worker scopes."""
    return _default_package_image(INTEGER_OWNER, INTEGER_BUNDLE_RESOURCE, 10)


def default_execution_ledger_image():
    """Select the cold VM's execution ledger outside explicitly owned scopes."""
    return _default_package_image(LEDGER_OWNER, LEDGER_BUNDLE_RESOURCE, 11)


def default_reference_graph():
    """Select the cold graph projector and its independently compiled resource VM."""
    return _default_package_image(GRAPH_OWNER, GRAPH_BUNDLE_RESOURCE, 12, owned_vm=True)


def default_core_admission():
    """Bind the cold whole-program verifier when individual policies have no explicit owners."""
    from .hia_capability_renaming_native import SELECTOR as renaming
    from .hia_function_shape_native import SELECTOR as function_shape
    from .hia_instruction_policy_native import SELECTOR as instruction
    from .hia_program_shape_native import SELECTOR as program_shape

    if any(selector in os.environ for selector in (renaming, function_shape, instruction, program_shape)):
        return None
    return _default_package_image(ADMISSION_OWNER, ADMISSION_BUNDLE_RESOURCE, 14)


def _default_package_image(owner, resource, pin_index, *, owned_vm=False):
    from . import hia_native_helpers as helpers

    helpers._check_scope_owner()
    selector, candidate = owner
    if helpers._SCOPE_OWNER is not None or selector in os.environ:
        return None
    captured = _capture_package()
    if captured is None:
        return None
    directory, value, pins = captured
    if len(value) <= pin_index:
        return None
    binding = helpers.NativeHelpersBinding(str(directory / resource), value[pin_index])
    if set(binding.selections) != {selector} or len(binding.images) != 1:
        raise ValueError('unexpected owner for ' + candidate + ' in the cold distribution')
    binding.snapshots.extend(pins)
    binding.check_files()
    image, = binding.images.values()
    if owned_vm:
        from hashlib import sha256
        executable = helpers._read(directory / OWNED_VM_RESOURCE, 16 << 20)
        if sha256(executable.raw).hexdigest() != value[13]:
            raise ValueError('resource VM differs from its installed source-bound identity')
        binding.snapshots.append((executable, 16 << 20))
        image._default_owned_vm = executable.raw, value[13]
        binding.check_files()
    binding.images.clear()
    image._default_package_binding = binding
    return image


def default_safe_core_pair(*, observe=False):
    """Bind a cold wheel's decoder and solver only for final Safe Core proof."""
    from . import hia_native_helpers as helpers
    from .hia_json_preflight_native import _INPUT_IMAGE_OBSERVERS

    helpers._check_scope_owner()
    required = [selector for selector, _ in CORE_PROOF_OWNERS]
    wire_selector, _ = CORE_WIRE_OWNER
    supported = [*required, wire_selector]
    if helpers._SCOPE_OWNER is not None or any(selector in os.environ for selector in supported):
        return None, None
    captured = _capture_package()
    if captured is None:
        return None, None
    directory, value, pins = captured
    if len(value) < 8:
        return None, None
    binding = helpers.NativeHelpersBinding(str(directory / PROOF_BUNDLE_RESOURCE), value[7])
    binding.snapshots.extend(pins)
    if set(binding.selections) not in (set(required), set(supported)):
        raise ValueError('package Safe Core proof bundle has the wrong owners')
    binding.check_files()
    images = []
    for selector in supported:
        if selector not in binding.selections:
            continue
        selected = str(Path(binding.selections[selector]).resolve(strict=True))
        ((manifest, source, schema, factory), image), = (
            (key, image) for key, image in binding.images.items() if key[0] == selected)
        if observe:
            for observer in _INPUT_IMAGE_OBSERVERS.get():
                observer(manifest, Path(source), schema, factory, image)
        image._default_package_binding = binding
        if selector == wire_selector:
            images[1]._default_core_proof_wire = image
        else:
            images.append(image)
    if len(value) >= 10 and not any(selector in os.environ for selector, _ in CORE_ELF_OWNERS):
        from .hia_safe_core_binder_native import MAX_EXECUTABLE, NativeSafeCoreBinder
        artifact = helpers._read(directory / BINDER_RESOURCE, MAX_EXECUTABLE)
        images[1]._default_elf_binder = NativeSafeCoreBinder(artifact.raw, value[9], value[6])
        binding.snapshots.append((artifact, MAX_EXECUTABLE))
        binding.check_files()
    binding.images.clear()
    return tuple(images)


from .hia_loaded_source import register_loaded_module as _register_loaded_source
_register_loaded_source(__name__)
