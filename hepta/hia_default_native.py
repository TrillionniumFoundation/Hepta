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
PROOF_BUNDLE_RESOURCE = '_data/native/default/full_cost/proof-bundle.json'
BINDER_RESOURCE = '_data/native/default/full_cost/hia-safe-core-bind'
CLI_BUNDLE_RESOURCE = '_data/native/default/cli/manifest.json'
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

    if len(value) not in ((10, 11) if value[4] == SCOPES[0] else (7,)):
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
    if len(value) == 11:
        resources.append((INTEGER_BUNDLE_RESOURCE, value[10]))
    for path, expected in resources:
        raw = _read(directory / path, 16 << 20).raw
        if sha256(raw).hexdigest() != expected:
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
    if (type(value) is not tuple or len(value) not in (7, 8, 9, 10, 11)
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


def default_cli():
    from .hia_cli_native import installed_cli, native_cli_profile

    if native_cli_profile() is None:
        return None
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
    from . import hia_native_helpers as helpers

    helpers._check_scope_owner()
    selector, _ = INTEGER_OWNER
    if helpers._SCOPE_OWNER is not None or selector in os.environ:
        return None
    captured = _capture_package()
    if captured is None:
        return None
    directory, value, pins = captured
    if len(value) < 11:
        return None
    binding = helpers.NativeHelpersBinding(str(directory / INTEGER_BUNDLE_RESOURCE), value[10])
    if set(binding.selections) != {selector} or len(binding.images) != 1:
        raise ValueError('unexpected integer VM owner in the cold distribution')
    binding.snapshots.extend(pins)
    binding.check_files()
    image, = binding.images.values()
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
