"""Package-owned default image custody, separate from operator selections.

The checked-in pin is None, so ordinary source and portable wheels retain
their existing defaults. The explicit candidate wheel builder derives one
data-only pin after compiling the HIA owner. A candidate installation uses
that fixed bundle without environment configuration. It never supplements an
active administrator scope with executable code outside its pinned bundle.
"""
from __future__ import annotations

from pathlib import Path

PIN_SCHEMA = 'hepta.hia.default-native-package.v1'
TARGET = 'linux-x86_64-lp64'
BUNDLE_RESOURCE = '_data/native/default/full_cost/bundle.json'
SELECTOR = 'HEPTA_HIA_FULL_COST_MANIFEST'
SCOPES = ('MATCHING_SOURCE_COLD_COMPONENT', 'DEVELOPMENT_COMPONENT')
MAX_PIN_BYTES = 4096
MAX_RECORD_BYTES = 1 << 20
PIN_HEADER = '"""Build-derived native default pin; None is the portable source profile."""\n\nRELEASE_PIN = '


def render_pin(value):
    """The sole build-derived Python declaration; no generated runtime policy."""
    return (PIN_HEADER + repr(value) + '\n').encode('ascii')


def _record_pin(pin_path, raw):
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
    pins, has_default = [], False
    for row in csv.reader(io.StringIO(record.decode('utf-8'))):
        if len(row) != 3:
            raise ValueError('invalid native-default wheel RECORD')
        if row[0] == 'hepta/hia_default_native_pin.py':
            pins.append(row)
        if row[0] == 'hepta/' + BUNDLE_RESOURCE:
            has_default = True
    expected = 'sha256=' + base64.urlsafe_b64encode(sha256(raw).digest()).rstrip(b'=').decode('ascii')
    if len(pins) != 1 or pins[0][1:] != [expected, str(len(raw))]:
        raise ValueError('native-default declaration differs from installed wheel RECORD')
    return record_path, record, has_default


def capture_default_bundle():
    """Return a fixed package bundle and captured pin, or the portable profile.

    The pin module is always shipped. Missing or changed pin bytes are errors,
    including after its initial import; they cannot disable a candidate default.
    """
    from . import hia_default_native_pin
    value = hia_default_native_pin.RELEASE_PIN
    pin_path = Path(__file__).resolve().with_name('hia_default_native_pin.py')
    with pin_path.open('rb', buffering=8192) as stream:
        raw = stream.read(MAX_PIN_BYTES + 1)
    record = _record_pin(pin_path, raw)
    if value is None:
        if (raw != render_pin(None) or (record is not None and record[2])
                or (pin_path.parent / BUNDLE_RESOURCE).parent.exists()):
            raise ValueError('portable native-default pin bytes changed')
        return None
    if (type(value) is not tuple or len(value) != 7
            or any(type(item) is not str for item in value)
            or value[:3] != (PIN_SCHEMA, TARGET, BUNDLE_RESOURCE)
            or value[4] not in SCOPES
            or any(len(value[index]) != 64 or any(c not in '0123456789abcdef' for c in value[index])
                   for index in (3, 6))
            or (value[4] == SCOPES[0] and (len(value[5]) != 64
                or any(c not in '0123456789abcdef' for c in value[5])))
            or (value[4] == SCOPES[1] and value[5] != '-')
            or raw != render_pin(value)):
        raise ValueError('invalid or changed package native-default pin')
    import ctypes
    import platform
    if (platform.system() != 'Linux' or platform.machine() != 'x86_64'
            or ctypes.sizeof(ctypes.c_void_p) != 8):
        raise ValueError('default native candidate package requires Linux x86-64 LP64')
    from .hia_native_helpers import _read
    captured = _read(pin_path, MAX_PIN_BYTES)
    if captured.raw != raw:
        raise ValueError('package native-default pin changed during capture')
    if record is None or not record[2]:
        raise ValueError('native candidate lacks its installed wheel RECORD binding')
    captured_record = _read(record[0], len(record[1]))
    if captured_record.raw != record[1]:
        raise ValueError('native-default wheel RECORD changed during capture')
    bundle = pin_path.parent / BUNDLE_RESOURCE
    return bundle, value[3], ((captured, MAX_PIN_BYTES), (captured_record, len(record[1])))


def default_image(selector):
    """Capture the package's sole HIA owner outside a worker scope.

    Workers receive their selections through native_helpers_scope instead.
    An explicit worker bundle lacking this owner must refuse at this boundary.
    """
    captured = capture_default_bundle()
    if captured is None:
        return None
    if selector != SELECTOR:
        raise ValueError('unregistered package native-default selector')
    from . import hia_native_helpers as helpers
    helpers._check_scope_owner()
    if helpers._SCOPE_OWNER is not None:
        raise ValueError('required package native owner is absent from the active worker bundle')
    bundle, expected, pins = captured
    binding = helpers.NativeHelpersBinding(str(bundle), expected)
    binding.snapshots.extend(pins)
    if set(binding.selections) != {SELECTOR}:
        raise ValueError('default native candidate must contain exactly its full-cost owner')
    from .hia_full_cost_native import NativeFullCost, SOURCE, SCHEMA
    key = (str(Path(binding.selections[SELECTOR]).resolve(strict=True)),
           str(SOURCE.resolve(strict=True)), SCHEMA, NativeFullCost)
    image = binding.images[key]
    binding.check_files()
    # Only the image retains its custody. The construction index must not retain
    # that same image and create a cycle requiring cyclic GC to release mappings.
    binding.images.clear()
    # The image retains its complete bundle/manifest/source/image/pin custody.
    # NativeFullCost checks that custody before and after each actual entry.
    image._default_package_binding = binding
    return image
