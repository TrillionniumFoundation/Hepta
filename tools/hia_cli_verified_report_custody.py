"""Exact current-source custody for the optional report + five-image CLI route."""
from __future__ import annotations
from hashlib import sha256
from pathlib import Path
from tools import hia_cli_discovery_bundle_custody as original

ROOT = Path(__file__).resolve().parents[1]
CAPACITY = original.CAPACITY
SOURCE = 'examples/hia_bootstrap/verified_report.hepta'
SCHEMA = 'hepta.hia.verified-report-native.v2'
BUNDLE_SCHEMA = 'hepta.hia.cli-verified-report-bundle.v2'
LABEL = 'verified-report'
RETAINED = 'tests/fixtures/hia_verified_report_retained.json'
OWN_FILES = (
    'hepta/hia_optional_profiles.py',
    'hepta/hia_front_runtime.py',
    'hepta/hia_front_continuation.py',
    'hepta/hia_exception_delivery.py',
    'hepta/hia_machine_transport.py',
    'setup.py',
    'hepta/hia_program.py',
    'tools/hia_verified_report_policy.py',
    'tools/generate_hia_verified_report.py',
    SOURCE,
    'hepta/hia_verified_report_ports.py',
    'hepta/hia_verified_report_native.py',
    'hepta/hia_cli_verified_report_native.py',
    'tools/hia_cli_verified_report_custody.py',
    'tools/build_hia_cli_verified_report_bundle.py',
    'tools/qualify_hia_cli_verified_report_bundle.py',
    'tools/hia_verified_report_controls.py',
    'tests/test_hia_cli_verified_report_native.py',
    RETAINED,
    'docs/HIA_VERIFIED_REPORT_NATIVE.md',
)
OWNER_FILES = tuple(dict.fromkeys((*original.OWNER_FILES, *OWN_FILES)))
require = original.require
read_json = original.read_json
encoded = original.encoded
publish = original.publish
admit_compilation = original.admit_compilation


def binding(path):
    # Preserve the original record and extent semantics, but capture bytes from
    # a nonblocking regular descriptor rather than reopening a checked path.
    import stat
    from hepta.hia_optional_profiles import _read_bound_file
    path = Path(path).absolute()
    observed = path.lstat()
    require(stat.S_ISREG(observed.st_mode), 'regular discovery custody input required')
    raw = _read_bound_file(path.parent, path.name, limit=max(1, observed.st_size),
                          expected_length=observed.st_size)
    after = path.lstat()
    identity = lambda value: (value.st_dev, value.st_ino, value.st_mode,
                              value.st_size, value.st_mtime_ns, value.st_ctime_ns)
    require(identity(observed) == identity(after), 'report custody input changed during capture')
    return {'path': str(path), 'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
            'mode': stat.S_IMODE(observed.st_mode)}


def check_bindings(values):
    require(type(values) is list and values, 'complete discovery input bindings required')
    paths = []
    for item in values:
        require(type(item) is dict and set(item) == {'path', 'bytes', 'sha256', 'mode'}
                and type(item['path']) is str and Path(item['path']).is_absolute()
                and type(item['bytes']) is int and type(item['mode']) is int,
                'invalid discovery input binding')
        require(binding(item['path']) == item, 'discovery input changed: ' + item['path'])
        paths.append(item['path'])
    require(len(paths) == len(set(paths)), 'duplicate discovery input binding')


def owner_sources():
    from hepta.hia_optional_profiles import fresh_profile_capture, _read_bound_file
    _, captures = fresh_profile_capture(BUNDLE_SCHEMA)
    return {name: sha256(captures[name] if name in captures else
                         _read_bound_file(ROOT, name, limit=CAPACITY)).hexdigest()
            for name in OWNER_FILES}


def require_owner_sources(sources):
    require(type(sources) is dict, 'complete report bundle source map required')
    for name, digest in owner_sources().items():
        require(sources.get(name) == digest, 'report input is outside current cold closure: ' + name)


def admit_cold(path):
    authority = original.admit_cold(path)
    require_owner_sources(authority['source_manifest'])
    return authority


def guard_authority(authority):
    original.guard_authority(authority)
    require_owner_sources(authority['source_manifest'])


def retained_inputs():
    # Original43 admission remains the exact original two byte streams and IDs.
    old = original.retained_inputs()
    value = read_json((ROOT / RETAINED).read_bytes())
    require(type(value) is dict and value.get('schema') == 'hepta.verified-report.retained-inputs.v1'
            and value.get('original_cli_ids') == old['original_ids']
            and type(value.get('case_names')) is list
            and len(value['case_names']) == len(set(value['case_names'])) == 140,
            'complete frozen report140 and original43 inventories required')
    for name in ('original_external_driver', 'original_class'):
        row = value.get(name)
        require(type(row) is dict and type(row.get('text')) is str,
                'full retained report input required: ' + name)
        raw = row['text'].encode('utf-8')
        require(type(row.get('bytes')) is int and row['bytes'] == len(raw)
                and sha256(raw).hexdigest() == row.get('sha256'),
                'retained report input byte identity differs: ' + name)
    require(value.get('methods') == ['sha256', 'canonical_json', 'input_sha256',
            'scalar_entrypoints', 'normalization_report', 'as_dict', 'report'],
            'the original seven complete report methods are required')
    return value
