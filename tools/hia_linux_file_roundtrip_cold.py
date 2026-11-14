"""Current-source cold custody for the explicit bounded roundtrip profile.

The original complete cold source domain is retained. The optional five-asset
profile is additionally read through its own versioned resource inventory; it
does not enlarge any default worker resource role. Frozen test observations,
development compiler pins and serialized fixture dictionaries grant no cold
authority. Every public admission performs the original fresh checks.
"""
from __future__ import annotations

import base64
from hashlib import sha256
from pathlib import Path
import stat
import zlib
import os
import sys
import sysconfig

from hepta.hia_linux_file_roundtrip import PROFILE, PROFILE_SOURCE_FILES
from tools import hia_linux_stdio_cold as original

ROOT = Path(__file__).resolve().parents[1]
CAPACITY = 1048576
AUTHORITY_SCHEMA = 'hepta.hia.linux-file-roundtrip-current-cold-inputs.v1'
COMPILER_SOURCE, PACKER_SOURCE, CONTROLLER_SOURCE, REPRESENTATION_SOURCE, SEMANTIC_SOURCE = PROFILE_SOURCE_FILES
ORDINARY_SOURCE = original.ORDINARY_SOURCE
RETAINED = 'tests/fixtures/hia_linux_file_roundtrip_retained.zlib.json'
RETAINED_SHA256 = '46030d20ec9431b76af4a551e489da5d508d6c8c31d70978cf9dc8a24d649323'
RETAINED_LOGICAL_SHA256 = 'bd2557ea678fd2e010e2ca3f1b462ce5a60a06d8db1cae37a6a8fd725b821c2a'
RETAINED_LOGICAL_BYTES = 3311433
KNOWN_SEPARATE_SEMANTIC_SUITE = {'addendum_git_blob': '23613b922b93db45f7023f031e583a1beef763dc', 'development_image_sha256': '47c710c755c8eb5fb351190a057ccc5fd754c3124501474a602c2ff2d137474a', 'failed': 1, 'failed_case': 'root-v8-cross-target-loans', 'fuel_limit': 10000000, 'logical_vm_cases': 6, 'passed': 5, 'reports_git_blob': '5a6db721b5b19c158884a8fee71c5c84a01ef2c4', 'source_sha256': '2fbedf12008851e7f428fbc60fed144c0d0ebd99d7cc93e004058a8d5e375aa9', 'status': 'ORIGINAL_FUEL_FAILURE_RETAINED_NOT_RECLASSIFIED', 'this_pipeline_seven_is_a_distinct_fixed_group': True}
OWN_SOURCES = (
    *PROFILE_SOURCE_FILES,
    'hepta/hia_optional_profiles.py', 'hepta/hia_linux_file_roundtrip.py',
    'hepta/hia_linux_file.py', 'hepta/hia_linux_file_render.py',
    'hepta/hia_linux_process.py', 'hepta/hia_linux_stdio.py',
    'tools/build_hia_linux_file_roundtrip_program.py',
    'tools/generate_hia_selfhost_linux_file_roundtrip.py',
    'tools/generate_hia_linux_file_roundtrip_entry.py',
    'tools/generate_hia_linux_file_render_entry.py',
    'tools/generate_hia_linux_file_entry.py',
    'tools/generate_hia_native_file_roundtrip.py',
    'tools/generate_hia_core_representation_private.py',
    'tools/generate_hia_file_render_checker_v4.py',
    'tools/hia_linux_file_roundtrip_cold.py',
    'tools/build_hia_linux_file_roundtrip_cold.py',
    'tools/qualify_hia_linux_file_roundtrip.py',
    'tools/hia_linux_file_roundtrip_readback.py',
    'tests/hia_linux_file_roundtrip_cases.py',
    'tests/hia_linux_file_roundtrip_ids.py',
    'tests/hia_linux_file_roundtrip_observer.py',
    'tests/hia_linux_file_roundtrip_exec.py',
    'tests/hia_linux_file_roundtrip_portable.py',
    'tests/hia_linux_file_roundtrip_installed.py',
    'tests/test_hia_linux_file_roundtrip_cold.py',
    'tests/test_hia_linux_file_roundtrip_source.py',
    'tests/hia_linux_process_cases.py',
    'tests/test_hia_agent_installed_resources.py',
    RETAINED, 'docs/HIA_LINUX_FILE_ROUNDTRIP_COLD.md',
    'setup.py', 'pyproject.toml', 'MANIFEST.in',
)
REQUIRED_SOURCES = tuple(dict.fromkeys((*original.REQUIRED_SOURCES, *OWN_SOURCES)))
require = original.require
decode = original.decode
wire = original.wire
publish = original.publish
pin = original.pin
check_bindings = original.check_bindings
observation = original.observation
capture = original.capture
digest = original.digest


def _runtime_stat_identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns)


def _runtime_file(path):
    """Read an ordinary runtime file and bind descriptor/path identity."""
    path = Path(path)
    require(path.is_absolute(), 'runtime file must be absolute')
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and before.st_size > 0,
                'runtime file must be nonempty and ordinary')
        require(_runtime_stat_identity(path.lstat()) == _runtime_stat_identity(before),
                'runtime named file differs from actual descriptor')
        parts = []
        remaining = before.st_size + 1
        while remaining:
            part = os.read(descriptor, min(1048576, remaining))
            if not part:
                break
            parts.append(part)
            remaining -= len(part)
        raw = b''.join(parts)
        after = os.fstat(descriptor)
        require(_runtime_stat_identity(before) == _runtime_stat_identity(after)
                == _runtime_stat_identity(path.lstat()) and len(raw) == before.st_size,
                'runtime file changed during actual read')
    finally:
        os.close(descriptor)
    return {'path': str(path), 'bytes': len(raw), 'sha256': digest(raw),
            'mode': stat.S_IMODE(before.st_mode), 'device': before.st_dev,
            'inode': before.st_ino, 'mtime_ns': before.st_mtime_ns, 'ctime_ns': before.st_ctime_ns}


def _runtime_library_mappings(raw, expected_names):
    """Read only actual libpython map identities; addresses are not authority."""
    require(type(raw) is bytes and type(expected_names) is tuple,
            'actual runtime mapping bytes and exact library names required')
    rows = []
    for line in raw.splitlines():
        fields = line.split(maxsplit=5)
        if len(fields) != 6:
            continue
        encoded = fields[5]
        name = os.fsdecode(encoded).removesuffix(' (deleted)').rsplit('/', 1)[-1]
        if not name.startswith('libpython'):
            continue
        require(not encoded.endswith(b' (deleted)') and encoded.startswith(b'/')
                and b'\\' not in encoded and b'\0' not in encoded,
                'deleted, relative or ambiguous runtime library mapping refused')
        path = Path(os.fsdecode(encoded))
        require(path.name in expected_names, 'mapped libpython does not match actual sysconfig names')
        device = fields[3].split(b':')
        require(len(device) == 2, 'complete runtime map device required')
        rows.append({'path': str(path), 'major': int(device[0], 16),
                     'minor': int(device[1], 16), 'inode': int(fields[4]),
                     'executable': b'x' in fields[1]})
    return rows


def capture_runtime_context():
    """Bind this running interpreter and its actual necessary shared library.

    The original venv invocation path is retained. No ambient LD_LIBRARY_PATH
    or LD_PRELOAD value is read. A statically linked interpreter is recognized
    only by explicit sysconfig=0 plus the absence of any libpython mapping.
    This is launch evidence, not a replacement for current-cold authority.
    """
    require(sys.platform == 'linux' and type(sys.executable) is str
            and Path(sys.executable).is_absolute(), 'actual absolute Linux interpreter required')
    invocation = sys.executable
    executable_path = Path(invocation).resolve(strict=True)
    current_exe = os.readlink('/proc/self/exe')
    require(not current_exe.endswith(' (deleted)') and Path(current_exe).is_absolute()
            and Path(current_exe) == executable_path,
            'selected interpreter differs from the actually running executable')
    config = {name: sysconfig.get_config_var(name)
              for name in ('Py_ENABLE_SHARED', 'LDLIBRARY', 'INSTSONAME')}
    require(type(config['Py_ENABLE_SHARED']) is int and config['Py_ENABLE_SHARED'] in (0, 1),
            'explicit actual interpreter linkage required')
    names = tuple(dict.fromkeys(value for value in (config['LDLIBRARY'], config['INSTSONAME'])
                                if type(value) is str and value))
    require(names and all(Path(name).name == name and name.startswith('libpython') for name in names),
            'actual sysconfig libpython names required')
    rows = _runtime_library_mappings(Path('/proc/self/maps').read_bytes(), names)
    executable = _runtime_file(executable_path)
    require((os.stat('/proc/self/exe').st_dev, os.stat('/proc/self/exe').st_ino)
            == (executable['device'], executable['inode']),
            'actual executable mapping differs from named interpreter bytes')
    library = None
    if config['Py_ENABLE_SHARED'] == 1:
        keys = {(row['path'], row['major'], row['minor'], row['inode']) for row in rows}
        require(len(keys) == 1 and any(row['executable'] for row in rows),
                'exactly one actual executable libpython mapping required')
        library = _runtime_file(rows[0]['path'])
        require(all((row['major'], row['minor'], row['inode']) ==
                    (os.major(library['device']), os.minor(library['device']), library['inode'])
                    for row in rows), 'actual libpython mapping and named bytes differ')
    else:
        require(not rows, 'static interpreter unexpectedly maps libpython')
    require(Path(invocation).resolve(strict=True) == executable_path
            and os.readlink('/proc/self/exe') == current_exe,
            'interpreter invocation changed during runtime capture')
    return {'schema': 'hepta.hia.roundtrip-runtime-launch-context.v1',
            'launch_executable': invocation, 'executable': executable,
            'python': sys.version, 'version': list(sys.version_info[:3]),
            'prefix': sys.prefix, 'base_prefix': sys.base_prefix,
            'sysconfig': config, 'library': library,
            'library_directory': None if library is None else str(Path(library['path']).parent)}


def guard_runtime_context(context):
    fresh = capture_runtime_context()
    require(type(context) is dict and fresh == context,
            'actual interpreter or libpython changed from the frozen launch context')
    return fresh


def runtime_child_environment(base, context):
    require(type(base) is dict and all(type(k) is str and type(v) is str for k, v in base.items())
            and 'LD_LIBRARY_PATH' not in base and 'LD_PRELOAD' not in base,
            'fixed original child environment required; ambient loader values refused')
    current = guard_runtime_context(context)
    result = dict(base)
    if current['library_directory'] is not None:
        result['LD_LIBRARY_PATH'] = current['library_directory']
    return result


def retained():
    raw = (ROOT / RETAINED).read_bytes()
    require(digest(raw) == RETAINED_SHA256, 'complete original roundtrip fixture changed')
    wrapper = decode(raw)
    require(type(wrapper) is dict and set(wrapper) == {'schema', 'logical', 'zlib_base64'}
            and wrapper['schema'] == 'hepta.hia.retained-zlib.v1'
            and type(wrapper['logical']) is dict
            and type(wrapper['logical'].get('bytes')) is int
            and wrapper['logical']['bytes'] == RETAINED_LOGICAL_BYTES
            and wrapper['logical'].get('sha256') == RETAINED_LOGICAL_SHA256,
            'fixed complete retained wrapper required')
    compressed = base64.b64decode(wrapper['zlib_base64'], validate=True)
    stream = zlib.decompressobj()
    logical = stream.decompress(compressed, RETAINED_LOGICAL_BYTES + 1)
    require(stream.eof and not stream.unconsumed_tail and not stream.unused_data
            and len(logical) == RETAINED_LOGICAL_BYTES
            and digest(logical) == RETAINED_LOGICAL_SHA256,
            'complete retained fixture extent or bytes differ')
    value = decode(logical)
    require(value.get('schema') == 'hepta.hia.linux-file-roundtrip-retained-controls.v1'
            and value.get('scope') == 'ORIGINAL_INPUTS_AND_OBSERVATIONS_NOT_CURRENT_QUALIFICATION'
            and value.get('matching_cold') is False and value.get('whole_native') is False,
            'original observations are not current cold qualification')
    require(value.get('known_separate_semantic_suite') == KNOWN_SEPARATE_SEMANTIC_SUITE,
            'original separate semantic fuel failure changed or disappeared')
    cases = value.get('kernel_cases')
    require(type(cases) is list and len(cases) == 130
            and len({row['name'] for row in cases}) == 130,
            'all original 130 ordered kernel controls required')
    for row in cases:
        for key in ('input', 'stdout', 'stderr'):
            retained_bytes(row[key])
        require(type(row['declared']['expected']) is int
                and row['declared']['name'] == row['original_observation']['name'] == row['name']
                and row['original_observation']['pass'] is True,
                'original control identity or outcome changed')
    return value


def retained_bytes(row):
    require(type(row) is dict and type(row.get('bytes')) is int
            and type(row.get('base64')) is str, 'exact retained byte record required')
    raw = base64.b64decode(row['base64'], validate=True)
    require(len(raw) == row['bytes'] and digest(raw) == row['sha256'],
            'retained bytes differ from original identity')
    return raw


def profile_capture(profile=PROFILE, *, resource_root=None):
    """Return the bytes from one safe capture; do not reopen their paths.

    The returned dictionary is source data, not cold or execution authority.
    The final guard remains a fresh read of the entire explicit profile.
    """
    from hepta.hia_optional_profiles import (
        OPTIONAL_PROFILE_FILES, fresh_profile_capture, guard_profile_identity,
    )
    root = ROOT if resource_root is None else Path(resource_root)
    require(type(profile) is str and profile in OPTIONAL_PROFILE_FILES,
            'exact declared optional profile required')
    names = OPTIONAL_PROFILE_FILES[profile]
    if profile == PROFILE:
        require(tuple(names) == PROFILE_SOURCE_FILES,
                'explicit roundtrip profile requires its exact five resources')
    observed, captures = fresh_profile_capture(profile, resource_root=root)
    require(type(observed) is dict and observed.get('profile') == profile
            and type(observed.get('files')) is dict and set(observed['files']) == set(names)
            and type(captures) is dict and set(captures) == set(names),
            'complete current profile capture required')
    for name in names:
        raw = captures[name]
        require(type(raw) is bytes and observed['files'][name] == {
            'bytes': len(raw), 'sha256': digest(raw)},
            'captured profile bytes differ from the actual safe-read identity: ' + name)
    guard_profile_identity(profile, observed, resource_root=root)
    return observed, captures


def profile_identity():
    return profile_capture()[0]


def captured_source_binding(path, raw):
    """Record captured bytes plus a non-opening path-mode observation.

    Mode is explicitly observed by lstat after capture; this metadata helper
    grants no cold authority and never reopens the source content.
    """
    path = Path(path).absolute()
    observed = path.lstat()
    require(type(raw) is bytes and stat.S_ISREG(observed.st_mode),
            'regular captured source with immutable bytes required')
    return {'path': str(path), 'bytes': len(raw), 'sha256': digest(raw),
            'mode': stat.S_IMODE(observed.st_mode)}


def admit_required_sources(sources):
    other_names = tuple(name for name in REQUIRED_SOURCES if name not in PROFILE_SOURCE_FILES)
    original.admit_required_sources(sources, root=ROOT, names=other_names)
    _, captures = profile_capture()
    for name in PROFILE_SOURCE_FILES:
        require(name in sources, 'roundtrip input missing from cold source map: ' + name)
        require(sources[name] == digest(captures[name]),
                'roundtrip captured input differs from cold source map: ' + name)


def admit_cold(cold_report, *, compiler=None):
    authority = original.admit_cold(cold_report, compiler=compiler)
    admit_required_sources(authority['source_manifest'])
    # The original authority already bound the actual outer/nested reports and
    # B1/B2/B3. No fixture boolean or caller digest can substitute for it.
    authority = {**authority, 'schema': AUTHORITY_SCHEMA, 'physical_profile': PROFILE,
                 'optional_profile': profile_identity()}
    guard_authority(authority)
    return authority


def guard_authority(authority):
    require(type(authority) is dict and authority.get('schema') == AUTHORITY_SCHEMA
            and authority.get('physical_profile') == PROFILE,
            'explicit current-cold roundtrip authority required')
    original.guard_authority(authority)
    admit_required_sources(authority['source_manifest'])
    require(profile_identity() == authority['optional_profile'],
            'roundtrip optional profile changed during qualification')


def re_admit_authority(authority):
    require(type(authority) is dict and authority.get('schema') == AUTHORITY_SCHEMA
            and authority.get('physical_profile') == PROFILE,
            'development or serialized fixture is not cold authority')
    fresh = admit_cold(authority['cold_report'], compiler=authority['compiler'])
    require(fresh == authority, 'fixture differs from fresh original cold authority')
    return fresh


def compile_bound(folder, label, provider, payload, authority, *, extension='.image.bin'):
    from tools.qualify_hia_selfhost import compile_stage
    guard_authority(authority)
    before = Path(provider).read_bytes()
    path, returned = compile_stage(Path(folder), label, Path(provider), payload,
                                   output_extension=extension)
    actual_path, produced, observed = observation(folder, label, provider, payload, extension=extension)
    require(path == actual_path and returned == observed and Path(provider).read_bytes() == before,
            'actual roundtrip compile request/receipt/provider changed: ' + label)
    guard_authority(authority)
    return path, produced, observed


def all_files(folder, exclude=()):
    folder = Path(folder)
    return [pin(path) for path in sorted(folder.rglob('*'))
            if path.is_file() and path.relative_to(folder).as_posix() not in exclude]


def owner_pass(owner):
    return (type(owner) is dict and owner.get('schema') == 'hepta.hia.selfhost-process-owner.v1'
        and owner.get('status') == 'OWNED_PROCESS_COMPLETED'
        and type(owner.get('returncode')) is int and owner['returncode'] == 0
        and type(owner.get('qualification_seconds')) is int and owner['qualification_seconds'] == 180
        and type(owner.get('cleanup_seconds')) is int and owner['cleanup_seconds'] == 3
        and owner.get('timed_out') is False and owner.get('exit_observed_before_deadline') is True
        and type(owner.get('cleanup')) is dict and owner['cleanup'].get('complete') is True
        and owner['cleanup'].get('observed_echild') is True)
