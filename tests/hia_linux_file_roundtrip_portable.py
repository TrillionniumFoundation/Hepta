"""Actual sdist/wheels/install and direct execution of the cold-built ELF.

The default wheel remains the original 210-resource profile. A second wheel
explicitly selects the five roundtrip assets. No compiler or kernel result is
fabricated from installed source metadata. All command failures retain their
requests/stdout/stderr and the group owner retains cleanup observations.
"""
from pathlib import Path
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import traceback
import zipfile
import unittest
from unittest import mock
import tempfile

from tools.hia_linux_file_roundtrip_cold import (
    ROOT, PROFILE, PROFILE_SOURCE_FILES, require, pin, publish, decode, wire,
    digest, guard_authority, retained_bytes, check_bindings, profile_capture, captured_source_binding,
    capture_runtime_context, guard_runtime_context, runtime_child_environment,
)

PORTABLE_CASES = ('exports-metadata-empty', 'v6-checked-overflow', 'entry-undefined-SSA')
BUILD_PROFILE_ENV = 'HEPTA_HIA_BUILD_PROFILES'
COMMAND_SECONDS = 60


def default_resources():
    from tests.test_hia_agent_installed_resources import RESOURCES
    from hepta.hia_agent_contract import (
        DISCOVERY_FILES, NATIVE_SOURCE_FILES, SOURCE_BUILD_FILES, COMPILER_BUILD_FILES,
        PUBLICATION_BUILD_FILES, BACKEND_BUILD_FILES, EMITTER_BUILD_FILES,
        BYTE_WRAPPER_BUILD_FILES, MACHINE_OBJECT_BUILD_FILES,
        EXECUTION_OBSERVATION_BUILD_FILES, CONTINUATION_BUILD_FILES, ENTRY_BUILD_FILES,
    )
    resources = (tuple('docs/' + name for name in DISCOVERY_FILES)
        + NATIVE_SOURCE_FILES + SOURCE_BUILD_FILES + COMPILER_BUILD_FILES
        + PUBLICATION_BUILD_FILES + BACKEND_BUILD_FILES + EMITTER_BUILD_FILES
        + BYTE_WRAPPER_BUILD_FILES + MACHINE_OBJECT_BUILD_FILES
        + EXECUTION_OBSERVATION_BUILD_FILES + CONTINUATION_BUILD_FILES + ENTRY_BUILD_FILES)
    require(type(RESOURCES) is tuple and len(RESOURCES) == len(set(RESOURCES)) == 210
            and len(NATIVE_SOURCE_FILES) == 92 and len(ENTRY_BUILD_FILES) == 19
            and set(PROFILE_SOURCE_FILES).isdisjoint(RESOURCES),
            'original worker 210-resource profile must remain independent')
    require(resources == RESOURCES, 'explicit whole-package resource roles differ')
    return resources


def capture_optional_sources():
    """Capture the explicit sdist-only optional union without reopening it."""
    from hepta.hia_optional_profiles import OPTIONAL_PROFILE_FILES
    identities, captures = {}, {}
    for profile in OPTIONAL_PROFILE_FILES:
        identity, current = profile_capture(profile)
        identities[profile] = identity
        for name, raw in current.items():
            require(name not in captures or captures[name] == raw,
                    'overlapping optional declarations disagree')
            captures[name] = raw
    return identities, captures


def guard_optional_sources(identities):
    from hepta.hia_optional_profiles import OPTIONAL_PROFILE_FILES, guard_profile_identity
    require(type(identities) is dict and set(identities) == set(OPTIONAL_PROFILE_FILES),
            'complete declared optional identities required')
    for profile, identity in identities.items():
        guard_profile_identity(profile, identity, resource_root=ROOT)


def wheel_bytes(path, expected):
    with zipfile.ZipFile(path) as archive:
        require(archive.testzip() is None, 'complete wheel CRC failed')
        names = archive.namelist()
        require(len(names) == len(set(names)), 'duplicate wheel member')
        wanted = {'hepta/_data/' + name for name in expected}
        require({name for name in names if name.startswith('hepta/_data/') and not name.endswith('/')} == wanted,
                'wheel selected resource closure differs')
        for name, raw in expected.items():
            require(archive.read('hepta/_data/' + name) == raw, 'wheel source bytes differ: ' + name)
        package = {p.relative_to(ROOT).as_posix(): p.read_bytes()
                   for p in (ROOT / 'hepta').rglob('*.py') if '__pycache__' not in p.parts}
        require({name for name in names if name.startswith('hepta/') and name.endswith('.py')} == set(package),
                'complete installed Python package differs')
        for name, raw in package.items():
            require(archive.read(name) == raw, 'wheel package source differs: ' + name)


def run(ctx, directory):
    from tests.test_hia_agent_installed_resources import SDIST_SUPPORT_FILES
    from hepta.hia_optional_profiles import OPTIONAL_PROFILE_FILES
    from tools.build_hia_linux_file_roundtrip_cold import build_portable_bundle
    from tests.hia_linux_process_cases import direct
    folder = Path(directory) / 'portable'; folder.mkdir(mode=0o700)
    report = {'schema': 'hepta.hia.roundtrip-portable-observations.v1', 'status': 'FAIL',
        'profile': PROFILE, 'matching_cold': False, 'whole_native': False,
        'default_activated': False, 'commands': [], 'kernel_cases': []}
    commands = report['commands']
    authority = ctx['authority']
    runtime_context = None
    environment = {'PATH': os.environ.get('PATH', ''), 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
        'PYTHONDONTWRITEBYTECODE': '1', 'PIP_NO_INDEX': '1', 'PIP_DISABLE_PIP_VERSION_CHECK': '1',
        'PIP_NO_CACHE_DIR': '1'}
    source = folder / 'source'

    def command(label, arguments, *, cwd=source, profile=False, success=True, error=None):
        guard_runtime_context(runtime_context)
        env = {**environment, **({BUILD_PROFILE_ENV: PROFILE} if profile else {})}
        args = [sys.executable, '-B', *map(str, arguments)]
        request = {'label': label, 'command': args, 'cwd': str(cwd), 'environment': env,
                   'timeout_seconds': COMMAND_SECONDS, 'expected_success': success, 'expected_error': error,
                   'runtime_launch_context': runtime_context}
        publish(folder / (label + '.REQUEST.json'), request)
        row = {**request, 'timed_out': False, 'returncode': None}
        stdout = stderr = b''
        try:
            result = subprocess.run(args, cwd=cwd, env=env, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, timeout=COMMAND_SECONDS)
            stdout, stderr = result.stdout, result.stderr; row['returncode'] = result.returncode
        except subprocess.TimeoutExpired as exc:
            row.update(timed_out=True, traceback=traceback.format_exc())
            stdout, stderr = exc.stdout or b'', exc.stderr or b''
            raise
        except BaseException:
            row['traceback'] = traceback.format_exc(); raise
        finally:
            out = folder / (label + '.stdout'); err = folder / (label + '.stderr')
            out.write_bytes(stdout); err.write_bytes(stderr)
            row.update(stdout=pin(out), stderr=pin(err)); commands.append(row)
            publish(folder / (label + '.COMMAND.json'), row)
        guard_runtime_context(runtime_context)
        require(type(row['returncode']) is int and (row['returncode'] == 0) is success,
                'portable command outcome differs: ' + label)
        if error is not None:
            require(error.encode() in stderr, 'installed refusal has a different failure boundary: ' + label)
        return stdout

    try:
        runtime_context = capture_runtime_context()
        environment = runtime_child_environment(environment, runtime_context)
        report['runtime_launch_context'] = runtime_context
        selected = (*default_resources(), *PROFILE_SOURCE_FILES)
        optional_identities, optional_sources = capture_optional_sources()
        originals = {name: optional_sources[name] if name in optional_sources else (ROOT / name).read_bytes() for name in selected}
        optional = tuple(dict.fromkeys(name for names in OPTIONAL_PROFILE_FILES.values() for name in names))
        source.mkdir(mode=0o700)
        shutil.copytree(ROOT / 'hepta', source / 'hepta', ignore=shutil.ignore_patterns('__pycache__'))
        for name in (*selected, *optional, *SDIST_SUPPORT_FILES, 'setup.py', 'pyproject.toml', 'MANIFEST.in'):
            target = source / name; target.parent.mkdir(parents=True, exist_ok=True)
            if name in optional_sources:
                target.write_bytes(optional_sources[name])
            else:
                shutil.copyfile(ROOT / name, target)
        command('sdist', ['setup.py', 'sdist', '--dist-dir', folder / 'sdist'])
        archive, = (folder / 'sdist').glob('*.tar.gz')
        with tarfile.open(archive) as tar:
            members = tar.getmembers(); names = [member.name for member in members]
            require(len(names) == len(set(names)), 'duplicate sdist member')
            prefix = members[0].name.split('/')[0] + '/'
            for name in (*selected, *optional):
                member = tar.getmember(prefix + name)
                expected = optional_sources[name] if name in optional_sources else originals[name]
                require(member.isfile() and tar.extractfile(member).read() == expected,
                        'sdist original/optional source differs: ' + name)
        command('default-wheel', ['-m', 'pip', 'wheel', '--no-deps', '--no-build-isolation',
            '--wheel-dir', folder / 'default-wheel', archive])
        ordinary, = (folder / 'default-wheel').glob('*.whl')
        wheel_bytes(ordinary, {name: originals[name] for name in default_resources()})
        command('selected-wheel', ['-m', 'pip', 'wheel', '--no-deps', '--no-build-isolation',
            '--wheel-dir', folder / 'selected-wheel', archive], profile=True)
        wheel, = (folder / 'selected-wheel').glob('*.whl'); wheel_bytes(wheel, originals)
        installed = folder / 'installed'
        command('install', ['-m', 'pip', 'install', '--no-deps', '--no-index', '--target', installed, wheel])
        installed_identity, installed_sources = profile_capture(resource_root=installed / 'hepta/_data')
        require(installed_identity == authority['optional_profile'], 'installed profile identity differs')
        for name, raw in originals.items():
            actual = installed_sources[name] if name in installed_sources else (installed / 'hepta/_data' / name).read_bytes()
            require(actual == raw, 'installed source differs: ' + name)
        bundle_path = build_portable_bundle(folder / 'bundle', ctx['production_path'])
        bundle = decode(bundle_path.read_bytes()); executable = Path(bundle['executable']['path'])
        request = {'installed': str(installed), 'bundle': str(bundle_path.parent), 'profile': PROFILE,
            'profile_identity': authority['optional_profile'],
            'executable_sha256': ctx['production']['executable']['sha256'],
            'executable_bytes': ctx['production']['executable']['bytes']}
        request_path = folder / 'INSTALLED-REQUEST.json'; publish(request_path, request)
        helper = ROOT / 'tests/hia_linux_file_roundtrip_installed.py'
        args = ['-I', '-S', helper, request_path]
        observed = decode(command('installed', args, cwd=folder))
        require(observed['identity'] == authority['optional_profile'], 'installed profile identity differs')
        inputs = {row['name']: row for row in ctx['retained']['kernel_cases']}
        for name in PORTABLE_CASES:
            case = inputs[name]; item = folder / ('kernel-' + name); item.mkdir()
            path = item / 'input.json'; raw = retained_bytes(case['input']); path.write_bytes(raw)
            actual = direct(item / 'native', executable,
                (b'hia-native-file-roundtrip', b'render-assembly', os.fsencode(path)), (b'LC_ALL=C.UTF-8',))
            require(actual['returncode'] == case['declared']['expected'] and not actual['timed_out']
                    and actual['reaped_ECHILD'] and actual['exec_failure'] is None
                    and bytes.fromhex(actual['stdout_hex']) == retained_bytes(case['stdout'])
                    and bytes.fromhex(actual['stderr_hex']) == retained_bytes(case['stderr'])
                    and path.read_bytes() == raw, 'installed actual native observation differs: ' + name)
            report['kernel_cases'].append({'name': name, 'observation': pin(item / 'native/OBSERVATION.json')})
        # These are real installed-file refusals, before any payload execution.
        for index, name in enumerate(PROFILE_SOURCE_FILES):
            path = Path(observed['paths'][name]); raw = installed_sources[name]; mode = captured_source_binding(path, raw)['mode']
            path.unlink()
            try:
                command('missing-' + str(index), args, cwd=ROOT, success=False, error='FileNotFoundError')
            finally:
                path.write_bytes(raw); path.chmod(mode)
        first = Path(observed['paths'][PROFILE_SOURCE_FILES[0]])
        raw = installed_sources[PROFILE_SOURCE_FILES[0]]; mode = captured_source_binding(first, raw)['mode']
        first.write_bytes(bytes([raw[0] ^ 1]) + raw[1:])
        try:
            command('changed-source', args, cwd=ROOT, success=False, error='ValueError')
        finally:
            first.write_bytes(raw); first.chmod(mode)
        raw_elf = executable.read_bytes(); executable.chmod(0o700)
        executable.write_bytes(raw_elf[:-1] + bytes([raw_elf[-1] ^ 1])); executable.chmod(0o500)
        try:
            command('changed-ELF', args, cwd=ROOT, success=False, error='AssertionError')
        finally:
            executable.chmod(0o700); executable.write_bytes(raw_elf); executable.chmod(0o500)
        require(decode(command('restored', args, cwd=folder)) == observed, 'restored installed observation differs')
        guard_authority(authority)
        guard_optional_sources(optional_identities)
        final_installed_identity, final_installed_sources = profile_capture(resource_root=installed / 'hepta/_data')
        require((final_installed_identity, final_installed_sources) == (installed_identity, installed_sources),
                'installed sources changed after the real refusal controls')
        report.update(status='PASS', archive=pin(archive), default_wheel=pin(ordinary), wheel=pin(wheel),
            installed=str(installed), bundle=pin(bundle_path), observed=observed,
            default_resource_count=210, selected_resource_count=215,
            actual_kernel_execution=True, installed_payload_requires_python=False,
            source_and_inputs_unchanged=True, resource_bindings=[
                captured_source_binding(installed / 'hepta/_data' / n, installed_sources[n])
                if n in installed_sources else pin(installed / 'hepta/_data' / n) for n in selected])
        package = sorted(p.relative_to(ROOT).as_posix() for p in (ROOT / 'hepta').rglob('*.py')
                         if '__pycache__' not in p.parts)
        for name in package:
            require((installed / name).read_bytes() == (ROOT / name).read_bytes(), 'installed package differs: ' + name)
        report['package_bindings'] = [pin(installed / name) for name in package]
        publish(folder / 'RESOURCE-READBACK.json', {
            'default': {name: {'bytes': len(originals[name]), 'sha256': digest(originals[name])} for name in default_resources()},
            'explicit_optional': authority['optional_profile'],
            'all_sdist_wheel_installed_bytes_equal': True,
            'default_count': 210, 'selected_count': 215})
    except BaseException:
        report.update(status='FAIL', traceback=traceback.format_exc()); raise
    finally:
        active_error = sys.exc_info()[0] is not None
        runtime_error = None
        try:
            require(runtime_context is not None, 'no actual portable runtime context captured')
            report['runtime_after'] = guard_runtime_context(runtime_context)
            report['runtime_unchanged'] = True
        except BaseException as error:
            runtime_error = error
            report.update(status='FAIL', runtime_unchanged=False,
                          runtime_final_guard_error=traceback.format_exc())
        publish(folder / 'COMMANDS.json', commands)
        publish(folder / 'PORTABLE-RESULT.json', report)
        if runtime_error is not None and not active_error:
            raise runtime_error
    return report


def verify(ctx, directory):
    """Re-read every actual package/command/kernel result without executing it."""
    from hepta.hia_optional_profiles import OPTIONAL_PROFILE_FILES, fresh_profile_identity
    from tools.build_hia_linux_file_roundtrip_cold import BUNDLE_SCHEMA, _header, _saved
    from tools.hia_linux_file_roundtrip_readback import actual_kernel
    folder = Path(directory) / 'portable'
    report = decode((folder / 'PORTABLE-RESULT.json').read_bytes())
    require(report.get('schema') == 'hepta.hia.roundtrip-portable-observations.v1'
            and report.get('status') == 'PASS' and report.get('profile') == PROFILE
            and report.get('matching_cold') is False and report.get('whole_native') is False
            and report.get('default_activated') is False and report.get('actual_kernel_execution') is True
            and report.get('installed_payload_requires_python') is False
            and report.get('source_and_inputs_unchanged') is True
            and type(report.get('default_resource_count')) is int and report['default_resource_count'] == 210
            and type(report.get('selected_resource_count')) is int and report['selected_resource_count'] == 215,
            'complete actual portable observation required')
    runtime_context = report.get('runtime_launch_context')
    require(report.get('runtime_unchanged') is True
            and report.get('runtime_after') == runtime_context,
            'complete actual portable runtime binding required')
    guard_runtime_context(runtime_context)
    archive, = (folder / 'sdist').glob('*.tar.gz')
    ordinary, = (folder / 'default-wheel').glob('*.whl')
    wheel, = (folder / 'selected-wheel').glob('*.whl')
    installed = folder / 'installed'
    require(report['archive'] == pin(archive) and report['default_wheel'] == pin(ordinary)
            and report['wheel'] == pin(wheel) and report['installed'] == str(installed),
            'actual package artifacts differ')
    names = (*default_resources(), *PROFILE_SOURCE_FILES)
    optional_identities, optional_sources = capture_optional_sources()
    originals = {name: optional_sources[name] if name in optional_sources else (ROOT / name).read_bytes() for name in names}
    optional = tuple(dict.fromkeys(name for values in OPTIONAL_PROFILE_FILES.values() for name in values))
    with tarfile.open(archive) as tar:
        members = tar.getmembers(); seen = [member.name for member in members]
        require(len(seen) == len(set(seen)), 'duplicate retained sdist path')
        prefix = members[0].name.split('/')[0] + '/'
        for name in (*names, *optional):
            member = tar.getmember(prefix + name)
            expected = optional_sources[name] if name in optional_sources else originals[name]
            require(member.isfile() and tar.extractfile(member).read() == expected,
                    'complete retained sdist bytes differ')
    wheel_bytes(ordinary, {name: originals[name] for name in default_resources()})
    wheel_bytes(wheel, originals)
    installed_identity, installed_sources = profile_capture(resource_root=installed / 'hepta/_data')
    require(installed_identity == ctx['authority']['optional_profile'], 'retained installed profile differs')
    require(report['resource_bindings'] == [
        captured_source_binding(installed / 'hepta/_data' / name, installed_sources[name])
        if name in installed_sources else pin(installed / 'hepta/_data' / name) for name in names],
            'installed resource bindings differ')
    for name, raw in originals.items():
        actual = installed_sources[name] if name in installed_sources else (installed / 'hepta/_data' / name).read_bytes()
        require(actual == raw, 'installed resources differ')
    package = sorted(p.relative_to(ROOT).as_posix() for p in (ROOT / 'hepta').rglob('*.py')
                     if '__pycache__' not in p.parts)
    require(report['package_bindings'] == [pin(installed / name) for name in package],
            'installed package bindings differ')
    for name in package:
        require((installed / name).read_bytes() == (ROOT / name).read_bytes(), 'installed module bytes differ')
    bundle_path = folder / 'bundle/BUILD.json'; bundle = decode(bundle_path.read_bytes())
    _header(bundle, BUNDLE_SCHEMA, ctx['authority']); _saved(bundle_path, bundle)
    require(report['bundle'] == pin(bundle_path) and bundle['production'] == pin(ctx['production_path'])
            and (folder / 'bundle/SOURCE-BUILD.json').read_bytes() == Path(ctx['production_path']).read_bytes(),
            'installed bundle lost actual current-cold build lineage')
    executable = folder / 'bundle/bin/hia-native-file-roundtrip'
    require(bundle['executable'] == pin(executable) and bundle['executable']['mode'] == 0o500
            and executable.read_bytes() == Path(ctx['production']['executable']['path']).read_bytes()
            and bundle['resources'] == fresh_profile_identity(PROFILE, resource_root=folder / 'bundle/resources')
            == ctx['authority']['optional_profile'], 'installed ELF/profile bytes differ from actual cold build')
    observed = report['observed']; request_path = folder / 'INSTALLED-REQUEST.json'
    request = decode(request_path.read_bytes())
    require(request == {'installed': str(installed), 'bundle': str(bundle_path.parent), 'profile': PROFILE,
        'profile_identity': ctx['authority']['optional_profile'],
        'executable_sha256': ctx['production']['executable']['sha256'],
        'executable_bytes': ctx['production']['executable']['bytes']}, 'installed input request differs')
    require(observed.get('schema') == 'hepta.hia.roundtrip-installed-observation.v1'
            and observed.get('profile') == PROFILE and observed.get('identity') == ctx['authority']['optional_profile']
            and observed.get('paths') == {name: str((installed / 'hepta/_data' / name).resolve()) for name in PROFILE_SOURCE_FILES}
            and observed.get('optional_module') == str((installed / 'hepta/hia_optional_profiles.py').resolve())
            and observed.get('executable_bytes') == len(executable.read_bytes())
            and type(observed.get('executable_bytes')) is int
            and observed.get('executable_sha256') == digest(executable.read_bytes())
            and observed.get('actual_kernel_execution') is False and observed.get('matching_cold') is False
            and observed.get('whole_native') is False
            and observed.get('request_sha256') == digest(request_path.read_bytes()),
            'actual installed module observation differs')
    environment = {'PATH': os.environ.get('PATH', ''), 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
        'PYTHONDONTWRITEBYTECODE': '1', 'PIP_NO_INDEX': '1', 'PIP_DISABLE_PIP_VERSION_CHECK': '1',
        'PIP_NO_CACHE_DIR': '1'}
    environment = runtime_child_environment(environment, runtime_context)
    source = folder / 'source'
    helper_args = ['-I', '-S', ROOT / 'tests/hia_linux_file_roundtrip_installed.py', request_path]
    specifications = [
        ('sdist', ['setup.py', 'sdist', '--dist-dir', folder / 'sdist'], source, False, True, None),
        ('default-wheel', ['-m', 'pip', 'wheel', '--no-deps', '--no-build-isolation', '--wheel-dir', folder / 'default-wheel', archive], source, False, True, None),
        ('selected-wheel', ['-m', 'pip', 'wheel', '--no-deps', '--no-build-isolation', '--wheel-dir', folder / 'selected-wheel', archive], source, True, True, None),
        ('install', ['-m', 'pip', 'install', '--no-deps', '--no-index', '--target', installed, wheel], source, False, True, None),
        ('installed', helper_args, folder, False, True, None),
        *[('missing-' + str(index), helper_args, ROOT, False, False, 'FileNotFoundError') for index in range(5)],
        ('changed-source', helper_args, ROOT, False, False, 'ValueError'),
        ('changed-ELF', helper_args, ROOT, False, False, 'AssertionError'),
        ('restored', helper_args, folder, False, True, None),
    ]
    commands = decode((folder / 'COMMANDS.json').read_bytes())
    require(report['commands'] == commands and len(commands) == len(specifications), 'full portable command list differs')
    for row, (label, arguments, cwd, profile, success, error) in zip(commands, specifications, strict=True):
        wanted = {'label': label, 'command': [sys.executable, '-B', *map(str, arguments)], 'cwd': str(cwd),
            'environment': {**environment, **({BUILD_PROFILE_ENV: PROFILE} if profile else {})},
            'timeout_seconds': COMMAND_SECONDS, 'expected_success': success, 'expected_error': error,
            'runtime_launch_context': runtime_context}
        require(decode((folder / (label + '.REQUEST.json')).read_bytes()) == wanted
                and decode((folder / (label + '.COMMAND.json')).read_bytes()) == row
                and all(row.get(key) == value and type(row[key]) is type(value) for key, value in wanted.items())
                and row.get('timed_out') is False and type(row.get('returncode')) is int
                and (row['returncode'] == 0) is success
                and row['stdout'] == pin(folder / (label + '.stdout'))
                and row['stderr'] == pin(folder / (label + '.stderr')), 'actual portable command differs: ' + label)
        stderr = (folder / (label + '.stderr')).read_bytes()
        require(error is None or error.encode() in stderr, 'portable refusal changed boundary: ' + label)
    require(decode((folder / 'installed.stdout').read_bytes()) == decode((folder / 'restored.stdout').read_bytes()) == observed,
            'actual installed/restored stdout differs')
    resource_report = decode((folder / 'RESOURCE-READBACK.json').read_bytes())
    require(resource_report == {
        'default': {name: {'bytes': len(originals[name]), 'sha256': digest(originals[name])} for name in default_resources()},
        'explicit_optional': ctx['authority']['optional_profile'], 'all_sdist_wheel_installed_bytes_equal': True,
        'default_count': 210, 'selected_count': 215}, 'complete installed resource report differs')
    originals = {row['name']: row for row in ctx['retained']['kernel_cases']}
    actual_rows = []
    for name in PORTABLE_CASES:
        case = originals[name]; item = folder / ('kernel-' + name); path = item / 'input.json'
        require(path.read_bytes() == retained_bytes(case['input']), 'portable original input differs')
        actual, _ = actual_kernel(item / 'native', executable,
            (b'hia-native-file-roundtrip', b'render-assembly', os.fsencode(path)))
        require(actual['returncode'] == case['declared']['expected']
                and bytes.fromhex(actual['stdout_hex']) == retained_bytes(case['stdout'])
                and bytes.fromhex(actual['stderr_hex']) == retained_bytes(case['stderr']),
                'actual installed payload differs from original oracle')
        actual_rows.append({'name': name, 'observation': pin(item / 'native/OBSERVATION.json')})
    require(report['kernel_cases'] == actual_rows, 'actual installed kernel control list differs')
    guard_authority(ctx['authority'])
    guard_optional_sources(optional_identities)
    final_identity, final_sources = profile_capture(resource_root=installed / 'hepta/_data')
    require((final_identity, final_sources) == (installed_identity, installed_sources),
            'installed profile changed during parent readback')
    guard_runtime_context(runtime_context)
    return {'report': pin(folder / 'PORTABLE-RESULT.json'), 'resource_readback': pin(folder / 'RESOURCE-READBACK.json'),
            'kernel_cases': actual_rows, 'default_resource_count': 210, 'selected_resource_count': 215}


class RoundtripProfileCaptureSourceTests(unittest.TestCase):
    """New source-only controls; the original sixteen bodies remain exact."""

    def test_current_profile_capture_does_not_reopen_asset_paths(self):
        from tools import hia_linux_file_roundtrip_cold as custody
        paths = {custody.ROOT / name for name in custody.PROFILE_SOURCE_FILES}
        actual_read = Path.read_bytes
        attempted = []
        def ordinary_read(path):
            if path in paths:
                attempted.append(str(path))
                raise AssertionError('ordinary reopen after safe profile capture')
            return actual_read(path)
        with mock.patch.object(Path, 'read_bytes', ordinary_read):
            identity, captures = custody.profile_capture()
            self.assertEqual(custody.profile_identity(), identity)
        self.assertEqual(attempted, [])
        self.assertEqual(set(captures), set(custody.PROFILE_SOURCE_FILES))
        self.assertEqual(identity['files'], {name: {'bytes': len(raw), 'sha256': digest(raw)}
                                           for name, raw in captures.items()})

    def test_same_captured_objects_reach_payload_projection(self):
        from tools import build_hia_linux_file_roundtrip_cold as builder
        from tools import hia_linux_file_roundtrip_cold as custody
        _, captures = custody.profile_capture()
        checked = object()
        with mock.patch.object(Path, 'read_bytes', side_effect=AssertionError('must consume captured bytes')), \
                mock.patch.object(builder, 'assemble_program', return_value=checked) as parse, \
                mock.patch.object(builder, 'render_assembly', return_value='source-only-render-marker') as render, \
                mock.patch.object(builder, '_checked_components') as components:
            values = builder._payload_sources(captures)
        self.assertIs(parse.call_args.args[0], captures[custody.CONTROLLER_SOURCE])
        self.assertEqual(parse.call_args.kwargs, {'profile': custody.PROFILE})
        self.assertIs(render.call_args.args[0], checked)
        expected = tuple(captures[name] for name in (custody.REPRESENTATION_SOURCE, custody.SEMANTIC_SOURCE))
        self.assertTrue(all(a is b for a, b in zip(components.call_args.args[0], expected, strict=True)))
        self.assertEqual(values[0], b'source-only-render-marker')
        self.assertTrue(all(a is b for a, b in zip(values[1:], expected, strict=True)))

    def test_capture_identity_and_exact_bytes_must_agree(self):
        from hepta import hia_optional_profiles as optional
        from tools import hia_linux_file_roundtrip_cold as custody
        identity, captures = optional.fresh_profile_capture(custody.PROFILE, resource_root=custody.ROOT)
        first = custody.PROFILE_SOURCE_FILES[0]
        changed = dict(captures); changed[first] = changed[first][:-1] + bytes([changed[first][-1] ^ 1])
        missing = dict(captures); missing.pop(first)
        extra = dict(captures); extra['undeclared'] = b'no authority'
        mutable = dict(captures); mutable[first] = bytearray(mutable[first])
        for bad in (changed, missing, extra, mutable):
            with self.subTest(keys=tuple(bad), value_type=type(bad.get(first)).__name__), \
                    mock.patch.object(optional, 'fresh_profile_capture', return_value=(identity, bad)), \
                    mock.patch.object(optional, 'guard_profile_identity', side_effect=AssertionError('must refuse before guard')) as guard:
                with self.assertRaises(ValueError): custody.profile_capture()
                guard.assert_not_called()

    def test_replacement_after_real_capture_is_refused_without_plain_open(self):
        from hepta import hia_optional_profiles as optional
        from tools import hia_linux_file_roundtrip_cold as custody
        _, sources = optional.fresh_profile_capture(custody.PROFILE, resource_root=custody.ROOT)
        actual_capture = optional.fresh_profile_capture
        actual_read = Path.read_bytes
        for replacement in ('fifo', 'symlink'):
            with self.subTest(replacement=replacement), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                for name, raw in sources.items():
                    path = root / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(raw)
                target = root / custody.PROFILE_SOURCE_FILES[0]
                backup = target.with_name(target.name + '.saved')
                replaced, ordinary_opens = [], []
                def after_capture(profile, **kwargs):
                    observed = actual_capture(profile, **kwargs)
                    if not replaced:
                        target.rename(backup)
                        if replacement == 'fifo': os.mkfifo(target)
                        else: target.symlink_to(backup)
                        replaced.append(replacement)
                    return observed
                def no_ordinary_open(path):
                    if path in {root / name for name in sources}:
                        ordinary_opens.append(str(path))
                        raise AssertionError('unsafe path reopen after actual capture')
                    return actual_read(path)
                try:
                    with mock.patch.object(custody, 'ROOT', root), \
                            mock.patch.object(optional, 'fresh_profile_capture', after_capture), \
                            mock.patch.object(Path, 'read_bytes', no_ordinary_open):
                        with self.assertRaises((ValueError, OSError)): custody.profile_capture()
                    self.assertEqual(replaced, [replacement])
                    self.assertEqual(ordinary_opens, [])
                finally:
                    if target.is_symlink() or target.exists(): target.unlink()
                    if backup.exists(): backup.rename(target)

    def test_terminal_fresh_guard_error_is_not_suppressed(self):
        from hepta import hia_optional_profiles as optional
        from tools import hia_linux_file_roundtrip_cold as custody
        error = ValueError('terminal safe capture guard failed')
        with mock.patch.object(optional, 'guard_profile_identity', side_effect=error) as guard:
            with self.assertRaises(ValueError) as observed: custody.profile_capture()
        self.assertIs(observed.exception, error)
        self.assertEqual(guard.call_count, 1)

    def test_sdist_optional_union_uses_safe_captures(self):
        from hepta.hia_optional_profiles import OPTIONAL_PROFILE_FILES
        names = {name for files in OPTIONAL_PROFILE_FILES.values() for name in files}
        actual_read = Path.read_bytes
        def ordinary_read(path):
            if path in {ROOT / name for name in names}:
                raise AssertionError('optional sdist source was reopened')
            return actual_read(path)
        with mock.patch.object(Path, 'read_bytes', ordinary_read):
            identities, captures = capture_optional_sources()
            guard_optional_sources(identities)
        self.assertEqual(set(identities), set(OPTIONAL_PROFILE_FILES))
        self.assertEqual(set(captures), names)
        self.assertEqual(len(names), 8)
        self.assertTrue(names.isdisjoint(default_resources()))

    def test_runtime_context_binds_three_environments_and_refuses_wrong_runtime(self):
        import ast
        import copy
        from tools import hia_linux_file_roundtrip_cold as custody
        from tools import qualify_hia_linux_file_roundtrip as qualifier
        context = custody.capture_runtime_context()
        self.assertEqual(context['launch_executable'], sys.executable)
        self.assertEqual(context['executable']['path'], str(Path(sys.executable).resolve()))
        self.assertEqual(context['version'], list(sys.version_info[:3]))
        self.assertEqual(context['sysconfig']['Py_ENABLE_SHARED'], 1)
        self.assertIs(qualifier.runtime_child_environment, custody.runtime_child_environment)
        self.assertIs(runtime_child_environment, custody.runtime_child_environment)
        # The three actual producer/readback sites must use the same captured
        # context; no source string is accepted as evidence of a child launch.
        for filename, function in (('tools/qualify_hia_linux_file_roundtrip.py', 'qualify'),
                                   ('tests/hia_linux_file_roundtrip_portable.py', 'run'),
                                   ('tests/hia_linux_file_roundtrip_portable.py', 'verify')):
            module = ast.parse((ROOT / filename).read_bytes())
            node = next(item for item in module.body if isinstance(item, ast.FunctionDef) and item.name == function)
            calls = [item for item in ast.walk(node) if isinstance(item, ast.Call)
                     and isinstance(item.func, ast.Name) and item.func.id == 'runtime_child_environment']
            self.assertEqual(len(calls), 1, function)
            self.assertEqual(ast.dump(calls[0], include_attributes=False), ast.dump(
                ast.parse('runtime_child_environment(environment, runtime_context)', mode='eval').body,
                include_attributes=False))
        base = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'PYTHONDONTWRITEBYTECODE': '1'}
        with mock.patch.dict(os.environ, {'LD_LIBRARY_PATH': '/untrusted/ambient/lib',
                                         'LD_PRELOAD': '/untrusted/ambient/preload.so'}):
            actual = custody.runtime_child_environment(base, context)
        self.assertEqual(actual, {**base, 'LD_LIBRARY_PATH': context['library_directory']})
        self.assertEqual(base, {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'PYTHONDONTWRITEBYTECODE': '1'})
        self.assertNotIn('LD_PRELOAD', actual)
        wrong_executable = copy.deepcopy(context); wrong_executable['launch_executable'] += '-wrong'
        wrong_library = copy.deepcopy(context); wrong_library['library']['sha256'] = '0' * 64
        for value in (wrong_executable, wrong_library):
            with self.subTest(refusal='mismatched-context'):
                with self.assertRaises(ValueError): custody.runtime_child_environment(base, value)
        for variable in ('LD_LIBRARY_PATH', 'LD_PRELOAD'):
            with self.subTest(refusal=variable):
                with self.assertRaises(ValueError):
                    custody.runtime_child_environment({**base, variable: '/untrusted'}, context)
        with mock.patch.object(sys, 'executable', context['launch_executable'] + '-absent'):
            with self.assertRaises((ValueError, OSError)): custody.capture_runtime_context()
        names = tuple(dict.fromkeys(context['sysconfig'][key] for key in ('LDLIBRARY', 'INSTSONAME')))
        library = context['library']
        mapped_line = ('1000-2000 r-xp 0000 %x:%x %d %s' % (
            os.major(library['device']), os.minor(library['device']), library['inode'], library['path'])).encode()
        for bad in (mapped_line + b' (deleted)',
                    mapped_line.rsplit(b' ', 1)[0] + b' ' + Path(library['path']).name.encode()):
            with self.subTest(refusal='deleted-or-relative-mapping'):
                with self.assertRaises(ValueError): custody._runtime_library_mappings(bad, names)
        actual_read = Path.read_bytes
        extra = mapped_line.rsplit(b' ', 1)[0] + b' /missing-second-library/' + Path(library['path']).name.encode()
        def ambiguous_maps(path):
            if path == Path('/proc/self/maps'): return mapped_line + b'\n' + extra + b'\n'
            return actual_read(path)
        with mock.patch.object(Path, 'read_bytes', ambiguous_maps):
            with self.assertRaises(ValueError): custody.capture_runtime_context()
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            with self.assertRaises(ValueError): custody._runtime_file(folder)
            fifo = folder / 'fifo'; os.mkfifo(fifo)
            with self.assertRaises(ValueError): custody._runtime_file(fifo)
            source = folder / 'ordinary'; source.write_bytes(b'ABC')
            real_read = os.read; changed = []
            def replace_during_read(fd, capacity):
                raw = real_read(fd, capacity)
                if not changed:
                    source.write_bytes(b'XYZ'); changed.append(True)
                return raw
            with mock.patch.object(os, 'read', replace_during_read):
                with self.assertRaises(ValueError): custody._runtime_file(source)
            self.assertEqual(changed, [True])

            requested = []
            def never_eof(fd, capacity):
                requested.append(capacity)
                if len(requested) > 1:
                    raise AssertionError('runtime capture followed a growing file beyond its initial size')
                return b'Z' * capacity
            with mock.patch.object(os, 'read', never_eof):
                with self.assertRaises(ValueError): custody._runtime_file(source)
            self.assertEqual(requested, [4])

        from tools import hia_selfhost_process_owner as process_owner
        import subprocess
        class InterceptedLaunch(Exception):
            pass
        # These are intercepted API controls, not executed supervisors. The
        # separate qualification probe records the one real child launch.
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            for label, extra, supplied in (('omitted', {}, None),
                    ('none', {'supervisor_env': None}, None),
                    ('explicit', {'supervisor_env': actual}, actual)):
                item = folder / label; item.mkdir()
                calls = []
                def intercept(command, **keywords):
                    calls.append((command, keywords))
                    raise InterceptedLaunch
                with mock.patch.object(process_owner.subprocess, 'Popen', intercept):
                    with self.assertRaises(InterceptedLaunch):
                        process_owner.run_owned([sys.executable, '-I', '-B', '-c', 'pass'],
                            cwd=ROOT, env=base, stdout_path=item/'stdout', stderr_path=item/'stderr',
                            receipt_path=item/'owner', qualification_seconds=180, cleanup_seconds=3, **extra)
                self.assertEqual(len(calls), 1)
                command, keywords = calls[0]
                self.assertEqual(command[:5], [sys.executable, '-I', '-S', '-B', str(Path(process_owner.__file__).resolve())])
                self.assertEqual(set(keywords), {'stdin', 'stdout', 'stderr', 'close_fds', 'start_new_session'}
                                 | ({'env'} if supplied is not None else set()))
                self.assertEqual(keywords['stdin'], subprocess.DEVNULL)
                self.assertIs(keywords['close_fds'], True)
                self.assertIs(keywords['start_new_session'], True)
                if supplied is not None: self.assertEqual(keywords['env'], supplied)
                request = custody.decode((item/'owner.request.json').read_bytes())
                self.assertEqual(set(request), {'schema','command','cwd','env','stdout_path','stderr_path',
                    'receipt_path','parent_pid','started_ns','deadline_ns','qualification_seconds',
                    'cleanup_seconds','implementation_sha256'})
                self.assertEqual(request['env'], base)
                self.assertEqual((request['qualification_seconds'], request['cleanup_seconds']), (180, 3))
            class BadDictionary(dict): pass
            invalid = ([], 'bad', {'': 'x'}, {'A=B': 'x'}, {'A': 1}, {1: 'x'},
                       {'A': 'x\0y'}, {'A\0B': 'x'}, BadDictionary(A='x'))
            for index, value in enumerate(invalid):
                item = folder / ('invalid-' + str(index)); item.mkdir()
                with mock.patch.object(process_owner.subprocess, 'Popen', side_effect=AssertionError('invalid environment reached Popen')):
                    with self.assertRaises(process_owner.OwnerFailure):
                        process_owner.run_owned([sys.executable], cwd=ROOT, env=base,
                            stdout_path=item/'stdout', stderr_path=item/'stderr', receipt_path=item/'owner',
                            supervisor_env=value)
                self.assertEqual(list(item.iterdir()), [])
            receipt = {'schema': process_owner.SCHEMA, 'status': 'OWNED_PROCESS_COMPLETED',
                'returncode': 0, 'supervisor_pid': 123, 'cleanup': {'complete': True},
                'request_sha256': '1' * 64, 'implementation_sha256': '2' * 64}
            receipt_path = folder/'receipt.json'; raw = custody.wire(receipt); receipt_path.write_bytes(raw)
            returned = {**receipt, 'supervisor_returncode': 0, 'receipt_sha256': custody.digest(raw)}
            self.assertIs(qualifier._read_owner_return(receipt_path, returned), returned)
            held = {**returned, 'supervisor_returncode': 1, 'status': 'OWNER_EXIT_MISMATCH_HOLD'}
            self.assertIs(qualifier._read_owner_return(receipt_path, held), held)
            missing = dict(returned); del missing['cleanup']
            for value in ({**returned, 'receipt_sha256': '0' * 64}, {**returned, 'extra': 0}, missing,
                          {**returned, 'supervisor_returncode': False},
                          {**held, 'status': 'OWNED_PROCESS_COMPLETED'}):
                with self.subTest(refusal='complete-owner-binding'):
                    with self.assertRaises(ValueError): qualifier._read_owner_return(receipt_path, value)
        owner_ast = next(item for item in ast.parse((ROOT / 'tools/qualify_hia_linux_file_roundtrip.py').read_bytes()).body
                         if isinstance(item, ast.FunctionDef) and item.name == '_owner')
        launches = [item for item in ast.walk(owner_ast) if isinstance(item, ast.Call)
                    and isinstance(item.func, ast.Name) and item.func.id == 'run_owned']
        self.assertEqual(len(launches), 1)
        explicit = next(item.value for item in launches[0].keywords if item.arg == 'supervisor_env')
        self.assertEqual(ast.dump(explicit), ast.dump(ast.Name(id='environment', ctx=ast.Load())))
