"""Real filesystem interleavings for optional-resource captures; no native execution."""
from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import unittest
from unittest.mock import patch

from tests.test_hia_optional_profiles import (
    ROOT, copy_resources, default_resources, setup_functions,
)


def _observed_open_race(invoke, target, mutate, *, occurrence=1):
    """Isolate the irreversible audit hook; a blocking open is an actual failure."""
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(read_fd)
        result = {'fired': False, 'matching_opens': 0, 'status': 'UNFINISHED'}
        def audit(event, arguments):
            if event != 'open' or not isinstance(arguments[0], (str, bytes, os.PathLike)):
                return
            path = os.fsdecode(arguments[0])
            if (Path(path).name != target.name
                    or (Path(path).is_absolute() and Path(path) != target.absolute())):
                return
            result['matching_opens'] += 1
            if result['matching_opens'] == occurrence:
                result.update(fired=True, open_flags=arguments[2], open_path=path)
                mutate()
        def expired(signum, frame):
            raise TimeoutError('filesystem capture blocked after the controlled replacement')
        try:
            signal.signal(signal.SIGALRM, expired)
            signal.alarm(3)
            sys.addaudithook(audit)
            invoke()
            result['status'] = 'ACCEPTED'
        except BaseException as error:
            result.update(status='TIMED_OUT' if isinstance(error, TimeoutError) else 'REJECTED',
                          exception_type=type(error).__name__, exception=str(error))
        finally:
            signal.alarm(0)
            raw = json.dumps(result, sort_keys=True).encode()
            os.write(write_fd, raw)
            os.close(write_fd)
            os._exit(0)
    os.close(write_fd)
    chunks = []
    while True:
        chunk = os.read(read_fd, 65536)
        if not chunk:
            break
        chunks.append(chunk)
    os.close(read_fd)
    waited, status = os.waitpid(pid, 0)
    if waited != pid or status != 0:
        raise AssertionError(('race child did not exit normally', waited, status))
    observed = json.loads(b''.join(chunks))
    print('OPTIONAL_PROFILE_RACE_OBSERVATION ' + json.dumps(observed, sort_keys=True), flush=True)
    return observed


def _replace_with_fifo(target):
    target.unlink()
    os.mkfifo(target)


class OptionalProfileRaceSourceTests(unittest.TestCase):
    def assert_refused_capture(self, result):
        self.assertTrue(result['fired'], result)
        self.assertEqual(result['status'], 'REJECTED', result)
        self.assertIn(result['exception_type'], ('ValueError', 'OSError', 'FileNotFoundError',
                                                'NotADirectoryError'), result)
        self.assertTrue(result['open_flags'] & os.O_NONBLOCK, result)

    def test_installed_report_loader_rejects_fifo_on_second_source_open(self):
        from hepta import hia_cli_verified_report_native as owner
        from hepta import hia_cli_discovery_routing_native as discovery
        from hepta.hia_optional_profiles import fresh_profile_identity
        from hepta.hia_verified_report_native import SCHEMA
        source = 'examples/hia_bootstrap/verified_report.hepta'
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            component = root / 'verified_report'
            resources = component / 'profile-resources'
            copy_resources(resources, (source,))
            target = resources / source
            compiler = 'c' * 64
            control = root / 'control/manifest.json'
            control.parent.mkdir()
            control.write_text(json.dumps({'compiler_sha256': compiler}))
            metadata = {'schema': SCHEMA, 'source_sha256': sha256(target.read_bytes()).hexdigest(),
                        'image_path': 'verified-report.image.bin', 'image_sha256': 'd' * 64,
                        'compiler_sha256': compiler,
                        'profile_resources': {'schema': owner.RESOURCE_SCHEMA,
                            'profile': owner.RESOURCE_PROFILE, 'source_root': 'profile-resources',
                            'source_relative': source, 'source_sha256': sha256(target.read_bytes()).hexdigest(),
                            'identity': fresh_profile_identity(owner.RESOURCE_PROFILE, resource_root=resources),
                            'host_sources': owner.host_compatibility_sources()}}
            report = component / 'manifest.json'
            report.write_text(json.dumps(metadata))
            bundle = {'schema': owner.BUNDLE_SCHEMA}
            for name in ('control', 'format', 'discovery', 'routing', 'parser_context', 'verified_report'):
                manifest = report if name == 'verified_report' else control
                bundle[name + '_manifest'] = manifest.relative_to(root).as_posix()
                bundle[name + '_manifest_sha256'] = sha256(manifest.read_bytes()).hexdigest()
            path = root / 'bundle.json'
            raw = json.dumps(bundle).encode()
            path.write_bytes(raw)
            base = object.__new__(discovery.NativeDiscoveryCli)
            base.parser_context = object()
            # Source-layer interleaving only: the two mapping dependencies are
            # explicit placeholders. No machine image or cold authority is used.
            def invoke():
                with patch.object(discovery, 'installed_bundle', return_value=base), \
                        patch.object(owner, '_load_report_manifest', return_value=object()):
                    owner.installed_bundle(path, raw, bundle)
            observed = _observed_open_race(invoke, target, lambda: _replace_with_fifo(target), occurrence=2)
            self.assert_refused_capture(observed)
            self.assertEqual(observed['matching_opens'], 2)

    def test_all_twelve_host_files_reject_fifo_replacement_before_open(self):
        from hepta import hia_cli_verified_report_native as owner
        for name in owner.HOST_SOURCE_FILES:
            with self.subTest(source=name), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                copy_resources(root, owner.HOST_SOURCE_FILES)
                target = root / name
                def invoke():
                    with patch.object(owner, '__file__', str(root / 'hepta/hia_cli_verified_report_native.py')):
                        owner.host_compatibility_sources()
                observed = _observed_open_race(invoke, target, lambda: _replace_with_fifo(target))
                self.assert_refused_capture(observed)

    def test_profile_capture_rejects_parent_directory_rebinding(self):
        from hepta.hia_optional_profiles import fresh_profile_capture
        profile = 'hepta.hia.cli-verified-report-bundle.v2'
        source = 'examples/hia_bootstrap/verified_report.hepta'
        for replacement in ('symlink', 'new-directory'):
            with self.subTest(replacement=replacement), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                copy_resources(root, (source,))
                target = root / source
                raw = target.read_bytes()
                held = target.parent.with_name('retained-directory')
                def mutate():
                    target.parent.rename(held)
                    if replacement == 'symlink':
                        target.parent.symlink_to(held, target_is_directory=True)
                    else:
                        target.parent.mkdir()
                        target.write_bytes(raw)
                observed = _observed_open_race(
                    lambda: fresh_profile_capture(profile, resource_root=root), target, mutate)
                self.assert_refused_capture(observed)

    def test_optional_packager_uses_captured_source_and_does_not_follow_output_symlink(self):
        from setuptools import Distribution
        from setuptools.command.build_py import build_py
        profile = 'hepta.hia.cli-verified-report-bundle.v2'
        name = 'examples/hia_bootstrap/verified_report.hepta'
        for defect in ('source-fifo', 'output-symlink'):
            with self.subTest(defect=defect), tempfile.TemporaryDirectory() as folder, setup_functions() as values:
                root = Path(folder) / 'source'
                root.mkdir()
                copy_resources(root, (*default_resources(), name, 'hepta/hia_agent_contract.py',
                                      'hepta/hia_optional_profiles.py'))
                globals_ = values['_optional_profile_plan'].__globals__
                previous = globals_['ROOT']
                command = values['AgentResourceBuild'](Distribution({'packages': []}))
                command.build_lib = str(Path(folder) / 'installed')
                source = root / name
                target = Path(command.build_lib) / 'hepta/_data' / name
                try:
                    globals_['ROOT'] = root
                    def invoke():
                        with patch.object(build_py, 'run'), patch.dict(os.environ, {'HEPTA_HIA_BUILD_PROFILES': profile}):
                            command.run()
                    if defect == 'source-fifo':
                        observed = _observed_open_race(invoke, source, lambda: _replace_with_fifo(source), occurrence=2)
                        self.assert_refused_capture(observed)
                    else:
                        outside = Path(folder) / 'outside'
                        original = b'outside must remain untouched'
                        outside.write_bytes(original)
                        target.parent.mkdir(parents=True)
                        target.symlink_to(outside)
                        invoke()
                        self.assertEqual(outside.read_bytes(), original)
                        self.assertFalse(target.is_symlink())
                        self.assertEqual(target.read_bytes(), source.read_bytes())
                finally:
                    globals_['ROOT'] = previous

    def test_optional_parent_symlink_refuses_before_creating_outside_directories(self):
        from setuptools import Distribution
        from setuptools.command.build_py import build_py
        import shutil
        profile = 'hepta.hia.cli-verified-report-bundle.v2'
        name = 'examples/hia_bootstrap/verified_report.hepta'
        original_names = default_resources()
        with tempfile.TemporaryDirectory() as folder, setup_functions() as values:
            root = Path(folder) / 'source'
            root.mkdir()
            copy_resources(root, (*original_names, name, 'hepta/hia_agent_contract.py',
                                  'hepta/hia_optional_profiles.py'))
            globals_ = values['_optional_profile_plan'].__globals__
            previous = globals_['ROOT']
            command = values['AgentResourceBuild'](Distribution({'packages': []}))
            command.build_lib = str(Path(folder) / 'installed')
            source = root / name
            target = Path(command.build_lib) / 'hepta/_data' / name
            outside = Path(folder) / 'outside'
            outside.mkdir()
            captured, injected = [], []
            real_copy, real_is_file = shutil.copyfile, Path.is_file
            def copy_default(source_path, destination_path, *args, **kwargs):
                result = real_copy(source_path, destination_path, *args, **kwargs)
                captured.append(Path(source_path).relative_to(root).as_posix())
                return result
            def admitted_source(path, *args, **kwargs):
                result = real_is_file(path, *args, **kwargs)
                if path == source and result and not injected:
                    # The real original 210 copies have already finished. Only
                    # this optional iteration receives the parent replacement.
                    self.assertEqual(captured, list(original_names))
                    examples = target.parent.parent
                    retained = examples.with_name('default-examples-retained')
                    examples.rename(retained)
                    examples.symlink_to(outside, target_is_directory=True)
                    injected.append(True)
                return result
            try:
                globals_['ROOT'] = root
                with patch.object(build_py, 'run'), patch.dict(os.environ, {'HEPTA_HIA_BUILD_PROFILES': profile}), \
                        patch.object(shutil, 'copyfile', side_effect=copy_default), \
                        patch.object(Path, 'is_file', admitted_source):
                    with self.assertRaises((OSError, ValueError)):
                        command.run()
                observed = sorted(path.relative_to(outside).as_posix() for path in outside.rglob('*'))
                print('OPTIONAL_PARENT_BINDING_OBSERVATION ' + json.dumps({
                    'default_copies_completed': len(captured), 'default_copy_order_exact': captured == list(original_names),
                    'injected_after_optional_is_file': bool(injected), 'outside_paths_after': observed,
                    'scope': 'Optional iteration only; no sandbox claim for the original default branch.'}, sort_keys=True), flush=True)
                self.assertEqual(captured, list(original_names))
                self.assertEqual(injected, [True])
                self.assertEqual(observed, [])
            finally:
                globals_['ROOT'] = previous


if __name__ == '__main__':
    unittest.main()
