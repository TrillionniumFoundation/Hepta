"""Actual v6 admission controls in a private copy of a freshly built tree.

The primary source/build/receipt tree is read only. No original fixture,
business expectation or Native resource bound is edited by these controls.
"""
from pathlib import Path
from hashlib import sha256
import argparse
import copy
import json
import shutil
import sys
import types
import unittest

def pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}

def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    source, output = args.source.resolve(strict=True), args.output.resolve()
    output.mkdir(mode=0o700)
    original = {p.relative_to(source).as_posix(): pin(p.read_bytes())
                for p in sorted(source.rglob('*')) if p.is_file()}
    control = output / 'control-source'
    shutil.copytree(source, control)
    for path in control.rglob('*'):
        if path.is_file(): path.chmod(0o700 if path.stat().st_mode & 0o111 else 0o600)
    manifest_raw = args.manifest.read_bytes()
    manifest_value = json.loads(manifest_raw)
    component = output / 'component'; component.mkdir()
    image_origin = args.manifest.parent / manifest_value['image_path']
    image_raw = image_origin.read_bytes()
    assert sha256(image_raw).hexdigest() == manifest_value['image_sha256']
    (component / manifest_value['image_path']).write_bytes(image_raw)
    manifest = component / 'manifest.json'; manifest.write_bytes(manifest_raw)
    sys.path.insert(0, str(control))
    from tools.capture_hia_native_carrier_bundle import create
    from hepta import hia_native_helpers as authority
    from hepta import hia_native_image as image_loader
    from hepta import hia_cell_frame as cell_loader
    from hepta import hia_service_artifact_native as artifact
    from hepta import hia_service_verification_native as verification
    base = {'schema': authority.SCHEMA, 'target': authority.TARGET, 'abi': authority.ABI,
            'helpers': [{'selector': 'HEPTA_HIA_SERVICE_ARTIFACT_MANIFEST',
                         'manifest_path': str(manifest), 'manifest_sha256': sha256(manifest_raw).hexdigest()}]}
    base_path = output / 'base-v1.json'; base_path.write_bytes(canonical(base))
    capsule_path = output / 'carrier-v6.json'
    create(control / 'hepta', base_path, sha256(base_path.read_bytes()).hexdigest(),
           {'native-image': sha256((control / 'hepta/_native_image_build.json').read_bytes()).hexdigest()}, capsule_path)
    capsule_raw = capsule_path.read_bytes(); capsule = json.loads(capsule_raw)
    capsule_sha = sha256(capsule_raw).hexdigest()
    controls = []

    class AdmissionTests(unittest.TestCase):
        def admitted(self):
            return authority.native_helpers_scope(str(capsule_path), capsule_sha)

        def refusal(self, label, function, errors=(ValueError,)):
            try: function()
            except errors as error:
                controls.append({'id': label, 'refused': True, 'exception': type(error).__name__})
            else: self.fail('invalid authority was accepted: ' + label)

        def enter(self, path, digest):
            with authority.native_helpers_scope(str(path), digest):
                self.fail('invalid authority reached the active scope')

        def test_00_old_v1_and_unselected_do_not_load_unpinned_c(self):
            self.assertIsNone(image_loader.selected_extension())
            self.assertIsNone(cell_loader.selected_extension())
            self.refusal('unselected-no-linker-authority', image_loader.extension)
            self.assertNotIn('hepta._hia_native_image', sys.modules)
            self.assertNotIn('hepta._hia_cell_frame', sys.modules)
            with authority.native_helpers_scope(str(base_path), sha256(base_path.read_bytes()).hexdigest()) as binding:
                image = artifact.installed_service_artifact(str(manifest))
                self.assertIsNone(image._native_image_carrier)
                self.assertIsNone(image_loader.selected_extension())
                self.assertIsNone(cell_loader.selected_extension())
                self.assertNotIn('hepta._hia_native_image', sys.modules)
                binding.check()
            controls.append({'id': 'original-v1-retains-foreign-carrier', 'passed': True})

        def test_01_current_capsule_real_types_and_repeated_admission(self):
            first = None
            for repeat in range(2):
                with self.admitted() as binding:
                    selected = image_loader.selected_extension()
                    image = artifact.installed_service_artifact(str(manifest))
                    self.assertIs(image._native_image_carrier, selected)
                    self.assertIs(type(image._mapping), selected.Image)
                    self.assertEqual(selected.Buffer(b'ab', 4).raw, b'ab\0\0')
                    if first is not None: self.assertIs(selected, first)
                    first = selected
                    self.refusal('undeclared-cell-bridge-' + str(repeat), cell_loader.selected_extension)
                    binding.check()
                    controls.append({'id': 'fresh-current-scope-' + str(repeat), 'passed': True})

        def test_02_outer_shape_and_all_nested_pins_are_closed(self):
            variants = []
            def alter(label, function):
                value = copy.deepcopy(capsule); function(value); variants.append((label, value))
            alter('schema-old', lambda v: v.update(schema='hepta.hia.native-helpers.v5'))
            alter('schema-future', lambda v: v.update(schema='hepta.hia.native-helpers.v7'))
            alter('target', lambda v: v.update(target='other'))
            alter('abi', lambda v: v.update(abi='other'))
            alter('outer-extra', lambda v: v.update(extra=0))
            alter('bridges-empty', lambda v: v.update(bridges=[]))
            alter('bridges-not-list', lambda v: v.update(bridges={}))
            alter('bridges-duplicate', lambda v: v['bridges'].append(copy.deepcopy(v['bridges'][0])))
            alter('bridge-extra', lambda v: v['bridges'][0].update(extra=0))
            alter('bridge-unregistered', lambda v: v['bridges'][0].update(name='arbitrary'))
            alter('bridge-wrong-owner', lambda v: v['bridges'][0].update(name='cell-frame'))
            alter('bridge-abi', lambda v: v['bridges'][0].update(abi='other'))
            alter('bridge-path', lambda v: v['bridges'][0].update(package_path=str(control)))
            alter('profile-bool-is-not-integer', lambda v: v['bridges'][0]['profile'].update(gil_disabled=0))
            alter('profile-python-bool', lambda v: v['bridges'][0]['profile']['python'].__setitem__(0, True))
            alter('receipt-pin', lambda v: v['bridges'][0]['build_receipt'].update(sha256='0' * 64))
            alter('binary-pin', lambda v: v['bridges'][0]['binary'].update(sha256='0' * 64))
            alter('binary-bytes-bool', lambda v: v['bridges'][0]['binary'].update(bytes=True))
            alter('missing-source', lambda v: v['bridges'][0]['sources'].pop(next(iter(v['bridges'][0]['sources']))))
            for name in capsule['bridges'][0]['sources']:
                alter('source-pin:' + name, lambda v, name=name: v['bridges'][0]['sources'][name].update(sha256='0' * 64))
                alter('source-path:' + name, lambda v, name=name: v['bridges'][0]['sources'][name].update(path=str(control/'hepta/other')))
            for index, (label, value) in enumerate(variants):
                path = output / ('invalid-capsule-' + str(index) + '.json')
                raw = canonical(value); path.write_bytes(raw)
                self.refusal(label, lambda: self.enter(path, sha256(raw).hexdigest()))
            self.refusal('wrong-preexisting-outer-sha', lambda: self.enter(capsule_path, '0' * 64))
            self.refusal('outer-sha-not-text', lambda: self.enter(capsule_path, True))
            for label, raw in (('duplicate-json-key', capsule_raw[:-2] + b',"schema":"duplicate"}\n'),
                               ('nonfinite-json-value', capsule_raw[:-2] + b',"other":NaN}\n')):
                path = output / (label + '.json'); path.write_bytes(raw)
                self.refusal(label, lambda: self.enter(path, sha256(raw).hexdigest()))

        def test_03_actual_source_binary_receipt_are_freshly_read(self):
            paths = [control / name for name in image_loader.SOURCES]
            paths += [control / 'hepta/_native_image_build.json',
                      control / 'hepta' / capsule['bridges'][0]['binary']['name']]
            for path in paths:
                raw, mode = path.read_bytes(), path.stat().st_mode & 0o777
                for missing in (False, True):
                    try:
                        if missing: path.unlink()
                        else: path.write_bytes(raw + b' ')
                        self.refusal(('missing:' if missing else 'changed:') + str(path.relative_to(control)),
                                     lambda: self.enter(capsule_path, capsule_sha), (ValueError, OSError))
                    finally:
                        path.write_bytes(raw); path.chmod(mode)
                with self.admitted() as binding:
                    self.assertIsNotNone(image_loader.selected_extension())
                    binding.check()
                controls.append({'id': 'fresh-after-refused-drift:' + str(path.relative_to(control)), 'passed': True})

        def test_04_terminal_drift_and_stale_binding_never_fall_back(self):
            with self.admitted() as prior:
                prior.check()
            with self.admitted() as binding:
                saved = {name: getattr(authority, name) for name in
                         ('_ACTIVE', '_MECHANICAL_SCOPE', '_MECHANICAL_BUILD', '_MECHANICAL_SELECTED')}
                states = (
                    ('lost-active', {'_ACTIVE': None}),
                    ('foreign-active', {'_ACTIVE': object()}),
                    ('prior-same-thread-v6', {'_ACTIVE': prior}),
                    ('lost-scope', {'_MECHANICAL_SCOPE': None}),
                    ('overlap-constructor', {'_MECHANICAL_BUILD': binding}),
                    ('unselected-with-scope', {'_MECHANICAL_SELECTED': False}),
                    ('untyped-flag', {'_MECHANICAL_SELECTED': 1}),
                    ('lost-all-live-authority', {'_ACTIVE': None, '_MECHANICAL_SCOPE': None}),
                )
                fake = types.SimpleNamespace(image=object(), namespace={}, global_builtins={}, import_capsules={},
                                             _capture=lambda *names: object())
                for label, changes in states:
                    try:
                        for name, value in changes.items(): setattr(authority, name, value)
                        self.refusal('image-select-' + label, image_loader.selected_extension)
                        self.refusal('cell-select-' + label, cell_loader.selected_extension)
                        self.refusal('actual-image-factory-' + label,
                            lambda: artifact.NativeServiceArtifact(image_raw, manifest_value['image_sha256']))
                        self.refusal('actual-private-cell-factory-' + label,
                            lambda: verification.ServiceVerificationFrame._make_acyclic(fake))
                    finally:
                        for name, value in saved.items(): setattr(authority, name, value)
                binding.check()
                path = control / 'hepta/hia_service_artifact_bridge.py'
                raw = path.read_bytes()
                try:
                    path.write_bytes(raw + b' ')
                    self.refusal('complete-terminal-readback', binding.check)
                    self.refusal('cached-loader-rereads-current-source', image_loader.selected_extension)
                finally:
                    path.write_bytes(raw)

        def test_05_export_drift_is_not_repaired_from_cached_success(self):
            with self.admitted() as binding:
                selected = image_loader.selected_extension()
                original = selected.Buffer
                try:
                    selected.Buffer = object
                    self.refusal('executed-export-drift', image_loader.selected_extension)
                finally:
                    selected.Buffer = original
                self.assertIs(image_loader.selected_extension(), selected)
                binding.check()
            self.assertIsNone(image_loader.selected_extension())
            self.refusal('module-cache-does-not-grant-unselected-authority', image_loader.extension)

    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(AdmissionTests))
    after = {p.relative_to(source).as_posix(): pin(p.read_bytes())
             for p in sorted(source.rglob('*')) if p.is_file()}
    stable = (original == after and args.manifest.read_bytes() == manifest_raw
              and image_origin.read_bytes() == image_raw and capsule_path.read_bytes() == capsule_raw)
    report = {'schema': 'hepta.native-carrier-admission-controls.v1',
              'status': 'PASS' if result.wasSuccessful() and stable else 'HOLD',
              'runtime': sys.version, 'tests': result.testsRun, 'controls': controls,
              'control_count': len(controls), 'original_source_and_component_stable': stable,
              'source_before': original, 'source_after': after,
              'primary_source_mutated': False, 'public_component_qualification_claimed': False}
    (output / 'report.json').write_bytes(canonical(report))
    print(json.dumps({key: report[key] for key in ('status', 'runtime', 'tests', 'control_count', 'original_source_and_component_stable')}))
    return 0 if report['status'] == 'PASS' else 1

if __name__ == '__main__':
    raise SystemExit(main())
