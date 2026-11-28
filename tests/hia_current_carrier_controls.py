"""Actual current typed Worker/carrier controls; no default-release claim.

The retained old v6 controls are a separate unchanged command. These controls
exercise the distinct current envelope using real HIA images and real extensions.
"""
from pathlib import Path
from hashlib import sha256
import argparse
import copy
import json
import os
import shutil
import struct
import sys
import types
import unittest
from unittest.mock import patch


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--components', type=Path, required=True)
    parser.add_argument('--policy-release', type=Path, required=True)
    parser.add_argument('--expected-publication-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    source, output = args.source.resolve(strict=True), args.output.resolve()
    output.mkdir(mode=0o700)

    def inventory(root):
        return {p.relative_to(root).as_posix(): {**pin(p.read_bytes()), 'mode': p.stat().st_mode & 0o777}
                for p in sorted(root.rglob('*')) if p.is_file()}

    before = inventory(source)
    control = output / 'source'
    shutil.copytree(source, control)
    for path in control.rglob('*'):
        if path.is_file():
            path.chmod(0o700 if path.stat().st_mode & 0o111 else 0o600)
    components, release = output / 'components', output / 'release'
    shutil.copytree(args.components, components)
    shutil.copytree(args.policy_release, release)
    for root in (components, release):
        for path in root.rglob('*'):
            if path.is_file():
                path.chmod(0o600)
    sys.path.insert(0, str(control))
    from tools.capture_hia_native_carrier_bundle import create as old_create
    from tools.capture_hia_current_carrier_bundle import create
    from hepta import hia_native_helpers as authority
    from hepta import hia_current_carrier_worker_bundle as current
    from hepta import hia_native_image as image_loader
    from hepta import hia_cell_frame as cell_loader
    from hepta import hia_carrier_policy_release as publication
    from hepta import hia_service_artifact_native as artifact
    from hepta import hia_service_verification_native as verification

    artifact_manifest = components / 'artifact' / 'manifest.json'
    verification_manifest = components / 'verification' / 'manifest.json'
    page_bundle = components / 'page' / 'manifest.json'
    base = {'schema': authority.SCHEMA, 'target': authority.TARGET, 'abi': authority.ABI,
            'helpers': [
                {'selector': artifact.SELECTOR, 'manifest_path': str(artifact_manifest),
                 'manifest_sha256': sha256(artifact_manifest.read_bytes()).hexdigest()},
                {'selector': verification.SELECTOR, 'manifest_path': str(verification_manifest),
                 'manifest_sha256': sha256(verification_manifest.read_bytes()).hexdigest()},
            ]}
    base_path = output / 'base-v1.json'
    base_path.write_bytes(canonical(base))
    typed = {'schema': 'hepta.hia.artifact-page-worker-bundle.v1',
             'target': authority.TARGET, 'abi': authority.ABI,
             'base_bundle': str(base_path), 'base_bundle_sha256': sha256(base_path.read_bytes()).hexdigest(),
             'page_bundle': str(page_bundle), 'page_bundle_sha256': sha256(page_bundle.read_bytes()).hexdigest()}
    typed_path = output / 'typed-page.json'
    typed_path.write_bytes(canonical(typed))
    receipts = {name: sha256((control / 'hepta' / receipt).read_bytes()).hexdigest()
                for name, receipt in (('native-image', '_native_image_build.json'),
                                      ('cell-frame', '_cell_frame_build.json'))}
    capsule_path = output / 'current-carriers.json'
    made = create(control / 'hepta', typed_path, sha256(typed_path.read_bytes()).hexdigest(),
                  release, args.expected_publication_sha256, receipts, capsule_path)
    assert made['product_qualification_claimed'] is False and made['scope'] == 'DATA_CAPTURE_ONLY'
    capsule_raw = capsule_path.read_bytes()
    capsule = json.loads(capsule_raw)
    capsule_sha = sha256(capsule_raw).hexdigest()
    controls = []

    class CurrentControls(unittest.TestCase):
        def refusal(self, label, operation, errors=(ValueError, OSError)):
            try:
                operation()
            except errors as exc:
                controls.append({'id': label, 'refused': True, 'type': type(exc).__name__})
            else:
                self.fail('invalid current authority accepted: ' + label)

        def enter(self, path, digest):
            with authority.native_helpers_scope(str(path), digest):
                self.fail('invalid current capsule reached its active scope')

        def selected(self):
            return authority.native_helpers_scope(str(capsule_path), capsule_sha)

        def test_00_original_domain_and_all_initial_inputs_precede_extension_load(self):
            with authority.native_helpers_scope(str(typed_path), sha256(typed_path.read_bytes()).hexdigest()) as binding:
                selected = artifact.installed_service_artifact(str(artifact_manifest))
                self.assertIsNone(selected._native_image_carrier)
                self.assertIsNone(image_loader.selected_extension())
                binding.check()
            self.assertNotIn('hepta._hia_native_image', sys.modules)
            self.assertNotIn('hepta._hia_cell_frame', sys.modules)
            self.refusal('old-v6-does-not-upgrade-current-child', lambda: old_create(
                control / 'hepta', typed_path, sha256(typed_path.read_bytes()).hexdigest(),
                receipts, output / 'invalid-old-v6.json'))
            self.refusal('new-current-does-not-retag-closed-v1', lambda: create(
                control / 'hepta', base_path, sha256(base_path.read_bytes()).hexdigest(),
                release, args.expected_publication_sha256, receipts, output / 'invalid-new-v1.json'))
            for label, path in (('publication', release / publication.MANIFEST),
                                ('image-policy', release / 'carrier-image-policy.flat'),
                                ('cell-policy', release / 'carrier-cell-policy.flat'),
                                ('child-page', page_bundle)):
                raw = path.read_bytes()
                try:
                    path.write_bytes(raw + b' ')
                    self.refusal('initial-' + label, lambda: self.enter(capsule_path, capsule_sha))
                finally:
                    path.write_bytes(raw)
                self.assertNotIn('hepta._hia_native_image', sys.modules)
                self.assertNotIn('hepta._hia_cell_frame', sys.modules)

        def test_01_late_child_and_publication_mutation_precede_extension_load(self):
            original = current._ordinary_binding
            for label, path in (('actual-child', artifact_manifest),
                                ('publication', release / publication.MANIFEST),
                                ('executing-current-source', control / 'hepta/hia_current_carrier_worker_bundle.py')):
                raw = path.read_bytes()
                def late(*args, path=path, raw=raw, **kwargs):
                    result = original(*args, **kwargs)
                    path.write_bytes(raw + b' ')
                    return result
                try:
                    with patch.object(current, '_ordinary_binding', late):
                        self.refusal('late-before-linker-' + label, lambda: self.enter(capsule_path, capsule_sha))
                finally:
                    path.write_bytes(raw)
                self.assertNotIn('hepta._hia_native_image', sys.modules)
                self.assertNotIn('hepta._hia_cell_frame', sys.modules)

        def test_02_actual_typed_child_and_two_native_policies_are_bound(self):
            first = None
            for repeat in range(2):
                with self.selected() as binding:
                    self.assertIs(type(binding), current.NativeCurrentCarrierWorkerBinding)
                    self.assertEqual(type(binding.ordinary_binding()).__name__, 'NativeArtifactPageWorkerBinding')
                    image_module = image_loader.selected_extension()
                    cell_module = cell_loader.selected_extension()
                    mapped = artifact.installed_service_artifact(str(artifact_manifest))
                    self.assertIs(mapped._native_image_carrier, image_module)
                    self.assertIs(type(mapped._mapping), image_module.Image)
                    request = image_module.Buffer(struct.pack('<10Q', artifact.REQUEST_MAGIC,
                        0, 0, 0, 0, 1, 11, 17, 0, 0), 80)
                    answer, state = image_module.Buffer(96), image_module.Buffer(128)
                    result = mapped._entry(request, 80, answer, 96, state, 128)
                    self.assertIs(type(result), int)
                    cells = cell_module.CellBindings(('value',), (types.CellType(7),),
                                                     verification._read_empty_free_cell)
                    self.assertEqual(cells['value'], 7)
                    self.assertIn('HEPTA_HIA_ARTIFACT_PAGE_MANIFEST', binding.selections)
                    self.assertEqual(authority.native_helpers_identity(), {'native_helpers_sha256': capsule_sha})
                    binding.check()
                    if first is not None:
                        self.assertIs(image_module, first[0])
                        self.assertIs(cell_module, first[1])
                    first = (image_module, cell_module)
                    controls.append({'id': 'actual-current-scope-' + str(repeat), 'passed': True})
            self.assertIsNone(image_loader.selected_extension())
            self.assertIsNone(cell_loader.selected_extension())

        def test_03_exact_current_shape_and_nested_pins(self):
            variants = []
            def change(name, operation):
                value = copy.deepcopy(capsule)
                operation(value)
                variants.append((name, value))
            change('old-schema', lambda v: v.update(schema='hepta.hia.native-helpers.v6'))
            change('unknown-schema', lambda v: v.update(schema='hepta.hia.current-carrier-worker-bundle.v2'))
            change('wrong-abi', lambda v: v.update(abi='hia-worker-native-carriers-v1'))
            change('extra', lambda v: v.update(extra=0))
            change('base-pin', lambda v: v.update(base_bundle_sha256='0' * 64))
            change('publication-pin', lambda v: v.update(policy_release_sha256='0' * 64))
            change('publication-bool', lambda v: v.update(policy_release_sha256=True))
            change('no-bridges', lambda v: v.update(bridges=[]))
            change('missing-carrier', lambda v: v['bridges'].pop())
            change('reverse-carriers', lambda v: v['bridges'].reverse())
            change('duplicate-carrier', lambda v: v['bridges'].append(copy.deepcopy(v['bridges'][0])))
            for i in range(2):
                change('receipt-' + str(i), lambda v, i=i: v['bridges'][i]['build_receipt'].update(sha256='0' * 64))
                change('binary-' + str(i), lambda v, i=i: v['bridges'][i]['binary'].update(bytes=True))
                change('profile-' + str(i), lambda v, i=i: v['bridges'][i]['profile'].update(gil_disabled=0))
                for name in capsule['bridges'][i]['sources']:
                    change('source-' + str(i) + ':' + name,
                           lambda v, i=i, name=name: v['bridges'][i]['sources'][name].update(sha256='0' * 64))
            for index, (label, value) in enumerate(variants):
                path = output / ('bad-current-' + str(index) + '.json')
                raw = canonical(value)
                path.write_bytes(raw)
                self.refusal(label, lambda: self.enter(path, sha256(raw).hexdigest()))

        def test_04_native_publication_extent_and_role_are_closed(self):
            raw = (release / publication.MANIFEST).read_bytes()
            for length in (0, 1, 303, 305):
                value = (raw + b'X')[:length]
                self.refusal('native-publication-length-' + str(length), lambda: publication.parse(value))
            for offset, value in ((0, 0), (8, 2), (16, 1), (24, 1), (32, 0), (72, 0),
                                  (112, 2), (120, 1), (128, 0), (136, 0),
                                  (208, 1), (216, 1), (224, 0), (232, 0)):
                modified = bytearray(raw)
                struct.pack_into('<Q', modified, offset, value)
                self.refusal('native-publication-word-' + str(offset), lambda: publication.parse(bytes(modified)))

        def test_05_terminal_actual_files_and_cached_exports_are_rechecked(self):
            paths = [release / publication.MANIFEST, release / 'carrier-image-policy.flat',
                     release / 'carrier-cell-policy.flat', artifact_manifest, page_bundle,
                     control / 'hepta/hia_carrier_policy_release.py',
                     control / 'hepta/hia_current_carrier_worker_bundle.py']
            for path in paths:
                with self.selected() as binding:
                    raw = path.read_bytes()
                    try:
                        path.write_bytes(raw + b' ')
                        self.refusal('terminal:' + str(path), binding.check)
                        self.refusal('cached-image:' + str(path), image_loader.selected_extension)
                        self.refusal('cached-cell:' + str(path), cell_loader.selected_extension)
                    finally:
                        path.write_bytes(raw)
            with self.selected() as binding:
                selected = image_loader.selected_extension()
                old = selected.Image
                try:
                    selected.Image = object
                    self.refusal('image-export-substitution', image_loader.selected_extension)
                finally:
                    selected.Image = old
                binding.check()

        def test_06_stale_or_lost_current_scope_never_selects_an_old_route(self):
            with self.selected() as prior:
                prior.check()
            with self.selected() as binding:
                names = ('_ACTIVE', '_MECHANICAL_SCOPE', '_MECHANICAL_BUILD', '_MECHANICAL_SELECTED')
                saved = {name: getattr(authority, name) for name in names}
                for label, values in (
                        ('lost-active', {'_ACTIVE': None}),
                        ('stale-active', {'_ACTIVE': prior}),
                        ('lost-scope', {'_MECHANICAL_SCOPE': None}),
                        ('overlap', {'_MECHANICAL_BUILD': binding}),
                        ('untyped-selection', {'_MECHANICAL_SELECTED': 1}),
                        ('lost-selection', {'_MECHANICAL_SELECTED': False})):
                    try:
                        for name, value in values.items():
                            setattr(authority, name, value)
                        self.refusal('current-image-' + label, image_loader.selected_extension)
                        self.refusal('current-cell-' + label, cell_loader.selected_extension)
                    finally:
                        for name, value in saved.items():
                            setattr(authority, name, value)
                binding.check()

    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(CurrentControls))
    stable = inventory(source) == before and capsule_path.read_bytes() == capsule_raw
    report = {'schema': 'hepta.hia.current-carrier-controls.v1',
              'passed': result.wasSuccessful() and stable, 'tests': result.testsRun,
              'controls': controls, 'control_count': len(controls),
              'source_unchanged': stable, 'source': before,
              'scope': 'ACTUAL_CURRENT_TYPED_PAGE_COMPONENT',
              'full_default_worker_or_installed_qualification_claimed': False}
    (output / 'report.json').write_bytes(canonical(report))
    print(json.dumps({k: report[k] for k in ('passed', 'tests', 'control_count', 'source_unchanged', 'scope')}))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
