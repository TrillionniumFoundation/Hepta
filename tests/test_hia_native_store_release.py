"""Source and refusal controls for the native Store release builder."""
import tempfile
from hashlib import sha256
import unittest
from pathlib import Path
from unittest.mock import patch

from tools import build_hia_native_store_release as release


class StoreReleaseBuildTests(unittest.TestCase):
    def test_admission_precedes_any_output_or_component_call(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            image, report, output = root / 'image', root / 'report', root / 'release'
            image.write_bytes(b'different compiler')
            report.write_text('{}')
            for existing in (False, True):
                with self.subTest(existing=existing):
                    if existing:
                        output.mkdir()
                    with patch.object(release, '_stage_component_outputs', side_effect=AssertionError('early build')):
                        with self.assertRaises(ValueError):
                            release.build(output, image, report)
                    self.assertEqual(output.exists(), existing)
                    if existing:
                        self.assertEqual(list(output.iterdir()), [])

    def test_existing_contents_and_output_links_are_refused_without_reading_inputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / 'target'
            target.mkdir()
            sentinel = target / 'existing'
            sentinel.write_bytes(b'keep')
            link = root / 'link'
            link.symlink_to(target)
            for output in (target, link):
                with self.assertRaises(FileExistsError):
                    release.build(output, root / 'absent-compiler', root / 'absent-report')
            self.assertEqual(sentinel.read_bytes(), b'keep')

    def test_store_role_inventory_separates_standalone_programs_and_eval_carriers(self):
        self.assertEqual(set(release.AGENT_STDIO_ROLES) - set(release.STDIO_ROLES),
                         {'borrowed-wrapper', 'context-cost-diagnostic', 'worker-describe-reactor'})
        self.assertEqual(len(release.STDIO_ROLES), len(set(release.STDIO_ROLES)))
        self.assertIn('worker-evaluate-input-binding', release.STDIO_ROLES)
        for kind in ('evaluate-replay', 'evaluate-intake'):
            self.assertIn(kind, release.FLOW_ROLES)
            self.assertIn(kind, release.LAUNCHERS)


class InstalledMemberIntegrityTests(unittest.TestCase):
    def test_installation_refuses_mode_drift_and_nonregular_members(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            native = directory / 'hia-worker'
            data = directory / 'manifest.json'
            native.write_bytes(b'\x7fELF' + b'valid-native-member')
            data.write_bytes(b'{"source":"sealed"}')
            native.chmod(0o500)
            data.chmod(0o400)
            expected = {x.name: sha256(x.read_bytes()).hexdigest() for x in (native, data)}
            self.assertEqual(release._installed_member_hashes(directory), expected)
            for target, unsafe in ((native, 0o700), (data, 0o600),
                                   (data, 0o500), (native, 0o400)):
                original = target.stat().st_mode & 0o7777
                try:
                    target.chmod(unsafe)
                    with self.subTest(name=target.name, unsafe=oct(unsafe)):
                        with self.assertRaisesRegex(ValueError, 'unsafe mode'):
                            release._installed_member_hashes(directory)
                finally:
                    target.chmod(original)
            alien = directory / 'other'
            alien.symlink_to(data)
            with self.assertRaisesRegex(ValueError, 'non-regular'):
                release._installed_member_hashes(directory)
