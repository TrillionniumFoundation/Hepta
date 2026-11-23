"""Source and refusal controls for the native Store release builder."""
from hashlib import sha256
import tarfile
import tempfile
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
        for kind in ('evaluate-claim', 'evaluate-proof'):
            self.assertIn(kind, release.FLOW_ROLES)

    def test_source_archive_is_deterministic_and_includes_only_the_complete_cold_inputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            declarations = {}
            for name, raw in (('a', b'primary'), ('nested/b', b'secondary')):
                source = root / name
                source.parent.mkdir(exist_ok=True)
                source.write_bytes(raw)
                declarations[name] = sha256(raw).hexdigest()
            (root / 'stale-package').write_bytes(b'old')
            with patch.object(release, 'ROOT', root), patch.object(release, 'current_sources', return_value=declarations):
                first = release.write_source_archive(root / 'one.tar.gz')
                second = release.write_source_archive(root / 'two.tar.gz')
                self.assertEqual(first.read_bytes(), second.read_bytes())
                with tarfile.open(first) as archive:
                    self.assertEqual(archive.getnames(), ['hia-core-source/a', 'hia-core-source/nested/b'])
                    for name, digest in declarations.items():
                        self.assertEqual(sha256(archive.extractfile('hia-core-source/' + name).read()).hexdigest(), digest)
                with self.assertRaises(FileExistsError):
                    release.write_source_archive(first)
                (root / 'a').write_bytes(b'changed')
                with self.assertRaisesRegex(ValueError, 'changed during export'):
                    release.write_source_archive(root / 'incomplete')
                self.assertFalse((root / 'incomplete').exists())
