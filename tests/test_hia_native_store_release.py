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
        for kind in ('evaluate-claim', 'evaluate-proof', 'evaluate-document'):
            self.assertIn(kind, release.FLOW_ROLES)

    def test_workspace_compiler_requires_all_four_source_images(self):
        recipes = {name: (packer, inputs) for name, packer, inputs in release._source_release_recipes()}
        packer, inputs = recipes['hia-workspace-compile']
        self.assertEqual(packer, 'core_workspace_pipeline_packer.hepta')
        self.assertEqual(list(inputs.values()),
                         ['core_workspace_json.hepta', 'core_admission.hepta',
                          'core_json_frontend.hepta', 'selfhost.hepta'])

    def test_native_directory_packer_is_the_first_source_member(self):
        first = next(release._source_member_recipes())
        self.assertEqual(first, release._source_directory_recipe())
        name, packer, sources = first
        self.assertEqual((name, packer), ('hia-directory-package-build', 'release_directory_packer.hepta'))
        self.assertEqual(list(sources.values()), ['release_directory_policy.hepta', 'sha256_stream.hepta'])

    def test_source_member_admission_checks_the_staged_elf_and_captured_hia_sources(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            names = ('hia-source-build', 'hia-directory-package-build')
            tools = {}
            for name in names:
                data = name.encode()
                (work / name).write_bytes(data)
                tools[name] = sha256(data).hexdigest()
            published = []
            with patch.object(release, '_run_captured', side_effect=AssertionError('premature execution')):
                with self.assertRaisesRegex(ValueError, 'source differs from cold admission'):
                    release._stage_source_members(work, work, {}, tools, published.append,
                                                  compiler_bytes=b'', report_bytes=b'', core_inputs=(None, None))
                (work / names[0]).write_bytes(b'changed')
                with self.assertRaisesRegex(ValueError, 'tool differs from its staged identity'):
                    release._stage_source_members(work, work, {}, tools, published.append,
                                                  compiler_bytes=b'', report_bytes=b'', core_inputs=(None, None))
            self.assertEqual(published, [])

    def test_package_publication_retains_the_verified_inode_across_receipts_and_withdrawal(self):
        import json
        import os
        import subprocess
        from hepta.artifact_publication import publish_verified, verify_published, withdraw_own_link

        with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ, {}, clear=True):
            root = Path(temporary)
            expected = b'ordinary release package'
            digest = sha256(expected).hexdigest()
            for timing in ('unchanged', 'publish', 'verify'):
                with self.subTest(timing=timing):
                    stage = root / ('package-' + timing)
                    stage.write_bytes(expected)
                    stage.chmod(0o400)
                    original = stage.stat()
                    output = root / ('output-' + timing)

                    def native(_image, args, wire, _work, **_options):
                        operation, source, destination = args
                        if operation == 'withdraw':
                            receipt = {'withdrawn': withdraw_own_link(source, destination)}
                        else:
                            action = publish_verified if operation == 'publish' else verify_published
                            receipt = action(source, destination, wire)
                        if str(destination).startswith('/proc/self/fd/') and operation == timing:
                            stage.unlink()
                            stage.write_bytes(expected)
                            stage.chmod(0o400)
                        return subprocess.CompletedProcess(args, 0, json.dumps(receipt).encode(), b'')

                    with patch.object(release, '_run_captured', side_effect=native):
                        if timing == 'unchanged':
                            published = release._publish_verified_package(stage, output, expected, digest,
                                                                          b'image', original)
                            self.assertTrue(published.samefile(stage))
                        else:
                            with self.assertRaisesRegex(ValueError, 'inode changed'):
                                release._publish_verified_package(stage, output, expected, digest,
                                                                  b'image', original)
                            self.assertFalse(output.exists())
                            self.assertEqual(stage.read_bytes(), expected)

    def test_native_inventory_reads_the_real_installed_files_and_refuses_changed_bytes(self):
        import json
        import subprocess

        with tempfile.TemporaryDirectory() as temporary:
            installed = Path(temporary)
            (installed / 'zero').touch()
            (installed / 'data').write_bytes(b'native member')
            members = {path.name: sha256(path.read_bytes()).hexdigest() for path in installed.iterdir()}
            actions = []

            def native(_image, args, _wire, _work, *, stdin, pass_fds):
                operation, path, alias = args
                self.assertTrue(pass_fds)
                if operation == 'verify':
                    self.assertTrue(Path(path).samefile(alias))
                data = stdin.read()
                actions.append(operation)
                receipt = {'sha256': sha256(data).hexdigest(), 'bytes': len(data)}
                return subprocess.CompletedProcess(args, 0, json.dumps(receipt).encode(), b'')

            with patch.object(release, '_run_captured', side_effect=native):
                release._verify_installed_members(installed, members, b'image', installed)
                self.assertCountEqual(actions, ['store-hash', 'verify'])
                (installed / 'data').write_bytes(b'different')
                with self.assertRaisesRegex(ValueError, 'differs from its source'):
                    release._verify_installed_members(installed, members, b'image', installed)

    def test_source_archive_rejects_symlinks_and_nonregular_cold_inputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / 'source'
            external = root / 'external'
            source.mkdir()
            external.mkdir()
            (external / 'data').write_bytes(b'outside cold source root')
            (source / 'direct').symlink_to(external / 'data')
            (source / 'parent').symlink_to(external, target_is_directory=True)
            fifo = source / 'fifo'
            import os
            os.mkfifo(fifo)
            for name in ('direct', 'parent/data', 'fifo'):
                with self.subTest(name=name):
                    digest = sha256(b'outside cold source root').hexdigest()
                    with patch.object(release, 'ROOT', source), patch.object(
                            release, 'current_sources', return_value={name: digest}):
                        destination = root / ('archive-' + name.replace('/', '-'))
                        with self.assertRaisesRegex(ValueError, 'cold source.*(regular|symlink)'):
                            release.write_source_archive(destination)
                        self.assertFalse(destination.exists())

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
