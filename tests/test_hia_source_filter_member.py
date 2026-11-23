"""Rebuild the ordinary two/three-image Store filters from a qualified native source seed."""
from hashlib import sha256
import os
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
import unittest

from hepta.hia_agent_assembly import assemble_program

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ROOT / 'examples/hia_bootstrap'
POLICY = SOURCES / 'source_filter_member.hepta'
# The public release names differ from source stems for these three members.
SPECIAL = {
    'hia-evaluate-projector': ('evaluate_reference_wire', 'evaluate_reference_wire_filter_packer'),
    'hia-execution-budget-session': ('execution_budget', 'execution_budget_session_packer'),
    'hia-safe-core-loader': ('safe_core_elf_inventory', 'safe_core_loader_filter_packer'),
}
CANONICAL = {'hia-evaluate-cost-ledger', 'hia-evaluate-run-plan'}
MEMBERS = tuple('hia-evaluate-' + name for name in (
    'budget-observation', 'budget-store', 'cost-ledger', 'cost-ledger-flow', 'measurements',
    'native-report', 'paired-batch', 'publication', 'reference-batch', 'reference-report',
    'report-flow', 'run-plan', 'settlement')) + tuple(SPECIAL)


class SourceFilterMemberTests(unittest.TestCase):
    def test_native_policy_is_valid_assembly(self):
        self.assertGreater(len(assemble_program(POLICY.read_bytes()).as_dict()['functions']), 3)


@unittest.skipUnless(os.environ.get('HIA_TEST_NATIVE_FILTER_RELEASE'), 'requires a qualified, installed Store')
class InstalledSourceMemberTests(unittest.TestCase):
    def setUp(self):
        self.release = Path(os.environ['HIA_TEST_NATIVE_FILTER_RELEASE']).resolve()
        self.sources = Path(os.environ.get('HIA_TEST_NATIVE_FILTER_SOURCES', SOURCES)).resolve()
        self.seed = self.release / 'hia-source-build'
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)

    def invoke(self, argv, wire=b'', *, refused=False):
        result = subprocess.run(argv, input=wire, capture_output=True, cwd=self.work,
                                env={'PATH': ''}, timeout=120)
        self.assertEqual(result.stderr, b'')
        if refused:
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, b'')
        else:
            self.assertEqual(result.returncode, 0)
        return result.stdout

    def source_images(self, directory, named_sources):
        with TemporaryDirectory(dir=directory.parent, prefix=directory.name + '-') as tmp:
            directory = Path(tmp)
            for name, path in named_sources.items():
                member = directory / name
                member.write_bytes(path.read_bytes())
                member.chmod(0o400)
            packed = subprocess.run([self.release / 'hia-directory-package-build', directory],
                                    capture_output=True, cwd=self.work, env={'PATH': ''}, timeout=120)
        self.assertEqual(packed.returncode, 0)
        self.assertEqual(packed.stderr, (sha256(packed.stdout).hexdigest() + '\n').encode())
        self.assertEqual(packed.stdout[:8], b'HIAREL01')
        return self.invoke([self.seed, 'build'], packed.stdout)

    def member_builder(self, directory, packer):
        directory.mkdir(mode=0o700)
        kit = self.source_images(directory / 'kit', {
            'source_build_policy.hepta': POLICY, 'selfhost.hepta': self.sources / 'selfhost.hepta',
            'source_build_packer.hepta': self.sources / packer})
        builder = directory / 'member-builder'
        builder.write_bytes(self.invoke([self.seed, 'pack'], kit))
        builder.chmod(0o500)
        return builder

    def test_flat_helper_manifests_recompile_both_images_before_publishing(self):
        import json
        import struct
        from tools.build_hia_json_preflight import CANDIDATES
        from tools.build_hia_source_build import _compiled_sources
        from tools.build_hia_worker_release import INSTALLED_HELPERS

        selfhost = self.sources / 'selfhost.hepta'
        kit = self.source_images(self.work / 'manifest-kit', {
            'source_build_policy.hepta': SOURCES / 'source_helper_manifest.hepta',
            'selfhost.hepta': selfhost,
            'source_build_packer.hepta': self.sources / 'source_build_packer.hepta',
        })
        author = self.work / 'manifest-author'
        author.write_bytes(self.invoke([self.seed, 'pack'], kit))
        author.chmod(0o500)
        compiler = self.invoke([self.seed, 'compile'], selfhost.read_bytes())
        paths = {CANDIDATES[k][0] + '.hepta': self.sources / (CANDIDATES[k][0] + '.hepta')
                 for k in INSTALLED_HELPERS}
        sources = {name: path.read_bytes() for name, path in paths.items()}
        images = _compiled_sources(self.source_images(self.work / 'helpers', paths), sources)

        def frame(role, source, image, compiler_source, compiler_image):
            parts = (source, image, compiler_source, compiler_image)
            return struct.pack('<8s5Q', b'HIAHLM01', role, *map(len, parts)) + b''.join(parts)

        compiler_source = selfhost.read_bytes()
        for role, kind in enumerate(INSTALLED_HELPERS, 1):
            name = CANDIDATES[kind][0] + '.hepta'
            source, image = sources[name], images[name]
            with self.subTest(kind=kind):
                raw = self.invoke([author, 'build'], frame(role, source, image, compiler_source, compiler))
                self.assertEqual(raw, (self.release / (kind + '-manifest.json')).read_bytes())
                record = json.loads(raw)
                self.assertEqual(image, (self.release / record['image_path']).read_bytes())
                self.assertEqual(record['source_sha256'], sha256(source).hexdigest())
                self.assertEqual(record['compiler_sha256'], sha256(compiler).hexdigest())
            if role == 1:
                for invalid in (frame(2, source, image, compiler_source, compiler),
                                frame(role, source, image[:-1], compiler_source, compiler),
                                frame(role, source, image, compiler_source, compiler[:-1]),
                                frame(role, source, image, source, compiler)):
                    self.invoke([author, 'build'], invalid, refused=True)

    def test_from_native_sources_against_every_installed_filter(self):
        for name in MEMBERS:
            with self.subTest(member=name):
                path = self.work / name
                stem = name[4:].replace('-', '_')
                app, packer = SPECIAL.get(name, (stem, stem + '_packer'))
                builder = self.member_builder(path, packer + '.hepta')
                inputs = {app + '.hepta': self.sources / (app + '.hepta')}
                if name in CANONICAL:
                    inputs['worker_request.hepta'] = self.sources / 'worker_request.hepta'
                images = self.source_images(path / 'inputs', inputs)
                self.assertEqual(self.invoke([builder, 'build'], images), (self.release / name).read_bytes())
                for rejected in (images[:-1], images + b'x', b'badmagic' + images[8:],
                                 images[:-1] + bytes((images[-1] ^ 1,))):
                    self.invoke([builder, 'build'], rejected, refused=True)
                if name in CANONICAL:
                    alone = self.source_images(path / 'missing-canonical', {app + '.hepta': inputs[app + '.hepta']})
                    self.invoke([builder, 'build'], alone, refused=True)
                if name == 'hia-evaluate-settlement':
                    packet = self.source_images(path / 'wrong-role', {
                        'evaluate_measurements.hepta': self.sources / 'evaluate_measurements.hepta'})
                    self.invoke([builder, 'build'], packet, refused=True)
                    self.invoke([builder, 'compile'], images, refused=True)
                    disguised = self.source_images(path / 'wrong-module', {
                        'evaluate_settlement.hepta': self.sources / 'evaluate_measurements.hepta'})
                    self.invoke([builder, 'build'], disguised, refused=True)

    def test_from_native_sources_against_every_installed_agent_stdio_role(self):
        from tools.build_hia_agent_read_page import JOURNAL_PACKER, JOURNAL_TRANSPORT, STDIO_PACKER, VARIANTS
        from tools.build_hia_native_store_release import STDIO_ROLES

        generic = self.member_builder(self.work / 'stdio', Path(STDIO_PACKER).name)
        journal = self.member_builder(self.work / 'journal', Path(JOURNAL_PACKER).name)
        codec = Path(JOURNAL_TRANSPORT).name
        for role in STDIO_ROLES:
            name = 'hia-agent-' + role
            with self.subTest(member=name):
                builder = journal if role == 'journal' else generic
                inputs = {name + '.hepta': self.sources / (VARIANTS[role][0] + '.hepta')}
                if role == 'journal':
                    inputs[codec] = self.sources / codec
                packet = self.source_images(self.work / name, inputs)
                self.assertEqual(self.invoke([builder, 'build'], packet), (self.release / name).read_bytes())
                self.invoke([builder, 'build'], packet[:-1] + bytes([packet[-1] ^ 1]), refused=True)
        wrong = self.source_images(self.work / 'wrong-module', {
            'hia-agent-worker-canonical.hepta': self.sources / 'worker_evaluate_case.hepta'})
        self.invoke([generic, 'build'], wrong, refused=True)
        wrong_codec = self.source_images(self.work / 'wrong-journal-transport', {
            'hia-agent-journal.hepta': self.sources / (VARIANTS['journal'][0] + '.hepta'),
            'worker_request.hepta': self.sources / 'worker_request.hepta'})
        self.invoke([journal, 'build'], wrong_codec, refused=True)

    def test_from_native_sources_against_every_worker_carrier_and_launcher(self):
        from tools.build_hia_native_store_release import _source_worker_recipes

        builders = {}
        products = set()
        for name, packer, sources in _source_worker_recipes():
            with self.subTest(member=name):
                products.add(name)
                if packer not in builders:
                    builders[packer] = self.member_builder(self.work / packer, packer)
                builder = builders[packer]
                inputs = {alias: self.sources / source for alias, source in sources.items()}
                images = self.source_images(self.work / name, inputs)
                self.assertEqual(self.invoke([builder, 'build'], images), (self.release / name).read_bytes())
                self.invoke([builder, 'build'], images[:-1] + bytes([images[-1] ^ 1]), refused=True)
                if len(inputs) > 1:
                    without = dict(inputs)
                    del without[next(reversed(without))]
                    missing = self.source_images(self.work / 'missing-companion', without)
                    self.invoke([builder, 'build'], missing, refused=True)
        self.assertTrue({'hia-agent-verify-worker-carrier', 'hia-agent-evaluate-full-launcher',
                         'hia-agent-context-control-launcher', 'hia-agent-evaluate-unkeyed-worker-carrier'} <= products)

    def test_source_to_installed_linkers_reference_executor_and_transport_tools(self):
        from tools.build_hia_native_store_release import _source_tool_recipes

        builders = {}
        for name, packer, sources in _source_tool_recipes():
            with self.subTest(name=name):
                if packer not in builders:
                    builders[packer] = self.member_builder(self.work / packer, packer)
                inputs = {alias: self.sources / source for alias, source in sources.items()}
                images = self.source_images(self.work / name, inputs)
                self.assertEqual(self.invoke([builders[packer], 'build'], images), (self.release / name).read_bytes())
                self.invoke([builders[packer], 'build'], images[:-1] + bytes([images[-1] ^ 1]), refused=True)
                other = self.sources / ('cnf.hepta' if 'cnf.hepta' not in sources.values() else 'worker_prepare.hepta')
                alias, = sources
                mismatch = self.source_images(self.work / 'alias-mismatch', {alias: other})
                self.invoke([builders[packer], 'build'], mismatch, refused=True)

    def test_build_core_and_release_tools_against_independent_installation(self):
        from tools.build_hia_native_store_release import _source_release_recipes

        for name, packer, sources in _source_release_recipes():
            with self.subTest(name=name):
                builder = self.member_builder(self.work / packer, packer)
                inputs = {alias: self.sources / source for alias, source in sources.items()}
                # Bundle order is independent of required image order in the ELF.
                image = self.source_images(self.work / name, dict(reversed(tuple(inputs.items()))))
                self.assertEqual(self.invoke([builder, 'build'], image), (self.release / name).read_bytes())
                for missing in inputs:
                    partial = {alias: source for alias, source in inputs.items() if alias != missing}
                    broken = self.source_images(self.work / 'incomplete-core', partial)
                    self.invoke([builder, 'build'], broken, refused=True)
                self.invoke([builder, 'build'], image[:-1] + bytes([image[-1] ^ 1]), refused=True)
