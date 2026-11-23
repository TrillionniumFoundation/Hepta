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

    def test_publication_descriptor_pins_public_and_private_entrypoints_for_migration(self):
        from hepta.hia_artifact_delivery_protocol import DESCRIPTOR_OFFSET, ENTRY_WORD_OFFSET, NOTE_OFFSET
        from tools import build_hia_native_store_release as release
        from tools.build_hia_artifact_publication import SOURCES
        from tools.build_hia_sqlite_migration_publish import read_dependency

        original = (self.release / 'hia-artifact').read_bytes()
        admitted = {path: sha256((ROOT / path).read_bytes()).hexdigest() for path in SOURCES}
        for offset in (ENTRY_WORD_OFFSET, NOTE_OFFSET, DESCRIPTOR_OFFSET + 16, DESCRIPTOR_OFFSET + 40):
            changed = bytearray(original)
            changed[offset] ^= 1
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                release._bind_artifact_publisher(self.work, bytes(changed), admitted, b'compiler', b'cold')
        folder = release._bind_artifact_publisher(self.work, original, admitted, b'compiler', b'cold')
        body, *_ = read_dependency(folder, 'hia-artifact', 'hepta.hia.artifact-publication-build.v1',
                                   sha256(b'compiler').hexdigest(), sha256(b'cold').hexdigest(), admitted)
        self.assertEqual(body, original)

    def test_transaction_programs_match_original_placement_and_migration_receipts(self):
        from tools import build_hia_native_store_release as release
        from tools.build_hia_agent_batch_commit import VARIANTS
        from tools.build_hia_source_build import _compiled_sources
        from tools.build_hia_sqlite_migrate import read_component
        from tools.build_hia_sqlite_migration_publish import read_dependency

        programs = {v[0]: (k, v) for k, v in VARIANTS.items()}
        compiler = self.invoke([self.seed, 'compile'], (self.sources / 'selfhost.hepta').read_bytes())
        report = b'captured cold report for the receipt-consumer test'
        for name, packer, inputs in release._source_transaction_recipes():
            kind, variant = programs[name]
            with self.subTest(name=name):
                builder = self.member_builder(self.work / kind, packer)
                source = {alias: self.sources / path for alias, path in inputs.items()}
                group = self.source_images(self.work / name, source)
                compiled = _compiled_sources(group, {alias: path.read_bytes() for alias, path in source.items()})
                original = (self.release / name).read_bytes()
                program = self.invoke([builder, 'build'], group)
                self.assertEqual(program, original)
                self.invoke([builder, 'build'], group[:-1], refused=True)
                admitted = {p: sha256((ROOT / p).read_bytes()).hexdigest() for p in
                            (variant[2], variant[3], *('examples/hia_bootstrap/' + v for v in inputs.values()))}
                damaged = program[:-1] + bytes([program[-1] ^ 1])
                with self.assertRaises(ValueError):
                    release._bind_transaction_program(self.work, kind, variant, inputs, compiled, damaged,
                                                      admitted, compiler, report)
                folder = release._bind_transaction_program(self.work, kind, variant, inputs, compiled, program,
                                                           admitted, compiler, report)
                if folder is None:
                    self.assertEqual(kind, 'sealed')
                    continue
                cf, cr = sha256(compiler).hexdigest(), sha256(report).hexdigest()
                if kind == 'batch':
                    actual, *_ = read_dependency(folder, name, 'hepta.hia.agent-batch-commit-build.v1', cf, cr, admitted)
                else:
                    actual, _ = read_component(folder, 'initializer', name, 'hepta.hia.agent-store-init-build.v1',
                                               cf, cr, admitted)
                self.assertEqual(actual, original)
                if kind == 'batch':
                    parts = dict(reversed(tuple(source.items())))
                    self.assertEqual(self.invoke([builder, 'build'], self.source_images(self.work / 'reordered', parts)),
                                     original)
                    for absent in source:
                        partial = {key: path for key, path in source.items() if key != absent}
                        packet = self.source_images(self.work / 'incomplete', partial)
                        self.invoke([builder, 'build'], packet, refused=True)

    def test_artifact_capture_from_admitted_native_adapters_and_source(self):
        import struct
        from tools.build_hia_sqlite_components import CAPTURE_ADAPTERS

        source = self.sources / 'agent_artifact_capture.hepta'
        def owner(packer):
            kit = self.source_images(self.work / 'capture-kit', {
                'source_build_policy.hepta': SOURCES / 'source_sqlite_unit.hepta',
                'selfhost.hepta': self.sources / 'selfhost.hepta',
                'source_build_packer.hepta': self.sources / packer,
            })
            program = self.work / packer
            program.write_bytes(self.invoke([self.seed, 'pack'], kit))
            program.chmod(0o500)
            return program

        def request(tag, ordinal, data):
            return struct.pack('<8sQQ', tag, ordinal, len(data)) + data

        adapter = owner('sqlite_component_adapters.hepta')
        embedder = owner('elf_embed_image.hepta')
        objects = []
        for ordinal, filename in enumerate(CAPTURE_ADAPTERS, 2):
            data = (ROOT / filename).read_bytes()
            objects.append(self.invoke([adapter, 'build'], request(b'HIASQAD1', ordinal, data)))
            self.invoke([adapter, 'build'], request(b'HIASQAD1', ordinal, data + b'x'), refused=True)
        data = source.read_bytes()
        component = self.invoke([embedder, 'build'], request(b'HIASQCP1', 32, data))
        for tag, ordinal in ((b'HIASQCP1', 1), (b'HIASQUN1', 32)):
            self.invoke([embedder, 'build'], request(tag, ordinal, data), refused=True)
        objects.append(component)
        wire = struct.pack('<8s3Q', b'HIASQLK1', *map(len, objects)) + b''.join(objects)
        linked_input = self.invoke([embedder, 'build'], wire)
        self.assertEqual(self.invoke([self.release / 'hia-elf-link'], linked_input),
                         (self.release / 'hia-agent-artifact-capture').read_bytes())

    def test_agent_stdio_rebuilds_the_catalogs_and_three_source_images(self):
        from tools import build_hia_native_store_release as release
        from tools.build_hia_source_build import _compiled_sources, _run_captured

        seed = self.seed.read_bytes()
        catalog_program = (self.release / 'hia-catalog').read_bytes()
        compiler = self.invoke([self.seed, 'compile'], (self.release / 'selfhost.hepta').read_bytes())
        published = []

        def compile_sources(named):
            files = {alias: self.sources / path for alias, path in named.items()}
            sources = {alias: path.read_bytes() for alias, path in files.items()}
            packet = self.source_images(self.work / 'agent-stdio', files)
            return packet, _compiled_sources(packet, sources), sources

        def call(program, operation, wire):
            proc = _run_captured(program, operation, wire, self.work)
            self.assertEqual((proc.returncode, proc.stderr), (0, b''))
            if program != catalog_program and operation == 'build':
                for changed in (wire[:-1], wire + b'x'):
                    refused = _run_captured(program, operation, changed, self.work)
                    self.assertNotEqual(refused.returncode, 0)
                    self.assertEqual((refused.stdout, refused.stderr), (b'', b''))
            return proc.stdout

        def publish(path, *, expected):
            data = path.read_bytes()
            self.assertEqual(sha256(data).hexdigest(), expected)
            self.assertEqual(data, (self.release / 'hia-native').read_bytes())
            published.append(path.name)

        release._stage_agent_stdio(self.work, seed, catalog_program, compile_sources, call, compiler, publish)
        self.assertEqual(published, ['hia-native'])

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

    def test_normal_sqlite_units_match_the_independent_installed_programs(self):
        from tools import build_hia_native_store_release as release
        from tools.build_hia_nominal_json import STDIO
        from tools.build_hia_source_build import _compiled_sources, _run_captured
        from tools.build_hia_sqlite_components import (
            CAPTURE_ADAPTERS, COMPONENT_TEMPLATES, INPUT, PROJECTION, PROJECTION_ADAPTER, PROJECTION_ROLES, START, UNITS,
        )
        from tools.build_hia_sqlite_pager import ADAPTERS, EMBED_SOURCE, PAGER, STATIC_LINKER, STREAM, TEMPLATES

        seed = self.seed.read_bytes()
        linker = (self.release / 'hia-elf-link').read_bytes()
        dependencies = (START, INPUT, *CAPTURE_ADAPTERS, PROJECTION_ADAPTER, COMPONENT_TEMPLATES, EMBED_SOURCE,
                        STDIO, STATIC_LINKER, PAGER, STREAM, TEMPLATES, *ADAPTERS,
                        'examples/hia_bootstrap/source_sqlite_unit.hepta', *('examples/hia_bootstrap/' + unit.replace('-', '_') + '.hepta'
                                         for unit in (PROJECTION, *PROJECTION_ROLES)))
        admitted = {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in dependencies}

        def compile_sources(names):
            paths = {name: self.sources / source for name, source in names.items()}
            sources = {name: path.read_bytes() for name, path in paths.items()}
            group = self.source_images(self.work / 'sqlite-sources', paths)
            return group, _compiled_sources(group, sources), sources

        def call(program, operation, wire):
            result = _run_captured(program, operation, wire, self.work)
            self.assertEqual((result.returncode, result.stderr), (0, b''))
            return result.stdout

        published = set()

        def publish(path, *, expected):
            self.assertNotIn(path.name, published)
            output = path.read_bytes()
            self.assertEqual(sha256(output).hexdigest(), expected)
            self.assertEqual(output, (self.release / path.name).read_bytes())
            published.add(path.name)

        release._stage_sqlite_units(self.work, seed, linker, compile_sources, call, admitted, publish)
        self.assertEqual(published, {'hia-' + unit for unit in (*UNITS, 'agent-artifact-capture', 'nominal-packet', 'sqlite-pager', PROJECTION)})

    def test_read_carrier_rebuilds_all_four_native_flows(self):
        from tools import build_hia_native_store_release as release
        from tools.build_hia_source_build import _compiled_sources, _run_captured
        from tools.generate_hia_worker_flow_packer import FLOW, PEERS, PORTS, PROGRAMS
        from tools.generate_hia_worker_read_release import ADAPTER, ENTRIES, SOURCE

        names = (FLOW, PEERS, PORTS, ADAPTER, SOURCE, *(PROGRAMS[role][1] for role in ENTRIES))
        admitted = {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in names}

        def compile_sources(named):
            paths = {name: self.sources / path for name, path in named.items()}
            captured = {name: path.read_bytes() for name, path in paths.items()}
            group = self.source_images(self.work / 'four-flows', paths)
            return group, _compiled_sources(group, captured), captured

        def call(program, mode, wire):
            result = _run_captured(program, mode, wire, self.work)
            self.assertEqual((result.returncode, result.stderr), (0, b''))
            return result.stdout

        published = []
        def publish(path, *, expected):
            self.assertEqual(path.name, 'hia-agent-read-carrier')
            self.assertEqual(path.read_bytes(), (self.release / path.name).read_bytes())
            self.assertEqual(sha256(path.read_bytes()).hexdigest(), expected)
            published.append(path.name)

        release._stage_read_carrier(self.work, self.seed.read_bytes(), compile_sources, call, admitted, publish)
        self.assertEqual(published, ['hia-agent-read-carrier'])

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
        from tools.build_hia_native_store_release import _source_directory_recipe, _source_release_recipes

        for name, packer, sources in (_source_directory_recipe(), *_source_release_recipes()):
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

    def test_compiler_manifest_rebuilds_three_images_and_the_selected_elf(self):
        import json
        import struct
        from tools.build_hia_source_build import _compiled_sources

        core_sources = ('core_json_cli_packer.hepta', 'core_json_frontend.hepta', 'selfhost.hepta')
        sources = {name: self.release / name for name in core_sources}
        compiled = self.source_images(self.work / 'core-sources', sources)
        captured = {name: path.read_bytes() for name, path in sources.items()}
        images = _compiled_sources(compiled, captured)
        kit = self.source_images(self.work / 'manifest-author', {
            'source_build_policy.hepta': SOURCES / 'source_compiler_manifest.hepta',
            'selfhost.hepta': sources['selfhost.hepta'],
            'source_build_packer.hepta': sources['core_json_cli_packer.hepta'],
        })
        author = self.work / 'author'
        author.write_bytes(self.invoke([self.seed, 'pack'], kit))
        author.chmod(0o500)
        # Use the installation's actual manifest as independent oracle for every
        # field except the fixture cold report, whose bytes belong to this test.
        cold = b'captured test report'
        expected = json.loads((self.release / 'compiler-manifest.json').read_bytes())
        expected['cold_report_sha256'] = sha256(cold).hexdigest()
        parts = [cold, images['selfhost.hepta'], (self.release / 'hia-core-json').read_bytes(),
                 images['core_json_frontend.hepta'], images['core_json_cli_packer.hepta'],
                 (self.release / 'HIA_SELFHOST_CORE_SUPPORT.json').read_bytes(),
                 *(captured[name] for name in core_sources)]

        def frame(fields):
            return struct.pack('<8s9Q', b'HIACMF01', *map(len, fields)) + b''.join(fields)

        packet = frame(parts)
        actual = self.invoke([author, 'build'], packet)
        self.assertEqual(actual, (json.dumps(expected, indent=2, sort_keys=True) + '\n').encode())
        for malformed in (packet[:-1], packet + b'x', b'bad-head' + packet[8:]):
            self.invoke([author, 'build'], malformed, refused=True)
        for slot in (1, 2, 3, 4, 6, 7, 8):
            with self.subTest(slot=slot):
                changed = parts.copy()
                changed[slot] = bytes([changed[slot][0] ^ 1]) + changed[slot][1:]
                self.invoke([author, 'build'], frame(changed), refused=True)

    def test_request_programs_from_their_native_source_and_packer(self):
        from tools.build_hia_native_store_release import _source_request_recipes
        builders = {}
        for name, packer, inputs in _source_request_recipes():
            with self.subTest(name=name):
                if packer not in builders:
                    builders[packer] = self.member_builder(self.work / packer, packer)
                builder = builders[packer]
                if inputs:
                    source = {alias: self.sources / path for alias, path in inputs.items()}
                    packet = self.source_images(self.work / name, source)
                    alias, = inputs
                    wrong = self.source_images(self.work / 'wrong-request-module',
                                               {alias: self.sources / 'cnf.hepta'})
                    self.invoke([builder, 'build'], wrong, refused=True)
                    self.invoke([builder, 'build'], packet[:-1] + bytes([packet[-1] ^ 1]), refused=True)
                else:
                    packet = b'HIAWPRT1'
                    self.invoke([builder, 'build'], b'HIAWPRT0', refused=True)
                self.assertEqual(self.invoke([builder, 'build'], packet),
                                 (self.release / name).read_bytes())
                self.invoke([builder, 'build'], packet + b'x', refused=True)
