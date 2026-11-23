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


WORKER_MEMBERS = (
    'hia-agent-describe-worker-carrier', 'hia-agent-input-carrier',
    'hia-agent-artifact-worker-carrier', 'hia-agent-discovery-carrier',
    'hia-agent-context-worker-carrier', 'hia-agent-inspection-worker-carrier',
    'hia-agent-candidate-worker-carrier', 'hia-agent-rollback-worker-carrier',
    'hia-agent-emit-worker-carrier', 'hia-agent-adopt-worker-carrier',
    'hia-agent-verify-worker-carrier', 'hia-agent-discovery-bootstrap-carrier',
    'hia-agent-evaluate-replay-worker-carrier', 'hia-agent-evaluate-intake-worker-carrier',
    'hia-agent-evaluate-claim-worker-carrier', 'hia-agent-evaluate-run-input-worker-carrier',
    'hia-agent-evaluate-run-worker-carrier', 'hia-agent-evaluate-proof-worker-carrier',
    'hia-agent-evaluate-document-worker-carrier',
    'hia-agent-evaluate-closeout-worker-carrier', 'hia-agent-evaluate-unkeyed-worker-carrier',
    'hia-agent-read-launcher', 'hia-agent-context-control-launcher',
    'hia-agent-native-launcher', 'hia-agent-readonly-launcher',
    'hia-agent-evaluate-replay-launcher', 'hia-agent-evaluate-intake-launcher',
    'hia-agent-evaluate-full-launcher',
)
TOOL_MEMBERS = (
    'hia-worker-prepare', 'hia-proof-cnf', 'hia-elf-link', 'hia-elf-link-shared',
    'hia-elf-link-direct-shared', 'hia-direct-call', 'hia-job-receipt', 'hia-reference-wire',
)
REQUEST_MEMBERS = (
    'hia-worker-admit', 'hia-worker-terminal', 'hia-worker-data', 'hia-worker-response',
    'hia-worker-journal-call', 'hia-worker-port',
)
RELEASE_MEMBERS = (
    'hia-directory-package-build', 'hia-artifact', 'hia-release', 'hia-core-json',
    'hia-workspace-compile', 'hia-select', 'hia-patch-result', 'hia-core',
    'hia-totality-core', 'hia-core-proof-wire',
)
TRANSACTION_MEMBERS = (
    'hia-agent-batch-commit', 'hia-agent-sealed-commit', 'hia-agent-store-init',
)


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

    def release_planner(self):
        kit = self.source_images(self.work / 'recipe-kit', {
            'source_build_policy.hepta': self.sources / 'source_release_member_plan.hepta',
            'selfhost.hepta': self.sources / 'selfhost.hepta',
            'source_build_packer.hepta': self.sources / 'source_build_packer.hepta',
        })
        planner = self.work / 'release-plan'
        planner.write_bytes(self.invoke([self.seed, 'pack'], kit))
        planner.chmod(0o500)
        return planner

    def release_recipes(self, names):
        from tools.build_hia_native_store_release import _decode_member_plan

        table = (self.sources / 'release_member_sources.tsv').read_bytes()
        wire = self.invoke([self.release_planner(), 'build'], table)
        rows = {name: (name, packer, inputs) for name, packer, inputs in _decode_member_plan(wire)}
        return [rows[name] for name in names]

    def test_native_release_plan_preserves_role_and_input_order(self):
        from tools.build_hia_native_store_release import _decode_member_plan

        planner = self.release_planner()
        table = (self.sources / 'release_member_sources.tsv').read_bytes()
        wire = self.invoke([planner, 'build'], table)
        # Frozen from the independently built 191-role release, including relocation input order.
        self.assertEqual(sha256(wire).hexdigest(), '5d0dadcfb23371b82e7ff0c3aaa8d55b63a175b690216fe895825e33cd0e181b')
        self.assertEqual(len(_decode_member_plan(wire)), 191)
        lines = table.splitlines(keepends=True)
        duplicate_alias = lines[1].rstrip(b'\n') + b'\t' + lines[1].split(b'\t')[2] + b'\n'
        for label, changed in (
                ('missing role', b''.join(lines[:-1])),
                ('duplicate role', table.replace(lines[3], lines[2], 1)),
                ('duplicate alias', table.replace(lines[1], duplicate_alias, 1)),
                ('traversal', table.replace(b'=release_directory_policy.hepta', b'=../outside.hepta', 1)),
                ('truncated row', table[:-1])):
            with self.subTest(label=label):
                self.invoke([planner, 'build'], changed, refused=True)

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
        for name, packer, inputs in self.release_recipes(TRANSACTION_MEMBERS):
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

    def test_packaged_scalar_and_attached_prover_match_the_installed_compiler(self):
        from tools import build_hia_core_static as core
        from tools.build_hia_json_preflight import current_sources
        from tools.build_hia_source_build import _compiled_sources, _run_captured

        def call(program, operation, wire):
            run = _run_captured(program, operation, wire, self.work)
            self.assertEqual((run.returncode, run.stderr), (0, b''))
            return run.stdout

        def compile_sources(named):
            files = {name: self.sources / relative for name, relative in named.items()}
            pinned = {name: path.read_bytes() for name, path in files.items()}
            bundle = self.source_images(self.work / 'wrapper-sources', files)
            return bundle, _compiled_sources(bundle, pinned), pinned

        tools = self.seed.read_bytes(), compile_sources, call
        scalar = (self.release / 'hia-worker-scalar-implementation').read_bytes()
        prover = (self.release / 'hia-safe-core-prove').read_bytes()
        compiled, detail = core.pack_implementation(tools, current_sources(), core.ReleaseCodec(tools),
                                                    scalar, prover=prover)
        self.assertEqual(compiled, (self.release / 'hia-build-object').read_bytes())
        self.assertEqual(detail['implementation_sha256'], sha256(scalar).hexdigest())
        self.assertEqual(detail['attached_prover_sha256'], sha256(prover).hexdigest())

    def test_native_dispatch_binds_the_actual_selfhost_executable(self):
        import struct
        from tools.build_hia_core_edit import SELFHOST_ENTRY
        from tools.build_hia_core_static import bound_source
        from tools.build_hia_source_build import _run_captured

        kit = self.source_images(self.work / 'pin-kit', {
            'selfhost.hepta': self.sources / 'selfhost.hepta',
            'source_build_policy.hepta': SOURCES / 'source_core_pin.hepta',
            'source_build_packer.hepta': self.sources / 'source_build_packer.hepta',
        })
        binder = self.invoke([self.seed, 'pack'], kit)
        role = 'hia-selfhost-component'
        template = (ROOT / SELFHOST_ENTRY).read_bytes()
        original = (self.release / role).read_bytes()

        def call(program, operation, wire):
            run = _run_captured(program, operation, wire, self.work)
            self.assertEqual((run.returncode, run.stderr), (0, b''))
            return run.stdout

        for executable in (original, original + b'x'):
            bound = bound_source((None, None, call), binder, 2, template, {role: executable})
            for word in (len(executable), *struct.unpack('<4Q', sha256(executable).digest())):
                self.assertIn(b'{"value":' + str(word).encode('ascii') + b'}', bound)
        for name, source, payload in ((role, template + b' ', original), ('wrong', template, original),
                                      (role, template, b'bad')):
            wire = (struct.pack('<8s4Q', b'HIACPIN1', 2, len(source), len(name), len(payload))
                    + source + name.encode('ascii') + payload)
            run = _run_captured(binder, 'build', wire, self.work)
            self.assertNotEqual(run.returncode, 0)
            self.assertEqual((run.stdout, run.stderr), (b'', b''))

    def test_fixed_core_source_rejects_unbound_adapter_and_recompiled_image(self):
        import struct
        from tools.build_hia_source_build import _compiled_sources

        def owner(leaf):
            kit = self.source_images(self.work / 'core-kit', {
                'source_build_policy.hepta': SOURCES / 'source_core_application.hepta',
                'selfhost.hepta': self.sources / 'selfhost.hepta',
                'source_build_packer.hepta': self.sources / 'core_edit' / leaf,
            })
            program = self.work / leaf
            program.write_bytes(self.invoke([self.seed, 'pack'], kit))
            program.chmod(0o500)
            return program

        template = owner('adapter_templates_a.hepta')
        application = owner('packer.hepta')
        row = self.invoke([template, 'build'], struct.pack('<8sQ', b'HIACST01', 1))
        name = 'cli_discovery_json.hepta'
        source = (self.sources / name).read_bytes()
        compiled = self.source_images(self.work / 'core-source', {name: self.sources / name})
        image = _compiled_sources(compiled, {name: source})[name]
        adapter = (ROOT / 'tools/hia_core_edit_catalog.S').read_bytes()

        def request(ordinal=1, asm=adapter, record=row, module=source, supplied=image):
            return (struct.pack('<8s5Q', b'HIACSA01', ordinal, len(asm), len(record), len(module), len(supplied))
                    + asm + record + module + supplied)

        binary = self.invoke([application, 'build'], request())
        self.assertEqual(binary, (self.release / 'hia-catalog').read_bytes())
        changed_record = row[:112] + bytes([row[112] ^ 1]) + row[113:]
        changed_image = bytes([image[0] ^ 1]) + image[1:]
        for wire in (request(ordinal=2), request(asm=adapter + b' '), request(record=changed_record),
                     request(module=source.replace(b'cli_discovery_json', b'cli_discoverx_json', 1)),
                     request(supplied=changed_image), request() + b'!'):
            self.invoke([application, 'build'], wire, refused=True)

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

    def test_agent_store_rebuilds_all_native_modules_and_its_transaction_root(self):
        import json
        from hepta.hia_json_preflight_native import NativeHiaJsonImage
        from tools import build_hia_native_store_release as release
        from tools.build_hia_agent_store import ADAPTER, PLAN, apply_filter
        from tools.build_hia_source_build import _compiled_sources, _run_captured

        def compile_sources(names):
            paths = {alias: self.sources / name for alias, name in names.items()}
            sources = {alias: path.read_bytes() for alias, path in paths.items()}
            packet = self.source_images(self.work / 'store-sources', paths)
            return packet, _compiled_sources(packet, sources), sources

        def invoke(program, operation, wire):
            result = _run_captured(program, operation, wire, self.work)
            if result.returncode or result.stderr:
                raise ValueError(f'Store source was rejected with status {result.returncode}')
            return result.stdout

        outputs = set()
        def publish(path, *, expected):
            raw = path.read_bytes()
            self.assertNotIn(path.name, outputs)
            self.assertEqual(raw, (self.release / path.name).read_bytes())
            self.assertEqual(sha256(raw).hexdigest(), expected)
            outputs.add(path.name)

        admitted = {path: sha256((ROOT / path).read_bytes()).hexdigest() for path in (PLAN, ADAPTER)}
        seed = self.seed.read_bytes()
        compiler = invoke(seed, 'compile', (self.sources / 'selfhost.hepta').read_bytes())
        release._stage_agent_store(self.work, seed, compile_sources, invoke, compiler, admitted, publish)
        self.assertEqual(outputs, {'hia-agent-store', *(f'module-{n}.bin' for n in range(4))})

        # The established bounded-step ABI still yields in the original 16 KiB workspace.
        unit = json.loads((ROOT / PLAN).read_bytes())['units']['rowid']
        programs = self.sources / 'agent_store'
        word_filter = invoke(seed, 'compile', (programs / 'word_filter.hepta').read_bytes())
        image = NativeHiaJsonImage(word_filter, sha256(word_filter).hexdigest())
        flat = invoke(seed, 'compile', (programs / unit['source']).read_bytes())
        data, calls = apply_filter(image, flat, unit)
        self.assertGreater(calls, 1)
        self.assertEqual(sha256(data).hexdigest(), unit['image_sha256'])

    def test_nominal_constructor_rebuilds_all_embedded_images_and_its_split_transport(self):
        from tools import build_hia_native_store_release as release
        from tools.build_hia_nominal_constructor import TRANSPORT_ROLES
        from tools.build_hia_source_build import _compiled_sources, _run_captured

        def compile_sources(names):
            paths = {alias: self.sources / name for alias, name in names.items()}
            sources = {alias: path.read_bytes() for alias, path in paths.items()}
            packet = self.source_images(self.work / 'constructor-sources', paths)
            return packet, _compiled_sources(packet, sources), sources

        def invoke(program, operation, wire):
            result = _run_captured(program, operation, wire, self.work)
            if result.returncode or result.stderr:
                raise ValueError(f'constructor source rejected with status {result.returncode}')
            return result.stdout

        expected = (self.release / 'hia-nominal-constructor').read_bytes()
        outputs = []
        def publish(path, *, expected):
            raw = path.read_bytes()
            self.assertEqual(sha256(raw).hexdigest(), expected)
            outputs.append((path.name, raw))

        inputs = {path: sha256((ROOT / path).read_bytes()).hexdigest() for path in TRANSPORT_ROLES}
        seed = self.seed.read_bytes()
        tools = release._sqlite_build_tools(seed, (self.release / 'hia-elf-link').read_bytes(),
                                           compile_sources, invoke, inputs)
        path = release._stage_nominal_constructor(self.work, compile_sources, publish, tools)
        self.assertEqual(outputs, [('hia-nominal-constructor', expected)])
        self.assertEqual(path.read_bytes(), expected)

    def test_core_nominal_tools_link_the_installed_implementations_and_real_prover(self):
        import struct
        import zlib
        from tools import build_hia_core_edit as core
        from tools.build_hia_core_edit_link import build_implementations
        from tools.build_hia_source_build import _compiled_sources, _run_captured

        def compile_sources(named):
            paths = {alias: self.sources / source for alias, source in named.items()}
            originals = {alias: path.read_bytes() for alias, path in paths.items()}
            packet = self.source_images(self.work / 'core-link-sources', paths)
            return packet, _compiled_sources(packet, originals), originals

        def invoke(program, operation, wire):
            result = _run_captured(program, operation, wire, self.work)
            self.assertEqual((result.returncode, result.stderr), (0, b''))
            return result.stdout

        admitted = {path: sha256((ROOT / path).read_bytes()).hexdigest()
                    for path in (*core.NOMINAL_ADAPTER_ROLES, core.REGISTER_RELAY)}
        prover = (self.release / 'hia-safe-core-prove').read_bytes()
        tools = (self.seed.read_bytes(), compile_sources, invoke)
        built = build_implementations(tools, admitted, prover=prover)
        self.assertEqual(set(built), set(core.NOMINAL_CLI_IMAGES))
        for kind, (actual, details) in built.items():
            with self.subTest(kind=kind):
                raw = (self.release / core.PROGRAMS[kind][0]).read_bytes()
                at = raw.index(core.EXEC_ARCHIVE_MAGIC) + 8
                extent, = struct.unpack_from('<Q', raw, at)
                self.assertEqual(extent, len(actual))
                pos = at + 8
                original = bytearray()
                while len(original) < extent:
                    encoded, size = struct.unpack_from('<QQ', raw, pos)
                    block = zlib.decompress(raw[pos + 16:pos + 16 + encoded], -15)
                    self.assertEqual(len(block), size)
                    original.extend(block)
                    pos += 16 + encoded
                self.assertEqual(actual, original)
                self.assertEqual(details['link_receipt']['status'], extent)
        self.assertEqual(built['build_object'][0], (self.release / 'hia-worker-scalar-implementation').read_bytes())

    def test_normal_sqlite_units_match_the_independent_installed_programs(self):
        from tools import build_hia_native_store_release as release
        from tools.build_hia_agent_batch_commit import VARIANTS
        from tools.build_hia_artifact_publication import SOURCES as ARTIFACT_SOURCES
        from tools.build_hia_sqlite_migration_publish import ADAPTER as PUBLISH_ADAPTER, MIGRATION_TEMPLATES, UNITS as PUBLISH_UNITS
        from tools.build_hia_sqlite_migrate import ADAPTER as MIGRATE_ADAPTER, COORDINATOR
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
                        *ARTIFACT_SOURCES, *PUBLISH_UNITS.values(), MIGRATION_TEMPLATES,
                        PUBLISH_ADAPTER, MIGRATE_ADAPTER, COORDINATOR,
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
            if result.returncode or result.stderr:
                raise ValueError(f'embedded SQLite source rejected with status {result.returncode}')
            return result.stdout

        published = set()

        def publish(path, *, expected):
            self.assertNotIn(path.name, published)
            output = path.read_bytes()
            self.assertEqual(sha256(output).hexdigest(), expected)
            self.assertEqual(output, (self.release / path.name).read_bytes())
            published.add(path.name)

        tools = release._sqlite_build_tools(seed, linker, compile_sources, call, admitted)
        linked = release._stage_sqlite_units(self.work, compile_sources, admitted, publish, tools)
        compiler = self.invoke([self.seed, 'compile'], (self.sources / 'selfhost.hepta').read_bytes())
        report = b'independent cold receipt for staged SQLite inputs'
        artifact = (self.release / 'hia-artifact').read_bytes()
        folders = {'artifact': release._bind_artifact_publisher(self.work, artifact, admitted, compiler, report)}
        variants = {row[0]: (kind, row) for kind, row in VARIANTS.items()}
        for name, _, inputs in self.release_recipes(TRANSACTION_MEMBERS):
            kind, variant = variants[name]
            if kind in ('batch', 'initialize'):
                paths = [variant[2], variant[3], *('examples/hia_bootstrap/' + value for value in inputs.values())]
                admitted.update({path: sha256((ROOT / path).read_bytes()).hexdigest() for path in paths})
                _, images, _ = compile_sources(inputs)
                raw = (self.release / name).read_bytes()
                folders[kind] = release._bind_transaction_program(self.work, kind, variant, inputs, images, raw,
                                                                  admitted, compiler, report)
        release._stage_sqlite_migrations(self.work, compile_sources, admitted, publish, tools, linked, folders,
                                         compiler, report)
        self.assertEqual(published, {'hia-' + unit for unit in (*UNITS, 'agent-artifact-capture', 'nominal-packet',
                                      'sqlite-pager', PROJECTION, 'sqlite-migration-publish', 'sqlite-migrate')})
        _, embed, _ = tools
        for digest in (sha256(artifact + b'x').digest(), bytes(32)):
            with self.assertRaises(ValueError):
                embed(b'HIAMGEL1', 17, artifact, digest)
        with self.assertRaises(ValueError):
            embed(b'HIAMGEL1', 18, artifact, sha256(artifact).digest())

    def test_supplied_proof_rebuilds_and_rebinds_all_five_nested_programs(self):
        import struct
        from tools import build_hia_native_store_release as release
        from tools.build_hia_source_build import _compiled_sources, _run_captured
        from tools.generate_hia_safe_core_binder_packer import ADAPTER
        from tools.generate_hia_supplied_safe_core_proof_packer import ADAPTER as OUTER_ADAPTER

        admitted = {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in (ADAPTER, OUTER_ADAPTER)}
        children = {}
        published = []

        def compile_sources(named):
            paths = {name: self.sources / path for name, path in named.items()}
            captures = {name: path.read_bytes() for name, path in paths.items()}
            group = self.source_images(self.work / 'proof-programs', paths)
            return group, _compiled_sources(group, captures), captures

        def call(program, mode, wire):
            result = _run_captured(program, mode, wire, self.work)
            self.assertEqual((result.returncode, result.stderr), (0, b''))
            if wire[:8] == b'HIASPR01':
                role, = struct.unpack_from('<Q', wire, 8)
                if role < 6:
                    children[role] = result.stdout
                if role == 6:
                    self.assertEqual(set(children), set(range(1, 6)))
                    for child in children.values():
                        start = wire.index(child)
                        self.assertEqual(wire.count(child), 1)
                        # Cover the syscall adapter and the last image inside each distinct child.
                        for offset in (start + 182, start + len(child) - 16):
                            damaged = wire[:offset] + bytes([wire[offset] ^ 1]) + wire[offset + 1:]
                            refused = _run_captured(program, mode, damaged, self.work)
                            self.assertNotEqual(refused.returncode, 0)
                            self.assertEqual((refused.stdout, refused.stderr), (b'', b''))
            return result.stdout

        def publish(path, *, expected):
            data = path.read_bytes()
            self.assertEqual(path.name, 'hia-safe-core-prove')
            self.assertEqual(data, (self.release / path.name).read_bytes())
            self.assertEqual(sha256(data).hexdigest(), expected)
            published.append(path.name)

        release._stage_safe_proof(self.work, self.seed.read_bytes(), compile_sources, call, admitted, publish)
        self.assertEqual(published, ['hia-safe-core-prove'])

    def test_owned_reference_relocates_the_private_entry_when_source_layout_changes(self):
        import struct
        from tools import build_hia_native_store_release as release
        from tools.build_hia_source_build import _compiled_sources, _run_captured
        from tools.generate_hia_owned_reference import ADAPTER_PATH, PACKER_PATH, SOURCE_PATH
        from tools.generate_hia_native_filter import elf_header, read_adapter_binding, verify_adapter

        adapter = (ROOT / ADAPTER_PATH).read_bytes()
        admitted = {ADAPTER_PATH: sha256(adapter).hexdigest()}
        binding = read_adapter_binding((ROOT / PACKER_PATH).read_bytes(), adapter, calls=2)
        source = self.sources / Path(SOURCE_PATH).name
        original = source.read_bytes()
        start = original.index(b'\nfn ') + 1
        end = original.index(b'\nfn ', start) + 1
        signature = original[start:end].splitlines()[:2]
        self.assertTrue(signature[0].startswith(b'fn f0') and signature[1].startswith(b'block b0'))
        # Preserve the public planner signature and every later function, including the executor.
        reduced = b'\n'.join([*signature, b'  v3:u32 = const() {"value":0}', b'  ret(v3)', b'end', b''])
        variant = self.work / source.name
        variant.write_bytes(original[:start] + reduced + original[end:])
        compiler = self.invoke([self.seed, 'compile'], (self.sources / 'selfhost.hepta').read_bytes())
        entries = []

        def call(program, mode, wire):
            result = _run_captured(program, mode, wire, self.work)
            self.assertEqual((result.returncode, result.stderr), (0, b''))
            return result.stdout

        for input_source in (source, variant):
            def compile_sources(named):
                paths = {name: input_source if path == source.name else self.sources / path
                         for name, path in named.items()}
                captures = {name: path.read_bytes() for name, path in paths.items()}
                group = self.source_images(self.work / 'owned-inputs', paths)
                return group, _compiled_sources(group, captures), captures

            def publish(path, *, expected):
                product = path.read_bytes()
                self.assertEqual(path.name, 'hia-owned-reference-wire')
                self.assertEqual(sha256(product).hexdigest(), expected)
                image = self.invoke([self.seed, 'compile'], input_source.read_bytes())
                _, adapter_size, (_, hole) = binding
                delta, = struct.unpack_from('<i', product, len(elf_header()) + hole)
                entry = hole + 4 + delta - adapter_size
                verify_adapter(product, image, binding, entries=(0, entry))
                self.assertEqual(image[entry:entry + 4], bytes.fromhex('554889e5'))
                if input_source == source:
                    self.assertEqual(product, (self.release / path.name).read_bytes())
                entries.append(entry)

            release._stage_owned_reference(self.work, self.seed.read_bytes(), compile_sources, call,
                                           compiler, admitted, publish)
        self.assertEqual(len(set(entries)), 2)

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

        builders = {}
        products = set()
        for name, packer, sources in self.release_recipes(WORKER_MEMBERS):
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

        builders = {}
        for name, packer, sources in self.release_recipes(TOOL_MEMBERS):
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

        for name, packer, sources in self.release_recipes(RELEASE_MEMBERS):
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
        builders = {}
        for name, packer, inputs in self.release_recipes(REQUEST_MEMBERS):
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
