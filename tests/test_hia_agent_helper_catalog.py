"""Independent version-03 Agent helper source and actual native regressions."""
from copy import deepcopy
from hashlib import sha256
import importlib
import json
import os
from pathlib import Path
import struct
import subprocess
import unittest

from hepta.hia_agent_assembly import assemble_program
from tools.generate_hia_source_agent_helper_manifest import (
    AGENT_HELPERS, MAGIC, CHECK_MODE, STAGE_OPERATION, COMPILER_ROLE,
    OUTPUTS, owner_program, stage_program, generated_files, unchanged_profile)
from tools.generate_hia_source_helper_manifest import (
    original, function, operation, generated_files as prior_generated)
from tools.build_hia_json_preflight import CANDIDATES, image_manifest_schema
from tools.build_hia_worker_release import AGENT_INSTALLED_HELPERS
from tools.build_hia_source_build import _named_source_request, _compiled_sources
from tests.test_hia_release_stage_plan import frame_request
from tests.test_hia_release_member_check import check_packet
from tests import test_hia_helper_catalog_native as prior

ROOT = Path(__file__).resolve().parents[1]


class AgentHelperCatalogSourceControls(unittest.TestCase):
    def test_complete_prior_protocol_assets_remain_exact(self):
        for name, raw in prior_generated().items():
            self.assertEqual((ROOT / name).read_bytes(), raw, name)
        self.assertEqual(sha256((ROOT / 'examples/hia_bootstrap/source_release_stage_plan.hepta').read_bytes()).hexdigest(),
                         '614f35f61cdad7f5759f17d2ab7b7fd40af0d9643d328ae679cc447284362f53')

    def test_actual_agent_sources_and_original_capacity_profile(self):
        from hepta.hia_program import verify_program
        for name, raw in generated_files().items():
            self.assertEqual((ROOT / name).read_bytes(), raw)
            model = assemble_program(raw).as_dict()
            verify_program(model)
            unchanged_profile(model)
        self.assertEqual((MAGIC, CHECK_MODE, STAGE_OPERATION, COMPILER_ROLE),
                         (b'HIAHLM03', 15, 3, 24))
        self.assertEqual([row[0] for row in AGENT_HELPERS], [20, 21, 22, 23])

    def test_complete_reused_digest_parser_and_cli_bodies_are_unchanged(self):
        before, after = original('helper'), owner_program()
        current = {f['name']: f for f in after['functions']}
        for old in before['functions']:
            if old['name'] in ('admit', 'render'):
                continue
            expected = deepcopy(old)
            if expected['name'] in ('module_header', 'protocol_name'):
                expected['name'] += '_prior'
            self.assertEqual(current[expected['name']], expected, old['name'])
        before, after = original('stage'), stage_program()
        originals = {f['name']: f for f in before['functions']}
        for actual in after['functions']:
            if actual['name'] not in originals or actual['name'] in ('f0', 'f21', 'f26', 'f57'):
                continue
            self.assertEqual(actual, originals[actual['name']], actual['name'])
        entry = deepcopy(function(after, 'f0'))
        changes = [op for b in entry['blocks'] for op in b['ops']
                   if op['op'] == 'call' and op['attrs'].get('function') == 'reject_plan']
        self.assertEqual(len(changes), 1)
        changes[0]['attrs']['function'] = 'f1'
        self.assertEqual(entry, function(before, 'f0'))
        check = deepcopy(function(after, 'check_agent'))
        check['name'] = 'f26'
        for name in ('v64', 'v470', 'v497'):
            target = operation(check, name)
            target.clear()
            target.update(deepcopy(operation(function(before, 'f26'), name)))
        self.assertEqual(check, function(before, 'f26'))

    def test_four_real_sources_schemas_and_custody_factories_are_registered(self):
        from hepta.hia_native_helpers import HELPERS
        from hepta.hia_agent_contract import NATIVE_SOURCE_FILES
        from tools.hia_selfhost_contract import SOURCE_FILES
        self.assertEqual(AGENT_INSTALLED_HELPERS, tuple((r, c) for r, c, *_ in AGENT_HELPERS))
        for role, candidate, module, image, schema, core in AGENT_HELPERS:
            self.assertEqual(CANDIDATES[candidate], (module, image))
            self.assertEqual(image_manifest_schema(candidate, image), schema)
            source = 'examples/hia_bootstrap/' + module + '.hepta'
            self.assertTrue((ROOT / source).read_bytes().startswith(
                f'hia-asm.v1 hepta.hia.program.v{core} {module}\n'.encode()))
            self.assertIn(source, NATIVE_SOURCE_FILES)
            self.assertIn(source, SOURCE_FILES)
            selector = 'HEPTA_HIA_' + candidate.replace('-', '_').upper() + '_MANIFEST'
            adapter, factory = HELPERS[selector]
            loaded = importlib.import_module('hepta.' + adapter)
            self.assertEqual(loaded.SCHEMA, schema)
            self.assertEqual(loaded.SOURCE.resolve(), (ROOT / source).resolve())
            self.assertTrue(callable(getattr(loaded, factory)))

    def test_recipe_and_current_release_inventory_include_all_eight_actual_publications(self):
        from tools.generate_hia_agent_helper_recipe import recipe, SOURCE_PATH
        from tools.hia_native_release_dependencies import read_recipe, release_dependencies, check_source_files
        graph = recipe()
        self.assertEqual((ROOT / SOURCE_PATH).read_bytes(), graph.binary())
        expected = [name for _, candidate, _, image, _, _ in AGENT_HELPERS
                    for name in (candidate + '-manifest.json', image + '.image.bin')]
        decoded = read_recipe(graph.binary())
        self.assertEqual(decoded['publications'], expected)
        self.assertEqual(len(expected), 8)
        self.assertEqual(sum(op == 6 for op, *_ in graph.nodes), 12)
        self.assertEqual(sum(op == 8 for op, *_ in graph.nodes), 6)
        required = {OUTPUTS['owner'], OUTPUTS['stage'],
                    *(f'examples/hia_bootstrap/{module}.hepta' for _, _, module, *_ in AGENT_HELPERS)}
        self.assertTrue(required <= set(decoded['sources']))
        closure = release_dependencies(ROOT)
        check_source_files(ROOT, closure['required_sources'])


ENV = ('HIA_TEST_AGENT_HELPER_STAGE', 'HIA_TEST_AGENT_HELPER_OWNER',
       'HIA_TEST_NATIVE_SOURCE_SEED', 'HIA_TEST_AGENT_HELPER_EVIDENCE',
       'HIA_TEST_HELPER_MANIFEST_OWNER', 'HIA_TEST_RELEASE_STAGE_PLANNER',
       'HIA_TEST_HELPER_EXTENSION_STAGE')


@unittest.skipUnless(all(os.environ.get(name) for name in ENV),
                     'requires actual native Agent and prior protocol kits and source compiler')
class AgentHelperCatalogNativeControls(unittest.TestCase):
    invoke = prior.HelperCatalogNativeControls.invoke
    parts = prior.HelperCatalogNativeControls.parts
    owner_wire = prior.HelperCatalogNativeControls.owner_wire
    expected = prior.HelperCatalogNativeControls.expected

    @classmethod
    def setUpClass(cls):
        cls.planner = Path(os.environ[ENV[0]]).resolve()
        cls.owner = Path(os.environ[ENV[1]]).resolve()
        cls.seed = Path(os.environ[ENV[2]]).resolve()
        cls.evidence = Path(os.environ[ENV[3]]).resolve()
        cls.evidence.mkdir(mode=0o700, exist_ok=False)
        cls.prior_owner = Path(os.environ[ENV[4]]).resolve()
        cls.prior_planner = Path(os.environ[ENV[5]]).resolve()
        cls.prior_extension = Path(os.environ[ENV[6]]).resolve()
        cls.serial = 0
        cls.roles = AGENT_INSTALLED_HELPERS
        named = {module + '.hepta': (ROOT / 'examples/hia_bootstrap' / (module + '.hepta')).read_bytes()
                 for _, _, module, _, _, _ in AGENT_HELPERS}
        cls.selfhost = (ROOT / 'examples/hia_bootstrap/selfhost.hepta').read_bytes()
        named['selfhost.hepta'] = cls.selfhost
        request = _named_source_request(named)
        p = subprocess.run([str(cls.seed), 'sources'], input=request, capture_output=True,
                           env={'PATH': ''}, timeout=180)
        for suffix, raw in (('request', request), ('stdout', p.stdout), ('stderr', p.stderr)):
            (cls.evidence / ('compile.' + suffix)).write_bytes(raw)
        (cls.evidence / 'compile.terminal.json').write_text(json.dumps(
            {'returncode': p.returncode, 'seconds_limit': 180}) + '\n')
        if p.returncode != 0 or p.stderr != b'':
            raise AssertionError((p.returncode, p.stderr))
        cls.sources = named
        cls.images = _compiled_sources(p.stdout, named)
        cls.compiler = cls.images['selfhost.hepta']
        if sha256(cls.compiler).hexdigest() != 'acb6478d1a466d17210611c5fcbbd5aeec3109b0813e917f0bb5c8419f3c33a9':
            raise AssertionError('development compiler differs from its exact source-built identity')

    def check(self, role, kind, manifest, *, accepted=True, source=None, image=None, compiler=None):
        parts = self.parts(kind)
        request = check_packet(CHECK_MODE, role, [
            manifest, parts[0] if source is None else source,
            parts[1] if image is None else image,
            parts[3] if compiler is None else compiler])
        raw = self.invoke(self.planner, request, accepted=accepted)
        if accepted:
            self.assertEqual(raw, struct.pack('<8s3Q', b'HIASTOK1',
                                             CHECK_MODE, role, len(manifest)))

    def test_all_four_actual_frames_manifests_and_independent_checkers(self):
        for role, kind in self.roles:
            with self.subTest(role=role, component=kind):
                parts = self.parts(kind)
                framed = self.invoke(self.planner, frame_request(4, STAGE_OPERATION, role, parts))
                self.assertEqual(framed, self.owner_wire(MAGIC, role, parts))
                manifest = self.invoke(self.owner, framed)
                expected = (json.dumps(self.expected(kind), sort_keys=True, indent=2) + '\n').encode()
                self.assertEqual(manifest, expected)
                self.check(role, kind, manifest)

    def test_all_three_protocol_domains_remain_separate(self):
        parts = self.parts('agent-native-metadata')
        manifest = json.dumps(self.expected('agent-native-metadata')).encode()
        for role in (*range(20), 24, 25, (1 << 64) - 1):
            self.invoke(self.owner, self.owner_wire(MAGIC, role, parts), accepted=False)
            self.invoke(self.planner, frame_request(4, STAGE_OPERATION, role, parts), accepted=False)
            self.check(role, 'agent-native-metadata', manifest, accepted=False)
        for role, kind in self.roles:
            parts = self.parts(kind)
            for magic in (b'HIAHLM01', b'HIAHLM02'):
                self.invoke(self.owner, self.owner_wire(magic, role, parts), accepted=False)
                self.invoke(self.prior_owner, self.owner_wire(magic, role, parts), accepted=False)
            for operation in (0, 1, 2, 4):
                self.invoke(self.planner, frame_request(4, operation, role, parts), accepted=False)
            self.invoke(self.prior_planner, frame_request(4, 1, role, parts), accepted=False)
            self.invoke(self.prior_extension, frame_request(4, 2, role, parts), accepted=False)
            for mode in (0, 5, 13, 14, 16):
                self.invoke(self.planner, check_packet(mode, role, [
                    manifest, parts[0], parts[1], parts[3]]), accepted=False)

    def test_owner_refuses_other_source_changed_image_and_incomplete_framing(self):
        for role, kind in self.roles:
            parts = self.parts(kind)
            other = 'agent-json-wire' if kind != 'agent-json-wire' else 'agent-native-metadata'
            wrong = list(parts);wrong[0] = self.parts(other)[0]
            self.invoke(self.owner, self.owner_wire(MAGIC, role, wrong), accepted=False)
            for index in (1, 3):
                wrong = list(parts);wrong[index] += b'\0'
                self.invoke(self.owner, self.owner_wire(MAGIC, role, wrong), accepted=False)
            valid = self.owner_wire(MAGIC, role, parts)
            for bad in (valid[:47], valid[:-1], valid + b'\0'):
                self.invoke(self.owner, bad, accepted=False)

    def test_checker_preserves_full_five_field_parser_and_all_digest_bindings(self):
        for role, kind in self.roles:
            expected = self.expected(kind)
            valid = json.dumps(expected, separators=(',', ':')).encode()
            self.check(role, kind, valid)
            self.check(role, kind, json.dumps(dict(reversed(list(expected.items()))), indent=4).encode())
            for field in expected:
                for value in ('wrong', 1, None, [], {}):
                    bad = dict(expected);bad[field] = value
                    self.check(role, kind, json.dumps(bad).encode(), accepted=False)
                bad = dict(expected);del bad[field]
                self.check(role, kind, json.dumps(bad).encode(), accepted=False)
            self.check(role, kind, json.dumps(dict(expected, unknown='field')).encode(), accepted=False)
            self.check(role, kind, valid[:-1] + b',"schema":"duplicate"}', accepted=False)
            self.check(role, kind, valid + b'x', accepted=False)
            parts = self.parts(kind)
            self.check(role, kind, valid, source=parts[0] + b'\n', accepted=False)
            self.check(role, kind, valid, image=parts[1] + b'\0', accepted=False)
            self.check(role, kind, valid, compiler=parts[3] + b'\0', accepted=False)


if __name__ == '__main__':
    unittest.main()
