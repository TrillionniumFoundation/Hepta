"""Independent source-graph and native release qualification entry checks."""
from hashlib import sha256
from pathlib import Path
import struct
import unittest

from tools.qualify_hia_release_owner import inventory

ROOT = Path(__file__).resolve().parents[1]
BOOT = ROOT / 'examples/hia_bootstrap'

# Independent stage inventory before the six complete-controller publications.
# Frozen Git source: 35068b189a0f9042c64cd7e1cb45d0c0933e9b93
# release_stage_sources.tsv SHA256: 0b63fe4c2f1171d75a5807e4bbeeb54425e86ef4092a1a34caca2909412696cb
LEGACY_STAGE_OUTPUTS = {'safe': ('hia-safe-core-prove',), 'constructor': ('hia-nominal-constructor',), 'core': ('hia', 'hia-selfhost-component', 'hia-normalize-core', 'hia-verify-core-json', 'hia-inspect-core-json', 'hia-patch-core-json', 'hia-catalog', 'hia-import-assembly', 'hia-render-assembly', 'hia-capabilities', 'hia-emit-object', 'hia-build-object', 'hia-publish-program', 'hia-publish-assembly', 'hia-publish-patch', 'hia-publish-edit', 'hia-publish-query', 'hia-publish-batch-query', 'hia-publish-batch', 'hia-impact-core-json', 'hia-prepare-edit-query', 'hia-prepare-edit-batch', 'hia-apply-edit', 'hia-apply-edit-batch', 'hia-worker-scalar-implementation'), 'additional': ('agent-schema-manifest.json', 'agent-schema.image.bin', 'agent-response-schema-manifest.json', 'agent-response-schema.image.bin', 'agent-verify-response-schema-manifest.json', 'agent-verify-response-schema.image.bin', 'agent-discovery-manifest.json', 'agent-discovery.image.bin', 'agent-inspection-manifest.json', 'agent-inspection.image.bin', 'agent-identity-manifest.json', 'agent-identity.image.bin', 'elf-shared-linker-manifest.json', 'elf-shared-linker.image.bin', 'scalar-reference-manifest.json', 'scalar-reference.image.bin', 'module-0.bin', 'module-1.bin', 'module-2.bin', 'module-3.bin', 'hia-agent-store', 'hia-native', 'hia-agent-read-carrier', 'hia-owned-reference-wire', 'hia-sqlite-rowid-lookup', 'hia-sqlite-table-walk', 'hia-sqlite-record-layout', 'hia-sqlite-agent-row-import', 'hia-sqlite-agent-catalog', 'hia-sqlite-agent-import-batch', 'hia-sqlite-agent-cost-sequence', 'hia-sqlite-agent-artifact-catalog', 'hia-sqlite-migration-plan', 'hia-agent-artifact-capture', 'hia-nominal-packet', 'hia-sqlite-migration-projection', 'hia-sqlite-pager', 'hia-sqlite-migration-publish', 'hia-sqlite-migrate')}
CONTROLLER_OUTPUTS = (
    'hia-mcp-request-audit', 'hia-mcp-job-bridge', 'hia-mcp-service',
    'hia-ndu-scalar', 'hepta-runtime-jobctl', 'hia-source-contract',
)


def decode_dag(raw):
    magic, count, expected = struct.unpack_from('<8s2Q', raw)
    if magic != b'HIASTD01' or not 0 < count <= 8192:
        raise ValueError('DAG envelope')
    at, handles, publishes, operations = 24, set(), [], []
    for _ in range(count):
        op, identity, argc, size = struct.unpack_from('<4Q', raw, at)
        at += 32
        if not 1 <= op <= 19 or argc > 132 or at + argc * 8 + size > len(raw):
            raise ValueError('DAG extent')
        args = struct.unpack_from('<' + 'Q' * argc, raw, at)
        at += argc * 8
        payload = raw[at:at + size]
        at += size
        effect = 7 <= op <= 10
        if effect != (identity == 0) or (not effect and (identity in handles or not 1 <= identity <= 2048)):
            raise ValueError('DAG result identity')
        if op in (2, 3, 13, 17):
            refs = args
        elif op in (4, 14, 15):
            refs = args[:1]
        elif op in (5, 10):
            refs = args[4 if op == 5 else 2:]
        elif op == 6:
            refs = (args[0], args[2])
        elif op == 7:
            refs = (args[0],) + ((args[1],) if args[1] else ())
            publishes.append(payload.decode('ascii'))
        elif op in (8, 9, 16, 19):
            refs = args
        elif op == 18:
            refs = args[1:6]
        else:
            refs = ()
        if any(ref not in handles for ref in refs):
            raise ValueError('forward or absent DAG reference')
        if not effect:
            handles.add(identity)
        operations.append(op)
    if at != len(raw) or len(publishes) != expected or len(set(publishes)) != expected:
        raise ValueError('DAG publication inventory')
    return publishes, operations


class NativeReleaseOwnerSourceTests(unittest.TestCase):
    def test_complete_special_graphs_have_exact_stage_outputs_and_prior_references(self):
        table = (BOOT / 'release_stage_sources.tsv').read_text('ascii').splitlines()[1:]
        outputs = {}
        for line in table:
            fields = line.split('\t')
            if fields[0] == 'output':
                outputs.setdefault(int(fields[1]), []).append(fields[2])
        expected = {
            'safe': outputs[1], 'constructor': outputs[2], 'core': outputs[3],
            'additional': [name for stage in range(4, 11) for name in outputs[stage]
                           if name not in CONTROLLER_OUTPUTS],
            'controller': list(CONTROLLER_OUTPUTS),
        }
        all_names = []
        for kind, names in expected.items():
            with self.subTest(kind=kind):
                actual, operations = decode_dag((BOOT / f'release_stage_{kind}.hiastd').read_bytes())
                self.assertEqual(actual, names)
                self.assertIn(10, operations)
                all_names.extend(actual)
        self.assertEqual(set(outputs), set(range(1, 11)))
        self.assertEqual(len(all_names), 72)
        self.assertEqual(len(set(all_names)), 72)
        self.assertEqual(all_names, [name for stage in range(1, 11) for name in outputs[stage]])

    def test_original_66_publications_remain_exact_against_frozen_stage_inventory(self):
        all_names = []
        for kind, names in LEGACY_STAGE_OUTPUTS.items():
            with self.subTest(kind=kind):
                actual, operations = decode_dag((BOOT / f'release_stage_{kind}.hiastd').read_bytes())
                self.assertEqual(actual, list(names))
                self.assertIn(10, operations)
                all_names.extend(actual)
        self.assertEqual(len(all_names), 66)
        self.assertEqual(len(set(all_names)), 66)

    def test_current_72_stage_outputs_are_part_of_the_complete_289_member_package(self):
        from tools.build_hia_json_preflight import current_sources
        from tools.build_hia_native_distribution_package import expected_member_names, MANDATORY_PROGRAMS
        from tools.generate_hia_release_owner import DAG_KINDS
        self.assertEqual(DAG_KINDS, ('safe', 'constructor', 'core', 'additional', 'controller'))
        stage_names = []
        for kind in DAG_KINDS:
            names, unused = decode_dag((BOOT / f'release_stage_{kind}.hiastd').read_bytes())
            stage_names.extend(names)
        declared = expected_member_names(current_sources())
        self.assertEqual(len(declared), 289)
        self.assertEqual(len(stage_names), 72)
        self.assertTrue(set(stage_names) <= declared)
        self.assertTrue(set(MANDATORY_PROGRAMS) <= declared)
        self.assertTrue(set(CONTROLLER_OUTPUTS) <= declared)

    def test_worker_owner_and_dag_are_current_generated_release_compositions(self):
        from hepta.hia_agent_assembly import render_assembly
        from tools.generate_hia_artifact_publication import document
        from tools.generate_hia_worker_install_owner import policy_source, packer_source
        for name, source in (
                ('worker_install_owner', policy_source()),
                ('worker_install_dag', policy_source(stage=True)),
                ('worker_install_owner_packer', packer_source())):
            with self.subTest(name=name):
                self.assertEqual(render_assembly(document(source, name)).encode(),
                                 (BOOT / (name + '.hepta')).read_bytes())

    def test_core_graph_retains_dynamic_codec_roundtrips_and_exact_tail_checks(self):
        _, operations = decode_dag((BOOT / 'release_stage_core.hiastd').read_bytes())
        self.assertIn(18, operations)
        self.assertIn(19, operations)
        raw = (BOOT / 'release_stage_core.hiastd').read_bytes()
        broken = bytearray(raw)
        struct.pack_into('<Q', broken, 24 + 8, 2049)
        with self.assertRaises(ValueError):
            decode_dag(broken)
        with self.assertRaises(ValueError):
            decode_dag(raw + b'trailing')

    def test_authored_core_recipe_is_the_checked_resource(self):
        from tools.generate_hia_release_core_recipe import CoreRecipe
        self.assertEqual(CoreRecipe().build().binary(), (BOOT / 'release_stage_core.hiastd').read_bytes())

    def test_inventory_keeps_every_independent_source_pin_in_byte_order(self):
        pins = {'z.hepta': sha256(b'z').hexdigest(), 'a/empty': sha256(b'').hexdigest()}
        raw = inventory(pins)
        self.assertEqual(raw[:16], struct.pack('<8sQ', b'HIASPI01', 2))
        at, observed = 16, []
        while at < len(raw):
            size, = struct.unpack_from('<Q', raw, at)
            pin = raw[at + 8:at + 40].hex()
            name = raw[at + 40:at + 40 + size].decode('ascii')
            observed.append((name, pin))
            at += 40 + size
        self.assertEqual(observed, sorted(pins.items()))
        for name in ('/absolute', '../escape', 'a//b', './same', 'a/../b'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                inventory({name: pins['z.hepta']})


if __name__ == '__main__':
    unittest.main()
