"""Independent source-graph and native release qualification entry checks."""
from hashlib import sha256
from pathlib import Path
import struct
import unittest

from tools.qualify_hia_release_owner import inventory

ROOT = Path(__file__).resolve().parents[1]
BOOT = ROOT / 'examples/hia_bootstrap'


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
            'additional': [name for stage in range(4, 11) for name in outputs[stage]],
        }
        all_names = []
        for kind, names in expected.items():
            with self.subTest(kind=kind):
                actual, operations = decode_dag((BOOT / f'release_stage_{kind}.hiastd').read_bytes())
                self.assertEqual(actual, names)
                self.assertIn(10, operations)
                all_names.extend(actual)
        self.assertEqual(len(all_names), 66)
        self.assertEqual(len(set(all_names)), 66)

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
