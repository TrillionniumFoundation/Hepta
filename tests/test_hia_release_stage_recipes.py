"""Independent binary DAG decoding, source contracts and real HIA semantic guards."""
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import subprocess
import unittest

from tools.build_hia_json_preflight import CANDIDATES, _image_manifest
from tools.build_hia_worker_release import INSTALLED_HELPERS
from tools.generate_hia_release_stage_recipes import ROOT, PROGRAMS, RECIPE_NAMES


def decode(raw):
    if len(raw) < 24:
        raise ValueError('short header')
    magic, count, declared = struct.unpack_from('<8s2Q', raw)
    if magic != b'HIASTD01' or not 1 <= count <= 2048:
        raise ValueError('header')
    at, handles, nodes, publications = 24, set(), [], []
    for _ in range(count):
        if len(raw) - at < 32:
            raise ValueError('short node')
        op, identity, argc, size = struct.unpack_from('<4Q', raw, at)
        at += 32
        if not 1 <= op <= 19 or argc > 132 or argc * 8 + size > len(raw) - at:
            raise ValueError('node extent')
        args = struct.unpack_from('<' + 'Q' * argc, raw, at)
        at += argc * 8
        payload = raw[at:at + size]
        at += size
        if op in (7, 8, 9, 10):
            if identity:
                raise ValueError('effect identity')
        elif not 1 <= identity <= 2048 or identity in handles:
            raise ValueError('view identity')
        references = ()
        if op in (2, 3, 4, 9, 13, 14, 15, 17):
            references = args[:1]
        elif op in (16, 19):
            references = args
        elif op == 18:
            references = args[1:6]
        elif op in (5, 10):
            references = args[4 if op == 5 else 2:]
        elif op == 6:
            references = (args[0], args[2])
        elif op in (7, 8):
            references = tuple(value for value in args if value or op == 8)
        if any(value not in handles for value in references):
            raise ValueError('forward or absent view')
        if identity:
            handles.add(identity)
        if op == 7:
            name = payload.decode('ascii')
            if not name or '/' in name or name in publications:
                raise ValueError('publication')
            publications.append(name)
        nodes.append((op, identity, args, payload))
    if at != len(raw) or len(publications) != declared:
        raise ValueError('exhaustion')
    return nodes, publications


class ReleaseStageRecipeSourceTests(unittest.TestCase):
    def test_final_recipes_equal_current_source_declarations(self):
        from tools.generate_hia_release_stage_recipes import recipes, outputs
        generated = recipes()
        actual = []
        for name in RECIPE_NAMES:
            raw = (ROOT / PROGRAMS / name).read_bytes()
            self.assertEqual(raw, generated[name].binary())
            _, names = decode(raw)
            actual.extend(names)
        expected = [*outputs(2), *(name for stage in range(4, 11) for name in outputs(stage))]
        self.assertEqual(actual, expected)
        self.assertEqual(len(set(actual)), 46)

    def test_transport_resources_rederive_from_original_flow_sources(self):
        from tools.generate_hia_release_stage_recipes import read_adapters
        self.assertEqual(len(read_adapters()), 4)
        for path, raw in read_adapters().items():
            self.assertEqual((ROOT / path).read_bytes(), raw)

    def test_all_captured_paths_are_existing_normalized_repo_resources(self):
        for name in RECIPE_NAMES:
            nodes, _ = decode((ROOT / PROGRAMS / name).read_bytes())
            for op, _, _, payload in nodes:
                if op != 1:
                    continue
                count, = struct.unpack_from('<Q', payload)
                at, aliases = 8, set()
                self.assertGreater(count, 0)
                for _ in range(count):
                    alias_size, path_size = struct.unpack_from('<2Q', payload, at)
                    at += 16
                    alias = payload[at:at + alias_size].decode('ascii')
                    at += alias_size
                    path = payload[at:at + path_size].decode('ascii')
                    at += path_size
                    self.assertNotIn(alias, aliases)
                    aliases.add(alias)
                    self.assertFalse(path.startswith('/'))
                    self.assertTrue(all(p not in ('', '.', '..') for p in path.split('/')))
                    self.assertTrue((ROOT / path).is_file(), path)
                self.assertEqual(at, len(payload))

    def test_malformed_graph_controls_are_not_valid_recipes(self):
        original = (ROOT / PROGRAMS / RECIPE_NAMES[0]).read_bytes()
        duplicate = bytearray(original)
        # The first CAPTURE cannot refer to a future handle, and identities
        # belong only to producing nodes; corruptions must not pass admission.
        struct.pack_into('<Q', duplicate, 24 + 8, 0)
        for raw in (original[:-1], original + b'x', bytes(duplicate),
                    b'BADMAGIC' + original[8:]):
            with self.assertRaises(ValueError):
                decode(raw)


@unittest.skipUnless(os.environ.get('HIA_TEST_RELEASE_STAGE_PLANNER'),
                     'requires the actual source-compiled HIA stage checker')
class ReleaseStageSemanticGuardTests(unittest.TestCase):
    def check(self, mode, calls, parts):
        wire = struct.pack('<8s4Q', b'HIASTC01', mode, calls, len(parts), 0)
        wire += b''.join(struct.pack('<Q', len(part)) + part for part in parts)
        p = subprocess.run([os.environ['HIA_TEST_RELEASE_STAGE_PLANNER'], 'build'],
                           input=wire, capture_output=True, env={'PATH': ''}, timeout=30)
        self.assertEqual(p.stderr, b'')
        if p.returncode == 0:
            self.assertEqual(p.stdout, struct.pack('<8s3Q', b'HIASTOK1', mode, calls, len(parts[0])))
            return True
        self.assertEqual(p.stdout, b'')
        return False

    def test_each_helper_binds_exact_source_image_compiler_and_manifest_schema(self):
        for ordinal, kind in enumerate(INSTALLED_HELPERS, 1):
            source, image, compiler = b'source\0' * 11, b'\x7fimage\xff' * 9, b'compiler' * 65
            protocol = CANDIDATES[kind][1]
            expected = _image_manifest(kind, protocol, source, image,
                                       protocol + '.image.bin', sha256(compiler).hexdigest())
            variants = (json.dumps(expected).encode(),
                        json.dumps(dict(reversed(list(expected.items()))), indent=2).encode() + b'\n')
            for manifest in variants:
                with self.subTest(kind=kind, manifest=manifest[:20]):
                    self.assertTrue(self.check(5, ordinal, [manifest, source, image, compiler]))
            for key in expected:
                changed = dict(expected)
                changed[key] += 'x'
                self.assertFalse(self.check(5, ordinal, [json.dumps(changed).encode(), source, image, compiler]))
            self.assertFalse(self.check(5, ordinal, [variants[0], source + b'x', image, compiler]))
            self.assertFalse(self.check(5, ordinal, [variants[0], source, image + b'x', compiler]))
            self.assertFalse(self.check(5, ordinal, [variants[0], source, image, compiler + b'x']))

    def test_helper_rejects_duplicate_unknown_missing_and_trailing_fields(self):
        kind = INSTALLED_HELPERS[0]
        protocol = CANDIDATES[kind][1]
        parts = [b'', b'image', b'compiler']
        expected = _image_manifest(kind, protocol, *parts[:2], protocol + '.image.bin', sha256(parts[2]).hexdigest())
        raw = json.dumps(expected).encode()
        self.assertTrue(self.check(5, 1, [raw, *parts]))
        duplicate = raw[:-1] + b',"schema":' + json.dumps(expected['schema']).encode() + b'}'
        for bad in (duplicate, raw + b'x', b'{}', raw[:-1],
                    json.dumps(dict(expected, unknown='x')).encode()):
            self.assertFalse(self.check(5, 1, [bad, *parts]))
        self.assertFalse(self.check(5, 0, [raw, *parts]))
        self.assertFalse(self.check(5, 9, [raw, *parts]))

    @unittest.skipUnless(os.environ.get('HIA_TEST_ARTIFACT_DESCRIPTOR'),
                         'requires an actual source-built artifact publisher')
    def test_actual_artifact_descriptor_matches_retained_independent_admission(self):
        from hepta.hia_artifact_delivery_protocol import control_descriptor, private_executable, public_executable
        original = Path(os.environ['HIA_TEST_ARTIFACT_DESCRIPTOR']).read_bytes()
        self.assertEqual(public_executable(private_executable(original)), original)
        controls = [original, original + b'x', original[:351], private_executable(original)]
        for offset in (0, 16, 24, 32, 56, 64, 96, 104, 120, 176, 232, 244,
                       256, 264, 272, 280, 288, 296, 304, 312, 320, 328, 336, 344,
                       len(original) - 1):
            changed = bytearray(original)
            changed[offset] ^= 1
            controls.append(bytes(changed))
        for raw in controls:
            try:
                control_descriptor(raw)
                expected = True
            except ValueError:
                expected = False
            self.assertEqual(self.check(6, 0, [raw]), expected, sha256(raw).hexdigest())


if __name__ == '__main__':
    unittest.main()
