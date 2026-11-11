"""Provenance boundaries for a conditional proof of actual C1 output bytes."""
from __future__ import annotations

import copy
import difflib
from hashlib import sha1, sha256
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

from tools.hia_selfhost_select import select_source
from tools.qualify_hia_original_select_fragments import projection_object, select_fragment

# The 35-byte span observed from the exact frozen C1's u8/u32/u64/usize output.
# Tests of this layout are not represented as proof of an actual compiler run;
# the qualification tool separately retains all native compiler observations.
OBSERVED = bytes.fromhex(
    "488b9580ffffff488b8d60fcffff488b8540f9ffff4885d2480f45c148898530f9ffff")


class OriginalSelectFragmentTests(unittest.TestCase):
    def test_source_slot_identity_prevents_neighboring_value_substitution(self):
        source = select_source("u64")
        image = b"\x90" * 19 + OBSERVED + b"\xc3"
        binding = select_fragment(source, image)
        self.assertEqual((binding["start"], binding["end"]), (19, 54))
        self.assertEqual(binding["variables"], ["v6", "v56", "v106", "v107"])
        damaged = bytearray(image)
        struct.pack_into("<i", damaged, 19 + 10, -32 - 16 * 55)
        with self.assertRaisesRegex(ValueError, "different source/result SSA slots"):
            select_fragment(source, bytes(damaged))

    def test_result_slot_and_uniqueness_are_part_of_provenance(self):
        source = select_source("u32")
        damaged = bytearray(OBSERVED)
        struct.pack_into("<i", damaged, 31, -32 - 16 * 108)
        with self.assertRaisesRegex(ValueError, "different source/result SSA slots"):
            select_fragment(source, bytes(damaged))
        with self.assertRaisesRegex(ValueError, "exactly one selection marker"):
            select_fragment(source, OBSERVED + OBSERVED)
        with self.assertRaisesRegex(ValueError, "truncated"):
            select_fragment(source, OBSERVED[3:])

    def test_projection_retains_actual_bytes_and_an_explicit_context_boundary(self):
        for typ in ("u8", "u32", "u64", "usize"):
            with self.subTest(typ=typ):
                binding = select_fragment(select_source(typ), OBSERVED)
                obj, projection = projection_object(binding)
                self.assertIn(OBSERVED, obj)
                self.assertTrue(projection["scaffolding_is_new"])
                self.assertFalse(projection["scaffolding_proves_original_context"])
                self.assertFalse(binding["entire_compiler_output_validated"])
                self.assertFalse(binding["fragment_instructions_reemitted"])

    def test_changed_copied_bytes_are_rejected_before_projection(self):
        binding = copy.deepcopy(select_fragment(select_source("u64"), OBSERVED))
        binding["fragment_hex"] = (OBSERVED[:-1] + b"\0").hex()
        with self.assertRaisesRegex(ValueError, "changed before projection"):
            projection_object(binding)


class HistoricalBoundaryReached(RuntimeError):
    """A suffix fixture reached the subsequent worker or proof boundary."""


class SourceSuffixConsumerTests(unittest.TestCase):
    """Exercise path consumers without claiming a compiler or SMT qualification."""

    @staticmethod
    def frozen_inputs(directory):
        original = (
            'hia-asm.v1 hepta.hia.program.v8 historical_suffix\n'
            'fn value() -> (u32) effects() entry(b0)\n'
            'block b0()\n'
            '  n:u32 = const() {"value":1}\n'
            '  ret(n)\n'
            'end\n'
        ).encode()
        candidate = original.replace(b'{"value":1}', b'{"value":2}')
        member = 'examples/hia_bootstrap/selfhost.hiaasm'
        patch_bytes = (
            'diff --git a/' + member + ' b/' + member + '\n'
            + ''.join(difflib.unified_diff(
                original.decode().splitlines(keepends=True),
                candidate.decode().splitlines(keepends=True),
                fromfile='a/' + member, tofile='b/' + member))
        ).encode()
        data = {'original': original, 'candidate': candidate, 'patch': patch_bytes}
        paths = {}
        for name, raw in data.items():
            suffix = '.patch' if name == 'patch' else '.hepta'
            paths[name] = directory / (name + suffix)
            paths[name].write_bytes(raw)
        return data, paths, {name: sha256(raw).hexdigest() for name, raw in data.items()}

    def test_current_repository_protocol_paths_resolve_the_same_pinned_sources(self):
        from tools import qualify_hia_agent_repository_maintenance as maintenance

        config = maintenance.cfg()
        self.assertEqual(config['source_base'], '1b5e946c9889b1c19ae86235cb14dfb76da10777')
        self.assertEqual(len(config['tasks']), 2)
        for task in config['tasks']:
            with self.subTest(task=task['id']):
                path = maintenance.ROOT / task['source_path']
                self.assertEqual(path.suffix, '.hepta')
                raw = path.read_bytes()
                self.assertEqual(sha256(raw).hexdigest(), task['source_sha256'])
                self.assertEqual(
                    sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest(),
                    task['source_git_blob'])
                checked = maintenance.target(task)
                self.assertIn(task['function'], [fn['name'] for fn in checked['functions']])

    def test_exact_historical_patch_members_reconstruct_in_both_qualifiers(self):
        from tools import qualify_hia_original_select_fragments as fragments
        from tools import qualify_hia_agent_original_select_delta as delta

        with tempfile.TemporaryDirectory(prefix='hepta-historical-patch-') as tmp:
            directory = Path(tmp)
            inputs = directory / 'supplied-inputs'
            inputs.mkdir()
            data, paths, hashes = self.frozen_inputs(inputs)
            fragment_output = directory / 'fragment-qualification'
            fragment_output.mkdir()
            with patch.object(fragments, 'HASHES', hashes):
                self.assertEqual(fragments.freeze_inputs(paths, fragment_output), data)
            record = json.loads((fragment_output / 'patch-apply.json').read_bytes())
            self.assertEqual(record['returncode'], 0)
            self.assertIn('--include=examples/hia_bootstrap/selfhost.hiaasm', record['command'])

            delta_output = directory / 'delta-qualification'
            with (
                patch.object(delta, 'BASE_SHA', hashes['original']),
                patch.object(delta, 'CANDIDATE_SHA', hashes['candidate']),
                patch.object(delta, 'PATCH_SHA', hashes['patch']),
                patch.object(delta, 'PinnedWorker', side_effect=HistoricalBoundaryReached) as worker,
                self.assertRaises(HistoricalBoundaryReached),
            ):
                delta.run(paths['original'], paths['candidate'], paths['patch'], delta_output)
            worker.assert_called_once_with(delta_output, delta_output / 'frozen-inputs')

            for output in (fragment_output, delta_output):
                with self.subTest(qualifier=output.name):
                    self.assertEqual(
                        (output / 'patch-reconstruction/examples/hia_bootstrap/selfhost.hiaasm').read_bytes(),
                        data['candidate'])
                    for name, raw in data.items():
                        suffix = '.patch' if name == 'patch' else '.hiaasm'
                        self.assertEqual((output / 'frozen-inputs' / (name + suffix)).read_bytes(), raw)
            for name, path in paths.items():
                self.assertEqual(path.read_bytes(), data[name])

    def test_historical_replay_keeps_manifest_members_and_reaches_proof_boundary(self):
        from tools import qualify_hia_original_select_fragments as fragments
        from tools import replay_hia_original_select_fragments as replay

        with tempfile.TemporaryDirectory(prefix='hepta-historical-replay-') as tmp:
            directory = Path(tmp)
            inputs = directory / 'supplied-inputs'
            inputs.mkdir()
            data, _, hashes = self.frozen_inputs(inputs)
            archive = directory / 'retained-fixture'
            frozen = archive / 'frozen-inputs'
            frozen.mkdir(parents=True)
            for name, raw in data.items():
                suffix = '.patch' if name == 'patch' else '.hiaasm'
                (frozen / (name + suffix)).write_bytes(raw)
            seed = archive / 'frozen-c1-seed/B0.so'
            seed.parent.mkdir()
            seed.write_bytes(b'opaque retained compiler bytes; never executed')
            # Synthetic scope metadata admits the path reader only. The mocked next
            # boundary prevents these fixture bytes from becoming proof evidence.
            report = {
                'schema': fragments.SCHEMA,
                'status': 'PASS_SCOPED_COPIED_FRAGMENTS',
                'original_agent_four_claim_gate': 'HOLD',
                'agent_proof_receipt_issued': False,
                'evaluation_performed': False,
                'adoption_authorized': False,
                'whole_compiler_or_original_agent_delta_proved': False,
                'cases': [{'type': typ} for typ in fragments.WIDTHS],
                'exact_frozen_input_sha256': hashes,
                'candidate_seed_image_sha256': sha256(seed.read_bytes()).hexdigest(),
            }
            (archive / 'qualification.json').write_text(json.dumps(report))
            first_case = archive / next(iter(fragments.WIDTHS))
            first_case.mkdir()
            source_bytes = b'opaque supplied source'
            image_bytes = b'opaque supplied output'
            (first_case / 'actual-c1-output.input.bin').write_bytes(source_bytes)
            (first_case / 'actual-c1-output.image.bin').write_bytes(image_bytes)
            manifest = {p.relative_to(archive).as_posix(): sha256(p.read_bytes()).hexdigest()
                        for p in sorted(archive.rglob('*')) if p.is_file()}
            manifest_path = archive / 'artifact-manifest.json'
            manifest_path.write_text(json.dumps(manifest, sort_keys=True))
            manifest_sha256 = sha256(manifest_path.read_bytes()).hexdigest()
            before = {p.relative_to(archive): p.read_bytes()
                      for p in archive.rglob('*') if p.is_file()}
            output = directory / 'fresh-replay'
            output.mkdir()
            prefix = output / 'empty-bytecode-cache'
            prefix.mkdir()
            with (
                patch.object(fragments, 'HASHES', hashes),
                patch.object(fragments, 'select_fragment', side_effect=HistoricalBoundaryReached) as boundary,
                patch.object(sys, 'dont_write_bytecode', True),
                patch.object(sys, 'pycache_prefix', str(prefix)),
                patch.object(sys, 'path', sys.path[:]),
                self.assertRaises(HistoricalBoundaryReached),
            ):
                replay.replay(archive, manifest_sha256, output)
            boundary.assert_called_once_with(source_bytes, image_bytes)
            self.assertEqual(
                {p.relative_to(archive): p.read_bytes() for p in archive.rglob('*') if p.is_file()},
                before)
            self.assertFalse(list(prefix.rglob('*')))


if __name__ == "__main__":
    unittest.main()
