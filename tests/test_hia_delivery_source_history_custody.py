"""Physical-custody negatives for the retained artifact and Store Source fixtures."""
from hashlib import sha256
import json
from pathlib import Path
import tempfile
import unittest

from tests import hia_artifact_delivery_source_history as artifact
from tests import hia_component_native_cold_history as builder
from tests import hia_component_authoring_history as component

ROOT = Path(__file__).resolve().parents[1]
BUILDER_ORIGINAL = {'bytes': 4487, 'sha256': 'f5630ef5176057b9d9470e2300f27332200540b99e271ecaed7a4ec18ddda95d'}


def pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


def builder_gate(root, *, take=Path.read_bytes):
    raw = take(root / builder.PATH)
    raw = builder.predecessor(builder.PATH, raw, root=root, take=take)
    raw = component.predecessor(builder.PATH, raw, root=root, take=take)
    if pin(raw) != BUILDER_ORIGINAL:
        raise ValueError('the unchanged whole original builder pin differs')
    return raw


def stage(root, sources):
    for name, raw in sources.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)


class DeliverySourceHistoryCustodyTests(unittest.TestCase):
    def test_builder_complete_two_stage_history_keeps_original_authority(self):
        physical = (ROOT / builder.PATH).read_bytes()
        predecessor = builder.predecessor(builder.PATH, physical, root=ROOT)
        self.assertEqual(pin(physical), builder.CURRENT)
        self.assertEqual(pin(predecessor), builder.PREDECESSOR)
        self.assertEqual(pin(builder_gate(ROOT)), BUILDER_ORIGINAL)
        self.assertEqual((ROOT / builder.PATH).read_bytes(), physical)
        self.assertEqual(builder.predecessor(builder.PATH, predecessor, root=ROOT), predecessor)

    def test_builder_every_physical_input_refuses_missing_and_refreshed_drift(self):
        names = (builder.PATH, builder.SOURCE, builder.FIXTURE, component.FIXTURE)
        originals = {name: (ROOT / name).read_bytes() for name in names}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage(root, originals)
            self.assertEqual(pin(builder_gate(root)), BUILDER_ORIGINAL)
            for name in names:
                for missing in (False, True):
                    with self.subTest(path=name, missing=missing):
                        path = root / name
                        if missing:
                            path.unlink()
                        elif name == builder.FIXTURE:
                            value = json.loads(originals[name])
                            value['files'][builder.PATH]['predecessor']['sha256'] = '0' * 64
                            path.write_text(json.dumps(value))
                        else:
                            path.write_bytes(originals[name] + b'\n')
                        with self.assertRaises((ValueError, FileNotFoundError)):
                            builder_gate(root)
                        path.write_bytes(originals[name])

    def test_builder_rejects_foreign_argument_and_terminal_source_change(self):
        physical = (ROOT / builder.PATH).read_bytes()
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(FileNotFoundError):
                builder.predecessor(builder.PATH, physical, root=Path(temporary))
        reads = {}

        def take(path):
            raw = path.read_bytes()
            reads[path] = reads.get(path, 0) + 1
            if path == ROOT / builder.PATH and reads[path] > 1:
                return raw + b'\n'
            return raw

        with self.assertRaisesRegex(ValueError, 'terminal physical reread'):
            builder.predecessor(builder.PATH, physical, root=ROOT, take=take)

    def test_artifact_current_sources_restore_all_63_without_replacing_current_callers(self):
        from tools.run_hia_unittest_gate import load_declared_suite

        prepared, physical = artifact.artifact_sources(ROOT)
        original = json.loads(prepared[artifact.ORIGINAL])
        changed = []
        for name in artifact.CALLERS:
            self.assertEqual(pin(prepared[name]),
                {key: original['source_files'][name][key] for key in ('bytes', 'sha256')})
            self.assertEqual((ROOT / name).read_bytes(), physical[name])
            if prepared[name] != physical[name]:
                changed.append(name)
        self.assertEqual(changed, list(artifact.CALLERS[1:3]))
        suite, planned = load_declared_suite([name[:-3].replace('/', '.') for name in artifact.CALLERS])
        self.assertEqual(suite.countTestCases(), 63)
        self.assertEqual(list(planned), original['declared_original_test_ids'])
        with artifact.historical_artifact_source_root(ROOT) as root:
            for name, raw in prepared.items():
                self.assertEqual((root / name).read_bytes(), raw)
        self.assertEqual({name: (ROOT / name).read_bytes() for name in physical}, physical)

    def test_artifact_every_capture_refuses_absent_tampered_and_foreign_source(self):
        prepared, physical = artifact.artifact_sources(ROOT)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaises(FileNotFoundError):
                artifact.artifact_sources(root)
            stage(root, physical)
            self.assertEqual(artifact.artifact_sources(root)[0], prepared)
            # Generator semantics remain governed by the unchanged original
            # policy assertion; the retained fixed caller/authority boundary is
            # what this independent admission control exercises.
            protected = set(physical) - {artifact.GENERATOR, artifact.OLD_GENERATOR}
            for name in sorted(protected):
                for missing in (False, True):
                    with self.subTest(path=name, missing=missing):
                        path = root / name
                        if missing:
                            path.unlink()
                        else:
                            path.write_bytes(physical[name] + b'\n')
                        with self.assertRaises((ValueError, FileNotFoundError)):
                            artifact.artifact_sources(root)
                        path.write_bytes(physical[name])

    def test_artifact_projection_and_actual_source_are_both_reread_at_terminal(self):
        _, physical = artifact.artifact_sources(ROOT)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage(root, physical)
            with self.assertRaisesRegex(ValueError, 'data projection changed'):
                with artifact.historical_artifact_source_root(root) as historical:
                    path = historical / artifact.CALLERS[1]
                    path.write_bytes(path.read_bytes() + b'\n')
            with self.assertRaisesRegex(ValueError, 'source changed while historical control ran'):
                with artifact.historical_artifact_source_root(root):
                    path = root / artifact.CALLERS[1]
                    path.write_bytes(physical[artifact.CALLERS[1]] + b'\n')
