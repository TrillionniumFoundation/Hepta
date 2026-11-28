"""Original-stage custody and current DAG catalog controls."""
from hashlib import sha256
from pathlib import Path
import unittest

from tools.generate_hia_release_extension_catalog import generated_table, BASE_GROUPS
from tools.hia_native_release_dependencies import TABLE, release_dependencies, read_source_table
from tools.hia_release_stage_source_history import (
    original_stage_inputs, PRIOR_TAKE, FIXTURE_TABLE, TABLE_SHA,
)

ROOT = Path(__file__).resolve().parents[1]
BASELINE = 'tests/fixtures/hia_release_stage_original_d1a62d1/current_fourteen_stage_sources.tsv.txt'


class ReleaseExtensionCatalogControls(unittest.TestCase):
    def test_all_original_fourteen_group_rows_are_preserved_as_whole_input(self):
        original = (ROOT / BASELINE).read_bytes()
        self.assertEqual(sha256(original).hexdigest(),
                         'dc743c86cbcfb7a9b7953bfd9a8c44b79190b7295b6dfd5072f251526b6042f2')
        current, report = generated_table(ROOT, source_table=original)
        old = original.decode('ascii').splitlines()
        kept = [row for row in current.decode('ascii').splitlines()[1:]
                if int(row.split('\t')[1]) <= 14]
        self.assertEqual(('\n'.join([old[0], *kept]) + '\n').encode('ascii'), original)
        self.assertTrue(report['original_fourteen_groups_unchanged'])

    def test_current_catalog_matches_every_actual_registered_publication(self):
        current = (ROOT / TABLE).read_bytes()
        generated, report = generated_table(ROOT)
        self.assertEqual(current, generated)
        closure = release_dependencies(ROOT)
        self.assertEqual(read_source_table(current)['publications'], closure['publications'])
        self.assertEqual(report['publications'], closure['publication_count'])
        self.assertIn('helper_extensions', report['extension_stages'])
        required = set(closure['required_sources'])
        self.assertIn('examples/hia_bootstrap/source_helper_extension_stage.hepta', required)
        self.assertIn('examples/hia_bootstrap/source_helper_manifest.hepta', required)

    def test_current_catalog_regeneration_is_idempotent(self):
        first, _ = generated_table(ROOT)
        second, _ = generated_table(ROOT, source_table=first)
        self.assertEqual(first, second)

    def test_unrecognized_extra_stage_is_not_silently_discarded(self):
        raw = (ROOT / BASELINE).read_bytes()
        lines = raw.decode('ascii').splitlines()
        lines[0] = 'stage\t15\t84'
        malformed = ('\n'.join([*lines, 'stage\t15\tuser-owned-stage']) + '\n').encode('ascii')
        with self.assertRaisesRegex(ValueError, 'unrecognized stage'):
            generated_table(ROOT, source_table=malformed)

    def test_original_take_changes_only_the_explicit_input_binding(self):
        import tests.test_hia_release_stage_plan as original
        actual_path, actual_raw = original.TABLE, original.TABLE.read_bytes()
        with original_stage_inputs(ROOT, original, prior_take=PRIOR_TAKE) as record:
            self.assertEqual(original.TABLE, ROOT / FIXTURE_TABLE)
            self.assertEqual(sha256(original.TABLE.read_bytes()).hexdigest(), TABLE_SHA)
            self.assertEqual(actual_path.read_bytes(), actual_raw)
            self.assertNotEqual(record['physical_initial'][TABLE]['sha256'], TABLE_SHA)
        self.assertEqual(original.TABLE, actual_path)
        self.assertTrue(record['source_initial_terminal_identical'])
        self.assertEqual(record['status'], 'UNCHANGED_AND_RESTORED')
        with self.assertRaisesRegex(ValueError, 'prior_take'):
            with original_stage_inputs(ROOT, original, prior_take='current'):
                self.fail('wrong historical take accepted')



class InitialReleaseCapabilityControls(unittest.TestCase):
    def test_complete_worker_compat_uses_only_explicit_stage_zero_capabilities(self):
        from tools.generate_hia_release_extension_catalog import INITIAL_PRODUCTS, imports
        path = "examples/hia_bootstrap/release_stage_worker_compat.hiastd"
        self.assertEqual(imports((ROOT / path).read_bytes()),
                         ("selfhost.image.bin", "hia-source-build",
                          "hia-subprocess", "hia-source-capture"))
        self.assertEqual(INITIAL_PRODUCTS, frozenset((
            "hia-source-build", "hia-elf-link", "selfhost.image.bin",
            "hia-subprocess", "hia-source-capture")))
        current, report = generated_table(ROOT)
        number = report["extension_stages"]["worker_compat"]
        rows = [row.split("\t") for row in current.decode("ascii").splitlines()
                if row.startswith("need\t" + str(number) + "\t")]
        self.assertEqual(rows, [["need", str(number), "0", name]
                               for name in imports((ROOT / path).read_bytes())])
        self.assertEqual(current, (ROOT / TABLE).read_bytes())

    def test_similar_unknown_runner_and_capture_imports_are_rejected(self):
        import tempfile
        from tools.hia_native_release_dependencies import PROGRAMS, registered_dags
        path = PROGRAMS + "release_stage_worker_compat.hiastd"
        names = [TABLE, "tools/generate_hia_release_owner.py"]
        names += [PROGRAMS + "release_stage_" + name + ".hiastd"
                  for name in registered_dags(ROOT)]
        original = (ROOT / path).read_bytes()
        for product in (b"hia-subprocess", b"hia-source-capture"):
            with self.subTest(product=product), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                for name in names:
                    target = root / name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes((ROOT / name).read_bytes())
                self.assertEqual(original.count(product), 1)
                (root / path).write_bytes(original.replace(product, product[:-1] + b"z", 1))
                with self.assertRaisesRegex(ValueError, "product not yet published"):
                    generated_table(root)
                self.assertEqual((root / TABLE).read_bytes(), (ROOT / TABLE).read_bytes())

if __name__ == '__main__':
    unittest.main()
