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


if __name__ == '__main__':
    unittest.main()
