"""Regression gates for registered native release source/publication closure."""
from pathlib import Path
import tempfile
import unittest

from tools.hia_native_release_dependencies import (
    TABLE, check_authorities, read_source_table, release_dependencies,
)

ROOT = Path(__file__).resolve().parents[1]


class NativeReleaseDependencyTests(unittest.TestCase):
    def test_every_declared_output_and_captured_source_is_registered(self):
        dependency = release_dependencies(ROOT)
        self.assertIn('runtime', dependency['registered_dags'])
        self.assertIn('generation_lease', dependency['registered_dags'])
        check_authorities(ROOT, dependency['required_sources'])

    def test_omitting_runtime_cannot_pass_a_complete_source_declaration(self):
        dependency = release_dependencies(ROOT)
        for omitted in ('runtime', 'generation_lease'):
            names = [name for name in dependency['registered_dags'] if name != omitted]
            with self.subTest(omitted=omitted), self.assertRaisesRegex(
                    ValueError, 'publications differ from source table'):
                release_dependencies(ROOT, names=names)

    def test_stage14_registration_repairs_the_stale_header_and_preserves_other_stages(self):
        from tools.generate_hia_generation_lease_native_release import build_recipe, register_stage
        recipe, paths, resources = build_recipe()
        original = (ROOT / TABLE).read_bytes()
        records = original.decode('ascii').splitlines()[1:]
        retained = [line for line in records if int(line.split('\t')[1]) != 14]
        with tempfile.TemporaryDirectory(prefix='hia-release-registration-') as temporary:
            root = Path(temporary)
            table = root / TABLE
            table.parent.mkdir(parents=True)
            # This is the original broken aggregate: stage 14 rows with a stage 13 header.
            table.write_bytes(b'stage\t13\t81\n' + original.split(b'\n', 1)[1])
            with self.assertRaisesRegex(ValueError, 'stage out of range'):
                read_source_table(table.read_bytes())
            register_stage(paths, resources, recipe.published, root=root)
            first = table.read_bytes()
            actual = read_source_table(first)
            self.assertEqual(actual['stages'], 14)
            self.assertEqual(actual['publications'][-3:], list(recipe.published))
            self.assertEqual([line for line in first.decode('ascii').splitlines()[1:]
                              if int(line.split('\t')[1]) != 14], retained)
            register_stage(paths, resources, recipe.published, root=root)
            self.assertEqual(table.read_bytes(), first)


if __name__ == '__main__':
    unittest.main()
