"""Regression gates for registered native release source/publication closure."""
from pathlib import Path
import unittest

from tools.hia_native_release_dependencies import check_authorities, release_dependencies

ROOT = Path(__file__).resolve().parents[1]


class NativeReleaseDependencyTests(unittest.TestCase):
    def test_every_declared_output_and_captured_source_is_registered(self):
        dependency = release_dependencies(ROOT)
        self.assertIn('runtime', dependency['registered_dags'])
        check_authorities(ROOT, dependency['required_sources'])

    def test_omitting_runtime_cannot_pass_a_complete_source_declaration(self):
        dependency = release_dependencies(ROOT)
        names = [name for name in dependency['registered_dags'] if name != 'runtime']
        with self.assertRaisesRegex(ValueError, 'publications differ from source table'):
            release_dependencies(ROOT, names=names)


if __name__ == '__main__':
    unittest.main()
