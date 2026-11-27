"""Pinned fixture relocation must be reversible and cannot retain stale roots."""
import ast
import unittest
from tools.qualify_hia_future_value_integration import rebind_original_root

class FutureFixtureBindingTests(unittest.TestCase):
    def test_relocated_fixture_recovers_original_bytes_and_ast(self):
        original = "ROOT='/original/custody'\npaths=['/original/custody/a', '/original/custody/b']\nassert len(paths)==2\n"
        bound = rebind_original_root(original, '/original/custody', '/fresh/fixtures')
        self.assertNotIn('/original/custody', bound)
        recovered = bound.replace('/fresh/fixtures', '/original/custody')
        self.assertEqual(recovered.encode(), original.encode())
        self.assertEqual(ast.dump(ast.parse(recovered)), ast.dump(ast.parse(original)))

    def test_no_root_reference_preserves_source(self):
        original = 'assert 1 + 1 == 2\n'
        self.assertEqual(rebind_original_root(original, '/original/custody', '/fresh/fixtures'), original)

    def test_target_collision_cannot_fabricate_reverse_source(self):
        with self.assertRaises(AssertionError):
            rebind_original_root("paths=['/original/custody/a','/fresh/fixtures/b']", '/original/custody', '/fresh/fixtures')

    def test_nested_target_cannot_keep_old_prefix(self):
        with self.assertRaises(AssertionError):
            rebind_original_root("path='/original/custody/a'", '/original/custody', '/original/custody/fresh')

    def test_invalid_prefixes_refuse(self):
        for old,new in (('', '/fresh'), ('relative', '/fresh'), ('/', '/fresh'), ('/old', 'relative'), ('/old', '/'), ('/old', '/new\x00')):
            with self.subTest(old=old, new=new), self.assertRaises(AssertionError):
                rebind_original_root('pass', old, new)

if __name__ == '__main__':
    unittest.main()
