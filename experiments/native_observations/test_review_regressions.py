"""Independent real-GCC regressions for dependency pathname fidelity."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from experiments.request_load.context import Rejected
from .context import Context
from .observer import Observer


class ReviewRegressions(unittest.TestCase):
    def test_gcc_literal_backslash_pair_never_observes_decoy(self):
        self._assert_exact_path_or_rejected('a' + '\\' * 2 + 'b.h', 'a' + '\\' + 'b.h')

    def test_gcc_trailing_backslash_never_becomes_continuation(self):
        self._assert_exact_path_or_rejected('a' + '\\', 'a')

    def _assert_exact_path_or_rejected(self, actual_name, decoy_name):
        cc = shutil.which('gcc')
        self.assertIsNotNone(cc, 'real GCC is required, never skip this control')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            actual = root / actual_name
            decoy = root / decoy_name
            actual.write_text('/* actual compiler input */\n')
            decoy.write_text('/* unrelated decoy */\n')
            source = root / 'main.c'
            source.write_text('int main(void) { return 0; }\n')
            depfile = root / 'unit.d'
            subprocess.run([cc, '-include', str(actual), '-MD', '-MF', str(depfile),
                            '-c', str(source), '-o', str(root / 'unit.o')],
                           check=True, capture_output=True)
            context = Context()
            observer = Observer(context)
            try:
                observer.collect(depfile)
            except Rejected:
                # Supporting every GCC filename is unnecessary; safe refusal is fine.
                self.assertTrue(context.closed)
                return
            self.assertIn(str(actual), observer.receipt(),
                          'must not silently substitute a different dependency pathname')
            self.assertNotIn(str(decoy), observer.receipt())
            actual.write_text('/* changed compiler input */\n')
            with self.assertRaises(Rejected):
                observer.revalidate()
            self.assertTrue(context.closed)


if __name__ == '__main__':
    unittest.main()
