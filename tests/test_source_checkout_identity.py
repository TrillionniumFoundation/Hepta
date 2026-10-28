"""Real autocrlf checkouts must preserve the compiler's exact Python bytes."""
from hashlib import sha256
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class PythonCheckoutIdentityTests(unittest.TestCase):
    def test_autocrlf_checkout_matches_git_blob_identity_and_negative_control(self):
        attributes = (ROOT / '.gitattributes').read_text()
        rule = '*.py text eol=lf'
        self.assertEqual(attributes.splitlines().count(rule), 1)
        self.assertIn('experiments/hia_optimizer_eval/rebind/source_changes.diff -whitespace', attributes)
        sources = {path.name: path.read_bytes() for path in sorted((ROOT / 'hepta').glob('*.py'))}
        self.assertTrue(sources)

        def git(directory, *arguments):
            result = subprocess.run(['git', *arguments], cwd=directory, capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
            return result.stdout

        for with_lf_rule in (False, True):
            with self.subTest(lf_rule=with_lf_rule), tempfile.TemporaryDirectory(prefix='hepta-checkout-bytes-') as temporary:
                base = Path(temporary)
                seed, checkout = base / 'seed', base / 'windows-style-checkout'
                (seed / 'hepta').mkdir(parents=True)
                selected = attributes if with_lf_rule else attributes.replace(rule + '\n', '')
                (seed / '.gitattributes').write_text(selected)
                for name, data in sources.items():
                    (seed / 'hepta' / name).write_bytes(data)
                git(seed, 'init', '--quiet')
                git(seed, '-c', 'core.autocrlf=false', '-c', 'core.safecrlf=false',
                    'add', '.gitattributes', 'hepta')
                git(seed, '-c', 'user.name=Hepta checkout test', '-c', 'user.email=checkout-test@example.invalid',
                    '-c', 'commit.gpgsign=false', '-c', 'core.hooksPath=/dev/null',
                    'commit', '--quiet', '-m', 'Local checkout identity fixture')
                # --config is applied before this real clone's first checkout.
                git(base, 'clone', '--quiet', '--no-hardlinks', '--config', 'core.autocrlf=true',
                    str(seed), str(checkout))
                self.assertEqual(git(checkout, 'config', '--get', 'core.autocrlf'), b'true\n')
                expected_hash = sha256()
                changed = []
                for name in sources:
                    original = git(checkout, 'show', 'HEAD:hepta/' + name)
                    expected_hash.update(name.encode() + b'\0' + original + b'\0')
                    actual = (checkout / 'hepta' / name).read_bytes()
                    if with_lf_rule:
                        self.assertEqual(actual, original, name)
                        self.assertNotIn(b'\r\n', actual, name)
                    elif actual != original:
                        changed.append(name)
                        self.assertEqual(actual, original.replace(b'\n', b'\r\n'), name)
                # Invoke the unchanged production hasher from the actual clone,
                # not an in-test normalization or a relaxed validator.
                env = dict(os.environ, PYTHONPATH='', PYTHONDONTWRITEBYTECODE='1')
                observed = subprocess.run([sys.executable, '-c',
                    'from hepta.pipeline import compiler_hash; print(compiler_hash())'],
                    cwd=checkout, env=env, capture_output=True, text=True, timeout=30)
                self.assertEqual(observed.returncode, 0, observed.stderr)
                if with_lf_rule:
                    self.assertEqual(observed.stdout.strip(), expected_hash.hexdigest())
                else:
                    self.assertTrue(changed, 'negative control must actually convert source bytes')
                    self.assertNotEqual(observed.stdout.strip(), expected_hash.hexdigest())
                self.assertEqual(git(checkout, 'status', '--porcelain'), b'')


if __name__ == '__main__':
    unittest.main()
