"""Physical HIA suffixes and whole-program admission, with immutable history."""
from contextlib import contextmanager
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from tools.check_hia_core_only import ROOT, check


@contextmanager
def source_tree():
    with tempfile.TemporaryDirectory(prefix='hia-source-suffix-') as temporary:
        root = Path(temporary)
        for name in ('pyproject.toml', 'docs/HIA_CORE_ONLY_SCOPE.json'):
            destination = root / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, destination)
        (root / 'examples').mkdir()
        yield root


def scalar_document(version, *, composite=False):
    schema = ('hepta.hia.composite.v' if composite else 'hepta.hia.program.v') + str(version)
    document = dict(schema=schema, module='suffix_gate', functions=[
        dict(name='main', params=[], returns=['u32'], effects=[], entry='entry',
             blocks=[dict(id='entry', params=[], ops=[
                 dict(op='const', args=[], out=[dict(name='answer', type='u32')], attrs=dict(value=7))],
                 term=dict(op='ret', values=['answer']))])])
    if composite:
        document['types'] = []
    return document


def scalar_assembly(version=8):
    return (
        'hia-asm.v1 hepta.hia.program.v' + str(version) + ' suffix_gate\n'
        'fn main() -> (u32) effects() entry(entry)\n'
        'block entry()\n'
        '  answer:u32 = const() {"value":7}\n'
        '  ret(answer)\n'
        'end\n'
    ).encode()


class HiaSourceSuffixTests(unittest.TestCase):
    def test_all_current_assembly_versions_are_fully_checked_without_rewriting(self):
        with source_tree() as root:
            frozen = {}
            for version in (6, 7, 8):
                path = root / 'examples' / ('assembly_v' + str(version) + '.hepta')
                raw = scalar_assembly(version)
                path.write_bytes(raw)
                frozen[path.relative_to(root).as_posix()] = sha256(raw).hexdigest()
            result = check(root)
            self.assertEqual(result['status'], 'PASS')
            self.assertEqual(result['hia_source_suffix'], '.hepta')
            self.assertEqual(result['hia_source_files'], 3)
            self.assertEqual(result['hia_source_manifest_sha256'],
                             sha256(json.dumps(frozen, sort_keys=True).encode()).hexdigest())
            for name, digest in frozen.items():
                self.assertEqual(sha256((root / name).read_bytes()).hexdigest(), digest)

    def test_all_primitive_and_composite_json_versions_remain_supported(self):
        with source_tree() as root:
            for composite, versions in ((False, range(1, 9)), (True, range(1, 5))):
                for version in versions:
                    name = ('composite' if composite else 'primitive') + str(version) + '.hepta'
                    (root / 'examples' / name).write_text(json.dumps(
                        scalar_document(version, composite=composite)))
            result = check(root)
            self.assertEqual(result['status'], 'PASS')
            self.assertEqual(result['hia_source_files'], 12)

    def test_legacy_and_noncanonical_case_suffixes_are_refused_as_real_files(self):
        with source_tree() as root:
            for suffix in ('.hia', '.HIA', '.hiaasm', '.HiaAsm', '.hia.json', '.HIA.JSON',
                           '.HEPTA', '.Hepta'):
                path = root / 'examples' / ('source' + suffix)
                path.write_bytes(scalar_assembly())
                with self.subTest(suffix=suffix), self.assertRaisesRegex(ValueError, 'HIA source suffix'):
                    check(root)
                path.unlink()

    def test_canonical_suffix_does_not_admit_header_only_receipts_or_removed_source(self):
        # Runtime concatenation keeps this a used negative case rather than a
        # retained source-language fixture in the authored Core-only tree.
        removed = 'module retired;' + '\n' + 'export "C" ' + 'fn gone() -> u32 { return 1; }'
        cases = (
            b'hia-asm.v1 hepta.hia.program.v8 header_only\n',
            b'{"schema":"hepta.hia.program.v8","status":"PASS"}',
            b'{"schema":',
            b'\xff' + scalar_assembly(),
            removed.encode(),
        )
        with source_tree() as root:
            path = root / 'examples' / 'invalid.hepta'
            for index, raw in enumerate(cases):
                path.write_bytes(raw)
                with self.subTest(case=index), self.assertRaisesRegex(ValueError, 'invalid HIA source content'):
                    check(root)
                self.assertEqual(path.read_bytes(), raw)

    def test_valid_syntax_still_reaches_full_ssa_and_nominal_type_verification(self):
        bad_primitive = scalar_document(8)
        bad_primitive['functions'][0]['blocks'][0]['term']['values'] = ['missing']
        bad_nominal = scalar_document(4, composite=True)
        bad_nominal['functions'][0]['returns'] = ['MissingType']
        cases = (
            scalar_assembly().replace(b'ret(answer)', b'ret(missing)'),
            json.dumps(bad_primitive).encode(),
            json.dumps(bad_nominal).encode(),
        )
        with source_tree() as root:
            path = root / 'examples' / 'invalid.hepta'
            for index, raw in enumerate(cases):
                path.write_bytes(raw)
                with self.subTest(case=index), self.assertRaisesRegex(ValueError, 'invalid HIA source content') as caught:
                    check(root)
                self.assertRegex(str(caught.exception), 'E_HIA_(SSA|TYPE)')
                self.assertEqual(path.read_bytes(), raw)

    def test_historical_receipt_paths_and_hashes_remain_byte_identical(self):
        with source_tree() as root:
            historical = root / 'docs' / 'historical-receipt.json'
            record = {
                'schema': 'hepta.hia.program.v8',
                'original_sources': {
                    'examples/old.hiaasm': 'a' * 64,
                    'examples/old.HIA': 'b' * 64,
                    'examples/old.hia.json': 'c' * 64,
                },
                'status': 'HISTORICAL_RECORD_ONLY',
            }
            raw = json.dumps(record, indent=2, sort_keys=True).encode() + b'\n'
            historical.write_bytes(raw)
            note = root / 'docs' / 'HISTORY.md'
            note_bytes = b'Archived paths: old.hiaasm, old.HIA, old.hia.json.\n'
            note.write_bytes(note_bytes)
            (root / 'examples' / 'current.hepta').write_bytes(scalar_assembly())
            result = check(root)
            self.assertEqual(result['status'], 'PASS')
            self.assertEqual(result['hia_source_files'], 1)
            self.assertEqual(historical.read_bytes(), raw)
            self.assertEqual(sha256(historical.read_bytes()).hexdigest(), sha256(raw).hexdigest())
            self.assertEqual(note.read_bytes(), note_bytes)

    def test_canonical_source_must_be_an_actual_regular_file(self):
        with source_tree() as root:
            target = root / 'examples' / 'target.txt'
            target.write_bytes(scalar_assembly())
            link = root / 'examples' / 'linked.hepta'
            link.symlink_to(target)
            with self.assertRaisesRegex(ValueError, 'regular non-symlink file'):
                check(root)
            link.unlink()
            directory = root / 'examples' / 'directory.hepta'
            directory.mkdir()
            with self.assertRaisesRegex(ValueError, 'regular non-symlink file'):
                check(root)


if __name__ == '__main__':
    unittest.main()
