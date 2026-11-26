"""Native admission authoring refuses incomplete or foreign source custody."""
from hashlib import sha256
from pathlib import Path
import json
import tempfile
import unittest

from tools.generate_hia_source_release_cold_admit import (
    CONTRACT_PATH, NATIVE_METADATA, native_authority_contract,
)
from tools.hia_native_worker_source_authority import SCHEMA


class NativeColdAdmissionAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.authority = self.root / 'authority.json'
        self.source = 'examples/hia_bootstrap/actual.hepta'
        self.metadata = {
            'profile': 'retained-profile',
            'claims': {'whole_HIA_language_self_hosted': False},
            'qualification': {'phase_count': 60, 'seconds': 180, 'cleanup_seconds': 3},
            'source_identity': {'files': {}, 'policy': 'exact current capture'},
        }
        self.write(CONTRACT_PATH, b'{}\n')
        self.write(NATIVE_METADATA, json.dumps(self.metadata).encode())
        self.write(self.source, b'actual HIA source\n')
        self.paths = sorted((CONTRACT_PATH, NATIVE_METADATA, self.source))
        self.catalog()

    def write(self, path, raw):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)

    def catalog(self):
        self.authority.write_text(json.dumps({'schema': SCHEMA, 'paths': self.paths}))

    def contract(self):
        return native_authority_contract(self.root, self.authority)

    def test_actual_pins_and_retained_metadata_without_recursive_self_pin(self):
        result = self.contract()
        pins = result['source_identity'].pop('files')
        result['source_identity']['files'] = {}
        self.assertEqual(result, self.metadata)
        self.assertNotIn(CONTRACT_PATH, pins)
        self.assertEqual(pins[self.source], sha256((self.root / self.source).read_bytes()).hexdigest())
        self.write(self.source, b'changed actual HIA source\n')
        self.assertNotEqual(self.contract()['source_identity']['files'][self.source], pins[self.source])

    def test_missing_source_is_refused(self):
        (self.root / self.source).unlink()
        with self.assertRaisesRegex(ValueError, 'missing'):
            self.contract()

    def test_host_language_catalog_entry_is_refused(self):
        self.paths.append('tools/hosted.py')
        self.paths.sort()
        self.catalog()
        with self.assertRaisesRegex(ValueError, 'invalid native source authority path'):
            self.contract()

    def test_source_symlink_is_refused_even_inside_root(self):
        target = self.root / self.source
        target.unlink()
        target.symlink_to(self.root / CONTRACT_PATH)
        with self.assertRaisesRegex(ValueError, 'symlink'):
            self.contract()

    def test_required_contract_and_metadata_are_not_optional(self):
        for omitted in (CONTRACT_PATH, NATIVE_METADATA):
            with self.subTest(omitted=omitted):
                self.paths = sorted({CONTRACT_PATH, NATIVE_METADATA, self.source} - {omitted})
                self.catalog()
                with self.assertRaisesRegex(ValueError, 'frozen contract and native metadata'):
                    self.contract()

    def test_embedded_stale_source_map_is_refused(self):
        self.metadata['source_identity']['files'] = {'old.py': '0' * 64}
        self.write(NATIVE_METADATA, json.dumps(self.metadata).encode())
        with self.assertRaisesRegex(ValueError, 'empty source_identity.files'):
            self.contract()

    def test_duplicate_metadata_key_is_refused(self):
        self.write(NATIVE_METADATA, b'{"source_identity":{"files":{}},"source_identity":{"files":{}}}')
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            self.contract()


if __name__ == '__main__':
    unittest.main()
