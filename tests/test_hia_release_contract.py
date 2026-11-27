"""Native release identity must not fall back to the hosted seed domain."""
from hashlib import sha256
from pathlib import Path
import copy
import json
import tempfile
import unittest
from unittest.mock import patch

from tools.generate_hia_selfhost_contract import write_hosted_contract
from tools.hia_native_worker_source_authority import SCHEMA
from tools.hia_release import describe
from tools.hia_release_contract import (
    CONTRACT_PATH, HOSTED_SEED, NATIVE_AUTHORITY, source_domain,
    validate_release_contract,
)

METADATA = 'docs/HIA_NATIVE_SELFHOST_METADATA.json'
SOURCE = 'examples/hia_bootstrap/current.hepta'


class NativeReleaseContractTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='hia-native-contract-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.paths = sorted((CONTRACT_PATH, METADATA, NATIVE_AUTHORITY, SOURCE))
        self.metadata = {
            'schema': 'hepta.hia.selfhost-core-support.v1',
            'profile': 'native-test-profile',
            'claims': {'whole_HIA_language_self_hosted': False},
            'source_identity': {
                'roles': {'authoring_authority': NATIVE_AUTHORITY},
                'files': {},
            },
        }
        self.write(SOURCE, b'current native source\n')
        self.write_json(METADATA, self.metadata)
        self.write_json(NATIVE_AUTHORITY, {'schema': SCHEMA, 'paths': self.paths})
        self.contract = copy.deepcopy(self.metadata)
        self.contract['source_identity']['files'] = {
            name: sha256((self.root / name).read_bytes()).hexdigest()
            for name in self.paths if name != CONTRACT_PATH
        }
        self.write_json(CONTRACT_PATH, self.contract)

    def write(self, name, raw):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)

    def write_json(self, name, value):
        self.write(name, json.dumps(value, sort_keys=True).encode() + b'\n')

    def test_exact_native_contract_has_no_hosted_seed_requirement(self):
        with patch('tools.hia_release_contract.support_contract',
                   side_effect=AssertionError('native validation invoked the hosted seed')):
            self.assertEqual(validate_release_contract(self.root), self.contract)
            value = describe(self.root)
        self.assertEqual(value['source_contract_domain'], 'native')
        self.assertFalse(value['host_build_requires_python'])
        self.assertFalse(value['whole_native_delivery_qualified'])
        self.assertFalse(value['production_activated'])

    def test_changed_source_or_metadata_cannot_reuse_the_contract(self):
        for name in (SOURCE, METADATA):
            with self.subTest(name=name):
                original = (self.root / name).read_bytes()
                self.write(name, original + b'\n')
                with self.assertRaisesRegex(ValueError, 'current source closure'):
                    validate_release_contract(self.root)
                self.write(name, original)

    def test_broadened_claim_or_extra_pin_is_refused(self):
        changed = copy.deepcopy(self.contract)
        changed['claims']['whole_HIA_language_self_hosted'] = True
        self.write_json(CONTRACT_PATH, changed)
        with self.assertRaisesRegex(ValueError, 'current source closure'):
            validate_release_contract(self.root)
        changed = copy.deepcopy(self.contract)
        changed['source_identity']['files']['old.py'] = '0' * 64
        self.write_json(CONTRACT_PATH, changed)
        with self.assertRaisesRegex(ValueError, 'current source closure'):
            validate_release_contract(self.root)

    def test_missing_source_never_falls_back_to_hosted_validation(self):
        (self.root / SOURCE).unlink()
        with patch('tools.hia_release_contract.support_contract',
                   side_effect=AssertionError('native failure fell back to hosted')):
            with self.assertRaisesRegex(ValueError, 'missing'):
                validate_release_contract(self.root)

    def test_unpinned_authority_is_refused(self):
        self.write_json(NATIVE_AUTHORITY, {
            'schema': SCHEMA, 'paths': [p for p in self.paths if p != NATIVE_AUTHORITY],
        })
        with self.assertRaisesRegex(ValueError, 'capture its authority'):
            validate_release_contract(self.root)

    def test_duplicate_contract_field_is_refused(self):
        raw = (self.root / CONTRACT_PATH).read_bytes().rstrip()
        self.write(CONTRACT_PATH, raw[:-1] + b',"profile":"duplicate"}')
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            validate_release_contract(self.root)

    def test_symlink_contract_is_refused_even_with_equal_bytes(self):
        original = (self.root / CONTRACT_PATH).read_bytes()
        self.write('elsewhere.json', original)
        (self.root / CONTRACT_PATH).unlink()
        (self.root / CONTRACT_PATH).symlink_to(self.root / 'elsewhere.json')
        with self.assertRaisesRegex(ValueError, 'symlink'):
            validate_release_contract(self.root)

    def test_hosted_generator_cannot_overwrite_native_contract(self):
        original = (self.root / CONTRACT_PATH).read_bytes()
        with patch('tools.generate_hia_selfhost_contract.support_contract',
                   side_effect=AssertionError('hosted generator was invoked')):
            with self.assertRaisesRegex(ValueError, 'must not overwrite'):
                write_hosted_contract(self.root)
        self.assertEqual((self.root / CONTRACT_PATH).read_bytes(), original)

    def test_unknown_domain_is_refused(self):
        for contract in ({}, {'source_identity': []},
                         {'source_identity': {'roles': {'authoring_authority': 'old.json'}}}):
            with self.subTest(contract=contract), self.assertRaises(ValueError):
                source_domain(contract)

    def test_explicit_hosted_domain_retains_complete_equality_check(self):
        hosted = {'source_identity': {'roles': {'seed_entry': HOSTED_SEED}, 'files': {}}}
        self.write_json(CONTRACT_PATH, hosted)
        with patch('tools.hia_release_contract.support_contract', return_value=hosted) as expected:
            self.assertEqual(validate_release_contract(self.root), hosted)
            expected.assert_called_once_with(self.root)
        changed = copy.deepcopy(hosted)
        changed['source_identity']['files']['source.py'] = '0' * 64
        with patch('tools.hia_release_contract.support_contract', return_value=changed):
            with self.assertRaisesRegex(ValueError, 'current source closure'):
                validate_release_contract(self.root)


    def test_public_contract_api_uses_native_authority_and_refuses_changed_source(self):
        from tools.hia_selfhost_contract import validate_contract
        with patch('tools.hia_selfhost_contract.support_contract',
                   side_effect=AssertionError('public native validation used hosted closure')), \
                patch('tools.hia_release_contract.support_contract',
                      side_effect=AssertionError('native validation fell back to hosted')):
            self.assertEqual(validate_contract(self.root), self.contract)
            self.write(SOURCE, b'changed native source\\n')
            with self.assertRaisesRegex(ValueError, 'current source closure'):
                validate_contract(self.root)
            (self.root / SOURCE).unlink()
            with self.assertRaisesRegex(ValueError, 'missing'):
                validate_contract(self.root)

    def test_public_contract_api_preserves_complete_hosted_equality(self):
        from tools.hia_selfhost_contract import validate_contract
        hosted = {'source_identity': {'roles': {'seed_entry': HOSTED_SEED}, 'files': {}}}
        self.write_json(CONTRACT_PATH, hosted)
        with patch('tools.hia_release_contract.support_contract', return_value=hosted) as expected:
            self.assertEqual(validate_contract(self.root), hosted)
            expected.assert_called_once_with(self.root)
        changed = copy.deepcopy(hosted)
        changed['source_identity']['files']['source.py'] = '0' * 64
        with patch('tools.hia_release_contract.support_contract', return_value=changed):
            with self.assertRaisesRegex(ValueError, 'current source closure'):
                validate_contract(self.root)

    def test_public_contract_api_rejects_unknown_domain_and_duplicate_fields(self):
        from tools.hia_selfhost_contract import validate_contract
        self.write_json(CONTRACT_PATH, {'source_identity': {'roles': {'authoring_authority': 'old.json'}}})
        with self.assertRaisesRegex(ValueError, 'unrecognized'):
            validate_contract(self.root)
        raw = json.dumps(self.contract).encode()
        self.write(CONTRACT_PATH, raw[:-1] + b',"profile":"duplicate"}')
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            validate_contract(self.root)


if __name__ == '__main__':
    unittest.main()
