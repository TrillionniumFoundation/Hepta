"""Explicit optional Core checking and complete original portable resources."""
import json
import unittest
from unittest import mock

from hepta.hia_agent_assembly import assemble_program
from hepta.hia_program import verify_program
from hepta.hia_linux_file_roundtrip import PROFILE
from tests.test_hia_source_suffix import source_tree
from tools.check_hia_core_only import (
    ROOT, EXPLICIT_SOURCE_PROFILES, OPTIONAL_SOURCE_PROFILES, check,
)


ROUNDTRIP_SOURCE = 'examples/hia_bootstrap/native_file_roundtrip.hepta'


class RoundtripSourceRoleTests(unittest.TestCase):
    def test_optional_roundtrip_role_is_exact_and_both_formats_are_fully_checked(self):
        from hepta.hia_optional_profiles import OPTIONAL_PROFILE_FILES
        self.assertEqual(OPTIONAL_SOURCE_PROFILES, {ROUNDTRIP_SOURCE: PROFILE})
        self.assertTrue(set(OPTIONAL_SOURCE_PROFILES).isdisjoint(EXPLICIT_SOURCE_PROFILES))
        self.assertIn(ROUNDTRIP_SOURCE, OPTIONAL_PROFILE_FILES[PROFILE])
        raw = (ROOT / ROUNDTRIP_SOURCE).read_bytes()
        with self.assertRaises(ValueError):
            assemble_program(raw)
        structured = assemble_program(raw, profile=PROFILE).canonical_bytes
        with self.assertRaises(ValueError):
            verify_program(structured)
        with source_tree() as root:
            target = root / ROUNDTRIP_SOURCE
            target.parent.mkdir(parents=True, exist_ok=True)
            for content, target_function, original in (
                    (raw, 'hepta.hia_agent_assembly.assemble_program', assemble_program),
                    (structured, 'hepta.hia_program.verify_program', verify_program)):
                with self.subTest(format=content[:1]):
                    target.write_bytes(content)
                    with mock.patch(target_function, wraps=original) as calls:
                        report = check(root)
                    self.assertEqual(report['status'], 'PASS')
                    self.assertEqual(report['hia_source_files'], 1)
                    self.assertEqual([call.args for call in calls.call_args_list], [(content,)])
                    self.assertEqual([call.kwargs for call in calls.call_args_list], [{'profile': PROFILE}])
                    self.assertEqual(target.read_bytes(), content)

    def test_optional_roundtrip_role_refuses_invalid_effects_and_unregistered_paths(self):
        raw = (ROOT / ROUNDTRIP_SOURCE).read_bytes()
        structured = assemble_program(raw, profile=PROFILE).canonical_bytes
        with source_tree() as root:
            target = root / ROUNDTRIP_SOURCE
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
            unregistered = root / 'examples/unregistered_roundtrip.hepta'
            for content in (raw, structured):
                with self.subTest(unregistered_format=content[:1]):
                    unregistered.write_bytes(content)
                    with self.assertRaisesRegex(ValueError, 'invalid HIA source content: examples/unregistered_roundtrip'):
                        check(root)
                    self.assertEqual(unregistered.read_bytes(), content)
                    unregistered.unlink()
            for bad_effect in ('unreviewed_roundtrip_effect', 'linux_roundtrip'):
                with self.subTest(effect=bad_effect):
                    broken = json.loads(structured)
                    self.assertIn('linux_roundtrip', broken['functions'][0]['effects'])
                    broken['functions'][0]['effects'].append(bad_effect)
                    content = json.dumps(broken).encode()
                    target.write_bytes(content)
                    with self.assertRaisesRegex(ValueError, 'invalid HIA source content: .*E_HIA_EFFECT'):
                        check(root)
                    self.assertEqual(target.read_bytes(), content)

    def test_portable_default_resources_use_all_original_roles_in_order(self):
        from hepta import hia_agent_contract as contract
        from tests.hia_linux_file_roundtrip_portable import default_resources
        from tests.test_hia_agent_installed_resources import RESOURCES
        names = (
            'DISCOVERY_FILES', 'NATIVE_SOURCE_FILES', 'SOURCE_BUILD_FILES',
            'COMPILER_BUILD_FILES', 'PUBLICATION_BUILD_FILES', 'BACKEND_BUILD_FILES',
            'EMITTER_BUILD_FILES', 'BYTE_WRAPPER_BUILD_FILES', 'MACHINE_OBJECT_BUILD_FILES',
            'EXECUTION_OBSERVATION_BUILD_FILES', 'CONTINUATION_BUILD_FILES', 'ENTRY_BUILD_FILES',
        )
        expected = tuple('docs/' + name for name in contract.DISCOVERY_FILES)
        for name in names[1:]:
            expected += getattr(contract, name)
        self.assertEqual(len(expected), len(set(expected)))
        self.assertEqual(len(expected), 210)
        self.assertEqual(default_resources(), expected)
        self.assertEqual(default_resources(), RESOURCES)
        for name in names:
            original = getattr(contract, name)
            self.assertTrue(original)
            replacement = original[:-1] + ('unregistered-roundtrip-resource',)
            with self.subTest(role=name), mock.patch.object(contract, name, replacement):
                with self.assertRaisesRegex(ValueError, 'explicit whole-package resource roles differ'):
                    default_resources()


if __name__ == '__main__':
    unittest.main()
