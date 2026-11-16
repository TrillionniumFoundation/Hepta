"""Custody diagnostics and nonexecuting publisher fixture integration.

Fresh children exercise representation state only. Original native installed
worker controls remain responsible for actual delivery qualification.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
_CHILD = r'''
import importlib.util
import json
import sys
import traceback

spec = importlib.util.spec_from_file_location('retirement_chain_control', sys.argv[1])
delivery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(delivery)
mode = sys.argv[2]

class Resource:
    pass

class StoreArtifactProfileUnknown(RuntimeError):
    pass

resource = Resource()
record = delivery.DeliveryRecord(object())
record.associate(resource)
origin = ValueError('original delivery observation failed')
record.enter_native()
assert record.failed(origin)
assert record.loss is record and record.error is origin
resources = tuple(record.resources)
wrapper = StoreArtifactProfileUnknown('original transport classification')
unrelated = LookupError('unrelated outer handler')
try:
    if mode == 'no_active':
        delivery.check_resource_retirement(resource)
    elif mode == 'cleanup':
        try:
            try:
                raise origin
            except ValueError as error:
                raise wrapper from error
        finally:
            delivery.check_resource_retirement(resource)
    elif mode == 'unrelated':
        try:
            raise unrelated
        except LookupError:
            delivery.check_resource_retirement(resource)
    else:
        raise AssertionError(mode)
except delivery.NativeDeliveryUnknown as error:
    refusal = error
else:
    raise AssertionError('retained resource was allowed to retire')
assert type(refusal) is delivery.NativeDeliveryUnknown
if mode == 'no_active':
    assert refusal.__cause__ is origin and refusal.__context__ is None
    assert refusal.__suppress_context__ is True
else:
    expected = wrapper if mode == 'cleanup' else unrelated
    assert refusal.__context__ is expected and refusal.__cause__ is None
    assert refusal.__suppress_context__ is False
    if mode == 'cleanup':
        assert wrapper.__cause__ is origin
        rendered = ''.join(traceback.format_exception(refusal))
        assert 'StoreArtifactProfileUnknown' in rendered
        assert 'original delivery observation failed' in rendered
        assert 'NativeDeliveryUnknown' in rendered
assert record.loss is record and record.error is origin
assert tuple(record.resources) == resources
assert record.resources[0][0] is resource
assert delivery._CUSTODY[id(record)] is record
assert delivery._resource_loss(resource) is record
assert not record.retired and not record.terminal
assert sys.exception() is None
try:
    delivery.check_resource_retirement(resource)
except delivery.NativeDeliveryUnknown as later:
    assert later.__cause__ is origin and later.__context__ is None
else:
    raise AssertionError('cleanup refusal discharged custody')
record.retire()
assert not record.retired and delivery._CUSTODY[id(record)] is record
print(json.dumps({'mode': mode, 'resource_refused': True,
                  'original_loss_retained': True, 'native_execution': False}))
'''


class DeliveryIntegrationSourceTests(unittest.TestCase):
    def _retirement(self, mode):
        environment = {key: value for key, value in os.environ.items()
                       if key not in ('PYTHONPATH', 'PYTHONHOME')
                       and not key.startswith('HEPTA_HIA_')}
        result = subprocess.run(
            [sys.executable, '-I', '-B', '-c', _CHILD,
             str(ROOT / 'hepta/hia_native_delivery.py'), mode],
            capture_output=True, env=environment, timeout=5, check=False)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
        self.assertEqual(result.stderr, b'')
        self.assertEqual(json.loads(result.stdout), {
            'mode': mode, 'resource_refused': True,
            'original_loss_retained': True, 'native_execution': False})

    def test_retirement_without_active_handler_keeps_actual_loss_cause(self):
        self._retirement('no_active')

    def test_retirement_during_cleanup_keeps_original_transport_chain(self):
        self._retirement('cleanup')

    def test_retirement_in_unrelated_handler_does_not_replace_custody_origin(self):
        self._retirement('unrelated')

    def test_publisher_fixture_has_two_trap_entries_and_reversible_private_header(self):
        from hepta.hia_artifact_delivery_protocol import (
            control_descriptor, private_executable, public_executable)
        from tests.test_hia_standalone_builder_source_binding import (
            _publication_descriptor_fixture)
        raw = _publication_descriptor_fixture()
        descriptor = control_descriptor(raw)
        self.assertEqual((descriptor.public_entry, descriptor.private_entry,
                          descriptor.prefix_bytes), (0x400160, 0x400164, 16))
        self.assertEqual(raw[352:], b'\x0f\x0b\0\0\x0f\x0b\0\0')
        private = private_executable(raw)
        self.assertEqual(control_descriptor(private, private=True), descriptor)
        self.assertEqual(public_executable(private), raw)
        self.assertEqual(private[:24] + private[32:], raw[:24] + raw[32:])

    def test_publisher_rejects_invalid_descriptor_even_with_bound_packer_receipt(self):
        from tests import test_hia_standalone_builder_source_binding as original
        case = original.StandaloneBuilderSourceBindingTests(
            'test_current_cold_records_complete_identity_without_native_pass_claim')
        self.addCleanup(case.doCleanups)
        case.setUp()
        case.write_report()
        pristine = original._publication_descriptor_fixture()
        changes = [('short-note', pristine[:351])]
        for label, offset, value in (
                ('ELF-magic', 0, 0), ('ELF-entry', 24, 0x400164),
                ('load-size', 96, 359), ('note-name', 244, 0),
                ('descriptor-magic', 256, 0), ('descriptor-version', 264, 2),
                ('private-equals-public', 280, 0x400160),
                ('prefix-width', 288, 15), ('ack-width', 296, 127),
                ('entry-field-offset', 312, 25), ('reserved-word', 320, 1),
                ('operations', 336, 0)):
            changed = bytearray(pristine)
            struct.pack_into('<Q', changed, offset, value)
            changes.append((label, bytes(changed)))
        for label, raw in changes:
            with self.subTest(descriptor=label):
                output = case.root / ('invalid-private-descriptor-' + label)
                with patch.object(original, '_publication_descriptor_fixture', return_value=raw):
                    with self.assertRaises(ValueError):
                        case.publication.build(output, case.compiler, case.cold)
                self.assertFalse((output / 'hia-artifact').exists())
                self.assertFalse((output / 'build.json').exists())


if __name__ == '__main__':
    unittest.main()
