"""Sealed Journal transport, terminal and role controls beyond the frozen caller suite."""
from __future__ import annotations

import json
import os
from pathlib import Path
import struct
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_agent_journal_native import (
    ALIAS, ATOMIC, CONTINUE, HEADER_OFFSET, PRIVATE_BYTES, TOOLS,
)
from hepta.hia_agent_service import HIAAgentService
from tests import test_hia_agent_journal_native as original

ROOT, COLD = original.ROOT, original.COLD
independent_wire, rows = original.independent_wire, original.rows


class JournalExtensionSourceTests(unittest.TestCase):

    def test_sealed_journal_refuses_a_truncated_or_overlong_reply(self):
        from hepta.hia_agent_journal_native import JOURNAL_REPLY, STATE_BYTES, _standalone_journal

        state = bytes(STATE_BYTES)
        accepted = JOURNAL_REPLY.pack(b'HIAJOU01', 1, 0, 0, STATE_BYTES, 0) + state
        for stdout in (accepted[:-1], accepted + b'\0',
                       JOURNAL_REPLY.pack(b'HIAJOU01', 1, 0, 0, STATE_BYTES, 1) + state + b'a'):
            with self.subTest(length=len(stdout)), patch(
                    'hepta.hia_agent_journal_native.subprocess.run',
                    return_value=SimpleNamespace(returncode=0, stdout=stdout, stderr=b'')):
                with self.assertRaisesRegex(RuntimeError, 'invalid sealed HIA journal frame'):
                    _standalone_journal(b'program', 0, b'input', state)

    def test_transport_rejects_bad_reply_extents_without_publishing_a_header(self):
        from hepta.hia_agent_assembly import assemble_program
        from hepta.hia_program_runtime import _Machine, _Owner, _View
        from tools.generate_hia_agent_journal_transport import SOURCE as TRANSPORT_SOURCE

        program = assemble_program((ROOT / TRANSPORT_SOURCE).read_bytes())
        data = _Owner(-1, bytearray(HEADER_OFFSET + 512 + PRIVATE_BYTES + 64))
        output = _Owner(-2, bytearray(b'\xa5' * 48))
        control = _Owner(-3, bytearray(struct.pack('<3Q', 16, 1, 3)))
        arguments = [_View(data, False), _View(output, True), _View(control, True)]
        arena = HEADER_OFFSET + 512 + 32
        for extent in (63, 65, 64):
            struct.pack_into('<Q', data.data, arena, extent)
            machine = _Machine(program, 1_000_000, 64 << 20, None, 128)
            result = machine.invoke(program.as_dict()['functions'][0], arguments)[0]
            if extent == 64:
                self.assertEqual((result, bytes(output.data)),
                                 (1, struct.pack('<8s5Q', b'HIAJOU01', 1, 0, 0, 512, 64)))
            else:
                self.assertEqual((result, bytes(output.data)), (4294967293, b'\xa5' * 48))

    def test_transport_packer_binds_two_separate_images(self):
        from tools.generate_hia_journal_stdio_packer import MAGIC, SOURCE as PACKER, render, template
        from tools.qualify_hia_selfhost_cli import inspect_executable
        from tests.test_hia_core_workspace_facts_native import vm_run

        source = ROOT / PACKER
        self.assertEqual(source.read_text(), render())
        prefix, (first, second) = template()
        journal, codec = b'journal-transitions', b'frame-policy'
        packet = struct.pack('<3Q', MAGIC, len(journal), len(codec)) + journal + codec
        size = len(prefix) + len(journal) + len(codec)
        count, executable = vm_run(source, packet, size, 0)
        self.assertEqual(count, size)
        self.assertEqual(inspect_executable(executable)['bytes'], size)
        self.assertEqual(executable[len(prefix):], journal + codec)
        for displacement, expected in ((first, len(prefix)), (second, len(prefix) + len(journal))):
            self.assertEqual(displacement + 4 + struct.unpack_from('<i', executable, displacement)[0],
                             expected)
        self.assertEqual(vm_run(source, packet, size - 1, 0), (0xfffffffe, b'\xa5' * (size - 1)))
        self.assertEqual(vm_run(source, packet[:-1], size, 0), (0xffffffff, b'\xa5' * size))

    def test_transport_source_is_exact(self):
        from tools.generate_hia_agent_journal_transport import (
            SOURCE, document, transport_program,
        )

        expected_transport = render_assembly(document(transport_program(), 'agent_journal_transport'))
        self.assertEqual((ROOT / SOURCE).read_text(), expected_transport)

class JournalExtensionNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        original.JournalNativeTests.setUpClass.__func__(cls)
        selected_cold = os.environ.get(COLD)
        cls.cold = Path(selected_cold) if selected_cold else None
        if cls.cold is not None:
            report = json.loads(cls.cold.read_bytes())
            nested = json.loads(Path(report['nested_report']).read_bytes())
            cls.compiler = Path(nested['generations'][-1]['produced_image'])

    @classmethod
    def tearDownClass(cls):
        original.JournalNativeTests.tearDownClass.__func__(cls)

    setUp = original.JournalNativeTests.setUp
    selected = original.JournalNativeTests.selected

    def test_completion_envelope_binds_the_original_result_before_validation(self):
        from hepta.hia_agent_contract import VERSION

        session = self.image.session()
        result = {'z': None, 'a': [-0.0, '雪']}
        with self.assertRaisesRegex(RuntimeError, 'response envelope'):
            session.completed(result)
        self.assertEqual(session.prepare(independent_wire({'tool': 'hia_describe', 'arguments': {}})).action,
                         CONTINUE)
        with self.assertRaisesRegex(RuntimeError, 'response envelope'):
            session.completed(result)
        self.assertEqual(session.effect().action, CONTINUE)
        with patch('hepta.hia_agent_journal_native.wire', side_effect=AssertionError('result serialized early')):
            response = session.completed(result)
        self.assertEqual(tuple(response), ('contract_version', 'request_id', 'status', 'result'))
        self.assertEqual(response, {'contract_version': VERSION, 'request_id': session.request_id,
                                    'status': 'completed', 'result': result})
        self.assertIs(response['result'], result)
        self.assertEqual(session.finish(response).response, independent_wire(response))

    def test_rejected_envelope_uses_admitted_identity_or_pre_admission_nonce(self):
        from hepta.hia_agent_contract import VERSION

        session = self.image.session()
        details = {'message': '雪'}
        pending = 'unadmitted-' + '5a' * 16
        for wrong in ('r-' + '5a' * 32, pending[:-1], pending[:-1] + 'G'):
            with self.assertRaisesRegex(RuntimeError, 'response envelope'):
                session.rejected(wrong, details)
        before = session.rejected(pending, details)
        session.prepare(independent_wire({'tool': 'unknown', 'arguments': {}}))
        after = session.rejected(pending, details)
        for response, identity in ((before, pending), (after, session.request_id)):
            self.assertEqual(tuple(response), ('contract_version', 'request_id', 'status', 'error'))
            self.assertEqual(response, {'contract_version': VERSION, 'request_id': identity,
                                        'status': 'rejected', 'error': details})
            self.assertIs(response['error'], details)
        self.assertNotEqual(before['request_id'], after['request_id'])

        with self.selected():
            service = HIAAgentService(self.case / 'selected-rejection')
            self.addCleanup(service.close)
            with patch.object(service, '_error', side_effect=AssertionError('host envelope used')):
                invalid = service.call('unknown', {})
                unserializable = service.call('hia_describe', {'set'})
            self.assertEqual(invalid['error']['code'], 'E_HIA_TOOL')
            self.assertTrue(invalid['request_id'].startswith('r-'))
            self.assertEqual(unserializable['error']['code'], 'E_HIA_REJECTED')
            self.assertTrue(unserializable['request_id'].startswith('unadmitted-'))

    def _session_executable(self):
        executable = os.environ.get('HEPTA_HIA_AGENT_JOURNAL_DEVELOPMENT_EXECUTABLE')
        if executable is not None and self.cold is not None:
            self.fail('development executable cannot override a requested cold report')
        if executable is None:
            if self.cold is None:
                self.skipTest('requires the journal executable or a matching cold report')
            from tools.build_hia_agent_read_page import build
            executable = build(self.case / 'transport', self.compiler, self.cold, self.manifest, kind='journal')
        binary = Path(executable).read_bytes()
        self.assertTrue(self.image.matches_standalone(binary))
        return binary

    def test_one_journal_process_holds_admitted_state_and_refuses_replayed_frames(self):
        from hepta.hia_agent_journal_native import _JournalProcess, _standalone_journal, STATE_BYTES

        binary = self._session_executable()
        raw = independent_wire({'tool': 'hia_adopt', 'arguments': {'request_key': 'sealed-session'}})
        process = _JournalProcess(binary)
        self.addCleanup(process.close, check=False)
        pid = process.process.pid
        state = bytes(STATE_BYTES)
        catalog = (ROOT / 'docs/HIA_AGENT_NATIVE_TOOL_CATALOG.json').read_bytes()
        for stage, observed in ((9, catalog), (0, raw), (7, b''), (1, b'null'), (2, b''), (5, b'')):
            expected = _standalone_journal(binary, stage, observed, state)
            self.assertEqual(process.step(stage, observed, b'', data_profile=False), expected)
            self.assertEqual(process.process.pid, pid)
            if expected[0] < 1 << 31:
                state = expected[3]
        self.assertEqual(expected[0], ATOMIC)

        process.sequence -= 1
        with self.assertRaisesRegex(RuntimeError, 'stopped before replying'):
            process.step(7, b'', b'', data_profile=False)
        self.assertEqual(process.process.wait(timeout=5), 2)

    def test_journal_session_rejects_unsealed_observation_before_hia(self):
        import socket
        from hepta.hia_agent_journal_native import JOURNAL_FRAME, _JournalProcess, _journal_scratch

        process = _JournalProcess(self._session_executable())
        self.addCleanup(process.close, check=False)
        raw = independent_wire({'tool': 'hia_describe', 'arguments': {}})
        frame = JOURNAL_FRAME.pack(
            b'HIAJIN02', len(raw), _journal_scratch(0, raw, b''), 0, 4300, 0, 0, 1)
        fd = os.memfd_create('journal-unsealed', os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC)
        with os.fdopen(fd, 'wb', buffering=0) as stream:
            stream.write(frame + raw)
            process.control.sendmsg([b'J'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, struct.pack('@i', fd))])
        self.assertEqual(process.process.communicate(timeout=5), (b'', None))
        self.assertEqual(process.process.returncode, 2)

    def test_native_post_schema_tool_admission_preserves_order_and_context_effects(self):
        from hepta.hia_agent_store import AgentRejected

        installed = {'worker_sha256': 'a' * 64, 'catalog_sha256': 'b' * 64}
        stale = {**installed, 'worker_sha256': 'c' * 64}
        for tool in TOOLS:
            with self.subTest(tool=tool):
                session = self.image.session()
                with self.assertRaises(RuntimeError):
                    session.admit_catalog('b' * 64, 'b' * 64)
                prepared = session.prepare(independent_wire({'tool': tool, 'arguments': {}}))
                if prepared.action == ALIAS:
                    session.aliased()
                else:
                    self.assertEqual(prepared.action, CONTINUE)
                if tool == 'hia_describe':
                    session.admit_catalog(None, 'b' * 64)
                else:
                    with self.assertRaises(AgentRejected) as raised:
                        session.admit_catalog('c' * 64, 'b' * 64)
                    self.assertEqual(raised.exception.code, 'E_HIA_CATALOG_STALE')
                    session.admit_catalog('b' * 64, 'b' * 64)
                with self.assertRaises(AgentRejected) as raised:
                    session.plan_context(stale, installed, True)
                self.assertEqual(raised.exception.code, 'E_HIA_IMPLEMENTATION_STALE')
                self.assertEqual(session.plan_context(installed, installed, False), 0)
                expected = {'hia_inspect': 1, 'hia_rollback': 1, 'hia_candidate': 3}.get(tool, 2)
                self.assertEqual(session.plan_context(dict(reversed(installed.items())), installed, True),
                                 expected)
                effect = session.effect()
                self.assertEqual(effect.action, ATOMIC if tool in {'hia_adopt', 'hia_rollback'} else CONTINUE)
                self.assertEqual(effect.effect_role, 3 if tool == 'hia_resource_read' else TOOLS.index(tool) + 1)

    def test_native_terminal_ack_cannot_journal_a_rolled_back_success(self):
        from hepta.hia_agent_journal_native import JournalSession
        import itertools
        for operation, after, exception in itertools.product(
                ('completed',), (False, True),
                (RuntimeError, KeyboardInterrupt, SystemExit, MemoryError)):
                with self.subTest(operation=operation, after=after, exception=exception.__name__), self.selected():
                    service = HIAAgentService(self.case / ('ack-%s-%s-%s' % (operation, after, exception.__name__)))
                    self.addCleanup(service.close)
                    service.store.db.execute('CREATE TABLE effect_probe (value TEXT)')
                    def effect(_args):
                        service.store.db.execute("INSERT INTO effect_probe VALUES ('effect')")
                        return {'effect': 'would-have-committed'}
                    original = getattr(JournalSession, operation)
                    def fail(session, *args):
                        if after:
                            original(session, *args)
                        raise exception('injected native protocol acknowledgement failure')
                    args = {'catalog_sha256': service.catalog_sha256, 'request_key': 'native-ack'}
                    with patch('hepta.hia_agent_service.validate', return_value=None), \
                            patch.object(service, '_hia_adopt', side_effect=effect), \
                            patch.object(JournalSession, operation, fail):
                        with self.assertRaisesRegex(exception, 'acknowledgement failure'):
                            service.call('hia_adopt', args)
                    state = rows(service)
                    self.assertEqual(list(service.store.db.execute('SELECT * FROM effect_probe')), [])
                    self.assertEqual(state['costs'], [])
                    self.assertEqual(len(state['requests']), 1)
                    self.assertEqual(state['requests'][0][3:5], ('running', None))
                    with patch.object(service, '_hia_adopt', side_effect=AssertionError('unknown effect retried')):
                        retry = service.call('hia_adopt', args)
                    self.assertEqual(retry['error']['code'], 'E_HIA_REQUEST_UNKNOWN')

    def test_native_tool_effect_role_cannot_be_substituted(self):
        original = self.image._entry
        session = self.image.session()
        session.prepare(b'{"tool":"hia_describe","arguments":{}}')

        def substitute_effect(source, source_size, output, output_size, scratch, scratch_size):
            result = original(source, source_size, output, output_size, scratch, scratch_size)
            struct.pack_into('<Q', output, HEADER_OFFSET + 328, 2)
            return result

        with patch.object(self.image, '_entry', substitute_effect):
            with self.assertRaisesRegex(RuntimeError, 'invalid native journal tool effect'):
                session.effect()
