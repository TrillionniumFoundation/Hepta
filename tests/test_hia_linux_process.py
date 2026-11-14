"""Public process authority, exact startup bytes and fixed syscall boundaries."""
from __future__ import annotations

import copy
from dataclasses import FrozenInstanceError
import unittest
from unittest import mock

from hepta.hia_agent_assembly import assemble_program, render_assembly
from hepta.hia_program import HIAProgramRejected, VerifiedProgram, verify_program
from hepta.hia_program_runtime import execute_program, HIAProgramTrap, HIAProgramBudgetExceeded
from hepta.hia_linux_process import (
    PROFILE, MODULE, IO_OPCODES, STARTUP_OPCODES, LinuxStartupSnapshot,
    VerifiedLinuxProcessProgram, LinuxProcessProviderRejected, LinuxProcessSignal,
)
from tests.hia_linux_process_programs import program, document


def one(operation='linux.argv.copy', args=('v1', 'v3', 'v4', 'v5', 'v6'), *,
        destination=2, index=0, source=1, count=3):
    return ('''hia-asm.v1 hepta.hia.program.v8 selfhost_linux_process
fn f0(v0:readbuf,v1:mutbuf,v2:mutbuf) -> (u32) effects(read,write,trap,linux_startup,linux_io) entry(b0)
block b0(v0:readbuf,v1:mutbuf,v2:mutbuf)
  v3:usize = const() {"value":DESTINATION}
  v4:usize = const() {"value":INDEX}
  v5:usize = const() {"value":SOURCE}
  v6:usize = const() {"value":COUNT}
  v7:RESULTTYPE = OPERATION(ARGS)
  v8:u32 = const() {"value":0}
  ret(v8)
end
'''.replace('DESTINATION', str(destination)).replace('INDEX', str(index))
        .replace('SOURCE', str(source)).replace('COUNT', str(count))
        .replace('RESULTTYPE', 'i64' if operation in IO_OPCODES else 'usize')
        .replace('OPERATION', operation).replace('ARGS', ','.join(args))).encode()


class LinuxProcessPublicSourceTests(unittest.TestCase):
    def check(self, raw=None):
        return assemble_program(one() if raw is None else raw, profile=PROFILE)

    def vm(self, checked=None, *, argv=(b'abcdef',), env=(), provider=None,
           snapshot=None, output=b'\xa5' * 16, workspace=b'\x5a' * 16, **limits):
        return execute_program(self.check() if checked is None else checked, 'f0',
            (b'read-only', output, workspace), profile=PROFILE,
            linux_process_startup=LinuxStartupSnapshot(argv, env) if snapshot is None else snapshot,
            linux_process_provider=(lambda request: self.fail('no physical I/O expected'))
                if provider is None else provider, **limits)

    def test_public_parse_verify_render_uses_distinct_rechecked_authority(self):
        checked = self.check()
        self.assertIs(type(checked), VerifiedLinuxProcessProgram)
        self.assertNotIsInstance(checked, VerifiedProgram)
        self.assertEqual(render_assembly(checked, profile=PROFILE).encode(), one())
        self.assertEqual(verify_program(checked, profile=PROFILE), checked)
        self.assertFalse(checked.report()['startup_reference_is_native_authority'])
        for profile in (None, False, 1, '', PROFILE + ' ', 'selfhost_linux_process'):
            with self.subTest(profile=profile):
                with self.assertRaises(HIAProgramRejected):
                    assemble_program(one(), profile=profile)

    def test_default_and_stdio_v1_consumers_refuse_process_program(self):
        from hepta.hia_linux_stdio import PROFILE as OLD
        from hepta.hia_program_native import emit_program_machine, compile_program_machine
        from hepta.hia_program_llvm import emit_program_llvm
        checked = self.check()
        calls = [lambda: assemble_program(one()), lambda: render_assembly(checked),
                 lambda: verify_program(checked), lambda: verify_program(checked.as_dict()),
                 lambda: execute_program(checked, 'f0', (b'', b'', b'')),
                 lambda: assemble_program(one(), profile=OLD),
                 lambda: emit_program_machine(checked), lambda: emit_program_llvm(checked),
                 lambda: compile_program_machine(checked, program=checked, output='unreachable')]
        for i, call in enumerate(calls):
            with self.subTest(i=i):
                with self.assertRaises((HIAProgramRejected, ValueError, TypeError)):
                    call()

    def test_fixed_opcode_inventory_does_not_modify_global_defaults(self):
        from hepta.hia_opcodes import OPCODES, EFFECTS
        self.assertEqual(set(IO_OPCODES), {'linux.stdin.read', 'linux.stdout.write', 'linux.stderr.write'})
        self.assertEqual(set(STARTUP_OPCODES), {f'linux.{group}.{action}'
            for group in ('argv', 'env') for action in ('count', 'length', 'copy')})
        self.assertFalse(set(IO_OPCODES) & set(OPCODES))
        self.assertFalse(set(STARTUP_OPCODES) & set(OPCODES))
        self.assertNotIn('linux_io', EFFECTS)
        self.assertNotIn('linux_startup', EFFECTS)
        with self.assertRaises(TypeError):
            IO_OPCODES['linux.any'] = next(iter(IO_OPCODES.values()))

    def test_exact_snapshot_preserves_raw_duplicates_order_and_empty(self):
        snapshot = LinuxStartupSnapshot((b'\xff', b''), (b'A=1', b'A=2', b'', b'raw\x80'))
        with self.assertRaises(FrozenInstanceError):
            snapshot.argv = ()
        source = one('linux.env.copy', count=3, source=1, index=3)
        observed = self.vm(self.check(source), snapshot=snapshot)
        self.assertEqual(bytes.fromhex(observed['output_hex']), b'\xa5\xa5aw\x80' + b'\xa5' * 11)
        self.assertEqual(observed['effects'][0]['index'], 3)
        self.assertEqual(snapshot.environment, (b'A=1', b'A=2', b'', b'raw\x80'))

    def test_snapshot_accepts_empty_vectors_and_more_than_one_MiB_total(self):
        checked = self.check(one('linux.env.count', ()))
        for snapshot, expected in ((LinuxStartupSnapshot((), ()), 0),
                (LinuxStartupSnapshot((), (b'x' * 65536,) * 17), 17)):
            result = self.vm(checked, snapshot=snapshot)
            self.assertEqual(result['effects'][0]['result'], expected)
        for bad in ({'argv': (), 'environment': ()}, LinuxStartupSnapshot([], ()),
                LinuxStartupSnapshot((bytearray(b'x'),), ()), LinuxStartupSnapshot((b'x\0y',), ()),
                LinuxStartupSnapshot((b'x',), ('decoded',))):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(HIAProgramRejected):
                    self.vm(checked, snapshot=bad)

    def test_copy_bounds_complete_before_mutation_including_zero_and_overflow(self):
        invalid = [(2, 1, 1, 1), (0, 0, 7, 0), (0, 0, 5, 2),
                   (17, 0, 0, 0), (15, 0, 0, 2), ((1 << 64) - 1, 0, 0, 1),
                   (0, 0, (1 << 64) - 1, 1)]
        for dest, index, start, count in invalid:
            with self.subTest(values=(dest, index, start, count)):
                with self.assertRaises(HIAProgramTrap) as caught:
                    self.vm(self.check(one(destination=dest, index=index, source=start, count=count)))
                self.assertEqual(caught.exception.code, 'bounds')
                self.assertEqual(caught.exception.report['output_hex'], (b'\xa5' * 16).hex())
                self.assertEqual(caught.exception.report['effects'], [])
        observed = self.vm(self.check(one(destination=16, source=6, count=0)))
        self.assertEqual(observed['output_hex'], (b'\xa5' * 16).hex())
        self.assertEqual(observed['effects'][0]['count'], 0)

    def test_copy_uses_actual_linear_loan_checker_and_parent_suspension(self):
        raw = one()
        bad = raw.replace(b'  v3:usize', b'  v20:mutbuf = borrow.mut(v1)\n  v3:usize', 1)
        bad = bad.replace(b'  ret(', b'  _ = loan.end(v20)\n  ret(', 1)
        with self.assertRaises(HIAProgramRejected) as caught:
            self.check(bad)
        self.assertEqual(caught.exception.code, 'E_HIA_LOAN')
        fixed = bad.replace(b'linux.argv.copy(v1,', b'linux.argv.copy(v20,', 1)
        observed = self.vm(self.check(fixed))
        self.assertEqual(observed['resources']['loans_started'], 1)
        self.assertEqual(observed['resources']['loans_ended'], 1)
        self.assertEqual(bytes.fromhex(observed['output_hex'])[2:5], b'bcd')

    def test_types_effects_and_attributes_cannot_grant_arbitrary_pointer_or_fd(self):
        raw = one()
        invalid = [raw.replace(b',linux_startup', b'', 1),
            raw.replace(b'read,write,trap', b'read,trap', 1),
            raw.replace(b'linux.argv.copy(v1,', b'linux.argv.copy(v0,', 1),
            raw.replace(b'v4:usize', b'v4:u64', 1), raw.replace(b'v7:usize', b'v7:u64', 1),
            raw.replace(b'linux.argv.copy(v1,v3,v4,v5,v6)', b'linux.argv.copy(v1,v3,v4,v5,v6) {"pointer":0}', 1),
            raw.replace(b'linux.argv.copy', b'linux.arbitrary.copy', 1),
            raw.replace(b'linux.argv.copy(v1,v3,v4,v5,v6)', b'call(v1,v3,v4,v5,v6) {"function":"syscall"}', 1),
            one('linux.stderr.write', ('v1', 'v3', 'v6')).replace(b'linux.stderr.write(v1,v3,v6)',
                b'linux.stderr.write(v1,v3,v6) {"fd":99}', 1)]
        for i, source in enumerate(invalid):
            with self.subTest(i=i):
                with self.assertRaises(HIAProgramRejected):
                    self.check(source)

    def test_callee_startup_effect_propagation_is_not_hidden_behind_call(self):
        raw = b'''hia-asm.v1 hepta.hia.program.v8 selfhost_linux_process
fn f0(v0:readbuf,v1:mutbuf,v2:mutbuf) -> (u32) effects(read,trap) entry(b0)
block b0(v0:readbuf,v1:mutbuf,v2:mutbuf)
  v3:usize = call() {"function":"f1"}
  v4:u32 = int.cast(v3) {"mode":"wrap"}
  ret(v4)
end
fn f1() -> (usize) effects(read,trap,linux_startup) entry(b0)
block b0()
  v0:usize = linux.argv.count()
  ret(v0)
end
'''
        with self.assertRaises(HIAProgramRejected) as caught:
            self.check(raw)
        self.assertEqual(caught.exception.code, 'E_HIA_EFFECT')
        fixed = raw.replace(b'effects(read,trap)', b'effects(read,trap,linux_startup)', 1)
        self.assertEqual(self.vm(self.check(fixed), argv=(b'a', b'b'))['values'], [2])

    def test_fixed_stderr_provider_is_single_call_even_for_negative_and_zero(self):
        for count, response in ((3, (-9, b'')), (3, (-32, b'')), (3, (2, b'')),
                                (0, (-9, b'')), (0, (0, b''))):
            with self.subTest(count=count, response=response):
                seen = []
                checked = self.check(one('linux.stderr.write', ('v1', 'v3', 'v6'), count=count))
                result = self.vm(checked, provider=lambda r: (seen.append(r) or response))
                self.assertEqual(len(seen), 1)
                self.assertEqual((seen[0].fd, seen[0].count), (2, count))
                self.assertEqual(result['effects'][0]['result'], response[0])
        original = RuntimeError('exact provider exception')
        def provider(_):
            raise original
        with self.assertRaises(RuntimeError) as caught:
            self.vm(self.check(one('linux.stderr.write', ('v1', 'v3', 'v6'))), provider=provider)
        self.assertIs(caught.exception, original)

    def test_provider_result_domain_and_signal_remain_explicit_reference(self):
        checked = self.check(one('linux.stderr.write', ('v1', 'v3', 'v6'), count=3))
        for response in ((True, b''), (-4096, b''), (4, b''), (1, b'wrong'), (0,), [0, b'']):
            with self.subTest(response=response):
                with self.assertRaises(LinuxProcessProviderRejected):
                    self.vm(checked, provider=lambda _: response)
        def provider(_):
            raise LinuxProcessSignal(13)
        with self.assertRaises(LinuxProcessSignal) as caught:
            self.vm(checked, provider=provider)
        self.assertFalse(caught.exception.report['actual_kernel_execution'])
        self.assertEqual(caught.exception.report['signal'], 13)

    def test_forged_snapshot_or_profile_object_is_not_native_or_core_authority(self):
        checked = self.check()
        document = checked.as_dict()
        document['functions'][0]['effects'] = []
        with self.assertRaises(HIAProgramRejected):
            verify_program(document, profile=PROFILE)
        for invalid in (bytearray(checked.canonical_bytes), b'{}'):
            with self.assertRaises(HIAProgramRejected):
                self.vm(VerifiedLinuxProcessProgram(invalid))
        self.assertEqual(self.check().canonical_bytes, checked.canonical_bytes)

    def test_v1_and_default_reject_new_physical_provider_arguments(self):
        from hepta.hia_linux_stdio import PROFILE as OLD
        from tests.test_hia_linux_stdio import program as old_program
        old = assemble_program(old_program(), profile=OLD)
        for profile in (None, OLD):
            with self.subTest(profile=profile):
                with self.assertRaises(HIAProgramRejected):
                    execute_program(old, 'f0', (b'', b'', b''), profile=profile,
                        linux_process_startup=LinuxStartupSnapshot((), ()),
                        linux_process_provider=lambda _: (0, b''))
        with self.assertRaises(HIAProgramRejected):
            execute_program(self.check(), 'f0', (b'', b'', b''), profile=PROFILE,
                linux_process_startup=LinuxStartupSnapshot((), ()),
                linux_process_provider=lambda _: (0, b''), linux_stdio_provider=lambda _: (0, b''))

    def test_original_finite_resource_limits_remain_unchanged(self):
        for kwargs in ({'max_steps': True}, {'max_steps': 10000001}, {'max_call_depth': 257},
                       {'max_heap_bytes': -1}, {'allocation_fail_at': 0}):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(HIAProgramRejected):
                    self.vm(**kwargs)
        with self.assertRaises(HIAProgramBudgetExceeded):
            self.vm(max_steps=1)
        with self.assertRaises(HIAProgramRejected):
            self.vm(output=bytes(1048577))


if __name__ == '__main__':
    unittest.main()
