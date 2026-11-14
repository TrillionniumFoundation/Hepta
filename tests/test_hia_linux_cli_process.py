"""Explicit resident-call authority and unchanged ordinary consumer boundaries."""
from pathlib import Path
import unittest
from unittest import mock

from hepta.hia_agent_assembly import assemble_program, render_assembly
from hepta.hia_program import HIAProgramRejected, VerifiedProgram, verify_program
from hepta.hia_program_runtime import execute_program, HIAProgramTrap
from hepta.hia_linux_cli_process import (
    PROFILE, PROFILE_OPCODES, RESIDENT_OPCODES, COMPONENT_PINS,
    VerifiedLinuxCliProcessProgram, LinuxStartupSnapshot, _checked_components,
)

ROOT = Path(__file__).resolve().parents[1]


def one(*, offset=0, count=0, operation='linux.cli.control'):
    return ('''hia-asm.v1 hepta.hia.program.v8 selfhost_linux_cli_process
fn f0(v0:mutbuf,v1:mutbuf,v2:mutbuf) -> (u32) effects(read,write,trap,linux_cli) entry(b0)
block b0(v0:mutbuf,v1:mutbuf,v2:mutbuf)
  v3:usize = const() {"value":OFFSET}
  v4:usize = const() {"value":COUNT}
  v5:u32 = OPERATION(v0,v3,v4,v1,v3,v4,v2,v3,v4)
  ret(v5)
end
'''.replace('OFFSET', str(offset)).replace('COUNT', str(count)).replace('OPERATION', operation)).encode()


class LinuxCliProcessSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.components = tuple((ROOT / ('examples/hia_bootstrap/' + name + '.hepta')).read_bytes()
            for name in ('cli_control', 'cli_format', 'cli_discovery_json'))

    def checked(self, raw=None):
        return assemble_program(one() if raw is None else raw, profile=PROFILE)

    def vm(self, checked=None, **kwargs):
        return execute_program(self.checked() if checked is None else checked, 'f0',
            (b'A', b'B', b'C'), profile=PROFILE,
            linux_process_startup=LinuxStartupSnapshot((b'hia',), ()),
            linux_process_provider=lambda _: self.fail('no physical I/O is allowed by this fixture'),
            linux_cli_components=self.components, **kwargs)

    def test_public_roundtrip_has_distinct_rechecked_authority(self):
        checked = self.checked()
        self.assertIs(type(checked), VerifiedLinuxCliProcessProgram)
        self.assertNotIsInstance(checked, VerifiedProgram)
        self.assertEqual(render_assembly(checked, profile=PROFILE).encode(), one())
        self.assertEqual(verify_program(checked, profile=PROFILE), checked)
        report = checked.report()
        self.assertFalse(report['default_core_authority'])
        self.assertFalse(report['native_artifact_created'])

    def test_default_native_llvm_and_old_profile_consumers_reject(self):
        from hepta.hia_program_native import emit_program_machine
        from hepta.hia_program_llvm import emit_program_llvm
        from hepta.hia_linux_stdio import PROFILE as STDIO
        from hepta.hia_linux_process import PROFILE as PROCESS
        checked = self.checked()
        calls = [lambda: assemble_program(one()), lambda: render_assembly(checked),
            lambda: verify_program(checked), lambda: verify_program(checked.as_dict()),
            lambda: execute_program(checked, 'f0', (b'', b'', b'')),
            lambda: emit_program_machine(checked), lambda: emit_program_llvm(checked)]
        calls += [lambda p=p: assemble_program(one(), profile=p) for p in (STDIO, PROCESS)]
        for index, call in enumerate(calls):
            with self.subTest(index=index), self.assertRaises((HIAProgramRejected, ValueError, TypeError)):
                call()

    def test_component_sources_are_exact_immutable_ordered_inputs(self):
        admitted = _checked_components(self.components)
        self.assertEqual(tuple(admitted), tuple(COMPONENT_PINS))
        bad = [list(self.components), self.components[:2], self.components[::-1],
            (bytearray(self.components[0]), *self.components[1:]),
            (self.components[0] + b'\n', *self.components[1:]),
            (self.components[0], self.components[1], b'{}')]
        for value in bad:
            with self.subTest(kind=type(value).__name__), self.assertRaises(HIAProgramRejected):
                _checked_components(value)

    def test_inventory_is_fixed_and_does_not_extend_global_core(self):
        from hepta.hia_opcodes import OPCODES, EFFECTS
        self.assertEqual(set(RESIDENT_OPCODES),
            {'linux.cli.control', 'linux.cli.format', 'linux.cli.discovery'})
        self.assertFalse(set(PROFILE_OPCODES) & set(OPCODES))
        self.assertNotIn('linux_cli', EFFECTS)
        with self.assertRaises(TypeError):
            PROFILE_OPCODES['linux.cli.arbitrary'] = RESIDENT_OPCODES['linux.cli.control']
        for operation in RESIDENT_OPCODES:
            self.assertEqual(RESIDENT_OPCODES[operation].guards,
                ('read:0', 'write:3', 'write:6', 'distinct:0:3', 'distinct:0:6', 'distinct:3:6'))

    def test_actual_type_effect_and_attribute_checker_refuses_unsafe_call(self):
        raw = one()
        bad = [raw.replace(b',linux_cli', b'', 1), raw.replace(b'read,write,trap', b'read,trap', 1),
            raw.replace(b'v3:usize', b'v3:u64', 1), raw.replace(b'v5:u32', b'v5:u64', 1),
            raw.replace(b'v2:mutbuf', b'v2:readbuf'),
            raw.replace(b'linux.cli.control', b'linux.cli.any'),
            raw.replace(b'linux.cli.control(v0,v3,v4,v1,v3,v4,v2,v3,v4)',
                        b'linux.cli.control(v0,v3,v4,v1,v3,v4,v2,v3,v4) {"address":4194304}'),
            raw.replace(b'linux.cli.control(v0,v3,v4,v1,v3,v4,v2,v3,v4)',
                        b'call(v0,v3,v4,v1,v3,v4,v2,v3,v4) {"function":"native_pointer"}')]
        for index, value in enumerate(bad):
            with self.subTest(index=index), self.assertRaises(HIAProgramRejected):
                self.checked(value)

    def test_actual_loan_checker_rejects_aliases_and_suspended_parent(self):
        for target in (b'v0', b'v1'):
            bad = one().replace(b',v2,v3,v4)', b',' + target + b',v3,v4)')
            with self.subTest(target=target), self.assertRaises(HIAProgramRejected) as caught:
                self.checked(bad)
            self.assertEqual(caught.exception.code, 'E_HIA_LOAN')
        bad = one().replace(b'  v3:usize', b'  v8:mutbuf = borrow.mut(v1)\n  v3:usize', 1)
        bad = bad.replace(b'  ret(v5)', b'  _ = loan.end(v8)\n  ret(v5)', 1)
        with self.assertRaises(HIAProgramRejected) as caught:
            self.checked(bad)
        self.assertEqual(caught.exception.code, 'E_HIA_LOAN')
        fixed = bad.replace(b',v1,v3,v4,', b',v8,v3,v4,', 1)
        self.checked(fixed)

    def test_all_extent_guards_precede_resident_or_physical_effect(self):
        for offset, count in ((2, 0), (1, 1), (0, 2), ((1 << 64) - 1, 0), (0, (1 << 64) - 1)):
            with self.subTest(offset=offset, count=count), self.assertRaises(HIAProgramTrap) as caught:
                self.vm(self.checked(one(offset=offset, count=count)))
            report = caught.exception.report
            self.assertEqual(caught.exception.code, 'bounds')
            self.assertEqual(report['effects'], [])
            self.assertEqual((report['source_hex'], report['output_hex'], report['workspace_hex']),
                             (b'A'.hex(), b'B'.hex(), b'C'.hex()))

    def test_missing_components_or_invalid_limits_fail_before_io(self):
        for values in ({'max_steps': True}, {'max_steps': 10000001}, {'max_call_depth': 257},
                       {'max_heap_bytes': -1}, {'allocation_fail_at': 0}):
            with self.subTest(values=values), self.assertRaises(HIAProgramRejected):
                self.vm(**values)
        for components in (None, (), self.components[::-1]):
            with self.subTest(components=type(components).__name__), self.assertRaises(HIAProgramRejected):
                execute_program(self.checked(), 'f0', (b'A', b'B', b'C'), profile=PROFILE,
                    linux_process_startup=LinuxStartupSnapshot((), ()),
                    linux_process_provider=lambda _: self.fail('no I/O'), linux_cli_components=components)

    def test_component_argument_cannot_leak_through_default_or_legacy_entry(self):
        from hepta.hia_linux_process import PROFILE as PROCESS
        from tests.test_hia_linux_process import one as process_source
        old = assemble_program(process_source(), profile=PROCESS)
        for profile in (None, PROCESS, 'hepta.hia.linux-stdio.v1'):
            with self.subTest(profile=profile), self.assertRaises(HIAProgramRejected):
                execute_program(old, 'f0', (b'A', b'B', b'C'), profile=profile,
                    linux_cli_components=self.components)

    def test_forged_verified_object_does_not_grant_authority(self):
        for raw in (bytearray(self.checked().canonical_bytes), b'{}'):
            with self.subTest(kind=type(raw).__name__), self.assertRaises(HIAProgramRejected):
                verify_program(VerifiedLinuxCliProcessProgram(raw), profile=PROFILE)
        document = self.checked().as_dict()
        document['functions'][0]['effects'] = []
        with self.assertRaises(HIAProgramRejected):
            verify_program(document, profile=PROFILE)

    def test_builder_rejects_bad_inputs_before_child_or_output_directory(self):
        from tools.build_hia_linux_cli_process_program import build_linux_cli_process_program
        with mock.patch('tools.build_hia_linux_cli_process_program.compile_stage',
                        side_effect=AssertionError('no child before admission')):
            for profile, components in ((None, self.components), (PROFILE, self.components[::-1])):
                with self.subTest(profile=profile), self.assertRaises(HIAProgramRejected):
                    build_linux_cli_process_program(self.checked(), ROOT / 'unreachable-cli-output',
                        profile=profile, compiler=ROOT / 'unreachable-compiler',
                        compiler_sha256='0' * 64, components=components)
        self.assertFalse((ROOT / 'unreachable-cli-output').exists())

    def test_source_generators_and_three_frozen_residents_are_exact(self):
        from tools.generate_hia_native_cli_process import document
        from tools.generate_hia_linux_cli_entry import generated
        from hashlib import sha256
        self.assertEqual(render_assembly(document(), profile=PROFILE).encode(),
            (ROOT / 'examples/hia_bootstrap/native_cli_process.hepta').read_bytes())
        self.assertEqual(generated().encode(),
            (ROOT / 'examples/hia_bootstrap/linux_cli_entry_packer.hepta').read_bytes())
        self.assertEqual(tuple(sha256(x).hexdigest() for x in self.components), tuple(COMPONENT_PINS.values()))


if __name__ == '__main__':
    unittest.main()
