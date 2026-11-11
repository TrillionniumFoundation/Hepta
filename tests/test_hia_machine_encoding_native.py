"""Independent instruction observations and explicit native Code selection."""
from __future__ import annotations
import ast
from collections import Counter
from contextlib import ExitStack
import ctypes
from hashlib import sha256
import inspect
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from hepta import hia_machine_x64 as reference
from hepta.hia_machine_encoding_native import (
    SOURCE, SCHEMA, SELECTOR, COMMANDS, NativeMachineEncoding,
    installed_machine_encoding, selected_code_class)
from hepta.hia_agent_assembly import assemble_program, render_assembly
from hepta.hia_program_runtime import _Machine, _Owner, _View

DEVELOPMENT = 'HEPTA_HIA_MACHINE_ENCODING_DEVELOPMENT_MANIFEST'
COLD = 'HEPTA_HIA_MACHINE_ENCODING_COLD_REPORT'
EVIDENCE = 'HEPTA_HIA_MACHINE_ENCODING_FIXTURE_EVIDENCE'

RETAINED_METHODS = {'__init__': '06a754ed0699cc7559aed24727073cb39f07542c1c202651a3a5f106dbeb9189', '_reg': 'ee1514db9f10bc5e444d0e0ab4aa410e9e063caa1977e05ecf420de3d7d2cb95', 'align': '8dabb955a3d0a44078a86b7253d4e6456ac4b92d3deec0a33f06f3da1dfbf44d', 'offset': '08cfa71290284c3ed0a077c20610c68e2bc2a5afddfffc119bed168d26800da6', 'emit': 'a3be9f9c11529f973e77b4a213022af6100f32c717242d99e207e2f8bd2e58d2', '_rr': '4887f81b2db0ebb10ccafc37d4dd02fcd62b2c79256fe96547485ffdf723c387', '_mem': '2d7ac9ef9c8ea8ea271d8a8dbcc1a99fa7d02d7742ad797c586aee8c8d8ad380', 'label': '6dde375b2687b4c6a7c3dfc243d56573f32b50afdab5f5742c665d5d49f4653b', '_branch': '4086d91e4900dac8bf32c2d6b1f392c3f04ac55d43bec1a9226828b673a93682', 'jmp': '34091e001e04afc45bfa2978f8382187c83bd0986800f3dc4ff0967b7a14be6c', 'jcc': '4eba97e1fe9e563b4f2914ab06732c227bc435517b3f199d28676a77149af917', 'call': '09e7340731d460c0dda2c1bc4421f3b2fc94a2a8affb5339c046576586a2e357', 'mov_rr': '2d30fe916599df338ded49b556af7cb7cf7a61de8a311341dcdce43648fcb98c', 'mov_imm': '40eccb9ed9f0de65207a8a1544589298f990d438b57c5e17596e9f1582bf5ff4', 'load': '6f1a06d5a06e596d75c5cc654b4b0445c152ba9c122aa5049f28fe55c9a23195', 'store': '1f5176bfddeee0ff1d7939169818e372255166087c40e337b228d087717b0014', 'lea': '1cb3a569b71fc7229201e41240d347c75c81d3d3dfa183d50635a3398c1797b8', 'load_u8': 'd055b57d21b5fd5d2cd8035dcab9c0c72eebcc56bce44e83015eaa95b35052c6', 'store_u8': 'f011bb9eda71eed462479884537ebcf3beb5e4f8a7c78835eb74227158f2c972', 'add': '483bd9b922f6886caf6848d7d06fd344274d0f03e5938d5849bfda34777e256f', 'sub': 'abeb10b5f15a03bf3bee690bca24008ac556c950caef5270376da688532d258a', 'and_': 'd5850518214c25f6de2f4aff396221c5db991427ca7ad7734fb27229c4df7b25', 'or_': 'a6b918ce50e95d0b1e831fe3010d3b99d60b242b3dbffab85a7fe23bf601dfa4', 'xor': '3ede04a6be3bb4954037adc1ee13a9fedc5f4007c1d2b268e0cf61ee16f49b6e', 'cmp': '7ad79441494484123d7fa1c0efb277499da4d9d9b176285fe9e602a96a119f36', 'test': 'cb61e6c5afd38e188603d837ea60f5a6afdd1f89e67c0b16a6bc9a555c00cb55', 'alu_imm': '7d5eea1aaaea03d15d2d8f8f8186232c76b1c2011ce71b2acf71aa41619a5e4a', 'shift': '38af858a0e50411d3f3e2ae24c7888fb770af55b8ca221f4d3489f72f99eded1', 'shift_imm': 'b042dfd1169fa057819459cc8dbf346a119527501e26c6fac068d1bd6dee2207', 'shift_cl': '924f5728aa4cdff056e94e8bcbe5fb366a990cf38aacb114db85b3538c8fc052', 'shl': '1dd611872f33c8e3a34549f00a82dd024dd6c1c77574d7bf323fa609582e8fb5', 'shr': 'f9f95943c455fbb18093944ec373986951578d3dfd74cccea38bf571d282748b', 'sar': '51124352f0976b2e8faf6ba20df149566cd99f247d6b230957ca7e5cbe058e28', 'imul': '58cbcede149ae2f52c9cc48c7aac7e75787165d310eaed5921f4931b8ca368c9', 'imul_rr': '24e5a91307ec68b1f27f7e6136715de7a85c7fe58550ab3723f84e94c5902b8f', '_unary': '8ccabb2fe3af1cb6676d28b2274d9a89c2a01e592ef9021f207ebbd7bbc756d0', 'mul': '26c6b7a56bef06ca6f5fdc48d35506b2a4fe1b5a66e2b1be004b4170a178abed', 'imul_full': '07d711a9014c48b4aa8caf83e1de3d8c454541b3d96b95fadde8ea9e246f29c5', 'div': '5d92339f021bffe83a959761031a54b7962be691ffdd5967e2b56394540e3470', 'idiv': '3048b4065586360287a1c6a86c21277a0854ce08db3a1c7ff3cd92d2cc538944', 'neg': 'c40c6f8c826f9fbe6073420b457e894b75c07ce533da223acdf8a703ce93d5e7', 'bitnot': '47ea883dd51d53b2974d48db91f62d53b0df4b5f8a3c48f2ed69d73cd59faa77', 'cqo': 'd9d334ce522a7f8426449137484d517747a3bc013fb40e5d5ea1bc4188b61571', 'setcc': 'e7e8144ee550df15bf9a2d54743374184eb7f368ce2203c3d0540158ddb3657f', 'cmov': '2265378ecde6587d13b7add2ccf4ae83a2e19f825ce0df02794c113dd8dbf5ab', 'push': 'e539a298f0b32a365e4e61bfa42648f531afd22d89e3e6970a63bb49bb96d365', 'pop': '5129698488e7694af014d9fabb2a7567b33077d2c2ef4d1196c167f9d353fd03', 'ret': 'e2c98093e5c993841a1b1cf084b1e61711c371505e5958172c770f5eea22cc02', 'leave': 'dc4194b74e7a8ea385140173daaaaf76e0859dcc8633e709ea939899b1492a8b', 'ud2': 'c0e15647e904cc669d3e41927578a2c3aec9bd3d4b4d2175d533e6768e2a4528', 'finalize': '5b046a2db7b01cd0d5f747425b0dc90825a14e64042c741c1619ea961d260cbd'}

def cases():
    rows = []
    def add(name, operations, **options):
        rows.append({'id': name, 'operations': operations, 'options': options})
    instructions = [
        ('align', [32]), ('mov_rr', ['r15', 'r12']),
        ('load', ['r15', 'rsp', -(1 << 31)]), ('store', ['r12', (1 << 31) - 1, 'r9']),
        ('lea', ['r10', 'r12', -17]), ('load_u8', ['r9', 'rsp', 0]),
        ('store_u8', ['r12', 17, 'rsi']),
        *[(op, ['r9', 'r15']) for op in ('add', 'sub', 'and_', 'or_', 'xor', 'cmp', 'test', 'imul', 'imul_rr')],
        *[(op, ['r15']) for op in ('mul', 'imul_full', 'div', 'idiv', 'neg', 'bitnot', 'push', 'pop')],
        *[(op, []) for op in ('cqo', 'ret', 'leave', 'ud2')],
        ('setcc', ['ne', 'r11']), ('cmov', ['e', 'r10', 'r9']),
        ('shift_imm', ['sar', 'r9', 63]), ('shift_cl', ['shr', 'r10']),
        ('shl', ['r10', 0]), ('shr', ['r11', 17]), ('sar', ['r12', 'cl']),
    ]
    for swapped in (False, True):
        options = {'scratch_registers': {'r10': 'r11', 'r11': 'r10'}} if swapped else {}
        for index, instruction in enumerate(instructions):
            add(f'public-{int(swapped)}-{index}', [instruction], **options)
    for compact in (False, True):
        options = {'move_immediate': 'mov32_if_exact' if compact else 'movabs',
                   'alu_immediate': 'imm8_if_exact' if compact else 'imm32'}
        for index, value in enumerate((-(1 << 63), -1, 0, (1 << 32) - 1, 1 << 32, (1 << 64) - 1)):
            add(f'move-{int(compact)}-{index}', [('mov_imm', ['r9', value])], **options)
        for op in ('add', 'or', 'and', 'sub', 'xor', 'cmp'):
            for value in (-129, -128, 127, 128):
                add(f'alu-{int(compact)}-{op}-{value}', [('alu_imm', [op, 'r11', value])], **options)
    for condition in ('o', 'no', 'c', 'nc', 'z', 'nz', 'na', 'nbe', 's', 'ns', 'pe', 'po', 'nge', 'nl', 'ng', 'nle'):
        add('condition-' + condition, [('setcc', [condition, 'r15']), ('cmov', [condition, 'r8', 'r9'])])
    add('labels-calls-rel32', [('label', ['start']), ('jmp', ['end']), ('call', ['calloc']),
        ('jcc', ['ne', 'start']), ('label', ['end']), ('ret', [])])
    bad = [
        ('mov_rr', ['rax', 'eax']), ('mov_imm', ['rax', True]),
        ('mov_imm', ['rax', 1 << 64]), ('load', ['rax', 'r12', 1 << 31]),
        ('shift', ['shl', 'rax', 64]), ('alu_imm', ['bad', 'unknown', True]),
        ('jcc', ['unsupported', 'x']), ('cmov', ['e', 'rax', '[rcx]']),
        ('call', ['puts;system']), ('jmp', ['']), ('align', [True]),
    ]
    for index, operation in enumerate(bad):
        add('refusal-' + str(index), [operation])
    add('unresolved-label', [('jmp', ['missing'])])
    return rows

def observe(factory, row):
    value = factory(**row['options'])
    result = {'exception': None}
    try:
        for name, arguments in row['operations']:
            getattr(value, name)(*arguments)
        raw, relocations = value.finalize()
        result['final'] = {'bytes': raw.hex(), 'relocations': relocations}
        if value.finalize() != (raw, relocations):
            raise AssertionError('repeated finalize differs')
    except Exception as exc:
        result['exception'] = {'type': type(exc).__name__, 'message': str(exc)}
    result.update(data=value.data.hex(), labels=dict(value.labels), fixups=list(value.fixups),
                  relocations=[dict(item) for item in value.relocations])
    return result


class MachineEncodingSourceTests(unittest.TestCase):
    def test_retained_reference_methods_are_unchanged(self):
        tree = ast.parse(inspect.getsource(reference))
        original = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'Code')
        actual = {node.name: sha256(ast.dump(node, include_attributes=False).encode()).hexdigest()
                  for node in original.body if isinstance(node, ast.FunctionDef)}
        self.assertEqual({name: actual[name] for name in RETAINED_METHODS}, RETAINED_METHODS)

    def test_generated_HIA_and_independent_Core_observations(self):
        from tools.generate_hia_machine_encoding import document
        self.assertEqual(render_assembly(document()).encode(), SOURCE.read_bytes())
        program = assemble_program(SOURCE.read_bytes())
        function = program.as_dict()['functions'][0]
        resources = []
        def entry(source, size, output, output_size, workspace, workspace_size):
            packet = ctypes.string_at(source, size)
            owners = [_Owner(-1, bytearray(packet)),
                _Owner(-2, bytearray(ctypes.string_at(output, output_size))),
                _Owner(-3, bytearray(ctypes.string_at(workspace, workspace_size)))]
            machine = _Machine(program, 4_000_000, 16 << 20, None, 128)
            result = machine.invoke(function, [_View(owners[0], False),
                _View(owners[1], True), _View(owners[2], True)])[0]
            self.assertEqual(bytes(owners[0].data), packet)
            for destination, owner in ((output, owners[1]), (workspace, owners[2])):
                ctypes.memmove(destination, bytes(owner.data), len(owner.data))
            resources.append(machine.resources())
            return result
        owner = NativeMachineEncoding.__new__(NativeMachineEncoding)
        owner._entry, owner.calls = entry, Counter()
        selected = selected_code_class(owner)
        with patch.dict(os.environ, {SELECTOR: ''}):
            for row in cases():
                with self.subTest(case=row['id']):
                    self.assertEqual(observe(selected, row), observe(reference.Code, row))
        self.assertEqual(set(owner.calls), set(COMMANDS))
        self.assertEqual(len(cases()), 159)
        self.assertTrue(all(row['live_owners'] == row['live_local_loans'] == 0 for row in resources))

    def test_cold_admission_precedes_build_output(self):
        from tools.build_hia_machine_encoding import build
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            compiler, cold = directory / 'compiler', directory / 'cold'
            compiler.write_bytes(b'explicitly-unqualified')
            cold.write_text('{"status":"DEVELOPMENT_ONLY"}')
            with self.assertRaisesRegex(ValueError, 'completed matching native cold'):
                build(directory / 'new-parent' / 'image', compiler, cold)
            self.assertFalse((directory / 'new-parent').exists())

    def test_unselected_identity_and_subclasses_remain_original(self):
        with patch.dict(os.environ, {SELECTOR: ''}):
            self.assertIs(type(reference.Code()), reference.Code)
        class ForeignCode(reference.Code):
            def ret(self):
                self.emit(b'foreign')
        with patch.dict(os.environ, {SELECTOR: '/missing/explicit-native-manifest'}):
            code = ForeignCode()
            code.ret()
            self.assertEqual(code.data, b'foreign')
            with self.assertRaises(FileNotFoundError):
                reference.Code()


class MachineEncodingNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        development, cold = os.environ.get(DEVELOPMENT), os.environ.get(COLD)
        if development and cold:
            raise AssertionError('development image cannot override a requested cold report')
        evidence = os.environ.get(EVIDENCE)
        if evidence:
            cls.folder = Path(evidence).resolve()
            cls.folder.mkdir(parents=True, exist_ok=False)
        else:
            cls.temporary = tempfile.TemporaryDirectory(prefix='hia-machine-encoding-native-')
            cls.addClassCleanup(cls.temporary.cleanup)
            cls.folder = Path(cls.temporary.name)
        if cold:
            from tools.build_hia_machine_encoding import build
            report = json.loads(Path(cold).read_bytes())
            nested = json.loads(Path(report['nested_report']).read_bytes())
            compiler = Path(nested['generations'][-1]['produced_image'])
            cls.manifest = build(cls.folder / 'qualified', compiler, Path(cold))
            cls.scope = 'MATCHING_SOURCE_COLD_BUILD'
        elif development:
            cls.manifest = Path(development).resolve(strict=True)
            cls.scope = 'EXPLICIT_DEVELOPMENT_ONLY'
        else:
            raise unittest.SkipTest('requires explicit current cold report or development manifest')
        cls.native = installed_machine_encoding(str(cls.manifest))

    def selected(self, forbid_reference=True):
        stack = ExitStack()
        stack.enter_context(patch.dict(os.environ, {SELECTOR: str(self.manifest)}))
        if forbid_reference:
            for name, member in reference.Code.__dict__.items():
                if inspect.isfunction(member) and name not in {'__new__', '__init__', '_reg', 'emit', 'label'}:
                    stack.enter_context(patch.object(reference.Code, name,
                        side_effect=AssertionError('retained instruction encoder entered: ' + name)))
        return stack

    def test_ordinary_Code_constructor_enters_all_commands_without_retained_encoding(self):
        with patch.dict(os.environ, {SELECTOR: ''}):
            wanted = [observe(reference.Code, row) for row in cases()]
        self.native.calls.clear()
        with self.selected():
            for row, expected in zip(cases(), wanted):
                with self.subTest(case=row['id']):
                    self.assertEqual(observe(reference.Code, row), expected)
        self.assertEqual(set(self.native.calls), set(COMMANDS))

    def test_backend_identity_binds_actual_pinned_selection(self):
        from hepta import hia_program_native as backend
        from hepta.hia_program import verify_program
        from tests.test_hia_machine_plan import call_document
        checked = verify_program(call_document())
        with patch.dict(os.environ, {SELECTOR: ''}):
            old = backend.emit_program_machine(checked)
        with self.selected():
            actual = backend.emit_program_machine(checked)
            self.assertEqual(actual.implementation_sha256, backend._implementation_hash())
        self.assertEqual(actual.object_bytes, old.object_bytes)
        self.assertNotEqual(actual.implementation_sha256, old.implementation_sha256)
        original_render = backend._Emitter.render
        def foreign_render(emitter):
            os.environ[SELECTOR] = '/missing/changed-after-capture'
            return original_render(emitter)
        with self.selected(), patch.object(backend._Emitter, 'render', foreign_render):
            frozen = backend.emit_program_machine(checked)
        self.assertEqual(frozen.object_bytes, actual.object_bytes)
        self.assertEqual(frozen.implementation_sha256, actual.implementation_sha256)

    def test_cached_image_rebinds_package_source_and_rejects_forged_source(self):
        from hepta import hia_machine_encoding_native as bridge
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            source = directory / 'machine_encoding.hiaasm'
            source.write_bytes(SOURCE.read_bytes())
            with patch.object(bridge, 'SOURCE', source):
                self.assertIs(installed_machine_encoding(str(self.manifest)), self.native)
                source.write_bytes(source.read_bytes() + b'\n')
                with self.assertRaisesRegex(ValueError, 'source identity mismatch'):
                    installed_machine_encoding(str(self.manifest))
                source.unlink()
                with self.assertRaises(FileNotFoundError):
                    installed_machine_encoding(str(self.manifest))
            forged = json.loads(self.manifest.read_bytes())
            forged['source_sha256'] = '0' * 64
            path = directory / 'forged.json'
            path.write_text(json.dumps(forged))
            with self.assertRaisesRegex(ValueError, 'source identity mismatch'):
                installed_machine_encoding(str(path))


if __name__ == '__main__':
    unittest.main()
