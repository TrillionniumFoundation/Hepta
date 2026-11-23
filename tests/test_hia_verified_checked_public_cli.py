"""Regression coverage for checked arithmetic through the installed HIA build and supplied verifier."""
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import subprocess
from tempfile import TemporaryDirectory
import unittest

from hepta.hia_scalar_reference_native import sealed_reference_bytes
from tests.test_hia_program import arithmetic, b, jump, ret


def checked_source(typ, operation):
    doc = arithmetic(f'int.{operation}.checked', typ)
    function, = doc['functions']
    entry, = function['blocks']
    result, = entry['term']['values']
    entry['term'] = jump('finish', result)
    function['blocks'].append(b('finish', [('value', typ)], [], ret('value')))
    return json.dumps(doc).encode()


def supplied_verdict(cli, source, obj, elf):
    header = struct.pack('<8s5Q', b'HIAPRF02', 0, 10000, len(source), len(obj), len(elf))
    with sealed_reference_bytes(header, source, obj, elf) as fd:
        os.lseek(fd, 0, os.SEEK_SET)
        result = subprocess.run([cli.parent / 'hia-safe-core-prove'], stdin=fd,
                                env={'PATH': ''}, capture_output=True, timeout=60)
    if result.returncode:
        return None
    if len(result.stdout) < 32 or result.stdout[:8] != b'HIAPRR01':
        raise AssertionError('invalid supplied proof frame')
    return struct.unpack_from('<Q', result.stdout, 8)[0]


CLI = os.environ.get('HEPTA_HIA_TEST_INSTALLED_CHECKED_CLI')


@unittest.skipUnless(CLI, 'requires an installed HIA CLI and its supplied-artifact verifier')
class PublicCheckedArithmetic(unittest.TestCase):
    def test_checked_words_through_publication_and_independent_verification(self):
        cli = Path(CLI).resolve()
        cases = [('u8', 'div', 211, 13, 16), ('i16', 'rem', -91, 12, -7),
                 ('u32', 'rem', 0xfffffffe, 31, 2), ('i32', 'div', -1234567, 31, -39824),
                 ('i64', 'shr', -65, 3, -9), ('u64', 'shl', 17, 58, 17 << 58)]
        alternate = {'div': 'rem', 'rem': 'div', 'shl': 'shr', 'shr': 'shl'}
        with TemporaryDirectory() as temp:
            root = Path(temp)
            for typ, op, left, right, expected in cases:
                with self.subTest(typ=typ, operation=op):
                    case = root / (typ + '-' + op)
                    case.mkdir()
                    source = checked_source(typ, op)
                    src = case / 'kernel.hepta'
                    obj = case / 'kernel.o'
                    elf = case / 'kernel.so'
                    src.write_bytes(source)
                    for backend, kind, output in [('native', 'object', obj), ('auto', 'shared', elf)]:
                        result = subprocess.run([cli, 'build', src, '-o', output, '--backend', backend, '--kind', kind],
                                                cwd=case, env={'PATH': ''}, capture_output=True,
                                                timeout=90, check=True)
                    report = json.loads(result.stdout)
                    original = obj.read_bytes()
                    linked = elf.read_bytes()
                    self.assertEqual(report['artifact_sha256'], sha256(linked).hexdigest())
                    self.assertEqual(report['object_sha256'], sha256(original).hexdigest())
                    self.assertEqual(report['machine_proof']['obligations_proven'], 5)
                    self.assertEqual(supplied_verdict(cli, source, original, linked), 1)
                    self.assertNotEqual(supplied_verdict(cli, checked_source(typ, alternate[op]), original, linked), 1)
                    entry = ctypes.CDLL(str(elf)).calculate
                    word = getattr(ctypes, 'c_' + ('int' if typ.startswith('i') else 'uint') + typ[1:])
                    entry.argtypes = [word, word]
                    entry.restype = word
                    self.assertEqual(entry(left, right), expected)
