"""Finite differential controls for the one-limb integer-decimal branch.

The reference is the complete already-closed pre-change HIA, not a new
generation or a matching-cold claim.  Source4 invokes the old and new helper
with identical complete workspaces.  Native4 uses the actual public entry of
both executable images and retains every packet and full buffer before/after.
The existing Source8, Native8, 89 methods and five-second assertion are intact.
"""
from __future__ import annotations

import ast
import base64
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import unittest
from unittest.mock import patch
import zlib

from hepta import hia_json_wire_native as native

ROOT = Path(__file__).resolve().parents[1]
OLD_ASSEMBLY = ROOT / 'tests/fixtures/hia_json_wire_leaf05_pre_u32_decimal.hiaasm'
OLD_ASSEMBLY_SHA256 = 'c2a90ab12eaad558356d3ceca0051a2d87266deaf38039b6d0c1e61831d86792'
OLD_AUTHOR_SHA256 = '04117743984d1c4d15de6f9a9ff0077f5e28fa6209701f2e85eab7c4a0f30b2a'
OLD_IMAGE_SHA256 = '191d82ef912253aa86bca538798269a696fa88b6aa8c27c8e06e6ded5e8bcb8d'
NATIVE_FIXTURE = 'HEPTA_HIA_JSON_WIRE_U32_DECIMAL_FIXTURE'
SOURCE_CASE_COUNTS = (0, 30, 118, 18)
NATIVE_CASE_COUNTS = (30, 54, 16, 10)
BOUNDARIES = (0, 1, 999999999, 1000000000, 1000000001,
              1999999999, 2000000000, 2000000001,
              2999999999, 3000000000, 3000000001,
              3999999999, 4000000000, 4000000001, 4294967295)
MULTI_LIMB = (1 << 32, (1 << 32) + 1, (1 << 64) - 1, 1 << 64,
              10 ** 27 - 1, 10 ** 27, 10 ** 27 + 1, (1 << 96) - 1)
LIMIT_PAIRS = ((0, 0), (1, 0), (9, 0), (10, 0), (11, 0),
               (32, 1), (32, 9), (32, 10), (32, 11))
SOURCE_OBSERVATIONS = []
NATIVE_OBSERVATIONS = []
NATIVE_CASES = []
OLD_BLOCK = "            quotient = 0\n            bit = 32\n            while bit > 0:\n                bit = bit - 1\n                carry = (carry << 1) | ((value >> bit) & 1)\n                if carry >= 1000000000:\n                    carry = carry - 1000000000\n                    quotient = quotient | (1 << bit)\n"
NEW_BLOCK = "            quotient = 0\n            if words == 1:\n                if value < 2000000000:\n                    quotient = choose(value < 1000000000, 0, 1)\n                elif value < 3000000000:\n                    quotient = 2\n                else:\n                    quotient = choose(value < 4000000000, 3, 4)\n                carry = value - quotient * 1000000000\n            else:\n                bit = 32\n                while bit > 0:\n                    bit = bit - 1\n                    carry = (carry << 1) | ((value >> bit) & 1)\n                    if carry >= 1000000000:\n                        carry = carry - 1000000000\n                        quotient = quotient | (1 << bit)\n"


def _packed(raw):
    """Losslessly retain full buffer bytes without repeating zero padding."""
    raw = bytes(raw)
    compressed = zlib.compress(raw)
    if zlib.decompress(compressed) != raw:
        raise AssertionError('full observation compression mismatch')
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
            'encoding': 'zlib-base64',
            'data': base64.b64encode(compressed).decode('ascii')}


def _unpacked(row):
    raw = zlib.decompress(base64.b64decode(row['data'], validate=True))
    if len(raw) != row['bytes'] or sha256(raw).hexdigest() != row['sha256']:
        raise AssertionError('full observation restoration mismatch')
    return raw


def _workspace(value, negative, maximum=128, limit=0, *, limbs=None,
               target=512, limb_base=768):
    from tools.generate_hia_json_wire import FIELDS
    if limbs is None:
        limbs = []
        remaining = value
        while remaining:
            limbs.append(remaining & 0xffffffff)
            remaining >>= 32
        if not limbs:
            limbs = [0]
    raw = bytearray(b'\xa5' * 1024)
    fields = {'N_LIMBS': len(limbs), 'N_A': int(negative),
              'N_TARGET': target, 'LIMB_BASE': limb_base, 'MAX': maximum,
              'N_LIMIT': limit, 'PHASE': 27, 'N_COUNT': 0x1122334455667788}
    for name, number in fields.items():
        struct.pack_into('<Q', raw, FIELDS[name], number)
    for index, limb in enumerate(limbs):
        struct.pack_into('<I', raw, limb_base + index * 4, limb)
    return bytes(raw)


def _helper(program, function, raw):
    from hepta.hia_program_runtime import _Machine, _Owner, _View
    owner = _Owner(-1, bytearray(raw))
    machine = _Machine(program, 10000000, 64 << 20, None, 128)
    result = None
    error = None
    try:
        result = machine.invoke(function, [_View(owner, True)])
    except BaseException as exc:
        error = {'type': type(exc).__module__ + '.' + type(exc).__qualname__,
                 'args': [str(arg) for arg in exc.args],
                 'code': getattr(exc, 'code', None)}
    return {'result': result, 'error': error, 'workspace': bytes(owner.data).hex()}


class WireU32DecimalSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from hepta.hia_agent_assembly import assemble_program
        from tools.generate_hia_json_wire import source_program
        raw = OLD_ASSEMBLY.read_bytes()
        if len(raw) != 363463 or sha256(raw).hexdigest() != OLD_ASSEMBLY_SHA256:
            raise AssertionError('complete frozen old HIA changed')
        cls.programs = (assemble_program(raw), assemble_program(native.SOURCE.read_bytes()))
        names = [node.name for node in ast.parse(source_program()).body]
        if len(names) != len(set(names)) or names.count('integer_decimal') != 1:
            raise AssertionError('unique complete helper-name mapping')
        symbol = 'f' + str(names.index('integer_decimal'))
        cls.functions = []
        for program in cls.programs:
            functions = program.as_dict()['functions']
            if [fn['name'] for fn in functions] != ['f' + str(i) for i in range(len(names))]:
                raise AssertionError('old/new function-symbol populations differ')
            cls.functions.append(next(fn for fn in functions if fn['name'] == symbol))

    def compare(self, label, raw, *, trap=False):
        old = _helper(self.programs[0], self.functions[0], raw)
        new = _helper(self.programs[1], self.functions[1], raw)
        row = {'method': self.id(), 'case': label, 'before': raw.hex(),
               'old': old, 'new': new}
        SOURCE_OBSERVATIONS.append(row)  # Preserve both actuals before assertion.
        self.assertEqual(new, old)
        if trap:
            self.assertEqual(old['error']['type'], 'hepta.hia_program_runtime.HIAProgramTrap')
            self.assertEqual(old['error']['code'], 'bounds')
            self.assertIsNone(old['result'])
        else:
            self.assertIsNone(old['error'])
            self.assertEqual(len(old['result']), 1)
            self.assertIs(type(old['result'][0]), int)
            self.assertIn(old['result'][0], (0, 112))
        return row

    def normal(self, label, value, negative, maximum, limit):
        from tools.generate_hia_json_wire import FIELDS
        before = _workspace(value, negative, maximum, limit)
        row = self.compare(label, before)
        digits = str(value).encode('ascii')
        status = 112 if limit and len(digits) > limit else 0
        self.assertEqual(row['new']['result'], [status])
        after = bytes.fromhex(row['new']['workspace'])
        count = struct.unpack_from('<Q', before, FIELDS['N_LIMBS'])[0]
        self.assertEqual(after[768:768 + count * 4], b'\0' * (count * 4))
        if status == 112:
            self.assertEqual(after[FIELDS['N_COUNT']:FIELDS['N_COUNT'] + 8],
                             before[FIELDS['N_COUNT']:FIELDS['N_COUNT'] + 8])
            self.assertEqual(after[FIELDS['PHASE']:FIELDS['PHASE'] + 8],
                             before[FIELDS['PHASE']:FIELDS['PHASE'] + 8])
        else:
            self.assertEqual(struct.unpack_from('<Q', after, FIELDS['N_COUNT'])[0],
                             len(digits) + int(negative))
            self.assertEqual(struct.unpack_from('<Q', after, FIELDS['PHASE'])[0], 29)
            if len(digits) <= maximum:
                expected = (b'-' if negative else b'') + digits
                self.assertEqual(after[512:512 + len(expected)], expected)
        return row

    def test_01_exact_author_inverse_and_original_nine_caps(self):
        from hepta.hia_agent_assembly import render_assembly, assemble_program
        from tools.generate_hia_json_wire import document, FIELDS
        author = (ROOT / 'tools/generate_hia_json_wire.py').read_text()
        self.assertEqual(author.count(NEW_BLOCK), 1)
        self.assertEqual(sha256(author.replace(NEW_BLOCK, OLD_BLOCK, 1).encode()).hexdigest(),
                         OLD_AUTHOR_SHA256)
        self.assertEqual(native.LEAF_MAGIC, int.from_bytes(b'HIAWIR05', 'little'))
        self.assertEqual(native.MAXIMUM, 8 << 20)
        self.assertEqual([FIELDS[name] for name in ('MAX', 'LIMB_BASE', 'N_A', 'N_TARGET',
                         'N_COUNT', 'N_LIMBS', 'N_LIMIT', 'PHASE')],
                         [32, 272, 352, 376, 392, 400, 416, 24])
        current = render_assembly(document()).encode()
        self.assertEqual(current, native.SOURCE.read_bytes())
        for raw in (OLD_ASSEMBLY.read_bytes(), current):
            doc = assemble_program(raw).as_dict()
            self.assertEqual(render_assembly(doc).encode(), raw)
            functions = doc['functions']
            blocks = [block for fn in functions for block in fn['blocks']]
            self.assertLessEqual(len(raw), 1 << 20)
            self.assertLessEqual(len(raw.splitlines()), 16384)
            self.assertLessEqual(len(functions), 128)
            self.assertLessEqual(len(blocks), 1536)
            self.assertLessEqual(sum(len(block['ops']) + 1 for block in blocks), 8192)
            for fn in functions:
                self.assertLessEqual(len(fn['blocks']), 256)
                self.assertLessEqual(len(fn['params']), 16)
                self.assertLessEqual(len(fn['returns']), 3)
                definitions = {v['name'] for v in fn['params']}
                for block in fn['blocks']:
                    self.assertLessEqual(len(block['params']), 16)
                    definitions.update(v['name'] for v in block['params'])
                    for op in block['ops']:
                        self.assertLessEqual(len(op.get('args', [])), 16)
                        self.assertLessEqual(len(op['out']), 3)
                        definitions.update(v['name'] for v in op['out'])
                    term = block['term']
                    for edge in ('then', 'else'):
                        if edge in term:
                            self.assertLessEqual(len(term[edge]['args']), 16)
                    self.assertLessEqual(len(term.get('args', [])), 16)
                    self.assertLessEqual(len(term.get('values', [])), 16)
                self.assertLessEqual(len(definitions), 2048)

    def test_02_all_u32_quotient_boundaries_both_signs(self):
        for value in BOUNDARIES:
            for negative in (False, True):
                with self.subTest(value=value, negative=negative):
                    self.normal(f'u32:{value}:{int(negative)}', value, negative, 128, 0)

    def test_03_maximum_digit_limits_and_multilimb_to_single(self):
        for value in (999999999, 1000000000, 4294967295):
            for negative in (False, True):
                for maximum, limit in LIMIT_PAIRS:
                    with self.subTest(value=value, negative=negative, maximum=maximum, limit=limit):
                        self.normal(f'limits:{value}:{int(negative)}:{maximum}:{limit}',
                                    value, negative, maximum, limit)
        for value in MULTI_LIMB:
            digits = len(str(value))
            for negative in (False, True):
                for limit in (0, digits - 1, digits, digits + 1):
                    with self.subTest(value=value, negative=negative, limit=limit):
                        self.normal(f'multi:{value}:{int(negative)}:{limit}', value, negative,
                                    native.MAXIMUM, limit)

    def test_04_complete_partial_traps_and_nonminimal_limb_storage(self):
        from tools.generate_hia_json_wire import FIELDS
        full = _workspace(4294967295, False)
        for size in (0, 7, 400, 407, 768, 769, 770, 771):
            self.compare(f'cut:{size}', full[:size], trap=True)
        self.compare('partial-limit-read',
                     _workspace(12345, False, limb_base=64, target=128)[:423], trap=True)
        for value, maximum in ((1, 128), (0, 0)):
            self.compare(f'target-outside:{value}:{maximum}',
                         _workspace(value, False, maximum, target=1024), trap=maximum != 0)
        for negative in (False, True):
            self.compare(f'partial-digit-stores:{int(negative)}',
                         _workspace(12345, negative, target=1022), trap=True)
        for negative in (False, True):
            raw = bytearray(_workspace(1, negative))
            struct.pack_into('<Q', raw, FIELDS['N_TARGET'], (1 << 64) - 1)
            self.compare(f'target-wrap:{int(negative)}', bytes(raw), trap=True)
        raw = bytearray(_workspace(1, False))
        struct.pack_into('<Q', raw, FIELDS['LIMB_BASE'], (1 << 64) - 1)
        self.compare('limb-address-overflow', bytes(raw), trap=True)
        self.compare('two-limbs-high-zero', _workspace(1, False, limbs=[1, 0]))
        self.compare('three-limbs-high-zero',
                     _workspace(4294967295, True, limbs=[4294967295, 0, 0]))


def _guarded(raw):
    raw = bytes(raw)
    owner = ctypes.create_string_buffer(len(raw) + 32)
    ctypes.memset(owner, 0xa5, len(owner))
    if raw:
        ctypes.memmove(ctypes.addressof(owner) + 16, raw, len(raw))
    return owner, ctypes.c_void_p(ctypes.addressof(owner) + 16)


def _contents(owner, size):
    return ctypes.string_at(ctypes.addressof(owner) + 16, size)


def _canary(owner):
    return owner.raw[:16] + owner.raw[-16:]


class _PublicEntryPair:
    """Only transport/capture; both actual public HIA entries run per step."""
    def __init__(self, case, label, old, current):
        self.case, self.label = case, label
        self.images = (old, current)
        self.calls = 0

    def _entry(self, source, source_size, output, output_size, workspace, workspace_size):
        before = (ctypes.string_at(source, source_size),
                  ctypes.string_at(output, output_size),
                  ctypes.string_at(workspace, workspace_size))
        row = {'method': self.case.id(), 'case': self.label, 'step': self.calls,
               'lengths': [source_size, output_size, workspace_size],
               'before': [_packed(raw) for raw in before], 'actual': []}
        NATIVE_OBSERVATIONS.append(row)  # Preserve PRE even if an actual call fails.
        current_after = None
        for name, image in zip(('reference', 'candidate'), self.images):
            owners, pointers = zip(*(_guarded(raw) for raw in before))
            status = image._entry(pointers[0], source_size, pointers[1], output_size,
                                  pointers[2], workspace_size)
            after = tuple(_contents(owner, size) for owner, size in zip(owners, row['lengths']))
            record = {'role': name, 'returned': status,
                      'after': [_packed(raw) for raw in after],
                      'canaries': [_canary(owner).hex() for owner in owners]}
            row['actual'].append(record)  # Complete raw POST before any assertion.
            if name == 'candidate':
                current_after = after
        old, new = row['actual']
        self.case.assertIs(type(old['returned']), int)
        self.case.assertIs(type(new['returned']), int)
        self.case.assertEqual(new['returned'], old['returned'])
        for position in range(3):
            self.case.assertEqual(_unpacked(old['after'][position]),
                                  _unpacked(new['after'][position]))
        self.case.assertEqual(_unpacked(old['after'][0]), before[0])
        self.case.assertEqual(_unpacked(new['after'][0]), before[0])
        self.case.assertEqual(old['canaries'], [b'\xa5'.hex() * 32] * 3)
        self.case.assertEqual(new['canaries'], old['canaries'])
        ctypes.memmove(output, current_after[1], output_size)
        ctypes.memmove(workspace, current_after[2], workspace_size)
        self.calls += 1
        return new['returned']


class WireU32DecimalNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = os.environ.get(NATIVE_FIXTURE)
        if not path:
            raise unittest.SkipTest('requires explicit finite old/new wire image fixture')
        fixture = json.loads(Path(path).read_bytes())
        if fixture['scope'] != 'EXPLICIT_DEVELOPMENT_DIFFERENTIAL_ONLY':
            raise AssertionError('finite historical reference scope changed')
        old_raw = OLD_ASSEMBLY.read_bytes()
        if sha256(old_raw).hexdigest() != OLD_ASSEMBLY_SHA256:
            raise AssertionError('complete old HIA fixture changed')
        image_raw = Path(fixture['reference_image']).read_bytes()
        if (fixture['reference_source_sha256'] != OLD_ASSEMBLY_SHA256
                or fixture['reference_image_sha256'] != OLD_IMAGE_SHA256
                or len(image_raw) != 448572
                or sha256(image_raw).hexdigest() != OLD_IMAGE_SHA256):
            raise AssertionError('closed historical reference image differs')
        cls.reference = native.NativeJsonWire(image_raw, OLD_IMAGE_SHA256)
        cls.reference._bind_manifest_source(OLD_ASSEMBLY_SHA256)
        cls.image = native.installed_json_wire(fixture['candidate_manifest'])
        if (cls.image.admitted_source_sha256 != sha256(native.SOURCE.read_bytes()).hexdigest()
                or cls.image.admitted_source_sha256 == OLD_ASSEMBLY_SHA256):
            raise AssertionError('candidate must bind its newly generated source')
        cls.scope = fixture['scope']

    def session(self, value, maximum, label):
        observer = native.ForeignGraphObserver()
        pair = _PublicEntryPair(self, label, self.reference, self.image)
        session = native.WireSession(pair, observer, observer.register(value), maximum,
            ensure_ascii=False, sort_keys=True, _builtin_keys=True,
            _builtin_key_summaries=True, _builtin_leaves=True)
        self.assertEqual(session._protocol_magic, native.LEAF_MAGIC)
        self.assertEqual(bytes(session.workspace), b'\0' * len(session.workspace))
        return session, pair

    def run_pair(self, label, value, maximum=128, limit=0):
        session, pair = self.session(value, maximum, label)
        row = {'method': self.id(), 'case': label, 'maximum': maximum, 'digit_limit_reply': limit,
               'first_entry': len(NATIVE_OBSERVATIONS), 'status': None, 'exception': None,
               'observations': []}
        NATIVE_CASES.append(row)
        packet = session.packet
        try:
            while True:
                status = session.step(packet)
                row['status'] = status
                if status != 1:
                    break
                original = session.observe()
                packet = original
                if struct.unpack_from('<Q', packet, 16)[0] == native.DIGIT_LIMIT:
                    packet = bytearray(packet)
                    struct.pack_into('<Q', packet, 24, limit)
                    packet = bytes(packet)
                row['observations'].append({'original_reply': original.hex(), 'supplied_reply': packet.hex()})
            if status == 2:
                count = struct.unpack_from('<Q', session.workspace, 112)[0]
                self.assertLessEqual(count, session.output_size)
                self.assertEqual(ctypes.string_at(session.output, count), str(value).encode('ascii'))
            else:
                self.assertIn(status, native.REASONS)
        except BaseException as exc:
            row['exception'] = {'type': type(exc).__name__, 'message': str(exc)}
            raise
        finally:
            row['entries'] = pair.calls
            row['last_entry'] = len(NATIVE_OBSERVATIONS)
        self.assertGreater(pair.calls, 0)
        return row

    def test_01_public_entry_u32_boundaries_and_signs(self):
        for value in BOUNDARIES:
            for negative in (False, True):
                self.run_pair(f'u32:{value}:{int(negative)}', -value if negative else value)

    def test_02_public_entry_maximum_and_digit_limit_replies(self):
        for value in (999999999, 1000000000, 4294967295):
            for negative in (False, True):
                for maximum, limit in LIMIT_PAIRS:
                    self.run_pair(f'limits:{value}:{int(negative)}:{maximum}:{limit}',
                                  -value if negative else value, maximum, limit)

    def test_03_public_entry_multilimb_reaches_single_limb(self):
        for value in MULTI_LIMB:
            for negative in (False, True):
                self.run_pair(f'multi:{value}:{int(negative)}', -value if negative else value, 128, 0)

    def test_04_public_entry_full_budget_extents_and_protocol_refusals(self):
        for value, maximum in ((0, native.MAXIMUM), (4294967295, native.MAXIMUM),
                               (1, native.MAXIMUM + 1), (1, -1)):
            self.run_pair(f'full-budget:{value}:{maximum}', value, maximum)
        for mode in ('short-packet', 'bad-magic', 'old-magic-current-extent',
                     'short-workspace', 'short-output', 'wrong-ack-sequence'):
            session, pair = self.session(1, 32, mode)
            row = {'method': self.id(), 'case': mode, 'first_entry': len(NATIVE_OBSERVATIONS)}
            NATIVE_CASES.append(row)
            packet = session.packet
            output_size = session.output_size
            workspace_size = len(session.workspace)
            if mode == 'short-packet':
                packet = packet[:103]
            elif mode in ('bad-magic', 'old-magic-current-extent'):
                packet = bytearray(packet)
                struct.pack_into('<Q', packet, 0, 0 if mode == 'bad-magic' else native.KEY_SUMMARY_MAGIC)
                packet = bytes(packet)
            elif mode == 'short-workspace':
                workspace_size -= 1
            elif mode == 'short-output':
                output_size -= 1
            elif mode == 'wrong-ack-sequence':
                self.assertEqual(session.step(), 1)
                packet = bytearray(session.observe())
                struct.pack_into('<Q', packet, 8, struct.unpack_from('<Q', packet, 8)[0] + 1)
                packet = bytes(packet)
            status = pair._entry(packet, len(packet), session.output, output_size,
                                 session.workspace, workspace_size)
            row.update(status=status, entries=pair.calls, last_entry=len(NATIVE_OBSERVATIONS))
            self.assertEqual(status, 199)


if __name__ == '__main__':
    unittest.main()
