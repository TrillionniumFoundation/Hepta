"""Source-only adversarial controls for the independently read byte DAG."""
from unittest import TestCase

from tools import core_byte_facts_dag as dag

NS = 'HiaCoreSyntaxSlice.Test'


def source(*lines):
    return 'namespace ' + NS + '\n' + ''.join(line + '\n' for line in lines) + 'end ' + NS + '\n'


def definition(name, rhs):
    return 'def ' + name + ' : List Nat := ' + rhs


class ByteExpressionTests(TestCase):
    def test_frozen_ast(self):
        self.assertEqual(dag.parse_rhs('(a ++ [1,2]) ++ (44 :: b)'),
                         ('append', ('append', ('ref', 'a'), ('literal', (1, 2))),
                          ('cons', 44, ('ref', 'b'))))
        self.assertEqual(dag.parse_rhs('[]'), ('literal', ()))
        self.assertEqual(dag.parse_rhs('0 :: ([255] ++ a)'),
                         ('cons', 0, ('append', ('literal', (255,)), ('ref', 'a'))))

    def test_reject_unknown_ambiguous_or_noncanonical_rhs(self):
        bad = ('a ++ b ++ c', '1 :: a ++ b', '1 :: 2 :: a', 'a ++ 1 :: b',
               'a b', 'List.nil', 'Other.a', 'a.1', '_a', '[] : List Nat',
               '[01]', '[00]', '[+1]', '[-1]', '[0x10]', '[1_0]', '[256]',
               '[١]', '[1, 2]', '[ 1]', '[1 ]', '[1,]', '[,1]', '[1,,2]',
               '[] ', ' []', 'a++b', 'a  ++ b', '( a)', '(a )', '(a', 'a)',
               '', '1', '01 :: a', '256 :: a', 'a\n', 'a\tb', 'by exact a',
               'a -- comment', 'a /- comment -/', '["1"]', '[1;2]',
               '[' + '1' * 10000 + ']')
        for rhs in bad:
            with self.subTest(rhs=rhs[:60]), self.assertRaises(ValueError):
                dag.parse_rhs(rhs)

    def test_depth_limit_exact_boundary(self):
        self.assertEqual(dag.parse_rhs('(' * 32 + 'a' + ')' * 32), ('ref', 'a'))
        for n in (33, 10000):
            with self.assertRaisesRegex(ValueError, 'depth'):
                dag.parse_rhs('(' * n + 'a' + ')' * n)

    def test_token_limit(self):
        # '[' + n numerals + n-1 commas + ']' = 2n+1 tokens.
        self.assertEqual(len(dag.parse_rhs('[' + ','.join(['1'] * 2047) + ']')[1]), 2047)
        with self.assertRaisesRegex(ValueError, 'token'):
            dag.parse_rhs('[' + ','.join(['1'] * 2048) + ']')


class ByteDagTests(TestCase):
    def analyze(self, *lines, expected=b'\x01\x02'):
        return dag.analyze(source(*lines), NS, 'demo', expected)

    def test_original_order_reachability_full_bytes_and_offsets(self):
        lines = (definition('dead', '[99]'), definition('second', '[2]'),
                 definition('first', '[1]'), definition('b0', 'first ++ second'),
                 definition('demoBytes', 'b0'))
        result = self.analyze(*lines)
        self.assertEqual(tuple(r['name'] for r in result['rows']),
                         ('second', 'first', 'b0', 'demoBytes'))
        self.assertEqual(result['root'], 'demoBytes')
        self.assertEqual(result['rows'][-1]['value'], (1, 2))
        raw = source(*lines).encode()
        for row in result['rows']:
            self.assertEqual(raw[row['source_start']:row['source_end']],
                             (definition(row['name'], row['rhs']) + '\n').encode())
        with self.assertRaises(TypeError):
            result['root'] = 't0'
        with self.assertRaises(TypeError):
            result['rows'][0]['value'] = ()
        self.assertEqual(result['graph_digest'], self.analyze(*lines)['graph_digest'])

    def test_wrong_same_length_bytes_prefix_and_append_order(self):
        for rhs in ('[2,1]', '[1]', 'a ++ b', 't0'):
            with self.subTest(rhs=rhs), self.assertRaises(ValueError):
                self.analyze(definition('a', '[2]'), definition('b', '[1]'),
                             definition('t0', '[9,9]'), definition('demoBytes', rhs))

    def test_duplicate_unknown_forward_cycles_and_wrong_type(self):
        cases = (
            (definition('demoBytes', 'unknown'),),
            (definition('demoBytes', 'later'), definition('later', '[1,2]')),
            (definition('a', 'b'), definition('b', 'a'), definition('demoBytes', 'a')),
            (definition('a', 'a'), definition('demoBytes', 'a')),
            (definition('a', '[1,2]'), definition('a', '[1,2]'), definition('demoBytes', 'a')),
            ('def a : Raw := .num 1', definition('demoBytes', 'a')),
            (definition('a', '[1,2]'), 'theorem a : True := by trivial', definition('demoBytes', 'a')),
            (definition('demoByte', '[1,2]'),),
            (definition('dead', 'missing'), definition('demoBytes', '[1,2]')),
            (definition('dead', '[256]'), definition('demoBytes', '[1,2]')),
        )
        for lines in cases:
            with self.subTest(lines=lines), self.assertRaises(ValueError):
                self.analyze(*lines)

    def test_scoping_namespace_and_lexical_hiding(self):
        valid = source(definition('demoBytes', '[1,2]'))
        bad = (
            valid.replace(NS, NS + '.Other'),
            valid.replace('def demoBytes', 'def Other.demoBytes'),
            valid.replace('def demoBytes', 'namespace Other\ndef demoBytes'),
            valid.replace('def demoBytes', 'end ' + NS + '\nnamespace ' + NS + '\ndef demoBytes'),
            valid.replace('def demoBytes', '/-\ndef demoBytes'),
            valid.replace('def demoBytes', '-- def hidden\ndef demoBytes'),
            valid.replace('def demoBytes', '  def demoBytes'),
            valid.replace('def demoBytes', 'private def demoBytes'),
            valid.replace('\n', '\r\n'), valid + '\n', '\n' + valid,
            valid.replace('def demoBytes', 'section\ndef demoBytes'),
            valid.replace('def demoBytes', 'open Other\ndef demoBytes'),
            valid.replace('def demoBytes', 'notation "demoBytes" => []\ndef demoBytes'),
        )
        for value in bad:
            with self.subTest(value=value[:100]), self.assertRaises(ValueError):
                dag.analyze(value, NS, 'demo', b'\x01\x02')

    def test_vertex_and_reference_edge_limits(self):
        lines = [definition('a' + str(i), '[]') for i in range(4095)]
        self.assertEqual(len(self.analyze(*lines, definition('demoBytes', 'a0'), expected=b'')['rows']), 2)
        with self.assertRaisesRegex(ValueError, 'vertex'):
            self.analyze(*lines, definition('extra', '[]'), definition('demoBytes', 'a0'), expected=b'')
        lines = [definition('base', '[]')]
        lines += [definition('a' + str(i), '(base ++ base) ++ base') for i in range(2730)]
        self.analyze(*lines, definition('demoBytes', 'base'), expected=b'')
        with self.assertRaisesRegex(ValueError, 'edge'):
            self.analyze(*lines, definition('extra', 'base ++ base'), definition('demoBytes', 'base'), expected=b'')

    def test_long_alias_chain_uses_iterative_graph_traversal(self):
        lines = [definition('a0', '[1,2]')]
        lines += [definition('a' + str(i), 'a' + str(i - 1)) for i in range(1, 4000)]
        result = self.analyze(*lines, definition('demoBytes', 'a3999'))
        self.assertEqual(len(result['rows']), 4001)
        self.assertEqual(result['rows'][-1]['value'], (1, 2))

    def test_expansion_and_input_limits(self):
        lines = [definition('a0', '[1]')]
        lines += [definition('a' + str(i), 'a' + str(i - 1) + ' ++ a' + str(i - 1)) for i in range(1, 16)]
        self.analyze(*lines, definition('demoBytes', 'a15'), expected=b'\x01' * 32768)
        for rhs in ('1 :: a15', 'a15 ++ a0'):
            with self.assertRaisesRegex(ValueError, 'length'):
                self.analyze(*lines, definition('demoBytes', rhs), expected=b'')
        with self.assertRaises(ValueError):
            self.analyze(definition('demoBytes', '[]'), expected=b'\x01' * 32769)
        with self.assertRaises(ValueError):
            self.analyze(definition('demoBytes', '[]'), expected=[1, 2])
        with self.assertRaisesRegex(ValueError, 'source'):
            dag.analyze(' ' * (dag.MAX_SOURCE_BYTES + 1), NS, 'demo', b'')

    def test_changed_data_changes_digest_even_if_reachable_value_same(self):
        a = self.analyze(definition('demoBytes', '[1,2]'))
        b = self.analyze(definition('demoBytes', '(1 :: [2])'))
        self.assertNotEqual(a['graph_digest'], b['graph_digest'])
        self.assertNotEqual(a['source_sha256'], b['source_sha256'])


class OriginalByteDagTests(TestCase):
    @classmethod
    def setUpClass(cls):
        from tools import core_syntax_structured_stages
        cls.prepared = core_syntax_structured_stages.build_inputs()

    def test_all_five_complete_original_graphs(self):
        for key, cert in self.prepared['structured_certificates'].items():
            with self.subTest(key=key):
                m = cert['manifest']
                result = dag.analyze(cert['source'], m['namespace'], m['stem'],
                                     self.prepared['binding_inputs'][key]['bytes'])
                rows = result['rows']
                self.assertEqual(len(rows), 595)
                self.assertEqual(sum(r['ast'][0] == 'literal' for r in rows), 281)
                self.assertEqual(rows[-1]['name'], m['stem'] + 'Bytes')
                self.assertEqual(rows[-1]['ast'], ('ref', m['stem'] + '_b0'))
                self.assertEqual(rows[-1]['length'], 14585 if key == 'wrong_condition' else 14466)
                seen = set()
                for row in rows:
                    self.assertTrue(set(row['dependencies']) <= seen)
                    seen.add(row['name'])
                self.assertNotIn(m['stem'] + '_t0', seen)

    def test_original_root_short_prefix_substitution(self):
        cert = self.prepared['structured_certificates']['linear']
        m = cert['manifest']
        altered = cert['source'].replace('def linearBytes : List Nat := linear_b0',
                                         'def linearBytes : List Nat := [1,2]')
        self.assertNotEqual(altered, cert['source'])
        with self.assertRaisesRegex(ValueError, 'complete original'):
            dag.analyze(altered, m['namespace'], m['stem'], self.prepared['binding_inputs']['linear']['bytes'])
