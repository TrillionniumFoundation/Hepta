"""Differential checks for pure structured-source parsing and local DAG reuse.

The reference expression parser is the exact pre-change adjacent-match algorithm.
These controls grant no Lean, native, or production acceptance.
"""
from copy import deepcopy
from hashlib import sha256
import itertools
import json
import random
import re
import unittest

from tools import core_syntax_structured_sources as s


def legacy_parse(text, env):
    tokens, pos = [], 0
    while pos < len(text):
        match = s._TOKEN.match(text, pos)
        s.require(match is not None, 'unsupported emitted data syntax')
        tokens.append(match.group(1))
        pos = match.end()
    index = 0

    def take(wanted=None):
        nonlocal index
        s.require(index < len(tokens), 'incomplete emitted expression')
        token = tokens[index]
        index += 1
        s.require(wanted is None or wanted == token, 'unexpected emitted token')
        return token

    def atom():
        token = take()
        if token == '(':
            first = expr()
            if index < len(tokens) and tokens[index] == ',':
                take(',')
                first = (first, expr())
            take(')')
            return first
        if token == '[':
            items = []
            if index < len(tokens) and tokens[index] != ']':
                items.append(expr())
                while index < len(tokens) and tokens[index] == ',':
                    take(',')
                    items.append(expr())
            take(']')
            return items
        if token.startswith('.'):
            s.require(token in ('.str', '.num', '.arr', '.obj'), 'unknown Raw constructor')
            return s._Raw(token[1:], atom())
        if token.isdigit():
            return int(token)
        s.require(token in env, 'missing/forward data alias: ' + token)
        return env[token]

    def expr():
        left = atom()
        if index < len(tokens) and tokens[index] in ('::', '++'):
            op = take()
            right = expr()
            s.require(type(right) is list, 'list operator right type')
            if op == '::':
                return [left] + right
            s.require(type(left) is list, 'append left type')
            return left + right
        return left

    result = expr()
    s.require(index == len(tokens), 'unconsumed emitted expression')
    return result


def observed(fn, *args):
    try:
        return ('value', fn(*args))
    except Exception as error:
        return ('error', type(error).__name__, str(error))


class StructuredSourceCostTests(unittest.TestCase):
    def test_expression_tokens_match_complete_legacy_domain(self):
        env = {'xs': [1, 2], 'r': s._Raw('num', 7)}
        examples = ['', ' ', '\t', '[]', '[1,2]', '(.arr [r])',
                    '(.obj [([97], r)])', '1 :: xs', 'xs ++ [3]',
                    '\u2003[1,2]', '[1,2]\u2003', '1 # 2', '1\x00',
                    '.num 1', '.num1', '.num -1', '.num True',
                    '.unknown []', '(xs, [3])', '[r] ++ [r]',
                    '[1] ::: []', 'not_found', 'xsx', '[1,]', '(1,2,3)',
                    '\u00e9', '[1]\n', '[\n1,\t2]', '01', '.num 00']
        # Exhaust all short strings over structural, numeral, alias and gap bytes.
        alphabet = ('[', ']', '(', ')', ',', '1', 'x', ' ', '#')
        examples.extend(''.join(parts) for n in range(5)
                        for parts in itertools.product(alphabet, repeat=n))
        rng = random.Random(601105)
        fragments = ('[]', '[1]', 'xs', 'r', '.num', '1', '2', '::', '++',
                     '(', ')', ',', '\t', '\u2003', '\x00', 'bad', '.')
        examples.extend(' '.join(rng.choices(fragments, k=rng.randrange(1, 12)))
                        for _ in range(2000))
        for text in examples:
            with self.subTest(text=text):
                self.assertEqual(observed(legacy_parse, text, env),
                                 observed(s._parse_expression, text, env))

    def test_expression_aliases_are_read_only_after_publication(self):
        child = s._Raw('num', 9)
        env = {'xs': [child], 'ys': [3, 4]}
        before = deepcopy(env)
        first = s._parse_expression('xs ++ xs', env)
        second = s._parse_expression('2 :: ys', env)
        self.assertEqual(env, before)
        self.assertIsNot(first, env['xs'])
        self.assertIsNot(second, env['ys'])
        self.assertIs(first[0], child)
        self.assertIs(first[1], child)

    def test_tokenizer_rejects_long_gaps_without_searching_each_suffix(self):
        spaces = ' ' * 65536
        for text in ('1' + spaces, spaces, spaces + '#', '1' + spaces + '# 2',
                     'x' * 65536 + '#'):
            with self.subTest(prefix=text[:16], length=len(text)):
                self.assertEqual(observed(legacy_parse, text, {}),
                                 observed(s._parse_expression, text, {}))

    def test_raw_dag_values_match_recursive_reference(self):
        leaf = s._Raw('obj', [([97], s._Raw('str', [65, 66])),
                              ([98], s._Raw('num', 11))])
        values = [leaf]
        for _ in range(8):
            values.append(s._Raw('arr', [values[-1], leaf]))
        values.extend([None, 0, [], s._Raw('num', True),
                       s._Raw('num', -1), s._Raw('num', s.old.MAX_INTEGER + 1),
                       s._Raw('str', [31]), s._Raw('str', [34]),
                       s._Raw('str', [92]), s._Raw('str', [127]),
                       s._Raw('str', [65.0]), s._Raw('str', (65,)),
                       s._Raw('arr', (leaf,)), s._Raw('arr', [None]),
                       s._Raw('obj', [[[], leaf]]),
                       s._Raw('obj', [([98], leaf), ([97], leaf)]),
                       s._Raw('obj', [([97], leaf), ([97], leaf)]),
                       s._Raw('obj', [([True], leaf)]),
                       s._Raw('legacy_unknown_kind', [])])
        decoder = s._ParsedRawValues()
        for raw in values:
            with self.subTest(raw=repr(raw)[:200]):
                self.assertEqual(observed(s._raw_value, raw),
                                 observed(decoder.decode, raw))
                self.assertEqual(observed(s._raw_value, raw),
                                 observed(decoder.decode, raw))

    def test_raw_string_byte_domain_is_exact(self):
        class IntSubclass(int):
            pass

        def reference(value):
            s.require(type(value) is list and all(type(n) is int and
                      32 <= n <= 126 and n not in (34, 92) for n in value),
                      'Raw string domain')
            return bytes(value).decode('ascii')

        values = [[n] for n in range(-2, 258)]
        values += [[], [32, 33, 126], [34], [92], [True], [65.0],
                   [IntSubclass(65)], [2**100], (-1,), b'A', None]
        for value in values:
            with self.subTest(value=value):
                self.assertEqual(observed(reference, value),
                                 observed(s._raw_value, s._Raw('str', value)))

    def test_theorem_index_preserves_literal_nonoverlapping_count(self):
        fragments = ('theorem ', 'theorem a ', 'theorem theorem ', 'theorem  ',
                     'prefix_theorem a : ', '\u00e9theorem a : ',
                     '\ntheorem a : x := ', 'theorem a\nb : ',
                     'theorem a\tb : ', 'def a ', 'theorem a')
        literals = ('', 'theorem', 'theorem ', 'theorem a', 'theorem a ',
                    'theorem a : ', 'theorem theorem ', 'theorem theorem theorem ',
                    'theorem  ', 'theorem a\nb ', 'theorem a\tb ', 'def a ')
        sources = list(fragments)
        sources.extend(''.join(parts) for parts in itertools.product(fragments, repeat=3))
        for source in sources:
            index = s._LiteralTheoremCounts(source)
            for literal in literals:
                with self.subTest(source=source, literal=literal):
                    self.assertEqual(index.count(literal), source.count(literal))

    def test_temporary_wrapper_identity_cannot_be_reused(self):
        decoder = s._ParsedRawValues()
        for n in range(2048):
            value = s._Raw('obj', [([97], s._Raw('num', n))])
            self.assertEqual(decoder.decode(value), {'a': n})
            self.assertIs(decoder._values[id(value)][0], value)
        self.assertEqual(len(decoder._values), 4096)
        self.assertEqual(len({id(v[0]) for v in decoder._values.values()}), 4096)

    def test_failed_parent_is_never_cached(self):
        decoder = s._ParsedRawValues()
        raw = s._Raw('arr', [s._Raw('num', 1), s._Raw('num', -1)])
        with self.assertRaisesRegex(ValueError, 'Raw numeric domain'):
            decoder.decode(raw)
        self.assertNotIn(id(raw), decoder._values)
        raw.value[-1] = s._Raw('num', 2)
        self.assertEqual(decoder.decode(raw), [1, 2])

    def test_each_complete_verification_reconstructs_actual_changed_source(self):
        tree = {'sample': [1, 2], 'text': 'ok'}
        data = s.canonical(tree)
        proposal = s.build_structured_input('sample', tree, data,
                                           s.NS + '.CostControl', 'sample', 'sampleCert')
        manifest = proposal.manifest
        wanted = s.verify_structured_source(proposal.source, manifest, tree, data)
        changed = proposal.source.replace('.num 1', '.num 3', 1)
        self.assertNotEqual(changed, proposal.source)
        forged = deepcopy(manifest)
        forged['source_sha256'] = sha256(changed.encode()).hexdigest()
        expressions = {m[1]: m[2] for m in re.finditer(
            r'(?m)^def ([A-Za-z][A-Za-z0-9_]*) : .+? := (.+)$', changed)}
        for row in forged['definitions']:
            row['rhs_sha256'] = sha256(expressions[row['name']].encode()).hexdigest()
        with self.assertRaisesRegex(ValueError, 'full emitted Raw differs'):
            s.verify_structured_source(changed, forged, tree, data)
        self.assertEqual(s.verify_structured_source(proposal.source, manifest, tree, data), wanted)

    def test_caller_equality_cannot_mutate_private_decoded_values(self):
        tree = {'sample': [1, 2], 'text': 'ok'}
        data = s.canonical(tree)
        proposal = s.build_structured_input('sample', tree, data,
                                           s.NS + '.CostControl', 'sample', 'sampleCert')
        changed = proposal.source.replace('.num 1', '.num 3', 1)
        manifest = proposal.manifest
        manifest['source_sha256'] = sha256(changed.encode()).hexdigest()
        expressions = {m[1]: m[2] for m in re.finditer(
            r'(?m)^def ([A-Za-z][A-Za-z0-9_]*) : .+? := (.+)$', changed)}
        for row in manifest['definitions']:
            row['rhs_sha256'] = sha256(expressions[row['name']].encode()).hexdigest()

        class MutatingExpected(dict):
            def __eq__(self, other):
                if type(other) is dict:
                    other.clear()
                    other.update(deepcopy(tree))
                    return True
                return False

        # The caller can lie in an equality method; the subsequent internal
        # source-byte-derived subtree comparison must still reject the change.
        with self.assertRaisesRegex(ValueError, 'exact complete subtree alias binding'):
            s.verify_structured_source(changed, manifest, MutatingExpected(tree), data)


if __name__ == '__main__':
    unittest.main()
