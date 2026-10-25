"""Bounded independent evaluation of source and translated scalar ASTs.

A finite differential oracle, not a theorem. It uses a separate evaluator for
both wire formats and a deliberately wrong-translation negative control.
"""
import copy
import json
import unittest
from hepta.hsir_scalar_bridge import lower_source_bound_scalar
from test_hsir_scalar_bridge import sample


def evaluate_expr(node, env, old):
    if old:
        kind, value, args = node['op'], node['value'], node['args']
    else:
        kind, value, args = node['operation'], node['value'], node['operands']
    if kind == 'name':
        return env[value]
    if kind in ('int', 'bool', 'float'):
        return value
    operands = [evaluate_expr(x, env, old) for x in args]
    if kind == 'binary':
        a, b = operands
        return {'+': lambda: a+b, '-': lambda: a-b, '*': lambda: a*b,
                '<': lambda: a<b, '<=': lambda: a<=b, '>': lambda: a>b,
                '>=': lambda: a>=b, '==': lambda: a==b, '!=': lambda: a!=b}[value]()
    if kind == 'unary':
        return -operands[0] if value == '-' else not operands[0]
    raise AssertionError('unexpected expression '+str(kind))


def run(program, n, old):
    env = {'n': n}
    budget = 1000
    body = program['functions'][0]['body']
    def statements(items):
        nonlocal budget
        for item in items:
            budget -= 1
            if budget < 0:
                raise RuntimeError('step bound')
            op = item['op'] if old else item['operation']
            d = item['data'] if old else item['fields']
            def value(key):
                return evaluate_expr(d[key], env, old)
            if op == 'let':
                env[d['name']] = value('expr')
            elif op == 'assign':
                target = d['target']['value']
                env[target] = value('expr')
            elif op == 'if':
                found = statements(d['then'] if value('condition') else d['else'])
                if found is not None:
                    return found
            elif op == 'while':
                while value('condition'):
                    found = statements(d['body'])
                    if found is not None:
                        return found
            elif op == 'return':
                return value('expr')
            else:
                raise AssertionError('unexpected statement '+str(op))
        return None
    return statements(body)


class DifferentialTests(unittest.TestCase):
    def test_finite_oracle_comparison_including_loop_phi(self):
        original = sample()
        translated = json.loads(lower_source_bound_scalar(original)[0])
        for n in range(-10, 50):
            with self.subTest(n=n):
                self.assertEqual(run(original, n, True), run(translated, n, False))
                self.assertEqual(run(translated, n, False), max(0, n))

    def test_intentionally_wrong_translation_is_caught(self):
        old = sample()
        translated = json.loads(lower_source_bound_scalar(old)[0])
        body = translated['functions'][0]['body'][1]['fields']['body'][0]['fields']['then']
        # Deliberately wrong +2 in place of +1, the independent oracle must fail.
        body[0]['fields']['expr']['operands'][1]['value'] = 2
        self.assertNotEqual(run(old, 3, True), run(translated, 3, False))

    def test_producer_not_mutated(self):
        original = sample()
        frozen = copy.deepcopy(original)
        lower_source_bound_scalar(original)
        self.assertEqual(original, frozen)


if __name__ == '__main__':
    unittest.main()
