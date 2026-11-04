"""Policy snapshots and exact structured admission thresholds."""
from dataclasses import FrozenInstanceError, asdict, replace
from pathlib import Path
import tempfile
import unittest

from experiments.loader_budget.prototype import Rejected as ReaderRejected
from experiments.package_copy.owner import Limits as PreviousLimits, _COPY
from experiments.package_copy.test_owner import package, observed
from .owner import Owner, Policy, Failure, Rejected


class PolicyTests(unittest.TestCase):
    def test_defaults_match_all_inherited_limits(self):
        policy = Policy()
        self.assertEqual(policy.version, 'loader-experimental-v1')
        self.assertEqual(dict(policy.limits), asdict(PreviousLimits()))
        self.assertEqual(set(policy.units), set(policy.limits))
        self.assertTrue(all(type(unit) is str and unit for unit in policy.units.values()))

    def test_overrides_are_copied_without_changing_defaults(self):
        values = {'package_copy_calls': 7, 'reads': 3}
        policy = Policy(limits=values)
        values['reads'] = 100
        self.assertEqual(policy.limits['reads'], 3)
        self.assertEqual(policy.limits['package_copy_calls'], 7)
        expected = asdict(PreviousLimits())
        expected.update(package_copy_calls=7, reads=3)
        self.assertEqual(dict(policy.limits), expected)
        self.assertEqual(dict(Policy().limits), asdict(PreviousLimits()))

    def test_all_limit_values_require_exact_positive_ints(self):
        class IntSubclass(int):
            pass
        for name in asdict(PreviousLimits()):
            for value in (0, -1, True, False, 1.0, '1', None, IntSubclass(1)):
                with self.subTest(name=name, value=repr(value)):
                    with self.assertRaises((ValueError, TypeError)):
                        Policy(limits={name: value})

    def test_unknown_limit_is_rejected(self):
        with self.assertRaises((ValueError, TypeError)):
            Policy(limits={'imaginary_visits': 1})

    def test_parser_depth_cannot_relax_existing_ceiling(self):
        with self.assertRaises((ValueError, TypeError)):
            Policy(limits={'parser_depth': 97})
        self.assertEqual(Policy(limits={'parser_depth': 96}).limits['parser_depth'], 96)

    def test_policy_and_mappings_are_frozen(self):
        policy = Policy()
        with self.assertRaises((FrozenInstanceError, AttributeError, TypeError)):
            policy.version = 'other'
        for mapping in (policy.limits, policy.units):
            with self.assertRaises(TypeError):
                mapping['reads'] = 99
        with self.assertRaises((FrozenInstanceError, AttributeError, TypeError)):
            policy.limits = {}


class ThresholdTests(unittest.TestCase):
    def assert_budget(self, owner, operation, dimension, limit, admitted, attempted):
        with self.assertRaises(Rejected) as caught:
            operation()
        failure = caught.exception.failure
        self.assertIsInstance(failure, Failure)
        self.assertIs(owner.context.failure, failure)
        self.assertEqual(failure.category, 'budget')
        self.assertEqual(failure.dimension, dimension)
        self.assertEqual(failure.limit, limit)
        self.assertEqual(failure.admitted, admitted)
        self.assertEqual(failure.attempted, attempted)
        self.assertIsInstance(failure.phase, str)
        self.assertTrue(failure.phase)
        self.assertTrue(owner.context.closed)
        return failure

    def test_every_generic_count_accepts_exact_limit(self):
        counts = Owner().context.counts
        for name in counts:
            with self.subTest(dimension=name):
                owner = Owner(policy=Policy(limits={name: 2}))
                owner.context.charge(name)
                owner.context.charge(name)
                self.assertEqual(owner.context.counts[name], 2)
                self.assertIsNone(owner.context.failure)
                self.assert_budget(owner, lambda: owner.context.charge(name), name, 2, 2, 3)
                self.assertEqual(owner.context.counts[name], 2)

    def test_multi_unit_charge_reports_absolute_attempt_not_delta(self):
        owner = Owner(policy=Policy(limits={'total_tokens': 5}))
        owner.context.charge('total_tokens', 3)
        self.assert_budget(owner, lambda: owner.context.charge('total_tokens', 4),
                           'total_tokens', 5, 3, 7)
        self.assertEqual(owner.context.counts['total_tokens'], 3)

    def test_specialized_count_admissions(self):
        methods = {'copy_visits': 'admit_copy_visit',
                   'transform_visits': 'admit_transform',
                   'authority_visits': 'admit_authority',
                   'package_copy_calls': 'admit_package_call'}
        for name, method in methods.items():
            with self.subTest(dimension=name):
                owner = Owner(policy=Policy(limits={name: 2}))
                admit = getattr(owner.context, method)
                admit(1); admit(1)
                self.assert_budget(owner, lambda: admit(1), name, 2, 2, 3)
                self.assertEqual(owner.context.counts[name], 2)
        owner = Owner(policy=Policy(limits={'shallow_fields': 2}))
        owner.context.admit_shallow_field(); owner.context.admit_shallow_field()
        self.assert_budget(owner, owner.context.admit_shallow_field,
                           'shallow_fields', 2, 2, 3)

    def test_specialized_depth_admissions(self):
        methods = {'copy_depth': ('admit_copy_visit', 'copy_visits'),
                   'transform_depth': ('admit_transform', 'transform_visits'),
                   'authority_depth': ('admit_authority', 'authority_visits'),
                   'package_copy_depth': ('admit_package_call', 'package_copy_calls')}
        for name, (method, counter) in methods.items():
            with self.subTest(dimension=name):
                owner = Owner(policy=Policy(limits={name: 2}))
                admit = getattr(owner.context, method)
                admit(2)
                self.assert_budget(owner, lambda: admit(3), name, 2, None, 3)
                self.assertEqual(owner.context.counts[counter], 1)

    def test_real_package_copy_count_boundary(self):
        value = package()
        count = len(observed(value)[1])
        owner = Owner(policy=Policy(limits={'package_copy_calls': count}))
        result = owner._authority_copy(_COPY, value, 'package')
        self.assertEqual(result, value)
        self.assertIsNot(result, value)
        self.assertEqual(owner.context.counts['package_copy_calls'], count)
        owner = Owner(policy=Policy(limits={'package_copy_calls': count - 1}))
        self.assert_budget(owner, lambda: owner._authority_copy(_COPY, value, 'package'),
                           'package_copy_calls', count - 1, count - 1, count)

    def test_real_package_copy_depth_boundary(self):
        value = package()
        depth = max(d for _, d in observed(value)[1])
        Owner(policy=Policy(limits={'package_copy_depth': depth}))._authority_copy(_COPY, value, 'package')
        owner = Owner(policy=Policy(limits={'package_copy_depth': depth - 1}))
        self.assert_budget(owner, lambda: owner._authority_copy(_COPY, value, 'package'),
                           'package_copy_depth', depth - 1, None, depth)

    def test_failure_is_frozen_and_terminal_attempt_preserves_first(self):
        owner = Owner(policy=Policy(limits={'modules': 1}))
        owner.context.charge('modules')
        failure = self.assert_budget(owner, lambda: owner.context.charge('modules'),
                                     'modules', 1, 1, 2)
        with self.assertRaises((FrozenInstanceError, AttributeError, TypeError)):
            failure.category = 'other'
        with self.assertRaises(Rejected) as caught:
            owner.context.check()
        self.assertIs(caught.exception.failure, failure)
        self.assertIs(owner.context.failure, failure)
        self.assertEqual(owner.context.counts['modules'], 1)

    def test_success_and_cumulative_reload_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            entry = Path(directory) / 'main.hepta'
            entry.write_text('fn main()->Unit effects {} {}')
            owner = Owner(policy=Policy(limits={'transform_visits': 27}))
            owner.load(entry)
            self.assertIsNone(owner.context.failure)
            failure = self.assert_budget(owner, lambda: owner.load(entry),
                                         'transform_visits', 27, 27, 28)
            self.assertEqual(failure.observed_bytes, owner.context.reader.bytes_read)
            self.assertEqual(failure.observed_reads, owner.context.reader.reads)

    def test_swallowed_nested_load_keeps_first_failure_and_stops_work(self):
        with tempfile.TemporaryDirectory() as directory:
            entry = Path(directory) / 'main.hepta'
            entry.write_text('fn main()->Unit effects {} {}')
            nested = []
            owner = None
            def checkpoint():
                try:
                    owner.load(entry)
                except Rejected as error:
                    nested.append(error.failure)
            owner = Owner(checkpoint=checkpoint)
            with self.assertRaises(Rejected) as caught:
                owner.load(entry)
            self.assertEqual(len(nested), 1)
            self.assertIs(caught.exception.failure, nested[0])
            self.assertIs(owner.context.failure, nested[0])
            self.assertEqual(nested[0].category, 'reentrancy')
            self.assertTrue(all(value == 0 for value in owner.context.counts.values()))
            self.assertEqual(owner.context.reader.reads, 0)
            self.assertEqual(owner._handles, [])

    def test_swallowed_nested_reader_keeps_first_failure_and_stops_work(self):
        with tempfile.TemporaryDirectory() as directory:
            entry = Path(directory) / 'main.hepta'
            entry.write_bytes(b'hello')
            nested = []
            owner = None
            def checkpoint():
                try:
                    owner.context.reader.read(entry)
                except ReaderRejected:
                    nested.append(owner.context.failure)
            owner = Owner(checkpoint=checkpoint)
            with self.assertRaises(Rejected) as caught:
                owner.context.reader.read(entry)
            self.assertEqual(len(nested), 1)
            self.assertIs(caught.exception.failure, nested[0])
            self.assertIs(owner.context.failure, nested[0])
            self.assertEqual(nested[0].category, 'reentrancy')
            self.assertEqual(owner.context.reader.reads, 0)
            self.assertEqual(owner.context.reader.bytes_read, 0)


    def test_context_limits_replacement_detected_before_admission(self):
        owner = Owner()
        owner.context.limits = replace(owner.context.limits, modules=1)
        with self.assertRaises(Rejected) as caught:
            owner.context.charge('modules')
        self.assertEqual(caught.exception.failure.category, 'policy_drift')
        self.assertIs(owner.context.failure, caught.exception.failure)
        self.assertEqual(owner.context.counts['modules'], 0)

    def test_equal_value_limits_replacement_detected(self):
        owner = Owner()
        owner.context.limits = replace(owner.context.limits)
        with self.assertRaises(Rejected) as caught:
            owner.context.check()
        self.assertEqual(caught.exception.failure.category, 'policy_drift')

    def test_reader_chunk_limit_drift_detected(self):
        owner = Owner()
        object.__setattr__(owner.context.reader.limits, 'chunk_bytes', 1)
        with self.assertRaises(Rejected) as caught:
            owner.context.check()
        self.assertEqual(caught.exception.failure.category, 'policy_drift')
        self.assertEqual(owner.context.reader.reads, 0)


    def test_context_limits_forced_mutation_detected(self):
        owner = Owner()
        object.__setattr__(owner.context.limits, 'modules', 1)
        with self.assertRaises(Rejected) as caught:
            owner.context.check()
        self.assertEqual(caught.exception.failure.category, 'policy_drift')
        self.assertEqual(owner.context.counts['modules'], 0)


if __name__ == '__main__':
    unittest.main()
