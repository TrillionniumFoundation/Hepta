import json
from pathlib import Path
import tempfile
import unittest

from hepta.ast import HeptaError
from hepta.modules import load_project
from hepta.packages import write_lock
from experiments.request_load.context import Context, Limits, Rejected
from .contract import Ledger, BudgetExceeded, OverlayRejected, freeze_overrides


class ContractTests(unittest.TestCase):
    def test_fixed_workload_recording_matches_except_checkout_depth(self):
        from .measure import measure
        root = Path(__file__).resolve().parents[2]
        observed = measure(root)
        recorded = json.loads(Path(__file__).with_name('workloads.json').read_text())
        for report in (observed, recorded):
            self.assertEqual(len(report['workloads']), 6)
            for row in report['workloads']:
                self.assertEqual(row['outcome'], 'passed')
                for stage in row['stages']:
                    stage.pop('path_checks')
        self.assertEqual(observed, recorded)

    def test_boundary_terminal_failure_preserves_original_diagnostic(self):
        ledger = Ledger({'reads': 2})
        ledger.charge('reads', 2, phase='initial')
        with self.assertRaises(BudgetExceeded) as first:
            ledger.charge('reads', 1, phase='revalidation')
        self.assertEqual(json.loads(json.dumps(first.exception.diagnostic.to_dict())),
                         dict(code='E_LOAD_BUDGET', phase='revalidation', dimension='reads',
                              limit=2, admitted=2, attempted=3))
        with self.assertRaises(BudgetExceeded) as second:
            ledger.charge('reads', 0, phase='initial')
        self.assertEqual(first.exception.diagnostic, second.exception.diagnostic)
        self.assertNotIsInstance(first.exception, (HeptaError, ValueError))
        self.assertEqual(ledger.counts['reads'], 2)

    def test_overlay_rejects_every_call_after_first_budget_failure(self):
        ledger = Ledger({'override_entries': 0, 'override_bytes': 0})
        with self.assertRaises(BudgetExceeded) as first:
            freeze_overrides({'a.hepta': 'a'}, ledger)
        class Custom(dict):
            pass
        for source in (None, {}, Custom(), [], {'b.hepta': 'b'}):
            with self.assertRaises(BudgetExceeded) as later:
                freeze_overrides(source, ledger)
            self.assertIs(later.exception.diagnostic, first.exception.diagnostic)

    def test_limits_are_copied(self):
        limits = {'reads': 1}
        ledger = Ledger(limits)
        limits['reads'] = 999
        self.assertEqual(ledger.limits['reads'], 1)
        with self.assertRaises(TypeError):
            ledger.limits['reads'] = 999

    def test_bad_charges_cannot_refund(self):
        ledger = Ledger({'reads': 1})
        for amount in [-1, True, 0.5]:
            with self.assertRaises(ValueError):
                ledger.charge('reads', amount, phase='initial')
        with self.assertRaises(ValueError):
            ledger.charge('unknown', 1, phase='initial')
        self.assertEqual(ledger.counts, {'reads': 0})

    def test_none_and_empty_overlay_are_equivalent(self):
        for source in [None, {}]:
            ledger = Ledger({'override_entries': 0, 'override_bytes': 0})
            self.assertEqual(dict(freeze_overrides(source, ledger)), {})
            self.assertEqual(ledger.counts, {'override_entries': 0, 'override_bytes': 0})

    def test_utf8_unused_entries_and_frozen_snapshot(self):
        source = {'unused.hepta': 'é'}
        ledger = Ledger({'override_entries': 1, 'override_bytes': 2})
        frozen = freeze_overrides(source, ledger)
        source['unused.hepta'] = 'mutated'
        self.assertEqual(frozen[str(Path('unused.hepta').resolve())], b'\xc3\xa9')
        with self.assertRaises(TypeError):
            frozen['new'] = b'new'
        self.assertEqual(ledger.counts, {'override_entries': 1, 'override_bytes': 2})

    def test_utf8_budget_rejects_before_retaining_full_input(self):
        ledger = Ledger({'override_entries': 1, 'override_bytes': 2048})
        with self.assertRaises(BudgetExceeded) as error:
            freeze_overrides({'unused.hepta': 'é' * 4096}, ledger)
        self.assertEqual(error.exception.diagnostic.dimension, 'override_bytes')
        self.assertEqual(error.exception.diagnostic.admitted, 2048)
        self.assertEqual(error.exception.diagnostic.attempted, 4096)

    def test_alias_collision_and_callback_containers_are_policy_errors(self):
        ledger = Ledger({'override_entries': 2, 'override_bytes': 2})
        with self.assertRaises(OverlayRejected):
            freeze_overrides({'same.hepta': 'a', './same.hepta': 'b'}, ledger)
        class Custom(dict):
            def items(self):
                raise AssertionError('must not invoke callback')
        with self.assertRaises(OverlayRejected):
            freeze_overrides(Custom(), ledger)

    def test_legacy_override_identity_and_disk_revalidation_are_not_overlay_aware(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'main.hepta'
            path.write_text('fn main() -> i32 effects {} { return 1; }')
            replacement = 'fn main() -> i32 effects {} { return 2; }'
            project = load_project(path, source_overrides={str(path): replacement})
            self.assertEqual(project.source_bytes[str(path)], replacement.encode())
            self.assertFalse(project.unchanged())
            self.assertTrue(project.unchanged(except_paths=[path]))
            self.assertNotEqual(project.identity, load_project(path).identity)

    def test_legacy_unused_overrides_do_not_change_graph_identity(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'main.hepta'
            path.write_text('fn main() -> i32 effects {} { return 1; }')
            self.assertEqual(load_project(path).report(),
                             load_project(path, source_overrides={'unused.hepta': 'bad syntax'}).report())

    def test_lock_validates_disk_inventory_not_overlaid_text(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            path = root / 'main.hepta'
            path.write_text('fn main() -> i32 effects {} { return 1; }')
            (root / 'hepta.toml').write_text('[package]\nname="example"\nversion="1.0.0"\nsource_root="."\nentry="main.hepta"\n')
            write_lock(root)
            overlay = {str(path): 'fn main() -> i32 effects {} { return 2; }'}
            project = load_project(root, locked=True, source_overrides=overlay)
            self.assertTrue(project.locked)
            self.assertEqual(project.source_bytes[str(path)], overlay[str(path)].encode())
            self.assertFalse(project.unchanged())
            path.write_text('fn main() -> i32 effects {} { return 3; }')
            with self.assertRaises(HeptaError) as error:
                load_project(root, locked=True, source_overrides=overlay)
            self.assertEqual(error.exception.diagnostic.code, 'E_LOCK_STALE')

    def test_context_exhaustion_must_not_turn_into_unchanged_false(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'main.hepta'
            path.write_text('fn main() -> i32 effects {} { return 1; }')
            context = Context(Limits(reads=2))
            project = context.load(path)
            with self.assertRaises(Rejected):
                project.unchanged()
            self.assertTrue(context.closed)

    def test_context_reloads_accumulate_real_parse_and_byte_counts(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'main.hepta'
            path.write_text('fn main() -> i32 effects {} { return 1; }')
            context = Context()
            first = context.load(path)
            before = context.reader.bytes_read
            self.assertTrue(first.unchanged())
            second = context.load(path)
            self.assertEqual(first.report(), second.report())
            self.assertEqual(context.reader.bytes_read, before * 2 + len(path.read_bytes()))
            self.assertEqual(context.counts['parses'], 2)


if __name__ == '__main__':
    unittest.main()
