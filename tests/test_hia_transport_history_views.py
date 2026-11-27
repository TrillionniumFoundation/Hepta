"""Physical capture controls for composed transport source-history views."""
from hashlib import sha256
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tests import hia_caller_diagnostics_admission as diagnostics
from tests import hia_historical_diagnostic_controls as historical
from tests import hia_installed_distribution_history as installed
from tests import hia_component_authoring_history as component
from tests import hia_native_transport_worker_successor as transport
from tests import hia_store_delivery_successor as store

ROOT = Path(__file__).resolve().parents[1]


class TransportHistoryViewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.saved = {}
        cls.physical = (ROOT / diagnostics.PATH).read_bytes()

        def take(path):
            raw = path.read_bytes()
            name = path.relative_to(ROOT).as_posix()
            if name in cls.saved and cls.saved[name] != raw:
                raise AssertionError('current input changed during fixture capture')
            cls.saved[name] = raw
            return raw

        cls.prior, _, prior_take = transport._installed_view(
            diagnostics.PATH, cls.physical, root=ROOT, take=take)
        cls.original = transport._reverse_sqlite_boundary(
            diagnostics.PATH, cls.prior, take(ROOT / transport.SQLITE_BOUNDARY_FIXTURE),
            transport.DIAGNOSTIC_FIXTURE, take(ROOT / transport.DIAGNOSTIC_FIXTURE),
            diagnostics.CURRENT, root=ROOT, take=prior_take)
        if diagnostics.pin(cls.original) != diagnostics.CURRENT:
            raise AssertionError('the complete original diagnostic source differs')
        if cls.prior == cls.physical:
            raise AssertionError('the actual current diagnostic source needs no projection')
        if any((ROOT / name).read_bytes() != raw for name, raw in cls.saved.items()):
            raise AssertionError('physical source fixture changed at terminal')

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='hia-transport-prior-view-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for name, raw in self.saved.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)

    def test_actual_predecessor_view_keeps_physical_capture_identity(self):
        captured = {}
        def take(path):
            raw = path.read_bytes()
            captured[path.relative_to(self.root).as_posix()] = raw
            return raw
        prior, _, view = transport._installed_view(
            diagnostics.PATH, self.physical, root=self.root, take=take)
        self.assertEqual(prior, self.prior)
        self.assertEqual(view(self.root / diagnostics.PATH), self.prior)
        self.assertEqual(captured[diagnostics.PATH], self.physical)
        self.assertEqual((self.root / diagnostics.PATH).read_bytes(), self.physical)
        self.assertNotEqual(sha256(prior).hexdigest(),
                            sha256(captured[diagnostics.PATH]).hexdigest())

    def test_both_real_physical_and_reviewed_inputs_restore_the_original(self):
        for raw in (self.physical, self.prior):
            with self.subTest(input=sha256(raw).hexdigest()):
                self.assertEqual(historical.diagnostic_predecessor(self.root, raw), self.original)

    def test_explicit_root_never_reads_default_transport_root(self):
        with patch.object(transport, 'ROOT', self.root / 'missing-global-root'):
            self.assertEqual(historical.diagnostic_predecessor(self.root, self.prior),
                             self.original)

    def test_unreviewed_supplied_predecessor_is_rejected(self):
        for raw in (self.physical + b' ', self.prior + b' ', self.original):
            with self.subTest(input=sha256(raw).hexdigest()):
                with self.assertRaises(ValueError):
                    historical.diagnostic_predecessor(self.root, raw)

    def test_projection_rejects_another_complete_physical_version(self):
        (self.root / diagnostics.PATH).write_bytes(self.prior)
        with self.assertRaises(ValueError):
            historical.diagnostic_predecessor(self.root, self.physical)

    def test_each_partial_authority_is_rejected(self):
        for missing in (component.FIXTURE, installed.FIXTURE):
            with self.subTest(missing=missing):
                path = self.root / missing
                raw = path.read_bytes()
                try:
                    path.unlink()
                    with self.assertRaises((ValueError, FileNotFoundError)):
                        historical.diagnostic_predecessor(self.root, self.prior)
                finally:
                    path.write_bytes(raw)

    def test_source_change_after_projection_is_rejected(self):
        _, _, view = transport._installed_view(
            diagnostics.PATH, self.physical, root=self.root)
        (self.root / diagnostics.PATH).write_bytes(self.prior)
        with self.assertRaises(ValueError):
            view(self.root / diagnostics.PATH)

    def test_source_and_authorities_are_reread_after_the_exact_inverse(self):
        real_reverse = store.reverse_exact
        for name in (diagnostics.PATH, component.FIXTURE, installed.FIXTURE,
                     transport.SQLITE_BOUNDARY_FIXTURE, transport.DIAGNOSTIC_FIXTURE):
            with self.subTest(late_change=name):
                target = self.root / name
                saved = target.read_bytes()
                fired = []
                def reverse(raw, record, expected):
                    result = real_reverse(raw, record, expected)
                    if expected == diagnostics.CURRENT and not fired:
                        fired.append(True)
                        target.write_bytes(saved + b' ')
                    return result
                try:
                    with patch.object(store, 'reverse_exact', reverse):
                        with self.assertRaises(ValueError):
                            historical.diagnostic_predecessor(self.root, self.prior)
                    self.assertEqual(fired, [True])
                finally:
                    target.write_bytes(saved)

    def test_prior_reader_rejects_an_escaped_dependency(self):
        view = transport._prior_take(
            diagnostics.PATH, self.physical, self.prior, root=self.root)
        for path in (self.root.parent / 'another-source',
                     self.root / '..' / 'another-source', self.root):
            with self.subTest(path=str(path)), self.assertRaises(ValueError):
                view(path)
        for name in ('../another-source', '/another-source', 'tests/../another-source'):
            with self.subTest(source=name), self.assertRaises(ValueError):
                transport._prior_take(name, self.physical, self.prior, root=self.root)


if __name__ == '__main__':
    unittest.main()
