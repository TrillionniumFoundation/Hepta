"""Physical import-domain controls for the strict native Cell builder."""
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

from tools import build_hia_cell_bridge as build


class CellBuildCustodyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parents[1]
        cls.captured = {
            p.relative_to(cls.root).as_posix(): p.read_bytes()
            for prefix in ("hepta", "tools") for p in (cls.root / prefix).rglob("*.py")
        }

    def test_actual_loaded_domain_has_only_captured_source(self):
        build._check_loaded_sources(self.root, self.captured)

    def test_external_implementation_module_is_refused(self):
        with tempfile.TemporaryDirectory(prefix="cell-foreign-module-") as directory:
            source = Path(directory) / "foreign.py"
            source.write_text("value = 7\n")
            module = types.ModuleType("tools.cell_foreign_probe")
            module.__file__ = str(source)
            with patch.dict(sys.modules, {module.__name__: module}), self.assertRaisesRegex(
                    ValueError, "escaped its physical source root"):
                build._check_loaded_sources(self.root, self.captured)

    def test_external_implementation_namespace_is_refused(self):
        with tempfile.TemporaryDirectory(prefix="cell-foreign-namespace-") as directory:
            module = types.ModuleType("hepta.cell_foreign_namespace_probe")
            module.__path__ = [directory]
            with patch.dict(sys.modules, {module.__name__: module}), self.assertRaisesRegex(
                    ValueError, "namespace escaped"):
                build._check_loaded_sources(self.root, self.captured)

    def test_physical_alias_cannot_omit_captured_source(self):
        module = types.ModuleType("cell_unqualified_implementation_probe")
        # A Python alias points to the exact loaded implementation file.
        module.__file__ = str(self.root / "tools/build_hia_cell_bridge.py")
        captured = dict(self.captured)
        captured.pop("tools/build_hia_cell_bridge.py")
        with patch.dict(sys.modules):
            sys.modules.pop(build.__name__)
            sys.modules[module.__name__] = module
            with self.assertRaisesRegex(ValueError, "uncaptured Cell implementation module"):
                build._check_loaded_sources(self.root, captured)

    def test_captured_bytes_must_equal_the_physical_module(self):
        captured = dict(self.captured)
        captured["tools/build_hia_cell_bridge.py"] += b"\n# different captured bytes\n"
        with self.assertRaisesRegex(ValueError, "bytes differ from captured source"):
            build._check_loaded_sources(self.root, captured)

    def test_foreign_standard_module_is_outside_the_implementation_domain(self):
        with tempfile.TemporaryDirectory(prefix="cell-neutral-module-") as directory:
            source = Path(directory) / "other.py"
            source.write_text("value = 7\n")
            module = types.ModuleType("cell_neutral_probe")
            module.__file__ = str(source)
            with patch.dict(sys.modules, {module.__name__: module}):
                build._check_loaded_sources(self.root, self.captured)


if __name__ == "__main__":
    unittest.main()
