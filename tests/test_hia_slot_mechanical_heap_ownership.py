"""Check cyclic collection of instances from the actual CPython Slot extension."""
from pathlib import Path
import gc
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
import weakref

from hepta.native.slot_mechanical_build import supported_profile


ROOT = Path(__file__).resolve().parents[1]


def load_isolated(binary):
    spec = importlib.util.spec_from_file_location("probe._hia_slot_mechanical", binary)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def make_module_cycle(binary):
    module = load_isolated(binary)

    def continuation():
        return None

    method = module.bind(continuation, None, object, RuntimeError, continuation, 1)
    module.bound_method = method
    # Each weakref observes an object in the cycle without keeping it alive.
    refs = tuple(weakref.ref(obj) for obj in (module, type(method), continuation))
    return refs, type(method) in gc.get_referents(method)


def make_instance_cycle(binary, name):
    module = load_isolated(binary)
    heap_type = next(obj for obj in gc.get_referents(module)
                     if isinstance(obj, type) and obj.__name__ == name)
    instance = heap_type()
    module.owned_instance = instance
    return (weakref.ref(module), weakref.ref(heap_type)), heap_type in gc.get_referents(instance)


@unittest.skipUnless(supported_profile(), "requires the supported CPython Slot extension ABI")
class SlotMechanicalHeapOwnershipTests(unittest.TestCase):
    def test_instances_report_their_heap_types_and_module_cycles_are_collectible(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "build"
            subprocess.run(
                [sys.executable, "-I", "-B", str(ROOT / "tools/build_hia_slot_mechanical.py"),
                 "--output", str(output)],
                cwd=ROOT, check=True, capture_output=True,
            )
            build = json.loads((output / "report.json").read_bytes())
            self.assertTrue(build["extension_receipt_verified"])
            receipt = Path(build["identity_path"])
            binary = receipt.parent / json.loads(receipt.read_bytes())["binary"]["name"]
            with self.subTest(bound_continuation=True):
                refs, visits_type = make_module_cycle(binary)
                gc.collect()
                self.assertEqual([ref() is None for ref in refs], [True, True, True])
                self.assertTrue(visits_type)
            for name in ("Continuation", "Session", "CursorIteration"):
                with self.subTest(heap_type=name):
                    refs, visits_type = make_instance_cycle(binary, name)
                    gc.collect()
                    self.assertEqual([ref() is None for ref in refs], [True, True])
                    self.assertTrue(visits_type)
