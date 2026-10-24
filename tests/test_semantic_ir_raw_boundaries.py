"""HSIR inventories transitive raw-pointer signatures, not pointer safety."""
import unittest

from hepta.ast import Type
from hepta.checker import check
from hepta.parser import parse
from hepta.semantic_ir import _type_has_raw, lower_checked_program


class RawBoundaryInventoryTests(unittest.TestCase):
    def lower(self, source):
        program = parse(source, "raw-boundary.hepta")
        checked = check(program)
        self.assertTrue(checked.ok, [d.to_dict() for d in checked.diagnostics])
        return lower_checked_program(program, checked)

    def test_nested_nominal_types_retain_raw_signature_obligation(self):
        cases = [
            "struct Wrapper { p: raw const u8 }",
            "struct Box<T> { value: T } struct Wrapper { pointer_box: Box<raw const u8>, plain: Box<u32> }",
            "struct Inner { p: raw mut u8 } struct Wrapper { inner: Inner }",
            "enum Wrapper { Empty, Pointer(raw const u8) }",
            "struct Inner { p: raw const u8 } enum Wrapper { Empty, Present(Inner) }",
            "struct Inner { p: raw const u8 } struct Wrapper { values: [Inner; 2] }",
            "struct Link<T> { p: raw const T } struct Wrapper { node: Link<Wrapper> }",
            "struct Box<T> { value: T } struct Inner { p: raw const u8 } struct Wrapper { box: Box<Inner> }",
        ]
        for declarations in cases:
            with self.subTest(declarations=declarations):
                source = declarations + " fn echo(x: Wrapper) -> Wrapper effects {} { return x; }"
                ir = self.lower(source)
                self.assertEqual(ir["external_obligations"], [{
                    "function": "echo", "reasons": ["raw_pointer_signature"],
                    "status": "caller_obligation_not_dischargeable_by_hsir"}])
                self.assertTrue(all(value is False for value in ir["claims"].values()))
                self.assertEqual(ir, self.lower(source))

    def test_defensive_nominal_cycles_terminate_without_skipping_siblings(self):
        # Synthetic raw-free value cycles are not accepted language layouts;
        # exercise the inventory's defensive graph walk directly, not lowering.
        fields = {"A": (Type("B"),), "B": (Type("A"),)}
        self.assertFalse(_type_has_raw(Type("A"), fields))
        fields["B"] = (Type("raw_const", (Type("u8"),)), Type("A"))
        self.assertTrue(_type_has_raw(Type("A"), fields))

    def test_return_only_raw_wrapper_is_inventoried(self):
        ir = self.lower("struct Wrapper { p: raw const u8 } fn make() -> Wrapper effects {} { return make(); }")
        self.assertEqual(ir["external_obligations"][0]["reasons"], ["raw_pointer_signature"])

    def test_raw_free_nominal_types_do_not_gain_obligations(self):
        ir = self.lower("""
            struct Box<T> { value: T }
            enum Item { Empty, Present(Box<u32>) }
            struct Wrapper { items: [Item; 2] }
            fn echo(x: Wrapper) -> Wrapper effects {} { return x; }
        """)
        self.assertEqual(ir["external_obligations"], [])


if __name__ == "__main__":
    unittest.main()
