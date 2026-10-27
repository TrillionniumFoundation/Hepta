"""P0 fail-closed HIA grammar audit regressions (static; no producer import)."""
from __future__ import annotations

import copy
import unittest

from tools.audit_hia_schema_collision import (
    HIAWireAuditRejected, compare, declarations,
)


BASE = (
    b'SCHEMA = "hepta.hia.program.v2"\n'
    b'PROFILE = "nominal-products-enums"\n'
)
OTHER = (
    b'SCHEMA = "hepta.hia.program.v2"\n'
    b'PROFILE = "bulk-memory"\n'
)


class SchemaBindingAuditTests(unittest.TestCase):
    def test_literal_sources_remain_compatible_with_collision_report(self):
        nominal = declarations(BASE)
        bulk = declarations(OTHER)
        report = compare(nominal, bulk)
        self.assertEqual(len(report["semantic_profile_collisions"]), 1)
        self.assertEqual(report["shared_schema_labels"], ["hepta.hia.program.v2"])
        self.assertFalse(report["safe_to_merge_without_source_and_consumer_review"])
        self.assertEqual(compare(nominal, nominal)["semantic_profile_collisions"], [])
        self.assertEqual(declarations(BASE + b"import os\n")["profiles"], nominal["profiles"])

    def test_nested_rebinding_and_reflection_fail_closed(self):
        malicious = (
            b'if True:\n    SCHEMA = "hepta.hia.program.v3"\n',
            b'for SCHEMA in ["hepta.hia.program.v4"]: pass\n',
            b'while False:\n    PROFILE = "hidden"\n',
            b'def f():\n    global SCHEMA\n    SCHEMA = "hepta.hia.program.v4"\n',
            b'def f():\n    global SCHEMA\n    del SCHEMA\n',
            b'from other import PROFILE\n',
            b'import other as SCHEMA\n',
            b'try: pass\nexcept Exception as PROFILE: pass\n',
            b'match value:\n    case {"a": x, **SCHEMA}: pass\n',
            b'def SCHEMA(): pass\n',
            b'class PROFILE: pass\n',
            b'items = [(SCHEMA := x) for x in [1]]\n',
            b'with cm() as SCHEMA: pass\n',
            b'def f(PROFILE): pass\n',
            b'globals()["SCHEMA"] = "hepta.hia.program.v3"\n',
            b'exec("pass")\n',
            b'async def f():\n    async for SCHEMA in foo: pass\n',
        )
        for injected in malicious:
            with self.subTest(injected=injected):
                with self.assertRaises(HIAWireAuditRejected):
                    declarations(BASE + injected)

    def test_reflection_aliases_cannot_launder_schema_changes(self):
        # A literal SCHEMA/PROFILE pair cannot be certified when an imported
        # or stored reflection helper can rebind its module after scanning.
        aliases = (
            b'from builtins import globals as g\ng()["SCHEMA"] = "hepta.hia.program.v7"\n',
            b'from builtins import exec as run\nrun("SCHEMA = 1")\n',
            b'import builtins as bi\nbi.exec("SCHEMA = 1")\n',
            b'helper = globals\nhelper()["PROFILE"] = "changed"\n',
            b'get = getattr\nrun = get(__builtins__, "exec")\nrun("SCHEMA=1")\n',
            b'from builtins import __import__ as load\nload("builtins")\n',
        )
        for payload in aliases:
            with self.subTest(payload=payload):
                with self.assertRaisesRegex(HIAWireAuditRejected, "E_HIA_SCHEMA_AUDIT"):
                    declarations(BASE + payload)

    def test_compare_rejects_duplicate_and_malformed_inventories(self):
        valid = declarations(BASE)
        cases = []
        duplicated = copy.deepcopy(valid)
        duplicated["profiles"].append(dict(duplicated["profiles"][0], profile="other"))
        cases.append(duplicated)
        cases.append(dict(valid, sha256="forged"))
        cases.append(dict(valid, profiles="not-a-list"))
        cases.append(dict(valid, profiles=[]))
        cases.append(dict(valid, profiles=[dict(valid["profiles"][0], profile=False)]))
        cases.append(dict(valid, profiles=[dict(valid["profiles"][0], unexpected=True)]))
        cases.append(dict(valid, profiles=[dict(valid["profiles"][0], declaration="PROFILE")]))
        for entry in cases:
            with self.subTest(entry=entry):
                with self.assertRaises(HIAWireAuditRejected):
                    compare(entry, valid)

    def test_unbound_nonliteral_assignment_is_never_read_as_authority(self):
        for suffix in (
            b'if True:\n    PROFILE = "nominal-products-enums"\n',
            b'SCHEMA = get_schema()\n',
            b'PROFILE = "rebound"\n',
        ):
            with self.subTest(suffix=suffix):
                with self.assertRaises(HIAWireAuditRejected):
                    declarations(BASE + suffix)


if __name__ == "__main__":
    unittest.main()
