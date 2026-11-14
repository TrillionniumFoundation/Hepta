"""Source-only representation policy and foreign-route controls; no Native claim."""
from pathlib import Path
import ast
import copy
from hashlib import sha256
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
ENTRIES = ('sha256', 'canonical_json', 'input_sha256', 'scalar_entrypoints',
           'normalization_report', 'as_dict', 'report')
ORIGINAL_CLASS_SOURCE_SHA256 = 'f856aa2f9509c1cc8f2e8286d79c00a98a7625af578b6d316714148dc156efef'
ORIGINAL_CLASS_SOURCE = '@dataclass(frozen=True, slots=True)\nclass VerifiedProgram:\n    """Immutable bytes, not an unforgeable receipt; consumers reverify them."""\n\n    canonical_bytes: bytes\n    structured_bytes: bytes | None = None\n\n    @property\n    def sha256(self):\n        return payload_sha256(self.canonical_bytes).hex()\n\n    @property\n    def canonical_json(self):\n        return self.canonical_bytes.decode("utf-8")\n\n    @property\n    def input_sha256(self):\n        return payload_sha256(self.structured_bytes if self.structured_bytes is not None\n                              else self.canonical_bytes).hex()\n\n    @property\n    def scalar_entrypoints(self):\n        # A nominal aggregate erased into scalar slots is still not a scalar\n        # public signature.  Generated protocol helpers are internal too.\n        document = self.as_dict()\n        if "exports" in document:\n            return frozenset(document["exports"])\n        return frozenset(fn["name"] for fn in document["functions"]\n                         if all(type(p["type"]) is str and p["type"] in SCALARS for p in fn["params"])\n                         and all(type(t) is str and t in SCALARS for t in fn["returns"]))\n\n    @property\n    def normalization_report(self):\n        checked = verify_program(self)\n        core = checked.as_dict()\n        original = (decode_internal_canonical(checked.structured_bytes, max_nodes=MAX_NODES, max_depth=MAX_DEPTH)\n                    if checked.structured_bytes is not None else core)\n        return {"input_sha256": checked.input_sha256,\n                "core_sha256": checked.sha256,\n                "input_schema": original["schema"],\n                "input_profile": profile_for_schema(original["schema"]),\n                "core_schema": core["schema"],\n                "core_profile": profile_for_schema(core["schema"]),\n                "structured_elaboration_rechecked": checked.structured_bytes is not None,\n                "primitive_core_rechecked": True,\n                "source_ast_required": False,\n                "public_scalar_entrypoints": sorted(checked.scalar_entrypoints)}\n\n    def as_dict(self):\n        return decode_internal_canonical(self.canonical_bytes, max_nodes=MAX_NODES, max_depth=MAX_DEPTH)\n\n    def report(self):\n        # This public constructor is intentionally not an authority. Even a\n        # report rechecks the immutable bytes instead of trusting its class.\n        checked = verify_program(self)\n        data = checked.as_dict()\n        profile = profile_for_schema(data["schema"])\n        return {"schema": "hepta.hia.program-verification.v1", "ok": True,\n                "profile": profile, "program_sha256": checked.sha256,\n                "input_sha256": checked.input_sha256,\n                "normalization": checked.normalization_report,\n                "word_bits": WORD_BITS, "functions_checked": len(data["functions"]),\n                "blocks_checked": sum(len(f["blocks"]) for f in data["functions"]),\n                "source_required": False,\n                "claims": {"typed_closed_ssa_checked": True,\n                           "linear_resources_and_loan_provenance_checked": True,\n                           "whole_language_soundness_proved": False,\n                           "backend_refinement_proved": False,\n                           "foreign_code_supported": False,\n                           "escaping_loans_supported": False,\n                           "parameter_bound_loan_returns_supported": supports_feature(data["schema"], "parameter_loan_returns"),\n                           "concurrency_supported": False,\n                           "nominal_products_and_enums_checked": checked.structured_bytes is not None,\n                           "local_stored_loan_identity_checked": checked.structured_bytes is not None,\n                           "record_field_borrow_provenance_checked": checked.structured_bytes is not None,\n                           "cooperative_task_protocol_checked": checked.structured_bytes is not None,\n                           "background_tasks_supported": False,\n                           "recursive_heap_adts_supported": False,\n                           "recursive_buffer_chains_supported": supports_feature(data["schema"], "recursive_chain"),\n                           "preemptive_or_async_cancellation_supported": False}}\n'


class VerifiedReportSourceTests(unittest.TestCase):
    def test_complete_seven_bodies_and_definition_time_class_are_retained(self):
        from hepta import hia_program as original
        from hepta.hia_verified_report_native import ARITIES
        from hepta.hia_verified_report_ports import ROOT_NAMES
        tree = ast.parse((ROOT/'hepta/hia_program.py').read_bytes())
        cls = next(node for node in tree.body if isinstance(node,ast.ClassDef) and node.name == 'VerifiedProgram')
        self.assertEqual(sha256(ORIGINAL_CLASS_SOURCE.encode()).hexdigest(),ORIGINAL_CLASS_SOURCE_SHA256)
        frozen_cls=next(n for n in ast.parse(ORIGINAL_CLASS_SOURCE).body if isinstance(n,ast.ClassDef))
        self.assertEqual(ast.dump(cls,include_attributes=False),ast.dump(frozen_cls,include_attributes=False))
        methods = {node.name:node for node in cls.body if isinstance(node,ast.FunctionDef)}
        policies = {node.name:node for node in ast.parse((ROOT/'tools/hia_verified_report_policy.py').read_bytes()).body
                    if isinstance(node,ast.FunctionDef)}
        self.assertEqual(tuple(policies),ENTRIES)
        self.assertEqual(tuple(ARITIES),ENTRIES)
        self.assertEqual(tuple(ARITIES.values()),(1,)*7)
        self.assertEqual(ROOT_NAMES,ENTRIES)
        self.assertIs(original._NATIVE_VERIFIED_REPORT_CLASS,original.VerifiedProgram)
        for name in ENTRIES:
            with self.subTest(method=name):
                expected=copy.deepcopy(methods[name]);expected.decorator_list=[]
                self.assertEqual(ast.dump(expected,include_attributes=False),
                                 ast.dump(policies[name],include_attributes=False))
                descriptor=original.VerifiedProgram.__dict__[name]
                function=descriptor.fget if type(descriptor) is property else descriptor
                self.assertIs(original._NATIVE_VERIFIED_REPORT_ENTRIES[name],function)
                anchor=original._NATIVE_VERIFIED_REPORT_ANCHORS[name]
                self.assertIs(anchor[0],descriptor)
                self.assertIs(anchor[1],function)
                self.assertIs(anchor[2],function.__code__)

    def test_generated_hia_and_ports_reproduce_and_verify_independently(self):
        from tools.generate_hia_verified_report import generated
        from hepta.hia_agent_assembly import assemble_program
        from hepta.hia_program import verify_program
        first=generated()
        second=generated()
        self.assertEqual(first[:2],second[:2])
        self.assertEqual(first[0],(ROOT/'examples/hia_bootstrap/verified_report.hepta').read_bytes())
        self.assertEqual(first[1],(ROOT/'hepta/hia_verified_report_ports.py').read_bytes())
        self.assertEqual(sha256(first[0]).hexdigest(),
            '2d3e5a21227ccdc6f40cbbfd9b72c8d1eacbdca0b24c40fc64937506a55af048')
        verified=verify_program(assemble_program(first[0]))
        actual=verified.as_dict()
        self.assertEqual(actual['schema'],'hepta.hia.program.v8')
        self.assertEqual(len(actual['functions']),25)
        self.assertEqual(sum(len(fn['blocks']) for fn in actual['functions']),248)
        self.assertEqual(sum(len(block['ops']) for fn in actual['functions']
                             for block in fn['blocks']),2156)

    def test_foreign_report_lookup_and_call_preserve_exact_single_dispatch(self):
        from hepta import hia_program as original
        from hepta.hia_verified_report_native import NativeVerifiedReport
        # This is the real host-provider guard without constructing a Native image.
        owner=object.__new__(NativeVerifiedReport)
        owner._class=original._NATIVE_VERIFIED_REPORT_CLASS
        owner._definitions=dict(original._NATIVE_VERIFIED_REPORT_ANCHORS)
        owner._mro,owner._dict_descriptor,owner._getattribute=original._NATIVE_VERIFIED_REPORT_LOOKUP
        plain=object.__new__(original.VerifiedProgram)
        self.assertTrue(owner._ordinary_attribute(plain,'report'))
        calls=[]
        marker=object()
        def replacement(value):
            calls.append(value)
            return marker
        with patch.object(original.VerifiedProgram,'report',replacement):
            self.assertFalse(owner._ordinary_attribute(plain,'report'))
            method=owner.attribute(plain,'report',None)
            self.assertIs(method.__self__,plain)
            self.assertIs(owner.invoke_bound_report(method),marker)
            self.assertEqual(calls,[plain])
        self.assertTrue(owner._ordinary_attribute(plain,'report'))
        fault=MemoryError('exact foreign report failure')
        class Foreign:
            def __getattribute__(self,name):
                if name=='report':
                    calls.append('lookup')
                    return failing
                raise AssertionError('unrequested foreign attribute')
        def failing():
            calls.append('call')
            raise fault
        calls.clear()
        foreign=Foreign()
        method=owner.attribute(foreign,'report',None)
        with self.assertRaises(MemoryError) as caught:
            owner.invoke_bound_report(method)
        self.assertIs(caught.exception,fault)
        self.assertEqual(calls,['lookup','call'])
        self.assertFalse(hasattr(owner,'_entry'))


if __name__ == '__main__':
    unittest.main()
