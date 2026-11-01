"""Factoring the verifier cannot leave its transitive identity unbound."""
from pathlib import Path
import unittest
from unittest.mock import patch


class CapabilityImplementationIdentityTests(unittest.TestCase):
    def test_every_existing_direct_verifier_digest_binds_the_new_flow_module(self):
        from hepta import (hia_optimization, hia_program_llvm, hia_bounded_unroll,
                           hia_scalar_lowering_check, hia_x86_search, hia_finite_context)
        functions = [hia_optimization.checker_identity, hia_program_llvm._implementation_hash,
                     hia_bounded_unroll.checker_identity, hia_scalar_lowering_check.checker_identity,
                     hia_x86_search._implementation_hash, hia_finite_context._implementation]
        read = Path.read_bytes
        def altered(path):
            raw = read(path)
            return raw+b'\n# changed capability transition\n' if path.name=='hia_capability_flow.py' else raw
        for identity in functions:
            with self.subTest(identity=identity.__module__):
                before = identity()
                with patch.object(Path,'read_bytes',altered):
                    after = identity()
                self.assertNotEqual(before,after)

    def test_resource_and_kernel_export_manifests_include_capability_flow(self):
        from hepta.hia_optimization_contract import SOURCE_FILES
        from tools.qualify_hia_selected_formal import SOURCE_FILES as SELECTED
        from tools.qualify_hia_register_safety import SOURCE_FILES as REGISTER
        self.assertIn('hia_capability_flow.py',SOURCE_FILES)
        for manifest in (SELECTED,REGISTER):
            self.assertIn('hepta/hia_capability_flow.py',manifest)


if __name__=='__main__':
    unittest.main()
