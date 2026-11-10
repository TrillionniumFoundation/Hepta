"""Explicit cache-input closure; independent of the historical test inventories."""
from contextlib import contextmanager
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import core_seven_shared_acceptance_plan as plan


CACHE_INPUTS = ('hepta/hia_result_cache.py', 'hepta/hia_result_cache_audit.py')
VALIDATION_INPUTS = ('tests/test_core_capture_cleanup_replay.py', 'tests/test_core_structured_source_cost.py', 'tests/test_core_syntax_partition_parse_fast.py', 'tests/test_core_seven_external_hash.py')
ROUND5_VALIDATION_INPUTS = ('tests/test_hia_scalar_return_signature.py', 'tests/test_hia_ndu_preparation_bound.py')
ROUND6_INPUTS = plan.ROUND6_ADDITIONS
LINUX_INPUTS = plan.LINUX_ADDITIONS
ROUND6_COMPILER_INPUTS = ('hepta/hia_ndu_module_costs.py', 'hepta/hia_ndu_policy.py')
LINUX_COMPILER_INPUTS = ('hepta/hia_linux_kernel.py',)
NATIVE_AGENT_INPUTS = (
    'hepta/hia_agent_contract.py',
    'hepta/hia_agent_exec.py',
    'hepta/hia_agent_runner.py',
    'hepta/hia_agent_service.py',
    'hepta/hia_agent_store.py',
    'hepta/hia_agent_worker.py',
    'hepta/hia_machine_elf.py',
    'hepta/hia_machine_x64.py',
    'hepta/hia_program_native.py',
)
P0_P3_INPUTS = (
    'hepta/hia_agent_macro_discovery.py',
    'hepta/hia_agent_macro_policy.py',
    'hepta/hia_machine_plan.py',
    'hepta/hia_native_byte_abi.py',
    'hepta/hia_native_byte_runner.py',
)
SAFE_CORE_INPUTS = (
    'hepta/hia_safe_core.py',
    'hepta/hia_safe_core_elf.py',
    'hepta/hia_safe_core_x64.py',
)
SCOPED_AGENT_NDU_INPUTS = (
    'hepta/hia_agent_buffers.py', 'hepta/hia_ndu_prepared_ranker.py',
    'hepta/hia_ndu_scalar_selection.py', 'hepta/hia_proof_contract.py',
    'hepta/hia_scalar_proof_contract.py',
)
PERSISTENT_NDU_INPUTS = ('hepta/hia_ndu_persistent_ranker.py',)
JSON_NATIVE_ADDITIONS = (
    'examples/hia_bootstrap/core_json_frontend.hiaasm',
    'examples/hia_bootstrap/json_canonical.hiaasm',
    'examples/hia_bootstrap/json_decode.hiaasm',
    'examples/hia_bootstrap/json_preflight.hiaasm',
    'hepta/hia_core_json_frontend_native.py',
    'hepta/hia_json_canonical_native.py',
    'hepta/hia_json_decode.py',
    'hepta/hia_json_decode_native.py',
    'hepta/hia_json_preflight_native.py',
    'tests/test_hia_core_json_frontend_native.py',
    'tests/test_hia_json_canonical_native.py',
    'tests/test_hia_json_decode_native.py',
    'tests/test_hia_json_preflight.py',
    'tests/test_hia_json_preflight_native.py',
    'tools/build_hia_core_json_frontend.py',
    'tools/build_hia_json_canonical.py',
    'tools/build_hia_json_decode.py',
    'tools/build_hia_json_preflight.py',
    'tools/compile_hia_core_json.py',
    'tools/generate_hia_core_json_frontend.py',
    'tools/generate_hia_json_canonical.py',
    'tools/generate_hia_json_decode.py',
    'tools/generate_hia_json_preflight.py',
)

SHA256_NATIVE_ADDITIONS = (
    'examples/hia_bootstrap/sha256.hiaasm',
    'hepta/hia_sha256_native.py',
    'tests/test_hia_sha256_native.py',
    'tools/build_hia_sha256.py',
    'tools/generate_hia_sha256.py',
)

SOURCE_LEXER_ADDITIONS = (
    'examples/hia_bootstrap/source_lexer.hiaasm',
    'hepta/hia_source_lexer_native.py',
    'tests/test_hia_source_lexer_native.py',
    'tools/build_hia_source_lexer.py',
    'tools/generate_hia_source_lexer.py',
)

TYPE_PARSER_ADDITIONS = (
    'examples/hia_bootstrap/source_type_parser.hiaasm',
    'hepta/hia_type_parser_native.py',
    'tests/test_hia_type_parser_native.py',
    'tools/build_hia_type_parser.py',
    'tools/generate_hia_type_parser.py',
)

SOURCE_PARSER_ADDITIONS = (
    'examples/hia_bootstrap/source_parser.hiaasm',
    'hepta/hia_source_parser_native.py',
    'tests/test_hia_source_parser_native.py',
    'tools/build_hia_source_parser.py',
    'tools/generate_hia_source_parser.py',
)

SOURCE_EFFECTS_ADDITIONS = (
    'examples/hia_bootstrap/source_effects.hiaasm',
    'hepta/hia_source_effects_native.py',
    'tests/test_hia_source_effects_native.py',
    'tools/build_hia_source_effects.py',
    'tools/generate_hia_source_effects.py',
)

TYPE_GRAPH_ADDITIONS = (
    'examples/hia_bootstrap/type_graph.hiaasm',
    'hepta/hia_type_graph_native.py',
    'tests/test_hia_type_graph_native.py',
    'tools/build_hia_type_graph.py',
    'tools/generate_hia_type_graph.py',
)

NEW_INPUTS = (*CACHE_INPUTS, 'tests/test_core_seven_shared_source_closure.py', *VALIDATION_INPUTS, *ROUND5_VALIDATION_INPUTS, *ROUND6_INPUTS, *LINUX_INPUTS, *NATIVE_AGENT_INPUTS, *P0_P3_INPUTS, *SAFE_CORE_INPUTS, *SCOPED_AGENT_NDU_INPUTS, *PERSISTENT_NDU_INPUTS, *JSON_NATIVE_ADDITIONS, *SHA256_NATIVE_ADDITIONS, *SOURCE_LEXER_ADDITIONS, *TYPE_PARSER_ADDITIONS, *SOURCE_PARSER_ADDITIONS, *SOURCE_EFFECTS_ADDITIONS, *TYPE_GRAPH_ADDITIONS)
PRIOR_COMMITMENT = '36af03771b8b81803d90baafc92fd290d9e6cadbb03e7e135a99beae804bb0f0'
ROUND4_COMMITMENT = 'ffc0f4bd9585328bb21e99d0fe3bac7717b65d823a72cb5de9987886018055db'
ROUND5_COMMITMENT = 'd27b4d1edaa27950489d7b54fa6b8242b493883d0927933fa303e5b1203c9c55'
LINUX_COMMITMENT = 'a48ba3c0244975ebaf4219e6409a0293fa3ae7339704554dc4ba1f3e0c6eb86c'
NATIVE_AGENT_COMMITMENT = 'd999ff7dc718330771ddb745dbed6a5a7ecdcdea8f9011e35f0a07417f09b9c0'
P0_P3_COMMITMENT = '77fb9af75d987acab91d224cf47c5e6734f8c6eb9c4fa895064fba306289a016'
SAFE_CORE_COMMITMENT = '223c03fa82d871fee3d85d57bb1e254d658a9d85007ec11bea5bfbb1fad5d1b5'
SCOPED_AGENT_NDU_COMMITMENT = '9a888e4dbfe883eb74fd8961a5fbc2b90b0cac7b9a6343ef5720145e23be72c7'
PERSISTENT_NDU_COMMITMENT = '5a6311333c82ea95a464ff9257f190f5712b52e3da90c02169e063ca1698f8dc'
CURRENT_COMMITMENT = '48c6bb782538d50e2c60d715c3f9fe92f2b0bf88db5df2b74c79c1dfea9ddfaf'


@contextmanager
def compiler_directory():
    names = tuple(name for name in plan.source_paths()
                  if name.startswith('hepta/') and name.count('/') == 1
                  and name.endswith('.py'))
    with tempfile.TemporaryDirectory(prefix='hia-explicit-compiler-closure-') as directory:
        root = Path(directory)
        (root / 'hepta').mkdir()
        for name in names:
            (root / name).write_bytes(b'')
        yield root


class FixedCompilerSourceClosureTests(unittest.TestCase):
    def test_complete_reviewed_closure_retains_every_prior_path(self):
        actual = plan.source_paths()
        self.assertEqual(len(actual), 390)
        self.assertEqual(plan.NATIVE_AGENT_ADDITIONS, NATIVE_AGENT_INPUTS)
        self.assertEqual(plan.P0_P3_ADDITIONS, P0_P3_INPUTS)
        self.assertEqual(plan.SAFE_CORE_ADDITIONS, SAFE_CORE_INPUTS)
        self.assertEqual(plan.SCOPED_AGENT_NDU_ADDITIONS, SCOPED_AGENT_NDU_INPUTS)
        self.assertEqual(plan.PERSISTENT_NDU_ADDITIONS, PERSISTENT_NDU_INPUTS)
        self.assertEqual(plan.JSON_NATIVE_ADDITIONS, JSON_NATIVE_ADDITIONS)
        self.assertEqual(plan.SHA256_NATIVE_ADDITIONS,SHA256_NATIVE_ADDITIONS)
        self.assertEqual(plan.SOURCE_LEXER_ADDITIONS,SOURCE_LEXER_ADDITIONS)
        self.assertEqual(plan.TYPE_PARSER_ADDITIONS,TYPE_PARSER_ADDITIONS)
        self.assertEqual(plan.SOURCE_PARSER_ADDITIONS,SOURCE_PARSER_ADDITIONS)
        self.assertEqual(plan.SOURCE_EFFECTS_ADDITIONS,SOURCE_EFFECTS_ADDITIONS)
        self.assertEqual(plan.TYPE_GRAPH_ADDITIONS,TYPE_GRAPH_ADDITIONS)
        effects_native=tuple(name for name in actual if name not in TYPE_GRAPH_ADDITIONS)
        self.assertEqual(len(effects_native),385)
        self.assertEqual(plan.commitment(effects_native),'c40333f36ef9bec6ac55c15926370629ec701fe83aedea9c639412a66bd08c52')
        source_native=tuple(name for name in effects_native if name not in SOURCE_EFFECTS_ADDITIONS)
        self.assertEqual(len(source_native),380)
        self.assertEqual(plan.commitment(source_native),'b70e5910a8cad3f61d16343c0795cb0a8ae2b89406f5b8fdc91ebdbcd88f4a14')
        type_native=tuple(name for name in source_native if name not in SOURCE_PARSER_ADDITIONS)
        self.assertEqual(len(type_native),375)
        self.assertEqual(plan.commitment(type_native),'49a2a910de52a02227d9d96fcf488df753362970ea79e92521d6e3efc984481e')
        lexer_native=tuple(name for name in type_native if name not in TYPE_PARSER_ADDITIONS)
        self.assertEqual(len(lexer_native),370)
        self.assertEqual(plan.commitment(lexer_native),'414e724f72c675c8cf7139da0710af16ec4417b4926a334b3f5c3c171b3b44f4')
        sha_native=tuple(name for name in lexer_native if name not in SOURCE_LEXER_ADDITIONS)
        self.assertEqual(len(sha_native),365)
        self.assertEqual(plan.commitment(sha_native),'82ab8f945ba088e88eb2ad47f51fbf3cc46d8f249d7f3d3e7ed08554229421ec')
        json_native=tuple(name for name in sha_native if name not in SHA256_NATIVE_ADDITIONS)
        self.assertEqual(len(json_native),360)
        self.assertEqual(plan.commitment(json_native),'84f2d792e39d1f6a5b059026acc14edc321bbe8528c026caa2f06fba55977ad2')
        persistent_ndu = tuple(name for name in json_native if name not in JSON_NATIVE_ADDITIONS)
        self.assertEqual(len(persistent_ndu), 337)
        self.assertEqual(plan.commitment(persistent_ndu), PERSISTENT_NDU_COMMITMENT)
        scoped_agent_ndu = tuple(name for name in persistent_ndu if name not in PERSISTENT_NDU_INPUTS)
        self.assertEqual(len(scoped_agent_ndu), 336)
        self.assertEqual(plan.commitment(scoped_agent_ndu), SCOPED_AGENT_NDU_COMMITMENT)
        safe_core = tuple(name for name in scoped_agent_ndu if name not in SCOPED_AGENT_NDU_INPUTS)
        self.assertEqual(len(safe_core), 331)
        self.assertEqual(plan.commitment(safe_core), SAFE_CORE_COMMITMENT)
        p0_p3 = tuple(name for name in safe_core if name not in SAFE_CORE_INPUTS)
        self.assertEqual(len(p0_p3), 328)
        self.assertEqual(plan.commitment(p0_p3), P0_P3_COMMITMENT)
        native_agent = tuple(name for name in p0_p3 if name not in P0_P3_INPUTS)
        self.assertEqual(len(native_agent), 323)
        self.assertEqual(plan.commitment(native_agent), NATIVE_AGENT_COMMITMENT)
        linux = tuple(name for name in native_agent if name not in NATIVE_AGENT_INPUTS)
        self.assertEqual(len(linux), 314)
        self.assertEqual(plan.commitment(linux), LINUX_COMMITMENT)
        round5 = tuple(name for name in linux if name not in (*ROUND6_INPUTS, *LINUX_INPUTS))
        self.assertEqual(len(round5), 267)
        self.assertEqual(plan.commitment(round5), ROUND5_COMMITMENT)
        round4 = tuple(name for name in round5 if name not in ROUND5_VALIDATION_INPUTS)
        self.assertEqual(len(round4), 265)
        self.assertEqual(plan.commitment(round4), ROUND4_COMMITMENT)
        self.assertEqual(plan.commitment(actual), CURRENT_COMMITMENT)
        self.assertTrue(set(NEW_INPUTS) <= set(actual))
        previous = tuple(name for name in actual if name not in NEW_INPUTS)
        self.assertEqual(len(previous), 258)
        self.assertEqual(plan.commitment(previous), PRIOR_COMMITMENT)
        before_new_controls = tuple(name for name in actual
                                      if name not in (*VALIDATION_INPUTS, *ROUND5_VALIDATION_INPUTS, *ROUND6_INPUTS, *LINUX_INPUTS, *NATIVE_AGENT_INPUTS, *P0_P3_INPUTS, *SAFE_CORE_INPUTS, *SCOPED_AGENT_NDU_INPUTS, *PERSISTENT_NDU_INPUTS, *JSON_NATIVE_ADDITIONS, *SHA256_NATIVE_ADDITIONS, *SOURCE_LEXER_ADDITIONS, *TYPE_PARSER_ADDITIONS, *SOURCE_PARSER_ADDITIONS, *SOURCE_EFFECTS_ADDITIONS, *TYPE_GRAPH_ADDITIONS))
        self.assertEqual(len(before_new_controls), 261)
        self.assertEqual(plan.commitment(before_new_controls),
                         '5758e93bc7e92d4b10370593c3f20b713741b7530d977507a1430c6eb9cfb0eb')
        self.assertEqual(sum(name.startswith('hepta/') and name.count('/') == 1
                             and name.endswith('.py') for name in actual), 223)
        for name in NEW_INPUTS:
            self.assertTrue((plan.ROOT / name).is_file(), name)

    def test_each_new_compiler_module_is_required(self):
        with compiler_directory() as root, patch.object(plan, 'ROOT', root):
            for name in (*(n for n in (*JSON_NATIVE_ADDITIONS,*SHA256_NATIVE_ADDITIONS, *SOURCE_LEXER_ADDITIONS, *TYPE_PARSER_ADDITIONS, *SOURCE_PARSER_ADDITIONS, *SOURCE_EFFECTS_ADDITIONS, *TYPE_GRAPH_ADDITIONS) if n.startswith('hepta/')), *CACHE_INPUTS, *ROUND6_COMPILER_INPUTS, *LINUX_COMPILER_INPUTS, *NATIVE_AGENT_INPUTS, *P0_P3_INPUTS, *SAFE_CORE_INPUTS, *SCOPED_AGENT_NDU_INPUTS, *PERSISTENT_NDU_INPUTS):
                with self.subTest(name=name):
                    (root / name).unlink()
                    with self.assertRaisesRegex(ValueError, 'complete actual compiler_hash input set'):
                        plan.source_paths()
                    (root / name).write_bytes(b'')

    def test_extra_actual_compiler_filename_is_refused(self):
        with compiler_directory() as root, patch.object(plan, 'ROOT', root):
            (root / 'hepta/hia_result_cache_unreviewed.py').write_bytes(b'')
            with self.assertRaisesRegex(ValueError, 'complete actual compiler_hash input set'):
                plan.source_paths()

    def test_unreviewed_declared_filename_is_refused(self):
        changed = tuple(sorted((*plan.SOURCE_IDENTITY_PATHS, 'hepta/unreviewed.py')))
        with patch.object(plan, 'SOURCE_IDENTITY_PATHS', changed):
            with self.assertRaisesRegex(ValueError, 'reviewed exact source identity closure'):
                plan.source_paths()
        # Even a reviewed current tuple cannot silently reinterpret its frozen
        # historical projection by changing which names count as additions.
        changed_additions = (*plan.SOURCE_PARSER_ADDITIONS,TYPE_PARSER_ADDITIONS[0])
        with patch.object(plan,'SOURCE_PARSER_ADDITIONS',changed_additions):
            with self.assertRaisesRegex(ValueError,'historical type parser identity projection'):
                plan.source_paths()
        changed_additions = (*plan.TYPE_PARSER_ADDITIONS,SOURCE_LEXER_ADDITIONS[0])
        with patch.object(plan,'TYPE_PARSER_ADDITIONS',changed_additions):
            with self.assertRaisesRegex(ValueError,'historical source lexer identity projection'):
                plan.source_paths()
        changed_additions = (*plan.SOURCE_LEXER_ADDITIONS,SHA256_NATIVE_ADDITIONS[0])
        with patch.object(plan,'SOURCE_LEXER_ADDITIONS',changed_additions):
            with self.assertRaisesRegex(ValueError,'historical SHA-256 source identity projection'):
                plan.source_paths()
        changed_additions = (*plan.SHA256_NATIVE_ADDITIONS,JSON_NATIVE_ADDITIONS[0])
        with patch.object(plan,'SHA256_NATIVE_ADDITIONS',changed_additions):
            with self.assertRaisesRegex(ValueError,'historical native JSON source identity projection'):
                plan.source_paths()
        changed_additions = (*plan.JSON_NATIVE_ADDITIONS, PERSISTENT_NDU_INPUTS[0])
        with patch.object(plan, 'JSON_NATIVE_ADDITIONS', changed_additions):
            with self.assertRaisesRegex(ValueError, 'historical persistent NDU source identity projection'):
                plan.source_paths()
        changed_additions = (*plan.P0_P3_ADDITIONS, NATIVE_AGENT_INPUTS[0])
        with patch.object(plan, 'P0_P3_ADDITIONS', changed_additions):
            with self.assertRaisesRegex(ValueError, 'historical native-Agent source identity projection'):
                plan.source_paths()
        changed_additions = (*plan.SAFE_CORE_ADDITIONS, P0_P3_INPUTS[0])
        with patch.object(plan, 'SAFE_CORE_ADDITIONS', changed_additions):
            with self.assertRaisesRegex(ValueError, 'historical P0/P3 source identity projection'):
                plan.source_paths()
        changed_additions = (*plan.SCOPED_AGENT_NDU_ADDITIONS, SAFE_CORE_INPUTS[0])
        with patch.object(plan, 'SCOPED_AGENT_NDU_ADDITIONS', changed_additions):
            with self.assertRaisesRegex(ValueError, 'historical Safe Core source identity projection'):
                plan.source_paths()
        changed_additions = (*plan.PERSISTENT_NDU_ADDITIONS, SAFE_CORE_INPUTS[0])
        with patch.object(plan, 'PERSISTENT_NDU_ADDITIONS', changed_additions):
            with self.assertRaisesRegex(ValueError, 'historical scoped Agent/NDU source identity projection'):
                plan.source_paths()

    def test_duplicate_declared_filename_is_refused(self):
        changed = tuple(sorted((*plan.SOURCE_IDENTITY_PATHS, CACHE_INPUTS[0])))
        with patch.object(plan, 'SOURCE_IDENTITY_PATHS', changed):
            with self.assertRaisesRegex(ValueError, 'reviewed exact source identity closure'):
                plan.source_paths()


if __name__ == '__main__':
    unittest.main()
