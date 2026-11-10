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
    'examples/hia_bootstrap/sha256_stream.hiaasm',
    'hepta/hia_sha256_native.py',
    'hepta/hia_sha256_stream_native.py',
    'tests/test_hia_sha256_native.py',
    'tests/test_hia_sha256_stream_native.py',
    'tools/build_hia_sha256.py',
    'tools/generate_hia_sha256.py',
    'tools/generate_hia_sha256_stream.py',
)

PRIOR_COMMITMENT = '36af03771b8b81803d90baafc92fd290d9e6cadbb03e7e135a99beae804bb0f0'
ROUND4_COMMITMENT = 'ffc0f4bd9585328bb21e99d0fe3bac7717b65d823a72cb5de9987886018055db'
ROUND5_COMMITMENT = 'd27b4d1edaa27950489d7b54fa6b8242b493883d0927933fa303e5b1203c9c55'
LINUX_COMMITMENT = 'a48ba3c0244975ebaf4219e6409a0293fa3ae7339704554dc4ba1f3e0c6eb86c'
NATIVE_AGENT_COMMITMENT = 'd999ff7dc718330771ddb745dbed6a5a7ecdcdea8f9011e35f0a07417f09b9c0'
P0_P3_COMMITMENT = '77fb9af75d987acab91d224cf47c5e6734f8c6eb9c4fa895064fba306289a016'
SAFE_CORE_COMMITMENT = '223c03fa82d871fee3d85d57bb1e254d658a9d85007ec11bea5bfbb1fad5d1b5'
SCOPED_AGENT_NDU_COMMITMENT = '9a888e4dbfe883eb74fd8961a5fbc2b90b0cac7b9a6343ef5720145e23be72c7'
PERSISTENT_NDU_COMMITMENT = '5a6311333c82ea95a464ff9257f190f5712b52e3da90c02169e063ca1698f8dc'
JSON_NATIVE_COMMITMENT = '84f2d792e39d1f6a5b059026acc14edc321bbe8528c026caa2f06fba55977ad2'
SHA256_NATIVE_COMMITMENT = '307a88b0ddc4431692a9e41a6121e1eb4f2e69983dff72c7513e0606d2e5e19a'
JSON_CLI_COMMITMENT = '61cbcf8e3082972e390ce512d12abd141c17b5262f324dacb80791bf73712f55'
EXPORT_CLI_COMMITMENT = '33d85f096323946e67ae7f9bc7006d1c5996a16234f689c8be83eac33ff2c535'
OBSERVER_V16_COMMITMENT = '5f77c57c507313d1e48179bbcd096dee04e481f071f530f2d8dc9d9cba89acc7'
INTEGRATED_V17_COMMITMENT = '16c29da84032d30fea440763f05f27eebc2e3327f5db9eabd2871d34cd96770c'
TYPES_V18_COMMITMENT = 'ba4fcb100a6f27c75e1eb195a32c5c61096b23e02d8de2c2a8c17888574a0379'
CURRENT_COMMITMENT = 'af317b47191d0c1f0a68aab03fd3991e5501fa673dbb2814d3f3553a455ae6a5'
JSON_CLI_ADDITIONS = (
    'examples/hia_bootstrap/core_json_cli_packer.hiaasm',
    'tests/test_hia_core_json_cli.py',
    'tools/build_hia_core_json_cli.py',
    'tools/generate_hia_core_json_cli.py',
)
EXPORT_CLI_ADDITIONS = (
    'tools/hia_selfhost_exports.py',
    'tools/hia_selfhost_exports_cases.py',
    'tools/hia_selfhost_exports_child.py',
    'tools/qualify_hia_selfhost_exports.py',
    'tests/test_hia_selfhost_exports.py',
)
NATIVE_OBSERVER_ADDITIONS = (
    'docs/HIA_NATIVE_BYTE_ABI_OBSERVER.md',
    'tools/generate_hia_native_observer.py',
    'tools/hia_selfhost_native_observer.py',
    'tools/hia_native_observer_template.S',
    'tests/test_hia_selfhost_native_observer.py',
    'examples/hia_bootstrap/native_observer_packer.hiaasm',
)
SOURCE_LEXER_ADDITIONS = (
    'examples/hia_bootstrap/source_lexer.hiaasm',
    'hepta/hia_source_lexer_native.py',
    'tests/test_hia_source_lexer_native.py',
    'tools/build_hia_source_lexer.py',
    'tools/generate_hia_source_lexer.py',
)
SHA256_STREAM_ADDITIONS = (
    'examples/hia_bootstrap/sha256_stream.hiaasm',
    'hepta/hia_sha256_stream_native.py',
    'tests/test_hia_sha256_stream_native.py',
    'tools/generate_hia_sha256_stream.py',
)
SOURCE_TYPES_ADDITIONS = (
    'examples/hia_bootstrap/source_types.hiaasm',
    'hepta/hia_source_types_native.py',
    'tests/test_hia_source_types_native.py',
    'tools/build_hia_source_types.py',
    'tools/generate_hia_source_types.py',
)
SOURCE_FRONTEND_ADDITIONS = (
    'examples/hia_bootstrap/source_clauses.hiaasm',
    'examples/hia_bootstrap/source_expressions.hiaasm',
    'examples/hia_bootstrap/source_names.hiaasm',
    'hepta/hia_source_clauses_native.py',
    'hepta/hia_source_expressions_native.py',
    'hepta/hia_source_frontend_native.py',
    'hepta/hia_source_names_native.py',
    'tests/test_hia_source_clauses_native.py',
    'tests/test_hia_source_expressions_native.py',
    'tests/test_hia_source_frontend_native.py',
    'tests/test_hia_source_names_native.py',
    'tools/build_hia_source_clauses.py',
    'tools/build_hia_source_expressions.py',
    'tools/build_hia_source_frontend.py',
    'tools/build_hia_source_names.py',
    'tools/generate_hia_source_clauses.py',
    'tools/generate_hia_source_expressions.py',
    'tools/generate_hia_source_names.py',
)
NEW_INPUTS = (*CACHE_INPUTS, 'tests/test_core_seven_shared_source_closure.py', *VALIDATION_INPUTS, *ROUND5_VALIDATION_INPUTS, *ROUND6_INPUTS, *LINUX_INPUTS, *NATIVE_AGENT_INPUTS, *P0_P3_INPUTS, *SAFE_CORE_INPUTS, *SCOPED_AGENT_NDU_INPUTS, *PERSISTENT_NDU_INPUTS, *JSON_NATIVE_ADDITIONS, *SHA256_NATIVE_ADDITIONS, *JSON_CLI_ADDITIONS, *EXPORT_CLI_ADDITIONS, *NATIVE_OBSERVER_ADDITIONS, *SOURCE_LEXER_ADDITIONS, *SOURCE_TYPES_ADDITIONS, *SOURCE_FRONTEND_ADDITIONS)


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
        self.assertEqual(len(actual), 412)
        self.assertEqual(plan.SOURCE_FRONTEND_ADDITIONS, SOURCE_FRONTEND_ADDITIONS)
        self.assertEqual(len(SOURCE_FRONTEND_ADDITIONS), 18)
        types_v18 = tuple(n for n in actual if n not in SOURCE_FRONTEND_ADDITIONS)
        self.assertEqual(len(types_v18), 394)
        self.assertEqual(plan.commitment(types_v18), TYPES_V18_COMMITMENT)
        self.assertEqual(plan.SOURCE_TYPES_ADDITIONS, SOURCE_TYPES_ADDITIONS)
        integrated_v17 = tuple(n for n in types_v18 if n not in SOURCE_TYPES_ADDITIONS)
        self.assertEqual(len(integrated_v17), 389)
        self.assertEqual(plan.commitment(integrated_v17), INTEGRATED_V17_COMMITMENT)
        self.assertEqual(plan.SOURCE_LEXER_ADDITIONS, SOURCE_LEXER_ADDITIONS)
        self.assertEqual(plan.SHA256_STREAM_ADDITIONS, SHA256_STREAM_ADDITIONS)
        lexer_v14 = tuple(n for n in integrated_v17 if n not in (*SHA256_STREAM_ADDITIONS, *JSON_CLI_ADDITIONS, *EXPORT_CLI_ADDITIONS, *NATIVE_OBSERVER_ADDITIONS))
        self.assertEqual(len(lexer_v14), 370)
        self.assertEqual(plan.commitment(lexer_v14), '414e724f72c675c8cf7139da0710af16ec4417b4926a334b3f5c3c171b3b44f4')
        observer_v16 = tuple(n for n in integrated_v17 if n not in SOURCE_LEXER_ADDITIONS)
        self.assertEqual(len(observer_v16), 384)
        self.assertEqual(plan.commitment(observer_v16), OBSERVER_V16_COMMITMENT)
        self.assertEqual(plan.NATIVE_OBSERVER_ADDITIONS, NATIVE_OBSERVER_ADDITIONS)
        export_native = tuple(name for name in observer_v16 if name not in NATIVE_OBSERVER_ADDITIONS)
        self.assertEqual(len(export_native), 378)
        self.assertEqual(plan.commitment(export_native), EXPORT_CLI_COMMITMENT)
        self.assertEqual(plan.EXPORT_CLI_ADDITIONS, EXPORT_CLI_ADDITIONS)
        cli_native = tuple(name for name in export_native if name not in EXPORT_CLI_ADDITIONS)
        self.assertEqual(len(cli_native), 373)
        self.assertEqual(plan.commitment(cli_native), JSON_CLI_COMMITMENT)
        self.assertEqual(plan.JSON_CLI_ADDITIONS, JSON_CLI_ADDITIONS)
        sha_native = tuple(name for name in cli_native if name not in JSON_CLI_ADDITIONS)
        self.assertEqual(len(sha_native), 369)
        self.assertEqual(plan.commitment(sha_native), SHA256_NATIVE_COMMITMENT)
        self.assertEqual(plan.NATIVE_AGENT_ADDITIONS, NATIVE_AGENT_INPUTS)
        self.assertEqual(plan.P0_P3_ADDITIONS, P0_P3_INPUTS)
        self.assertEqual(plan.SAFE_CORE_ADDITIONS, SAFE_CORE_INPUTS)
        self.assertEqual(plan.SCOPED_AGENT_NDU_ADDITIONS, SCOPED_AGENT_NDU_INPUTS)
        self.assertEqual(plan.PERSISTENT_NDU_ADDITIONS, PERSISTENT_NDU_INPUTS)
        self.assertEqual(plan.JSON_NATIVE_ADDITIONS, JSON_NATIVE_ADDITIONS)
        self.assertEqual(plan.SHA256_NATIVE_ADDITIONS, SHA256_NATIVE_ADDITIONS)
        json_native = tuple(name for name in sha_native if name not in SHA256_NATIVE_ADDITIONS)
        self.assertEqual(len(json_native), 360)
        self.assertEqual(plan.commitment(json_native), JSON_NATIVE_COMMITMENT)
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
                                      if name not in (*VALIDATION_INPUTS, *ROUND5_VALIDATION_INPUTS, *ROUND6_INPUTS, *LINUX_INPUTS, *NATIVE_AGENT_INPUTS, *P0_P3_INPUTS, *SAFE_CORE_INPUTS, *SCOPED_AGENT_NDU_INPUTS, *PERSISTENT_NDU_INPUTS, *JSON_NATIVE_ADDITIONS, *SHA256_NATIVE_ADDITIONS, *JSON_CLI_ADDITIONS, *EXPORT_CLI_ADDITIONS, *NATIVE_OBSERVER_ADDITIONS, *SOURCE_LEXER_ADDITIONS, *SOURCE_TYPES_ADDITIONS, *SOURCE_FRONTEND_ADDITIONS))
        self.assertEqual(len(before_new_controls), 261)
        self.assertEqual(plan.commitment(before_new_controls),
                         '5758e93bc7e92d4b10370593c3f20b713741b7530d977507a1430c6eb9cfb0eb')
        self.assertEqual(sum(name.startswith('hepta/') and name.count('/') == 1
                             and name.endswith('.py') for name in actual), 225)
        for name in NEW_INPUTS:
            self.assertTrue((plan.ROOT / name).is_file(), name)

    def test_each_new_compiler_module_is_required(self):
        with compiler_directory() as root, patch.object(plan, 'ROOT', root):
            for name in (*(n for n in (*JSON_NATIVE_ADDITIONS, *SHA256_NATIVE_ADDITIONS, *SOURCE_LEXER_ADDITIONS, *SOURCE_TYPES_ADDITIONS, *SOURCE_FRONTEND_ADDITIONS) if n.startswith('hepta/')), *CACHE_INPUTS, *ROUND6_COMPILER_INPUTS, *LINUX_COMPILER_INPUTS, *NATIVE_AGENT_INPUTS, *P0_P3_INPUTS, *SAFE_CORE_INPUTS, *SCOPED_AGENT_NDU_INPUTS, *PERSISTENT_NDU_INPUTS):
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
        changed_additions = (*plan.SOURCE_TYPES_ADDITIONS, SOURCE_LEXER_ADDITIONS[0])
        with patch.object(plan, 'SOURCE_TYPES_ADDITIONS', changed_additions):
            with self.assertRaisesRegex(ValueError, 'historical integrated native stack identity projection'):
                plan.source_paths()
        changed_additions = (*plan.SOURCE_LEXER_ADDITIONS, NATIVE_OBSERVER_ADDITIONS[0])
        with patch.object(plan, 'SOURCE_LEXER_ADDITIONS', changed_additions):
            with self.assertRaisesRegex(ValueError, 'historical native observer source identity projection'):
                plan.source_paths()
        changed_additions = (*plan.SHA256_STREAM_ADDITIONS, JSON_NATIVE_ADDITIONS[0])
        with patch.object(plan, 'SHA256_STREAM_ADDITIONS', changed_additions):
            with self.assertRaisesRegex(ValueError, 'historical source lexer fork identity projection'):
                plan.source_paths()
        changed_additions = (*plan.NATIVE_OBSERVER_ADDITIONS, EXPORT_CLI_ADDITIONS[0])
        with patch.object(plan, 'NATIVE_OBSERVER_ADDITIONS', changed_additions):
            with self.assertRaisesRegex(ValueError, 'historical combined JSON CLI/export source identity projection'):
                plan.source_paths()
        changed_additions = (*plan.EXPORT_CLI_ADDITIONS, JSON_CLI_ADDITIONS[0])
        with patch.object(plan, 'EXPORT_CLI_ADDITIONS', changed_additions):
            with self.assertRaisesRegex(ValueError, 'historical native JSON CLI source identity projection'):
                plan.source_paths()
        changed_additions = (*plan.JSON_CLI_ADDITIONS, SHA256_NATIVE_ADDITIONS[0])
        with patch.object(plan, 'JSON_CLI_ADDITIONS', changed_additions):
            with self.assertRaisesRegex(ValueError, 'historical source lexer fork identity projection'):
                plan.source_paths()
        changed_additions = (*plan.SHA256_NATIVE_ADDITIONS, JSON_NATIVE_ADDITIONS[0])
        with patch.object(plan, 'SHA256_NATIVE_ADDITIONS', changed_additions):
            with self.assertRaisesRegex(ValueError, 'historical JSON native source identity projection'):
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

    def test_source_frontend_additions_cannot_reinterpret_v18(self):
        changed = {
            'omitted': SOURCE_FRONTEND_ADDITIONS[1:],
            'historical-added': (*SOURCE_FRONTEND_ADDITIONS, SOURCE_TYPES_ADDITIONS[0]),
            'same-count-swap': (*SOURCE_FRONTEND_ADDITIONS[1:], SOURCE_TYPES_ADDITIONS[0]),
            'duplicate': (*SOURCE_FRONTEND_ADDITIONS, SOURCE_FRONTEND_ADDITIONS[0]),
            'unknown-added': (*SOURCE_FRONTEND_ADDITIONS, 'hepta/unreviewed.py'),
        }
        for label, additions in changed.items():
            with self.subTest(change=label), patch.object(plan, 'SOURCE_FRONTEND_ADDITIONS', additions):
                with self.assertRaisesRegex(ValueError, 'historical source type grammar identity projection'):
                    plan.source_paths()


if __name__ == '__main__':
    unittest.main()
