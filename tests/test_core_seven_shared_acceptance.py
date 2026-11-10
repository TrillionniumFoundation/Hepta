"""The new protocol keeps the old resource and independent-replay boundaries."""
from contextlib import contextmanager, ExitStack
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from tools import core_seven_relocation_acceptance_plan as old
from tools import core_seven_shared_acceptance_plan as p
from tools import core_seven_shared_acceptance_replay as replay


def fixture_git(root, *args, data=None):
    return subprocess.run(['git', '-C', str(root), *args], input=data,
        env={k: v for k, v in os.environ.items() if not k.startswith('GIT_')},
        capture_output=True, check=True).stdout


def fixture_commit(root, message='fixture'):
    fixture_git(root, '-c', 'user.name=HIAContract',
        '-c', 'user.email=hia@example.invalid', 'commit', '-qm', message)
    return fixture_git(root, 'rev-parse', 'HEAD').decode().strip()


@contextmanager
def source_repository():
    """Small real Git source and binary; all byte/descriptor checks stay real."""
    with tempfile.TemporaryDirectory(prefix='hia-git-source-') as directory:
        root = Path(directory)
        executable = root / 'pinned/bin/lean'
        executable.parent.mkdir(parents=True)
        executable.write_bytes(b'fixture pinned executable\n')
        (root / 'source.rs').write_bytes(b'frozen source\n')
        (root / 'formal').mkdir()
        (root / 'formal/toolchain-lock.json').write_text(json.dumps({
            'lean_binary_sha256': hashlib.sha256(executable.read_bytes()).hexdigest()}))
        fixture_git(root, 'init', '-q')
        fixture_git(root, 'add', 'source.rs', 'formal/toolchain-lock.json')
        fixture_commit(root)
        paths = ('formal/toolchain-lock.json', 'source.rs')
        with ExitStack() as stack:
            stack.enter_context(patch.object(p, 'ROOT', root))
            stack.enter_context(patch.object(p.diagnostic, 'ROOT', root))
            stack.enter_context(patch.object(p, 'SOURCE_IDENTITY_PATHS', paths))
            stack.enter_context(patch.object(p, 'source_paths', return_value=paths))
            stack.enter_context(patch.object(p, 'support_paths', return_value=()))
            yield root, executable


class GitSourceProvenanceTests(unittest.TestCase):
    def test_hidden_replaced_blob_rejected_before_source_admission(self):
        with source_repository() as (root, executable):
            source = root / 'source.rs'
            frozen = source.read_bytes()
            original = fixture_git(root, 'rev-parse', 'HEAD:source.rs').decode().strip()
            admitted = p.External(executable)
            self.assertEqual(admitted.records[str(source)]['sha256'], hashlib.sha256(frozen).hexdigest())
            changed = b'unreviewed replacement\n'
            source.write_bytes(changed)
            replacement = fixture_git(root, 'hash-object', '-w', '--stdin', data=changed).decode().strip()
            fixture_git(root, 'replace', original, replacement)
            fixture_git(root, 'update-index', '--assume-unchanged', 'source.rs')
            # The untracked fixture executable is outside the source closure.
            self.assertEqual(fixture_git(root, 'status', '--porcelain=v1', '--untracked-files=no'), b'')
            self.assertEqual(fixture_git(root, 'cat-file', 'blob', original), changed)
            value = object.__new__(p.External)
            value.executable = executable
            value.paths = dict(admitted.paths)
            value.inodes, value.parents, value.records = {}, {}, {}
            with self.assertRaisesRegex(ValueError, 'canonical HEAD'):
                value.check()
            self.assertEqual((value.inodes, value.parents, value.records), ({}, {}, {}))
            self.assertFalse(hasattr(value, 'git'))
            fixture_git(root, 'replace', '-d', original)
            fixture_git(root, 'update-index', '--no-assume-unchanged', 'source.rs')
            source.write_bytes(frozen)
            self.assertEqual(p.External(executable).git, admitted.git)

    def test_inherited_repository_cannot_relabel_streamed_source(self):
        with source_repository() as (root, executable), tempfile.TemporaryDirectory(prefix='hia-other-git-') as directory:
            expected = p.diagnostic._git_baseline()
            other = Path(directory)
            fixture_git(other, 'init', '-q')
            (other / 'unrelated').write_bytes(b'other repository\n')
            fixture_git(other, 'add', 'unrelated')
            other_head = fixture_commit(other)
            self.assertNotEqual(expected['head'], other_head)
            with patch.dict(os.environ, {'GIT_DIR': str(other / '.git'),
                    'GIT_WORK_TREE': str(other), 'GIT_INDEX_FILE': str(other / '.git/index'),
                    'GIT_CONFIG_COUNT': '1', 'GIT_CONFIG_KEY_0': 'core.sparseCheckout',
                    'GIT_CONFIG_VALUE_0': 'true'}):
                self.assertEqual(p.diagnostic._git_baseline(), expected)
                self.assertEqual(p.External(executable).git, expected)

    def test_baseline_ignores_replacement_commit_tree(self):
        with source_repository() as (root, executable):
            expected = p.diagnostic._git_baseline()
            (root / 'source.rs').write_bytes(b'different tree\n')
            fixture_git(root, 'add', 'source.rs')
            replacement = fixture_commit(root, 'replacement tree')
            fixture_git(root, 'update-ref', 'HEAD', expected['head'])
            fixture_git(root, 'replace', expected['head'], replacement)
            self.assertNotEqual(fixture_git(root, 'rev-parse', 'HEAD^{tree}').decode().strip(), expected['tree'])
            self.assertEqual(p.diagnostic._git_baseline(), expected)

    def test_source_head_move_before_publication_is_rejected(self):
        with source_repository() as (root, executable):
            admitted = p.External(executable)
            original = p.require_canonical_git_blobs
            value = object.__new__(p.External)
            value.executable, value.paths = executable, dict(admitted.paths)
            value.inodes, value.parents, value.records = {}, {}, {}

            def move_head(*args, **kwargs):
                original(*args, **kwargs)
                fixture_git(root, '-c', 'user.name=HIAContract',
                    '-c', 'user.email=hia@example.invalid', 'commit', '--allow-empty', '-qm', 'moved HEAD')

            with patch.object(p, 'require_canonical_git_blobs', side_effect=move_head), self.assertRaisesRegex(ValueError, 'git baseline changed'):
                value.check()
            self.assertEqual((value.inodes, value.parents, value.records), ({}, {}, {}))
            self.assertFalse(hasattr(value, 'git'))


class SharedAcceptanceContractTests(unittest.TestCase):
    def test_every_existing_hard_budget_unchanged(self):
        self.assertEqual(p.BUDGETS, old.BUDGETS)
        # Keep the historical envelope and path projection independently fixed.
        self.assertEqual(old.RAW_GLOBAL, 819891)
        self.assertEqual(old.METADATA_RESERVE, 224589)
        self.assertEqual(old.cap('IDENTITY.json'), 144713)
        self.assertEqual(p.support_paths(), old.support_paths())
        self.assertEqual(len(p.FROZEN_FILES), 81)
        self.assertEqual(len(p.SOURCE_FILES), 22)
        self.assertEqual(len(p.MODULE_FILES), 11)
        h = 'f' * 64

        def maximum_identity(protocol):
            # A serialization bound only; these records are not execution or
            # proof evidence and are never passed to an admission/replay gate.
            return dict(**protocol.common(h), commit_sha='f' * 40,
                tree_sha='f' * 40, lean_binary_sha256=h,
                sources={n: dict(sha256=h, bytes=2097152)
                         for n in protocol.source_paths()},
                support={n: dict(sha256=h, bytes=9223372036854775807)
                         for n in protocol.support_paths()})

        historical = maximum_identity(old)
        identity = maximum_identity(p)
        self.assertEqual(len(old.encode(historical)), 144713)
        self.assertEqual({n: identity['sources'][n] for n in old.source_paths()},
                         historical['sources'])
        union_identity = identity
        self.assertEqual(len(identity['sources']), 436)
        identity = {**identity, 'sources': {n: record for n, record in identity['sources'].items() if n not in p.AGENT_INSTALL_ADDITIONS}}
        self.assertEqual(p.commitment(tuple(sorted(identity['sources']))), 'ec78dce15177423d55341072c713977bfc4f76471df0861bd273a1329fc157dd')
        self.assertEqual(len(p.encode(identity)), 169000)
        self.assertEqual(len(identity['sources']), 421)
        identity = {**identity, 'sources': {n: record for n, record in identity['sources'].items() if n not in p.AGENT_IDENTITY_ADDITIONS}}
        self.assertEqual(p.commitment(tuple(sorted(identity['sources']))), '6c12f6dd1318b6eee2914d88379051087ef837d6c21d58a5b4d82bf0633bc933')
        self.assertEqual(len(p.encode(identity)), 168329)
        self.assertEqual(len(identity['sources']), 416)
        token_parser = {**identity, 'sources': {n: record for n, record in identity['sources'].items() if n not in (*p.SHA256_STREAM_ADDITIONS, *p.JSON_CLI_ADDITIONS, *p.EXPORT_CLI_ADDITIONS, *p.NATIVE_OBSERVER_ADDITIONS, *p.ELF_LINKER_ADDITIONS, *p.SOURCE_TYPES_ADDITIONS, *p.SOURCE_EXPRESSIONS_ADDITIONS)}}
        self.assertEqual(len(token_parser['sources']), 380)
        self.assertEqual(p.commitment(tuple(sorted(token_parser['sources']))), 'b70e5910a8cad3f61d16343c0795cb0a8ae2b89406f5b8fdc91ebdbcd88f4a14')
        self.assertEqual(len(p.encode(token_parser)), 163498)
        token_type = {**identity, 'sources': {n: record for n, record in token_parser['sources'].items() if n not in p.SOURCE_PARSER_ADDITIONS}}
        self.assertEqual(len(token_type['sources']), 375)
        self.assertEqual(p.commitment(tuple(sorted(token_type['sources']))), '49a2a910de52a02227d9d96fcf488df753362970ea79e92521d6e3efc984481e')
        self.assertEqual(len(p.encode(token_type)), 162832)
        identity = {**identity, 'sources': {n: record for n, record in identity['sources'].items() if n not in (*p.TYPE_PARSER_ADDITIONS, *p.SOURCE_PARSER_ADDITIONS)}}
        self.assertEqual(len(identity['sources']), 406)
        self.assertEqual(len(p.encode(identity)), 167000)
        self.assertEqual(p.commitment(tuple(sorted(identity['sources']))), '855761770d145406609a3b2daf764765305b101b0619c50315adee135846ae2a')
        linker_v18 = {**identity, 'sources': {n: record for n, record in identity['sources'].items()
            if n not in (*p.SOURCE_TYPES_ADDITIONS, *p.SOURCE_EXPRESSIONS_ADDITIONS)}}
        self.assertEqual(len(linker_v18['sources']), 396)
        self.assertEqual(p.commitment(tuple(sorted(linker_v18['sources']))),
                         '4997ea6d666023fd9888ede790a63fb3c978d40e32b8d4ba827b9f27cb9a62c4')
        self.assertEqual(len(p.encode(linker_v18)), 165648)
        expressions_v19 = {**identity, 'sources': {n: record for n, record in identity['sources'].items()
            if n not in p.ELF_LINKER_ADDITIONS}}
        self.assertEqual(len(expressions_v19['sources']), 399)
        self.assertEqual(p.commitment(tuple(sorted(expressions_v19['sources']))),
                         '1b2ca83b05da13e0e7f655ddbd41f3979ff6b95696a0037f7ad33f5f0ef5130f')
        self.assertEqual(len(p.encode(expressions_v19)), 166071)
        source_types_v18 = {**identity, 'sources': {
            n: record for n, record in expressions_v19['sources'].items()
            if n not in p.SOURCE_EXPRESSIONS_ADDITIONS}}
        self.assertEqual(len(source_types_v18['sources']), 394)
        self.assertEqual(p.commitment(tuple(sorted(source_types_v18['sources']))),
                         'ba4fcb100a6f27c75e1eb195a32c5c61096b23e02d8de2c2a8c17888574a0379')
        self.assertEqual(len(p.encode(source_types_v18)), 165380)
        integrated_v17 = {**source_types_v18, 'sources': {
            n: record for n, record in source_types_v18['sources'].items()
            if n not in p.SOURCE_TYPES_ADDITIONS}}
        self.assertEqual(len(integrated_v17['sources']), 389)
        self.assertEqual(p.commitment(tuple(sorted(integrated_v17['sources']))),
                         '16c29da84032d30fea440763f05f27eebc2e3327f5db9eabd2871d34cd96770c')
        self.assertEqual(len(p.encode(integrated_v17)), 164719)
        observer_v16 = {**integrated_v17, 'sources': {
            n: record for n, record in integrated_v17['sources'].items()
            if n not in p.SOURCE_LEXER_ADDITIONS}}
        self.assertEqual(len(observer_v16['sources']), 384)
        self.assertEqual(p.commitment(tuple(sorted(observer_v16['sources']))),
                         '5f77c57c507313d1e48179bbcd096dee04e481f071f530f2d8dc9d9cba89acc7')
        self.assertEqual(len(p.encode(observer_v16)), 164058)
        lexer_v14 = {**integrated_v17, 'sources': {
            n: record for n, record in integrated_v17['sources'].items()
            if n not in (*p.SHA256_STREAM_ADDITIONS, *p.JSON_CLI_ADDITIONS, *p.EXPORT_CLI_ADDITIONS, *p.NATIVE_OBSERVER_ADDITIONS)}}
        self.assertEqual(len(lexer_v14['sources']), 370)
        self.assertEqual(p.commitment(tuple(sorted(lexer_v14['sources']))),
                         '414e724f72c675c8cf7139da0710af16ec4417b4926a334b3f5c3c171b3b44f4')
        self.assertEqual(len(p.encode(lexer_v14)), 162169)
        export_native = {**observer_v16, 'sources': {
            n: record for n, record in observer_v16['sources'].items()
            if n not in p.NATIVE_OBSERVER_ADDITIONS}}
        self.assertEqual(len(export_native['sources']), 378)
        self.assertEqual(p.commitment(tuple(sorted(export_native['sources']))),
                         '33d85f096323946e67ae7f9bc7006d1c5996a16234f689c8be83eac33ff2c535')
        self.assertEqual(len(p.encode(export_native)), 163236)
        cli_native = {**export_native, 'sources': {
            n: record for n, record in export_native['sources'].items()
            if n not in p.EXPORT_CLI_ADDITIONS}}
        self.assertEqual(len(cli_native['sources']), 373)
        self.assertEqual(p.commitment(tuple(sorted(cli_native['sources']))),
                         '61cbcf8e3082972e390ce512d12abd141c17b5262f324dacb80791bf73712f55')
        self.assertEqual(len(p.encode(cli_native)), 162581)
        sha_native = {**cli_native, 'sources': {
            n: record for n, record in cli_native['sources'].items()
            if n not in p.JSON_CLI_ADDITIONS}}
        self.assertEqual(len(sha_native['sources']), 369)
        self.assertEqual(p.commitment(tuple(sorted(sha_native['sources']))),
                         '307a88b0ddc4431692a9e41a6121e1eb4f2e69983dff72c7513e0606d2e5e19a')
        self.assertEqual(len(p.encode(sha_native)), 162045)
        json_native = {**sha_native, 'sources': {
            n: record for n, record in sha_native['sources'].items()
            if n not in p.SHA256_NATIVE_ADDITIONS}}
        self.assertEqual(len(json_native['sources']), 360)
        self.assertEqual(p.commitment(tuple(sorted(json_native['sources']))),
                         '84f2d792e39d1f6a5b059026acc14edc321bbe8528c026caa2f06fba55977ad2')
        self.assertEqual(len(p.encode(json_native)), 160877)
        persistent_ndu = {**json_native, 'sources': {
            n: record for n, record in json_native['sources'].items()
            if n not in p.JSON_NATIVE_ADDITIONS}}
        self.assertEqual(len(persistent_ndu['sources']), 337)
        self.assertEqual(p.commitment(tuple(sorted(persistent_ndu['sources']))),
                         '5a6311333c82ea95a464ff9257f190f5712b52e3da90c02169e063ca1698f8dc')
        self.assertEqual(len(p.encode(persistent_ndu)), 157811)
        scoped_agent_ndu = {**persistent_ndu, 'sources': {
            n: record for n, record in persistent_ndu['sources'].items()
            if n not in p.PERSISTENT_NDU_ADDITIONS}}
        self.assertEqual(len(scoped_agent_ndu['sources']), 336)
        self.assertEqual(p.commitment(tuple(sorted(scoped_agent_ndu['sources']))),
                         '9a888e4dbfe883eb74fd8961a5fbc2b90b0cac7b9a6343ef5720145e23be72c7')
        self.assertEqual(len(p.encode(scoped_agent_ndu)), 157680)
        safe_core = {**scoped_agent_ndu, 'sources': {
            n: record for n, record in scoped_agent_ndu['sources'].items()
            if n not in p.SCOPED_AGENT_NDU_ADDITIONS}}
        self.assertEqual(len(safe_core['sources']), 331)
        self.assertEqual(p.commitment(tuple(sorted(safe_core['sources']))),
                         '223c03fa82d871fee3d85d57bb1e254d658a9d85007ec11bea5bfbb1fad5d1b5')
        self.assertEqual(len(p.encode(safe_core)), 157043)
        p0_p3 = {**safe_core, 'sources': {
            n: record for n, record in safe_core['sources'].items()
            if n not in p.SAFE_CORE_ADDITIONS}}
        self.assertEqual(len(p0_p3['sources']), 328)
        self.assertEqual(p.commitment(tuple(sorted(p0_p3['sources']))),
                         '77fb9af75d987acab91d224cf47c5e6734f8c6eb9c4fa895064fba306289a016')
        self.assertEqual(len(p.encode(p0_p3)), 156678)
        previous = {**p0_p3, 'sources': {
            n: record for n, record in p0_p3['sources'].items()
            if n not in p.P0_P3_ADDITIONS}}
        self.assertEqual(len(previous['sources']), 323)
        self.assertEqual(p.commitment(tuple(sorted(previous['sources']))),
                         'd999ff7dc718330771ddb745dbed6a5a7ecdcdea8f9011e35f0a07417f09b9c0')
        self.assertEqual(len(p.encode(previous)), 156044)
        raw_identity = p.encode(union_identity)
        self.assertEqual(len(raw_identity), 170901)
        self.assertEqual(len(p.encode(p0_p3)) - len(p.encode(previous)), 634)
        self.assertEqual(len(p.encode(safe_core)) - len(p.encode(p0_p3)), 365)
        self.assertEqual(len(p.encode(scoped_agent_ndu)) - len(p.encode(safe_core)), 637)
        self.assertEqual(len(p.encode(persistent_ndu)) - len(p.encode(scoped_agent_ndu)), 131)
        self.assertEqual(len(p.encode(json_native)) - len(p.encode(persistent_ndu)), 3066)
        self.assertEqual(len(p.encode(sha_native)) - len(p.encode(json_native)), 1168)
        self.assertEqual(len(p.encode(cli_native)) - len(p.encode(sha_native)), 536)
        self.assertEqual(len(p.encode(export_native)) - len(p.encode(cli_native)), 655)
        self.assertEqual(len(p.encode(observer_v16)) - len(p.encode(export_native)), 822)
        self.assertEqual(len(p.encode(integrated_v17)) - len(p.encode(observer_v16)), 661)
        self.assertEqual(len(p.encode(source_types_v18)) - len(p.encode(integrated_v17)), 661)
        self.assertEqual(len(p.encode(expressions_v19)) - len(p.encode(source_types_v18)), 691)
        self.assertEqual(len(p.encode(identity)) - len(p.encode(expressions_v19)), 929)
        self.assertEqual(len(p.encode(identity)) - len(p.encode(linker_v18)), 1352)
        self.assertEqual(p.cap('IDENTITY.json'), len(raw_identity))
        self.assertEqual(p.IDENTITY_RESERVE_DELTA,
                         len(raw_identity) - len(old.encode(historical)))
        self.assertEqual(p.METADATA_RESERVE, 250777)
        self.assertEqual(p.RAW_GLOBAL, 793703)
        self.assertEqual(p.METADATA_RESERVE - 237556, 131 + 3066 + 1168 + 536 + 655 + 822 + 661 + 661 + 691 + 929 + 1329 + 671 + 1901)
        self.assertEqual(806924 - p.RAW_GLOBAL, 131 + 3066 + 1168 + 536 + 655 + 822 + 661 + 661 + 691 + 929 + 1329 + 671 + 1901)
        self.assertEqual(p.METADATA_RESERVE - 236919, 637 + 131 + 3066 + 1168 + 536 + 655 + 822 + 661 + 661 + 691 + 929 + 1329 + 671 + 1901)
        self.assertEqual(807561 - p.RAW_GLOBAL, 637 + 131 + 3066 + 1168 + 536 + 655 + 822 + 661 + 661 + 691 + 929 + 1329 + 671 + 1901)
        self.assertEqual(p.METADATA_RESERVE - 236554, 365 + 637 + 131 + 3066 + 1168 + 536 + 655 + 822 + 661 + 661 + 691 + 929 + 1329 + 671 + 1901)
        self.assertEqual(807926 - p.RAW_GLOBAL, 365 + 637 + 131 + 3066 + 1168 + 536 + 655 + 822 + 661 + 661 + 691 + 929 + 1329 + 671 + 1901)
        self.assertEqual(p.METADATA_RESERVE - 235920, 634 + 365 + 637 + 131 + 3066 + 1168 + 536 + 655 + 822 + 661 + 661 + 691 + 929 + 1329 + 671 + 1901)
        self.assertEqual(808560 - p.RAW_GLOBAL, 634 + 365 + 637 + 131 + 3066 + 1168 + 536 + 655 + 822 + 661 + 661 + 691 + 929 + 1329 + 671 + 1901)
        self.assertEqual(p.METADATA_RESERVE - old.METADATA_RESERVE,
                         old.RAW_GLOBAL - p.RAW_GLOBAL)
        self.assertEqual(p.METADATA_RESERVE + p.RAW_GLOBAL + p.BUDGETS['display'],
                         p.BUDGETS['evidence_display'])
        p.budgets({'IDENTITY.json': raw_identity})
        with self.assertRaisesRegex(ValueError, 'fixed per-file caps'):
            p.budgets({'IDENTITY.json': raw_identity + b' '})

        # Exercise the unchanged one-MiB aggregate at its exact boundary, then
        # reject either allocation growing by one byte. This tests accounting,
        # not whether these deliberately opaque bytes are valid proof records.
        files = {'IDENTITY.json': raw_identity,
                 'PLAN.json': b'p' * p.cap('PLAN.json'),
                 'shared-manifest.json': b'm' * p.cap('shared-manifest.json'),
                 'RUN.json': b'r' * p.cap('RUN.json')}
        files['RESULT.json'] = b'r' * (p.METADATA_RESERVE - sum(map(len, files.values())))
        files[p.LOG_FILES[0]] = b'l' * p.BUDGETS['raw_stage']
        files[p.LOG_FILES[2]] = b'l' * (p.RAW_GLOBAL - p.BUDGETS['raw_stage'])
        display = b'd' * p.BUDGETS['display']
        p.budgets(files, display)
        with self.assertRaisesRegex(ValueError, 'aggregate payload caps'):
            p.budgets({**files, p.LOG_FILES[2]: files[p.LOG_FILES[2]] + b'l'}, display)
        with self.assertRaisesRegex(ValueError, 'aggregate evidence/container caps'):
            p.budgets({**files, 'RESULT.json': files['RESULT.json'] + b'r'}, display)

    def test_source_identity_includes_every_new_trust_dependency(self):
        paths = p.source_paths()
        self.assertEqual(len(paths), 436)
        self.assertTrue(set(old.source_paths()) < set(paths))
        for name in (*p.ADDITIONS, *p.ROUND6_ADDITIONS, *p.LINUX_ADDITIONS, *p.NATIVE_AGENT_ADDITIONS, *p.P0_P3_ADDITIONS, *p.SAFE_CORE_ADDITIONS, *p.SCOPED_AGENT_NDU_ADDITIONS, *p.PERSISTENT_NDU_ADDITIONS, *p.JSON_NATIVE_ADDITIONS, *p.SHA256_NATIVE_ADDITIONS, *p.JSON_CLI_ADDITIONS, *p.EXPORT_CLI_ADDITIONS, *p.NATIVE_OBSERVER_ADDITIONS, *p.SOURCE_LEXER_ADDITIONS, *p.SOURCE_TYPES_ADDITIONS, *p.SOURCE_EXPRESSIONS_ADDITIONS, *p.TYPE_PARSER_ADDITIONS, *p.SOURCE_PARSER_ADDITIONS):
            self.assertIn(name, paths)
            self.assertTrue((p.ROOT / name).is_file(), name)
        self.assertIn(p.shared.HELPER_PATH, paths)
        for name in ('CORE_MODEL_CONNECTION.md', 'UNSIGNED_STEP_CONNECTION.md'):
            self.assertIn('experiments/hia_initialization_frontiers_20261103/' + name, paths)


    def test_actual_compiler_hash_reads_cannot_escape_source_identity(self):
        registered = p.source_paths()
        expected = tuple(n for n in registered if n.startswith('hepta/') and
                         n.count('/') == 1 and n.endswith('.py'))
        self.assertEqual(len(expected), 225)
        self.assertEqual(expected, tuple(sorted(x.relative_to(p.ROOT).as_posix()
                         for x in (p.ROOT / 'hepta').glob('*.py'))))
        with tempfile.TemporaryDirectory(prefix='hia-compiler-inputs-') as directory:
            root = Path(directory)
            (root / 'hepta').mkdir()
            for name in expected:
                (root / name).write_bytes(b'')
            with patch.object(p, 'ROOT', root):
                self.assertEqual(p.source_paths(), registered)
                unbound = root / 'hepta' / 'unbound_compiler_input.py'
                unbound.write_text('UNREGISTERED = True\n')
                with self.assertRaisesRegex(ValueError, 'compiler_hash input set'):
                    p.source_paths()
                unbound.unlink()
                (root / expected[0]).unlink()
                with self.assertRaisesRegex(ValueError, 'compiler_hash input set'):
                    p.source_paths()

    def test_success_flag_cannot_replace_complete_replay(self):
        with tempfile.TemporaryDirectory(prefix='hia-shared-') as directory:
            Path(directory, 'RESULT.json').write_text(json.dumps({
                'status': 'passed', 'kernel_core_syntax_connection_checked': True}))
            with self.assertRaises(ValueError):
                replay.verify_evidence(directory)

    def test_source_generation_never_grants_broader_authority(self):
        for checked in (False, True):
            flags = p.flags(checked)
            self.assertFalse(flags['actual_core_bridge_proved'])
            self.assertFalse(flags['python_exporter_refinement_proved'])
            self.assertTrue(all(x['status'] == 'unproved' for x in flags['obligations']))
            self.assertEqual(flags['authority']['authority'], 'DENY_ALL')
            self.assertFalse(flags['authority']['production_admission'])

    def test_timeouts_and_unobserved_cleanup_still_fail(self):
        process = dict(spawned=True, returncode=0, timed_out=False, incomplete=False,
            output_truncated=False, leader_reaped=True, stdout_eof=True, stderr_eof=True,
            original_group_empty=True, elapsed_ns=1, cleanup_ns=1, leader_pid=123,
            original_pgid=123, leader_start_ticks=1, terminal_observation='waitid_wnowait',
            pre_reap_group_signal='sigkill_sent', leader_reap_observed=True,
            post_reap_group_probe='esrch')
        p.validate_process(process, success=True)
        for changed in ({'elapsed_ns': 60000000000}, {'cleanup_ns': 2000000000},
                        {'leader_reap_observed': False}, {'stdout_eof': False},
                        {'original_group_empty': False}, {'timed_out': True}):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                p.validate_process({**process, **changed}, success=True)


if __name__ == '__main__':
    unittest.main()
