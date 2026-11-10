"""Closed shared-composition acceptance plan and unchanged finite evidence limits.

No compiler execution here. Fixed hash commitments use canonical JSON plus LF;
legacy source manifest bytes retain their original no-LF protocol.
"""
from dataclasses import replace
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import re
import stat
import subprocess

from tools import check_core_syntax_staged as base
from tools import core_seven_certificate_sources as seven
from tools import core_seven_shared_sources as shared
from tools import core_seven_relocation_acceptance_plan as legacy
from tools import diagnose_core_seven_certificate as diagnostic
from tools.check_guarded_slice_lean import require

ROOT = base.ROOT
SCHEMA = 'hepta.hia.seven-shared-acceptance.v16'
PROTOCOL = 'seven-shared-acceptance-v16'
ADDITIONS = (
    'experiments/hia_initialization_frontiers_20261103/CORE_MODEL_CONNECTION.md',
    'experiments/hia_initialization_frontiers_20261103/UNSIGNED_STEP_CONNECTION.md',
    'hepta/hia_byte_sum.py',
    'hepta/hia_entry_layout.py',
    'hepta/hia_ndu_dynamic.py',
    'hepta/hia_ndu_raw_model.py',
    'hepta/hia_ndu_raw_session.py',
    'hepta/hia_result_cache.py',
    'hepta/hia_result_cache_audit.py',
    'docs/seven-data-nocode.md',
    'docs/seven-shared-composition.md',
    'experiments/hia_initialization_frontiers_20261103/SharedTransport.lean',
    'tests/test_core_seven_nocode_sources.py',
    'tests/test_core_seven_shared_acceptance.py',
    'tests/test_core_seven_shared_sources.py',
    'tests/test_core_seven_shared_source_closure.py',
    'tests/test_core_structured_source_cost.py',
    'tests/test_core_syntax_partition_parse_fast.py',
    'tests/test_core_seven_external_hash.py',
    'tests/test_core_capture_cleanup_replay.py',
    'tools/check_core_seven_shared.py',
    'tools/core_seven_nocode_sources.py',
    'tools/core_seven_shared_acceptance_plan.py',
    'tools/core_seven_shared_acceptance_replay.py',
    'tools/core_seven_shared_sources.py',
    'tools/diagnose_core_seven_nocode.py',
    'tests/test_hia_scalar_return_signature.py',
    'tests/test_hia_ndu_preparation_bound.py',
)
ROUND6_ADDITIONS = (
    'benchmarks/hia_ndu_policy_evolution/PROTOCOL.json',
    'benchmarks/hia_stb_service/PROTOCOL.json',
    'benchmarks/hia_stb_service/baseline.rs',
    'benchmarks/hia_stb_service/driver.c',
    'benchmarks/hia_upstream_factorial/PROTOCOL.json',
    'benchmarks/hia_upstream_factorial/README.md',
    'benchmarks/hia_upstream_factorial/UPSTREAM_FIX.json',
    'benchmarks/hia_upstream_factorial/UPSTREAM_TASKS.json',
    'benchmarks/hia_upstream_factorial/c_stb_div_floor-before.hiaasm',
    'benchmarks/hia_upstream_factorial/c_stb_mod_eucl-after.hiaasm',
    'benchmarks/hia_upstream_factorial/c_stb_mod_eucl-before.hiaasm',
    'benchmarks/hia_upstream_factorial/evaluator.py',
    'benchmarks/hia_upstream_factorial/floor_reference.hiaasm',
    'benchmarks/hia_upstream_factorial/tasks.py',
    'tests/test_hia_upstream_factorial.py',
    'tools/qualify_hia_upstream_factorial.py',
    'docs/HIA_BOUNDED_BYTE_PROFILE.md',
    'docs/HIA_NDU_POLICY_EVOLUTION.md',
    'docs/HIA_FRONTIER_FACTORIAL.md',
    'docs/HIA_STB_SERVICE.md',
    'hepta/hia_ndu_module_costs.py',
    'hepta/hia_ndu_policy.py',
    'tests/test_hia_agent_frontier_factorial.py',
    'tests/test_hia_agent_sealed_execution.py',
    'tests/test_hia_bounded_profile.py',
    'tests/test_hia_ndu_policy.py',
    'tests/test_hia_stb_service.py',
    'tools/qualify_hia_agent_frontier_factorial.py',
    'tools/qualify_hia_ndu_policy_evolution.py',
    'tools/qualify_hia_stb_service.py',
    'tools/qualify_hia_agent_provider.py',
    'tests/test_hia_agent_provider.py',
    'tools/qualify_hia_composition.py',
    'experiments/hia_agent_assembly_v4_20261030/evaluator.py',
    'experiments/hia_round4_20261105/run_frozen_candidate.py',
    'tests/test_hia_composition_raw_identity.py',
    'tools/build_hia_ndu_bridge.py',
    'tools/build_hia_ndu_dynamic_bridge.py',
    'rust/hia-ndu-dynamic-model/src/main.rs',
    'rust/hia-ndu-dynamic-model/src/planner.rs',
    'rust/hia-ndu-dynamic-model/src/model.rs',
    'rust/hia-ndu-dynamic-model/src/ndu.rs',
    'rust/hia-ndu-dynamic-model/src/workload.rs',
    'rust/hia-ndu-dynamic-model/Cargo.toml',
    'rust/hia-ndu-dynamic-model/Cargo.lock',
    'rust/hia-ndu-dynamic-model/upstream.json',
)
LINUX_ADDITIONS = ('hepta/hia_linux_kernel.py',)
# Reviewed direct-machine encoder/emitter and Agent execution boundaries. This
# explicit addition is not discovered from the filesystem: a future module
# still requires a new reviewed count/commitment and historical projection.
NATIVE_AGENT_ADDITIONS = (
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
# The unified candidate extends the reviewed native-Agent inventory explicitly;
# its five new compiler_hash inputs do not alter the historical 323-path tuple.
P0_P3_ADDITIONS = (
    'hepta/hia_agent_macro_discovery.py',
    'hepta/hia_agent_macro_policy.py',
    'hepta/hia_machine_plan.py',
    'hepta/hia_native_byte_abi.py',
    'hepta/hia_native_byte_runner.py',
)
# Existing reviewed Safe Core verifier and final-image emitters are also actual
# compiler_hash inputs. Bind these exact names without changing the historical
# 328-path P0/P3 or 323-path native-Agent projections.
SAFE_CORE_ADDITIONS = (
    'hepta/hia_safe_core.py',
    'hepta/hia_safe_core_elf.py',
    'hepta/hia_safe_core_x64.py',
)
# Review the two new buffer/prepared modules and the three already installed
# scalar-selection/proof modules. Preserve the exact historical 331-path
# Safe Core projection instead of accepting a filesystem-discovered expansion.
SCOPED_AGENT_NDU_ADDITIONS = (
    'hepta/hia_agent_buffers.py',
    'hepta/hia_ndu_prepared_ranker.py',
    'hepta/hia_ndu_scalar_selection.py',
    'hepta/hia_proof_contract.py',
    'hepta/hia_scalar_proof_contract.py',
)
# Explicit bounded native-process owner. Keep the earlier 336-path checkpoint
# independently reproducible when reviewing this additional compiler input.
PERSISTENT_NDU_ADDITIONS = ('hepta/hia_ndu_persistent_ranker.py',)
# Explicit reviewed HIA JSON source/image, host selection/build and conformance
# inputs. Do not discover a permissive closure from the filesystem. The entire
# prior 337-path checkpoint remains an independently pinned projection.
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
# Exact whole-parser inputs transfer 666 bytes from logs to identity metadata.
# All aggregate/source/module/process caps and prior projections are unchanged.
IDENTITY_CAP = 163498
IDENTITY_RESERVE_DELTA = 18785
METADATA_RESERVE = 224589 + IDENTITY_RESERVE_DELTA
RAW_GLOBAL = 819891 - IDENTITY_RESERVE_DELTA
BUDGETS = dict(source=2097152, sources=8388608, module=33554432, modules=134217728,
               raw_stage=507392, metadata=262144, evidence_display=1048576,
               container=143654912, display=4096, process_ns=60000000000,
               launch_ns=540000000000, cleanup_ns=2000000000, outer_seconds=600, job_minutes=15)
SOURCE_FILES = tuple('original/' + n + '.lean' for n in seven.original.NAMES) + tuple(
    'HiaSyntaxResearch/' + n + '.lean' for n in seven.NAMES)
MODULE_FILES = tuple('HiaSyntaxResearch/' + n + '.olean' for n in seven.NAMES)
LOG_FILES = tuple(n + '.' + stream for n in seven.NAMES for stream in ('stdout', 'stderr'))
RECEIPT_FILES = tuple(n + '.' + kind + '.json' for n in seven.NAMES for kind in ('started', 'finished'))
GLOBALS = ('IDENTITY.json', 'PLAN.json', 'RUN.json', 'shared-manifest.json')
FROZEN_FILES = frozenset(SOURCE_FILES + MODULE_FILES + LOG_FILES + RECEIPT_FILES + GLOBALS)
TERMINALS = ('RESULT.json', 'RESULT.pending.json', 'FAILURE.json')
FIXED_FILES = FROZEN_FILES | set(TERMINALS)
PHASE_CODES = {
    'preparation_invalid': ('preparation',),
    'identity_changed': ('preparation', 'prelaunch', 'verifying', 'receipt_commit', 'finalization'),
    'launch_deadline': ('prelaunch',),
    **{c: ('capturing',) for c in ('process_timeout', 'process_failed', 'output_limit', 'capture_incomplete', 'cleanup_failed')},
    **{c: ('verifying',) for c in ('inventory_invalid', 'module_invalid')},
    **{c: ('preparation', 'prelaunch', 'capturing', 'verifying', 'receipt_commit', 'finalization')
       for c in ('filesystem_invalid', 'evidence_limit')},
    'receipt_failed': ('prelaunch', 'receipt_commit'), 'finalization_failed': ('finalization',)}
SCOPE = 'Narrow Core syntax connection only; all twelve wider obligations unproved; DENY_ALL.'
digest = base.digest


def encode(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False) + '\n').encode()


def commitment(value):
    return digest(encode(value))


def same(a, b):
    return encode(a) == encode(b)


def parse(raw, *, newline=True):
    def pairs(items):
        out = {}
        for key, value in items:
            require(key not in out, 'duplicate JSON key')
            out[key] = value
        return out
    def constant(_):
        raise ValueError('nonfinite JSON')
    value = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    require(type(value) is dict and raw == (encode(value) if newline else encode(value)[:-1]), 'noncanonical JSON object')
    return value


def integer(value, low, high):
    require(type(value) is int and low <= value <= high, 'integer range/type')
    return value


def hash_value(value, length=64):
    require(type(value) is str and re.fullmatch('[0-9a-f]{%d}' % length, value), 'hash format')
    return value


def absolute(value):
    require(type(value) is str and len(value.encode()) <= 128 and re.fullmatch(r'/[A-Za-z0-9._/-]+', value)
            and all(c not in ('', '.', '..') for c in value.split('/')[1:]), 'absolute path alphabet/canonical form')
    require(str(Path(value).resolve(strict=False)) == value, 'path resolution differs')
    return value


def common(run_id):
    return dict(schema=SCHEMA, protocol=PROTOCOL, run_id=hash_value(run_id))


def flags(success=False):
    return dict(kernel_core_syntax_connection_checked=success, actual_core_bridge_proved=False,
                python_exporter_refinement_proved=False, body_prefix_refinement_proved=False,
                all_edge_transfer_proved=False,
                obligations=[dict(id=n, status='unproved') for n, _ in seven.facts.OBLIGATIONS],
                authority=dict(seven.facts.DENY))


# Frozen exact identity paths: do not hash files merely to discover their names.
SOURCE_IDENTITY_PATHS = tuple(sorted((*legacy.SOURCE_IDENTITY_PATHS, *ADDITIONS,
                                    *ROUND6_ADDITIONS, *LINUX_ADDITIONS,
                                    *NATIVE_AGENT_ADDITIONS, *P0_P3_ADDITIONS,
                                    *SAFE_CORE_ADDITIONS, *SCOPED_AGENT_NDU_ADDITIONS,
                                    *PERSISTENT_NDU_ADDITIONS, *JSON_NATIVE_ADDITIONS, *SHA256_NATIVE_ADDITIONS, *SOURCE_LEXER_ADDITIONS, *TYPE_PARSER_ADDITIONS, *SOURCE_PARSER_ADDITIONS)))
SUPPORT_IDENTITY_PATHS = legacy.SUPPORT_IDENTITY_PATHS


def source_paths():
    legacy.source_paths()  # retain the exact earlier source identity closure
    paths = SOURCE_IDENTITY_PATHS
    require(len(paths) == len(set(paths)) == 380 and commitment(paths) == 'b70e5910a8cad3f61d16343c0795cb0a8ae2b89406f5b8fdc91ebdbcd88f4a14',
            'reviewed exact source identity closure')
    previous = tuple(name for name in paths if name not in SOURCE_PARSER_ADDITIONS)
    require(len(previous) == 375 and commitment(previous) == '49a2a910de52a02227d9d96fcf488df753362970ea79e92521d6e3efc984481e',
            'historical type parser identity projection')
    previous = tuple(name for name in previous if name not in TYPE_PARSER_ADDITIONS)
    require(len(previous) == 370 and commitment(previous) == '414e724f72c675c8cf7139da0710af16ec4417b4926a334b3f5c3c171b3b44f4',
            'historical source lexer identity projection')
    previous = tuple(name for name in previous if name not in SOURCE_LEXER_ADDITIONS)
    require(len(previous) == 365 and commitment(previous) == '82ab8f945ba088e88eb2ad47f51fbf3cc46d8f249d7f3d3e7ed08554229421ec',
            'historical SHA-256 source identity projection')
    previous = tuple(name for name in previous if name not in SHA256_NATIVE_ADDITIONS)
    require(len(previous) == 360 and commitment(previous) == '84f2d792e39d1f6a5b059026acc14edc321bbe8528c026caa2f06fba55977ad2',
            'historical native JSON source identity projection')
    previous = tuple(name for name in previous if name not in JSON_NATIVE_ADDITIONS)
    require(len(previous) == 337 and commitment(previous) == '5a6311333c82ea95a464ff9257f190f5712b52e3da90c02169e063ca1698f8dc',
            'historical persistent NDU source identity projection')
    previous = tuple(name for name in previous if name not in PERSISTENT_NDU_ADDITIONS)
    require(len(previous) == 336 and commitment(previous) == '9a888e4dbfe883eb74fd8961a5fbc2b90b0cac7b9a6343ef5720145e23be72c7',
            'historical scoped Agent/NDU source identity projection')
    previous = tuple(name for name in previous if name not in SCOPED_AGENT_NDU_ADDITIONS)
    require(len(previous) == 331 and commitment(previous) == '223c03fa82d871fee3d85d57bb1e254d658a9d85007ec11bea5bfbb1fad5d1b5',
            'historical Safe Core source identity projection')
    previous = tuple(name for name in previous if name not in SAFE_CORE_ADDITIONS)
    require(len(previous) == 328 and commitment(previous) == '77fb9af75d987acab91d224cf47c5e6734f8c6eb9c4fa895064fba306289a016',
            'historical P0/P3 source identity projection')
    previous = tuple(name for name in previous if name not in P0_P3_ADDITIONS)
    require(len(previous) == 323 and commitment(previous) == 'd999ff7dc718330771ddb745dbed6a5a7ecdcdea8f9011e35f0a07417f09b9c0',
            'historical native-Agent source identity projection')
    # pipeline.compiler_hash reads every actual top-level hepta/*.py byte,
    # including modules that are not imported by this selected proof profile.
    # Reject an extra or absent filename before an external identity is built.
    actual_compiler_paths = tuple(sorted(p.relative_to(ROOT).as_posix()
                                        for p in (ROOT / 'hepta').glob('*.py')))
    bound_compiler_paths = tuple(n for n in paths if n.startswith('hepta/') and
                                n.count('/') == 1 and n.endswith('.py'))
    require(actual_compiler_paths == bound_compiler_paths,
            'complete actual compiler_hash input set')
    return paths


def require_canonical_git_blobs(root, expected_oids, *, commit='HEAD'):
    """Bind streamed worktree bytes to an unreplaced committed source tree.

    Status may hide assume-unchanged files and ordinary object reads honor
    refs/replace. Neither is an authority for the bytes attributed to a commit.
    """
    require(type(expected_oids) is dict and bool(expected_oids), 'empty Git source closure')
    require(all(type(name) is str and name and not name.startswith('/')
                and all(part not in ('', '.', '..') for part in name.split('/'))
                and type(oid) is str and re.fullmatch('[0-9a-f]{40}', oid)
                for name, oid in expected_oids.items()), 'invalid Git source identity')
    require(commit == 'HEAD' or type(commit) is str and re.fullmatch('[0-9a-f]{40}', commit),
            'invalid Git source commit')
    clean_git_env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
    try:
        raw = subprocess.check_output(
            ['git', '--no-replace-objects', '--literal-pathspecs', 'ls-tree',
             '-rz', '--full-tree', commit, '--', *sorted(expected_oids)],
            cwd=root, env=clean_git_env, timeout=15)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise ValueError('canonical Git source tree unavailable') from exc
    found = {}
    for entry in raw.split(b'\0'):
        if not entry:
            continue
        require(b'\t' in entry, 'invalid Git tree entry')
        metadata, path = entry.split(b'\t', 1)
        fields = metadata.split(b' ')
        require(len(fields) == 3 and fields[0] in (b'100644', b'100755')
                and fields[1] == b'blob' and re.fullmatch(b'[0-9a-f]{40}', fields[2]),
                'unexpected Git tree object')
        name = path.decode('utf-8', errors='strict')
        require(name not in found, 'duplicate Git source object')
        found[name] = fields[2].decode('ascii')
    require(found == expected_oids, 'canonical HEAD differs from authenticated worktree source')


def support_paths():
    return legacy.support_paths()  # unchanged 780 paths and exact commitment


def file_record(raw):
    return dict(sha256=digest(raw), bytes=len(raw))


def cap(name):
    require(name in FIXED_FILES, 'unplanned file')
    if name in SOURCE_FILES: return BUDGETS['source']
    if name in MODULE_FILES: return BUDGETS['module']
    if name in LOG_FILES: return BUDGETS['raw_stage']
    if name in ('PLAN.json', 'shared-manifest.json'): return 32768
    if name == 'IDENTITY.json': return IDENTITY_CAP
    if name == 'RUN.json': return 630
    return 16384


class Snapshot:
    """Stable descriptor reads, inode/ancestor and complete byte authentication."""
    def __init__(self, root):
        self.root = root
        self.files = {}
        self.directories = {}
        self.check_directories()

    def check_directories(self):
        self.root.unchanged()
        paths = [self.root.path, *self.root.path.parents]
        paths += [self.root.path / p for p in ('original', 'HiaSyntaxResearch') if os.path.lexists(self.root.path / p)]
        for path in paths:
            info = os.stat(path, follow_symlinks=False)
            key = str(path)
            value = (info.st_dev, info.st_ino)
            require(stat.S_ISDIR(info.st_mode) and (key not in self.directories or self.directories[key] == value),
                    'ancestor changed or unsafe')
            self.directories[key] = value

    def read(self, name, *, mutable=False):
        self.check_directories()
        raw = self.root.read(name, cap(name))
        info = os.stat(self.root.path / name, follow_symlinks=False)
        value = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_nlink)
        require(mutable or name not in self.files or self.files[name] == value, 'frozen inode changed')
        if not mutable: self.files[name] = value
        return raw


def _external_file_observation(item):
    """Read every byte; return immutable observations without shared state.

    Ancestors are observed on both sides of the descriptor read. The caller
    reconciles every occurrence of a directory against the other workers and
    the prior baseline before publishing any file or ancestor record.
    """
    import hashlib
    name, maximum, source_blob = item
    path = Path(name)
    parents = []

    def observe_parents():
        for parent in path.parents:
            info = os.stat(parent, follow_symlinks=False)
            require(stat.S_ISDIR(info.st_mode), 'external ancestor changed')
            parents.append((str(parent), (info.st_dev, info.st_ino)))

    observe_parents()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        fields = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns, s.st_nlink)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= maximum,
                'external unsafe file/size')
        h, count = hashlib.sha256(), 0
        # Hash source object IDs in the same descriptor read. Large support
        # libraries retain their original SHA256-only stream and chunk bounds.
        blob = hashlib.sha1(b'blob ' + str(before.st_size).encode('ascii') + b'\0') if source_blob else None
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            count += len(chunk)
            require(count <= maximum, 'external size grew')
            h.update(chunk)
            if blob is not None:
                blob.update(chunk)
        inode = fields(before)
        require(inode == fields(os.fstat(fd)) == fields(os.stat(path, follow_symlinks=False)) and count == before.st_size,
                'external read race')
        observe_parents()
        return name, tuple(parents), inode, count, h.hexdigest(), blob.hexdigest() if blob is not None else ''
    finally:
        os.close(fd)


class External:
    """Actual pinned binary, all support bytes and exact repository source bytes."""
    def __init__(self, executable):
        self.executable = Path(absolute(str(executable)))
        absolute(str(self.executable.parent.parent))
        self.paths = {str(ROOT / n): BUDGETS['source'] for n in source_paths()}
        self.paths.update({str(self.executable.parent.parent / n): 9223372036854775807 for n in support_paths()})
        self.paths[str(self.executable)] = 9223372036854775807
        self.inodes, self.parents, self.records = {}, {}, {}
        self.check()
        pin = json.loads(self.read_source('formal/toolchain-lock.json'))['lean_binary_sha256']
        require(self.records[str(self.executable)]['sha256'] == pin, 'pinned binary required')

    def reject_support_shadow(self):
        prefix = self.executable.parent.parent / 'lib/lean' / base.MODULE_PREFIX
        require(not os.path.lexists(prefix) and not os.path.lexists(str(prefix) + '.olean'), 'support module-prefix shadow')

    def check(self):
        self.reject_support_shadow()
        git = self.git if hasattr(self, 'git') else diagnostic._git_baseline()
        items = tuple(self.paths.items())
        source_by_path = {str(ROOT / name): name for name in SOURCE_IDENTITY_PATHS}
        read_items = tuple((name, maximum, name in source_by_path) for name, maximum in items)
        # Two bounded readers, each with one descriptor and 65536-byte chunks.
        # Failed work cancels queued reads and joins active readers before the
        # exception escapes; no partial observation is committed to the object.
        pool = ThreadPoolExecutor(max_workers=2)
        try:
            observations = tuple(pool.map(_external_file_observation, read_items))
        finally:
            pool.shutdown(wait=True, cancel_futures=True)
        parents, inodes, records = dict(self.parents), dict(self.inodes), dict(self.records)
        git_oids = {}
        for (expected_name, _), (name, ancestors, inode, count, sha, blob_oid) in zip(items, observations):
            require(name == expected_name, 'external observation path differs')
            for key, value in ancestors:
                require(key not in parents or parents[key] == value, 'external ancestor changed')
                parents[key] = value
            require(name not in inodes or inodes[name] == inode, 'external inode changed')
            record = dict(bytes=count, sha256=sha)
            require(name not in records or same(records[name], record), 'external bytes changed')
            inodes[name], records[name] = inode, record
            if name in source_by_path:
                git_oids[source_by_path[name]] = blob_oid
        require(tuple(self.paths.items()) == items, 'external path set changed')
        self.reject_support_shadow()
        require(set(git_oids) == set(SOURCE_IDENTITY_PATHS), 'incomplete authenticated Git source set')
        require_canonical_git_blobs(ROOT, git_oids, commit=git['head'])
        require(same(git, diagnostic._git_baseline()), 'git baseline changed')
        self.parents.update(parents)
        self.inodes.update(inodes)
        self.records.update(records)
        self.git = git

    def read_source(self, name):
        """Bounded nofollow reread of an already authenticated source file."""
        require(name in SOURCE_IDENTITY_PATHS, 'unplanned external source read')
        path = ROOT / name
        key = str(path)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            fields = lambda st: (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_nlink)
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= BUDGETS['source']
                    and fields(before) == self.inodes[key], 'external source reread identity')
            raw = bytearray()
            while len(raw) <= BUDGETS['source']:
                chunk = os.read(fd, min(65536, BUDGETS['source'] + 1 - len(raw)))
                if not chunk: break
                raw.extend(chunk)
            require(len(raw) <= BUDGETS['source'] and fields(before) == fields(os.fstat(fd)) == fields(os.stat(path, follow_symlinks=False)),
                    'external source reread race/bound')
            raw = bytes(raw)
            require(same(file_record(raw), self.records[key]), 'external source reread bytes')
            return raw
        finally:
            os.close(fd)

    def identity(self, run_id):
        return dict(**common(run_id), commit_sha=self.git['head'], tree_sha=self.git['tree'],
                    lean_binary_sha256=self.records[str(self.executable)]['sha256'],
                    sources={n: self.records[str(ROOT / n)] for n in source_paths()},
                    support={n: self.records[str(self.executable.parent.parent / n)] for n in support_paths()})


def negative_locations(prepared, proposal):
    # The shared manifest deliberately has no negative-coordinate ledger.
    # Parse the actual candidate declarations with the original unique-line rule.
    locations = {}
    for stage in proposal.stages[9:]:
        for name in stage.rejection_names:
            require(name not in locations and name in prepared['negatives'], 'unique original negative name')
            local = prepared['negatives'][name]['certificate'].rsplit('.', 1)[1]
            lines = [i for i, line in enumerate(stage.source.splitlines(), 1)
                     if line.startswith('theorem ' + local + ' :')]
            require(len(lines) == 1, 'unique actual negative declaration')
            locations[name] = dict(module=stage.module_name, line=lines[0])
    require(len(locations) == 10 and set(locations) == set(prepared['negatives']), 'complete ten current negative coordinates')
    return locations


def _reference_seven(prepared):
    """Construct untrusted ancestor bytes, with no validation/admission state.

    Both mandatory seven-source gates in the actual relocated inverse still
    validate this reference and the separately recovered actual candidate.
    Public legacy builders and validators remain unchanged.
    """
    earlier = seven.facts._derive(prepared)
    stages = seven._derive_stages(earlier.stages)
    previous_hash = earlier.manifest_sha256
    del earlier
    return seven.SevenCertificateSources(prepared['stages'], stages,
        seven.encode(seven._manifest(prepared, stages, previous_hash)))


def prepare():
    prepared = seven.original.build_inputs()
    previous = _reference_seven(prepared)
    # This builder invokes the unchanged shared validator, including the
    # mandatory actual-declaration inverse and unchanged old full validators.
    proposal = shared.build_sources(prepared, previous)
    require(type(proposal) is shared.SharedSources, 'distinct relocated candidate type')
    require(shared.validate_retention(proposal) == proposal.manifest['retained_source_bytes'], 'retained declarations changed')
    require(negative_locations(prepared, proposal) == previous.manifest['negative_declaration_locations'],
            'unchanged final-module negative coordinates')
    require({k: len(v['bytes']) for k, v in prepared['binding_inputs'].items()} ==
            dict(linear=14466, parallel=14466, wrong_phi=14466, literal_two=14466, wrong_condition=14585), 'full input lengths')
    return prepared, proposal


def make_plan(run_id, identity, executable, root, prepared, proposal):
    m = proposal.manifest
    locations = negative_locations(prepared, proposal)
    return dict(**common(run_id), identity_sha256=commitment(identity), original_manifest_sha256=prepared['manifest_sha256'],
        shared_manifest_sha256=proposal.manifest_sha256,
        previous_seven_manifest_sha256=m['previous_seven_manifest_sha256'],
        stages=[dict(index=i, name=s.name, module_name=s.module_name, source_path=s.module_name.replace('.', '/') + '.lean',
                     source_sha256=s.source_sha256, source_bytes=s.source_bytes, parents=list(s.parents),
                     direct_imports=list(s.direct_imports), subject_count=len(s.expected_theorems),
                     subject_sequence_sha256=commitment(seven._qualified_prints(s.source)), rejection_names=sorted(s.rejection_names))
                for i, s in enumerate(proposal.stages)], positive_targets=sorted(prepared['expected_theorems']),
        negatives={k: dict(v, current_location=locations[k]) for k, v in prepared['negatives'].items()},
        input_bindings={k: dict(file_record(v['bytes']), root_owner=m['root_owners'][k]) for k, v in prepared['binding_inputs'].items()},
        source_file_map={'original/' + s.name + '.lean': file_record(s.source.encode()) for s in prepared['stages']},
        budgets=dict(BUDGETS), process_spec=dict(executable=absolute(str(executable)), root=absolute(str(root)),
            sysroot=absolute(str(Path(executable).parent.parent)),
            argv_template=['executable', '--threads=1', '--root=root', '-o', 'root/module.olean', 'root/module.lean'],
            environment_keys=['LEAN_PATH', 'LEAN_SYSROOT'], unset_environment_keys=['LEAN_SRC_PATH']))


def make_run(plan):
    return dict(**common(plan['run_id']), identity_sha256=plan['identity_sha256'], plan_sha256=commitment(plan),
                original_manifest_sha256=plan['original_manifest_sha256'], shared_manifest_sha256=plan['shared_manifest_sha256'],
                previous_seven_manifest_sha256=plan['previous_seven_manifest_sha256'])


def reconstruct(snapshot):
    # Authenticated fixed inputs regenerate the complete original transient
    # manifest, then actual retained originals and candidates are checked in full.
    prepared = seven.original.build_inputs()
    from types import MappingProxyType
    actual_originals = []
    for stage in prepared['stages']:
        raw = snapshot.read('original/' + stage.name + '.lean')
        require(raw == stage.source.encode(), 'actual original declarations differ')
        actual_originals.append(replace(stage, source=raw.decode('utf-8')))
    actual_originals = tuple(actual_originals)
    # Reconstruct the full transient original manifest FROM those actual bytes,
    # including parsed declaration ownership and negative source coordinates.
    # Reference input streams are separately checked by the unchanged inverse.
    _, per_input = seven.original._stream(prepared['original_prepared'])
    manifest = seven.original._manifest(actual_originals, prepared['original_prepared'], per_input)
    manifest_json = seven.original.encode(manifest)
    require(manifest_json == prepared['manifest_json'], 'regenerated actual original manifest differs')
    prepared = dict(prepared, stages=actual_originals,
                    sources=MappingProxyType({s.module_name: s.source for s in actual_originals}),
                    manifest=manifest, manifest_json=manifest_json, manifest_sha256=digest(manifest_json.encode()))
    previous = _reference_seven(prepared)
    # Derive metadata scaffolding without validating a discarded generated candidate.
    # Every actual retained candidate byte still undergoes the full validator below.
    expected = shared._derive_stages(prepared, previous)
    stages = tuple(replace(s, source=snapshot.read(s.module_name.replace('.', '/') + '.lean').decode('utf-8')) for s in expected)
    proposal = shared.SharedSources(prepared['stages'], stages, snapshot.read('shared-manifest.json').decode('utf-8'))
    shared.validate_sources(prepared, previous, proposal)
    require(negative_locations(prepared, proposal) == previous.manifest['negative_declaration_locations'],
            'unchanged actual final-module negative coordinates')
    return prepared, proposal


def inventory(out, err, stage):
    return diagnostic._inventory(out, err, stage)


def started(plan, run, stage, accepted, remaining):
    integer(remaining, 0, BUDGETS['launch_ns'])
    return dict(**common(plan['run_id']), run_sha256=commitment(run), plan_sha256=commitment(plan),
                index=stage['index'], name=stage['name'], source_sha256=stage['source_sha256'],
                parents={p: accepted[p] for p in stage['parents']}, remaining_launch_ns=remaining)


def validate_process(p, success=False):
    booleans = ('spawned', 'timed_out', 'incomplete', 'output_truncated', 'leader_reaped', 'stdout_eof',
                'stderr_eof', 'original_group_empty', 'leader_reap_observed')
    keys = set(booleans) | {'returncode', 'elapsed_ns', 'cleanup_ns', 'leader_pid', 'original_pgid', 'leader_start_ticks',
                          'terminal_observation', 'pre_reap_group_signal', 'post_reap_group_probe'}
    require(type(p) is dict and set(p) == keys, 'process exact keys')
    require(all(type(p[k]) is bool for k in booleans), 'process booleans')
    if p['returncode'] is not None: integer(p['returncode'], -2147483648, 2147483647)
    integer(p['elapsed_ns'], 0, 600000000000); integer(p['cleanup_ns'], 0, BUDGETS['cleanup_ns'])
    for k in ('leader_pid', 'original_pgid'):
        if p[k] is not None: integer(p[k], 1, 2147483647)
    if p['leader_start_ticks'] is not None: integer(p['leader_start_ticks'], 0, 18446744073709551615)
    require(p['terminal_observation'] in ('waitid_wnowait', 'not_observed') and
            p['pre_reap_group_signal'] in ('sigkill_sent', 'sigkill_no_signalable_group', 'not_attempted', 'failed') and
            p['post_reap_group_probe'] in ('esrch', 'group_exists', 'unknown_or_permission_error', 'not_observed'), 'process enums')
    require(p['leader_reaped'] == p['leader_reap_observed'] and (p['returncode'] is not None) == p['leader_reaped'], 'reap/exit observations differ')
    require(p['post_reap_group_probe'] == 'not_observed' or p['leader_reaped'], 'probe requires reaped leader')
    require(p['original_group_empty'] == (p['post_reap_group_probe'] == 'esrch'), 'latest group probe differs')
    require(p['terminal_observation'] != 'waitid_wnowait' or p['leader_start_ticks'] is not None, 'terminal observation requires captured identity')
    require(p['cleanup_ns'] < BUDGETS['cleanup_ns'] or p['incomplete'], 'expired cleanup cannot be complete')
    if not p['spawned']:
        require(not any(p[k] for k in booleans) and p['cleanup_ns'] == 0, 'unspawned flags/cleanup')
        require(p['returncode'] is None and p['elapsed_ns'] == 0 and p['leader_pid'] is None and p['original_pgid'] is None
                and p['leader_start_ticks'] is None and not any(p[k] for k in ('leader_reaped', 'stdout_eof', 'stderr_eof', 'original_group_empty'))
                and p['terminal_observation'] == 'not_observed' and p['pre_reap_group_signal'] == 'not_attempted'
                and p['post_reap_group_probe'] == 'not_observed', 'nonlaunched observations')
    else:
        integer(p['leader_pid'], 1, 2147483647)
        require(p['original_pgid'] == p['leader_pid'], 'original process group identity')
        require(p['pre_reap_group_signal'] != 'not_attempted' and p['timed_out'] == (p['elapsed_ns'] >= BUDGETS['process_ns']), 'spawned cleanup/timeout observations')
    if p['original_group_empty']:
        require(p['leader_reaped'] and p['post_reap_group_probe'] == 'esrch', 'final empty group observation')
    if success:
        require(all(p[k] for k in ('spawned', 'leader_reaped', 'stdout_eof', 'stderr_eof', 'original_group_empty', 'leader_reap_observed'))
                and not any(p[k] for k in ('timed_out', 'incomplete', 'output_truncated')) and p['returncode'] == 0
                and p['elapsed_ns'] < BUDGETS['process_ns'] and p['cleanup_ns'] < BUDGETS['cleanup_ns']
                and p['terminal_observation'] == 'waitid_wnowait'
                and p['pre_reap_group_signal'] in ('sigkill_sent', 'sigkill_no_signalable_group')
                and p['post_reap_group_probe'] == 'esrch' and p['leader_start_ticks'] is not None, 'unsafe successful process')
    return p


def validate_failure(value):
    keys = {'schema', 'protocol', 'run_id', 'status', 'run_sha256', 'plan_sha256', 'identity_sha256',
            'failed_stage', 'phase', 'error_code', 'invocations', 'wall_ns', 'committed_receipt_sha256'} | set(flags())
    require(type(value) is dict and set(value) == keys, 'failure exact keys')
    require(all(same(value[k], v) for k, v in {**common(value['run_id']), **flags(), 'status': 'failed'}.items()), 'failure flags/header')
    code, phase, index = value['error_code'], value['phase'], value['failed_stage']
    require(type(code) is str and code in PHASE_CODES and phase in PHASE_CODES[code], 'failure code phase')
    if index is not None: integer(index, 0, 10)
    require((index is None) == (phase in ('preparation', 'finalization')), 'failure phase stage')
    integer(value['invocations'], 0, 11); integer(value['wall_ns'], 0, 600000000000)
    receipts = value['committed_receipt_sha256']
    require(type(receipts) is list and len(receipts) <= 11 and len(set(receipts)) == len(receipts), 'failure prefix shape')
    for h in receipts: hash_value(h)
    require(len(receipts) <= value['invocations'], 'failure prefix launches')
    if index is not None:
        require(len(receipts) == index and value['invocations'] in (index, index + 1), 'failure successful prefix')
        if phase == 'prelaunch': require(value['invocations'] == index, 'prelaunch invocation')
        if phase in ('capturing', 'verifying', 'receipt_commit'): require(value['invocations'] == index + 1, 'postlaunch invocation')
    if phase == 'preparation': require(value['invocations'] == 0 and not receipts, 'preparation prefix')
    for key in ('run_sha256', 'plan_sha256', 'identity_sha256'):
        if value[key] is None: require(phase == 'preparation', 'late missing binding')
        else: hash_value(value[key])
    require(value['run_sha256'] is None or value['plan_sha256'] is not None, 'run requires plan')
    require(value['plan_sha256'] is None or value['identity_sha256'] is not None, 'plan requires identity')
    return value


def budgets(files, display=b''):
    require(set(files) <= FIXED_FILES and all(type(raw) is bytes and len(raw) <= cap(n) for n, raw in files.items()), 'fixed per-file caps')
    sources = sum(len(files.get(n, b'')) for n in SOURCE_FILES)
    modules = sum(len(files.get(n, b'')) for n in MODULE_FILES)
    raw = sum(len(files.get(n, b'')) for n in LOG_FILES)
    metadata = sum(len(v) for n, v in files.items() if n not in SOURCE_FILES + MODULE_FILES + LOG_FILES)
    require(sources <= BUDGETS['sources'] and modules <= BUDGETS['modules'] and raw <= RAW_GLOBAL, 'aggregate payload caps')
    require(metadata <= METADATA_RESERVE <= BUDGETS['metadata'] and len(display) <= BUDGETS['display']
            and metadata + raw + len(display) <= BUDGETS['evidence_display']
            and sources + modules + raw + metadata <= BUDGETS['container'], 'aggregate evidence/container caps')
    for n in seven.NAMES:
        require(sum(len(files.get(n + '.' + s, b'')) for s in ('stdout', 'stderr')) <= BUDGETS['raw_stage'], 'stage raw cap')


def validate_plan_records(identity, plan, run, expected_identity, executable, root, prepared, proposal):
    require(same(identity, expected_identity), 'actual full identity differs')
    expected = make_plan(expected_identity['run_id'], expected_identity, executable, root, prepared, proposal)
    require(same(plan, expected) and same(run, make_run(expected)), 'strict complete independently regenerated plan/run')
    return expected


def validate_failed_stage(value):
    keys = {'schema', 'protocol', 'run_id', 'index', 'name', 'started_sha256', 'status',
            'process', 'logs', 'inventory', 'olean', 'error_code'}
    require(type(value) is dict and set(value) == keys, 'failed stage exact keys')
    require(all(same(value[k], v) for k, v in common(value['run_id']).items()), 'failed stage header')
    integer(value['index'], 0, 10)
    require(value['name'] == seven.NAMES[value['index']] and value['status'] == 'stage_failed'
            and value['error_code'] in PHASE_CODES and value['inventory'] is None and value['olean'] is None, 'failed stage status')
    hash_value(value['started_sha256'])
    process = validate_process(value['process'])
    logs = value['logs']
    if logs is None:
        require(not process['spawned'], 'spawned capture files required')
    else:
        require(type(logs) is dict and set(logs) == {'stdout', 'stderr'}, 'failed logs keys')
        total = 0
        for record in logs.values():
            require(type(record) is dict and set(record) == {'sha256', 'bytes'}, 'failed log record keys')
            hash_value(record['sha256']); integer(record['bytes'], 0, BUDGETS['raw_stage'])
            total += record['bytes']
        require(total <= BUDGETS['raw_stage'], 'failed raw pair bound')
        if not process['spawned']: require(total == 0, 'unspawned raw output')
    return value
