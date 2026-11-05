"""Closed shared-composition acceptance plan and unchanged finite evidence limits.

No compiler execution here. Fixed hash commitments use canonical JSON plus LF;
legacy source manifest bytes retain their original no-LF protocol.
"""
from dataclasses import replace
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
SCHEMA = 'hepta.hia.seven-shared-acceptance.v9'
PROTOCOL = 'seven-shared-acceptance-v9'
ADDITIONS = (
    'experiments/hia_initialization_frontiers_20261103/CORE_MODEL_CONNECTION.md',
    'experiments/hia_initialization_frontiers_20261103/UNSIGNED_STEP_CONNECTION.md',
    'hepta/hia_byte_sum.py',
    'hepta/hia_entry_layout.py',
    'hepta/hia_ndu_dynamic.py',
    'hepta/hia_ndu_raw_model.py',
    'hepta/hia_ndu_raw_session.py',
    'docs/seven-data-nocode.md',
    'docs/seven-shared-composition.md',
    'experiments/hia_initialization_frontiers_20261103/SharedTransport.lean',
    'tests/test_core_seven_nocode_sources.py',
    'tests/test_core_seven_shared_acceptance.py',
    'tests/test_core_seven_shared_sources.py',
    'tools/check_core_seven_shared.py',
    'tools/core_seven_nocode_sources.py',
    'tools/core_seven_shared_acceptance_plan.py',
    'tools/core_seven_shared_acceptance_replay.py',
    'tools/core_seven_shared_sources.py',
    'tools/diagnose_core_seven_nocode.py',
)
METADATA_RESERVE = 224589
RAW_GLOBAL = 819891
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
SOURCE_IDENTITY_PATHS = tuple(sorted((*legacy.SOURCE_IDENTITY_PATHS, *ADDITIONS)))
SUPPORT_IDENTITY_PATHS = legacy.SUPPORT_IDENTITY_PATHS


def source_paths():
    legacy.source_paths()  # retain the exact earlier source identity closure
    paths = SOURCE_IDENTITY_PATHS
    require(len(paths) == len(set(paths)) == 258 and commitment(paths) == '36af03771b8b81803d90baafc92fd290d9e6cadbb03e7e135a99beae804bb0f0',
            'reviewed exact source identity closure')
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
    if name == 'IDENTITY.json': return 144713
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
        self.git = diagnostic._git_baseline()

    def reject_support_shadow(self):
        prefix = self.executable.parent.parent / 'lib/lean' / base.MODULE_PREFIX
        require(not os.path.lexists(prefix) and not os.path.lexists(str(prefix) + '.olean'), 'support module-prefix shadow')

    def check(self):
        self.reject_support_shadow()
        # Streaming hashing avoids unbounded copies of support libraries.
        import hashlib
        for name, maximum in self.paths.items():
            path = Path(name)
            for parent in path.parents:
                info = os.stat(parent, follow_symlinks=False)
                key, value = str(parent), (info.st_dev, info.st_ino)
                require(stat.S_ISDIR(info.st_mode) and (key not in self.parents or self.parents[key] == value), 'external ancestor changed')
                self.parents[key] = value
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            try:
                before = os.fstat(fd)
                value = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns, s.st_nlink)
                require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= maximum,
                        'external unsafe file/size')
                h, count = hashlib.sha256(), 0
                while True:
                    chunk = os.read(fd, 65536)
                    if not chunk: break
                    count += len(chunk)
                    require(count <= maximum, 'external size grew')
                    h.update(chunk)
                require(value(before) == value(os.fstat(fd)) == value(os.stat(path, follow_symlinks=False)) and count == before.st_size,
                        'external read race')
                require(name not in self.inodes or self.inodes[name] == value(before), 'external inode changed')
                record = dict(bytes=count, sha256=h.hexdigest())
                require(name not in self.records or same(self.records[name], record), 'external bytes changed')
                self.inodes[name], self.records[name] = value(before), record
            finally: os.close(fd)
        self.reject_support_shadow()
        if hasattr(self, 'git'):
            require(same(self.git, diagnostic._git_baseline()), 'git baseline changed')

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


def prepare():
    prepared = seven.original.build_inputs()
    previous = seven.build_sources(prepared)
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
    previous = seven.build_sources(prepared)
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
