"""Closed nonaccepting Part03 plan, identity, retention and record grammar.

This module does not launch processes. Actual external reads retain full size,
hash and inode records even though durable identities contain only hashes.
"""
from dataclasses import replace
import json
import os
from pathlib import Path
import stat
from types import MappingProxyType

from tools import core_seven_relocation_acceptance_plan as inherited
from tools import core_seven_relocated_part03_sources as sources
from tools.check_guarded_slice_lean import require

base = inherited.base
seven = inherited.seven
relocation = inherited.relocation
diagnostic = inherited.diagnostic
ROOT = inherited.ROOT
SCHEMA = 'hepta.hia.seven-relocated-part03-diagnostic.v1'
PROTOCOL = 'seven-relocated-part03-diagnostic-v1'
CAPTURE_PROTOCOL = 'p03-pty-hardened-v1'
TARGET = sources.TARGET
PARENTS = seven.NAMES[:4]
SCHEDULE = PARENTS + (TARGET,)
BUDGETS = dict(inherited.BUDGETS)
METADATA_RESERVE = 224589
RAW_GLOBAL = 819891
MAX_PROCESSES = 5
ADDITIONS = (
    'tools/core_seven_relocated_part03_sources.py',
    'tools/core_seven_relocated_part03_plan.py',
    'tools/core_seven_relocated_part03_capture.py',
    'tools/core_seven_relocated_part03_replay.py',
    'tools/diagnose_core_seven_relocated_part03.py',
    'tests/test_core_seven_relocated_part03_sources.py',
    'tests/test_core_seven_relocated_part03_diagnostic.py',
    'docs/seven-relocated-part03-diagnostic.md')
SOURCE_IDENTITY_PATHS = tuple(sorted(set(inherited.SOURCE_IDENTITY_PATHS) | set(ADDITIONS)))
SUPPORT_IDENTITY_PATHS = inherited.SUPPORT_IDENTITY_PATHS
SOURCE_FILES = tuple('original/' + n + '.lean' for n in seven.original.NAMES) + tuple(
    ('HiaSyntaxResearch/' if i < 4 else 'relocated/') + n + '.lean' for i, n in enumerate(seven.NAMES)) + (
    'HiaSyntaxResearch/CertPart03.lean',)
MODULE_FILES = tuple('HiaSyntaxResearch/' + n + '.olean' for n in seven.NAMES[:5])
LOG_FILES = tuple(n + '.' + stream for n in SCHEDULE for stream in ('stdout', 'stderr'))
RECEIPT_FILES = tuple(n + '.' + kind + '.json' for n in PARENTS for kind in ('started', 'finished')) + (
    TARGET + '.started.json', TARGET + '.events.jsonl')
GLOBALS = ('IDENTITY.json', 'PLAN.json', 'RUN.json', 'relocation-manifest.json', 'diagnostic-manifest.json')
PREPARATION_ORDER = ('IDENTITY.json', 'diagnostic-manifest.json', 'PLAN.json', 'RUN.json',
                     'relocation-manifest.json') + tuple(sorted(SOURCE_FILES))
FROZEN_FILES = frozenset(SOURCE_FILES + MODULE_FILES + LOG_FILES + RECEIPT_FILES + GLOBALS)
TERMINALS = ('RESULT.json', 'RESULT.pending.json', 'FAILURE.json')
FIXED_FILES = FROZEN_FILES | set(TERMINALS)
PHASE_CODES = dict(inherited.PHASE_CODES, marker_invalid=('capturing', 'target_verifying'),
    platform_invalid=('target_prelaunch',), pty_invalid=('target_prelaunch',),
    clock_invalid=('capturing', 'target_verifying'), replay_invalid=('replay',),
    target_inventory_invalid=('target_verifying',), target_module_invalid=('target_verifying',))
STATUSES = ('diagnostic_completed', 'parent_failed', 'target_timeout', 'target_nonzero', 'no_launch',
            'capture_incomplete', 'cleanup_uncertain', 'raw_overflow', 'event_overflow',
            'finalization_failed', 'replay_failed', 'target_invalid')
PHASES = ('preparation', 'prelaunch', 'capturing', 'verifying', 'receipt_commit',
          'target_prelaunch', 'target_verifying', 'finalization', 'replay')
LAUNCH_STATES = ('not_attempted', 'not_spawned', 'spawned', 'spawn_outcome_uncertain')
encode = inherited.encode
commitment = inherited.commitment
same = inherited.same
integer = inherited.integer
hash_value = inherited.hash_value
absolute = inherited.absolute
digest = inherited.digest
file_record = inherited.file_record
validate_process = inherited.validate_process
inventory = inherited.inventory
negative_locations = inherited.negative_locations


def parse(raw, *, newline=True):
    def no_float(_):
        raise ValueError('floating point JSON forbidden')
    # The inherited parser checks canonical spelling and duplicate keys. A second
    # typed decode rejects finite floats too, even in otherwise unknown fields.
    value = inherited.parse(raw, newline=newline)
    json.loads(raw, parse_float=no_float)
    return value


def common(run_id):
    return dict(schema=SCHEMA, protocol=PROTOCOL, run_id=hash_value(run_id))


def flags():
    return dict(acceptance_eligible=False, **inherited.flags(False))


def source_paths():
    require(len(SOURCE_IDENTITY_PATHS) == 247 and len(inherited.source_paths()) == 239
            and commitment(SOURCE_IDENTITY_PATHS) == '61de35bb94487c706dba1e50224034982c881bbbd49c449d8a2e34975889f868',
            'exact implementation identity membership')
    return SOURCE_IDENTITY_PATHS


def support_paths():
    return inherited.support_paths()


def cap(name):
    require(name in FIXED_FILES, 'unplanned file')
    if name in SOURCE_FILES: return BUDGETS['source']
    if name in MODULE_FILES: return BUDGETS['module']
    if name in LOG_FILES: return BUDGETS['raw_stage']
    if name in ('PLAN.json', 'relocation-manifest.json'): return 32768
    if name == 'IDENTITY.json': return 144713
    if name == 'RUN.json': return 630
    if name == 'diagnostic-manifest.json': return 8192
    if name == TARGET + '.started.json': return 2368
    if name == TARGET + '.events.jsonl': return 8416
    if name in ('RESULT.json', 'RESULT.pending.json'): return 7968
    if name == 'FAILURE.json': return 4096
    return 2048


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
        paths += [self.root.path / p for p in ('original', 'relocated', 'HiaSyntaxResearch') if os.path.lexists(self.root.path / p)]
        for path in paths:
            info = os.stat(path, follow_symlinks=False)
            key = str(path)
            value = (info.st_dev, info.st_ino)
            require(stat.S_ISDIR(info.st_mode) and (key not in self.directories or self.directories[key] == value),
                    'ancestor changed or unsafe')
            self.directories[key] = value

    def read(self, name, *, mutable=False):
        self.check_directories()
        maximum = cap(name)
        parent, leaf = self.root._parent(name)
        fd = None
        try:
            fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            before = os.fstat(fd)
            fields = lambda x: (x.st_dev, x.st_ino, x.st_size, x.st_mtime_ns, x.st_ctime_ns, x.st_nlink)
            stamp = fields(before)
            require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= maximum,
                    'safe retained file size/type/link')
            chunks, count = [], 0
            while count <= maximum:
                chunk = os.read(fd, min(65536, maximum + 1 - count))
                if not chunk: break
                chunks.append(chunk); count += len(chunk)
            require(count == before.st_size and count <= maximum and stamp == fields(os.fstat(fd))
                    == fields(os.stat(leaf, dir_fd=parent, follow_symlinks=False)), 'retained read race/count')
            self.check_directories()
            require(mutable or name not in self.files or self.files[name] == stamp, 'frozen inode changed')
            if not mutable: self.files[name] = stamp
            return b''.join(chunks)
        finally:
            if fd is not None: os.close(fd)
            os.close(parent)


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
                    sources={n: self.records[str(ROOT / n)]['sha256'] for n in source_paths()},
                    support={n: self.records[str(self.executable.parent.parent / n)]['sha256'] for n in support_paths()})


def validate_identity(value):
    keys = set(common('0'*64)) | {'commit_sha', 'tree_sha', 'lean_binary_sha256', 'sources', 'support'}
    exact(value, keys, 'identity')
    header(value)
    hash_value(value['commit_sha'], 40); hash_value(value['tree_sha'], 40)
    hash_value(value['lean_binary_sha256'])
    for key, paths in (('sources', source_paths()), ('support', support_paths())):
        exact(value[key], set(paths), key)
        for h in value[key].values(): hash_value(h)
    require(len(encode(value)) <= cap('IDENTITY.json'), 'identity bytes')
    return value


def _previous_scaffolding(prepared):
    """Pure metadata/source derivation, never an authentication gate.

    Every caller must subsequently invoke the unchanged diagnostic source gate,
    which validates this old-seven object and the actual recovered layout through
    the full five-input/original/byte-facts inverse chain.
    """
    facts = seven.facts._derive(prepared)
    stages = seven._derive_stages(facts.stages)
    return seven.SevenCertificateSources(prepared['stages'], stages,
        seven.encode(seven._manifest(prepared, stages, facts.manifest_sha256)))


def prepare():
    prepared = seven.original.build_inputs()
    previous = _previous_scaffolding(prepared)
    stages = relocation._derive_stages(previous)
    proposal = relocation.ParallelRelocationSources(prepared['stages'], stages,
        relocation.encode(relocation._manifest(prepared, previous, stages)))
    marked = sources._derive(prepared, previous, proposal)
    sources.validate_diagnostic_sources(prepared, previous, proposal, marked)
    require(relocation.validate_retention(proposal) == 5593354, 'retained declarations changed')
    require(negative_locations(prepared, proposal) == previous.manifest['negative_declaration_locations'],
            'unchanged final-module negative coordinates')
    require({k: len(v['bytes']) for k, v in prepared['binding_inputs'].items()} ==
            dict(linear=14466, parallel=14466, wrong_phi=14466, literal_two=14466, wrong_condition=14585),
            'full input lengths')
    return prepared, proposal, marked


def make_plan(run_id, identity, executable, root, prepared, proposal, marked=None):
    validate_identity(identity)
    require(identity['run_id'] == run_id, 'identity run')
    previous = _previous_scaffolding(prepared)
    if marked is None: marked = sources._derive(prepared, previous, proposal)
    sources.validate_diagnostic_sources(prepared, previous, proposal, marked)
    return _derive_plan(run_id, identity, executable, root, prepared, proposal, marked)


def _derive_plan(run_id, identity, executable, root, prepared, proposal, marked):
    """Descriptor-only factory; used only immediately after the full source gate."""
    value = inherited.make_plan(run_id, identity, executable, root, prepared, proposal)
    value.update(common(run_id))
    for i, stage in enumerate(value['stages']):
        path = ('HiaSyntaxResearch/' if i < 4 else 'relocated/') + stage['name'] + '.lean'
        stage['retained_source_path'] = path
        stage['source_path'] = path if i < 4 else None
    value['source_file_map'] = {n: file_record(s.encode()) for n, s in
        sources.retained_sources(prepared, proposal, marked.stages).items()}
    value['process_spec'].update(parent_capture='core_seven_acceptance_capture.capture',
                                target_capture='core_seven_relocated_part03_capture.capture')
    target = marked.stages[4]
    value.update(schedule=list(SCHEDULE), maximum_processes=5, acceptance_eligible=False,
        metadata_reserve=METADATA_RESERVE, raw_global=RAW_GLOBAL,
        target=dict(name=TARGET, index=4, source_stage='CertPart03', module_name=target.module_name,
            source_path='HiaSyntaxResearch/CertPart03.lean', module_path=MODULE_FILES[4],
            source_sha256=target.source_sha256, source_bytes=target.source_bytes,
            unmarked_path='relocated/CertPart03.lean', diagnostic_manifest_sha256=marked.manifest_sha256,
            parents=list(target.parents), subject_count=1655,
            subject_sequence_sha256=marked.manifest['subject_sequence_sha256'], capture_protocol=CAPTURE_PROTOCOL))
    require(len(encode(value)) <= cap('PLAN.json'), 'plan bytes')
    return value


def make_run(plan):
    return dict(**common(plan['run_id']), identity_sha256=plan['identity_sha256'], plan_sha256=commitment(plan),
                diagnostic_manifest_sha256=plan['target']['diagnostic_manifest_sha256'])


def reconstruct(snapshot):
    prepared = seven.original.build_inputs()
    actual_originals = tuple(replace(s, source=snapshot.read('original/' + s.name + '.lean').decode('utf-8'))
                             for s in prepared['stages'])
    require(all(a.source == b.source for a, b in zip(actual_originals, prepared['stages'])),
            'actual original declarations differ')
    _, per_input = seven.original._stream(prepared['original_prepared'])
    manifest = seven.original._manifest(actual_originals, prepared['original_prepared'], per_input)
    manifest_json = seven.original.encode(manifest)
    require(manifest_json == prepared['manifest_json'], 'actual original manifest differs')
    prepared = dict(prepared, stages=actual_originals,
        sources=MappingProxyType({s.module_name: s.source for s in actual_originals}),
        manifest=manifest, manifest_json=manifest_json, manifest_sha256=digest(manifest_json.encode()))
    previous = _previous_scaffolding(prepared)
    expected = relocation._derive_stages(previous)
    stages = tuple(replace(s, source=snapshot.read(
        ('HiaSyntaxResearch/' if i < 4 else 'relocated/') + s.name + '.lean').decode('utf-8'))
        for i, s in enumerate(expected))
    proposal = relocation.ParallelRelocationSources(actual_originals, stages,
        snapshot.read('relocation-manifest.json').decode('utf-8'))
    marked_stages = stages[:4] + (replace(stages[4], source=snapshot.read(
        'HiaSyntaxResearch/CertPart03.lean').decode('utf-8')),)
    marked = sources.RelocatedPart03DiagnosticSources(marked_stages,
        snapshot.read('diagnostic-manifest.json').decode('utf-8'))
    sources.validate_diagnostic_sources(prepared, previous, proposal, marked)
    require(negative_locations(prepared, proposal) == previous.manifest['negative_declaration_locations'],
            'actual negative coordinates')
    return prepared, proposal, marked




def prepare_plan(identity, executable, root):
    """Own source generation and its full gate, then derive the closed plan.

    The runner must recheck its external byte identity after this operation and
    before materialization; this helper cannot authorize external file changes.
    """
    validate_identity(identity)
    prepared, proposal, marked = prepare()
    expected = _derive_plan(identity['run_id'], identity, executable, root, prepared, proposal, marked)
    return prepared, proposal, marked, expected


def reconstruct_plan(snapshot, identity, executable, root):
    """Full actual-byte source authentication followed by descriptor derivation.

    Unlike make_plan, this entry owns the retained-file reads and therefore does
    not rerun the identical source gate when constructing the expected plan.
    No caller-controlled admission flag or cached semantic verdict is accepted.
    """
    validate_identity(identity)
    prepared, proposal, marked = reconstruct(snapshot)
    expected = _derive_plan(identity['run_id'], identity, executable, root, prepared, proposal, marked)
    return prepared, proposal, marked, expected


def validate_plan_records(identity, plan, run, expected_identity, executable, root, prepared, proposal, marked=None):
    validate_identity(identity)
    require(same(identity, expected_identity), 'actual full identity differs')
    expected = make_plan(expected_identity['run_id'], expected_identity, executable, root, prepared, proposal, marked)
    require(same(plan, expected) and same(run, make_run(expected)), 'independently regenerated plan/run')
    return expected


def started(plan, run, stage, accepted, remaining):
    integer(remaining, 1, BUDGETS['launch_ns'])
    integer(stage['index'], 0, 4)
    require(stage['name'] == SCHEDULE[stage['index']], 'scheduled started stage')
    value = dict(**common(plan['run_id']), run_sha256=commitment(run), plan_sha256=commitment(plan),
        index=stage['index'], name=stage['name'], source_sha256=stage['source_sha256'],
        parents={p: accepted[p] for p in stage['parents']}, remaining_launch_ns=remaining)
    if stage['index'] == 4: value['diagnostic_manifest_sha256'] = plan['target']['diagnostic_manifest_sha256']
    validate_started(value)
    return value


def exact(value, keys, label='record'):
    require(type(value) is dict and set(value) == set(keys), label + ' exact keys')
    return value


def header(value):
    require(all(same(value[k], v) for k, v in common(value['run_id']).items()), 'diagnostic header')


def file_value(value, maximum, minimum=0):
    exact(value, ('bytes', 'sha256'), 'file record')
    integer(value['bytes'], minimum, maximum); hash_value(value['sha256'])
    return value


def module_value(value):
    exact(value, ('bytes', 'sha256', 'source_sha256'), 'module')
    file_value({k: value[k] for k in ('bytes', 'sha256')}, BUDGETS['module'], 1)
    hash_value(value['source_sha256'])
    return value


def inventory_value(value, count):
    exact(value, ('subject_count', 'inventory_sha256'), 'inventory')
    integer(value['subject_count'], count, count); hash_value(value['inventory_sha256'])
    return value


def validate_started(value):
    exact(value, set(common('0'*64)) | {'run_sha256', 'plan_sha256', 'index', 'name', 'source_sha256',
        'parents', 'remaining_launch_ns'} | ({'diagnostic_manifest_sha256'} if value.get('index') == 4 else set()), 'started')
    header(value); integer(value['index'], 0, 4)
    require(value['name'] == SCHEDULE[value['index']], 'started name')
    for k in ('run_sha256', 'plan_sha256', 'source_sha256'): hash_value(value[k])
    if value['index'] == 4: hash_value(value['diagnostic_manifest_sha256'])
    integer(value['remaining_launch_ns'], 1, BUDGETS['launch_ns'])
    expected = () if value['index'] == 0 else ('HiaSyntaxResearch.' + PARENTS[value['index']-1],)
    exact(value['parents'], expected, 'parent map')
    for parent in value['parents'].values():
        exact(parent, ('finished_receipt_sha256', 'olean_sha256', 'olean_bytes', 'source_sha256'), 'parent binding')
        integer(parent['olean_bytes'], 1, BUDGETS['module'])
        for key in ('finished_receipt_sha256', 'olean_sha256', 'source_sha256'): hash_value(parent[key])
    require(len(encode(value)) <= cap(value['name'] + '.started.json'), 'started bytes')
    return value


def validate_parent_finish(value):
    failed = value.get('status') == 'stage_failed'
    exact(value, set(common('0'*64)) | {'index', 'name', 'started_sha256', 'status', 'process', 'logs',
        'inventory', 'olean'} | ({'error_code'} if failed else set()), 'parent finish')
    header(value); integer(value['index'], 0, 3)
    require(value['name'] == PARENTS[value['index']] and value['status'] in ('stage_passed', 'stage_failed'), 'parent stage')
    hash_value(value['started_sha256']); validate_process(value['process'], success=not failed)
    if value['logs'] is None:
        require(failed and not value['process']['spawned'], 'spawned logs missing')
    else:
        exact(value['logs'], ('stdout', 'stderr'), 'logs')
        for record in value['logs'].values(): file_value(record, BUDGETS['raw_stage'])
        require(sum(v['bytes'] for v in value['logs'].values()) <= BUDGETS['raw_stage'], 'combined raw cap')
    if failed:
        require(value['error_code'] in inherited.PHASE_CODES and value['inventory'] is None and value['olean'] is None,
                'failed parent fields')
    else:
        inventory_value(value['inventory'], (56,547,271,54)[value['index']]); module_value(value['olean'])
    require(len(encode(value)) <= 2048, 'parent receipt bytes')
    return value


validate_failed_stage = validate_parent_finish


def budgets(files, display=b''):
    require(type(files) is dict and set(files) <= FIXED_FILES and
        all(type(raw) is bytes and len(raw) <= cap(n) for n, raw in files.items()), 'fixed per-file caps')
    require(type(display) is bytes, 'display bytes')
    source_total = sum(len(files.get(n, b'')) for n in SOURCE_FILES)
    module_total = sum(len(files.get(n, b'')) for n in MODULE_FILES)
    raw_total = sum(len(files.get(n, b'')) for n in LOG_FILES)
    metadata = sum(len(v) for n, v in files.items() if n not in SOURCE_FILES + MODULE_FILES + LOG_FILES)
    require(source_total <= BUDGETS['sources'] and module_total <= BUDGETS['modules'] and raw_total <= RAW_GLOBAL,
            'aggregate payload caps')
    require(metadata <= METADATA_RESERVE <= BUDGETS['metadata'] and len(display) <= BUDGETS['display']
        and metadata + raw_total + len(display) <= BUDGETS['evidence_display']
        and source_total + module_total + raw_total + metadata <= BUDGETS['container'], 'evidence/container caps')
    for name in SCHEDULE:
        require(sum(len(files.get(name + '.' + s, b'')) for s in ('stdout', 'stderr')) <= BUDGETS['raw_stage'], 'stage raw cap')
    event_bytes = len(files.get(TARGET + '.events.jsonl', b''))
    for terminal in ('RESULT.json', 'RESULT.pending.json'):
        require(event_bytes + len(files.get(terminal, b'')) <= 16384, 'events/result pair cap')
    return dict(sources=source_total, modules=module_total, raw=raw_total, metadata=metadata)


def frozen_map(files):
    require(set(files) <= FIXED_FILES, 'unplanned frozen file')
    return {n: file_record(raw) for n, raw in sorted(files.items()) if n not in TERMINALS}


def stage_files(index):
    integer(index, 0, 4)
    name = SCHEDULE[index]
    suffixes = ('started.json', 'stdout', 'stderr', 'finished.json') if index < 4 else (
        'started.json', 'stdout', 'stderr', 'events.jsonl')
    return frozenset([name + '.' + s for s in suffixes] + [MODULE_FILES[index]])


def validate_file_prefix(names, committed_parents, current=None, *, preparation=False):
    names = set(names)
    require(names <= FIXED_FILES, 'unknown retained artifacts')
    frozen = names - set(TERMINALS)
    integer(committed_parents, 0, 4)
    if preparation:
        require(committed_parents == 0 and current is None, 'preparation cannot launch')
        require(frozen == set(PREPARATION_ORDER[:len(frozen)]), 'materialization prefix order')
        return
    required = set(PREPARATION_ORDER)
    for i in range(committed_parents): required.update(stage_files(i))
    if current is None:
        require(frozen == required, 'exact committed prefix')
    else:
        integer(current, 0, 4)
        require(current == committed_parents and required <= frozen <= required | stage_files(current), 'current-only artifacts')


def validate_code_phase(code, phase):
    require(type(phase) is str and phase in PHASES and type(code) is str and code in PHASE_CODES, 'closed failure code/phase')
    normalized = {'target_prelaunch': 'prelaunch', 'target_verifying': 'verifying'}.get(phase, phase)
    allowed = PHASE_CODES[code]
    require(phase in allowed or (code in inherited.PHASE_CODES and normalized in allowed), 'failure code phase')


def _denials(value):
    require(all(same(value[k], v) for k, v in flags().items()), 'all denials required')


RESULT_HASHES = ('run_sha256', 'plan_sha256', 'identity_sha256', 'diagnostic_manifest_sha256',
    'target_started_sha256', 'target_events_sha256', 'target_terminal_sha256', 'frozen_files_sha256')


def validate_result(value):
    exact(value, set(common('0'*64)) | set(flags()) | set(RESULT_HASHES) | {
        'status', 'phase', 'error_code', 'failed_stage', 'invocations', 'launch_slots_used', 'launch_state',
        'wall_ns', 'committed_parent_receipt_sha256', 'target_marker_count', 'frozen_files_count'}, 'result')
    header(value); _denials(value)
    require(value['status'] in STATUSES and value['phase'] in PHASES and value['launch_state'] in LAUNCH_STATES,
            'result enums')
    for key in RESULT_HASHES:
        if value[key] is not None: hash_value(value[key])
    for key in ('invocations', 'launch_slots_used'): integer(value[key], 0, 5)
    integer(value['wall_ns'], 0, 600000000000)
    integer(value['target_marker_count'], 0, 11); integer(value['frozen_files_count'], 0, 53)
    index = value['failed_stage']
    if index is not None: integer(index, 0, 4)
    receipts = value['committed_parent_receipt_sha256']
    require(type(receipts) is list and len(receipts) <= 4, 'parent receipt prefix')
    for h in receipts: hash_value(h)
    require(len(set(receipts)) == len(receipts), 'unique parent receipts')
    require(len(receipts) <= value['invocations'] <= value['launch_slots_used'], 'launch accounting')
    for dependent, precursor in (('run_sha256','plan_sha256'), ('plan_sha256','identity_sha256'),
        ('target_started_sha256','run_sha256'), ('target_events_sha256','target_started_sha256'),
        ('target_terminal_sha256','target_events_sha256')):
        require(value[dependent] is None or value[precursor] is not None, 'acyclic established commitments')
    if value['target_started_sha256'] is not None: require(len(receipts) == 4, 'target requires four parents')
    if value['target_marker_count']:
        require(value['target_terminal_sha256'] is not None and len(receipts) == 4, 'frontier requires terminal and parents')
    if value['status'] == 'diagnostic_completed':
        require(value['phase'] == 'finalization' and value['error_code'] is None and index is None
            and value['invocations'] == value['launch_slots_used'] == 5 and value['launch_state'] == 'spawned'
            and len(receipts) == 4 and value['target_marker_count'] == 11 and value['frozen_files_count'] == 53
            and all(value[k] is not None for k in RESULT_HASHES), 'complete diagnostic result')
    else:
        validate_code_phase(value['error_code'], value['phase'])
        phase = value['phase']
        if phase == 'preparation':
            require(index is None and value['invocations'] == value['launch_slots_used'] == 0 and not receipts
                and value['launch_state'] == 'not_attempted' and value['target_marker_count'] == 0, 'preparation result')
        elif phase not in ('finalization', 'replay'):
            require(index is not None and len(receipts) == min(index, 4), 'failed current-stage prefix')
            if phase.startswith('target_'): require(index == 4, 'target phase index')
            if phase in ('prelaunch', 'target_prelaunch'):
                require(value['invocations'] == index and value['launch_state'] != 'spawned', 'prelaunch cannot claim current spawn')
            else:
                require(value['invocations'] in (index, index+1), 'postentry invocation prefix')
        else:
            require(index is None, 'terminal phase has no failed source stage')
        if value['launch_state'] == 'spawn_outcome_uncertain':
            require(value['launch_slots_used'] == value['invocations'] + 1 and value['target_marker_count'] == 0,
                    'uncertain entry consumes exactly one slot')
        if value['status'] in ('target_timeout','target_nonzero','target_invalid'):
            require(len(receipts) == 4 and value['invocations'] == 5 and index == 4, 'target result prefix')
        if value['status'] in ('capture_incomplete','cleanup_uncertain','raw_overflow','event_overflow','finalization_failed','replay_failed'):
            require(value['target_marker_count'] == 0, 'unverified outcome has no frontier')
        if value['status'] == 'no_launch':
            require(phase in ('preparation', 'prelaunch', 'target_prelaunch')
                and value['launch_state'] in ('not_attempted', 'not_spawned')
                and value['target_marker_count'] == 0, 'no-launch must be definitely unspawned')
        if value['status'] == 'parent_failed':
            require(index is not None and index < 4 and phase in ('capturing', 'verifying', 'receipt_commit')
                and value['invocations'] == index + 1 and value['launch_state'] == 'spawned', 'parent-failed spawned current stage')
        expected_codes = {'target_timeout': ('process_timeout',), 'target_nonzero': ('process_failed',),
            'cleanup_uncertain': ('cleanup_failed',), 'raw_overflow': ('output_limit',),
            'event_overflow': ('evidence_limit',), 'finalization_failed': ('finalization_failed',),
            'replay_failed': ('replay_invalid',)}
        if value['status'] in expected_codes:
            require(value['error_code'] in expected_codes[value['status']], 'outcome error agreement')
    require(len(encode(value)) <= cap('RESULT.json'), 'result cap')
    return value


validate_failure = validate_result


def validate_failure_footer(value):
    exact(value, set(common('0'*64)) | set(flags()) | {'status', 'error_code', 'phase', 'result_sha256',
        'pending_sha256', 'run_sha256', 'artifact_state'}, 'failure footer')
    header(value); _denials(value)
    require(value['status'] == 'container_invalid' and value['error_code'] == 'finalization_failed'
        and value['phase'] == 'finalization' and value['artifact_state'] in ('absent','present','uncertain'), 'footer constants')
    for key in ('result_sha256', 'pending_sha256', 'run_sha256'):
        if value[key] is not None: hash_value(value[key])
    if value['artifact_state'] == 'absent':
        require(value['result_sha256'] is None and value['pending_sha256'] is None, 'absent terminal hashes')
    require(len(encode(value)) <= cap('FAILURE.json'), 'footer cap')
    return value


def validate_marker(value, index, *, event=True):
    exact(value, {'id', 'original_offset', 'instrumented_offset', 'stdout_offset', 'received_ns'} |
          ({'kind'} if event else set()), 'marker')
    integer(index, 0, 10)
    if event: require(value['kind'] == 'marker', 'marker kind')
    require(value['id'] == 'HIA_SEVEN_DIAG_v1_P03_%03d' % index, 'marker ID order')
    integer(value['original_offset'], sources.OFFSETS[index], sources.OFFSETS[index])
    integer(value['instrumented_offset'], sources.OFFSETS[index]+35*index, sources.OFFSETS[index]+35*index)
    integer(value['stdout_offset'], 0, BUDGETS['raw_stage']); integer(value['received_ns'], 0, 600000000000)
    require(len(encode(value)) <= 224, 'marker cap')
    return value


SUMMARY_HASHES = ('source_sha256','diagnostic_manifest_sha256','events_sha256','result_sha256',
                  'evidence_sha256','identity_sha256','plan_sha256')


def validate_summary(value):
    exact(value, set(common('0'*64)) | set(SUMMARY_HASHES) | {'status','outcome','invocations','phase','error_code',
        'failed_stage','launch_state','parents','target','acceptance_eligible','kernel_core_syntax_connection_checked',
        'wider_obligations','authority'}, 'summary')
    header(value)
    require(value['acceptance_eligible'] is False and value['kernel_core_syntax_connection_checked'] is False
        and value['wider_obligations'] == '12 unproved' and value['authority'] == 'DENY_ALL', 'summary denials')
    require(value['status'] in ('complete_diagnostic_replayed','bounded_failure_replayed','container_unverifiable')
        and value['outcome'] in STATUSES and value['phase'] in PHASES and value['launch_state'] in LAUNCH_STATES, 'summary enums')
    integer(value['invocations'], 0, 5)
    if value['failed_stage'] is not None: integer(value['failed_stage'], 0, 4)
    if value['outcome'] == 'diagnostic_completed':
        require(value['error_code'] is None, 'complete error null')
    else: validate_code_phase(value['error_code'], value['phase'])
    for key in SUMMARY_HASHES:
        if value[key] is not None: hash_value(value[key])
    require(type(value['parents']) is list and len(value['parents']) <= 4, 'summary parent prefix')
    for i, parent in enumerate(value['parents']):
        exact(parent, ('name','subjects','status','elapsed_ns','cleanup_ns'), 'summary parent')
        require(parent['name'] == PARENTS[i] and parent['status'] in ('stage_passed','stage_failed','launch_uncertain'), 'summary parent enums')
        integer(parent['subjects'], (56,547,271,54)[i], (56,547,271,54)[i])
        for key, bound in (('elapsed_ns',600000000000), ('cleanup_ns',2000000000)):
            if parent[key] is not None: integer(parent[key], 0, bound)
        if i < len(value['parents'])-1: require(parent['status'] == 'stage_passed', 'parent failure ends prefix')
    target = exact(value['target'], ('name','marker_count','markers'), 'summary target')
    require(target['name'] == TARGET and type(target['markers']) is list, 'summary target identity')
    integer(target['marker_count'], 0, 11)
    require(len(target['markers']) == target['marker_count'], 'summary marker count')
    previous_time = previous_offset = -1
    for i, marker in enumerate(target['markers']):
        validate_marker(marker, i, event=False)
        require(marker['received_ns'] >= previous_time and marker['stdout_offset'] > previous_offset, 'marker clock/offset order')
        previous_time, previous_offset = marker['received_ns'], marker['stdout_offset']
    if value['status'] == 'container_unverifiable': require(not target['markers'], 'unverified has no frontier')
    if value['status'] == 'complete_diagnostic_replayed':
        require(value['outcome'] == 'diagnostic_completed' and value['phase'] == 'finalization' and value['failed_stage'] is None
            and value['invocations'] == 5 and value['launch_state'] == 'spawned' and len(value['parents']) == 4
            and all(p['status'] == 'stage_passed' for p in value['parents']) and target['marker_count'] == 11
            and all(value[k] is not None for k in SUMMARY_HASHES), 'complete replay summary')
    if value['status'] == 'bounded_failure_replayed': require(value['outcome'] != 'diagnostic_completed', 'failure cannot be completion')
    require(len(encode(value)) <= BUDGETS['display'], 'summary cap')
    return value
