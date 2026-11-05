"""Closed nonaccepting Part03 plan, identity, retention and record grammar.

This module does not launch processes. Actual external reads retain full size,
hash and inode records even though durable identities contain only hashes.
"""
from dataclasses import fields, replace
import json
import os
from pathlib import Path
import stat
from types import MappingProxyType

from tools import core_seven_relocation_acceptance_plan as inherited
from tools import core_seven_completion_part03_sources as sources
from tools import core_seven_relocated_part03_plan as previous_protocol
from tools.check_guarded_slice_lean import require

base = inherited.base
seven = inherited.seven
relocation = inherited.relocation
diagnostic = inherited.diagnostic
ROOT = inherited.ROOT
SCHEMA = 'hepta.hia.seven-completion-part03-diagnostic.v1'
PROTOCOL = 'seven-completion-part03-diagnostic-v1'
CAPTURE_PROTOCOL = 'p03-completion-pty-hardened-v1'
TARGET = sources.TARGET
PARENTS = seven.NAMES[:4]
SCHEDULE = PARENTS + (TARGET,)
BUDGETS = dict(inherited.BUDGETS)
METADATA_RESERVE = 224589
RAW_GLOBAL = 819891
MAX_PROCESSES = 5
ADDITIONS = (
    'tools/core_seven_completion_part03_sources.py',
    'tools/core_seven_completion_part03_plan.py',
    'tools/core_seven_completion_part03_capture.py',
    'tools/core_seven_completion_part03_replay.py',
    'tools/diagnose_core_seven_completion_part03.py',
    'tests/test_core_seven_completion_part03_sources.py',
    'tests/test_core_seven_completion_part03_diagnostic.py',
    'docs/seven-completion-part03-diagnostic.md')
SOURCE_IDENTITY_PATHS = tuple(sorted(set(previous_protocol.SOURCE_IDENTITY_PATHS) | set(ADDITIONS)))
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


SOURCE_PATHS_SHA256 = '054e820cca9d3c5780253ecd5a79a98c9056b3770e83bbd94c4bba9fa7672192'


def source_paths():
    require(len(SOURCE_IDENTITY_PATHS) == 255 and len(previous_protocol.source_paths()) == 247
            and commitment(SOURCE_IDENTITY_PATHS) == SOURCE_PATHS_SHA256,
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


def _context_scaffolding(prepared):
    """Derive temporary contexts. Only the subsequent full inverse authenticates them."""
    previous = _previous_scaffolding(prepared)
    stages = relocation._derive_stages(previous)
    relocated = relocation.ParallelRelocationSources(prepared['stages'], stages,
        relocation.encode(relocation._manifest(prepared, previous, stages)))
    return previous, relocated


def _freeze_reference(value):
    """Closed immutable construction data, never a semantic validation verdict."""
    kind = type(value)
    if value is None or kind in (str, bytes, int, bool):
        return ('scalar', value)
    if kind in (dict, MappingProxyType):
        require(all(type(k) is str for k in value), 'reference mapping key type')
        return ('mapping' if kind is MappingProxyType else 'dict',
                tuple((k, _freeze_reference(v)) for k, v in value.items()))
    if kind in (tuple, list, frozenset):
        return ({tuple: 'tuple', list: 'list', frozenset: 'frozenset'}[kind],
                tuple(_freeze_reference(v) for v in value))
    if kind is seven.original.legacy.Stage:
        return ('stage', tuple((f.name, _freeze_reference(getattr(value, f.name)))
                               for f in fields(kind)))
    raise ValueError('unsupported expected-reference type')


def _thaw_reference(value):
    tag, payload = value
    if tag == 'scalar': return payload
    if tag in ('dict', 'mapping'):
        result = {k: _thaw_reference(v) for k, v in payload}
        return MappingProxyType(result) if tag == 'mapping' else result
    if tag in ('tuple', 'list', 'frozenset'):
        return {'tuple': tuple, 'list': list, 'frozenset': frozenset}[tag](
            _thaw_reference(v) for v in payload)
    if tag == 'stage':
        return seven.original.legacy.Stage(**{k: _thaw_reference(v) for k, v in payload})
    raise ValueError('invalid private expected-reference tag')


def _construction_reference():
    # A process-local one-entry cache of pure generated ORIGINAL reference data.
    # Complete canonical IDENTITY bytes include run, Git, binary and every exact
    # source/support hash. Callers own fresh External/support checks before and
    # after use. A different key rebuilds rather than extending old authority.
    # No candidate, diagnostic, receipt, validation verdict, or caller token is
    # stored here. Every readback/finalization/replay still executes the full
    # actual-byte inverse and ALL unchanged source/input semantic gates.
    saved = None

    def original(identity):
        nonlocal saved
        validate_identity(identity)
        key = encode(identity)
        entry = saved
        if entry is None or entry[0] != key:
            prepared = seven.original.build_inputs()
            frozen = _freeze_reference(prepared)
            entry = (key, frozen)
            saved = entry
        # Keep the exact key/data association even if another caller replaces
        # the one-entry slot. No mutable cache object or Stage instance escapes.
        return _thaw_reference(entry[1])

    return original


_expected_original = _construction_reference()


def prepare():
    return _prepare_reference(seven.original.build_inputs())


def _prepare_reference(prepared):
    previous, proposal = _context_scaffolding(prepared)
    marked = sources.build_diagnostic_sources(prepared, previous, proposal)
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
    """Closed new descriptors, used only after this module owns the full source gate.

    Only the original relocation candidate and exact completion type are accepted.
    """
    require(type(proposal) is relocation.ParallelRelocationSources and
            type(marked) is sources.CompletionPart03DiagnosticSources,
            'exact new descriptor source types')
    manifest = marked.manifest
    locations = negative_locations(prepared, proposal)
    stages = []
    for i, stage in enumerate(proposal.stages):
        path = ('HiaSyntaxResearch/' if i < 4 else 'relocated/') + stage.name + '.lean'
        stages.append(dict(index=i, name=stage.name, module_name=stage.module_name,
            source_path=path if i < 4 else None, retained_source_path=path,
            source_sha256=stage.source_sha256, source_bytes=stage.source_bytes,
            parents=list(stage.parents), direct_imports=list(stage.direct_imports),
            subject_count=len(stage.expected_theorems),
            subject_sequence_sha256=commitment(seven._qualified_prints(stage.source)),
            rejection_names=sorted(stage.rejection_names)))
    target = marked.stages[4]
    value = dict(**common(run_id), identity_sha256=commitment(identity),
        original_manifest_sha256=prepared['manifest_sha256'],
        previous_seven_manifest_sha256=manifest['previous_seven_manifest_sha256'],
        relocation_manifest_sha256=manifest['relocation_manifest_sha256'],
        stages=stages,
        positive_targets=sorted(prepared['expected_theorems']),
        negatives={k: dict(v, current_location=locations[k]) for k, v in prepared['negatives'].items()},
        input_bindings={k: dict(file_record(v['bytes']), root_owner=seven.ROOT_OWNERS[k])
                        for k, v in prepared['binding_inputs'].items()},
        source_file_map={n: file_record(s.encode()) for n, s in
                        sources.retained_sources(prepared, proposal, marked.stages).items()},
        budgets=dict(BUDGETS), process_spec=dict(executable=absolute(str(executable)), root=absolute(str(root)),
            sysroot=absolute(str(Path(executable).parent.parent)),
            argv_template=['executable', '--root=root', '-o', 'root/module.olean', 'root/module.lean'],
            environment_keys=['LEAN_PATH', 'LEAN_SYSROOT'], unset_environment_keys=['LEAN_SRC_PATH'],
            parent_capture='core_seven_acceptance_capture.capture',
            target_capture='core_seven_completion_part03_capture.capture'),
        schedule=list(SCHEDULE), maximum_processes=5, acceptance_eligible=False,
        metadata_reserve=METADATA_RESERVE, raw_global=RAW_GLOBAL,
        target=dict(name=TARGET, index=4, source_stage='CertPart03', module_name=target.module_name,
            source_path='HiaSyntaxResearch/CertPart03.lean', module_path=MODULE_FILES[4],
            source_sha256=target.source_sha256, source_bytes=target.source_bytes,
            unmarked_path='relocated/CertPart03.lean', diagnostic_manifest_sha256=marked.manifest_sha256,
            parents=list(target.parents), subject_count=1655,
            subject_sequence_sha256=manifest['subject_sequence_sha256'], capture_protocol=CAPTURE_PROTOCOL))
    require(tuple(s['subject_count'] for s in stages) == relocation.COUNTS, 'fixed new subject counts')
    require(set(value['source_file_map']) == set(SOURCE_FILES), 'fixed source retention membership')
    require(len(encode(value)) <= cap('PLAN.json'), 'plan bytes')
    static_sizing(identity, value, prepared, proposal, marked)
    return value



def static_sizing(identity, plan, prepared, proposal, marked):
    """Fail closed before launch, within every unchanged aggregate/per-file cap.

    Sizing only: no generated reference is used as a semantic verdict. The caller
    already owns a complete actual-source gate. Header/name slack charges all
    remaining fixed receipt/footer records, including duplicate pending results.
    """
    old_identity = dict(identity, **previous_protocol.common(identity['run_id']))
    old_identity['sources'] = {n: identity['sources'][n] for n in previous_protocol.source_paths()}
    previous = _previous_scaffolding(prepared)
    old_marked = sources.original._derive(prepared, previous, proposal)
    old_plan = previous_protocol._derive_plan(identity['run_id'], old_identity,
        plan['process_spec']['executable'], plan['process_spec']['root'], prepared, proposal, old_marked)
    identity_delta = len(encode(identity)) - len(encode(old_identity))
    manifest_delta = len(marked.manifest_json.encode()) - len(old_marked.manifest_json.encode())
    plan_delta = len(encode(plan)) - len(encode(old_plan))
    # Exact maximal serialized observations: old eleven=1691; new thirteen=2138.
    # Exact full target summary delta=536; remaining closed header/name changes
    # across RUN, eight parent receipts, target-started, two results, footer,
    # and summary cost two bytes each. Target/capture labels add at most twelve
    # more bytes, giving less than64; reserve512 conservatively.
    metadata_delta_bound = identity_delta + manifest_delta + max(0, plan_delta) + 447 + 536 + 512
    require(identity_delta == 929 and manifest_delta == 828 and metadata_delta_bound <= 4096,
            'fixed completion metadata addition within4KiB')
    fixed = {'IDENTITY.json': encode(identity), 'PLAN.json': encode(plan),
             'RUN.json': encode(make_run(plan)), 'relocation-manifest.json': proposal.manifest_json.encode(),
             'diagnostic-manifest.json': marked.manifest_json.encode()}
    require(all(len(raw) <= cap(name) for name, raw in fixed.items()), 'static fixed metadata caps')
    dynamic = set(RECEIPT_FILES) | set(TERMINALS)
    metadata_bound = sum(map(len, fixed.values())) + sum(cap(n) for n in dynamic)
    retained = sources.retained_sources(prepared, proposal, marked.stages)
    source_bytes = sum(len(s.encode()) for s in retained.values())
    require(source_bytes == 6206175 and all(len(s.encode()) <= BUDGETS['source'] for s in retained.values()),
            'static exact source headroom')
    require(metadata_bound <= METADATA_RESERVE and
            METADATA_RESERVE + RAW_GLOBAL + BUDGETS['display'] <= BUDGETS['evidence_display'] and
            source_bytes + BUDGETS['modules'] + RAW_GLOBAL + METADATA_RESERVE <= BUDGETS['container'],
            'static unchanged aggregate headroom')
    source_delta = marked.stages[4].source_bytes - old_marked.stages[4].source_bytes
    nominal_output_delta = len(sources.SENTINEL_OUTPUT.encode()) + len(('"'+sources.MARKER_IDS[9]+'" : String\n').encode())
    require(source_delta == 60 and nominal_output_delta == 80 and source_delta < 256 and nominal_output_delta < 256,
            'exact source/nominal output increment')
    require(2368 + 2138 + 3584 <= cap(TARGET+'.events.jsonl'), 'static full event stream reserve')
    return dict(source_bytes=source_bytes, target_source_bytes=marked.stages[4].source_bytes,
        target_source_sha256=marked.stages[4].source_sha256, source_delta=source_delta,
        nominal_output_delta=nominal_output_delta, identity_bytes=len(encode(identity)),
        manifest_bytes=len(marked.manifest_json.encode()), plan_bytes=len(encode(plan)),
        metadata_delta_bound=metadata_delta_bound, identity_delta=identity_delta,
        manifest_delta=manifest_delta, plan_delta=plan_delta, observation_delta=447,
        summary_target_delta=536, remaining_header_name_reserve=512,
        metadata_bound=metadata_bound, metadata_headroom=METADATA_RESERVE-metadata_bound,
        event_stream_bound=8090, event_stream_headroom=326,
        container_bound=source_bytes+BUDGETS['modules']+RAW_GLOBAL+METADATA_RESERVE,
        container_headroom=BUDGETS['container']-source_bytes-BUDGETS['modules']-RAW_GLOBAL-METADATA_RESERVE)

def make_run(plan):
    return dict(**common(plan['run_id']), identity_sha256=plan['identity_sha256'], plan_sha256=commitment(plan),
                diagnostic_manifest_sha256=plan['target']['diagnostic_manifest_sha256'])


def reconstruct(snapshot):
    return _reconstruct_reference(snapshot, seven.original.build_inputs())


def _reconstruct_reference(snapshot, prepared):
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
    marked = sources.CompletionPart03DiagnosticSources(marked_stages,
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
    prepared, proposal, marked = _prepare_reference(_expected_original(identity))
    expected = _derive_plan(identity['run_id'], identity, executable, root, prepared, proposal, marked)
    return prepared, proposal, marked, expected


def reconstruct_plan(snapshot, identity, executable, root):
    """Full actual-byte source authentication followed by descriptor derivation.

    Unlike make_plan, this entry owns the retained-file reads and therefore does
    not rerun the identical source gate when constructing the expected plan.
    Only pure immutable expected-original construction can be reused under the
    full exact identity key. No caller-controlled admission flag or cached
    semantic verdict is accepted; actual originals and all inverse gates rerun.
    """
    validate_identity(identity)
    prepared, proposal, marked = _reconstruct_reference(snapshot, _expected_original(identity))
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



def _validate_outcome(status, phase, code, index, invocations, launch_state):
    """Closed shared outcome grammar, separate from actual evidence authority."""
    if status == 'diagnostic_completed':
        require(phase == 'finalization' and code is None and index is None
            and invocations == 5 and launch_state == 'spawned', 'complete outcome fields')
        return
    validate_code_phase(code, phase)
    if launch_state == 'spawned': require(invocations > 0, 'spawned outcome needs a process')
    if launch_state in ('not_spawned', 'spawn_outcome_uncertain'):
        require(invocations < 5, 'unconfirmed entry cannot consume a sixth slot')
    if phase == 'preparation':
        require(status == 'no_launch' and index is None and invocations == 0
            and launch_state == 'not_attempted', 'preparation no-launch fields')
    elif phase in ('finalization', 'replay'):
        require(index is None and status == ('finalization_failed' if phase == 'finalization' else 'replay_failed'),
                'terminal failure phase and outcome')
    else:
        require(index is not None, 'current outcome needs stage')
        require(invocations == index + int(launch_state == 'spawned'), 'current-stage confirmed invocation')
        if phase in ('prelaunch', 'verifying', 'receipt_commit'):
            require(index < 4, 'parent-only phase')
        if phase.startswith('target_'): require(index == 4, 'target-only phase')
        states = {'prelaunch': ('not_attempted', 'not_spawned'),
                  'target_prelaunch': ('not_attempted', 'not_spawned'),
                  'capturing': ('spawned', 'spawn_outcome_uncertain', 'not_spawned'),
                  'verifying': ('spawned',), 'receipt_commit': ('spawned',), 'target_verifying': ('spawned',)}
        require(launch_state in states[phase], 'current phase launch state')
        if phase == 'capturing' and launch_state == 'not_spawned':
            # Exact false can be established before malformed return/log data
            # raises, while the runner has not yet changed its capture phase.
            require(status == 'capture_incomplete' and code == 'filesystem_invalid',
                    'known unspawned malformed collector fallback')
    if code in ('marker_invalid', 'clock_invalid', 'platform_invalid', 'pty_invalid',
                'target_inventory_invalid', 'target_module_invalid'):
        require(index == 4, 'new target error belongs to target only')
    if status == 'no_launch':
        require(phase in ('preparation', 'prelaunch', 'target_prelaunch')
            and launch_state in ('not_attempted', 'not_spawned'), 'no-launch definitely unspawned')
    elif status == 'parent_failed':
        require(index is not None and index < 4 and launch_state == 'spawned'
            and phase in ('capturing', 'verifying', 'receipt_commit') and code in inherited.PHASE_CODES,
            'parent-failed source, phase and inherited error')
    elif status in ('target_timeout', 'target_nonzero', 'cleanup_uncertain', 'raw_overflow'):
        codes = {'target_timeout': 'process_timeout', 'target_nonzero': 'process_failed',
                 'cleanup_uncertain': 'cleanup_failed', 'raw_overflow': 'output_limit'}
        require(index == 4 and invocations == 5 and launch_state == 'spawned'
            and phase == 'capturing' and code == codes[status], 'confirmed target process outcome')
    elif status == 'target_invalid':
        require(index == 4 and invocations == 5 and launch_state == 'spawned'
            and phase in ('capturing', 'target_verifying') and code in
            ('marker_invalid', 'clock_invalid', 'target_inventory_invalid', 'target_module_invalid'),
            'target-invalid exact code and phase')
    elif status == 'event_overflow':
        require(index == 4 and code == 'evidence_limit' and
            ((phase == 'capturing' and launch_state in ('spawned', 'spawn_outcome_uncertain')) or
             (phase == 'target_prelaunch' and launch_state == 'not_spawned')),
            'target-only event persistence failure')
    elif status == 'capture_incomplete':
        require(code in ('capture_incomplete', 'filesystem_invalid', 'clock_invalid', 'evidence_limit', 'identity_changed')
            and (phase in ('capturing', 'verifying', 'receipt_commit', 'target_verifying') or
                (phase == 'target_prelaunch' and index == 4 and launch_state == 'not_spawned'
                 and code == 'filesystem_invalid')), 'incomplete exact code and phase')
    elif status == 'finalization_failed':
        require(phase == 'finalization' and code == 'finalization_failed', 'finalization outcome')
    elif status == 'replay_failed':
        require(phase == 'replay' and code == 'replay_invalid', 'replay outcome')
    else:
        raise ValueError('unknown outcome')


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
    integer(value['target_marker_count'], 0, 12); integer(value['frozen_files_count'], 0, 53)
    index = value['failed_stage']
    if index is not None: integer(index, 0, 4)
    receipts = value['committed_parent_receipt_sha256']
    require(type(receipts) is list and len(receipts) <= 4, 'parent receipt prefix')
    for h in receipts: hash_value(h)
    require(len(set(receipts)) == len(receipts), 'unique parent receipts')
    require(len(receipts) <= value['invocations'] <= value['launch_slots_used'], 'launch accounting')
    difference = value['launch_slots_used'] - value['invocations']
    require(difference == (1 if value['launch_state'] in ('not_spawned', 'spawn_outcome_uncertain') else 0),
            'one current collector entry exactly matches launch state')
    if value['launch_state'] == 'spawned': require(value['invocations'] > 0, 'spawned state needs a process')
    for dependent, precursor in (('run_sha256','plan_sha256'), ('plan_sha256','identity_sha256'),
        ('target_started_sha256','run_sha256'), ('target_events_sha256','target_started_sha256'),
        ('target_terminal_sha256','target_events_sha256')):
        require(value[dependent] is None or value[precursor] is not None, 'acyclic established commitments')
    if value['target_started_sha256'] is not None: require(len(receipts) == 4, 'target requires four parents')
    if value['target_marker_count']:
        require(value['target_terminal_sha256'] is not None and len(receipts) == 4, 'frontier requires terminal and parents')
    _validate_outcome(value['status'], value['phase'], value['error_code'], index,
                      value['invocations'], value['launch_state'])
    if value['status'] == 'diagnostic_completed':
        require(value['invocations'] == value['launch_slots_used'] == 5 and len(receipts) == 4
            and value['target_marker_count'] == 12 and value['frozen_files_count'] == 53
            and all(value[k] is not None for k in RESULT_HASHES), 'complete diagnostic result')
    else:
        if value['phase'] == 'preparation':
            require(value['launch_slots_used'] == 0 and not receipts, 'preparation has no launches or parents')
        elif value['phase'] not in ('finalization', 'replay'):
            require(len(receipts) == index, 'failed current-stage parent prefix')
        if value['status'] not in ('target_timeout', 'target_nonzero'):
            require(value['target_marker_count'] == 0, 'unverified outcome has no frontier')
    if value['target_marker_count']:
        require(all(value[k] is not None for k in RESULT_HASHES), 'frontier needs all established commitments')
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
    integer(index, 0, 11)
    keys = {'id', 'original_offset', 'instrumented_offset', 'stdout_offset', 'received_ns'}
    if index == 9: keys |= {'stdout_length', 'stdout_sha256'}
    exact(value, keys | ({'kind'} if event else set()), 'marker')
    if event: require(value['kind'] == 'marker', 'marker kind')
    require(value['id'] == sources.MARKER_IDS[index], 'marker ID order')
    integer(value['original_offset'], sources.OFFSETS[index], sources.OFFSETS[index])
    integer(value['instrumented_offset'], sources.MARKER_OFFSETS[index], sources.MARKER_OFFSETS[index])
    integer(value['stdout_offset'], 0, BUDGETS['raw_stage']); integer(value['received_ns'], 0, 600000000000)
    if index == 9:
        raw = ('\"' + sources.MARKER_IDS[index] + '\" : String\n').encode()
        integer(value['stdout_length'], len(raw), len(raw))
        require(value['stdout_sha256'] == digest(raw), 'exact completion marker raw hash')
    require(len(encode(value)) <= (272 if index == 9 else 224), 'marker cap')
    return value


def validate_sentinel(value, *, event=True):
    exact(value, {'id','stdout_offset','stdout_length','stdout_sha256','received_ns'} |
          ({'kind'} if event else set()), 'sentinel')
    if event: require(value['kind'] == 'sentinel', 'sentinel kind')
    require(value['id'] == 'True.intro', 'reserved sentinel identity')
    integer(value['stdout_offset'], 0, BUDGETS['raw_stage'])
    raw = sources.SENTINEL_OUTPUT.encode()
    integer(value['stdout_length'], len(raw), len(raw))
    require(value['stdout_sha256'] == digest(raw), 'exact sentinel raw hash')
    integer(value['received_ns'], 0, 600000000000)
    require(len(encode(value)) <= 208, 'sentinel cap')
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
    # An unrepresentable execution can only give this closed denial summary,
    # preserving known counters/stage without inventing receipts or applying
    # nominal capture-phase state claims to an unrepresentable outer failure.
    fallback = (value['status'] == 'container_unverifiable' and value['outcome'] == 'capture_incomplete'
        and value['phase'] == 'capturing' and value['error_code'] == 'capture_incomplete')
    if not fallback:
        _validate_outcome(value['outcome'], value['phase'], value['error_code'], value['failed_stage'],
                          value['invocations'], value['launch_state'])
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
    target = exact(value['target'], ('name','marker_count','markers','completion','sentinel'), 'summary target')
    require(target['name'] == TARGET and type(target['markers']) is list, 'summary target identity')
    integer(target['marker_count'], 0, 12)
    require(len(target['markers']) == target['marker_count'], 'summary marker count')
    if target['marker_count']:
        require(value['outcome'] in ('diagnostic_completed', 'target_timeout', 'target_nonzero')
            and value['invocations'] == 5 and value['launch_state'] == 'spawned'
            and len(value['parents']) == 4 and all(parent['status'] == 'stage_passed' for parent in value['parents']),
            'summary frontier needs a safe target outcome and four passed parents')
    previous_time = previous_offset = -1
    for i, marker in enumerate(target['markers']):
        validate_marker(marker, i, event=False)
        require(marker['received_ns'] >= previous_time and marker['stdout_offset'] > previous_offset, 'marker clock/offset order')
        previous_time, previous_offset = marker['received_ns'], marker['stdout_offset']
    sentinel = target['sentinel']
    if sentinel is not None:
        validate_sentinel(sentinel, event=False)
        require(target['marker_count'] >= 9, 'sentinel follows pre-inventory marker')
        before = target['markers'][8]
        require(sentinel['stdout_offset'] > before['stdout_offset'] and sentinel['received_ns'] >= before['received_ns'],
                'sentinel causal boundary')
        if target['marker_count'] >= 10:
            after = target['markers'][9]
            require(sentinel['stdout_offset'] + sentinel['stdout_length'] <= after['stdout_offset']
                    and sentinel['received_ns'] <= after['received_ns'], 'post-barrier causal boundary')
    require(target['marker_count'] < 10 or sentinel is not None, 'post-barrier marker requires sentinel')
    completion = exact(target['completion'], ('observed','received_ns','meaning'), 'completion observation')
    require(type(completion['observed']) is bool and completion['observed'] == (sentinel is not None)
            and completion['meaning'] == 'checked_chain_resolved_not_proof_success', 'completion meaning')
    require(same(completion['received_ns'], None if sentinel is None else sentinel['received_ns']), 'completion receipt')
    if value['status'] == 'container_unverifiable':
        require(not target['markers'] and sentinel is None and not value['parents'], 'unverified has no parent or target frontier')
    if value['status'] == 'complete_diagnostic_replayed':
        require(value['outcome'] == 'diagnostic_completed' and value['phase'] == 'finalization' and value['failed_stage'] is None
            and value['invocations'] == 5 and value['launch_state'] == 'spawned' and len(value['parents']) == 4
            and all(p['status'] == 'stage_passed' for p in value['parents']) and target['marker_count'] == 12
            and all(value[k] is not None for k in SUMMARY_HASHES), 'complete replay summary')
    if value['status'] == 'bounded_failure_replayed':
        index = value['failed_stage']
        require(value['outcome'] != 'diagnostic_completed' and index is not None
            and value['phase'] not in ('preparation', 'finalization', 'replay')
            and value['launch_state'] != 'spawn_outcome_uncertain', 'independently replayed failure stage')
        require(value['outcome'] != 'event_overflow', 'event persistence failure is not independently replayable')
        if value['outcome'] == 'capture_incomplete':
            require(value['error_code'] == 'capture_incomplete', 'external capture failure is not independently replayable')
        if value['outcome'] == 'target_invalid':
            require(value['error_code'] != 'clock_invalid', 'unrepresentable clock is not independently replayable')
        if value['outcome'] == 'parent_failed':
            require(value['error_code'] in ('process_timeout', 'process_failed', 'output_limit', 'cleanup_failed',
                    'capture_incomplete', 'inventory_invalid', 'module_invalid'),
                    'parent failure needs an independently reproducible predicate')
        require(len(value['parents']) <= value['invocations'], 'summary parents cannot exceed confirmed spawns')
        if index == 4:
            require(len(value['parents']) == 4 and all(row['status'] == 'stage_passed' for row in value['parents']),
                    'failed target needs four replayed parents')
        else:
            current_spawned = value['launch_state'] == 'spawned'
            require(len(value['parents']) == index + int(current_spawned)
                and all(row['status'] == 'stage_passed' for row in value['parents'][:index])
                and (not current_spawned or value['parents'][-1]['status'] == 'stage_failed'),
                'replayed parent failure prefix')
    require(len(encode(value)) <= BUDGETS['display'], 'summary cap')
    return value
