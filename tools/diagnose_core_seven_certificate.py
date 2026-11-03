"""Four-process seven-certificate diagnostic and independent, nonaccepting replay.

No target module is admitted, including on exit zero. Replay never launches Lean.
A frozen hash is an integrity binding, not authentication of a hostile host.
"""
from dataclasses import replace
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import time
import uuid

from tools import check_core_syntax_staged as base
from tools import core_syntax_diagnostic_capture as collector
from tools import core_syntax_partition_sources as sources
from tools import core_seven_certificate_sources as seven
from tools.check_guarded_slice_lean import require, theorem_inventory
from tools.check_initialization_frontiers import DENY
from tools.extract_initialization_obligations import OBLIGATIONS

ROOT = base.ROOT
PROTOCOL = 'seven-certificate-first-four-diagnostic-v1'
SCHEMA = 'hepta.hia.seven-certificate-first-four-result.v1'
DIAGNOSTIC_NAMES = ('Baseline', 'SyntaxData', 'CertPart01', 'CertPart02')
NOT_SCHEDULED = ('CertPart03', 'CertPart04', 'CertPart05', 'CertPart06', 'CertPart07',
                 'ConnectionsTransportRejections', 'WrongArm')
TARGET = 'SevenCertificatePart02'
CAPTURE_FILES = tuple(TARGET + suffix for suffix in ('.stdout', '.stderr', '.events.jsonl'))
TARGET_STARTED = TARGET + '.started.json'
TARGET_INVENTORY = TARGET + '.inventory.json'
PARENT_FILES = tuple(name + suffix for name in DIAGNOSTIC_NAMES[:3]
                     for suffix in ('.started.json', '.stdout', '.stderr', '.finished.json'))
PREPARATION = ('RUN.json', 'IDENTITY.json', 'original-manifest.json', 'seven-manifest.json',
               'diagnostic-manifest.json')
SOURCE_FILES = (tuple('original/' + name + '.lean' for name in sources.NAMES) +
                tuple(base.MODULE_PREFIX + '/' + name + '.lean' for name in DIAGNOSTIC_NAMES) +
                tuple('seven/' + name + '.lean' for name in seven.NAMES[3:]))
MODULE_FILES = tuple(base.MODULE_PREFIX + '/' + name + '.olean' for name in DIAGNOSTIC_NAMES)
FIXED_FILES = frozenset(PREPARATION + SOURCE_FILES + MODULE_FILES + PARENT_FILES + CAPTURE_FILES +
                        (TARGET_STARTED, TARGET_INVENTORY, 'EVIDENCE.json', 'RESULT.json'))
STATUSES = ('diagnostic_completed', 'diagnostic_timeout', 'diagnostic_failed',
            'diagnostic_infrastructure_failed', 'diagnostic_output_limit')
SOURCE_IDENTITY_ADDITIONS = (
    'tools/core_seven_certificate_sources.py', 'tools/core_seven_certificate_diagnostic_sources.py',
    'tools/diagnose_core_seven_certificate.py', 'tests/test_core_seven_certificate_sources.py',
    'tests/test_core_seven_certificate_diagnostic.py', 'tests/test_core_seven_certificate_runner.py',
    'docs/seven-certificate-source-proposal.md',
    'docs/seven-certificate-first-four-diagnostic-design.md')


def _encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def _same(left, right):
    return _encoded(left) == _encoded(right)


def _json(raw, *, newline=True):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate JSON field')
            result[key] = value
        return result
    def constant(value):
        raise ValueError('nonfinite JSON constant: ' + value)
    value = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    require(type(value) is dict, 'JSON object required')
    expected = _encoded(value) if newline else _encoded(value)[:-1]
    require(raw == expected, 'noncanonical JSON')
    return value


def _finite(value):
    return type(value) in (int, float) and math.isfinite(value) and 0 <= value <= 600


def _hash_map(value):
    require(type(value) is dict and value and all(type(k) is str and type(v) is str and
            re.fullmatch('[0-9a-f]{64}', v) for k, v in value.items()), 'invalid identity hash map')


def _denials():
    return dict(diagnostic_only=True, acceptance_eligible=False,
                kernel_core_syntax_connection_checked=False, actual_core_bridge_proved=False,
                python_exporter_refinement_proved=False, body_prefix_refinement_proved=False,
                all_edge_transfer_proved=False,
                obligations=[dict(id=n, status='unproved') for n, _ in OBLIGATIONS], **DENY)


def _cap(name):
    if name in SOURCE_FILES:
        return base.MAX_SOURCE
    if name in MODULE_FILES:
        return base.MAX_MODULE
    if name in ('seven-manifest.json', 'diagnostic-manifest.json'):
        return 32768
    if name in ('RESULT.json', CAPTURE_FILES[2]):
        return collector.METADATA_LIMIT
    return base.MAX_DIAGNOSTIC


class _Snapshot:
    """Bind each immutable file and every directory inode across all rereads."""
    def __init__(self, root):
        self.root, self.files, self.directories = root, {}, {}
        self.check_directories()

    def check_directories(self):
        self.root.unchanged()
        paths = [self.root.path, *self.root.path.parents]
        paths.extend(self.root.path / name for name in ('original', 'seven', base.MODULE_PREFIX)
                     if os.path.lexists(self.root.path / name))
        for path in paths:
            info = os.stat(path, follow_symlinks=False)
            require(stat.S_ISDIR(info.st_mode), 'symlink or non-directory ancestor')
            key, identity = str(path), (info.st_dev, info.st_ino)
            require(key not in self.directories or self.directories[key] == identity,
                    'directory inode changed')
            self.directories[key] = identity

    def read(self, name):
        self.check_directories()
        raw = self.root.read(name, _cap(name))
        info = os.stat(self.root.path / name, follow_symlinks=False)
        identity = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_nlink)
        require(name not in self.files or self.files[name] == identity, 'frozen file inode changed: ' + name)
        self.files[name] = identity
        return raw


class _ExternalSnapshot:
    """Pin regular source/support/binary files, not merely their content hashes."""
    def __init__(self, executable, identity, support):
        for name in identity:
            base._relative(name)
        for name in support:
            base._relative(name)
            require(name.startswith('lib/lean/'), 'support path outside pinned sysroot')
        self.paths = {str(ROOT / name): digest for name, digest in identity.items()}
        self.paths.update({str(executable.parent.parent / name): digest for name, digest in support.items()})
        self.paths[str(executable)] = base.digest(executable.read_bytes())
        self.identities, self.parents = {}, {}
        self.check()
        for path, digest in self.paths.items():
            require(base.digest(Path(path).read_bytes()) == digest, 'external initial bytes differ: ' + path)
        self.check()

    def check(self):
        for name in self.paths:
            path = Path(name)
            for parent in path.parents:
                info = os.stat(parent, follow_symlinks=False)
                value = (info.st_dev, info.st_ino)
                require(stat.S_ISDIR(info.st_mode) and
                        (str(parent) not in self.parents or self.parents[str(parent)] == value),
                        'external ancestor inode changed')
                self.parents[str(parent)] = value
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            try:
                info = os.fstat(fd)
                value = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_nlink)
                now = os.stat(path, follow_symlinks=False)
                current = (now.st_dev, now.st_ino, now.st_size, now.st_mtime_ns, now.st_ctime_ns, now.st_nlink)
                require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and value == current and
                        (name not in self.identities or self.identities[name] == value),
                        'external file inode changed: ' + name)
                self.identities[name] = value
            finally:
                os.close(fd)


def _evidence_budget(files, displayed=()):
    require(sum(len(files.get(n, b'')) for n in CAPTURE_FILES[:2]) <= collector.RAW_LIMIT,
            'raw evidence budget')
    require(len(files.get('RESULT.json', b'')) + len(files.get(CAPTURE_FILES[2], b'')) <=
            collector.METADATA_LIMIT, 'metadata evidence budget')
    durable = sum(len(raw) for name, raw in files.items()
                  if name not in SOURCE_FILES and name not in MODULE_FILES)
    display = sum(len(name.encode()) + 2 + len(files[name]) for name in displayed)
    require(durable + display <= base.MAX_DIAGNOSTIC, 'durable plus display evidence budget')


def source_identity():
    from tools.diagnose_core_byte_facts import source_identity as inherited
    result = inherited()
    for name in SOURCE_IDENTITY_ADDITIONS:
        result[name] = base.digest((ROOT / name).read_bytes())
    return result


def _git_baseline():
    # Read-only source identity metadata, not a diagnostic/Lean invocation.
    head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, timeout=5).decode().strip()
    tree = subprocess.check_output(['git', 'rev-parse', 'HEAD^{tree}'], cwd=ROOT, timeout=5).decode().strip()
    require(re.fullmatch('[0-9a-f]{40}', head) and re.fullmatch('[0-9a-f]{40}', tree), 'Git baseline identity')
    return dict(head=head, tree=tree)


def _command(executable, root, stage):
    source = str(Path(root) / (stage.module_name.replace('.', '/') + '.lean'))
    output = str(Path(root) / (stage.module_name.replace('.', '/') + '.olean'))
    return dict(argv=[str(executable), '--root=' + str(root), '-o', output, source],
                cwd=str(root), search_path=str(root), sysroot=str(Path(executable).parent.parent),
                timeout_seconds=60)


def _process(result, command, *, successful=False):
    require(type(result) is dict, 'process receipt missing')
    required = set(command) | {'returncode', 'timed_out', 'incomplete', 'output_truncated', 'elapsed_seconds'}
    optional = {'stdout', 'stderr', 'error_type', 'stdout_available_bytes', 'stderr_available_bytes',
                'stdout_available_sha256', 'stderr_available_sha256', 'retained_output_sha256'}
    require(required <= set(result) <= required | optional, 'parent process schema differs')
    if 'error_type' in result:
        require(type(result['error_type']) is str and bool(result['error_type']), 'parent error type differs')
    require(all(_same(result.get(k), value) for k, value in command.items()), 'process command/environment differs')
    require(_finite(result.get('elapsed_seconds')), 'process elapsed time invalid')
    for key in ('timed_out', 'incomplete', 'output_truncated'):
        require(type(result.get(key)) is bool, 'process flag type differs')
    require(result.get('returncode') is None or type(result['returncode']) is int, 'process exit type differs')
    if result['timed_out']:
        require(result['returncode'] is None and result['incomplete'] is True and
                result.get('error_type') == 'TimeoutExpired' and result['elapsed_seconds'] >= 60,
                'parent timeout semantics differ')
    elif result['returncode'] is None:
        require(result['incomplete'] is True and type(result.get('error_type')) is str,
                'nonstarted parent semantics differ')
    if successful:
        require(type(result.get('returncode')) is int and result['returncode'] == 0 and
                result['timed_out'] is False and result['incomplete'] is False and
                result['output_truncated'] is False, 'parent process incomplete or failed')


def _inventory(out, err, stage):
    text = (out + err).decode('utf-8', errors='strict').replace('\r\n', '\n')
    inventory = theorem_inventory(text, set(stage.expected_theorems))
    subjects = re.findall(r"^'([^']+)' (?:depends on axioms: \[[^\]]*\]|does not depend on any axioms)$", text, re.M)
    require(tuple(subjects) == seven._qualified_prints(stage.source), 'axiom print sequence differs')
    return inventory


def _start(stage, run, run_sha, identity_sha, parents, logical_target=None):
    value = dict(protocol=PROTOCOL, run_id=run['run_id'], run_sha256=run_sha,
                 identity_sha256=identity_sha, name=stage.name, module_name=stage.module_name,
                 source_sha256=stage.source_sha256, source_bytes=stage.source_bytes,
                 parents=parents, command=_command(run['executable'], run['root'], stage),
                 manifests={key: run[key] for key in ('original_manifest_sha256', 'seven_manifest_sha256',
                                                     'diagnostic_manifest_sha256')})
    if logical_target:
        value['logical_target'] = logical_target
    return value


def _module(stage, raw):
    require(0 < len(raw) <= base.MAX_MODULE, 'empty or oversized module')
    return dict(path=stage.module_name.replace('.', '/') + '.olean', sha256=base.digest(raw),
                bytes=len(raw), source_sha256=stage.source_sha256)


def execute_diagnostic(executable, output_directory, prepared, proposal, diagnostic, identity, support,
                       source_reader, support_reader, expected_binary_sha,
                       run_process=base.capture_result, capture=None):
    from tools import core_seven_certificate_diagnostic_sources as diagnostic_sources
    # These full gates precede even creating the evidence directory.
    base.validate_plan(prepared)
    seven.validate_sources(prepared, proposal)
    diagnostic_sources.validate_diagnostic_sources(prepared, proposal, diagnostic)
    retained = diagnostic_sources.retained_sources(prepared, proposal, diagnostic.stages)
    require(set(retained) == set(SOURCE_FILES) and sum(len(s.encode()) for s in retained.values()) == 5615437,
            'exact retained source plan')
    seven.validate_retention(proposal, (diagnostic.stages[3].source,))
    base._support_imports(prepared, support)
    _hash_map(identity); _hash_map(support)
    executable = Path(executable).absolute()
    require(_same(source_identity(), identity), 'exact complete source identity required')
    external = _ExternalSnapshot(executable, identity, support)
    require(source_reader() == identity and support_reader(executable) == support and
            base.digest(executable.read_bytes()) == expected_binary_sha, 'preparation identity changed')
    root = base.SafeRoot(output_directory)
    snapshot = _Snapshot(root)
    frozen, accepted, allowed = {}, {}, set()
    started_at = time.monotonic()
    current = None
    process_result = None
    target_capture_verified = False
    parent_process_verified = False
    report = dict(schema=SCHEMA, protocol=PROTOCOL, status='diagnostic_running', invocation_limit=4,
                  invocations=0, invocation_count_exact=True, stages=[], not_scheduled=list(NOT_SCHEDULED),
                  evidence_complete=False, **_denials())

    def write(name, raw):
        require(name in FIXED_FILES and name not in frozen, 'exclusive fixed evidence file')
        root.write(name, raw)
        allowed.add(name)
        frozen[name] = base.digest(raw)
        require(snapshot.read(name) == raw, 'written evidence differs')

    def write_json(name, value):
        write(name, _encoded(value))

    def state(extra=()):
        external.check()
        snapshot.check_directories()
        sysroot = executable.parent.parent / 'lib/lean'
        require(not os.path.lexists(sysroot / base.MODULE_PREFIX) and
                not os.path.lexists(sysroot / (base.MODULE_PREFIX + '.olean')), 'module prefix shadows support')
        require(base.digest(executable.read_bytes()) == expected_binary_sha and source_reader() == identity and
                support_reader(executable) == support, 'source/support/binary changed')
        external.check()
        files = root.scan(allowed | set(extra))
        _evidence_budget({name: snapshot.read(name) for name in frozen
                          if name not in SOURCE_FILES + MODULE_FILES})
        for name, digest in frozen.items():
            require(base.digest(snapshot.read(name)) == digest, 'frozen evidence changed: ' + name)
        modules = {name: size for name, size in files.items() if name in MODULE_FILES}
        require(all(size <= base.MAX_MODULE for size in modules.values()) and
                sum(modules.values()) <= base.MAX_TOTAL_MODULE, 'module byte budget')
        return files

    def freeze_optional(name):
        if name in frozen:
            return
        try:
            raw = snapshot.read(name)
        except FileNotFoundError:
            return
        frozen[name] = base.digest(raw)
        allowed.add(name)

    try:
        write('original-manifest.json', prepared['manifest_json'].encode())
        write('seven-manifest.json', proposal.manifest_json.encode())
        write('diagnostic-manifest.json', diagnostic.manifest_json.encode())
        write_json('IDENTITY.json', dict(source_sha256=identity, support_sha256=support,
                                       lean_binary_sha256=expected_binary_sha))
        run = dict(protocol=PROTOCOL, schema=SCHEMA, schedule=list(DIAGNOSTIC_NAMES), invocation_limit=4,
                   run_id=uuid.uuid4().hex, root=str(root.path), executable=str(executable),
                   git_baseline=_git_baseline(), source_baseline_sha256=base.digest(_encoded(identity)),
                   original_manifest_sha256=frozen['original-manifest.json'],
                   seven_manifest_sha256=frozen['seven-manifest.json'],
                   diagnostic_manifest_sha256=frozen['diagnostic-manifest.json'],
                   identity_sha256=frozen['IDENTITY.json'])
        write_json('RUN.json', run)
        for name, source in retained.items():
            write(name, source.encode())
        state()
        for index, stage in enumerate(diagnostic.stages):
            require(index < 4 and report['invocations'] < 4, 'four-process hard launch boundary')
            require(time.monotonic() - started_at < base.LAUNCH_SECONDS, 'new-stage deadline')
            require(all(parent in accepted for parent in stage.parents), 'fresh same-run parent required')
            state()
            output = stage.module_name.replace('.', '/') + '.olean'
            source = stage.module_name.replace('.', '/') + '.lean'
            require(output not in root.scan(allowed), 'fresh output required')
            current = _start(stage, run, frozen['RUN.json'], frozen['IDENTITY.json'],
                             {parent: accepted[parent] for parent in stage.parents}, TARGET if index == 3 else None)
            start_name = TARGET_STARTED if index == 3 else stage.name + '.started.json'
            write_json(start_name, current)
            process_result = None
            parent_process_verified = False
            if index < 3:
                current['process_started'] = False
            state()
            # Persisted started means attempted, not established process creation.
            report['invocations'] += 1
            report['invocation_count_exact'] = False
            if index < 3:
                current['process_started'] = None
                process_result = run_process(executable, root.path / source, root.path / output, root.path)
                _process(process_result, current['command'])
                parent_process_verified = True
                report['invocation_count_exact'] = True
                # An OSError receipt without a timeout/exit establishes no child.
                launched = process_result['returncode'] is not None or process_result['timed_out']
                if not launched:
                    require(process_result['incomplete'] and type(process_result.get('error_type')) is str,
                            'uncertain parent launch')
                    report['invocations'] -= 1
                current['process_started'] = bool(launched)
                out, err = process_result.get('stdout'), process_result.get('stderr')
                require(type(out) is str and type(err) is str, 'raw parent streams required')
                out, err = out.encode(), err.encode()
                require(len(out) + len(err) <= base.MAX_DIAGNOSTIC, 'parent raw budget')
                write(stage.name + '.stdout', out); write(stage.name + '.stderr', err)
                state((output,))
                _process(process_result, current['command'], successful=True)
                inventory = _inventory(out, err, stage)
                raw = snapshot.read(output)
                item = _module(stage, raw)
                freeze_optional(output)
                receipt = dict(current, status='parent_checked', started_sha256=frozen[start_name],
                               inventory=inventory, olean=item,
                               process={k: v for k, v in process_result.items() if k not in ('stdout', 'stderr')},
                               stdout_sha256=frozen[stage.name + '.stdout'], stderr_sha256=frozen[stage.name + '.stderr'])
                finish_name = stage.name + '.finished.json'
                write_json(finish_name, receipt)
                accepted[stage.module_name] = dict(item, receipt=finish_name, receipt_sha256=frozen[finish_name])
                report['stages'].append(dict(name=stage.name, status='parent_checked', receipt=finish_name,
                                             receipt_sha256=frozen[finish_name]))
                current = None
                state()
                continue
            process_result = (capture or collector.capture_result)(
                executable, root.path / source, root.path / output, root.path, safe_root=root,
                markers=diagnostic.manifest['markers'], target=TARGET,
                manifest_reference=dict(path='diagnostic-manifest.json', sha256=frozen['diagnostic-manifest.json']),
                started_reference=dict(path=TARGET_STARTED, sha256=frozen[TARGET_STARTED]))
            require(type(process_result) is dict and type(process_result.get('process_started')) is bool,
                    'capture launch receipt missing')
            if not process_result['process_started']:
                report['invocations'] -= 1
            report['invocation_count_exact'] = True
            allowed.update(CAPTURE_FILES)
            state((output,))
            for name in CAPTURE_FILES + (output,):
                freeze_optional(name)
            capture_stage = dict(name=stage.name, status=process_result.get('status'),
                                 process_started=process_result['process_started'], diagnostic_only=True,
                                 process=process_result)
            report['stages'].append(capture_stage)
            report['status'] = capture_stage['status']
            require(report['status'] in STATUSES, 'unknown collector status')
            verified = _verify_capture(snapshot, frozen, run, diagnostic, capture_stage)
            target_capture_verified = True
            if report['status'] == 'diagnostic_completed':
                inventory = _inventory(snapshot.read(CAPTURE_FILES[0]), snapshot.read(CAPTURE_FILES[1]), stage)
                item = _module(stage, snapshot.read(output))
                write_json(TARGET_INVENTORY, dict(name=stage.name, diagnostic_only=True,
                    started_sha256=frozen[TARGET_STARTED], source_sha256=stage.source_sha256,
                    inventory=inventory, untrusted_olean=item,
                    stdout_sha256=frozen[CAPTURE_FILES[0]], stderr_sha256=frozen[CAPTURE_FILES[1]]))
                capture_stage.update(inventory_receipt=TARGET_INVENTORY,
                                     inventory_receipt_sha256=frozen[TARGET_INVENTORY])
            capture_stage['markers_replay_complete'] = verified
            current = None
            state()
    except Exception as error:
        report.update(status='diagnostic_failed', error_type=type(error).__name__, error=str(error)[:512])
        if current is not None:
            report['failed_stage'] = current['name']
            if current['name'] != 'CertPart02':
                if isinstance(process_result, dict) and not parent_process_verified:
                    report['closure_failed'] = True
                finish = current['name'] + '.finished.json'
                receipt = dict(current, status='failed', started_sha256=frozen[current['name'] + '.started.json'],
                               error_type=type(error).__name__, error=str(error)[:512],
                               process={k: v for k, v in process_result.items() if k not in ('stdout', 'stderr')}
                               if type(process_result) is dict else None)
                for stream in ('stdout', 'stderr'):
                    name = current['name'] + '.' + stream
                    if name in frozen:
                        receipt[stream + '_sha256'] = frozen[name]
                if finish not in frozen:
                    try:
                        write_json(finish, receipt)
                        report['stages'].append(dict(name=current['name'], status='failed', receipt=finish,
                                                     receipt_sha256=frozen[finish]))
                    except Exception:
                        report['closure_failed'] = True
            else:
                target_rows = [row for row in report['stages'] if row['name'] == 'CertPart02']
                if target_rows:
                    target_rows[0].update(status='diagnostic_failed', markers_replay_complete=False,
                        validation_error=dict(error_type=type(error).__name__, error=str(error)[:512]))
                else:
                    report['target_outcome_uncertain'] = True
                if not target_capture_verified:
                    report['closure_failed'] = True
    finally:
        report['wall_seconds'] = time.monotonic() - started_at
        try:
            attempted = {row['name'] for row in report['stages']}
            if current is not None:
                attempted.add(current['name'])
            candidates = tuple(base.MODULE_PREFIX + '/' + name + '.olean' for name in attempted)
            if TARGET_STARTED in frozen:
                candidates += CAPTURE_FILES
            for name in candidates:
                freeze_optional(name)
            # Verify original frozen identities before creating containers. Never
            # replace their hashes with changed bytes to manufacture closure.
            state()
            require(set(PREPARATION + SOURCE_FILES) <= set(frozen), 'incomplete preparation')
            report['evidence_complete'] = not report.get('closure_failed', False)
            write_json('EVIDENCE.json', dict(protocol=PROTOCOL, schema=SCHEMA, sha256=dict(frozen)))
            report['evidence_sha256'] = frozen['EVIDENCE.json']
            files = {name: snapshot.read(name) for name in frozen if name not in SOURCE_FILES + MODULE_FILES}
            files['RESULT.json'] = _encoded(report)
            _evidence_budget(files)
            write('RESULT.json', files['RESULT.json'])
            state()
        except Exception as error:
            report.update(evidence_complete=False, finalization_error=type(error).__name__ + ': ' + str(error)[:256])
        finally:
            root.close()
    return report


def _verify_capture(snapshot, frozen, run, diagnostic, stage):
    """Verify collector framing/accounting; return whether markers are replayable."""
    process = stage.get('process')
    require(type(process) is dict and process.get('status') in STATUSES and
            type(process.get('process_started')) is bool, 'target process receipt differs')
    required_process = {'process_started', 'returncode', 'signal', 'timeout_seconds', 'platform', 'pty',
        'leader_reaped', 'group_kill_sent', 'drain_complete', 'kernel_core_syntax_connection_checked', 'authority',
        'metadata_written_bytes', 'metadata_remaining_bytes', 'raw_written_bytes', 'compact_receipt_reference',
        'started_reference', 'argv', 'cwd', 'search_path', 'sysroot', 'manifest_reference', 'status', 'error',
        'observed_bytes', 'output_truncated', 'marker_count', 'last_observed_marker', 'next_planned_marker_id',
        'cleanup_incomplete', 'elapsed_seconds', 'raw_files', 'files', 'terminal_record_persisted'}
    optional_process = {'pid', 'interrupted', 'group_cleanup_error', 'leader_cleanup_error'}
    require(required_process <= set(process) <= required_process | optional_process, 'target process schema differs')
    if 'interrupted' in process:
        require(type(process['interrupted']) is bool, 'interrupted flag type differs')
    for key in ('group_cleanup_error', 'leader_cleanup_error'):
        if key in process:
            require(type(process[key]) is str and bool(process[key]), 'cleanup error type differs')
    require(_same(stage.get('process_started'), process['process_started']), 'target launch flags differ')
    for key, value in _command(run['executable'], run['root'], diagnostic.stages[3]).items():
        require(_same(process.get(key), value), 'target command/environment differs')
    require(process.get('authority') == 'DENY_ALL' and
            process.get('kernel_core_syntax_connection_checked') is False, 'target denial flags differ')
    require(process.get('manifest_reference') == dict(path='diagnostic-manifest.json', sha256=frozen['diagnostic-manifest.json']) and
            process.get('started_reference') == dict(path=TARGET_STARTED, sha256=frozen[TARGET_STARTED]),
            'target manifest/started reference differs')
    require(_finite(process.get('elapsed_seconds')), 'target elapsed time invalid')
    for key in ('leader_reaped', 'group_kill_sent', 'drain_complete', 'cleanup_incomplete',
                'output_truncated', 'terminal_record_persisted'):
        require(type(process.get(key)) is bool, 'target process flag type differs')
    require(process.get('returncode') is None or type(process['returncode']) is int, 'target returncode type')
    require(process.get('signal') is None or type(process['signal']) is int, 'target signal type')
    require(process['cleanup_incomplete'] is (process['process_started'] and not (
            process['leader_reaped'] and process['drain_complete'] and 'group_cleanup_error' not in process)),
            'target cleanup flag differs from actual cleanup outcome')
    require('leader_cleanup_error' not in process or 'group_cleanup_error' in process,
            'leader cleanup error requires failed group cleanup')
    require(process.get('signal') == (-process['returncode'] if type(process['returncode']) is int and
            process['returncode'] < 0 else None), 'target signal differs')
    require(process.get('terminal_record_persisted') is True and CAPTURE_FILES[2] in frozen,
            'incomplete target terminal evidence')
    require(set(CAPTURE_FILES) <= set(frozen), 'incomplete target capture files')
    streams = {stream: snapshot.read(name) for stream, name in zip(('stdout', 'stderr'), CAPTURE_FILES[:2])}
    events_raw = snapshot.read(CAPTURE_FILES[2])
    require(events_raw and events_raw.endswith(b'\n'), 'incomplete capture event record')
    lines = events_raw.splitlines(keepends=True)
    records = [_json(line) for line in lines]
    starts = [row for row in records if row.get('kind') == 'start']
    terminals = [row for row in records if row.get('kind') == 'terminal']
    require(len(terminals) == 1 and records[-1] is terminals[0], 'unique final terminal required')
    terminal = terminals[0]
    require(set(terminal) == {'kind', 'process', 'accounting_before_terminal'}, 'terminal event schema')
    excluded = {'metadata_written_bytes', 'metadata_remaining_bytes', 'raw_written_bytes',
                'compact_receipt_reference', 'terminal_record_persisted', 'files'}
    require(_same(terminal['process'], {k: v for k, v in process.items() if k not in excluded}),
            'terminal and result process differ')
    raw_bytes = sum(map(len, streams.values()))
    require(_same(terminal['accounting_before_terminal'],
                  dict(raw_written_bytes=raw_bytes, metadata_written_bytes=len(events_raw) - len(lines[-1]))),
            'terminal prefix accounting differs')
    require(len(lines[-1]) <= collector.TERMINAL_RESERVE and
            len(events_raw) <= collector.INTERNAL_METADATA_LIMIT and
            len(events_raw) - len(lines[-1]) <= collector.INTERNAL_METADATA_LIMIT - collector.TERMINAL_RESERVE,
            'collector metadata budget differs')
    actual = {name: dict(path=name, bytes=len(snapshot.read(name)), sha256=frozen[name]) for name in CAPTURE_FILES}
    require(_same(process.get('files'), actual) and
            _same(process.get('raw_files'), {n: actual[n] for n in CAPTURE_FILES[:2]}) and
            _same(process.get('compact_receipt_reference'), actual[CAPTURE_FILES[2]]), 'capture file identities differ')
    require(type(process.get('raw_written_bytes')) is int and process['raw_written_bytes'] == raw_bytes and
            type(process.get('metadata_written_bytes')) is int and process['metadata_written_bytes'] == len(events_raw) and
            type(process.get('metadata_remaining_bytes')) is int and
            process['metadata_remaining_bytes'] == collector.METADATA_LIMIT - len(events_raw), 'capture final accounting differs')
    require(raw_bytes <= collector.RAW_LIMIT, 'capture raw budget')
    observed = process.get('observed_bytes')
    require(type(observed) is dict and set(observed) == {'stdout', 'stderr'} and
            all(type(value) is int and value >= len(streams[name]) for name, value in observed.items()) and
            sum(observed.values()) <= collector.RAW_LIMIT, 'capture observed byte counts differ')
    started = process['process_started']
    require(len(starts) == 1 if started else len(starts) <= 1, 'setup-start count differs')
    if starts:
        start = starts[0]
        require(records[0] is start and set(start) == {'kind', 'process', 'planned_markers', 'raw_limit',
                'metadata_limit', 'session'}, 'setup-start shape/order differs')
        require(type(start['planned_markers']) is int and start['planned_markers'] == 4 and
                type(start['raw_limit']) is int and start['raw_limit'] == collector.RAW_LIMIT and
                type(start['metadata_limit']) is int and start['metadata_limit'] == collector.METADATA_LIMIT and
                start['session'] == 'new session; no controlling terminal', 'setup-start budgets differ')
        initial = dict(process_started=False, returncode=None, signal=None, timeout_seconds=60,
                       platform=process.get('platform'), pty=process.get('pty'), leader_reaped=False,
                       group_kill_sent=False, drain_complete=False,
                       kernel_core_syntax_connection_checked=False, authority='DENY_ALL',
                       metadata_written_bytes=0, metadata_remaining_bytes=collector.METADATA_LIMIT,
                       raw_written_bytes=0, compact_receipt_reference=None,
                       started_reference=process['started_reference'], manifest_reference=process['manifest_reference'],
                       **{k: process[k] for k in ('argv', 'cwd', 'search_path', 'sysroot')})
        require(_same(start['process'], initial), 'setup-start process differs')
    if started:
        collector.require_platform(process.get('platform'))
        pty = process.get('pty')
        require(type(pty) is dict and set(pty) == {'before', 'after', 'isatty'} and pty['isatty'] is True and
                type(pty['before']) is list and type(pty['after']) is list and len(pty['after']) == 7 and
                type(pty['after'][1]) is int and pty['after'][1] == 0, 'target PTY receipt differs')
        require(type(process.get('pid')) is int and process['pid'] > 0, 'target PID receipt missing')
    else:
        require(not streams['stdout'] and not streams['stderr'] and observed == {'stdout': 0, 'stderr': 0} and
                process['returncode'] is None and process.get('pid') is None and
                process['leader_reaped'] is False and process['group_kill_sent'] is False and
                process['status'] == 'diagnostic_infrastructure_failed', 'nonstarted capture has process evidence')
        require(MODULE_FILES[3] not in frozen and TARGET_INVENTORY not in frozen, 'nonstarted target output forbidden')
    observer = collector.MarkerObserver(diagnostic.manifest['markers'], target=TARGET)
    positions = {'stdout': 0, 'stderr': 0}
    expected_markers, recorded_markers = [], []
    previous_time = 0
    for row in records:
        kind = row.get('kind')
        if kind == 'receive':
            require(started and set(row) == {'kind', 'stream', 'offset', 'bytes', 'received_seconds'}, 'receive schema')
            require(len(expected_markers) == len(recorded_markers), 'delayed marker event')
            stream, offset, size, elapsed = (row.get(k) for k in ('stream', 'offset', 'bytes', 'received_seconds'))
            require(stream in streams and type(offset) is int and type(size) is int and
                    0 < size <= collector.READ_CHUNK and offset == positions[stream] and
                    offset + size <= len(streams[stream]), 'receive holes/overlap/size differs')
            require(_finite(elapsed) and elapsed >= previous_time and elapsed <= process['elapsed_seconds'],
                    'receive timestamp differs')
            previous_time = elapsed
            expected_markers.extend(observer(stream, streams[stream][offset:offset + size], offset, elapsed))
            positions[stream] += size
        elif kind == 'marker':
            require(started and set(row) == {'kind', 'event', 'received_seconds'} and
                    len(recorded_markers) < len(expected_markers), 'unexpected marker event')
            require(_same(row['event'], expected_markers[len(recorded_markers)]) and
                    _same(row['received_seconds'], row['event']['received_seconds']), 'marker differs from raw receive')
            recorded_markers.append(row['event'])
        else:
            require(kind in ('start', 'terminal'), 'unknown capture event')
    require(positions == {name: len(raw) for name, raw in streams.items()} and
            _same(recorded_markers, expected_markers), 'capture raw replay incomplete')
    require(type(process.get('marker_count')) is int and process['marker_count'] == len(recorded_markers) and
            _same(process.get('last_observed_marker'), recorded_markers[-1] if recorded_markers else None) and
            process.get('next_planned_marker_id') ==
            (diagnostic.manifest['markers'][len(recorded_markers)]['id'] if len(recorded_markers) < 4 else None),
            'terminal marker frontier differs')
    status = process['status']
    clean = (process['leader_reaped'] is True and process['drain_complete'] is True and
             process['cleanup_incomplete'] is False and process['output_truncated'] is False and
             observed == {name: len(raw) for name, raw in streams.items()})
    if status == 'diagnostic_completed':
        require(started and clean and type(process['returncode']) is int and process['returncode'] == 0 and
                process.get('error') is None and len(recorded_markers) == 4, 'completed target prerequisites differ')
    elif status == 'diagnostic_timeout':
        require(started and process.get('error') == '60-second process deadline' and
                process['elapsed_seconds'] >= 60 and process['group_kill_sent'] is True and
                process['returncode'] is not None, 'timeout process semantics differ')
    elif status == 'diagnostic_output_limit':
        error = process.get('error')
        require(started and process['output_truncated'] is True and type(error) is str and
                ('raw read budget exhausted' in error or 'diagnostic metadata budget' in error),
                'output-limit reason/truncation differs')
        if 'raw read budget exhausted' in error:
            require(sum(observed.values()) == collector.RAW_LIMIT, 'raw limit was not reached')
        if 'diagnostic metadata budget' in error:
            require(sum(observed.values()) > raw_bytes, 'metadata limit must retain dropped-read accounting')
    else:
        require(type(process.get('error')) is str and process['error'] or
                (type(process['returncode']) is int and process['returncode'] != 0),
                'failed target lacks actual failure')
    return bool(started and clean and status in ('diagnostic_completed', 'diagnostic_timeout', 'diagnostic_failed'))


def _reconstruct(snapshot, frozen, identity):
    """Rebuild every source from pinned inputs and invert every retained candidate."""
    from tools import core_seven_certificate_diagnostic_sources as diagnostic_sources
    prepared = sources.build_inputs()
    base.validate_plan(prepared)
    require(snapshot.read('original-manifest.json') == prepared['manifest_json'].encode(),
            'retained original manifest differs from authenticated inputs')
    for stage in prepared['stages']:
        require(snapshot.read('original/' + stage.name + '.lean') == stage.source.encode(),
                'retained original source differs')
    expected = seven.build_sources(prepared)
    candidates = []
    for index, stage in enumerate(expected.stages):
        name = stage.module_name.replace('.', '/') + '.lean' if index < 3 else 'seven/' + stage.name + '.lean'
        source = snapshot.read(name).decode('utf-8', errors='strict')
        candidates.append(replace(stage, source=source, expected_theorems=frozenset(seven._qualified_prints(source))))
    proposal = seven.SevenCertificateSources(prepared['stages'], tuple(candidates),
                                             snapshot.read('seven-manifest.json').decode())
    # This performs complete independent inverse validation of all eleven files,
    # old byte-fact checks and all original transport/input/consumer checks.
    seven.validate_sources(prepared, proposal)
    marked = snapshot.read(base.MODULE_PREFIX + '/CertPart02.lean').decode('utf-8', errors='strict')
    stages = proposal.stages[:3] + (replace(proposal.stages[3], source=marked),)
    diagnostic = diagnostic_sources.DiagnosticSources(stages, snapshot.read('diagnostic-manifest.json').decode())
    diagnostic_sources.validate_diagnostic_sources(prepared, proposal, diagnostic)
    retained = diagnostic_sources.retained_sources(prepared, proposal, stages)
    require(set(retained) == set(SOURCE_FILES) and all(snapshot.read(name) == source.encode()
            for name, source in retained.items()), 'retained source paths differ')
    require(sum(len(snapshot.read(name)) for name in SOURCE_FILES) == 5615437 <= base.MAX_TOTAL_SOURCE,
            'actual retained source budget differs')
    seven.validate_retention(proposal, (marked,))
    return prepared, proposal, diagnostic


def _verify_parent(snapshot, frozen, stage, run, accepted, summary):
    name = stage.name
    start_name, finish_name = name + '.started.json', name + '.finished.json'
    require(start_name in frozen and finish_name in frozen, 'mandatory parent receipts missing')
    started, receipt = _json(snapshot.read(start_name)), _json(snapshot.read(finish_name))
    expected = _start(stage, run, frozen['RUN.json'], frozen['IDENTITY.json'],
                      {parent: accepted[parent] for parent in stage.parents})
    require(_same(started, expected), 'same-run parent started chain differs')
    require(summary.get('receipt') == finish_name and summary.get('receipt_sha256') == frozen[finish_name] and
            set(summary) == {'name', 'status', 'receipt', 'receipt_sha256'}, 'parent summary differs')
    require(receipt.get('started_sha256') == frozen[start_name] and
            all(_same(receipt.get(k), v) for k, v in expected.items()), 'parent terminal start binding differs')
    require(receipt.get('status') == summary['status'], 'parent terminal status differs')
    process = receipt.get('process')
    if process is not None:
        _process(process, expected['command'], successful=summary['status'] == 'parent_checked')
        require('stdout' not in process and 'stderr' not in process, 'duplicate parent raw streams forbidden')
        for stream in ('stdout', 'stderr'):
            log_name = name + '.' + stream
            if log_name in frozen:
                raw = snapshot.read(log_name)
                count_key, hash_key = stream + '_available_bytes', stream + '_available_sha256'
                if count_key in process:
                    require(type(process[count_key]) is int and process[count_key] >= len(raw), 'parent raw byte count differs')
                if hash_key in process:
                    require(type(process[hash_key]) is str and re.fullmatch('[0-9a-f]{64}', process[hash_key]),
                            'parent raw hash type differs')
                if summary['status'] == 'parent_checked':
                    require(count_key not in process or process[count_key] == len(raw), 'successful parent raw count differs')
                    require(hash_key not in process or process[hash_key] == base.digest(raw), 'successful parent raw hash differs')
        if 'retained_output_sha256' in process:
            require(process['retained_output_sha256'] == base.digest(snapshot.read(name + '.stdout') +
                    snapshot.read(name + '.stderr')), 'parent retained diagnostic hash differs')
    launched = receipt.get('process_started')
    require(launched is None or type(launched) is bool, 'parent launch type differs')
    if process is not None:
        require(launched is (process['returncode'] is not None or process['timed_out']),
                'parent launch flag differs from process outcome')
    else:
        require(launched is not True, 'missing parent outcome cannot prove launch')
    for stream in ('stdout', 'stderr'):
        path = name + '.' + stream
        require((path in frozen) == (stream + '_sha256' in receipt), 'parent log binding missing')
        if path in frozen:
            require(receipt[stream + '_sha256'] == frozen[path], 'parent log hash differs')
    if summary['status'] == 'failed':
        require('inventory' not in receipt and 'olean' not in receipt and type(receipt.get('error')) is str and
                type(receipt.get('error_type')) is str, 'failed parent cannot have admission')
        optional = {'process_started', 'stdout_sha256', 'stderr_sha256'}
        require(set(receipt) <= set(expected) | optional | {'status', 'started_sha256', 'error', 'error_type', 'process'},
                'failed parent receipt fields differ')
        return launched
    require(summary['status'] == 'parent_checked' and launched is True and process is not None,
            'successful parent launch missing')
    out, err = snapshot.read(name + '.stdout'), snapshot.read(name + '.stderr')
    item = _module(stage, snapshot.read(stage.module_name.replace('.', '/') + '.olean'))
    expected_receipt = dict(expected, process_started=True, status='parent_checked',
        started_sha256=frozen[start_name], inventory=_inventory(out, err, stage), olean=item,
        process=process, stdout_sha256=frozen[name + '.stdout'], stderr_sha256=frozen[name + '.stderr'])
    require(_same(receipt, expected_receipt), 'successful parent receipt/inventory differs')
    accepted[stage.module_name] = dict(item, receipt=finish_name, receipt_sha256=frozen[finish_name])
    return True


def verify_evidence(directory, *, source_reader=None, support_reader=None):
    """Independently replay a complete container without any Lean invocation.

    Reader injection is solely for fake-child tests. Production uses the exact
    inherited source identity and pinned binary/support readers.
    """
    from tools.qualify_hia_selected_formal import _support_identity
    production = source_reader is None
    source_reader = source_reader or source_identity
    support_reader = support_reader or _support_identity
    path = Path(directory).absolute()
    for parent in (path, *path.parents):
        require(not parent.is_symlink(), 'diagnostic ancestor symlink')
    root = object.__new__(base.SafeRoot)
    root.path = path
    root.fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    root.identity = os.fstat(root.fd)
    snapshot = _Snapshot(root)
    try:
        actual = root.scan(FIXED_FILES)
        require('RESULT.json' in actual and 'EVIDENCE.json' in actual, 'incomplete diagnostic containers')
        raw_result, raw_evidence = snapshot.read('RESULT.json'), snapshot.read('EVIDENCE.json')
        result, evidence = _json(raw_result), _json(raw_evidence)
        required_result = {'schema', 'protocol', 'status', 'invocation_limit', 'invocations',
                           'invocation_count_exact', 'stages', 'not_scheduled', 'evidence_complete',
                           'wall_seconds', 'evidence_sha256'} | set(_denials())
        require(required_result <= set(result) <= required_result | {'error_type', 'error', 'failed_stage',
                'closure_failed', 'target_outcome_uncertain'}, 'result schema differs')
        require(result.get('schema') == SCHEMA and result.get('protocol') == PROTOCOL and
                result.get('status') in STATUSES and result.get('evidence_complete') is True and
                all(_same(result.get(k), v) for k, v in _denials().items()), 'result status/schema/denials differ')
        require(type(result['invocations']) is int and 0 <= result['invocations'] <= 4 and
                type(result['invocation_limit']) is int and result['invocation_limit'] == 4 and
                type(result['invocation_count_exact']) is bool and _finite(result['wall_seconds']) and
                result['not_scheduled'] == list(NOT_SCHEDULED), 'invocation/schedule bounds differ')
        require(set(evidence) == {'schema', 'protocol', 'sha256'} and evidence['schema'] == SCHEMA and
                evidence['protocol'] == PROTOCOL and base.digest(raw_evidence) == result['evidence_sha256'],
                'evidence container binding differs')
        frozen = evidence['sha256']
        _hash_map(frozen)
        require(set(PREPARATION + SOURCE_FILES) <= set(frozen) <= FIXED_FILES - {'EVIDENCE.json', 'RESULT.json'} and
                set(actual) == set(frozen) | {'EVIDENCE.json', 'RESULT.json'}, 'fixed evidence file set differs')
        require(sum(actual[name] for name in MODULE_FILES if name in actual) <= base.MAX_TOTAL_MODULE,
                'aggregate module budget')
        all_bytes = {'RESULT.json': raw_result, 'EVIDENCE.json': raw_evidence}
        for name, expected in frozen.items():
            raw = snapshot.read(name)
            require(base.digest(raw) == expected, 'frozen evidence changed: ' + name)
            if name not in SOURCE_FILES + MODULE_FILES:
                all_bytes[name] = raw
            if name.endswith('.json'):
                _json(raw, newline=name not in ('original-manifest.json', 'seven-manifest.json', 'diagnostic-manifest.json'))
        _evidence_budget(all_bytes)
        identity, run = _json(snapshot.read('IDENTITY.json')), _json(snapshot.read('RUN.json'))
        require(set(identity) == {'source_sha256', 'support_sha256', 'lean_binary_sha256'}, 'identity fields differ')
        _hash_map(identity['source_sha256']); _hash_map(identity['support_sha256'])
        require(_same(source_reader(), identity['source_sha256']), 'source identity key set or bytes changed')
        require(set(run) == {'protocol', 'schema', 'schedule', 'invocation_limit', 'run_id', 'root', 'executable',
                'git_baseline', 'source_baseline_sha256', 'original_manifest_sha256', 'seven_manifest_sha256',
                'diagnostic_manifest_sha256', 'identity_sha256'}, 'RUN fields differ')
        require(run['protocol'] == PROTOCOL and run['schema'] == SCHEMA and run['schedule'] == list(DIAGNOSTIC_NAMES) and
                type(run['invocation_limit']) is int and run['invocation_limit'] == 4 and
                type(run['run_id']) is str and re.fullmatch('[0-9a-f]{32}', run['run_id']) and
                type(run['root']) is str and str(Path(run['root']).absolute()) == run['root'] and
                type(run['executable']) is str and str(Path(run['executable']).absolute()) == run['executable'] and
                _same(run['git_baseline'], _git_baseline()) and
                run['source_baseline_sha256'] == base.digest(_encoded(identity['source_sha256'])), 'RUN source/run binding differs')
        for key, filename in (('original_manifest_sha256', 'original-manifest.json'),
                              ('seven_manifest_sha256', 'seven-manifest.json'),
                              ('diagnostic_manifest_sha256', 'diagnostic-manifest.json'),
                              ('identity_sha256', 'IDENTITY.json')):
            require(run[key] == frozen[filename], 'RUN manifest chain differs')
        executable = Path(run['executable'])
        require(set(identity['source_sha256']) == set(source_identity()), 'exact source identity paths differ')
        if production:
            pin = json.loads((ROOT / 'formal/toolchain-lock.json').read_text())['lean_binary_sha256']
            require(identity['lean_binary_sha256'] == pin, 'unlocked Lean binary identity')
        require(base.digest(executable.read_bytes()) == identity['lean_binary_sha256'] and
                _same(support_reader(executable), identity['support_sha256']), 'binary/support identity changed')
        external = _ExternalSnapshot(executable, identity['source_sha256'], identity['support_sha256'])
        sysroot = executable.parent.parent / 'lib/lean'
        require(not os.path.lexists(sysroot / base.MODULE_PREFIX) and
                not os.path.lexists(sysroot / (base.MODULE_PREFIX + '.olean')), 'support-prefix shadowing')
        prepared, proposal, diagnostic = _reconstruct(snapshot, frozen, identity)
        base._support_imports(prepared, identity['support_sha256'])
        summaries = result['stages']
        require(type(summaries) is list and len(summaries) <= 4 and all(type(row) is dict for row in summaries) and
                [row.get('name') for row in summaries] == list(DIAGNOSTIC_NAMES[:len(summaries)]), 'stage history differs')
        accepted = {}
        permitted = set(PREPARATION + SOURCE_FILES)
        known_launches, failed_parent = 0, False
        for index, summary in enumerate(summaries[:3]):
            require(not failed_parent, 'later stage after failed parent')
            stage = diagnostic.stages[index]
            launched = _verify_parent(snapshot, frozen, stage, run, accepted, summary)
            known_launches += launched is True
            names = {stage.name + suffix for suffix in ('.started.json', '.stdout', '.stderr', '.finished.json')}
            names.add(MODULE_FILES[index])
            permitted.update(names)
            if summary['status'] == 'failed':
                failed_parent = True
                require(index == len(summaries) - 1 and result['status'] in ('diagnostic_failed', 'diagnostic_infrastructure_failed') and
                        result.get('failed_stage') == stage.name, 'failed parent stage/result differs')
                if launched is None:
                    require(result['invocation_count_exact'] is False, 'unknown launch count claimed exact')
            else:
                require(names <= set(frozen), 'successful parent files missing')
        validated_markers = False
        target_present = TARGET_STARTED in frozen
        if target_present:
            require(not failed_parent and len(accepted) == 3, 'target started before complete parent prefix')
            target = diagnostic.stages[3]
            expected_start = _start(target, run, frozen['RUN.json'], frozen['IDENTITY.json'],
                                    {parent: accepted[parent] for parent in target.parents}, TARGET)
            require(_same(_json(snapshot.read(TARGET_STARTED)), expected_start), 'target same-run parent/start binding differs')
            permitted.update((TARGET_STARTED, TARGET_INVENTORY, *CAPTURE_FILES, MODULE_FILES[3]))
            require(len(summaries) == 4, 'target started without terminal stage history')
            summary = summaries[3]
            required_summary = {'name', 'status', 'process_started', 'diagnostic_only', 'process', 'markers_replay_complete'}
            extra = {'inventory_receipt', 'inventory_receipt_sha256'} if summary.get('status') == 'diagnostic_completed' else set()
            validation_error = summary.get('validation_error')
            if validation_error is not None:
                extra.add('validation_error')
            require(set(summary) == required_summary | extra and summary['diagnostic_only'] is True and
                    summary['status'] == result['status'] and type(summary['markers_replay_complete']) is bool,
                    'target stage/result differs or target admission attempted')
            validated_markers = _verify_capture(snapshot, frozen, run, diagnostic, summary)
            if validation_error is not None:
                require(summary['status'] == 'diagnostic_failed' and summary['process']['status'] == 'diagnostic_completed' and
                        TARGET_INVENTORY not in frozen, 'invalid target validation-failure classification')
                actual_error = None
                try:
                    _inventory(snapshot.read(CAPTURE_FILES[0]), snapshot.read(CAPTURE_FILES[1]), target)
                    _module(target, snapshot.read(MODULE_FILES[3]))
                except (ValueError, FileNotFoundError, UnicodeError) as error:
                    actual_error = dict(error_type=type(error).__name__, error=str(error)[:512])
                require(actual_error is not None and _same(validation_error, actual_error),
                        'target validation failure not reproduced')
                validated_markers = False
            else:
                require(summary['status'] == summary['process']['status'], 'target process status differs')
            require(summary['markers_replay_complete'] is validated_markers, 'claimed marker replay differs')
            known_launches += summary['process_started'] is True
            require(result['invocation_count_exact'] is True, 'terminal target count uncertain')
            if summary['status'] == 'diagnostic_completed':
                require(validated_markers and summary['inventory_receipt'] == TARGET_INVENTORY and
                        summary['inventory_receipt_sha256'] == frozen.get(TARGET_INVENTORY), 'target inventory receipt missing')
                inventory = _inventory(snapshot.read(CAPTURE_FILES[0]), snapshot.read(CAPTURE_FILES[1]), target)
                expected_inventory = dict(name=target.name, diagnostic_only=True, started_sha256=frozen[TARGET_STARTED],
                    source_sha256=target.source_sha256, inventory=inventory,
                    untrusted_olean=_module(target, snapshot.read(MODULE_FILES[3])),
                    stdout_sha256=frozen[CAPTURE_FILES[0]], stderr_sha256=frozen[CAPTURE_FILES[1]])
                require(_same(_json(snapshot.read(TARGET_INVENTORY)), expected_inventory), 'target diagnostic inventory differs')
            else:
                require(TARGET_INVENTORY not in frozen, 'unsuccessful target inventory forbidden')
        else:
            require(len(summaries) <= 3 and result['status'] in ('diagnostic_failed', 'diagnostic_infrastructure_failed'),
                    'target terminal status without target start')
            require(TARGET_INVENTORY not in frozen and not set(CAPTURE_FILES) & set(frozen) and
                    MODULE_FILES[3] not in frozen, 'target evidence without target start')
        require(set(frozen) <= permitted, 'evidence extends past the actual stage prefix')
        if result['invocation_count_exact']:
            require(result['invocations'] == known_launches, 'exact invocation count differs')
        else:
            require(result['status'] in ('diagnostic_failed', 'diagnostic_infrastructure_failed') and
                    known_launches <= result['invocations'] <= min(4, known_launches + 1), 'uncertain launch bound differs')
        if result['status'] in ('diagnostic_completed', 'diagnostic_timeout', 'diagnostic_output_limit'):
            require(target_present and known_launches == 4 and len(accepted) == 3, 'four-launch terminal prerequisites missing')
        # Failure bytes remain durable and hash-checked. Only complete replay may
        # display target bytes that could be mistaken for marker observations.
        displayed = ['RUN.json', 'IDENTITY.json', 'seven-manifest.json', 'diagnostic-manifest.json', 'EVIDENCE.json']
        displayed.extend(name for name in PARENT_FILES if name in all_bytes)
        displayed.append(TARGET_STARTED) if target_present else None
        if validated_markers:
            displayed.extend(CAPTURE_FILES)
        displayed.append('RESULT.json')
        _evidence_budget(all_bytes, displayed)
        # No trusted output precedes this full final reread and source/support check.
        require(set(root.scan(FIXED_FILES)) == set(actual), 'file set changed during replay')
        for name, expected in frozen.items():
            require(base.digest(snapshot.read(name)) == expected, 'frozen evidence changed during replay')
        require(snapshot.read('RESULT.json') == raw_result and snapshot.read('EVIDENCE.json') == raw_evidence,
                'container changed during replay')
        require(_same(source_reader(), identity['source_sha256']) and
                _same(support_reader(executable), identity['support_sha256']) and
                base.digest(executable.read_bytes()) == identity['lean_binary_sha256'], 'identity changed during replay')
        snapshot.check_directories()
        external.check()
        return dict(result=result, validated_parent_count=len(accepted), validated_markers=validated_markers,
                    display=tuple((name, all_bytes[name]) for name in displayed))
    finally:
        root.close()


def print_events(directory):
    """Print only after complete independent validation and the final reread."""
    import sys
    if not Path(directory).exists() or not (Path(directory) / 'RESULT.json').exists():
        print('Incomplete diagnostic output: final RESULT.json is missing; no validated marker or proof evidence.')
        return False
    verified = verify_evidence(directory)
    for name, raw in verified['display']:
        sys.stdout.buffer.write(name.encode() + b'\n' + raw + b'\n')
    sys.stdout.buffer.flush()
    return True


def diagnose(lean, output_directory):
    from tools import core_seven_certificate_diagnostic_sources as diagnostic_sources
    from tools.qualify_hia_selected_formal import _support_identity
    executable = Path(lean).resolve(strict=True)
    pinned = json.loads((ROOT / 'formal/toolchain-lock.json').read_text())['lean_binary_sha256']
    require(base.digest(executable.read_bytes()) == pinned, 'pinned Lean binary required')
    identity, support = source_identity(), _support_identity(executable)
    preparation_snapshot = _ExternalSnapshot(executable, identity, support)
    prepared = sources.build_inputs()
    proposal = seven.build_sources(prepared)
    diagnostic = diagnostic_sources.build_diagnostic_sources(prepared, proposal)
    require(source_identity() == identity and _support_identity(executable) == support and
            base.digest(executable.read_bytes()) == pinned, 'preparation identity changed')
    preparation_snapshot.check()
    return execute_diagnostic(executable, output_directory, prepared, proposal, diagnostic, identity, support,
                              source_identity, _support_identity, pinned)


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lean', type=Path)
    parser.add_argument('--output-directory', type=Path, required=True)
    parser.add_argument('--print-diagnostics', action='store_true')
    args = parser.parse_args(argv)
    if args.print_diagnostics:
        print_events(args.output_directory)
    else:
        require(args.lean is not None, '--lean required')
        diagnose(args.lean, args.output_directory)
    # Even successful replay is diagnostic-only and cannot become acceptance.
    return 1


if __name__ == '__main__':
    raise SystemExit(main())
