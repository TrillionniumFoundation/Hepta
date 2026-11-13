"""Author new diagnostic custody sources; never execute a control or payload."""
from pathlib import Path
from hashlib import sha256, sha1
import ast
import difflib
import json

ROOT = Path(__file__).resolve().parents[1]
OLD = ROOT / 'reference/remote-r1'
OUT = ROOT / 'candidate'
OLD_PREFIX = 'experiments/hia_v92_failed_ci_20261113/multipart-r1'
PREFIX = 'experiments/hia_v92_failed_ci_20261113/diagnostics-only-r2'
MISSING = [
    'hia-core-unpack-evidence/callers/integer-report.json',
    'hia-core-unpack-evidence/callers/numeric/numeric-report.json',
    'hia-core-unpack-evidence/callers/numeric/callers/report.json',
    'hia-core-unpack-evidence/callers/numeric/callers/progress.receipt.json',
    'hia-core-unpack-evidence/callers/numeric/callers/core-callers/report.json',
]
EXPECTED = {'members': 22385, 'expanded_bytes': 1987786640,
            'selected_count': 460, 'selected_bytes': 3012789,
            'missing_expected': MISSING, 'metadata_files': 3}


def functions(text):
    lines = text.splitlines(keepends=True)
    return {n.name: ''.join(lines[n.lineno - 1:n.end_lineno])
            for n in ast.parse(text).body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}


def replace_function(text, name, replacement):
    old = functions(text)[name]
    assert text.count(old) == 1
    return text.replace(old, replacement.rstrip())


def remove_function(text, name):
    return replace_function(text, name, '')


RELOCATE = r'''
def relocate_diagnostic(root, public, name, expected):
    """Relocate one fixed diagnostic leaf after bound ECHILD, preserving bytes.

    The two namespaces are constructed here, not inferred from a generic
    slice name. All directory components below the two admitted private roots
    remain held, and all body reads use those descriptors. Failure never
    changes a file's permissions or fabricates a successful custody pin.
    """
    root, public = Path(root), Path(public)
    require(root.is_absolute() and public.is_absolute() and root.parent == public.parent
            and root != public and type(name) is str
            and (re.fullmatch(r'member-[0-9]{5}\.bin', name) is not None
                 or name in ('INDEX.json', 'DIRECTORY.jsonl', 'FULL-INVENTORY.jsonl')),
            'only a fixed diagnostic original may be relocated')
    source = root / 'diagnostics' / name
    target = public / 'small/originals' / name
    require(type(expected) is dict and expected.get('path') == str(source)
            and type(expected.get('bytes')) is int and 0 <= expected['bytes'] <= 64 << 20
            and type(expected.get('sha256')) is str
            and re.fullmatch('[0-9a-f]{64}', expected['sha256']) is not None
            and type(expected.get('identity')) is list and len(expected['identity']) == 9,
            'fixed diagnostic original record differs')
    held = []
    def directory(path, parent=None, component=None):
        fd = os.open(path if parent is None else component,
                     os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                     dir_fd=parent)
        held.append((fd, path, parent, component, os.fstat(fd)))
        entry = held[-1][4]
        require(stat.S_ISDIR(entry.st_mode) and entry.st_uid == os.geteuid()
                and not stat.S_IMODE(entry.st_mode) & 0o077
                and entry.st_dev == expected['identity'][0],
                'diagnostic parents must be owned private directories on one device')
        return fd
    def stable_parents():
        for fd, path, parent, component, initial in held:
            observed = os.fstat(fd)
            named = path.lstat() if parent is None else os.stat(component, dir_fd=parent, follow_symlinks=False)
            require(all(getattr(observed, key) == getattr(named, key) == getattr(initial, key)
                        for key in ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid')),
                    'diagnostic parent identity changed')
    def record_at(parent, path):
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
        with os.fdopen(fd, 'rb') as stream:
            before = os.fstat(stream.fileno())
            require(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
                    and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o400
                    and before.st_size == expected['bytes'], 'sealed diagnostic original identity differs')
            count, digest = 0, sha256()
            while True:
                block = stream.read(CHUNK)
                if not block:
                    break
                count += len(block)
                require(count <= expected['bytes'], 'diagnostic original grew during full read')
                digest.update(block)
            require(count == expected['bytes'] and digest.hexdigest() == expected['sha256']
                    and identity(before) == identity(os.fstat(stream.fileno()))
                    and identity(before) == identity(os.stat(name, dir_fd=parent, follow_symlinks=False)),
                    'diagnostic original changed during full read')
        return {'path': str(path), 'bytes': count, 'sha256': digest.hexdigest(),
                'identity': list(identity(before))}
    try:
        rfd = directory(root)
        pfd = directory(public)
        sfd = directory(root / 'diagnostics', rfd, 'diagnostics')
        mfd = directory(public / 'small', pfd, 'small')
        tfd = directory(public / 'small/originals', mfd, 'originals')
        stable_parents()
        original = record_at(sfd, source)
        require(original == expected, 'diagnostic original changed before relocation')
        before = os.stat(name, dir_fd=sfd, follow_symlinks=False)
        os.link(name, name, src_dir_fd=sfd, dst_dir_fd=tfd, follow_symlinks=False)
        left = os.stat(name, dir_fd=sfd, follow_symlinks=False)
        right = os.stat(name, dir_fd=tfd, follow_symlinks=False)
        stable = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_size', 'st_mtime_ns')
        require(all(getattr(left, key) == getattr(right, key) == getattr(before, key) for key in stable)
                and left.st_nlink == right.st_nlink == 2,
                'diagnostic link boundary changed; retain both names as HOLD')
        os.unlink(name, dir_fd=sfd)
        os.fsync(sfd)
        os.fsync(tfd)
        try:
            os.stat(name, dir_fd=sfd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise Refusal('private diagnostic name remains after relocation')
        retained = record_at(tfd, target)
        require(all(retained['identity'][i] == expected['identity'][i] for i in (0, 1, 2, 3, 4, 6, 7)),
                'relocated diagnostic original identity differs')
        stable_parents()
        return retained
    finally:
        for fd, *_ in reversed(held):
            os.close(fd)
'''


FINALIZE = r'''
def finalize(args):
    require(TOKEN_VARIABLE not in os.environ and 'GITHUB_TOKEN' not in os.environ
            and 'GH_TOKEN' not in os.environ, 'read token entered public finalization')
    _, policy, _, root, public, context = policy_and_context(args)
    pin = fixed_policy(policy)
    require(not os.path.lexists(public), 'public custody already exists; do not replay')
    public.mkdir(mode=0o700)
    for name in ('small', 'small/originals', 'small/controls'):
        (public / name).mkdir(mode=0o700)
    result = {'schema': 'hia.actions.v92-ci-diagnostics-only-final.v2',
              'status': 'DIAGNOSTIC_CUSTODY_HOLD', 'context': context, 'artifact': pin,
              'errors': [], 'missing_originals': [], 'typed_download_observations': [],
              'new_product_execution': False, 'old_runs_replayed': False,
              'historical_results_reclassified': False,
              'old_local_R4_owner_status': 'UNKNOWN_NOT_RECLASSIFIED',
              'old_remote_recovery_status': 'HOLD_NOT_RECLASSIFIED',
              'original_ZIP_member_inspection_started': None,
              'full_5400_retained_suite_executed': False, 'artifact_uploads_not_yet_observed': True,
              'original_full_ZIP_retained_private': False,
              'diagnostic_originals_relocated_not_duplicated': True,
              'partition_files_created': False, 'original_ZIP_bytes_or_compression_changed': False}
    setup = report = original = None
    closed = natural = accepted = storage_observed = diagnostics_complete = False
    captures_complete = True
    def error(stage, exc):
        result['errors'].append({'stage': stage, 'type': type(exc).__name__,
                                'safe_refusal': str(exc) if type(exc) is Refusal else None})
    try:
        setup, setup_record = document(root / 'setup.json')
        check_setup(setup, context, policy, root)
        request = read(root / 'guard/request.json', 262144, setup['guardian_config_sha256'])
        expected_request = {'schema': 'hia-external-guardian-request.v1', 'controller_seconds': 900,
                            'command': setup['command'], 'cwd': str(root),
                            'source_identities': setup['source_identities']}
        require(json.loads(request) == expected_request, 'actual original guardian request differs')
        guardian, guardian_record = document(root / 'guard/guardian.json')
        closed = closed_guardian(guardian, setup, policy, root)
        require(closed, 'this guardian did not prove closed ECHILD')
        result.update(setup=setup_record, guardian=guardian_record, closed_echild=True)
        try:
            natural_guardian(guardian, setup, policy, root)
            natural = True
        except BaseException as exc:
            error('NATURAL_GUARDIAN', exc)
        try:
            report, report_record = document(root / 'recovery-terminal.json')
            result['worker'] = report_record
            original = accept_worker(report, policy, setup, root)
            result['original_zip'] = original
            accepted = True
            result['original_full_ZIP_retained_private'] = True
        except BaseException as exc:
            error('ORIGINAL_ZIP_AND_WORKER', exc)
    except BaseException as exc:
        error('CLOSED_BOUNDARY', exc)

    # No child-body read, directory enumeration, partial capture or storage walk
    # occurs before this operation's bound raw request and ECHILD are confirmed.
    if closed:
        original_name = 'artifact-%d.zip' % pin['id']
        for path in (root / 'original' / original_name,
                     root / 'original' / (original_name + '.partial')):
            try:
                result['typed_download_observations'].append(typed_observation(path))
            except BaseException as exc:
                error('DOWNLOAD_TYPE', exc)
        try:
            diagnostic_capture = retain_diagnostics(root, public, policy, report)
            result['diagnostic_capture'] = diagnostic_capture
            diagnostics_complete = diagnostic_capture['complete']
            result['original_ZIP_member_inspection_started'] = None if report is None else report.get('original_ZIP_member_inspection_started')
            result['complete_original_ZIP_member_read_verified'] = diagnostics_complete
            require(diagnostics_complete, 'fixed diagnostic originals are incomplete; preserve HOLD')
        except BaseException as exc:
            error('STEP42_DIAGNOSTIC_CAPTURE', exc)
        fixed = ['context.json', 'setup.json', 'guard/request.json', 'guard/guardian.json',
                 'guard/child.stdout.log', 'guard/child.stderr.log',
                 'supervisor.stdout.log', 'supervisor.stderr.log',
                 'recovery.json', 'recovery-terminal.json',
                 'api/artifact-%d.metadata.original.json' % pin['id']]
        small_control_bytes = 0
        result['small_controls'] = []
        for name in fixed:
            try:
                source = root / name
                if not os.path.lexists(source):
                    result['missing_originals'].append(name)
                    captures_complete = False
                    continue
                actual = file_record(source, 8 << 20)
                small_control_bytes += actual['bytes']
                require(small_control_bytes <= MAX_DIAGNOSTIC_BYTES, 'whole small control bound exceeded')
                retained = copy_original(source, public / 'small/controls' / name.replace('/', '--'), actual)
                result['small_controls'].append({'name': name, 'original': actual, 'retained': retained})
            except BaseException as exc:
                captures_complete = False
                error('SMALL_CONTROL_' + name, exc)
        result['small_control_bytes'] = small_control_bytes
        try:
            result['source_inputs_final'] = final_input_records(setup, context)
            result['source_inputs_preserved'] = True
        except BaseException as exc:
            error('FINAL_SOURCE_INPUTS', exc)
        if original is not None:
            try:
                require(file_record(Path(original['path']), pin['bytes']) == original,
                        'original ZIP changed during diagnostic custody')
                result['original_zip_final_readback'] = original
            except BaseException as exc:
                accepted = False
                error('ORIGINAL_ZIP_FINAL_READBACK', exc)
        try:
            result['closed_storage_observation'] = closed_storage_observation(root, public, policy)
            storage_observed = True
        except BaseException as exc:
            error('CLOSED_STORAGE_BUDGET', exc)

    complete = (closed and natural and accepted and captures_complete and storage_observed and diagnostics_complete
                and result.get('original_full_ZIP_retained_private') is True
                and result.get('source_inputs_preserved') is True
                and not result['errors'] and not result['missing_originals'])
    result['complete_local_diagnostic_readback'] = complete
    if complete:
        result['status'] = 'ALL_AVAILABLE_STEP42_ORIGINALS_VERIFIED_NOT_QUALIFICATION'
    final_raw = wire(result)
    require(len(final_raw) <= 2 << 20, 'whole FINAL document exceeds fixed bound')
    create(public / 'small/FINAL.json', final_raw)
    require(read(public / 'small/FINAL.json', 2 << 20) == final_raw,
            'small FINAL complete readback differs')
    small_records = []
    for path in sorted((public / 'small').rglob('*')):
        entry = path.lstat()
        require(not stat.S_ISLNK(entry.st_mode), 'small public symlink refused')
        if stat.S_ISDIR(entry.st_mode):
            require(entry.st_uid == os.geteuid(), 'small public directory ownership differs')
        else:
            small_records.append(file_record(path, 64 << 20))
    require(len(small_records) <= 1040 and sum(x['bytes'] for x in small_records) <= 224 << 20,
            'small complete public artifact exceeds its fixed bound')
    for folder in ('originals', 'controls'):
        sync_dir(public / 'small' / folder)
    sync_dir(public / 'small')
    sync_dir(public)
    print(json.dumps({'status': result['status'], 'partition_files_created': False,
                      'complete_local_diagnostic_readback': complete,
                      'original_bytes': pin['bytes'], 'original_sha256': pin['sha256'],
                      'qualification_executed': False}), flush=True)
    return 0 if complete else 1
'''


def derive():
    controller = (OLD / 'controller.py').read_text()
    worker = (OLD / 'worker.py').read_text()
    common_old = functions(controller)['fixed_policy']
    assert common_old == functions(worker)['fixed_policy']
    fixed = common_old.replace('v92-ci-failed-original-parts-policy.v1', 'v92-ci-diagnostics-only-policy.v2')
    fixed = fixed.replace("'fixed five custody controls differ'", "'fixed six custody controls differ'")
    fixed = fixed.replace("policy.get('slice_publication') == 'RELOCATE_SAME_FILESYSTEM_AFTER_CLOSED_ECHILD'",
                          "policy.get('slice_publication') == 'NONE_DIAGNOSTICS_ONLY'\n            and policy.get('diagnostic_publication') == 'RELOCATE_SAME_FILESYSTEM_AFTER_CLOSED_ECHILD'")
    fixed = fixed.replace("    expected_parts(policy)\n", "    require(type(pin.get('bytes')) is int and 0 < pin['bytes'] <= 3 << 30\n            and policy.get('parts') == [] and policy.get('partition_files_created') is False,\n            'this request permits no partition production or publication')\n    require(policy.get('expected_diagnostics') == " + repr(EXPECTED) + ",\n            'fixed full original inventory or available diagnostic population differs')\n")
    controller = replace_function(controller, 'fixed_policy', fixed)
    worker = replace_function(worker, 'fixed_policy', fixed)
    for name in ('expected_parts', 'concat_parts', 'copy_unverified_range'):
        controller = remove_function(controller, name)
    controller = replace_function(controller, 'relocate_slice', RELOCATE)
    for name in ('expected_parts', 'split_original'):
        worker = remove_function(worker, name)
    controller = controller.replace('Deliver three exact failed v92 CI ZIP ranges and fixed step42 originals;',
                                    'Deliver all available fixed step42 originals from one failed v92 CI ZIP;')
    for suffix in ('policy', 'context', 'setup'):
        controller = controller.replace('v92-ci-failed-original-parts-' + suffix + '.v1',
                                        'v92-ci-diagnostics-only-' + suffix + '.v2')
    controller = controller.replace("('control', 'guard', 'original', 'parts', 'api')", "('control', 'guard', 'original', 'api')")
    accept = functions(controller)['accept_worker']
    accept = accept.replace('    parts = expected_parts(policy)\n', '')
    accept = accept.replace('v92-ci-failed-original-parts-worker.v1', 'v92-ci-diagnostics-only-worker.v2')
    accept = accept.replace('SEALED_PARTS_PENDING_NATURAL_GUARDIAN', 'SEALED_DIAGNOSTICS_PENDING_NATURAL_GUARDIAN')
    accept = accept.replace("and report.get('proxy_URLs_or_credentials_recorded') is False,", "and report.get('proxy_URLs_or_credentials_recorded') is False\n            and report.get('partition_files_created') is False and 'partition' not in report,")
    accept = accept.replace('worker complete multipart result or scope differs', 'worker complete diagnostic result or scope differs')
    accept = accept[:accept.index("    partition = report.get('partition', {})")] + '    return original\n'
    controller = replace_function(controller, 'accept_worker', accept)
    retention = functions(controller)['retain_diagnostics']
    retention = retention.replace('actual = relocate_slice(folder / name, destination / name, record)',
                                  'actual = relocate_diagnostic(root, public, name, record)')
    needle = "        require(set(os.listdir(folder)) == set(expected_records),"
    addition = "        observed_population = {'members': len(inventory), 'expanded_bytes': value['expanded_bytes'],\n            'selected_count': len(selected), 'selected_bytes': value['selected_bytes'],\n            'missing_expected': expected_missing, 'metadata_files': 3}\n        require(observed_population == policy.get('expected_diagnostics'),\n                'fixed original available460 and missing5 population differs')\n"
    assert retention.count(needle) == 1
    retention = retention.replace(needle, addition + needle)
    controller = replace_function(controller, 'retain_diagnostics', retention)
    storage = functions(controller)['closed_storage_observation']
    storage = storage.replace('    parts = expected_parts(policy)\n', '')
    start = storage.index('    for part in parts:')
    end = storage.index('    device = root.lstat().st_dev', start)
    storage = storage[:start] + storage[end:]
    storage = storage.replace("('control', 'guard', 'original', 'parts', 'api', 'diagnostics')", "('control', 'guard', 'original', 'api', 'diagnostics')")
    storage = storage.replace("sizes['public_diagnostic'] <= len(parts) * MAX_DIAGNOSTIC_BYTES", "sizes['public_diagnostic'] == 0")
    storage = storage.replace('the fixed two-replica plan', 'the unchanged original custody ceilings')
    storage = storage.replace('    final_documents = (len(parts) + 1) * (3 << 20)',
                              '    final_documents = 4 * (3 << 20)  # Preserve the original r1 reserve, although only one FINAL is produced.')
    storage = storage.replace('remaining_inode_reserve = 1024 + 2 * (len(parts) + 1)', 'remaining_inode_reserve = 1032')
    storage = storage.replace('hia.v92-original-transport.closed-storage.v1', 'hia.v92-diagnostics-only.closed-storage.v2')
    controller = replace_function(controller, 'closed_storage_observation', storage)
    controller = replace_function(controller, 'finalize', FINALIZE)
    worker = worker.replace('v92-ci-failed-original-parts-policy.v1', 'v92-ci-diagnostics-only-policy.v2')
    worker = worker.replace('v92-ci-failed-original-parts-worker.v1', 'v92-ci-diagnostics-only-worker.v2')
    worker = worker.replace("    parts = expected_parts(policy)\n", '')
    worker = worker.replace("        stage = 'MULTIPLE_CONTIGUOUS_PARTS'\n        report['partition'] = split_original(path, pin, policy, root, helper, deadline)\n", '')
    worker = worker.replace("'proxy_URLs_or_credentials_recorded': False}", "'proxy_URLs_or_credentials_recorded': False, 'partition_files_created': False}")
    worker = worker.replace('SEALED_PARTS_PENDING_NATURAL_GUARDIAN', 'SEALED_DIAGNOSTICS_PENDING_NATURAL_GUARDIAN')
    worker = worker.replace("'parts': len(parts)", "'partition_files_created': False")
    worker = worker.replace('multipart policy schema differs', 'diagnostics-only policy schema differs')
    for name, text in (('controller.py', controller), ('worker.py', worker)):
        ast.parse(text)
        (OUT / name).write_text(text)
    policy = json.loads((OLD / 'policy.json').read_text())
    policy.update(schema='hia.actions.v92-ci-diagnostics-only-policy.v2', control_prefix=PREFIX,
                  trigger_branch='codex/hia-v92-failed-ci-diagnostics-only-r2-20261113-e26e',
                  work_root_name='hia-v92-failed-ci-diagnostics-r2',
                  public_root_name='hia-v92-failed-ci-diagnostics-public-r2', parts=[],
                  partition_files_created=False, slice_publication='NONE_DIAGNOSTICS_ONLY',
                  diagnostic_publication='RELOCATE_SAME_FILESYSTEM_AFTER_CLOSED_ECHILD',
                  expected_diagnostics=EXPECTED)
    policy['historical_receiver_boundary'] = {'local_R4': 'UNKNOWN_NOT_RECLASSIFIED',
        'remote_run_43338002642': 'HOLD_NOT_RECLASSIFIED', 'same_request_replayed': False}
    for name in policy['control_files']:
        raw = (OUT / name).read_bytes()
        policy['control_files'][name] = {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}
    (OUT / 'policy.json').write_text(json.dumps(policy, sort_keys=True, indent=2) + '\n')
    template = (OLD / 'workflow-template.yml').read_text()
    replacements = {
        'HIA v92 failed CI original ranges and step42 diagnostics': 'HIA v92 failed CI diagnostics-only recovery r2',
        'Retain one historical ZIP as a fixed complete partition': 'Retain every available original step42 diagnostic',
        'codex/hia-v92-failed-ci-original-parts-r1-20261113-e26e': policy['trigger_branch'],
        OLD_PREFIX: PREFIX,
        'hia-v92-failed-ci-parts-public-r1': policy['public_root_name'],
        'hia-v92-failed-ci-parts-r1': policy['work_root_name'],
        'Read the one sealed original ZIP and create the fixed partition under the original 900-second guardian': 'Read one sealed original ZIP and all fixed diagnostics under the original 900-second guardian',
        'Independently retain every fixed part and controls after closed ECHILD': 'Independently retain every fixed diagnostic and controls after closed ECHILD',
        'hia-v92-failed-ci-step42-originals-${{ github.run_id }}-1': 'hia-v92-step42-diagnostics-only-r2-${{ github.run_id }}-1',
        'UPLOAD_STEPS_PENDING_ACTUAL_COUNT\n': '',
    }
    for before, after in replacements.items():
        assert before in template, before
        template = template.replace(before, after)
    (OUT / 'workflow-template.yml').write_text(template)
    renderer = (OLD / 'render_workflow.py').read_text()
    renderer = renderer.replace(OLD_PREFIX, PREFIX)
    start = renderer.index("UPLOAD = '''")
    end = renderer.index('\n\n\ndef require', start)
    renderer = renderer[:start] + renderer[end:]
    renderer = renderer.replace('v92-ci-failed-original-parts-policy.v1', 'v92-ci-diagnostics-only-policy.v2')
    start = renderer.index('    parts = []\n')
    end = renderer.index("    require(set(policy.get('control_files'", start)
    renderer = renderer[:start] + "    require(policy.get('parts') == [] and policy.get('partition_files_created') is False,\n            'diagnostics-only request must not produce original ZIP partitions')\n" + renderer[end:]
    renderer = renderer.replace("'five exact control files are required'", "'six exact control files are required'")
    renderer = renderer.replace("and template.count('UPLOAD_STEPS_PENDING_ACTUAL_COUNT') == 1", "and 'UPLOAD_STEPS_PENDING_ACTUAL_COUNT' not in template")
    start = renderer.index("    uploads = ''.join(")
    end = renderer.index("    require('PLACEHOLDER' not in text", start)
    renderer = renderer[:start] + renderer[end:]
    renderer = renderer.replace('return text.encode(), parts', 'return text.encode()')
    renderer = renderer.replace('output, parts = render(', 'output = render(')
    renderer = renderer.replace("'parts': len(parts)", "'partition_files_created': False")
    renderer = renderer.replace('The current draft policy is deliberately rejected.', 'Only the exact frozen diagnostic control policy can be rendered.')
    ast.parse(renderer)
    (OUT / 'render_workflow.py').write_text(renderer)
    diffs = []
    records = []
    for path in sorted(OUT.iterdir()):
        old = OLD / path.name
        raw = path.read_bytes()
        before = old.read_bytes()
        records.append({'name': path.name, 'changed': raw != before,
            'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
            'git_blob': sha1(b'blob ' + str(len(raw)).encode() + bytes([0]) + raw).hexdigest()})
        if raw != before:
            diffs.append(''.join(difflib.unified_diff(before.decode().splitlines(keepends=True),
                raw.decode().splitlines(keepends=True), fromfile='remote-r1/' + path.name,
                tofile='diagnostics-only-r2/' + path.name)))
    (ROOT / 'SOURCE-DELTA.patch').write_text(''.join(diffs))
    (ROOT / 'SOURCE-PINS.json').write_text(json.dumps(records, sort_keys=True, indent=2) + '\n')
    unchanged = {}
    for name in ('controller.py', 'worker.py'):
        a, b = functions((OLD / name).read_text()), functions((OUT / name).read_text())
        unchanged[name] = {key: sha256(a[key].encode()).hexdigest() for key in a.keys() & b.keys() if a[key] == b[key]}
    proof = {'status': 'AUTHORING_AST_AND_EXACT_FUNCTION_PROJECTION_ONLY',
             'controls_executed': 0, 'network_requests': 0, 'product_executed': False,
             'old_local_R4_receiver_status': 'UNKNOWN', 'expected_diagnostics': EXPECTED,
             'unchanged_function_bodies': unchanged,
             'unchanged_full_files': [r['name'] for r in records if not r['changed']]}
    assert set(('new_client','deadline_check','api_request','bounded_response','metadata',
                'official_location','storage_download')).issubset(unchanged['worker.py'])
    assert set(('closed_guardian','natural_guardian','run','copy_original','final_input_records')).issubset(unchanged['controller.py'])
    assert functions(controller)['fixed_policy'] == functions(worker)['fixed_policy']
    assert all(n not in functions(controller) for n in ('expected_parts','concat_parts','relocate_slice','copy_unverified_range'))
    assert all(n not in functions(worker) for n in ('expected_parts','split_original'))
    (ROOT / 'MECHANICAL-PROJECTION.json').write_text(json.dumps(proof, sort_keys=True, indent=2) + '\n')
    print(json.dumps({'status': proof['status'], 'changed_files': [r['name'] for r in records if r['changed']],
                      'unchanged_files': proof['unchanged_full_files'], 'root': str(ROOT)}))


if __name__ == '__main__':
    derive()
