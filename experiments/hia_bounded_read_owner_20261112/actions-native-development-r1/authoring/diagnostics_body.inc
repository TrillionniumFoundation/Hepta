MAX_RAW = 512 << 10
MAX_STDOUT = 1 << 20
MAX_INDEX = 64 << 10
MAX_OBSERVATION = 160 << 20
FRAME_BYTES = 8192

def inspect_boundary(root, policy, args, data):
    setup, context, config, guardian = (json.loads(data[name]) for name in
        ('setup.json', 'context.json', 'guard/request.json', 'guard/guardian.json'))
    require(setup['schema'] == 'hia.bounded-read-actions-setup.v1'
            and setup['status'] == 'PREPARED_NOT_EXECUTED' and setup['context'] == context
            and context['schema'] == 'hia.bounded-read-actions-context.v1'
            and context['root'] == str(root) and context['source'] == str(args.source)
            and context['policy_sha256'] == args.policy_sha256
            and context['actual_control_commit'] == args.control_commit
            and context['workflow_commit'] == os.environ['GITHUB_SHA']
            and context['workflow_commit'] == os.environ['GITHUB_WORKFLOW_SHA']
            and context['workflow_commit'] == os.environ['HIA_BOUNDED_READ_WORKFLOW_SHA']
            and context['run_id'] == int(os.environ['GITHUB_RUN_ID'])
            and context['run_attempt'] == int(os.environ['GITHUB_RUN_ATTEMPT']) == 1
            and context['candidate_commit'] == CANDIDATE and context['candidate_tree'] == TREE
            and context['controller_seconds'] == 180 and context['cleanup_seconds'] == 3,
            'small diagnostics context is not this operation')
    control = Path(__file__).absolute().parent
    originals = {str(control / name): expected['sha256'] for name, expected in policy['controls'].items()}
    originals[str(control / 'policy.json')] = args.policy_sha256
    require(context['control_sources'] == originals, 'small channel original control map differs')
    expected = dict(originals)
    expected.update({str(root / 'control' / name): item['sha256'] for name, item in policy['controls'].items()})
    expected[str(root / 'control/policy.json')] = args.policy_sha256
    expected[str(root / 'context.json')] = sha256(data['context.json']).hexdigest()
    expected[context['python']['resolved']] = context['python']['binary']['sha256']
    expected[context['git']['resolved']] = context['git']['binary']['sha256']
    command = [context['python']['resolved'], '-I', '-S', '-B', str(root / 'control/native_driver.py'),
        '--source-root', str(args.source), '--source-manifest', str(root / 'control/source-manifest.json'),
        '--control-manifest', str(root / 'control/control-manifest.json'),
        '--control-manifest-sha256', policy['controls']['control-manifest.json']['sha256'],
        '--output', str(root / 'evidence')]
    require(setup['command'] == command and setup['source_identities'] == expected
            and setup['guardian_config_sha256'] == sha256(data['guard/request.json']).hexdigest()
            and config == {'schema': 'hia-external-guardian-request.v1', 'controller_seconds': 180,
                'command': command, 'cwd': str(args.source), 'source_identities': expected},
            'fixed original guardian request differs')
    life = guardian.get('lifecycle', {})
    require(guardian.get('schema') == 'hepta.hia.external-qualification-guardian.v1'
            and guardian.get('command') == command and guardian.get('cwd') == str(args.source)
            and guardian.get('source_identities_before') == expected
            and guardian.get('external_controller_seconds') == 180
            and guardian.get('lifecycle_implementation_sha256') == policy['controls']['process_owner_impl.py']['sha256']
            and life.get('schema') == 'hepta.hia.external-qualification-guardian.v1.lifecycle'
            and life.get('qualification_seconds') == 180 and life.get('cleanup_seconds') == 3
            and life.get('subreaper_enabled') is True and life.get('qualification_started') is True,
            'small diagnostics guardian is not this exact operation')
    cleanup = life.get('cleanup', {})
    require(cleanup.get('attempted') is True and cleanup.get('complete') is True
            and cleanup.get('observed_echild') is True and cleanup.get('leader_reaped') is True
            and cleanup.get('deadline_exceeded') is False and cleanup.get('errors') == []
            and cleanup.get('remaining_direct_children') == [], 'no closed current ECHILD for child outputs')
    return {'current_operation_bound': True, 'closed_ECHILD': True,
            'guardian_sha256': sha256(data['guard/guardian.json']).hexdigest(),
            'original_product_status_not_changed': True}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--policy-sha256', required=True)
    parser.add_argument('--control-commit', required=True)
    args = parser.parse_args()
    root = Path(os.environ['RUNNER_TEMP']).resolve(strict=True) / WORK_ROOT
    workspace = Path(os.environ['GITHUB_WORKSPACE']).resolve(strict=True)
    control = Path(__file__).absolute().parent
    require(args.root == root and args.source == workspace / 'source'
            and control == workspace / 'control' / PREFIX
            and read(workspace / 'control/.git/HEAD', 256)[0] == (args.control_commit + '\n').encode(),
            'fixed diagnostic path or detached control differs')
    policy_raw, policy_pin = read(control / 'policy.json', 1 << 20)
    require(policy_pin['sha256'] == args.policy_sha256, 'small diagnostic policy differs')
    policy = json.loads(policy_raw)
    require(policy['schema'] == 'hia.bounded-read-actions-policy.v1'
            and policy['candidate'] == {'commit': CANDIDATE, 'tree': TREE, 'leaves': 4025}
            and policy['trigger_branch'] == TRIGGER and policy['small_raw_bytes'] == MAX_RAW
            and policy['small_stdout_bytes'] == MAX_STDOUT and policy['diagnostic_targets'] == 133,
            'fixed diagnostic policy bounds differ')
    for name in ('diagnostics.py', 'diagnostic-targets.json'):
        raw, observed = read(control / name, 1 << 20)
        expected = policy['controls'][name]
        require(observed['bytes'] == expected['bytes'] and observed['sha256'] == expected['sha256']
                and sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == expected['git_blob_sha1'],
                'exact diagnostic source/input differs')
    targets = json.loads(read(control / 'diagnostic-targets.json', 1 << 20)[0])
    require(targets['schema'] == 'hepta.hia.bounded-read-small-targets.v1'
            and len(targets['targets']) == 133 and len({row['name'] for row in targets['targets']}) == 133,
            'complete fixed 133 diagnostic population differs')
    cache, records, observed_bytes = {}, {}, 0
    def observe(row):
        nonlocal observed_bytes
        name = row['name']
        require(type(name) is str and not name.startswith('/') and '\\' not in name
                and '\0' not in name and all(part not in ('', '.', '..') for part in name.split('/')),
                'unsafe fixed diagnostic name')
        if row['location'] == 'root':
            path = root / name
        else:
            require(row['location'] == 'stage' and name in {
                'stage/' + phase + '.' + stream + '.log'
                for phase in ('prepare', 'run', 'finalize') for stream in ('stdout', 'stderr')},
                'unknown stage original')
            path = root.parent / (WORK_ROOT + '.' + name.removeprefix('stage/'))
        try:
            info = path.lstat()
            require(stat.S_ISREG(info.st_mode), 'regular small-channel original required')
            require(0 <= info.st_size <= 16 << 20 and observed_bytes + info.st_size <= MAX_OBSERVATION,
                    'fixed original hashing observation bound exceeded')
            observed_bytes += info.st_size
            raw, actual = read(path, 16 << 20)
            require(actual['identity'] == list(identity(info)), 'small original identity changed')
            cache[name] = raw
            records[name] = {'name': name, 'status': 'OBSERVED', 'bytes': len(raw),
                             'sha256': actual['sha256'],
                             'git_blob_sha1': sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}
        except FileNotFoundError:
            records[name] = {'name': name, 'status': 'MISSING'}
        except BaseException as error:
            records[name] = {'name': name, 'status': 'REFUSED', 'error_type': type(error).__name__}
    by_name = {row['name']: row for row in targets['targets']}
    metadata = ('setup.json', 'context.json', 'guard/request.json', 'guard/guardian.json')
    for name in metadata:
        observe(by_name[name])
    try:
        boundary = inspect_boundary(root, policy, args, cache)
    except BaseException as error:
        boundary = {'current_operation_bound': False, 'closed_ECHILD': False,
                    'error_type': type(error).__name__, 'error': str(error)[:1024]}
    for row in targets['targets']:
        name = row['name']
        if name in records:
            continue
        if boundary['closed_ECHILD']:
            observe(row)
        else:
            records[name] = {'name': name, 'status': 'NOT_READ_UNCLOSED_PROCESS_BOUNDARY'}
    selected, raw_bytes = [], 0
    for row in targets['targets']:
        name = row['name']
        item = records[name]
        if item['status'] != 'OBSERVED':
            continue
        size = item['bytes']
        if raw_bytes + size <= MAX_RAW:
            raw_bytes += size
            item['status'] = 'SELECTED_WHOLE_FILE'
            selected.append(name)
        else:
            item['status'] = 'OMITTED_WHOLE_FILE_BUDGET'
    index = {'schema': 'hepta.hia.bounded-read-small-channel-index.v1',
        'fixed_targets': 133, 'selected_files': len(selected), 'selected_raw_bytes': raw_bytes,
        'raw_limit': MAX_RAW, 'stdout_limit': MAX_STDOUT, 'observation_raw_bytes': observed_bytes,
        'boundary': boundary, 'complete_original_artifact_transport_claimed': False,
        'product_status_changed': False, 'records': [records[r['name']] for r in targets['targets']]}
    index_raw = wire(index)
    require(len(index_raw) <= MAX_INDEX, 'complete small-channel index exceeds its fixed limit')
    lines = []
    def line(kind, value):
        lines.append(kind + ' ' + json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n')
    line('HIA_BOUNDED_READ_DIAGNOSTIC_BEGIN', {'schema': 'hepta.hia.bounded-read-small-stream.v1',
        'run_id': int(os.environ['GITHUB_RUN_ID']), 'workflow_commit': os.environ['GITHUB_SHA'],
        'policy_sha256': args.policy_sha256, 'raw_limit': MAX_RAW, 'stdout_limit': MAX_STDOUT})
    line('HIA_BOUNDED_READ_DIAGNOSTIC_INDEX', index)
    frames = 0
    for name in selected:
        raw = cache[name]
        header = records[name]
        line('HIA_BOUNDED_READ_ORIGINAL_BEGIN', header)
        for offset in range(0, len(raw), FRAME_BYTES):
            block = raw[offset:offset + FRAME_BYTES]
            line('HIA_BOUNDED_READ_ORIGINAL_FRAME', {'name': name, 'offset': offset, 'bytes': len(block),
                'sha256': sha256(block).hexdigest(), 'base64': base64.b64encode(block).decode('ascii')})
            frames += 1
        line('HIA_BOUNDED_READ_ORIGINAL_END', header)
    line('HIA_BOUNDED_READ_DIAGNOSTIC_END', {'status': 'BOUNDED_WHOLE_FILE_CHANNEL_COMPLETE',
        'selected_files': len(selected), 'frames': frames, 'selected_raw_bytes': raw_bytes,
        'index_sha256': sha256(index_raw).hexdigest(), 'closed_ECHILD': boundary['closed_ECHILD'],
        'all_133_originals_transported': len(selected) == 133,
        'complete_original_artifact_transport_claimed': False})
    output = ''.join(lines).encode('utf-8')
    require(len(output) <= MAX_STDOUT, 'entire small stream including index/END exceeds its fixed limit')
    # One pre-budgeted byte stream; a partial pipe write has no later END claim.
    remaining = memoryview(output)
    while remaining:
        count = os.write(sys.stdout.fileno(), remaining)
        require(count > 0, 'small stdout made no progress')
        remaining = remaining[count:]
    return 0 if boundary['closed_ECHILD'] else 1

if __name__ == '__main__':
    try:
        code = main()
    except BaseException as error:
        # stderr is separate from the fixed stdout protocol; no partial stdout
        # fallback is emitted, so its one-MiB reservation is never exceeded.
        print(json.dumps({'small_diagnostic_status': 'HOLD', 'type': type(error).__name__,
                          'error': str(error)[:2048]}), file=sys.stderr, flush=True)
        code = 1
    raise SystemExit(code)
