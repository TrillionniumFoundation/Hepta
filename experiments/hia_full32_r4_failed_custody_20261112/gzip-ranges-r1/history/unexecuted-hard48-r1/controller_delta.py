"""Source-only replacements for the previously reviewed custody controller."""

def load_gzip_helper(control, policy):
    pin = policy['control_files']['gzip_evidence.py']
    path = control / 'gzip_evidence.py'
    raw = read(path, 1 << 20, pin['sha256'])
    require(len(raw) == pin['bytes'], 'frozen gzip evidence helper size differs')
    spec = importlib.util.spec_from_file_location('frozen_gzip_evidence', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def concat_parts(records, pin, parts):
    return GZIP_HELPER.concat_parts(records, pin, parts)


def capture_small(root, public, policy, inspection):
    """Only called after the current original guardian proves closed ECHILD."""
    private, destination = root / 'small', public / 'small'
    result = {'schema': 'hia.failed-full32.closed-small-capture.v1', 'status': 'HOLD',
              'files': [], 'errors': [], 'complete': False, 'original_results_reclassified': False,
              'product_execution_performed': False, 'child_bytes_read_only_after_bound_ECHILD': True}
    expected = {}
    index = None
    bound = False
    try:
        index, index_record = document(private / 'INDEX.json', 16 << 20)
        require(type(inspection) is dict and inspection.get('status') ==
                'ALL_AVAILABLE_BODIES_VERIFIED_HISTORICAL_RESULTS_UNCHANGED'
                and inspection.get('diagnostic_channel_complete') is True,
                'worker did not complete bounded original inspection')
        actual = file_record(private / 'INDEX.json', 16 << 20)
        same_original_record(inspection.get('index'), actual)
        require(index.get('schema') == 'hia.failed-full32.small-original-index.v1'
                and index.get('artifact') == policy['artifact']
                and index.get('diagnostic_channel_complete') is True
                and index.get('original_results_reclassified') is False
                and index.get('omitted_whole_originals') == [], 'small diagnostic index differs')
        physical, physical_pin = document(private / 'PHYSICAL-READBACK.json', 8 << 20)
        same_original_record(index.get('physical_readback'), file_record(private / 'PHYSICAL-READBACK.json', 8 << 20))
        require(physical.get('status') == inspection['status']
                and physical.get('artifact') == policy['artifact']
                and physical.get('all_available_original_bodies_independently_read') is True
                and physical.get('qualification_executed') is False
                and physical.get('original_results_reclassified') is False
                and physical.get('outer_files') == 48
                and physical.get('whole_originals_omitted_for_transport') == []
                and index.get('critical_originals') == physical.get('critical_originals'),
                'whole original physical readback differs')
        critical = physical.get('critical_originals')
        require(type(critical) is list and [x.get('path') for x in critical] == list(GZIP_HELPER.CRITICAL_INNER)
                and all(x.get('status') in ('PRESENT', 'ORIGINAL_MISSING', 'ORIGINAL_UNREADABLE') for x in critical),
                'complete fixed original diagnostic denominator differs')
        originals = index.get('originals')
        require(type(originals) is list and len(originals) == physical.get('selected_original_files')
                and len(originals) <= GZIP_HELPER.MAX_CAPTURE_FILES,
                'whole small-original count differs')
        paths = set()
        for row in originals:
            name = row.get('saved')
            require(type(name) is str and re.fullmatch('[OI][0-9]{6}\\.original', name)
                    and name not in expected and (row.get('scope'), row.get('path')) not in paths
                    and row.get('whole_original') is True and row.get('derived') is False,
                    'duplicate or non-whole selected original')
            paths.add((row['scope'], row['path']))
            expected[name] = row['actual']
        for name, pin in (('INDEX.json', inspection['index']),
                          ('PHYSICAL-READBACK.json', index['physical_readback']),
                          ('DIRECTORY.json', physical['directory']),
                          ('OUTER-INVENTORY.json', physical['outer_inventory']),
                          ('INNER-INVENTORY.json', physical['inner_inventory'])):
            expected[name] = pin
        require(set(os.listdir(private)) == set(expected), 'successful small namespace differs')
        bound = True
    except BaseException as exc:
        result['errors'].append({'stage': 'SMALL_ACCEPTANCE', 'type': type(exc).__name__,
            'safe_refusal': str(exc) if type(exc) is Refusal else None})
    reserved = 0
    try:
        parent = private.lstat()
        require(stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.geteuid()
                and parent.st_dev == root.lstat().st_dev and not stat.S_IMODE(parent.st_mode) & 0o077,
                'small original directory differs')
        names = sorted(os.listdir(private))
        require(len(names) <= GZIP_HELPER.MAX_CAPTURE_FILES + len(GZIP_HELPER.SMALL_DOCUMENTS),
                'small original file count exceeds bound')
        for name in names:
            try:
                require(name in GZIP_HELPER.SMALL_DOCUMENTS or re.fullmatch('[OI][0-9]{6}\\.original', name),
                        'unexpected file in small original namespace')
                path = private / name
                actual = file_record(path, 64 << 20)
                require(reserved + actual['bytes'] <= 192 << 20, 'whole small original total exceeds bound')
                reserved += actual['bytes']
                if bound:
                    same_original_record(expected[name], actual)
                copied = copy_original(path, destination / name, actual)
                result['files'].append({'name': name, 'original': actual, 'copy': copied,
                    'whole_original_or_whole_derived_document': True,
                    'verified_against_worker_and_index': bound})
            except BaseException as exc:
                result['errors'].append({'stage': 'SMALL_COPY_' + name, 'type': type(exc).__name__,
                    'safe_refusal': str(exc) if type(exc) is Refusal else None})
        require(identity(private.lstat()) == identity(parent), 'small original directory changed')
    except BaseException as exc:
        result['errors'].append({'stage': 'SMALL_NAMESPACE', 'type': type(exc).__name__,
            'safe_refusal': str(exc) if type(exc) is Refusal else None})
    result['complete'] = bound and not result['errors'] and len(result['files']) == len(expected)
    result['status'] = 'WHOLE_SMALL_ORIGINALS_BOUND_AND_COPIED' if result['complete'] else 'HOLD'
    result['bytes_reserved'] = reserved
    raw = wire(result)
    require(len(raw) <= 8 << 20, 'whole small capture inventory exceeds fixed bound')
    create(destination / 'SMALL-CAPTURE.json', raw)
    actual = file_record(destination / 'SMALL-CAPTURE.json', 8 << 20)
    require(actual['bytes'] == len(raw) and actual['sha256'] == sha256(raw).hexdigest(),
            'small capture inventory readback differs')
    return {'status': result['status'], 'complete': result['complete'], 'files': len(result['files']),
            'bytes_reserved': reserved, 'receipt': actual, 'errors': result['errors'][:32],
            'all_errors_retained_in_complete_receipt': True}


def closed_storage_observation(root, public, policy):
    """Actual same-device file allocation plus remaining immutable reserves."""
    pin, parts = policy['artifact'], expected_parts(policy)
    data_paths = {root / 'original' / ('artifact-%d.zip' % pin['id']),
                  root / 'original' / ('artifact-%d.zip.partial' % pin['id'])}
    private_files = {root / 'control' / name for name in (*policy['control_files'], 'policy.json')}
    names = ('context.json', 'setup.json', 'guard/request.json', 'guard/guardian.json',
             'guard/child.stdout.log', 'guard/child.stderr.log', 'supervisor.stdout.log',
             'supervisor.stderr.log', 'recovery.json', 'recovery.next.json', 'recovery-terminal.json',
             'api/artifact-%d.metadata.original.json' % pin['id'])
    private_files |= {root / name for name in names}
    diagnostic_names = tuple(x for x in names if x != 'recovery.next.json')
    public_files = set()
    allowed_dirs = {root, public, root / 'small', public / 'small'} | {
        root / name for name in ('control', 'guard', 'original', 'parts', 'api')}
    for part in parts:
        directory = public / ('part-%02d' % part['ordinal'])
        allowed_dirs |= {directory, directory / 'controls'}
        data_paths |= {root / 'parts' / part['name'], directory / 'slice.bin.gz',
                       directory / 'unverified-range.bin.gz', directory / 'unverified-range.bin'}
        public_files |= {directory / 'controls' / name.replace('/', '--') for name in diagnostic_names}
    public_files |= {public / 'small' / ('current--' + name.replace('/', '--')) for name in diagnostic_names}
    device, rows, unique = root.lstat().st_dev, [], {}
    def small_name(name):
        return name in GZIP_HELPER.SMALL_DOCUMENTS or re.fullmatch('[OI][0-9]{6}\\.original', name)
    def visit(path):
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            before = os.fstat(fd)
            require(path in allowed_dirs and stat.S_ISDIR(before.st_mode) and before.st_dev == device
                    and before.st_uid == os.geteuid() and not stat.S_IMODE(before.st_mode) & 0o077,
                    'actual storage directory identity differs')
            rows.append({'path': str(path), 'kind': 'directory', 'identity': list(identity(before)),
                         'allocated_bytes': before.st_blocks * 512})
            names = os.listdir(fd)
            require(len(rows) + len(names) <= 12288, 'actual storage entry bound exceeded')
            for name in sorted(names):
                child = path / name
                observed = os.stat(name, dir_fd=fd, follow_symlinks=False)
                if stat.S_ISDIR(observed.st_mode):
                    visit(child)
                else:
                    require(stat.S_ISREG(observed.st_mode) and observed.st_dev == device
                            and observed.st_uid == os.geteuid() and observed.st_nlink == 1,
                            'closed storage is not owned single-link regular bytes')
                    category = ('payload' if child in data_paths else 'private_metadata' if child in private_files
                        else 'public_diagnostic' if child in public_files
                        else 'private_small' if path == root / 'small' and small_name(name)
                        else 'public_small' if path == public / 'small' and (small_name(name) or name == 'SMALL-CAPTURE.json')
                        else None)
                    require(category is not None, 'unexpected file in exact custody namespace')
                    inode = (observed.st_dev, observed.st_ino)
                    require(inode not in unique, 'duplicate retained inode after closed storage')
                    unique[inode] = observed.st_size
                    rows.append({'path': str(child), 'kind': 'regular', 'category': category,
                                 'identity': list(identity(observed)), 'allocated_bytes': observed.st_blocks * 512})
                require(identity(os.stat(name, dir_fd=fd, follow_symlinks=False)) == identity(observed),
                        'storage child identity changed')
                require(len(rows) <= 12288, 'actual storage entry bound exceeded')
            require(identity(os.fstat(fd)) == identity(before) == identity(path.lstat()),
                    'storage directory identity changed')
        finally:
            os.close(fd)
    visit(root)
    visit(public)
    keys = ('payload', 'private_metadata', 'public_diagnostic', 'private_small', 'public_small')
    sizes = {key: sum(row['identity'][6] for row in rows if row.get('category') == key) for key in keys}
    require(sizes['payload'] <= pin['bytes'] + len(parts) * (313 << 20)
            and sizes['private_metadata'] <= 64 << 20
            and sizes['public_diagnostic'] <= (len(parts) + 1) * MAX_DIAGNOSTIC_BYTES
            and sizes['private_small'] <= 192 << 20 and sizes['public_small'] <= 200 << 20,
            'actual retained bytes exceed fixed two-payload-copy and small-channel bounds')
    allocation = sum(row['allocated_bytes'] for row in rows)
    final_documents = len(parts) * (3 << 20) + (16 << 20)
    upload_workspace, filesystem_reserve = 320 << 20, 512 << 20
    require(allocation + final_documents + upload_workspace + filesystem_reserve <= 8 << 30,
            'actual allocation plus final/upload/filesystem reserve exceeds original 8 GiB')
    capacity = os.statvfs(root.parent)
    inode_reserve = 1024 + 2 * len(parts)
    require(capacity.f_bavail * capacity.f_frsize >= final_documents + upload_workspace + filesystem_reserve
            and capacity.f_favail >= inode_reserve, 'remaining ordinary storage reserve unavailable')
    result = {'schema': 'hia.failed-full32-gzip.closed-storage.v1', 'entry_count': len(rows),
        'single_link_regular_files': len(unique), 'logical_bytes_by_category': sizes,
        'allocated_bytes_observed': allocation, 'future_final_document_bytes_reserved': final_documents,
        'one_serial_upload_workspace_reserved': upload_workspace, 'filesystem_overhead_reserved': filesystem_reserve,
        'remaining_free_bytes': capacity.f_bavail * capacity.f_frsize, 'remaining_free_inodes': capacity.f_favail,
        'remaining_inode_reserve': inode_reserve, 'records': rows,
        'file_bodies_read_by_this_observation': False, 'original_ZIP_bytes_rewritten': False}
    raw = wire(result)
    require(len(raw) <= 8 << 20, 'complete storage inventory exceeds fixed document reserve')
    create(public / 'small' / 'CLOSED-STORAGE.json', raw)
    stored = file_record(public / 'small' / 'CLOSED-STORAGE.json', 8 << 20)
    require(stored['sha256'] == sha256(raw).hexdigest() and stored['bytes'] == len(raw),
            'closed storage full inventory readback differs')
    return {key: value for key, value in result.items() if key != 'records'} | {'full_inventory': stored}
