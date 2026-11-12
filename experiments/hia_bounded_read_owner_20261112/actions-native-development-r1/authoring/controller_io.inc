def require(value, message):
    if not value:
        raise RuntimeError(message)

def wire(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()

def identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)

def _directory_identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)

def _checked_parent(path):
    """Retain the complete absolute directory chain without following symlinks."""
    path = Path(path)
    require(path.is_absolute() and path.anchor == '/' and '..' not in path.parts
            and len(path.parts) > 1, 'noncanonical controlled IO path')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptors = [os.open('/', flags)]
    links = []
    def stable():
        for parent, name, child, expected in links:
            require(_directory_identity(os.fstat(child)) == expected
                    and _directory_identity(os.stat(name, dir_fd=parent,
                                                     follow_symlinks=False)) == expected,
                    'controlled IO directory chain changed')
    try:
        for name in path.parts[1:-1]:
            parent = descriptors[-1]
            child = os.open(name, flags, dir_fd=parent)
            descriptors.append(child)
            info = os.fstat(child)
            require(stat.S_ISDIR(info.st_mode), 'controlled IO ancestor is not a directory')
            links.append((parent, name, child, _directory_identity(info)))
        stable()
        yield descriptors[-1], path.parts[-1], stable
        stable()
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)

def _read_extent(descriptor, size):
    chunks, remaining = [], size
    while remaining:
        block = os.read(descriptor, min(1 << 20, remaining))
        if not block:
            break
        chunks.append(block)
        remaining -= len(block)
    require(remaining == 0, 'controlled IO original ended before its declared extent')
    return b''.join(chunks)

def _create_bytes(path, raw, mode):
    """Create through the retained parent; read back the same open descriptor."""
    with _checked_parent(path) as (parent, name, stable):
        descriptor = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL
                             | os.O_NOFOLLOW | os.O_CLOEXEC, mode, dir_fd=parent)
        try:
            os.fchmod(descriptor, mode)
            remaining = memoryview(raw)
            while remaining:
                count = os.write(descriptor, remaining)
                require(count > 0, 'controlled IO write made no progress')
                remaining = remaining[count:]
            os.fsync(descriptor)
            before = os.fstat(descriptor)
            require(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
                    and before.st_nlink == 1 and before.st_size == len(raw),
                    'create-only controlled output identity differs')
            expected = (before.st_dev, before.st_ino, before.st_mode, before.st_uid,
                        before.st_gid, before.st_nlink, before.st_size,
                        before.st_mtime_ns, before.st_ctime_ns)
            def same_leaf(info):
                return (info.st_dev, info.st_ino, info.st_mode, info.st_uid,
                        info.st_gid, info.st_nlink, info.st_size,
                        info.st_mtime_ns, info.st_ctime_ns) == expected
            require(same_leaf(os.stat(name, dir_fd=parent, follow_symlinks=False)),
                    'create-only output name changed')
            stable()
            os.lseek(descriptor, 0, os.SEEK_SET)
            require(_read_extent(descriptor, len(raw)) == raw
                    and same_leaf(os.fstat(descriptor))
                    and same_leaf(os.stat(name, dir_fd=parent, follow_symlinks=False)),
                    'create-only descriptor readback differs')
            stable()
        finally:
            os.close(descriptor)

def _create_directory(path, mode=0o700):
    with _checked_parent(path) as (parent, name, stable):
        os.mkdir(name, mode=mode, dir_fd=parent)
        descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                             | os.O_CLOEXEC, dir_fd=parent)
        try:
            observed = os.fstat(descriptor)
            require(stat.S_ISDIR(observed.st_mode) and observed.st_uid == os.geteuid()
                    and not stat.S_IMODE(observed.st_mode) & 0o077
                    and _directory_identity(os.stat(name, dir_fd=parent,
                                                     follow_symlinks=False))
                        == _directory_identity(observed),
                    'create-only private directory differs')
            stable()
        finally:
            os.close(descriptor)

def read(path, maximum=MAX_RECEIPT, *, system_binary=False):
    with _checked_parent(path) as (parent, name, stable):
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                             | os.O_CLOEXEC, dir_fd=parent)
        try:
            before = os.fstat(descriptor)
            require(stat.S_ISREG(before.st_mode), 'regular input required: ' + str(path))
            if system_binary:
                require(before.st_uid in (0, os.geteuid()) and before.st_nlink >= 1
                        and not stat.S_IMODE(before.st_mode) & 0o022,
                        'runner tool is writable or has unexpected ownership')
            else:
                require(before.st_uid == os.geteuid() and before.st_nlink == 1,
                        'owned single-link input required')
            require(0 <= before.st_size <= maximum, 'bounded original input required')
            require(identity(os.stat(name, dir_fd=parent, follow_symlinks=False))
                        == identity(before), 'input changed before reading')
            stable()
            raw = _read_extent(descriptor, before.st_size)
            require(identity(os.fstat(descriptor)) == identity(before)
                    and identity(os.stat(name, dir_fd=parent, follow_symlinks=False))
                        == identity(before), 'input changed during reading')
            stable()
            return raw, {'path': str(path), 'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
                         'identity': list(identity(before))}
        finally:
            os.close(descriptor)

def create(path, raw):
    _create_bytes(path, raw, 0o400)
    copied, record = read(path, max(len(raw), 1))
    require(copied == raw, 'create-only original readback differs')
    return record

def save(path, value):
    return create(path, wire(value))

def clean_environment():
    environment = {name: value for name, value in os.environ.items()
                   if not name.startswith(('GIT_', 'LD_', 'HEPTA_HIA_', 'PYTHON'))
                   and name not in ('GITHUB_TOKEN', 'GH_TOKEN')}
    environment.update(PYTHONDONTWRITEBYTECODE='1', PYTHONUNBUFFERED='1')
    return environment
