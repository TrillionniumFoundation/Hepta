"""Package the pinned Agent discovery and native-app source resources.

This is a development Python wheel build hook, not native build orchestration.
It copies only explicit source-owned resources; it imports no product modules.
"""
from pathlib import Path, PurePosixPath
import ast
from hashlib import sha256
import os
import shutil
import stat
from setuptools import setup
from setuptools.command.build_py import build_py

ROOT=Path(__file__).resolve().parent

def agent_resources():
    tree=ast.parse((ROOT/'hepta/hia_agent_contract.py').read_text())
    values={}
    for symbol in ('DISCOVERY_FILES','NATIVE_SOURCE_FILES','SOURCE_BUILD_FILES','COMPILER_BUILD_FILES','PUBLICATION_BUILD_FILES','BACKEND_BUILD_FILES','EMITTER_BUILD_FILES','BYTE_WRAPPER_BUILD_FILES','MACHINE_OBJECT_BUILD_FILES','EXECUTION_OBSERVATION_BUILD_FILES','CONTINUATION_BUILD_FILES', 'ENTRY_BUILD_FILES'):
        declarations=[node for node in tree.body if isinstance(node,ast.Assign)
                      and any(isinstance(target,ast.Name) and target.id==symbol for target in node.targets)]
        if len(declarations)!=1:raise ValueError('one explicit Agent resource list required: '+symbol)
        names=ast.literal_eval(declarations[0].value)
        if type(names)is not tuple or any(type(n)is not str or not n for n in names):
            raise ValueError('invalid Agent resource names')
        values[symbol]=names
    if any(Path(n).name!=n for n in values['DISCOVERY_FILES']):
        raise ValueError('invalid Agent discovery resource filenames')
    names=tuple('docs/'+n for n in values['DISCOVERY_FILES'])+values['NATIVE_SOURCE_FILES']+values['SOURCE_BUILD_FILES']+values['COMPILER_BUILD_FILES']+values['PUBLICATION_BUILD_FILES']+values['BACKEND_BUILD_FILES']+values['EMITTER_BUILD_FILES']+values['BYTE_WRAPPER_BUILD_FILES']+values['MACHINE_OBJECT_BUILD_FILES']+values['EXECUTION_OBSERVATION_BUILD_FILES']+values['CONTINUATION_BUILD_FILES'] + values['ENTRY_BUILD_FILES']
    if len(names)!=len(set(names)) or any(Path(n).is_absolute() or '..' in Path(n).parts for n in names):
        raise ValueError('invalid or duplicate Agent resource paths')
    return names


def _read_bound_file(root, name, *, limit, expected_length=None, expected_sha256=None):
    """Capture one regular file through held, no-follow directory descriptors.

    This returns the actual verified bytes. Callers must use that capture, not
    reopen its pathname after this function's checks. It grants no authority.
    """
    root = Path(root)
    if (not root.is_absolute() or '..' in root.parts
            or type(name) is not str or not name
            or PurePosixPath(name).as_posix() != name
            or PurePosixPath(name).is_absolute()
            or any(part in ('.', '..') for part in PurePosixPath(name).parts)
            or type(limit) is not int or limit <= 0
            or (expected_length is not None and
                (type(expected_length) is not int or not 0 <= expected_length <= limit))
            or (expected_sha256 is not None and
                (type(expected_sha256) is not str or len(expected_sha256) != 64
                 or any(c not in '0123456789abcdef' for c in expected_sha256)))):
        raise ValueError('invalid bounded regular-file capture')
    parts = (*root.parts[1:], *PurePosixPath(name).parts)
    directories = []
    descriptor = None
    file_identity = lambda value: (value.st_dev, value.st_ino, value.st_mode,
                                   value.st_size, value.st_mtime_ns, value.st_ctime_ns)
    directory_identity = lambda value: (value.st_dev, value.st_ino, value.st_mode)
    try:
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY
        current = os.open(root.anchor, flags)
        directories.append((None, None, current, os.fstat(current)))
        for part in parts[:-1]:
            parent = current
            prior = os.stat(part, dir_fd=parent, follow_symlinks=False)
            if not stat.S_ISDIR(prior.st_mode):
                raise ValueError('bounded file directory must not be a symlink')
            current = os.open(part, flags, dir_fd=parent)
            observed = os.fstat(current)
            directories.append((parent, part, current, observed))
            if directory_identity(prior) != directory_identity(observed):
                raise ValueError('bounded file directory changed before capture')
        prior = os.stat(parts[-1], dir_fd=current, follow_symlinks=False)
        if (not stat.S_ISREG(prior.st_mode) or not 0 <= prior.st_size <= limit
                or (expected_length is not None and prior.st_size != expected_length)):
            raise ValueError('bounded file must have its declared regular-file extent')
        descriptor = os.open(parts[-1], os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
                             dir_fd=current)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or file_identity(prior) != file_identity(before):
            raise ValueError('bounded file changed before capture')
        chunks, remaining = [], limit + 1
        while remaining:
            block = os.read(descriptor, remaining)
            if not block:
                break
            chunks.append(block)
            remaining -= len(block)
        raw = b''.join(chunks)
        after = os.fstat(descriptor)
        current_leaf = os.stat(parts[-1], dir_fd=current, follow_symlinks=False)
        if (file_identity(before) != file_identity(after)
                or file_identity(after) != file_identity(current_leaf)
                or len(raw) != before.st_size or len(raw) > limit
                or (expected_length is not None and len(raw) != expected_length)
                or (expected_sha256 is not None and sha256(raw).hexdigest() != expected_sha256)):
            raise ValueError('bounded file identity changed or differs')
        for parent, part, directory, observed in directories:
            named = (os.stat(part, dir_fd=parent, follow_symlinks=False)
                     if parent is not None else os.stat(root.anchor, follow_symlinks=False))
            held = os.fstat(directory)
            if (directory_identity(named) != directory_identity(held)
                    or directory_identity(held) != directory_identity(observed)):
                raise ValueError('bounded file directory binding changed')
        return raw
    finally:
        if descriptor is not None:
            os.close(descriptor)
        for _, _, directory, _ in reversed(directories):
            os.close(directory)


def _fixed_optional_bytes(path, expected):
    path = Path(path).absolute()
    return _read_bound_file(path.parent, path.name, limit=1 << 20,
                            expected_length=expected[0], expected_sha256=expected[1])


def _write_optional_bytes(path, raw):
    # The build hook uses captured source bytes; it never reopens a source to
    # copy it. Publish through one held destination directory, without following
    # an existing destination or parent symlink.
    path = Path(path).absolute()
    if '..' in path.parts or type(raw) is not bytes or not 0 < len(raw) <= 1 << 20:
        raise ValueError('invalid optional package output')
    directories, descriptor, temporary = [], None, None
    identity = lambda value: (value.st_dev, value.st_ino, value.st_mode)
    try:
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY
        current = os.open(path.anchor, flags)
        directories.append((None, None, current, os.fstat(current)))
        for part in path.parts[1:-1]:
            parent = current
            try:
                prior = os.stat(part, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                try:
                    os.mkdir(part, dir_fd=parent)
                except FileExistsError:
                    pass
                prior = os.stat(part, dir_fd=parent, follow_symlinks=False)
            if not stat.S_ISDIR(prior.st_mode):
                raise ValueError('optional output directory must be ordinary')
            current = os.open(part, flags, dir_fd=parent)
            observed = os.fstat(current)
            directories.append((parent, part, current, observed))
            if identity(prior) != identity(observed):
                raise ValueError('optional output directory changed')
        temporary = '.hia-optional-' + os.urandom(16).hex()
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                             | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
                             0o644, dir_fd=current)
        written = 0
        while written < len(raw):
            count = os.write(descriptor, raw[written:])
            if count <= 0:
                raise ValueError('optional package write made no progress')
            written += count
        held = os.fstat(descriptor)
        if not stat.S_ISREG(held.st_mode) or held.st_size != len(raw):
            raise ValueError('optional package output extent differs')
        for parent, part, directory, observed in directories:
            named = (os.stat(part, dir_fd=parent, follow_symlinks=False)
                     if parent is not None else os.stat(path.anchor, follow_symlinks=False))
            if identity(named) != identity(os.fstat(directory)) or identity(named) != identity(observed):
                raise ValueError('optional output directory binding changed')
        os.replace(temporary, path.name, src_dir_fd=current, dst_dir_fd=current)
        temporary = None
        named = os.stat(path.name, dir_fd=current, follow_symlinks=False)
        if identity(named) != identity(held) or named.st_size != held.st_size:
            raise ValueError('optional output named binding differs')
        for parent, part, directory, observed in directories:
            named = (os.stat(part, dir_fd=parent, follow_symlinks=False)
                     if parent is not None else os.stat(path.anchor, follow_symlinks=False))
            if identity(named) != identity(os.fstat(directory)) or identity(named) != identity(observed):
                raise ValueError('optional output directory binding changed after publication')
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary is not None:
            try:
                os.unlink(temporary, dir_fd=current)
            except FileNotFoundError:
                pass
        for _, _, directory, _ in reversed(directories):
            os.close(directory)


def _optional_profile_plan(selection):
    """Install only an explicit versioned selection, without importing Hepta.

    The default wheel keeps the original 210 resources. Source distributions
    retain all declared optional sources through MANIFEST.in. An explicit
    selection is never inferred from which files happen to be present.
    """
    if type(selection) is not str:
        raise ValueError('optional HIA build profiles must be an explicit string')
    if selection == '':
        return (), {}
    selected = selection.split(',')
    if any(not name or name.strip() != name for name in selected) or len(selected) != len(set(selected)):
        raise ValueError('optional HIA build profiles must be exact and unique')
    tree = ast.parse(_read_bound_file(ROOT, 'hepta/hia_optional_profiles.py', limit=1 << 20))
    values = {}
    for symbol in ('OPTIONAL_PROFILE_FILES', 'OPTIONAL_RESOURCE_PINS'):
        nodes = [node for node in tree.body if isinstance(node, ast.Assign)
                 and any(isinstance(target, ast.Name) and target.id == symbol for target in node.targets)]
        if len(nodes) != 1:
            raise ValueError('one explicit optional profile declaration required: ' + symbol)
        values[symbol] = ast.literal_eval(nodes[0].value)
    profiles, pins = values['OPTIONAL_PROFILE_FILES'], values['OPTIONAL_RESOURCE_PINS']
    if (type(profiles) is not dict or type(pins) is not dict
            or any(type(name) is not str or not name for name in profiles)
            or any(type(names) is not tuple or not names or len(names) != len(set(names))
                   or any(type(name) is not str or not name or Path(name).is_absolute()
                          or '..' in Path(name).parts or Path(name).as_posix() != name
                          for name in names) for names in profiles.values())
            or set(pins) != {name for names in profiles.values() for name in names}
            or any(name not in profiles for name in selected)):
        raise ValueError('invalid or unknown optional HIA profile selection')
    names = tuple(dict.fromkeys(name for profile in selected for name in profiles[profile]))
    if set(names) & set(agent_resources()):
        raise ValueError('optional HIA profiles overlap the default worker resources')
    for name in names:
        expected = pins[name]
        if (type(expected) is not tuple or len(expected) != 2
                or type(expected[0]) is not int or not 0 < expected[0] <= 1 << 20
                or type(expected[1]) is not str or len(expected[1]) != 64
                or any(c not in '0123456789abcdef' for c in expected[1])):
            raise ValueError('invalid fixed optional HIA resource identity')
        source = ROOT / name
        path = ROOT
        for part in Path(name).parts:
            path = path / part
            if path.is_symlink():
                raise ValueError('optional HIA package resource symlinks are forbidden')
        _fixed_optional_bytes(source, expected)
    return names, {name: pins[name] for name in names}


def optional_profile_resources(selection):
    return _optional_profile_plan(selection)[0]


class AgentResourceBuild(build_py):
    def run(self):
        super().run()
        self._agent_outputs=[]
        selection = os.environ.get('HEPTA_HIA_BUILD_PROFILES', '')
        optional, pins = _optional_profile_plan(selection)
        for name in agent_resources() + optional:
            source=ROOT/name
            if not source.is_file():raise ValueError('missing Agent package resource: '+name)
            target=Path(self.build_lib)/'hepta/_data'/name
            if name in pins:
                captured = _fixed_optional_bytes(source, pins[name])
                _write_optional_bytes(target, captured)
            else:
                target.parent.mkdir(parents=True,exist_ok=True)
                shutil.copyfile(source,target)
            self._agent_outputs.append(str(target))
        if _optional_profile_plan(selection) != (optional, pins):
            raise ValueError('optional HIA build selection changed during installation')
        for name in optional:
            expected = pins[name]
            _fixed_optional_bytes(Path(self.build_lib)/'hepta/_data'/name, expected)

    def get_outputs(self,include_bytecode=True):
        return super().get_outputs(include_bytecode)+getattr(self,'_agent_outputs',[])

setup(cmdclass={'build_py':AgentResourceBuild})
