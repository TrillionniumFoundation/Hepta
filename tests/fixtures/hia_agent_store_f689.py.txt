"""Private, durable identities for HIA tools; digests are never authority.

The administrator selects one state directory per runtime authority. SQLite is
the journal/namespace; artifact files contain immutable bytes. Request intent is
committed before effects. A leftover intent is not retried as a new execution.
"""
from __future__ import annotations

from contextlib import contextmanager
from hashlib import sha256
import json
import math
import os
from pathlib import Path
import sqlite3
import stat
import threading
import uuid
import re

from .hia_program_tools import bounded_json_wire
from .hia_json_preflight import preflight_hia_json

MAX_INPUT_BYTES = 8 * 1024 * 1024
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024


class AgentRejected(ValueError):
    def __init__(self, code, message, phase="admission", *, retry_action="correct_input", details_artifact=None):
        super().__init__(message)
        self.code, self.phase, self.retry_action = code, phase, retry_action
        self.details_artifact = details_artifact


def wire(value):
    selected = os.environ.get('HEPTA_HIA_AGENT_BINARY64_FORMAT_MANIFEST')
    renderer = None
    if selected:
        from .hia_json_wire_native import SelectedBinary64Renderer
        renderer = SelectedBinary64Renderer(selected)
    return bounded_json_wire(value, MAX_INPUT_BYTES, ensure_ascii=False,
                             sort_keys=True, float_renderer=renderer)


def digest(value):
    return sha256(wire(value)).hexdigest()


def decode_data(payload):
    """Bounded ordinary JSON for tool data, including finite cost ratios.

    Reuse Core's duplicate-key/depth/node/string preflight after replacing only
    outside-string fractional/exponent number tokens with an integer token.
    By default the stdlib JSON decoder remains the value producer. An explicit
    installed Agent-data image replaces syntax/tree decoding, not the hosted
    object bridge. A separate explicit binary64 image can also replace decimal
    conversion; without it that operation remains hosted. Core programs retain their
    stricter, separate integer-only decoder. A selected image never falls back.
    """
    if type(payload) not in (bytes, str):
        reject("E_HIA_JSON", "JSON data must be UTF-8 bytes or text")
    selected_binary64 = os.environ.get('HEPTA_HIA_AGENT_BINARY64_MANIFEST')
    binary64 = None
    def floating(text):
        nonlocal binary64
        if selected_binary64:
            from .hia_agent_binary64_native import installed_agent_binary64
            try:
                if binary64 is None:
                    binary64 = installed_agent_binary64(selected_binary64)
                return binary64.convert(text)
            except ValueError as exc:
                reject("E_HIA_JSON", str(exc))
        value = float(text)
        if not math.isfinite(value):
            reject("E_HIA_JSON", "nonfinite JSON number")
        return value

    selected = os.environ.get('HEPTA_HIA_AGENT_DATA_JSON_MANIFEST')
    if selected:
        raw = payload if type(payload) is bytes else payload.encode('utf-8')
        if len(raw) > MAX_INPUT_BYTES:
            reject("E_HIA_JSON", "JSON data exceeds 8 MiB")
        from .hia_agent_data_json_native import installed_agent_data_json
        return installed_agent_data_json(selected).decode(raw,
            max_nodes=262144, max_depth=128, parse_float=floating)
    source = payload.decode("utf-8") if type(payload) is bytes else payload
    if len(source.encode("utf-8")) > MAX_INPUT_BYTES:
        reject("E_HIA_JSON", "JSON data exceeds 8 MiB")
    tokens, index, previous = [], 0, 0
    number = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")
    while index < len(source):
        ch = source[index]
        if ch == '"':
            index += 1
            while index < len(source):
                if source[index] == "\\":
                    index += 2
                elif source[index] == '"':
                    index += 1
                    break
                else:
                    index += 1
        elif ch == "-" or "0" <= ch <= "9":
            match = number.match(source, index)
            if match is None:
                index += 1
            else:
                if any(marker in match[0] for marker in (".", "e", "E")):
                    tokens.extend((source[previous:index], "0"))
                    previous = match.end()
                index = match.end()
        else:
            index += 1
    checked_source = source if not tokens else "".join([*tokens, source[previous:]])
    preflight_hia_json(checked_source, max_nodes=262144, max_depth=128)

    return json.loads(source, parse_float=floating,
        parse_constant=lambda _value: reject("E_HIA_JSON", "nonfinite JSON literal"))


def reject(code, message, phase="admission", **kwargs):
    raise AgentRejected(code, message, phase, **kwargs)


def keys(value, required, optional=(), label="object"):
    if (type(value) is not dict or not set(required) <= set(value)
            or set(value) - set(required) - set(optional)):
        reject("E_HIA_FIELDS", label + " has missing or unknown fields")


def _agent_resource_path(name):
    """Explicit source checkout or package-owned installed resource root.

    An installed package never searches cwd, HOME, sys.prefix or another source
    tree. Missing individual packaged resources do not fall back to sources.
    """
    from .hia_json_preflight_native import _source_resource_path
    return _source_resource_path(name)


def _reference_uint64(value):
    if (type(value) is not str or not value.isascii() or not value.isdecimal()
            or len(value) > 20 or (len(value) > 1 and value[0] == "0")
            or int(value) > (1 << 64) - 1):
        return None
    return int(value)


def _reference_digest(value):
    return type(value) is str and re.fullmatch("[0-9a-f]{64}", value) is not None


def _native_agent_identity():
    selected = os.environ.get("HEPTA_HIA_AGENT_IDENTITY_MANIFEST")
    if not selected:
        return None
    from .hia_agent_identity_native import installed_agent_identity
    return installed_agent_identity(selected)


def canonical_digest(value):
    native = _native_agent_identity()
    return native.digest(value) if native is not None else _reference_digest(value)


def uint64(value, label):
    native = _native_agent_identity()
    number = native.uint64(value) if native is not None else _reference_uint64(value)
    if number is None:
        reject("E_HIA_RANGE", label + " must be a canonical u64 decimal string")
    return number


def stable_read(path, limit, *, dir_fd=None):
    """Read an ordinary file through one descriptor, refusing symlink races."""
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    try:
        fd = os.open(path, flags, dir_fd=dir_fd)
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
                reject("E_HIA_ARTIFACT_FILE", "artifact is not a bounded ordinary file")
            data = stream.read(limit + 1)
            after = os.fstat(stream.fileno())
            identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
            if len(data) != before.st_size or identity(before) != identity(after):
                reject("E_HIA_ARTIFACT_CHANGED", "artifact changed while it was read")
            return data
    except OSError as exc:
        raise AgentRejected("E_HIA_ARTIFACT_FILE", "cannot read authorized ordinary artifact") from exc


def capture_path(path, roots, limit):
    """Resolve below an administrator root using no-follow directory handles.

    No user-supplied host, shell, expansion, traversal or root is accepted. Each
    component is opened relative to an already opened directory, so renaming a
    component cannot redirect a later lookup through a replacement symlink.
    """
    if type(path) is not str or not os.path.isabs(path):
        reject("E_HIA_PATH", "artifact paths must be absolute")
    parts = Path(path).parts
    if ".." in parts or "." in parts or "\x00" in path:
        reject("E_HIA_PATH", "artifact traversal is not permitted")
    lexical = Path(path)
    chosen = None
    for root in roots:
        try:
            relative = lexical.relative_to(root)
        except ValueError:
            continue
        if relative.parts:
            chosen = (root, relative.parts)
            break
    if chosen is None:
        reject("E_HIA_PATH_AUTHORITY", "artifact path is outside configured roots")
    root, relative = chosen
    descriptors = []
    try:
        # Roots are resolved once from trusted administrator configuration.
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
        descriptors.append(fd)
        for component in relative[:-1]:
            fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=fd)
            descriptors.append(fd)
        return stable_read(relative[-1], limit, dir_fd=fd)
    except OSError as exc:
        raise AgentRejected("E_HIA_PATH", "artifact path contains an unavailable or unsafe component") from exc
    finally:
        for fd in reversed(descriptors):
            os.close(fd)


def _native_artifact_rejection(exc):
    text=str(exc)
    if 'E_PUBLISH_LIMIT' in text:code='E_HIA_ARTIFACT_LIMIT'
    elif 'E_PUBLISH_BYTES' in text or 'E_PUBLISH_RACE' in text:code='E_HIA_ARTIFACT_CORRUPT'
    elif 'E_PUBLISH_NATIVE_CUSTODY' in text:code='E_HIA_ARTIFACT_NATIVE_CUSTODY'
    else:code='E_HIA_ARTIFACT_FILE'
    raise AgentRejected(code,'native artifact file operation refused; no request issuance or replay') from exc


def _native_artifact_admission():
    selected=os.environ.get('HEPTA_HIA_AGENT_ARTIFACT_STORE_MANIFEST')
    if not selected:return None
    from .artifact_publication_native import admit_artifact_store
    from .artifact_publication import PublicationRejected
    try:return admit_artifact_store(selected)
    except PublicationRejected as exc:_native_artifact_rejection(exc)


def _native_artifact_file(operation,root,*,data=b'',content_hash='-',_admission=None):
    selected=os.environ.get('HEPTA_HIA_AGENT_ARTIFACT_STORE_MANIFEST')
    if not selected:
        if _admission is not None:
            reject('E_HIA_ARTIFACT_NATIVE_CUSTODY','explicit selection changed during artifact call')
        return None
    from .artifact_publication_native import invoke_artifact_store
    from .artifact_publication import PublicationRejected
    try:return invoke_artifact_store(selected,operation,root,data=data,digest=content_hash,_admission=_admission)
    except PublicationRejected as exc:_native_artifact_rejection(exc)


class AgentStore:
    def __init__(self, root):
        supplied = Path(root).absolute()
        supplied.mkdir(mode=0o700, parents=True, exist_ok=True)
        if supplied.is_symlink():
            reject("E_HIA_STORE", "state directory cannot be a symbolic link")
        self.root = supplied.resolve()
        info = self.root.stat()
        if info.st_uid != os.geteuid() or info.st_mode & 0o022:
            reject("E_HIA_STORE", "state directory must be owned and not writable by other users")
        self.artifacts = self.root / "artifacts"
        self.artifacts.mkdir(mode=0o700, exist_ok=True)
        if self.artifacts.is_symlink():
            reject("E_HIA_STORE", "artifact directory cannot be a symbolic link")
        info = self.artifacts.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
            reject("E_HIA_STORE", "artifact directory must be owned and not writable by other users")
        database = self.root / "state.sqlite3"
        if database.exists() or database.is_symlink():
            info = database.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
                reject("E_HIA_STORE", "journal must be an owned private ordinary file")
        self.db = sqlite3.connect(database, isolation_level=None, timeout=10, check_same_thread=False)
        os.chmod(database, 0o600)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.lock = threading.RLock()
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS artifacts (
                id TEXT PRIMARY KEY, sha256 TEXT NOT NULL, uri TEXT UNIQUE NOT NULL,
                kind TEXT NOT NULL, metadata TEXT NOT NULL, content_key TEXT UNIQUE NOT NULL
            );
            CREATE TABLE IF NOT EXISTS profiles (
                id TEXT NOT NULL, sha256 TEXT NOT NULL, artifact TEXT NOT NULL,
                PRIMARY KEY (id,sha256)
            );
            CREATE TABLE IF NOT EXISTS contexts (
                id TEXT PRIMARY KEY, sha256 TEXT NOT NULL, artifact TEXT NOT NULL,
                created_ns TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS requests (
                key TEXT PRIMARY KEY, digest TEXT NOT NULL, tool TEXT NOT NULL,
                state TEXT NOT NULL, response TEXT, started_ns TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS costs (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT, context_id TEXT,
                tool TEXT NOT NULL, request_id TEXT NOT NULL, wall_ns TEXT NOT NULL,
                status TEXT NOT NULL, details TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS cursors (
                id TEXT PRIMARY KEY, artifact_id TEXT NOT NULL,
                sha256 TEXT NOT NULL, offset INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS slots (
                name TEXT PRIMARY KEY, context_id TEXT NOT NULL,
                generation TEXT NOT NULL, epoch TEXT NOT NULL, abi_sha256 TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS versions (
                slot TEXT NOT NULL, generation TEXT NOT NULL, artifact TEXT NOT NULL,
                PRIMARY KEY (slot,generation)
            );
            CREATE TABLE IF NOT EXISTS leases (
                id TEXT PRIMARY KEY, slot TEXT NOT NULL, generation TEXT NOT NULL,
                artifact TEXT NOT NULL, active INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS execution_budgets (
                context_id TEXT PRIMARY KEY, used_native_ns TEXT NOT NULL,
                owner TEXT
            );
        """)

    @contextmanager
    def transaction(self):
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                yield
            except BaseException:
                self.db.execute("ROLLBACK")
                raise
            else:
                self.db.execute("COMMIT")

    def close(self):
        self.db.close()

    def put(self, data, kind, metadata=None):
        if type(data) is not bytes or len(data) > MAX_ARTIFACT_BYTES:
            reject("E_HIA_ARTIFACT_LIMIT", "artifact exceeds the 64 MiB store limit")
        metadata = {} if metadata is None else metadata
        admission = _native_artifact_admission()
        native_hash = (_native_artifact_file('store-hash',self.artifacts,data=data,_admission=admission)
                       if admission is not None else None)
        content_hash = native_hash['sha256'] if native_hash is not None else sha256(data).hexdigest()
        content_key = digest({"sha256": content_hash, "kind": kind, "metadata": metadata})
        previous = self.db.execute("SELECT * FROM artifacts WHERE content_key=?", (content_key,)).fetchone()
        if previous is not None:
            ref = self._ref(previous)
            self.get(ref, kind=kind)
            return ref
        if native_hash is not None:
            stored = _native_artifact_file('store-put',self.artifacts,data=data,_admission=admission)
            if stored != native_hash:
                reject('E_HIA_ARTIFACT_CORRUPT','native artifact hash and durable file receipt differ')
        else:
            destination = self.artifacts / content_hash
            temporary = self.artifacts / (".write-" + uuid.uuid4().hex)
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o400)
            try:
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
                try:
                    os.link(temporary, destination, follow_symlinks=False)
                except FileExistsError:
                    if stable_read(destination, MAX_ARTIFACT_BYTES) != data:
                        reject("E_HIA_ARTIFACT_CORRUPT", "stored content does not match its immutable identity")
                directory_fd = os.open(self.artifacts, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            finally:
                temporary.unlink(missing_ok=True)
        ref = {"id": "a-" + uuid.uuid4().hex, "sha256": content_hash,
               "uri": "hia://artifacts/" + uuid.uuid4().hex}
        self.db.execute("INSERT OR IGNORE INTO artifacts VALUES (?,?,?,?,?,?)",
                        (ref["id"], content_hash, ref["uri"], kind, wire(metadata).decode(), content_key))
        row = self.db.execute("SELECT * FROM artifacts WHERE content_key=?", (content_key,)).fetchone()
        return self._ref(row)

    def json(self, value, kind, metadata=None):
        return self.put(wire(value), kind, metadata)

    @staticmethod
    def _ref(row):
        return {name: row[name] for name in ("id", "sha256", "uri")}

    def get(self, ref, *, kind=None):
        keys(ref, ("id", "sha256", "uri"), label="artifact reference")
        row = self.db.execute("SELECT * FROM artifacts WHERE id=?", (ref["id"],)).fetchone()
        if row is None or self._ref(row) != ref:
            reject("E_HIA_ARTIFACT_IDENTITY", "artifact reference was not issued in this runtime namespace")
        if kind is not None and row["kind"] != kind:
            reject("E_HIA_ARTIFACT_AUTHORITY", "input bytes cannot impersonate a retained " + kind)
        data = _native_artifact_file('store-get',self.artifacts,content_hash=row['sha256'])
        if data is None:
            data = stable_read(self.artifacts / row["sha256"], MAX_ARTIFACT_BYTES)
            if sha256(data).hexdigest() != row["sha256"]:
                reject("E_HIA_ARTIFACT_CORRUPT", "artifact bytes no longer match their recorded digest")
        return data, decode_data(row["metadata"])

    def get_json(self, ref, *, kind=None):
        data, metadata = self.get(ref, kind=kind)
        return decode_data(data), metadata

    def resolve_uri(self, uri):
        row = self.db.execute("SELECT * FROM artifacts WHERE uri=?", (uri,)).fetchone()
        if row is None:
            reject("E_HIA_ARTIFACT_IDENTITY", "resource URI was not issued in this runtime namespace")
        ref = self._ref(row)
        self.get(ref)
        return ref

    def profile(self, identifier, value):
        ref = self.json(value, "profile")
        profile = {"id": identifier, "sha256": ref["sha256"]}
        self.db.execute("INSERT OR IGNORE INTO profiles VALUES (?,?,?)",
                        (identifier, ref["sha256"], wire(ref).decode()))
        return profile, ref

    def check_profile(self, ref, expected):
        if ref != expected:
            reject("E_HIA_PROFILE_STALE", "profile is unavailable or differs from the installed implementation")
        row = self.db.execute("SELECT artifact FROM profiles WHERE id=? AND sha256=?",
                              (ref["id"], ref["sha256"])).fetchone()
        if row is None:
            reject("E_HIA_PROFILE_AUTHORITY", "profile does not resolve to a retained server record")
        return self.get_json(decode_data(row["artifact"]), kind="profile")[0]
