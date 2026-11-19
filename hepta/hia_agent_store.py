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


def wire(value, *, maximum=MAX_INPUT_BYTES):
    selected = os.environ.get('HEPTA_HIA_AGENT_BINARY64_FORMAT_MANIFEST')
    renderer = None
    if selected:
        from .hia_json_wire_native import SelectedBinary64Renderer
        renderer = SelectedBinary64Renderer(selected)
    return bounded_json_wire(value, maximum, ensure_ascii=False,
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


def _reference_record_authority(expected, observed, *, required_kind, observed_kind):
    if observed != expected:
        return 1
    return 2 if required_kind is not None and observed_kind != required_kind else 0


def record_authority(expected, observed, *, required_kind=None, observed_kind=None):
    native = _native_agent_identity()
    decide = _reference_record_authority if native is None else native.record_authority
    return decide(expected, observed, required_kind=required_kind, observed_kind=observed_kind)


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
            data = stream.read(before.st_size + 1)
            after = os.fstat(stream.fileno())
            identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
            if len(data) != before.st_size or identity(before) != identity(after):
                reject("E_HIA_ARTIFACT_CHANGED", "artifact changed while it was read")
            return data
    except OSError as exc:
        raise AgentRejected("E_HIA_ARTIFACT_FILE", "cannot read authorized ordinary artifact") from exc


def capture_path(path, roots, limit):
    selected = os.environ.get('HEPTA_HIA_AGENT_ARTIFACT_CAPTURE_MANIFEST')
    if selected is not None:
        from .hia_agent_artifact_capture_native import capture
        return capture(selected, path, roots, limit)
    return _reference_capture_path(path, roots, limit)


def _reference_capture_path(path, roots, limit):
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


@contextmanager
def _claim_state_directory(root):
    import fcntl

    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        opened = os.fstat(fd)
        observed = root.lstat()
        if (not os.path.samestat(opened, observed) or opened.st_uid != os.geteuid()
                or opened.st_mode & 0o022):
            reject("E_HIA_STORE", "state directory changed while selecting its journal")
        yield fd
        if not os.path.samestat(opened, root.lstat()):
            reject("E_HIA_STORE", "state directory changed while selecting its journal")
    finally:
        os.close(fd)


class AgentStore:
    def __init__(self, root, *, native_store=None):
        from .hia_execution_budget import admitted_execution_budget, execution_budget_store
        budget_admission = admitted_execution_budget()
        supplied = Path(root).absolute()
        supplied.mkdir(mode=0o700, parents=True, exist_ok=True)
        if supplied.is_symlink():
            reject("E_HIA_STORE", "state directory cannot be a symbolic link")
        self.root = supplied.resolve()
        info = self.root.stat()
        if info.st_uid != os.geteuid() or info.st_mode & 0o022:
            reject("E_HIA_STORE", "state directory must be owned and not writable by other users")
        database = self.root / "state.sqlite3"
        if native_store is None and os.path.lexists(self.root / "store" / "namespace.bin"):
            reject("E_HIA_STORE", "this state root belongs to the explicitly selected native Store")
        if native_store is not None:
            from .hia_native_helpers import pinned_store_initializer

            initializer = pinned_store_initializer(native_store)
            with _claim_state_directory(self.root) as parent:
                if any(os.path.lexists(str(database) + suffix) for suffix in ("", "-wal", "-shm", "-journal")):
                    reject("E_HIA_STORE", "native Store requires a separate staged state root")
                if initializer is not None and not os.path.lexists(self.root / "store"):
                    from .hia_agent_store_native import initialize_store

                    initialize_store(self.root, parent, initializer)
        self.artifacts = self.root / "artifacts"
        self.artifacts.mkdir(mode=0o700, exist_ok=True)
        if self.artifacts.is_symlink():
            reject("E_HIA_STORE", "artifact directory cannot be a symbolic link")
        info = self.artifacts.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
            reject("E_HIA_STORE", "artifact directory must be owned and not writable by other users")
        self.lock = threading.RLock()
        self._typed_journal = native_store is not None
        self._artifact_code = None
        self._capture_code = None
        if native_store is not None:
            from .hia_agent_store_native import NativeStoreConnection, StoreRefusal
            self.database_error = StoreRefusal
            self.db = NativeStoreConnection(self.root, *native_store, lock=self.lock)
            self._artifact_code = self.db.artifact_code
            self._capture_code = self.db.capture_code
            try:
                self.db.execute("BEGIN IMMEDIATE")
                self.db.execute("ROLLBACK")
                self.execution_budgets = execution_budget_store(self, budget_admission)
            except BaseException:
                self.db.close()
                raise
            return
        if database.exists() or database.is_symlink():
            info = database.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
                reject("E_HIA_STORE", "journal must be an owned private ordinary file")
        import sqlite3
        self.database_error = sqlite3.Error
        connection = None
        try:
            with _claim_state_directory(self.root):
                if os.path.lexists(self.root / "store" / "namespace.bin"):
                    reject("E_HIA_STORE", "this state root belongs to the explicitly selected native Store")
                connection = sqlite3.connect(database, isolation_level=None, timeout=10, check_same_thread=False)
        except BaseException:
            if connection is not None:
                connection.close()
            raise
        self.db = connection
        os.chmod(database, 0o600)
        self.database = database
        database_info = database.lstat()
        if not stat.S_ISREG(database_info.st_mode):
            reject('E_HIA_STORE', 'journal must remain an ordinary file after opening')
        self.database_identity = (database_info.st_dev, database_info.st_ino)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
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
        self.database_sidecars = None
        try:
            if budget_admission is not None:
                # Bind the official WAL namespace before the budget adapter opens
                # its dedicated connection to this same durable journal.
                self.db.execute('SELECT name FROM sqlite_master LIMIT 1').fetchone()
                sidecars = {}
                for suffix in ('-wal', '-shm'):
                    sidecar = Path(str(database) + suffix).lstat()
                    if (not stat.S_ISREG(sidecar.st_mode) or sidecar.st_uid != os.geteuid()
                            or sidecar.st_mode & 0o022):
                        reject('E_HIA_STORE', 'journal sidecar must be an owned private ordinary file')
                    sidecars[suffix] = (sidecar.st_dev, sidecar.st_ino)
                self.database_sidecars = sidecars
            self.execution_budgets = execution_budget_store(self, budget_admission)
        except BaseException as error:
            try:
                self.db.close()
            except BaseException as failure:
                error.add_note('AgentStore construction cleanup failed: ' + type(failure).__name__)
            raise

    def journal_lookup(self, key):
        if self._typed_journal:
            return self.db.journal_lookup(key)
        return self.db.execute('SELECT * FROM requests WHERE key=?', (key,)).fetchone()

    def journal_reserve(self, key, digest, tool, started_ns):
        if self._typed_journal:
            self.db.journal_reserve(key, digest, tool, started_ns)
        else:
            self.db.execute('INSERT INTO requests VALUES (?,?,?,?,?,?)',
                            (key, digest, tool, 'running', None, started_ns))

    def journal_complete(self, key, response):
        if self._typed_journal:
            self.db.journal_complete(key, response)
        else:
            self.db.execute("UPDATE requests SET state='completed',response=? WHERE key=?", (response, key))

    def journal_cost(self, context, tool, request_id, wall_ns, status, details):
        if self._typed_journal:
            self.db.journal_cost(context, tool, request_id, wall_ns, status, details)
        else:
            self.db.execute(
                'INSERT INTO costs (context_id,tool,request_id,wall_ns,status,details) VALUES (?,?,?,?,?,?)',
                (context, tool, request_id, wall_ns, status, details))

    @contextmanager
    def transaction(self):
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                yield
            except BaseException:
                if self.db.in_transaction:
                    self.db.execute("ROLLBACK")
                raise
            else:
                self.db.execute("COMMIT")

    def close(self):
        with self.lock:
            try:
                self.execution_budgets.close()
            finally:
                self.db.close()

    def _artifact_file(self, operation, *, data=b'', content_hash='-', admission=None):
        if self._artifact_code is None:
            return _native_artifact_file(operation, self.artifacts, data=data,
                                         content_hash=content_hash, _admission=admission)
        from .artifact_publication import PublicationRejected
        from .artifact_publication_native import invoke_pinned_artifact_store
        try:
            return invoke_pinned_artifact_store(self._artifact_code, operation, self.artifacts,
                                                data=data, digest=content_hash)
        except PublicationRejected as exc:
            _native_artifact_rejection(exc)

    def capture(self, path, roots, limit, expected):
        if self._capture_code is None:
            data = capture_path(path, roots, limit)
            if expected is not None and expected != sha256(data).hexdigest():
                reject("E_HIA_ARTIFACT_CHANGED", "captured bytes differ from the expected digest")
            return self.put(data, "input"), len(data)
        from .hia_agent_artifact_capture_native import capture_pinned
        data = capture_pinned(self._capture_code, path, roots, limit)
        return self.put(data, "input", expected_sha256=expected), len(data)

    def put(self, data, kind, metadata=None, *, expected_sha256=None):
        if type(data) is not bytes or len(data) > MAX_ARTIFACT_BYTES:
            reject("E_HIA_ARTIFACT_LIMIT", "artifact exceeds the 64 MiB store limit")
        metadata = {} if metadata is None else metadata
        admission = _native_artifact_admission() if self._artifact_code is None else None
        native_hash = (self._artifact_file('store-hash', data=data, admission=admission)
                       if self._artifact_code is not None or admission is not None else None)
        content_hash = native_hash['sha256'] if native_hash is not None else sha256(data).hexdigest()
        if expected_sha256 is not None and content_hash != expected_sha256:
            reject("E_HIA_ARTIFACT_CHANGED", "captured bytes differ from the expected digest")
        native = _native_agent_identity()
        stream = os.environ.get('HEPTA_HIA_SHA256_STREAM_MANIFEST')
        if native is not None and stream:
            from .hia_sha256_stream_native import installed_stream_hasher

            key_material = native.artifact_key_material(content_hash, kind, metadata)
            content_key = installed_stream_hasher(stream).new(key_material).hexdigest()
        else:
            content_key = digest({"sha256": content_hash, "kind": kind, "metadata": metadata})
        previous = self.db.execute("SELECT * FROM artifacts WHERE content_key=?", (content_key,)).fetchone()
        if previous is not None:
            ref = self._ref(previous)
            self.get(ref, kind=kind)
            return ref
        if native_hash is not None:
            stored = self._artifact_file('store-put', data=data, admission=admission)
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
        if native is None:
            ref = {"id": "a-" + uuid.uuid4().hex, "sha256": content_hash,
                   "uri": "hia://artifacts/" + uuid.uuid4().hex}
        else:
            ref = native.issued_artifact(content_hash, uuid.uuid4().bytes, uuid.uuid4().bytes)
        self.db.execute("INSERT OR IGNORE INTO artifacts VALUES (?,?,?,?,?,?)",
                        (ref["id"], content_hash, ref["uri"], kind, wire(metadata).decode(), content_key))
        row = self.db.execute("SELECT * FROM artifacts WHERE content_key=?", (content_key,)).fetchone()
        return self._ref(row)

    def json(self, value, kind, metadata=None):
        return self.put(wire(value), kind, metadata)

    @staticmethod
    def _ref(row):
        return {name: row[name] for name in ("id", "sha256", "uri")}

    def _artifact_record(self, ref, kind=None):
        identity_fields = ("id", "sha256", "uri")
        keys(ref, identity_fields, label="artifact reference")
        row = self.db.execute("SELECT * FROM artifacts WHERE id=?", (ref["id"],)).fetchone()
        stored = None if row is None else tuple(row[key] for key in identity_fields)
        decision = record_authority(tuple(ref[key] for key in identity_fields), stored,
                                    required_kind=kind,
                                    observed_kind=None if row is None else row["kind"])
        if decision == 1:
            reject("E_HIA_ARTIFACT_IDENTITY", "artifact reference was not issued in this runtime namespace")
        if decision == 2:
            reject("E_HIA_ARTIFACT_AUTHORITY", "input bytes cannot impersonate a retained " + kind)
        return row

    def get(self, ref, *, kind=None):
        row = self._artifact_record(ref, kind)
        data = self._artifact_file('store-get', content_hash=row['sha256'])
        if data is None:
            data = stable_read(self.artifacts / row["sha256"], MAX_ARTIFACT_BYTES)
            if sha256(data).hexdigest() != row["sha256"]:
                reject("E_HIA_ARTIFACT_CORRUPT", "artifact bytes no longer match their recorded digest")
        return data, decode_data(row["metadata"])

    def write_retained_artifact(self, ref, output):
        from .artifact_publication import PublicationRejected
        from .artifact_publication_native import capture_pinned_artifact

        row = self._artifact_record(ref)
        try:
            capture_pinned_artifact(self._artifact_code, self.artifacts, row['sha256'], output)
        except PublicationRejected as exc:
            _native_artifact_rejection(exc)
        # Preserve rejection order for a corrupt retained metadata record.
        decode_data(row['metadata'])

    def get_json(self, ref, *, kind=None):
        value, metadata, _ = self.get_json_with_wire(ref, kind=kind)
        return value, metadata

    def get_json_with_wire(self, ref, *, kind=None):
        data, metadata = self.get(ref, kind=kind)
        return decode_data(data), metadata, data

    def resolve_uri(self, uri):
        row = self.db.execute("SELECT * FROM artifacts WHERE uri=?", (uri,)).fetchone()
        if row is None:
            reject("E_HIA_ARTIFACT_IDENTITY", "resource URI was not issued in this runtime namespace")
        ref = self._ref(row)
        if self._artifact_code is None:
            self.get(ref)
        else:
            from subprocess import DEVNULL

            self.write_retained_artifact(ref, DEVNULL)
        return ref

    def profile(self, identifier, value):
        return self.profile_bytes(identifier, wire(value))

    def profile_bytes(self, identifier, canonical):
        ref = self.put(canonical, "profile")
        profile = {"id": identifier, "sha256": ref["sha256"]}
        self.db.execute("INSERT OR IGNORE INTO profiles VALUES (?,?,?)",
                        (identifier, ref["sha256"], wire(ref).decode()))
        return profile, ref

    def check_profile(self, ref, expected):
        from .hia_worker_report_native import SELECTOR, installed_worker_report

        selected = os.environ.get(SELECTOR)
        stale = not installed_worker_report(selected).equal_json(ref, expected) if selected else ref != expected
        if stale:
            reject("E_HIA_PROFILE_STALE", "profile is unavailable or differs from the installed implementation")
        row = self.db.execute("SELECT artifact FROM profiles WHERE id=? AND sha256=?",
                              (ref["id"], ref["sha256"])).fetchone()
        if row is None:
            reject("E_HIA_PROFILE_AUTHORITY", "profile does not resolve to a retained server record")
        return self.get_json(decode_data(row["artifact"]), kind="profile")[0]
