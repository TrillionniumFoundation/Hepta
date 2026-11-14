"""Exact retained AgentStore construction and close policy; offline authoring only."""

class AgentStore:
    def __init__(self, root):
        from .hia_execution_budget import admitted_execution_budget, execution_budget_store
        from .hia_request_journal_native import admitted_request_journal, request_journal_store
        from .hia_artifact_namespace_native import admitted_artifact_namespace, artifact_namespace_store
        from .hia_slot_ledger_continuation_native import admitted_slot_ledger, slot_ledger_store
        budget_admission = admitted_execution_budget()
        request_admission = admitted_request_journal()
        namespace_admission = admitted_artifact_namespace()
        ledger_admission = admitted_slot_ledger(namespace_admission=namespace_admission,
                                                request_admission=request_admission)
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
        self.database = database
        database_info = database.lstat()
        if not stat.S_ISREG(database_info.st_mode):
            reject('E_HIA_STORE', 'journal must remain an ordinary file after opening')
        self.database_identity = (database_info.st_dev, database_info.st_ino)
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
        self.execution_budgets = None
        self.request_journal = None
        self.artifact_namespace = None
        self.slot_ledger = None
        try:
            self.database_sidecars = None
            if budget_admission is not None or request_admission is not None or namespace_admission is not None:
                # Capture the official connection's WAL namespace before a second
                # connection can open it. Never adopt a replacement sidecar as the
                # identity merely because a new connection can read it.
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
            if namespace_admission is None:
                self.request_journal = request_journal_store(self, request_admission)
            else:
                self.request_journal = request_journal_store(self, request_admission, shared_lock=self.lock)
            self.artifact_namespace = artifact_namespace_store(self, namespace_admission)
            self.slot_ledger = slot_ledger_store(self, ledger_admission)
        except BaseException as error:
            # Construction retains the main cleanup boundary. Close only owners
            # actually returned by earlier admissions, in ordinary close order.
            for owner in (self.slot_ledger, self.artifact_namespace,
                          self.request_journal, self.execution_budgets):
                if owner is not None:
                    try:
                        owner.close()
                    except BaseException as failure:
                        error.add_note('AgentStore construction cleanup failed: ' + type(failure).__name__)
            try:
                self.db.close()
            except BaseException as failure:
                error.add_note('AgentStore construction cleanup failed: ' + type(failure).__name__)
            raise

    def close(self):
        if self.slot_ledger is not None:
            self.slot_ledger.close()
        if self.artifact_namespace is not None:
            self.artifact_namespace.close()
        if self.request_journal is not None:
            self.request_journal.close()
        self.execution_budgets.close()
        self.db.close()
