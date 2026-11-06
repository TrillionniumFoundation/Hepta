"""Bounded single-account quota application; all balance transitions are HIA.

The trusted POSIX host owns the directory, lock, immutable event publication and
request identities. It never implements credit/reserve/consume/release arithmetic.
This local journal is not a payment system or an external-effect authority.
"""
from __future__ import annotations

import argparse
import ctypes
import fcntl
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import threading
import uuid

from hepta.hia_agent_assembly import assemble_program
from hepta.hia_program_runtime import execute_program
from hepta.hia_program_tools import decode_json

LIMIT = (1 << 31) - 1
MAX_RECORDS = 1024
MAX_RECORD_BYTES = 4096
VERSIONS = ("v1", "v2")
OPERATIONS = {"credit": 0, "reserve": 1, "consume": 2, "release": 3, "debit": 4}
SCHEMA = "hepta.hia.quota-event.v1"


class QuotaRejected(ValueError):
    """The request or retained journal does not meet the closed contract."""


class CommitUnknown(RuntimeError):
    """Publication may have happened; recover/retry the same request identity."""


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")


def unsigned32(value):
    if type(value) is not int or not 0 <= value < 1 << 32:
        raise QuotaRejected("exact u32 required; bool, float and overflow reject")
    return value


def request_id(value):
    if type(value) is not str or re.fullmatch(r"[A-Za-z0-9_-]{1,96}", value) is None:
        raise QuotaRejected("request_id must contain 1..96 ASCII letters, digits, _ or -")
    return value


def unpack(value):
    if type(value) is not int or not 0 <= value < 1 << 64:
        raise QuotaRejected("HIA did not return an exact u64")
    return value >> 62, {"available": value & LIMIT, "held": (value >> 31) & LIMIT}


def serialized(method):
    def guarded(self, *args, **kwargs):
        # Check before acquiring a lock which may have been held by a vanished
        # thread at fork. An inherited flock descriptor is not a new owner.
        if os.getpid() != self._owner_pid:
            raise QuotaRejected("ledger instance belongs to another process")
        with self._mutex:
            if self._active:
                raise QuotaRejected("reentrant ledger operation is not supported")
            self._active = True
            try:
                return method(self, *args, **kwargs)
            finally:
                self._active = False
    return guarded


class HIAEngine:
    """Immutable checked programs; native mode compiles them with no fallback."""

    def __init__(self, *, clang=None):
        self.programs = {version: assemble_program(
            Path(__file__).with_name(f"quota_{version}.hiaasm").read_bytes())
            for version in VERSIONS}
        from hepta.hia_static_budget import analyze_static_budget
        self.budgets = {version: analyze_static_budget(program,
            max_allocator_interactions=0, max_vm_ticks=128, max_call_depth=1,
            max_live_heap_bytes=0) for version, program in self.programs.items()}
        self.clang = clang
        self.backend = "native" if clang else "vm"
        self.build_receipts = {}
        self.libraries = {}
        self.entries = {}
        self.closed = False
        self.directory = tempfile.TemporaryDirectory(prefix="hia-quota-native-") if clang else None

    def identity(self, version):
        if version not in self.programs:
            raise QuotaRejected("unknown quota program version")
        return self.programs[version].sha256

    def transition(self, version, state, amount, operation, *, replay=False):
        if self.closed:
            raise QuotaRejected("HIA engine is closed")
        self.identity(version)
        args = [unsigned32(state["available"]), unsigned32(state["held"]),
                unsigned32(amount), unsigned32(operation)]
        if self.clang and not replay:
            if version not in self.entries:
                from hepta.hia_program_llvm import build_program_native
                path = Path(self.directory.name) / f"{version}.so"
                receipt = build_program_native(self.programs[version], path, clang=self.clang)
                if sha256(path.read_bytes()).hexdigest() != receipt["artifact_sha256"]:
                    raise QuotaRejected("private native artifact identity changed")
                library = ctypes.CDLL(str(path))
                entry = library.transition
                entry.argtypes = [ctypes.c_uint32] * 4
                entry.restype = ctypes.c_uint64
                self.libraries[version], self.entries[version] = library, entry
                self.build_receipts[version] = receipt
            result = int(self.entries[version](*args))
        else:
            result = execute_program(self.programs[version], "transition", args,
                                     max_steps=128, max_heap_bytes=0, max_call_depth=1)["result"]
        return result

    def close(self):
        # No attempt to unload live ctypes code. The loader reference remains
        # alive as long as this engine does; temporary files can be unlinked.
        if self.directory is not None:
            self.directory.cleanup()
            self.directory = None
        self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class QuotaLedger:
    """One held flock, bounded immutable records, replay before every mutation.

    The caller supplies a private directory on a local filesystem supporting
    flock, hard links and fsync. No other writer may ignore that lock. Directory
    rollback by an administrator and hostile same-account replacement are not
    detected by a local hash chain.
    """

    def __init__(self, directory, *, initial=None, engine=None):
        self._owner_pid = os.getpid()
        self._mutex, self._active = threading.RLock(), False
        self.path = Path(directory)
        self.engine = engine or HIAEngine()
        self.owns_engine = engine is None
        self.dir_fd = self.lock_fd = None
        if not self.path.exists():
            if initial is None:
                raise QuotaRejected("ledger does not exist; init is required")
            self.path.mkdir(mode=0o700)
        try:
            self.dir_fd = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            self.lock_fd = os.open("LOCK", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                                   0o600, dir_fd=self.dir_fd)
            if not stat.S_ISREG(os.fstat(self.lock_fd).st_mode):
                raise QuotaRejected("LOCK must be an ordinary file")
            try:
                fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise QuotaRejected("another owner holds the ledger lock") from exc
            self._reload()
            if not self.records:
                if initial is None:
                    raise QuotaRejected("empty ledger requires explicit initialization")
                unsigned32(initial)
                packed = self.engine.transition("v1", {"available": 0, "held": 0}, initial, 0)
                code, state = unpack(packed)
                if code:
                    raise QuotaRejected("initial quota exceeds the HIA capacity")
                self._publish({"kind": "init", "account": uuid.uuid4().hex,
                    "initial": initial, "version": "v1", "program_sha256": self.engine.identity("v1"),
                    "state": state})
                self._reload()
            elif initial is not None:
                raise QuotaRejected("initialization never overwrites an existing ledger")
        except BaseException:
            self.close()
            raise

    @serialized
    def close(self):
        if self.lock_fd is not None:
            os.close(self.lock_fd)
            self.lock_fd = None
        if self.dir_fd is not None:
            os.close(self.dir_fd)
            self.dir_fd = None
        if self.owns_engine:
            self.engine.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def _read_record(self, name):
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.dir_fd)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_RECORD_BYTES:
                raise QuotaRejected("record is not a bounded ordinary file")
            raw = stream.read(MAX_RECORD_BYTES + 1)
        if len(raw) > MAX_RECORD_BYTES:
            raise QuotaRejected("record exceeds byte budget")
        try:
            record = decode_json(raw)
        except ValueError as exc:
            raise QuotaRejected("record contains invalid JSON") from exc
        if type(record) is not dict or canonical(record) != raw:
            raise QuotaRejected("record must use the exact canonical JSON representation")
        return record

    def _reload(self):
        if self.dir_fd is None:
            raise QuotaRejected("ledger is closed")
        names = []
        staged = 0
        with os.scandir(self.dir_fd) as entries:
            for item in entries:
                if item.name == "LOCK":
                    continue
                if re.fullmatch(r"\.stage-[a-f0-9]{32}", item.name):
                    staged += 1
                    if staged > MAX_RECORDS:
                        raise QuotaRejected("orphan stage inventory exceeds recovery budget")
                    continue
                if re.fullmatch(r"[0-9]{8}\.json", item.name) is None:
                    raise QuotaRejected("unexpected ledger directory entry")
                names.append(item.name)
                if len(names) > MAX_RECORDS:
                    raise QuotaRejected("journal exceeds the fixed record budget")
        names.sort()
        self.records, self.requests = [], {}
        self.state, self.version, self.head = None, None, None
        for index, name in enumerate(names):
            if name != f"{index:08d}.json":
                raise QuotaRejected("committed record gap")
            record = self._read_record(name)
            if set(record) != {"schema", "sequence", "previous", "event"}:
                raise QuotaRejected("unexpected record fields")
            if (record["schema"] != SCHEMA or type(record["sequence"]) is not int
                    or record["sequence"] != index or record["previous"] != self.head):
                raise QuotaRejected("record identity, sequence or hash chain mismatch")
            event = record["event"]
            self._replay_event(event, index)
            self.head = sha256(canonical(record)).hexdigest()
            self.records.append(record)

    def _replay_event(self, event, index):
        if type(event) is not dict:
            raise QuotaRejected("event must be an object")
        kind = event.get("kind")
        if kind == "init":
            if index or set(event) != {"kind", "account", "initial", "version", "program_sha256", "state"}:
                raise QuotaRejected("invalid genesis event")
            if type(event["account"]) is not str or re.fullmatch(r"[a-f0-9]{32}", event["account"]) is None:
                raise QuotaRejected("invalid account identity")
            if event["version"] != "v1" or event["program_sha256"] != self.engine.identity("v1"):
                raise QuotaRejected("genesis program identity mismatch")
            code, state = unpack(self.engine.transition("v1", {"available": 0, "held": 0},
                                                        event["initial"], 0, replay=True))
            if code or canonical(event["state"]) != canonical(state):
                raise QuotaRejected("genesis does not replay through HIA")
            self.state, self.version = state, "v1"
            return
        if self.state is None:
            raise QuotaRejected("first record must be genesis")
        common = {"kind", "request_id", "request", "version", "program_sha256", "before", "after", "status", "code"}
        if set(event) != common:
            raise QuotaRejected("unexpected transaction fields")
        identity = request_id(event["request_id"])
        if identity in self.requests:
            raise QuotaRejected("duplicate committed request identity")
        if (event["version"] != self.version or event["program_sha256"] != self.engine.identity(self.version)
                or canonical(event["before"]) != canonical(self.state)):
            raise QuotaRejected("transaction version, source or previous state mismatch")
        request = event["request"]
        if kind == "apply":
            if type(request) is not dict or set(request) != {"amount", "operation"}:
                raise QuotaRejected("invalid apply request")
            unsigned32(request["amount"])
            unsigned32(request["operation"])
            if event["status"] == "cancelled":
                code, after = None, self.state
            else:
                code, after = unpack(self.engine.transition(self.version, self.state,
                    request["amount"], request["operation"], replay=True))
                if event["status"] != ("applied" if code == 0 else "rejected"):
                    raise QuotaRejected("transaction status differs from HIA replay")
        elif kind == "upgrade":
            if request != {"target": "v2", "program_sha256": self.engine.identity("v2")} or self.version != "v1":
                raise QuotaRejected("only an explicit v1 to v2 upgrade is supported")
            code, after = unpack(self.engine.transition("v2", self.state, 0, 0, replay=True))
            if code or after != self.state or event["status"] != "upgraded":
                raise QuotaRejected("upgrade did not preserve the admitted state schema")
            self.version = "v2"
        else:
            raise QuotaRejected("unknown journal event")
        if canonical(event["code"]) != canonical(code) or canonical(event["after"]) != canonical(after):
            raise QuotaRejected("committed result differs from HIA replay")
        self.state = dict(after)
        self.requests[identity] = (index, event)

    def _sync_directory(self):
        os.fsync(self.dir_fd)

    def _publish(self, event):
        if len(self.records) >= MAX_RECORDS:
            raise QuotaRejected("journal record budget exhausted; no implicit history deletion")
        record = {"schema": SCHEMA, "sequence": len(self.records), "previous": self.head, "event": event}
        raw = canonical(record)
        if len(raw) > MAX_RECORD_BYTES:
            raise QuotaRejected("event exceeds byte budget")
        stage = ".stage-" + uuid.uuid4().hex
        name = f"{len(self.records):08d}.json"
        published = False
        attempted = False
        try:
            fd = os.open(stage, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o400, dir_fd=self.dir_fd)
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            attempted = True
            os.link(stage, name, src_dir_fd=self.dir_fd, dst_dir_fd=self.dir_fd, follow_symlinks=False)
            published = True
            self._sync_directory()
        except BaseException as exc:
            if published or attempted:
                raise CommitUnknown("publication outcome or durability acknowledgment unknown; retry the same request_id") from exc
            raise
        finally:
            try:
                os.unlink(stage, dir_fd=self.dir_fd)
            except OSError:
                pass

    @serialized
    def snapshot(self):
        self._reload()
        return {"schema": "hepta.hia.quota-snapshot.v1", "state": dict(self.state),
                "version": self.version, "program_sha256": self.engine.identity(self.version),
                "committed_records": len(self.records), "head_sha256": self.head,
                "backend": self.engine.backend}

    def _existing(self, identity, kind, request):
        previous = self.requests.get(identity)
        if previous is None:
            return None
        index, event = previous
        if event["kind"] != kind or canonical(event["request"]) != canonical(request):
            raise QuotaRejected("request_id already belongs to a different request")
        try:
            self._sync_directory()
        except OSError as exc:
            raise CommitUnknown("recovered record exists; directory durability remains unknown") from exc
        return self._receipt(index, event, replayed=True)

    def _receipt(self, index, event, *, replayed):
        return {"schema": "hepta.hia.quota-receipt.v1", "sequence": index,
                "request_id": event["request_id"], "status": event["status"], "code": event["code"],
                "state": dict(event["after"]), "execution_version": event["version"],
                "program_sha256": event["program_sha256"], "replayed": replayed,
                "record_sha256": sha256(canonical(self.records[index])).hexdigest()}

    def _readback_receipt(self, identity):
        try:
            self._reload()
            index, event = self.requests[identity]
            return self._receipt(index, event, replayed=False)
        except BaseException as exc:
            raise CommitUnknown("publication completed but result readback failed; recover the same request_id") from exc

    @serialized
    def apply(self, identity, operation, amount, *, cancelled=lambda: False):
        identity, amount, operation = request_id(identity), unsigned32(amount), unsigned32(operation)
        self._reload()
        request = {"operation": operation, "amount": amount}
        existing = self._existing(identity, "apply", request)
        if existing is not None:
            return existing
        decision = cancelled()
        if type(decision) is not bool:
            raise QuotaRejected("cancellation observation must be an exact bool")
        if decision:
            code, after, status = None, dict(self.state), "cancelled"
        else:
            code, after = unpack(self.engine.transition(self.version, self.state, amount, operation))
            status = "applied" if code == 0 else "rejected"
            decision = cancelled()
            if type(decision) is not bool:
                raise QuotaRejected("cancellation observation must be an exact bool")
            if decision:
                code, after, status = None, dict(self.state), "cancelled"
        event = {"kind": "apply", "request_id": identity, "request": request,
                 "version": self.version, "program_sha256": self.engine.identity(self.version),
                 "before": dict(self.state), "after": after, "code": code, "status": status}
        self._publish(event)
        return self._readback_receipt(identity)

    @serialized
    def upgrade(self, identity, target="v2"):
        identity = request_id(identity)
        if type(target) is not str or target != "v2":
            raise QuotaRejected("downgrade and unknown version reject")
        self._reload()
        request = {"target": target, "program_sha256": self.engine.identity(target)}
        existing = self._existing(identity, "upgrade", request)
        if existing is not None:
            return existing
        if self.version != "v1":
            raise QuotaRejected("new upgrade request requires current version v1")
        code, after = unpack(self.engine.transition(target, self.state, 0, 0))
        if code or after != self.state:
            raise QuotaRejected("migration does not preserve the fixed state schema")
        event = {"kind": "upgrade", "request_id": identity, "request": request,
                 "version": self.version, "program_sha256": self.engine.identity(self.version),
                 "before": dict(self.state), "after": after, "code": 0, "status": "upgraded"}
        self._publish(event)
        return self._readback_receipt(identity)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ledger", required=True)
    parser.add_argument("--clang", help="use actual Clang 20+ native HIA; absence selects the explicit VM")
    commands = parser.add_subparsers(dest="command", required=True)
    initialize = commands.add_parser("init")
    initialize.add_argument("--initial", type=int, required=True)
    commands.add_parser("status")
    apply = commands.add_parser("apply")
    apply.add_argument("request_id")
    apply.add_argument("operation", choices=OPERATIONS)
    apply.add_argument("amount", type=int)
    apply.add_argument("--cancel", action="store_true")
    upgrade = commands.add_parser("upgrade")
    upgrade.add_argument("request_id")
    args = parser.parse_args(argv)
    try:
        with HIAEngine(clang=args.clang) as engine, QuotaLedger(args.ledger,
                initial=args.initial if args.command == "init" else None, engine=engine) as ledger:
            if args.command in {"init", "status"}:
                result = ledger.snapshot()
            elif args.command == "upgrade":
                result = ledger.upgrade(args.request_id)
            else:
                result = ledger.apply(args.request_id, OPERATIONS[args.operation], args.amount,
                                      cancelled=lambda: args.cancel)
            print(canonical(result).decode("ascii"), end="")
        return 0
    except CommitUnknown as exc:
        print(canonical({"status": "unknown", "error": type(exc).__name__,
                         "request_id": getattr(args, "request_id", None), "message": str(exc)}).decode("ascii"), end="")
        return 3
    except (ValueError, OSError) as exc:
        print(canonical({"status": "error", "error": type(exc).__name__, "message": str(exc)}).decode("ascii"), end="")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
