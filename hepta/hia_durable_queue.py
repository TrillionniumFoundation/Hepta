"""Bounded durable intent/commit for the existing pure u64 native owner.

The journal stores data, never executable code or proof authority. Recovery
rebuilds and independently admits the same Core/implementation/policy/artifact
before replaying an unacknowledged intent from its last committed input state.
This is safe only for OwnedAdaptiveRuntime's closed, total, effect-free scalar
profile. It does not replay external effects, restore pointers or attest disk
rollback resistance. Linux local storage and an exclusive trusted directory
are required; fsync calls are not a power-loss certification of a filesystem.
"""
from __future__ import annotations

import copy
try:
    import fcntl
except ImportError:
    fcntl = None
from hashlib import sha256
import json
import os
from pathlib import Path
import secrets
import stat
import threading

from .hia_json_preflight import preflight_hia_json
from .hia_optimization import _policy
from .hia_stateful import (OwnedAdaptiveRuntime, _adapter_identity,
                          _snapshot_queue_work_item, _u64)

PROFILE = "hepta.hia.durable-pure-u64-queue.v1"
_MAX_BYTES = 8 * 1024 * 1024
_MAX_CELLS = 4096
_JOURNAL = "checkpoint.json"


class DurableQueueRejected(ValueError):
    pass


def _reject(reason):
    raise DurableQueueRejected("E_STATE_DURABLE: " + reason)


def _wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _digest(value):
    return sha256(_wire(value)).hexdigest()


def _source_identity():
    return _digest({"owner": _adapter_identity(),
                    "journal": sha256(Path(__file__).read_bytes()).hexdigest()})


def _integer(value, lo, hi, name):
    if type(value) is not int or not lo <= value <= hi:
        _reject("invalid bounded " + name)
    return value


def _hex(value, length, name):
    if (type(value) is not str or len(value) != length
            or any(c not in "0123456789abcdef" for c in value)):
        _reject("invalid " + name)
    return value


def _request_id(value):
    if (type(value) is not str or not 1 <= len(value) <= 64
            or not value.isascii() or not value.isprintable()):
        _reject("request ID must be bounded printable built-in ASCII")
    return value


def _values(values):
    if type(values) not in {list, tuple} or not 1 <= len(values) <= _MAX_CELLS:
        _reject("one to 4096 state cells required")
    frozen = tuple(values[:_MAX_CELLS + 1])
    if not 1 <= len(frozen) <= _MAX_CELLS:
        _reject("state changed during capture")
    return [_u64(value) for value in frozen]


def _items(items, cells):
    if type(items) is not list or not 1 <= len(items) <= 128:
        _reject("one to 128 explicit work items required")
    captured = tuple(items[:129])
    if not 1 <= len(captured) <= 128:
        _reject("queue changed during capture")
    result = []
    for item in captured:
        slot, delta, count = _snapshot_queue_work_item(item)
        result.append({"slot": _integer(slot, 0, cells - 1, "slot"),
                       "delta": _u64(delta),
                       "iterations": _integer(count, 1, 1_000_000_000, "iterations")})
    _integer(sum(row["iterations"] for row in result), 1, 1_000_000_000, "queue steps")
    return result


def _limits(requests, attempts, owner_starts, steps):
    return {"requests": _integer(requests, 1, 32, "request limit"),
            "attempts": _integer(attempts, 1, 65536, "attempt limit"),
            "owner_starts": _integer(owner_starts, 1, 65536, "owner-start limit"),
            "steps": _integer(steps, 1, 1_000_000_000, "total admitted-step limit")}


def _admit(program, policy):
    # Reuse the complete existing closed profile, including exact two-u64
    # entry ABI, total helpers, effect rejection and bounded acyclic calls.
    checked, _ = OwnedAdaptiveRuntime._admit_profile(object.__new__(OwnedAdaptiveRuntime), program)
    return checked, _policy(policy)


def _native_binding(owner):
    image = owner._images[owner._current]
    return {"artifact_sha256": image.artifact_sha256,
            "driver_artifact_sha256": owner._driver_receipt["artifact_sha256"],
            "compiler_sha256": owner._driver_receipt["compiler_sha256"]}


class DurableOwnedQueue:
    """Single-writer persistent queue over privately owned pure native state.

    Request history is never compacted or recredited. A full finite journal
    refuses new work. Every recovery consumes a persisted owner-start credit,
    and every native queue attempt consumes a persisted execution credit.
    A failed/uncertain operation poisons this live wrapper until it is closed
    and recovered. The private native owner is never exposed as a capability.
    """

    @classmethod
    def _storage(cls, directory):
        if fcntl is None or os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
            _reject("Linux descriptor-relative storage is required")
        self = object.__new__(cls)
        self._pid = os.getpid()
        self._mutex = threading.RLock()
        self._owner = self._data = None
        self._closed = self._failed = False
        self._dirfd = self._lockfd = None
        try:
            self._dirfd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
            directory_info = os.fstat(self._dirfd)
            if directory_info.st_uid != os.geteuid() or stat.S_IMODE(directory_info.st_mode) & 0o077:
                _reject("journal directory must be private and owned by this user")
            self._lockfd = os.open("owner.lock", os.O_CREAT | os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW,
                                   0o600, dir_fd=self._dirfd)
            info = os.fstat(self._lockfd)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) & 0o077):
                _reject("lock must be one ordinary private file")
            try:
                fcntl.flock(self._lockfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise DurableQueueRejected("E_STATE_DURABLE: journal already has a live owner") from exc
            return self
        except BaseException:
            self.close()
            raise

    @classmethod
    def create(cls, program, directory, build_directory, values, *, clang="clang", policy=None,
               max_requests=32, max_attempts=64, max_owner_starts=64, max_total_steps=1_000_000_000):
        checked, admitted_policy = _admit(program, policy)
        values = _values(values)
        limits = _limits(max_requests, max_attempts, max_owner_starts, max_total_steps)
        source = _source_identity()
        directory = Path(directory).absolute()
        directory.mkdir(mode=0o700, parents=False, exist_ok=False)
        # Persist the new directory entry as well as every later journal rename.
        parent = os.open(directory.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
        self = cls._storage(directory)
        try:
            self._owner = OwnedAdaptiveRuntime(checked, build_directory, values,
                                               clang=clang, policy=admitted_policy)
            if source != _source_identity():
                _reject("implementation changed while creating the owner")
            self._store({"schema": PROFILE, "journal_id": secrets.token_hex(16),
                "core_sha256": checked.sha256, "source_sha256": source,
                "policy_sha256": _digest(admitted_policy), "native_binding": _native_binding(self._owner),
                "limits": limits, "owner_starts_used": 1, "attempts_used": 0,
                "admitted_steps": 0, "committed_steps": 0, "values": values, "records": []})
            return self
        except BaseException:
            self.close()
            raise

    @classmethod
    def recover(cls, program, directory, build_directory, *, journal_id, clang="clang", policy=None):
        _hex(journal_id, 32, "expected journal identity")
        checked, admitted_policy = _admit(program, policy)
        self = cls._storage(directory)
        try:
            data = self._read()
            self._validate(data)
            if (data["journal_id"] != journal_id or data["core_sha256"] != checked.sha256
                    or data["source_sha256"] != _source_identity()
                    or data["policy_sha256"] != _digest(admitted_policy)):
                _reject("journal, Core, implementation or policy identity changed")
            if data["owner_starts_used"] >= data["limits"]["owner_starts"]:
                _reject("persistent owner-start budget exhausted")
            # Commit before any fresh native build/load. A failed build cannot
            # mint another recovery credit on the next process restart.
            data["owner_starts_used"] += 1
            self._store(data)
            self._owner = OwnedAdaptiveRuntime(checked, build_directory, data["values"],
                                               clang=clang, policy=admitted_policy)
            if (data["source_sha256"] != _source_identity()
                    or _native_binding(self._owner) != data["native_binding"]):
                _reject("rebuilt native artifact, compiler or implementation changed")
            return self
        except BaseException:
            self.close()
            raise

    def _read(self):
        fd = os.open(_JOURNAL, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
                     dir_fd=self._dirfd)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= _MAX_BYTES
                    or info.st_nlink != 1 or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) & 0o077):
                _reject("journal is not a bounded ordinary file")
            raw = os.pread(fd, _MAX_BYTES + 1, 0)
            after = os.fstat(fd)
            stable = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_size,
                                    value.st_mtime_ns, value.st_ctime_ns)
            if len(raw) != info.st_size or stable(after) != stable(info):
                _reject("journal changed during read")
        finally:
            os.close(fd)
        try:
            text = raw.decode("utf-8")
            preflight_hia_json(text, max_nodes=250000, max_depth=12)
            envelope = json.loads(text)
            if (type(envelope) is not dict or set(envelope) != {"payload", "sha256"}
                    or _wire(envelope) != raw or envelope["sha256"] != _digest(envelope["payload"])):
                _reject("journal envelope or integrity digest differs")
            return envelope["payload"]
        except (ValueError, OverflowError, UnicodeError, RecursionError) as exc:
            raise DurableQueueRejected("E_STATE_DURABLE: malformed or truncated journal") from exc

    @staticmethod
    def _validate(data):
        fields = {"schema", "journal_id", "core_sha256", "source_sha256", "policy_sha256", "native_binding",
                  "limits", "owner_starts_used", "attempts_used", "admitted_steps", "committed_steps", "values", "records"}
        if type(data) is not dict or set(data) != fields or data["schema"] != PROFILE:
            _reject("journal schema differs")
        _hex(data["journal_id"], 32, "journal identity")
        for key in ("core_sha256", "source_sha256", "policy_sha256"):
            _hex(data[key], 64, key)
        binding = data["native_binding"]
        if type(binding) is not dict or set(binding) != {"artifact_sha256", "driver_artifact_sha256", "compiler_sha256"}:
            _reject("native binding shape differs")
        for key, value in binding.items():
            _hex(value, 64, key)
        limits = data["limits"]
        if type(limits) is not dict or set(limits) != {"requests", "attempts", "owner_starts", "steps"}:
            _reject("persistent budget shape differs")
        _limits(limits["requests"], limits["attempts"], limits["owner_starts"], limits["steps"])
        _integer(data["owner_starts_used"], 1, limits["owner_starts"], "used owner starts")
        _integer(data["attempts_used"], 0, limits["attempts"], "used attempts")
        _integer(data["admitted_steps"], 0, limits["steps"], "admitted steps")
        _integer(data["committed_steps"], 0, data["admitted_steps"], "committed steps")
        values = _values(data["values"])
        records = data["records"]
        if type(records) is not list or len(records) > limits["requests"]:
            _reject("persistent request budget exceeded")
        seen, admitted, committed, attempts = set(), 0, 0, 0
        latest = None
        for index, record in enumerate(records):
            if (type(record) is not dict
                    or set(record) != {"request_id", "items", "sha256", "status", "attempts", "result"}):
                _reject("request record shape differs")
            key = _request_id(record["request_id"])
            if key in seen:
                _reject("repeated persistent request identity")
            seen.add(key)
            items = _items(record["items"], len(values))
            if record["sha256"] != _digest(items):
                _reject("request digest differs")
            steps = sum(item["iterations"] for item in items)
            admitted += steps
            attempts += _integer(record["attempts"], 0, limits["attempts"], "request attempts")
            if record["status"] == "pending":
                if index != len(records) - 1 or record["result"] is not None:
                    _reject("only the final request may be pending")
            elif record["status"] == "committed":
                result = record["result"]
                if (type(result) is not dict or set(result) != {"request_id", "queue_sha256", "executed_steps",
                        "final_values", "native_deployment_cost_ns", "durable_ack", "authority"}
                        or result["request_id"] != key or result["queue_sha256"] != record["sha256"]
                        or type(result["executed_steps"]) is not int or result["executed_steps"] != steps
                        or result["durable_ack"] is not True or result["authority"] != "DENY_ALL"
                        or record["attempts"] < 1):
                    _reject("committed result binding differs")
                latest = _values(result["final_values"])
                if len(latest) != len(values):
                    _reject("committed state extent changed")
                _integer(result["native_deployment_cost_ns"], 0, 2**128 - 1, "native measured cost")
                committed += steps
            else:
                _reject("unknown persistent request status")
        if (admitted != data["admitted_steps"] or committed != data["committed_steps"]
                or attempts != data["attempts_used"] or (latest is not None and latest != values)):
            _reject("persistent state or budget accounting differs")

    def _store(self, data):
        self._validate(data)
        raw = _wire({"payload": data, "sha256": _digest(data)})
        if len(raw) > _MAX_BYTES:
            _reject("encoded journal byte budget exceeded")
        # A fixed uncommitted slot keeps interrupted writes bounded across
        # restarts. The lock covers its exclusive ownership. Old uncommitted
        # bytes are never interpreted as a checkpoint or native authority.
        temporary = "checkpoint.next"
        fd = None
        try:
            try:
                os.unlink(temporary, dir_fd=self._dirfd)
            except FileNotFoundError:
                pass
            fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                         0o600, dir_fd=self._dirfd)
            offset = 0
            while offset < len(raw):
                count = os.write(fd, raw[offset:])
                if count <= 0:
                    _reject("journal write made no progress")
                offset += count
            os.fsync(fd)
            closing, fd = fd, None
            os.close(closing)
            os.replace(temporary, _JOURNAL, src_dir_fd=self._dirfd, dst_dir_fd=self._dirfd)
            os.fsync(self._dirfd)
            self._data = copy.deepcopy(data)
        except BaseException:
            # In particular, replace may have committed before a directory
            # fsync failure. Never continue with an assumed earlier state.
            self._failed = True
            raise
        finally:
            if fd is not None:
                os.close(fd)

    def _open(self):
        if self._closed or self._failed or self._owner is None:
            _reject("owner closed or uncertain; close and recover before further execution")
        if self._data["source_sha256"] != _source_identity():
            self._failed = True
            _reject("implementation identity changed")

    def _same_process(self):
        # flock follows an open-file description across fork; it does not
        # distinguish the parent's and child's copied Python owner objects.
        # Check before touching an inherited RLock, which may have been held
        # by a thread that does not exist in the child.
        if os.getpid() != self._pid:
            _reject("forked owner cannot run; close inherited storage and recover independently")

    def execute(self, request_id, items, *, expected_committed_steps=None):
        """Serialize one request, optionally conditional on a durable revision.

        The committed-step counter is a monotone revision: every admitted
        request has positive work and history is never compacted or reset.
        Check it under the same mutex as intent admission and native execution.
        For a duplicate ID the precondition refers to that original request's
        input revision, so a lost ACK can be retried after later commits.
        """
        self._same_process()
        key = _request_id(request_id)
        if expected_committed_steps is not None:
            _integer(expected_committed_steps, 0, 1_000_000_000, "expected committed revision")
        with self._mutex:
            self._open()
            frozen = _items(items, len(self._data["values"]))
            digest = _digest(frozen)
            prefix_steps = 0
            for record in self._data["records"]:
                if record["request_id"] == key:
                    if record["sha256"] != digest:
                        _reject("request ID already binds different work")
                    if expected_committed_steps is not None and expected_committed_steps != prefix_steps:
                        _reject("request input revision differs from the expected committed revision")
                    if record["status"] == "committed":
                        result = {**copy.deepcopy(record["result"]), "duplicate_ack": True, "native_executed": False}
                    else:
                        result = self._attempt_pending()
                    return self._revision_result(result, prefix_steps)
                if record["status"] == "committed":
                    prefix_steps += record["result"]["executed_steps"]
            if (expected_committed_steps is not None
                    and expected_committed_steps != self._data["committed_steps"]):
                _reject("stale expected committed revision")
            limits = self._data["limits"]
            if self._data["records"] and self._data["records"][-1]["status"] == "pending":
                _reject("recover the pending request before accepting new work")
            steps = sum(item["iterations"] for item in frozen)
            if (len(self._data["records"]) >= limits["requests"]
                    or self._data["admitted_steps"] + steps > limits["steps"]
                    or self._data["attempts_used"] >= limits["attempts"]):
                _reject("persistent request, work or execution budget exhausted")
            data = copy.deepcopy(self._data)
            data["records"].append({"request_id": key, "items": frozen, "sha256": digest,
                                    "status": "pending", "attempts": 0, "result": None})
            data["admitted_steps"] += steps
            self._store(data)
            return self._revision_result(self._attempt_pending(), prefix_steps)

    @staticmethod
    def _revision_result(result, prefix_steps):
        # Derived from the validated, append-only history; not a second stored
        # revision counter whose crash consistency would need reconciliation.
        return {**result, "input_committed_steps": prefix_steps,
                "output_committed_steps": prefix_steps + result["executed_steps"]}

    def resume(self):
        self._same_process()
        with self._mutex:
            self._open()
            if not self._data["records"] or self._data["records"][-1]["status"] != "pending":
                _reject("no pending durable intent")
            prefix_steps = self._data["committed_steps"]
            return self._revision_result(self._attempt_pending(), prefix_steps)

    def _attempt_pending(self):
        data = copy.deepcopy(self._data)
        if data["attempts_used"] >= data["limits"]["attempts"]:
            _reject("persistent execution-attempt budget exhausted")
        record = data["records"][-1]
        data["attempts_used"] += 1
        record["attempts"] += 1
        # The attempt is durable before submit/execute. A process that dies
        # after this point loses a credit, including zero-progress attempts.
        self._store(data)
        try:
            token = self._owner.submit_queue(record["items"])
            receipt = self._owner.execute_committed(token)
            steps = sum(item["iterations"] for item in record["items"])
            if (receipt["status"] != "completed" or receipt["executed_steps"] != steps
                    or receipt["queue_sha256"] != record["sha256"]
                    or receipt["cost_accounting_complete"] is not True
                    or receipt["replayed_steps"] != 0):
                _reject("native execution did not provide one complete pure queue result")
            final_values = _values(receipt["final_values"])
            if len(final_values) != len(data["values"]):
                _reject("native state extent changed")
            result = {"request_id": record["request_id"], "queue_sha256": record["sha256"],
                      "executed_steps": steps, "final_values": final_values,
                      "native_deployment_cost_ns": receipt["deployment_cost_ns"],
                      "durable_ack": True, "authority": "DENY_ALL"}
            record.update(status="committed", result=result)
            data["values"] = final_values
            data["committed_steps"] += steps
            # The acknowledgment follows file fsync, atomic replacement and
            # directory fsync. A lost acknowledgment is served by request ID.
            self._store(data)
            return {**copy.deepcopy(result), "duplicate_ack": False, "native_executed": True}
        except BaseException:
            self._failed = True
            raise

    def snapshot(self):
        self._same_process()
        with self._mutex:
            return {"profile": PROFILE, "journal": copy.deepcopy(self._data),
                    "closed": self._closed, "uncertain": self._failed,
                    "recovery_scope": "same-source-pure-u64-last-committed-state",
                    "serialized_proof_authority": False, "external_effect_exactly_once": False,
                    "power_loss_certified": False, "hostile_storage_rollback_resistant": False,
                    "device_recovery_supported": False, "full_cost_advantage_proved": False,
                    "concurrent_admission": "mutex-serialized-conditional-durable-revision",
                    "external_pointer_borrow_supported": False,
                    "device_permissions": [],
                    "authority": "DENY_ALL", "safety_certificate": False}

    def close(self):
        if os.getpid() != self._pid:
            # Drop only this process's descriptor references, without taking
            # an inherited mutex or calling into a potentially interrupted
            # native owner. Closing does not unlock the parent's flock.
            self._closed = True
            self._release_storage()
            return
        with self._mutex:
            if self._closed:
                return
            self._closed = True
            try:
                if self._owner is not None:
                    self._owner.close()
            finally:
                # Descriptor ownership is revoked before close. Ambiguous
                # close errors are never retried on a recycled fd number.
                self._release_storage()

    def _release_storage(self):
        lockfd, self._lockfd = self._lockfd, None
        dirfd, self._dirfd = self._dirfd, None
        try:
            if lockfd is not None:
                os.close(lockfd)
        finally:
            if dirfd is not None:
                os.close(dirfd)

    def __enter__(self):
        self._same_process()
        with self._mutex:
            self._open()
        return self

    def __exit__(self, *unused):
        self.close()

    def __copy__(self):
        _reject("durable owner cannot be copied")

    def __deepcopy__(self, memo):
        return self.__copy__()
