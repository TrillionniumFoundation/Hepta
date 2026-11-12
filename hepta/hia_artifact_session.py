"""Bounded reuse of internally proved, self-built checksum-workload artifacts.

This extends the existing private prepared-proof boundary for a narrow research
driver. It is not a general executor or production publisher. No serialized
receipt or foreign DSO can create an admission. Actual workload execution stays
in a child process; the controller never calls an effectful kernel in-process.
Python, the checker, LLVM, the supplied host driver and OS remain trusted.
"""
from __future__ import annotations

from dataclasses import dataclass
try:
    import fcntl
except ImportError:
    fcntl = None
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import secrets
import shutil
import stat
import subprocess
import threading
import time

from .hia_adaptive import _NativeRelease
from .hia_guarded_optimization import (
    _compose, _freeze, build_guarded_native, guarded_checker_identity)
from .hia_multiversion import PublicationCancellation
from .hia_narrowing import (
    _freeze_chain, build_guarded_narrowed_native, chain_checker_identity)
from .hia_native_differential import _pin_native_artifact
from .hia_optimization import _policy, _solver_identity, build_optimized_native
from .hia_prepared import _issue, _matches, _reuse
from .hia_program import verify_program
from .hia_program_llvm import TARGET, _implementation_hash
from .hia_translation_validation import QUALIFIED_CORE_SCHEMAS
from .native_tool_identity import digest_executable

PROFILE = "hepta.hia.prepared-checksum-artifact-session.v1"
_SEALS = 0x0008 | 0x0004 | 0x0002 | 0x0001
_GET_SEALS = getattr(fcntl, "F_GET_SEALS", 1034)


class ArtifactSessionRejected(ValueError):
    pass


def _reject(reason):
    raise ArtifactSessionRejected("E_HIA_ARTIFACT_SESSION: " + reason)


def _wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _identity():
    files = ("hia_artifact_session.py", "hia_prepared.py", "hia_adaptive.py",
             "hia_native_differential.py", "hia_multiversion.py", "native_tool_identity.py")
    return sha256(_wire({"files": {name: sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
                                    for name in files},
        "guarded_checker": guarded_checker_identity(), "chain_checker": chain_checker_identity(),
        "native_emitter": _implementation_hash()})).hexdigest()


def _profile(program):
    checked = verify_program(program)
    data = checked.as_dict()
    if data["schema"] not in QUALIFIED_CORE_SCHEMAS or len(data["functions"]) != 1:
        _reject("one v1-v7 scalar-export function is required")
    fn = data["functions"][0]
    if (fn["name"] != "full_lifecycle" or checked.scalar_entrypoints != frozenset({"full_lifecycle"})
            or [p["type"] for p in fn["params"]] != ["usize", "u32"] or fn["returns"] != ["u64"]
            or any(op["op"] == "call" for block in fn["blocks"] for op in block["ops"])):
        _reject("only the registered nonrecursive checksum-workload ABI is supported")
    return checked, {"schema": PROFILE, "target": TARGET, "entry": "full_lifecycle",
        "parameters": ["usize", "u32"], "returns": ["u64"], "effects": fn["effects"],
        "persistent_owners": [], "persistent_loans": [], "execution": "fresh-child-process"}


@dataclass(eq=False)
class _Image:
    program: object
    state: dict
    artifact_sha256: str
    receipt: dict


@dataclass(eq=False)
class _Entry:
    token: str
    generation: int
    image: _Image
    proof: object
    fd: int | None
    fd_identity: tuple
    release: _NativeRelease
    charged_bytes: int
    artifact_bytes: int
    metadata_bytes: int
    parent: object = None
    leases: int = 0
    dependents: int = 0
    retired: bool = False


class ArtifactLease:
    """A noncopyable borrow; a run/close race is serialized by its own lock."""
    def __init__(self, session, entry):
        self._session, self._entry = session, entry
        self._generation, self._closed = entry.generation, False
        self._lock = threading.RLock()

    @property
    def info(self):
        with self._lock:
            if self._closed:
                _reject("lease is closed")
            return self._session._entry_info(self._entry)

    def run(self, n, calls, seed, *, timeout=10):
        with self._lock:
            if self._closed:
                _reject("lease is closed")
            return self._session._run(self._entry, self._generation, n, calls, seed, timeout)

    def close(self):
        with self._lock:
            if not self._closed:
                self._closed = True
                session, entry = self._session, self._entry
                self._session = self._entry = None
                session._release_lease(entry)

    def __enter__(self):
        with self._lock:
            if self._closed:
                _reject("lease is closed")
        return self

    def __exit__(self, *unused):
        self.close()

    def __copy__(self):
        _reject("leases cannot be copied; acquire another bounded lease")

    def __deepcopy__(self, memo):
        return self.__copy__()


class PreparedArtifactSession:
    """Host-owned finite artifact/proof leases; no receipt-import capability.

    Entry/byte limits count held and uncertain-release resources. The byte
    bound covers retained canonical metadata and sealed images, not Python
    object overhead, build temporaries, child heap, allocator RSS or disk files.
    Published build files remain as evidence. Forgetting a lease consumes its
    finite slot; close must be explicit or use the context-manager protocol.
    """
    def __init__(self, directory, *, clang="clang", policy=None, max_entries=8,
                 max_retained_bytes=32 * 1024 * 1024, max_artifact_bytes=1024 * 1024,
                 max_metadata_bytes=1024 * 1024, max_leases=16, max_executions=256):
        if fcntl is None or platform.system() != "Linux" or platform.machine() not in {"x86_64", "amd64"}:
            _reject("only the qualified Linux x86-64 host is supported")
        for name, value, lo, hi in (("entries", max_entries, 1, 64), ("retained bytes", max_retained_bytes, 1, 256*1024*1024),
            ("artifact bytes", max_artifact_bytes, 1, 64*1024*1024), ("metadata bytes", max_metadata_bytes, 1, 16*1024*1024),
            ("leases", max_leases, 1, 256), ("executions", max_executions, 1, 65536)):
            if type(value) is not int or not lo <= value <= hi:
                _reject("invalid bounded " + name)
        import z3
        self._policy = _policy(policy)
        if self._policy["target"] != TARGET:
            _reject("policy target differs from the registered host")
        self._policy_wire = _wire(self._policy)
        self._implementation, self._solver = _identity(), _solver_identity(z3)
        found = shutil.which(clang)
        if found is None:
            _reject("an actual executable Clang driver is required")
        self._clang = str(Path(found).resolve())
        self._clang_sha = digest_executable(self._clang)
        self._directory = Path(directory).absolute()
        if self._directory.exists() or self._directory.is_symlink():
            _reject("a new private build directory is required")
        self._directory.mkdir(mode=0o700, parents=True)
        self._scope = secrets.token_hex(16)
        self._lock, self._writer = threading.RLock(), threading.Lock()
        self._entries, self._pending = {}, {}
        self._driver = None
        self._driver_attempted = False
        self._closed = self._invalidated = False
        self._limits = {"entries": max_entries, "bytes": max_retained_bytes, "artifact": max_artifact_bytes,
                        "metadata": max_metadata_bytes, "leases": max_leases, "executions": max_executions}
        self._charged = self._reserved = self._leased = self._next = self._executions = 0
        self._proof_attempts = self._admissions = self._runs_failed = 0

    def _open(self):
        if self._closed or self._invalidated:
            _reject("session is closed or permanently invalidated")

    def _reserve(self, amount, *, entry):
        self._open()
        if entry and len(self._entries) + len(self._pending) >= self._limits["entries"]:
            _reject("entry budget exhausted, including unresolved releases")
        if self._charged + self._reserved + amount > self._limits["bytes"]:
            _reject("retained-byte reservation exhausted")
        self._reserved += amount

    def _pin_close_owner(self, token, reserved):
        def close(fd):
            release = _NativeRelease(None, fd)
            release.attempt()
            if not release.complete:
                with self._lock:
                    # Pinning opens the read fd first; an uncertain read close
                    # aborts before creating the memfd. Thus this attempt can
                    # contribute at most one untransferred descriptor debt.
                    self._pending[token + ":pin"] = {"release": release, "charged_bytes": reserved,
                        "reason": "untransferred pin descriptor release uncertain"}
                    self._charged += reserved
                _reject("pin descriptor close is uncertain; no retry or admission")
        return close

    def bind_driver(self, driver, expected_sha256):
        """Pin one trusted host harness after the session already has an owner."""
        # A format-invalid but 64-character value must not consume this
        # one-shot binding, stat a path, or enter the native pinning routine.
        # hashlib.hexdigest() is exactly 64 lowercase ASCII hex characters.
        if (type(expected_sha256) is not str or len(expected_sha256) != 64
                or any(ch not in "0123456789abcdef" for ch in expected_sha256)):
            _reject("driver requires its expected SHA-256")
        with self._writer, self._lock:
            if self._driver_attempted:
                _reject("driver binding can be attempted only once")
            self._reserve(self._limits["artifact"], entry=False)
            self._driver_attempted = True
            reserved, fd = self._limits["artifact"], None
            unpublished = _NativeRelease(None, None)
            before_charge = self._charged
            try:
                path = Path(driver)
                if path.stat().st_size > self._limits["artifact"]:
                    _reject("driver exceeds the reserved artifact size")
                raw, _, fd = _pin_native_artifact(path, maximum_bytes=self._limits["artifact"],
                    close_owner=self._pin_close_owner("driver", reserved))
                unpublished.fd = fd
                self._driver = {"fd": fd, "release": unpublished, "bytes": len(raw),
                    "sha256": sha256(raw).hexdigest(), "identity": self._fd_identity(fd)}
                self._charged += len(raw)
                if len(raw) > reserved or self._driver["sha256"] != expected_sha256:
                    _reject("pinned driver does not match the host build identity")
            except BaseException:
                self._closed = True
                if self._driver is not None and self._driver["release"] is unpublished:
                    # Publication and accounting can be interrupted separately.
                    # Reconcile this owned driver before attempting its release.
                    self._charged = before_charge + self._driver["bytes"]
                    self._collect_driver()
                elif fd is not None:
                    unpublished.fd = fd
                    unpublished.attempt()
                    if not unpublished.complete:
                        self._pending["driver:unpublished"] = {"release": unpublished, "charged_bytes": reserved,
                            "reason": "unpublished driver release uncertain"}
                        self._charged += reserved
                raise
            finally:
                self._reserved -= reserved

    @staticmethod
    def _fd_identity(fd):
        value = os.fstat(fd)
        return value.st_dev, value.st_ino, value.st_size

    def _check_fd(self, fd, identity, expected_sha):
        if (fd is None or self._fd_identity(fd) != identity or not stat.S_ISREG(os.fstat(fd).st_mode)
                or fcntl.fcntl(fd, _GET_SEALS) & _SEALS != _SEALS
                or sha256(os.pread(fd, identity[2] + 1, 0)).hexdigest() != expected_sha):
            _reject("sealed artifact identity or bytes changed")

    def _check_implementation(self):
        import z3
        try:
            same = (_wire(self._policy) == self._policy_wire and _identity() == self._implementation
                    and _solver_identity(z3) == self._solver
                    and digest_executable(self._clang) == self._clang_sha)
        except Exception:
            self._invalidated = True
            raise
        if not same:
            self._invalidated = True
            _reject("Core/proof implementation, solver, policy or compiler identity changed")

    def prepare_base(self, program, *, cancellation=None, max_prepare_ns=120_000_000_000):
        return self._prepare(program, None, None, cancellation, max_prepare_ns)

    def prepare_guarded(self, base_token, proposal, *, cancellation=None, max_prepare_ns=120_000_000_000):
        return self._prepare(None, base_token, proposal, cancellation, max_prepare_ns)

    def prepare_guarded_narrowed(self, base_token, proposal, *, cancellation=None,
                                max_prepare_ns=120_000_000_000):
        """Independently prove both stages before issuing one bounded lease entry.

        The immutable baseline remains the proof ancestor. This does not admit
        an externally supplied proof, an unguarded narrowing, or a foreign DSO.
        """
        return self._prepare(None, base_token, proposal, cancellation, max_prepare_ns,
                             guarded_narrowed=True)

    def _prepare(self, program, base_token, proposal, cancellation, max_prepare_ns,
                 *, guarded_narrowed=False):
        started = time.monotonic_ns()
        if cancellation is None:
            cancellation = PublicationCancellation()
        if type(cancellation) is not PublicationCancellation or type(max_prepare_ns) is not int or not 0 < max_prepare_ns <= 120_000_000_000:
            _reject("preparation requires a bounded deadline and exact cancellation owner")
        def deadline():
            if cancellation.cancelled() or time.monotonic_ns() - started > max_prepare_ns:
                _reject("preparation cancelled or its measured deadline exhausted")
        reserved = self._limits["artifact"] + self._limits["metadata"]
        with self._writer:
            with self._lock:
                self._open()
                if self._driver is None or self._driver["release"].attempted:
                    _reject("a live internally pinned host driver is required")
                self._check_implementation()
                deadline()
                if cancellation.committed():
                    _reject("cancellation owner already committed another preparation")
                if guarded_narrowed and base_token is None:
                    _reject("guarded-narrowed preparation requires an internal baseline token")
                parent = None
                if base_token is not None:
                    parent = self._entries.get(base_token) if type(base_token) is str else None
                    if parent is None or parent.retired or parent.parent is not None:
                        _reject("guarded preparation requires a live internal baseline token")
                    self._validate_entry(parent, parent.generation)
                    if guarded_narrowed:
                        original, _, candidate, frozen = _freeze_chain(parent.image.program, proposal)
                        checked, state = _profile(candidate)
                    else:
                        original, fast, frozen = _freeze(parent.image.program, proposal)
                        checked, state = _profile(_compose(original, fast, frozen))
                    program = original
                else:
                    checked, state = _profile(program)
                    program, frozen = checked, None
                self._reserve(reserved, entry=True)
                self._next += 1
                generation = self._next
                token = f"{self._scope}-{generation}"
            fd, entry = None, None
            unpublished = _NativeRelease(None, None)
            try:
                path = self._directory / f"generation-{generation}.so"
                self._proof_attempts += 1
                if parent is None:
                    receipt = build_optimized_native(program, checked, path, policy=self._policy, clang=self._clang)
                else:
                    builder = build_guarded_narrowed_native if guarded_narrowed else build_guarded_native
                    receipt = builder(program, frozen, path, policy=self._policy, clang=self._clang)
                deadline()
                if path.stat().st_size > self._limits["artifact"]:
                    _reject("self-built artifact exceeds the reserved size")
                raw, _, fd = _pin_native_artifact(path, maximum_bytes=self._limits["artifact"],
                    close_owner=self._pin_close_owner(token, reserved))
                unpublished.fd = fd
                image = _Image(checked, state, sha256(raw).hexdigest(), receipt)
                proof = _issue(image, parent=parent.proof if parent else None,
                               implementation=self._implementation, policy=self._policy, scope=self._scope)
                metadata = len(_wire({"program": checked.as_dict(), "state": state, "receipt": receipt}))
                entry = _Entry(token, generation, image, proof, fd, self._fd_identity(fd), unpublished,
                               len(raw) + metadata, len(raw), metadata, parent=parent)
                if (len(raw) > self._limits["artifact"] or metadata > self._limits["metadata"]
                        or receipt["verification"]["solver"] != self._solver
                        or receipt["native"]["toolchain"]["sha256"] != self._clang_sha):
                    _reject("internally built artifact/proof exceeds or differs from the frozen admission")
                self._check_implementation()
                self._check_fd(fd, entry.fd_identity, image.artifact_sha256)
                with self._lock, cancellation._lock:
                    self._open()
                    deadline()
                    if cancellation._committed:
                        _reject("cancellation owner already committed another preparation")
                    previous_charge, previous_admissions = self._charged, self._admissions
                    previous_dependencies = parent.dependents if parent else None
                    previous_committed = cancellation._committed
                    try:
                        if parent:
                            parent.dependents = previous_dependencies + 1
                        self._charged = previous_charge + entry.charged_bytes
                        self._admissions = previous_admissions + 1
                        self._entries[token] = entry
                        cancellation._committed = True
                    except BaseException:
                        # No lease can observe this transaction before the
                        # lock is released. Remove visibility first, then
                        # restore every accounting/parent/cancel transition.
                        self._entries.pop(token, None)
                        if parent:
                            parent.dependents = previous_dependencies
                        self._charged = previous_charge
                        self._admissions = previous_admissions
                        cancellation._committed = previous_committed
                        raise
                return {**self._entry_info(entry), "preparation_ns": time.monotonic_ns() - started}
            finally:
                with self._lock:
                    self._reserved -= reserved
                    owned = entry is not None and self._entries.get(token) is entry
                    if fd is not None and not owned:
                        # A failed preparation retains one release owner. If
                        # close may have taken effect, its budget remains debt.
                        unpublished.fd = fd
                        release = unpublished
                        # The failed entry's metadata is not retained by this
                        # owner. Keep the whole reservation charged as a
                        # conservative bound on its uncertain native release.
                        charge = reserved
                        release.attempt()
                        if not release.complete:
                            self._pending[token] = {"release": release, "charged_bytes": charge,
                                "reason": "unpublished preparation release uncertain"}
                            self._charged += charge

    def _validate_entry(self, entry, generation):
        if (self._invalidated or self._entries.get(entry.token) is not entry or generation != entry.generation
                or entry.fd is None or entry.release.attempted):
            _reject("stale, foreign, retired or released admission")
        self._check_implementation()
        if not _matches(entry.proof, entry.image, implementation=self._implementation, policy=self._policy, scope=self._scope):
            _reject("private prepared-proof binding changed")
        if entry.parent is not None:
            _reuse(entry.parent.proof, entry.parent.image, entry.proof, entry.image,
                   implementation=self._implementation, policy=self._policy, scope=self._scope)
        self._check_fd(entry.fd, entry.fd_identity, entry.image.artifact_sha256)
        self._check_fd(self._driver["fd"], self._driver["identity"], self._driver["sha256"])

    def lease(self, token):
        with self._lock:
            self._open()
            entry = self._entries.get(token) if type(token) is str else None
            if entry is None or entry.retired:
                _reject("unknown or retired artifact token")
            if self._leased >= self._limits["leases"]:
                _reject("outstanding lease budget exhausted")
            self._validate_entry(entry, entry.generation)
            entry.leases += 1
            self._leased += 1
            return ArtifactLease(self, entry)

    def _run(self, entry, generation, n, calls, seed, timeout):
        started = time.monotonic_ns()
        for value, lo, hi in ((n, 0, 65536), (calls, 1, 1_000_000), (seed, 0, 255)):
            if type(value) is not int or not lo <= value <= hi:
                _reject("workload scalar input outside the bounded child-driver profile")
        if type(timeout) not in {int, float} or not 0 < timeout <= 120:
            _reject("child timeout must be finite and in (0, 120]")
        with self._lock:
            self._validate_entry(entry, generation)
            if self._executions >= self._limits["executions"]:
                _reject("session execution-attempt budget exhausted")
            self._executions += 1
            driver_fd, image_fd = self._driver["fd"], entry.fd
            command = [f"/proc/self/fd/{driver_fd}", f"/proc/self/fd/{image_fd}", str(n), str(calls), str(seed)]
        result = {"profile": PROFILE, "generation": generation, "artifact_sha256": entry.image.artifact_sha256,
                  "core_sha256": entry.image.program.sha256, "command": command, "new_solver_call": False,
                  "serialized_receipt_authority": False, "execution_attempted": False}
        try:
            remaining = timeout - (time.monotonic_ns() - started) / 1e9
            if remaining <= 0:
                return dict(result, status="timeout-before-launch", outer_wall_ns=time.monotonic_ns() - started)
            result["execution_attempted"] = True
            completed = subprocess.run(command, capture_output=True, check=False, timeout=remaining,
                                       pass_fds=(driver_fd, image_fd))
            result.update(status="completed" if completed.returncode == 0 else "child-failed",
                          returncode=completed.returncode, stdout=completed.stdout.decode(errors="replace"),
                          stderr=completed.stderr.decode(errors="replace"))
        except subprocess.TimeoutExpired as error:
            result.update(status="timeout", returncode=None, stdout=(error.stdout or b"").decode(errors="replace"),
                          stderr=(error.stderr or b"").decode(errors="replace"))
        except OSError as error:
            result.update(status="launch-failed", returncode=None, stdout="", stderr=str(error))
        finally:
            result["outer_wall_ns"] = time.monotonic_ns() - started
            with self._lock:
                if result.get("status") != "completed":
                    self._runs_failed += 1
        return result

    def _entry_info(self, entry):
        return {"token": entry.token, "generation": entry.generation, "core_sha256": entry.image.program.sha256,
            "artifact_sha256": entry.image.artifact_sha256, "artifact_bytes": entry.artifact_bytes,
            "encoded_metadata_bytes": entry.metadata_bytes, "verification_sha256": entry.proof.proof,
            "root_core_sha256": entry.proof.root_core, "proof_depth": entry.proof.depth,
            "active_leases": entry.leases, "dependent_artifacts": entry.dependents, "retired": entry.retired}

    def _collect(self, entry):
        if not entry.retired or entry.leases or entry.dependents:
            return
        self._entries.pop(entry.token)
        entry.fd = None
        parent, entry.parent = entry.parent, None
        entry.release.attempt()
        if entry.release.complete:
            self._charged -= entry.charged_bytes
        else:
            self._pending[entry.token] = {"release": entry.release, "charged_bytes": entry.charged_bytes,
                "reason": "retired artifact release uncertain"}
        if parent is not None:
            parent.dependents -= 1
            self._collect(parent)

    def _collect_driver(self):
        if not self._closed or self._leased or self._entries or self._driver is None:
            return
        release = self._driver["release"]
        if not release.attempted:
            self._driver["fd"] = None
            release.attempt()
            if release.complete:
                self._charged -= self._driver["bytes"]

    def _release_lease(self, entry):
        with self._lock:
            if entry.leases <= 0 or self._leased <= 0:
                _reject("lease release has no owned reservation")
            entry.leases -= 1
            self._leased -= 1
            self._collect(entry)
            self._collect_driver()

    def retire(self, token):
        with self._writer, self._lock:
            self._open()
            entry = self._entries.get(token) if type(token) is str else None
            if entry is None:
                _reject("unknown artifact token")
            entry.retired = True
            self._collect(entry)

    def snapshot(self):
        with self._lock:
            pending = [{"token": token, "charged_bytes": row["charged_bytes"], "reason": row["reason"],
                        "release": row["release"].snapshot()} for token, row in self._pending.items()]
            driver = self._driver["release"].snapshot() if self._driver else None
            return {"schema": PROFILE, "closed": self._closed, "invalidated": self._invalidated,
                "entries": [self._entry_info(e) for e in self._entries.values()], "pending_release_debt": pending,
                "driver_release": driver, "charged_retained_bytes": self._charged, "reserved_bytes": self._reserved,
                "outstanding_leases": self._leased, "limits": dict(self._limits), "proof_attempts": self._proof_attempts,
                "successful_admissions": self._admissions, "execution_attempts": self._executions, "failed_runs": self._runs_failed,
                "owned_native_release_complete": self._closed and not self._entries and not pending
                    and self._charged == 0 and self._reserved == 0 and self._leased == 0
                    and (self._driver is None or self._driver["release"].complete),
                "native_release_failures_are_retried": False, "build_files_retained_as_evidence": True,
                "whole_process_memory_bound": False, "serialized_receipt_authority": False,
                "authority": "DENY_ALL", "safety_certificate": False}

    def close(self):
        with self._writer, self._lock:
            self._closed = True
            for entry in list(self._entries.values()):
                entry.retired = True
            for entry in list(self._entries.values()):
                if entry.token in self._entries:
                    self._collect(entry)
            self._collect_driver()

    def __enter__(self):
        with self._lock:
            self._open()
        return self

    def __exit__(self, *unused):
        self.close()

    def __copy__(self):
        _reject("artifact sessions cannot be copied")

    def __deepcopy__(self, memo):
        return self.__copy__()
