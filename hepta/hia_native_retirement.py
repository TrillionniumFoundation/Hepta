"""Bounded, observable retirement of one runtime-owned native artifact.

Native release is attempted at most once: an exception may occur after a host
operation has already taken effect, so retrying an fd or loader handle could
release somebody else's reused resource. Only identity-checked disk cleanup is
retryable. Reports describe observed operations, not crash recovery or a proof
against a host process that mutates arbitrary Python state or filesystem paths.
"""
from __future__ import annotations

import ctypes
from dataclasses import dataclass, field
from pathlib import Path
import stat
import time

from .hia_retirement_effects import os


def _error(exc):
    return {"type": type(exc).__name__, "errno": getattr(exc, "errno", None),
            "message": str(exc)[:1024]}


@dataclass
class _ReferencePathIdentityPin:
    """Hold the original inode alive; never rebind a released path or fd number.

    A dev/inode pair alone is reusable immediately after unlink/rmdir. Keeping
    an actual fd to the original inode prevents that sequential reuse. Path
    deletion still assumes the documented private directory/no hostile races.
    """
    path: Path
    directory: bool = False
    fd: int | None = None
    inode: tuple[int, int] | None = None
    acquisition_attempted: bool = False
    acquisition_error: dict | None = None
    bound: bool = False
    path_released: bool = False
    close_attempted: bool = False
    close_result: dict = field(default_factory=lambda: {"status": "not_acquired"})

    @property
    def release_succeeded(self):
        return self.fd is None or self.close_attempted and self.close_result.get("status") == "closed"

    def acquire(self, expected_inode):
        if self.acquisition_attempted or self.close_attempted or self.path_released:
            raise ValueError("path identity is acquired at most once")
        self.acquisition_attempted = True
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
        if self.directory:
            flags |= os.O_DIRECTORY
        try:
            self.fd = os.open(self.path, flags)
            self.close_result = {"status": "open"}
            info = os.fstat(self.fd)
            inode = (info.st_dev, info.st_ino)
            correct_type = stat.S_ISDIR(info.st_mode) if self.directory else stat.S_ISREG(info.st_mode)
            path_info = self.path.lstat()
            if (not correct_type or inode != expected_inode
                    or (path_info.st_dev, path_info.st_ino) != inode):
                raise ValueError("opened path identity differs from the original owned inode")
            self.inode, self.bound = inode, True
        except BaseException as exc:
            self.acquisition_error = _error(exc)
            # An acquired but unbound handle is independently owned. Releasing
            # it does not grant authority to delete the unbound pathname.
            self._close_once()
            raise

    def _close_once(self):
        if self.close_attempted or self.fd is None:
            return
        self.close_attempted = True
        self.close_result = {"status": "unknown", "attempted_ns": time.monotonic_ns()}
        try:
            os.close(self.fd)
            self.close_result["status"] = "closed"
        except Exception as exc:
            self.close_result["error"] = _error(exc)
        self.close_result["finished_ns"] = time.monotonic_ns()

    def release_absent_path(self):
        # This flag survives any interruption/error while closing. Once the
        # path was released, a later recreation can never regain delete rights.
        self.path_released = True
        self._close_once()

    def observe(self):
        result = {"path": str(self.path), "observed_ns": time.monotonic_ns()}
        try:
            info = self.path.lstat()
            result["actual_inode"] = [info.st_dev, info.st_ino]
            if self.path_released:
                result["status"] = "recreated_after_release"
            elif not self.bound or self.fd is None or self.close_attempted:
                result["status"] = "unbound"
            else:
                pinned = os.fstat(self.fd)
                correct_type = stat.S_ISDIR(info.st_mode) if self.directory else stat.S_ISREG(info.st_mode)
                owned = (correct_type and (info.st_dev, info.st_ino) == self.inode
                         and (pinned.st_dev, pinned.st_ino) == self.inode)
                result["status"] = "owned_present" if owned else "replaced"
        except FileNotFoundError:
            result["status"] = "absent"
        except OSError as exc:
            result.update(status="error", error=_error(exc))
        return result

    def snapshot(self):
        import copy
        return {"path": str(self.path), "directory": self.directory,
                "inode": list(self.inode) if self.inode is not None else None,
                "acquisition_attempted": self.acquisition_attempted,
                "acquisition_error": copy.deepcopy(self.acquisition_error),
                "identity_bound": self.bound,
                "identity_fd_held": self.bound and self.fd is not None and not self.close_attempted,
                "path_released": self.path_released,
                "close_attempted": self.close_attempted,
                "close": copy.deepcopy(self.close_result),
                "release_succeeded": self.release_succeeded,
                "close_retry_permitted": False, "rebind_permitted": False}


def _reference_observe_directory(path, inode, pin=None):
    if pin is not None and pin.path == path and pin.directory and pin.inode == inode:
        return pin.observe()
    # Historical tuple identities are diagnostic, never delete authority.
    return _ReferencePathIdentityPin(path, directory=True).observe()


def _reference_remove_directory(path, inode, pin=None):
    before = _reference_observe_directory(path, inode, pin)
    result = {"path": str(path), "attempted_ns": time.monotonic_ns(), "before": before}
    if before["status"] == "absent":
        result["status"] = "already_absent"
        if pin is not None:
            pin.release_absent_path()
    elif before["status"] != "owned_present":
        result["status"] = "refused_unowned_or_unobservable"
    else:
        try:
            path.rmdir()
            result["status"] = "removed"
            pin.release_absent_path()
        except FileNotFoundError:
            result["status"] = "already_absent"
            pin.release_absent_path()
        except OSError as exc:
            result.update(status="error", error=_error(exc))
    result["after"] = _reference_observe_directory(path, inode, pin)
    result["identity_pin"] = pin.snapshot() if pin is not None else None
    return result


@dataclass
class _ReferenceNativeRetirement:
    generation: int
    cause: str
    artifact: Path
    inode: tuple[int, int] | None
    library: object
    functions: dict
    fd: int | None
    identity_pin: PathIdentityPin | None = None
    native_attempted: bool = False
    native: dict = field(default_factory=dict)
    disk: dict = field(default_factory=lambda: {"status": "not_attempted"})
    disk_attempts: int = 0

    def __post_init__(self):
        if self.identity_pin is None:
            # An old tuple-only caller cannot authorize a deletion.
            self.identity_pin = PathIdentityPin(self.artifact)

    @property
    def native_succeeded(self):
        return (self.native_attempted
                and self.native.get("library", {}).get("status") in {"closed", "not_acquired"}
                and self.native.get("fd", {}).get("status") in {"closed", "not_acquired"})

    @property
    def complete(self):
        return (self.native_succeeded and self.disk.get("status") in {"removed", "absent"}
                and self.identity_pin.release_succeeded)

    def attempt(self):
        if not self.native_attempted:
            self.native_attempted = True
            self.native = {"attempted_ns": time.monotonic_ns(),
                           "library": {"status": "not_acquired" if self.library is None else "unknown"},
                           "fd": {"status": "not_acquired" if self.fd is None else "unknown"}}
            self.functions.clear()
            if self.library is not None:
                try:
                    import _ctypes
                    handle = self.library._handle
                    for name, value in list(vars(self.library).items()):
                        if isinstance(value, ctypes._CFuncPtr):
                            delattr(self.library, name)
                    _ctypes.dlclose(handle)
                    self.native["library"] = {"status": "closed"}
                    self.library = None
                except Exception as exc:
                    self.native["library"] = {"status": "unknown", "error": _error(exc)}
            # A loader error must not skip the independently owned memfd.
            if self.fd is not None:
                try:
                    os.close(self.fd)
                    self.native["fd"] = {"status": "closed"}
                except Exception as exc:
                    self.native["fd"] = {"status": "unknown", "error": _error(exc)}
            self.native["finished_ns"] = time.monotonic_ns()
        self.disk_attempts += 1
        self.disk = {"attempted_ns": time.monotonic_ns()}
        observed = self.identity_pin.observe()
        self.disk["before"] = observed
        if observed["status"] == "absent":
            # Even an uncertain native release may release an identity pin
            # after a caller removed the path. Native handles are never retried.
            self.disk["status"] = "absent"
            self.identity_pin.release_absent_path()
        elif not self.native_succeeded:
            self.disk["status"] = "blocked_by_uncertain_native_release"
        elif observed["status"] != "owned_present" or self.identity_pin.inode != self.inode:
            self.disk["status"] = "refused_unowned"
        else:
            try:
                self.artifact.unlink()
                self.disk["status"] = "removed"
                self.identity_pin.release_absent_path()
            except FileNotFoundError:
                self.disk["status"] = "absent"
                self.identity_pin.release_absent_path()
            except OSError as exc:
                self.disk.update(status="error", error=_error(exc))
        return self.snapshot()

    def snapshot(self):
        # All entries are detached JSON values; loader objects and callables
        # never leave the runtime through this diagnostic path.
        import copy
        return {"generation": self.generation, "cause": self.cause,
                "artifact": str(self.artifact),
                "recorded_inode": list(self.inode) if self.inode is not None else None,
                "native_attempted": self.native_attempted,
                "native_release_succeeded": self.native_succeeded,
                "native": copy.deepcopy(self.native), "disk": copy.deepcopy(self.disk),
                "artifact_identity_pin": self.identity_pin.snapshot(),
                "disk_attempts": self.disk_attempts, "complete": self.complete,
                "native_retry_permitted": False}


def _native_image(pin=None):
    from .hia_retirement_state_native import (NativePathIdentityPin,
                                              selected_retirement_state)
    backend = getattr(pin, '_backend', None)
    if isinstance(backend, NativePathIdentityPin):
        # Resource custody is bound to this immutable native image for its
        # whole lifetime; changing ambient selection cannot replace its state
        # machine or prevent its already-authorized cleanup observations.
        return backend._state.image
    selected = selected_retirement_state()
    if pin is not None and selected is not None:
        raise ValueError('native retirement cannot import an existing hosted pin')
    return selected


def require_new_retirement_custody():
    """Refuse selected failed-policy admission before a runtime creates paths."""
    image = _native_image()
    if image is not None:
        from .hia_retirement_state_native import _admit_new_custody
        _admit_new_custody()
    return image


def retirement_quarantine_snapshot():
    """Observe process-local failed-policy custody; never retry its effects."""
    from .hia_retirement_state_native import retirement_quarantine_snapshot as observe
    return observe()


class PathIdentityPin:
    """One explicitly selected policy owner; the reference remains a test oracle.

    Foreign descriptors remain in this process. Selecting a native image never
    retries its admission or transition with the hosted policy implementation.
    """
    def __init__(self, path, directory=False, *reference_args, **reference_state):
        image = _native_image()
        if image is None:
            self._backend = _ReferencePathIdentityPin(path, directory, *reference_args, **reference_state)
        else:
            if reference_args or reference_state:
                raise ValueError('native retirement requires a fresh retained state owner')
            from .hia_retirement_state_native import NativePathIdentityPin
            self._backend = NativePathIdentityPin(path, directory, image)

    @classmethod
    def _from_admitted_image(cls, path, directory, image):
        """Prepare an owner before path creation, without a second selection."""
        pin = object.__new__(cls)
        if image is None:
            pin._backend = _ReferencePathIdentityPin(path, directory)
        else:
            from .hia_retirement_state_native import NativePathIdentityPin
            pin._backend = NativePathIdentityPin(path, directory, image)
        return pin

    def __getattr__(self, name):
        return getattr(self._backend, name)

    def __setattr__(self, name, value):
        if name == '_backend' or '_backend' not in self.__dict__:
            object.__setattr__(self, name, value)
        else:
            setattr(self._backend, name, value)

    def __delattr__(self, name):
        if name == '_backend':
            object.__delattr__(self, name)
        else:
            delattr(self._backend, name)

    @property
    def release_succeeded(self): return self._backend.release_succeeded
    def acquire(self, expected_inode): return self._backend.acquire(expected_inode)
    def _close_once(self): return self._backend._close_once()
    def release_absent_path(self): return self._backend.release_absent_path()
    def observe(self): return self._backend.observe()
    def snapshot(self): return self._backend.snapshot()


class NativeRetirement:
    """The actual runtime retirement entry, with an optional complete HIA policy."""
    def __init__(self, generation, cause, artifact, inode, library, functions, fd,
                 identity_pin=None, *reference_args, **reference_state):
        if identity_pin is None:
            identity_pin = PathIdentityPin(artifact)
        image = _native_image(identity_pin)
        values = (generation, cause, artifact, inode, library, functions, fd, identity_pin)
        if image is None:
            self._backend = _ReferenceNativeRetirement(*values, *reference_args, **reference_state)
        else:
            if reference_args or reference_state:
                raise ValueError('native retirement requires a fresh retained state owner')
            from .hia_retirement_state_native import NativeRetirement as NativeOwner
            try:
                self._backend = NativeOwner.retain_or_recover(*values)
            except BaseException as exc:
                # A returned native holder can outlive an interrupted Python
                # STORE_ATTR. Recover that same holder as inert custody; never
                # let a second wrapper manufacture a second state owner.
                pin = identity_pin._backend
                holder = pin._retirement_custody
                if holder is None or getattr(exc, '_hia_retirement_custody_conflict', False):
                    raise
                pin._state._fence(exc)
                self._backend = holder

    def __getattr__(self, name):
        return getattr(self._backend, name)

    def __setattr__(self, name, value):
        if name == '_backend' or '_backend' not in self.__dict__:
            object.__setattr__(self, name, value)
        else:
            setattr(self._backend, name, value)

    def __delattr__(self, name):
        if name == '_backend':
            object.__delattr__(self, name)
        else:
            delattr(self._backend, name)

    @property
    def native_succeeded(self): return self._backend.native_succeeded
    @property
    def complete(self): return self._backend.complete
    def attempt(self): return self._backend.attempt()
    def snapshot(self): return self._backend.snapshot()


def observe_directory(path, inode, pin=None):
    image = _native_image(pin)
    if image is None:
        return _reference_observe_directory(path, inode, pin)
    from .hia_retirement_state_native import observe_directory as native_observe
    return native_observe(path, inode, pin, image)


def remove_directory(path, inode, pin=None):
    image = _native_image(pin)
    if image is None:
        return _reference_remove_directory(path, inode, pin)
    from .hia_retirement_state_native import remove_directory as native_remove
    return native_remove(path, inode, pin, image)
