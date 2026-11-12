"""Foreign resource adapter for a retained HIA retirement state machine.

The HIA image owns admission, state transitions, effect preclaims and completion
decisions. This adapter owns Python/loader objects and performs only the effect
selected by that image. It never reconstructs a state block from Python flags.
"""
from __future__ import annotations

from contextlib import contextmanager
import copy
import ctypes
from dataclasses import dataclass
from pathlib import Path
import struct
import threading
import time

from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image, _source_resource_path
from .hia_retirement_effects import RetirementOpenPrimitive, os

SOURCE = _source_resource_path('examples/hia_bootstrap/retirement_state.hiaasm')
SCHEMA = 'hepta.hia.retirement-state-native.v1'
SELECTOR = 'HEPTA_HIA_RETIREMENT_STATE_MANIFEST'
REQUEST_MAGIC = int.from_bytes(b'HIARREQ1', 'little')
RESULT_MAGIC = int.from_bytes(b'HIARRES1', 'little')
STATE_BYTES = 4608
STATUS = ('not_acquired', 'open', 'unknown', 'closed')
OBSERVATION = ('pending', 'absent', 'owned_present', 'replaced', 'unbound',
               'recreated_after_release', 'error')
DISK = ('not_attempted', 'absent', 'blocked_by_uncertain_native_release',
        'refused_unowned', 'removed', 'error', None)
_ACTIONS = {0: (0,), 1: (0,), 2: (1, 2), 3: (3,), 4: (0,), 5: (0,),
            6: (0, 4), 7: (0,), 8: (0,), 9: (0, 3), 10: (0,),
            11: (0, 6, 8), 12: (0, 8), 13: (0,), 20: (0,),
            21: (0, 7), 22: (0,), 23: (0,), 24: (0, 5, 8), 25: (0, 8), 26: (0,)}

# Strong, process-local custody roots for native policy failures. These are
# foreign-resource quarantines, never replacement policy states or retry
# queues. There is intentionally no production "forget/close" operation.
_QUARANTINED = {}


def retirement_quarantine_snapshot():
    """Detached diagnostics; obtaining them grants no resource-release right."""
    rows = []
    for (pid, _identity), owner in tuple(_QUARANTINED.copy().items()):
        if pid == os.getpid():
            row = owner.snapshot()
            task = owner._retirement_custody
            if task is not None:
                row['retirement_task_custody'] = {
                    'generation': task.generation, 'native_descriptor': task.fd,
                    'library_held': task.library is not None,
                    'function_references': len(task.functions), 'effects_permitted': False}
            rows.append(row)
        else:
            rows.append({'creator_pid': pid, 'status': 'foreign_process_quarantine',
                         'effects_permitted': False})
    return rows


def _admit_new_custody():
    if _QUARANTINED:
        raise NativeRetirementFailure('native retirement custody is quarantined; new native owners require process retirement')


class NativeRetirementFailure(RuntimeError):
    """A selected native owner cannot authorize any further effect."""


@dataclass(frozen=True)
class EffectToken:
    owner: tuple[int, int]
    sequence: int


@dataclass(frozen=True)
class Receipt:
    action: int
    token: EffectToken
    value: int
    flags: int
    sequence: int
    observation: int


def _error(exc):
    return {'type': type(exc).__name__, 'errno': getattr(exc, 'errno', None),
            'message': str(exc)[:1024]}


def _inode_packet(inode):
    if inode is None:
        return (0, 0, 0)
    if (type(inode) is not tuple or len(inode) != 2
            or any(type(value) is not int or not 0 <= value < 1 << 64 for value in inode)):
        # A malformed expected tuple cannot create an original identity. The
        # native bind operation still owns the actual identity refusal.
        return (0, 0, 0)
    return (1, *inode)


class NativeRetirementImage(NativeHiaJsonImage):
    def __init__(self, image, expected_sha256):
        super().__init__(image, expected_sha256)
        self._open_primitive = RetirementOpenPrimitive()

    def owner(self, path, directory=False):
        return RetirementState(self, path, directory)


def installed_retirement_state(manifest_path):
    return _installed_json_image(manifest_path, SOURCE, SCHEMA, NativeRetirementImage)


def selected_retirement_state():
    selected = os.environ.get(SELECTOR)
    return installed_retirement_state(selected) if selected else None


class RetirementState:
    """One non-rebindable native block and its creator-process effect adapter.

    A native refusal caused by a malformed state/token/protocol permanently
    fences this object. The last attested header is retained for diagnostics;
    it is never written back or used to authorize an effect after fencing.
    """
    def __init__(self, image, path, directory):
        self.image = image
        self.path = Path(path)
        self._path_bytes = os.fsencode(self.path)
        if len(self._path_bytes) > 4096:
            raise ValueError('native retirement path exceeds the Linux 4096-byte profile')
        self._creator_pid = os.getpid()
        self._lock = threading.RLock()
        self._buffer = ctypes.create_string_buffer(STATE_BYTES)
        self._words = (0,) * 64
        self._flags = 0
        self._fenced = None
        self._owner = struct.unpack('<2Q', os.urandom(16))
        if self._owner == (0, 0):
            raise NativeRetirementFailure('native retirement instance identity unavailable')
        self.call(0, values=(int(directory),), path=self._path_bytes)

    def _check_process(self):
        if os.getpid() != self._creator_pid:
            # Check before an inherited lock can block a forked child.
            raise NativeRetirementFailure('native retirement owner belongs to its creator process')

    @contextmanager
    def scope(self):
        self._check_process()
        with self._lock:
            yield

    def _fence(self, exc):
        if self._fenced is None:
            self._fenced = _error(exc)
        self._flags = 0
        custodian = getattr(self, '_custodian', None)
        if custodian is not None:
            _QUARANTINED[(self._creator_pid, self._owner)] = custodian

    def call(self, event, *, token=None, values=(), path=b'', now=None):
        self._check_process()
        with self._lock:
            if self._fenced is not None:
                raise NativeRetirementFailure('native retirement state is fenced; no effect retry permitted')
            try:
                identity = self._owner if token is None else token.owner
                sequence = 0 if token is None else token.sequence
                numbers = [REQUEST_MAGIC, event, sequence,
                           time.monotonic_ns() if now is None else now, *values]
                if len(numbers) > 14 or any(type(x) is not int or not 0 <= x < 1 << 64 for x in numbers):
                    raise NativeRetirementFailure('invalid native retirement observation packet')
                numbers.extend([0] * (14 - len(numbers)))
                raw = struct.pack('<16Q', *numbers, *identity) + path
                source = ctypes.create_string_buffer(raw, len(raw))
                output = ctypes.create_string_buffer(64)
                returned = self.image._entry(source, len(raw), output, 64, self._buffer, STATE_BYTES)
                if self._fenced is not None:
                    raise NativeRetirementFailure('native retirement became fenced before its transition returned')
                if returned != 64:
                    raise NativeRetirementFailure('native retirement rejected its bounded ABI')
                magic, code, action, claimed, value, flags, current, observed = struct.unpack('<8Q', output.raw)
                if magic != RESULT_MAGIC or code > 7 or action > 8 or flags > 15 or observed > 6:
                    raise NativeRetirementFailure('invalid native retirement transition receipt')
                if code not in (0, 3, 5):
                    raise NativeRetirementFailure('native retirement state/token refused: ' + str(code))
                if ((code == 3 and event != 2) or (code == 5 and event != 4)
                        or (code == 0 and action not in _ACTIONS.get(event, ()))
                        or (code != 0 and action != 0)
                        or (0 < action < 8 and claimed == 0)):
                    raise NativeRetirementFailure('native retirement effect receipt differs from its operation')
                words = struct.unpack('<64Q', self._buffer.raw[:512])
                if words[2] != current or (words[55], words[56]) != self._owner:
                    raise NativeRetirementFailure('native retirement receipt does not bind retained state')
                self._words, self._flags = words, flags
                receipt = Receipt(action, EffectToken(self._owner, claimed), value, flags, current, observed)
            except BaseException as exc:
                self._fence(exc)
                raise
            if code == 3:
                error = ValueError('path identity is acquired at most once')
                error._hia_retirement_refusal = code
                raise error
            if code == 5:
                error = ValueError('opened path identity differs from the original owned inode')
                error._hia_retirement_refusal = code
                raise error
            return receipt

    def query(self):
        with self.scope():
            if self._fenced is None:
                try:
                    self.call(1)
                except NativeRetirementFailure:
                    pass
            return self._words, self._flags

    def diagnostic(self, report):
        if self._fenced is not None:
            report['native_policy_error'] = copy.deepcopy(self._fenced)
            report['native_policy_fields_are_last_attested'] = True
        return report


class NativePathIdentityPin:
    """Effect and diagnostic transport for one native-owned original path pin."""
    def __init__(self, path, directory, image):
        _admit_new_custody()
        self._acquisition_error = None
        self._close_error = None
        self._returned_open = None
        self._open_result = (ctypes.c_int64 * 2)()
        self._retirement_custody = None
        self._state = image.owner(path, directory)
        self._state._custodian = self

    @property
    def path(self): return self._state.path
    @property
    def directory(self): return bool(self._state._words[3])
    @property
    def fd(self): return self._state._words[6] if self._state._words[5] else None
    @property
    def inode(self): return self._state._words[8:10] if self._state._words[7] else None
    @property
    def acquisition_attempted(self): return bool(self._state._words[4])
    @property
    def acquisition_error(self): return copy.deepcopy(self._acquisition_error)
    @property
    def bound(self): return bool(self._state._words[7])
    @property
    def path_released(self): return bool(self._state._words[10])
    @property
    def close_attempted(self): return bool(self._state._words[11])
    @property
    def release_succeeded(self): return bool(self._state.query()[1] & 1)

    @property
    def close_result(self):
        words, _ = self._state.query()
        result = {'status': STATUS[words[12]]}
        if words[11]:
            result['attempted_ns'] = words[41]
        if words[43]:
            result['finished_ns'] = words[42]
        if self._close_error is not None:
            result['error'] = copy.deepcopy(self._close_error)
        return result

    def acquire(self, expected_inode):
        with self._state.scope():
            _admit_new_custody()
            receipt = self._state.call(2, values=_inode_packet(expected_inode))
            try:
                flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
                if receipt.action == 2:
                    flags |= os.O_DIRECTORY
                descriptor = os.open(self.path, flags, _hia_result=self._open_result,
                                     _hia_primitive=self._state.image._open_primitive)
                self._returned_open = {'descriptor': descriptor,
                    'instance': list(receipt.token.owner), 'acquisition_claim': receipt.token.sequence,
                    'native_transition_confirmed': False, 'close_retry_permitted': False}
                try:
                    self._state.call(3, token=receipt.token, values=(descriptor,))
                except BaseException as exc:
                    # The host returned an actual fd before native state
                    # acknowledgment. Keep that custody visible even if the
                    # native transition ran and its return was interrupted.
                    self._state._fence(exc)
                    raise
                self._returned_open['native_transition_confirmed'] = True
                info = os.fstat(descriptor)
                actual = self.path.lstat()
                try:
                    self._state.call(4, token=receipt.token,
                        values=(info.st_dev, info.st_ino, info.st_mode, actual.st_dev, actual.st_ino))
                except BaseException as exc:
                    if getattr(exc, '_hia_retirement_refusal', None) != 5:
                        self._state._fence(exc)
                    raise
            except BaseException as exc:
                self._acquisition_error = _error(exc)
                stage, returned = self._open_result
                if self._returned_open is None and stage == 2 and returned >= 0:
                    # The fixed primitive retains this result even if Python
                    # was interrupted before STORE_FAST or diagnostic creation.
                    self._returned_open = {'descriptor': returned,
                        'instance': list(receipt.token.owner), 'acquisition_claim': receipt.token.sequence,
                        'native_transition_confirmed': False, 'close_retry_permitted': False}
                if (stage not in (0, 2)
                        or stage == 2 and returned >= 0
                        and not self._returned_open['native_transition_confirmed']):
                    # Started-without-result is unknown. A known returned fd
                    # without attested handoff also grants no native close right.
                    self._state._fence(exc)
                if self._state._fenced is None:
                    try:
                        # Stage zero proves that the fixed primitive never
                        # entered; a negative completed result proves errno.
                        # An attested returned fd is handled by HIA's abort.
                        self._state.call(5, token=receipt.token)
                        self._close_once()
                    except BaseException as cleanup_error:
                        self._state._fence(cleanup_error)
                if self._state._fenced is not None:
                    # Retain the actual quarantined owner when a constructor
                    # unwinds. The detached public diagnostic is still JSON;
                    # this exception attribute is an in-process custody root.
                    try:
                        exc.hia_retirement_owner = self
                        exc.hia_retirement = self.snapshot()
                    except Exception:
                        pass
                raise

    def _close_once(self):
        with self._state.scope():
            receipt = self._state.call(6)
            if receipt.action == 0:
                return
            try:
                os.close(receipt.value)
            except Exception as exc:
                self._close_error = _error(exc)
                self._state.call(7, token=receipt.token, values=(0,))
            else:
                self._state.call(7, token=receipt.token, values=(1,))

    def release_absent_path(self):
        with self._state.scope():
            self._state.call(8)
            self._close_once()

    def _observe(self):
        with self._state.scope():
            result = {'path': str(self.path), 'observed_ns': time.monotonic_ns()}
            try:
                info = self.path.lstat()
                result['actual_inode'] = [info.st_dev, info.st_ino]
                receipt = self._state.call(9, now=result['observed_ns'],
                    values=(0, info.st_dev, info.st_ino, info.st_mode))
            except FileNotFoundError:
                receipt = self._state.call(9, values=(1,), now=result['observed_ns'])
            except OSError as exc:
                result['error'] = _error(exc)
                receipt = self._state.call(9, values=(2,), now=result['observed_ns'])
            if receipt.action == 3:
                try:
                    info = os.fstat(receipt.value)
                    receipt = self._state.call(10, token=receipt.token,
                        values=(0, info.st_dev, info.st_ino))
                except FileNotFoundError:
                    receipt = self._state.call(10, token=receipt.token, values=(1,))
                except OSError as exc:
                    result['error'] = _error(exc)
                    receipt = self._state.call(10, token=receipt.token, values=(2,))
            result['status'] = OBSERVATION[receipt.observation]
            return result, receipt.token

    def observe(self):
        if self._state._fenced is not None:
            return self.fenced_observation(self.path)
        return self._observe()[0]

    def fenced_observation(self, path):
        return {'path': str(path), 'observed_ns': time.monotonic_ns(),
                'status': 'error', 'error': copy.deepcopy(self._state._fenced)}

    def matches(self, path, inode):
        return bool(self._state.call(13, values=(1, *_inode_packet(inode)),
                                     path=os.fsencode(Path(path))).value)

    def snapshot(self):
        with self._state.scope():
            return self._snapshot()

    def _snapshot(self):
        words, flags = self._state.query()
        report = {'path': str(self.path), 'directory': bool(words[3]),
            'inode': list(words[8:10]) if words[7] else None,
            'acquisition_attempted': bool(words[4]),
            'acquisition_error': copy.deepcopy(self._acquisition_error),
            'identity_bound': bool(words[7]), 'identity_fd_held': bool(flags & 2),
            'path_released': bool(words[10]), 'close_attempted': bool(words[11]),
            'close': self.close_result, 'release_succeeded': bool(flags & 1),
            'close_retry_permitted': False, 'rebind_permitted': False}
        if self._state._fenced is not None and self._returned_open is not None:
            report['quarantined_open_result'] = copy.deepcopy(self._returned_open)
        if self._state._fenced is not None:
            stage, returned = self._open_result
            report['foreign_open_result_slot'] = {'stage': stage,
                'kernel_result': returned if stage == 2 else None,
                'outcome': 'not_entered' if stage == 0 else 'returned' if stage == 2 else 'unknown',
                'close_retry_permitted': False}
        return self._state.diagnostic(report)


class NativeRetirement:
    """A task attached once to its original native pin; foreign handles stay here."""
    @classmethod
    def retain_or_recover(cls, generation, cause, artifact, inode, library, functions, fd, identity_pin):
        pin = identity_pin._backend
        with pin._state.scope():
            existing = pin._retirement_custody
            if existing is not None:
                saved = existing._creation_fields
                if (saved is None or saved[:4] != (generation, cause, Path(artifact), inode)
                        or saved[4] is not library or saved[5] is not functions
                        or saved[6] != fd or saved[7] is not identity_pin):
                    error = ValueError('native pin already retains a different retirement resource holder')
                    error._hia_retirement_custody_conflict = True
                    raise error
                # Recover the same foreign holder if registration of its
                # wrapper was interrupted. This creates no second HIA owner.
                return existing
            try:
                return cls(generation, cause, artifact, inode, library, functions, fd, identity_pin)
            except BaseException as exc:
                # Cover dispatch after event20 returned, including the line
                # that records attachment confirmation. The holder is linked
                # before that transition and is therefore still recoverable.
                pin._state._fence(exc)
                if pin._retirement_custody is not None:
                    return pin._retirement_custody
                raise

    def __init__(self, generation, cause, artifact, inode, library, functions, fd, identity_pin):
        self._cause, self._artifact = cause, Path(artifact)
        self._library, self._functions, self._identity_pin = library, functions, identity_pin
        self._pin = identity_pin._backend
        self._state = self._pin._state
        self._library_error = self._fd_error = None
        self._disk_before = None
        self._disk_error = None
        self._unattached_custody = (generation, inode, fd)
        self._creation_fields = (generation, cause, Path(artifact), inode, library, functions, fd, identity_pin)
        if self._pin._retirement_custody is not None:
            raise ValueError('native pin already retains a retirement resource holder')
        # Retain all actual foreign handles before native attachment can fail.
        # A fenced pin is itself strongly retained by the process quarantine.
        self._pin._retirement_custody = self
        if self._state._fenced is None:
            try:
                self._state.call(20, values=(*_inode_packet(inode), int(library is not None),
                    int(fd is not None), 0 if fd is None else fd, generation), path=os.fsencode(self.artifact))
            except BaseException as exc:
                # Failure is an inert, incomplete owner, so the existing
                # pending-table registration can preserve an original prepare
                # error instead of losing these handles during unwinding.
                self._state._fence(exc)
            else:
                self._unattached_custody = None

    @property
    def generation(self): return self._unattached_custody[0] if self._unattached_custody is not None else self._state._words[31]
    @property
    def cause(self): return self._cause
    @property
    def artifact(self): return self._artifact
    @property
    def inode(self):
        if self._unattached_custody is not None: return self._unattached_custody[1]
        return self._state._words[17:19] if self._state._words[16] else None
    @property
    def library(self): return self._library
    @property
    def functions(self): return self._functions
    @property
    def fd(self):
        if self._unattached_custody is not None: return self._unattached_custody[2]
        return self._state._words[21] if self._state._words[20] else None
    @property
    def identity_pin(self): return self._identity_pin
    @property
    def native_attempted(self): return bool(self._state._words[22])
    @property
    def disk_attempts(self): return self._state._words[28]
    @property
    def native_succeeded(self): return bool(self._state.query()[1] & 4)
    @property
    def complete(self): return bool(self._state.query()[1] & 8)

    @property
    def native(self):
        words, _ = self._state.query()
        if not words[22]:
            return {}
        result = {'attempted_ns': words[38], 'library': {'status': STATUS[words[23]]},
                  'fd': {'status': STATUS[words[24]]}}
        if words[40]:
            result['finished_ns'] = words[39]
        if self._library_error is not None:
            result['library']['error'] = copy.deepcopy(self._library_error)
        if self._fd_error is not None:
            result['fd']['error'] = copy.deepcopy(self._fd_error)
        return result

    @property
    def disk(self):
        words, _ = self._state.query()
        result = {}
        if words[28]:
            result['attempted_ns'] = words[44]
            if self._disk_before is not None:
                result['before'] = copy.deepcopy(self._disk_before)
        if DISK[words[29]] is not None:
            result['status'] = DISK[words[29]]
        if self._disk_error is not None:
            result['error'] = copy.deepcopy(self._disk_error)
        return result

    def attempt(self):
        with self._state.scope():
            if self._state._fenced is not None:
                return self.snapshot()
            receipt = self._state.call(21)
            if receipt.action == 7:
                self._creation_fields = None
                # The HIA preclaim already fences both handles before any
                # Python operation (including a reentrant clear) can fail.
                self.functions.clear()
                if receipt.value & 1:
                    try:
                        import _ctypes
                        handle = self.library._handle
                        for name, value in list(vars(self.library).items()):
                            if isinstance(value, ctypes._CFuncPtr):
                                delattr(self.library, name)
                        _ctypes.dlclose(handle)
                    except Exception as exc:
                        self._library_error = _error(exc)
                        self._state.call(22, token=receipt.token, values=(1, 0))
                    else:
                        self._state.call(22, token=receipt.token, values=(1, 1))
                        self._library = None
                if receipt.value & 2:
                    try:
                        os.close(self._state._words[21])
                    except Exception as exc:
                        self._fd_error = _error(exc)
                        self._state.call(22, token=receipt.token, values=(2, 0))
                    else:
                        self._state.call(22, token=receipt.token, values=(2, 1))
                self._state.call(23, token=receipt.token)
            attempt = self._state.call(26)
            self._disk_before, self._disk_error = None, None
            before, observation = self._pin._observe()
            self._disk_before = before
            receipt = self._state.call(24, token=observation, values=(attempt.token.sequence,))
            if receipt.action == 5:
                try:
                    self._pin.path.unlink()
                except FileNotFoundError:
                    receipt = self._state.call(25, token=receipt.token, values=(1,))
                except OSError as exc:
                    self._disk_error = _error(exc)
                    receipt = self._state.call(25, token=receipt.token, values=(2,))
                else:
                    receipt = self._state.call(25, token=receipt.token, values=(0,))
            if receipt.action == 8:
                self._pin.release_absent_path()
            return self.snapshot()

    def snapshot(self):
        with self._state.scope():
            return self._snapshot()

    def _snapshot(self):
        words, flags = self._state.query()
        report = {'generation': self.generation, 'cause': self.cause,
            'artifact': str(self.artifact),
            'recorded_inode': list(self.inode) if self.inode is not None else None,
            'native_attempted': bool(words[22]), 'native_release_succeeded': bool(flags & 4),
            'native': self.native, 'disk': self.disk,
            'artifact_identity_pin': self._pin.snapshot(),
            'disk_attempts': words[28], 'complete': bool(flags & 8),
            'native_retry_permitted': False}
        if self._unattached_custody is not None or self._state._fenced is not None:
            report['quarantined_foreign_resources'] = {'library_held': self.library is not None,
                'native_descriptor': self.fd,
                'native_task_attachment_confirmed': self._unattached_custody is None}
        return self._state.diagnostic(report)


def directory_pin(path, inode, pin, image):
    if pin is not None and isinstance(pin._backend, NativePathIdentityPin):
        if pin._backend.matches(path, inode):
            return pin._backend
    return NativePathIdentityPin(path, True, image)


def observe_directory(path, inode, pin, image):
    if pin is not None and isinstance(pin._backend, NativePathIdentityPin) and pin._backend._state._fenced is not None:
        return pin._backend.fenced_observation(path)
    return directory_pin(path, inode, pin, image).observe()


def remove_directory(path, inode, pin, image):
    if pin is not None and isinstance(pin._backend, NativePathIdentityPin) and pin._backend._state._fenced is not None:
        return {'path': str(path), 'attempted_ns': time.monotonic_ns(),
            'before': pin._backend.fenced_observation(path),
            'status': 'refused_unowned_or_unobservable',
            'after': pin._backend.fenced_observation(path), 'identity_pin': pin.snapshot()}
    owned = directory_pin(path, inode, pin, image)
    with owned._state.scope():
        before, observation = owned._observe()
        result = {'path': str(path), 'attempted_ns': time.monotonic_ns(), 'before': before}
        receipt = owned._state.call(11, token=observation, now=result['attempted_ns'])
        if receipt.action == 6:
            try:
                path.rmdir()
            except FileNotFoundError:
                receipt = owned._state.call(12, token=receipt.token, values=(1,))
            except OSError as exc:
                result['error'] = _error(exc)
                receipt = owned._state.call(12, token=receipt.token, values=(2,))
            else:
                receipt = owned._state.call(12, token=receipt.token, values=(0,))
        result['status'] = {1: 'already_absent', 3: 'refused_unowned_or_unobservable',
                            4: 'removed', 5: 'error'}[receipt.value]
        if receipt.action == 8:
            owned.release_absent_path()
        result['after'] = owned.observe()
        result['identity_pin'] = pin.snapshot() if pin is not None else None
        return result
