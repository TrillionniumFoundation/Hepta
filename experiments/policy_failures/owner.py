"""Isolated v1 policy and first-origin failure ledger; never a sandbox or CLI default."""
from dataclasses import asdict, dataclass
from types import MappingProxyType
from pathlib import Path

from hepta.ast import HeptaError
from experiments.package_copy import owner as package
from experiments.request_load.context import Rejected as LegacyRejected

VERSION = 'loader-experimental-v1'
_UNITS = {
    **{name: 'bytes per file' for name in ('source', 'manifest', 'lock', 'sidecar', 'header')},
    'total_bytes': 'cumulative OS-returned bytes including overflow sentinel',
    'reads': 'read invocations before open',
    'inventory_entries': 'directory entries before retention',
    'directory_depth': 'absolute directory depth (root = 1)',
    'packages': 'package node admissions', 'package_depth': 'absolute package traversal depth',
    'package_edges': 'package edge admissions', 'module_edges': 'module edge admissions',
    'path_checks': 'path operation admissions', 'modules': 'module node admissions',
    'module_depth': 'absolute module traversal depth',
    'tokens_per_parse': 'tokens including EOF per lexical batch',
    'total_tokens': 'cumulative tokens including EOF', 'parses': 'parser invocations',
    'parser_depth': 'absolute parser nesting depth', 'metadata_parses': 'JSON/TOML invocations',
    'json_depth': 'absolute JSON structural nesting depth', 'ast_nodes': 'AST constructor attempts',
    'parser_appends': 'grammar append attempts', 'copy_visits': 'unfolded assembly copy visits',
    'copy_depth': 'absolute assembly copy depth', 'transform_visits': 'transform body entries',
    'transform_depth': 'absolute transform depth', 'authority_visits': 'authority map visits',
    'authority_depth': 'absolute authority map depth', 'shallow_fields': 'shallow state entries',
    'package_copy_calls': 'projected actual Package deepcopy calls',
    'package_copy_depth': 'absolute Package deepcopy projection depth',
}


@dataclass(frozen=True, init=False)
class Policy:
    version: str
    limits: object
    units: object

    def __init__(self, version=VERSION, limits=None):
        if type(version) is not str or version != VERSION:
            raise ValueError('unsupported policy version')
        values = asdict(package.Limits())
        if limits is not None:
            if type(limits) is not dict:
                raise TypeError('policy limits must be an exact dictionary')
            if any(type(key) is not str or key not in values for key in limits):
                raise ValueError('unknown policy limit')
            values.update(limits)
        # Validates exact positive ints and the non-relaxable parser ceiling.
        package.Limits(**values)
        if set(values) != set(_UNITS):
            raise ValueError('incomplete policy unit inventory')
        object.__setattr__(self, 'version', version)
        object.__setattr__(self, 'limits', MappingProxyType(values))
        object.__setattr__(self, 'units', MappingProxyType(dict(_UNITS)))
        object.__setattr__(self, '_limits_pin', self.limits)
        object.__setattr__(self, '_units_pin', self.units)


@dataclass(frozen=True)
class Failure:
    category: str
    phase: str
    dimension: str | None = None
    limit: int | None = None
    admitted: int | None = None
    attempted: int | None = None
    observed_bytes: int = 0
    observed_reads: int = 0


class Rejected(LegacyRejected):
    def __init__(self, message, failure):
        super().__init__(message)
        self.failure = failure


class Cancelled(Exception):
    """Explicit cooperative cancellation; arbitrary checkpoint errors are not cancellation."""


def _category(error):
    if isinstance(error, Cancelled):
        return 'cancelled'
    if isinstance(error, KeyboardInterrupt):
        return 'interrupted'
    if isinstance(error, MemoryError):
        return 'memory'
    if isinstance(error, RecursionError):
        return 'recursion'
    if isinstance(error, OSError):
        return 'io'
    if isinstance(error, HeptaError):
        return 'diagnostic'
    return 'unexpected'


def _matches(actual, expected, exact_type):
    # Reject foreign values before equality or keyed lookup can invoke their hooks.
    if type(actual) is not exact_type or len(actual) != len(expected):
        return False
    for key, value in actual.items():
        if type(key) is not str or key not in expected:
            return False
        if type(value) is not type(expected[key]) or value != expected[key]:
            return False
    return True


class _Context(package._Context):
    def __init__(self, policy, checkpoint):
        self.failure = None
        self.policy = policy
        self._policy = policy
        self._policy_values = dict(policy.limits)
        self._policy_units = dict(policy.units)
        self._policy_limits_pin = policy.limits
        self._policy_units_pin = policy.units
        self._raw_checkpoint = checkpoint
        super().__init__(package.Limits(**policy.limits), self._checkpoint)
        self._limits = self.limits
        self._limit_values = dict(vars(self.limits))
        self._reader_limits = self.reader.limits
        self._reader_values = dict(vars(self.reader.limits))
        self.reader.on_failure = self._reader_failure
        self._read_role = None
        self._cap_roles = {}
        self._checkpoint_pin = self.checkpoint
        self._reader_checkpoint_pin = self.reader.checkpoint
        self._observer_pin = self.reader.on_failure

    def record(self, *, error=None, category=None, phase='operation', dimension=None,
               limit=None, admitted=None, attempted=None):
        if self.failure is None:
            self.failure = Failure(category or _category(error), phase, dimension,
                                   limit, admitted, attempted,
                                   self.reader.bytes_read, self.reader.reads)
        self.closed = True
        return self.failure

    def _reader_failure(self, **metadata):
        if metadata.get('dimension') == 'per_file':
            metadata['dimension'] = self._read_role or 'reader_per_file'
        self.record(**metadata)

    def reject(self, message, **metadata):
        failure = self.record(**metadata)
        raise Rejected(message, failure)

    def _drift(self):
        policy_state = vars(self._policy)
        if (self.checkpoint is not self._checkpoint_pin
                or self.reader.checkpoint is not self._reader_checkpoint_pin
                or self.reader.on_failure is not self._observer_pin
                or self.policy is not self._policy
                or any(type(key) is not str for key in policy_state)
                or set(policy_state) != {'version', 'limits', 'units', '_limits_pin', '_units_pin'}
                or type(policy_state.get('version')) is not str
                or policy_state['version'] != VERSION
                or policy_state.get('limits') is not self._policy_limits_pin
                or policy_state.get('units') is not self._policy_units_pin
                or not _matches(policy_state.get('limits'), self._policy_values, MappingProxyType)
                or not _matches(policy_state.get('units'), self._policy_units, MappingProxyType)
                or self.limits is not self._limits
                or not _matches(vars(self._limits), self._limit_values, dict)
                or self.reader.limits is not self._reader_limits
                or not _matches(vars(self._reader_limits), self._reader_values, dict)):
            self.reject('frozen policy drift', category='policy_drift', phase='policy')

    def _checkpoint(self):
        try:
            self._raw_checkpoint()
        except BaseException as error:
            self.record(error=error, category='unexpected' if isinstance(error, OSError) else None, phase='checkpoint')
            raise
        self._drift()
        if self.failure is not None:
            self.reject('request context is terminal', category='terminal', phase='checkpoint')

    def check(self):
        if self.failure is not None:
            self.reject('request context is terminal', category='terminal', phase='check')
        self._drift()
        super().check()
        self._drift()

    def _cap(self, path, role):
        role = self.role(path) if role is None else role
        if role not in {'source', 'manifest', 'lock', 'sidecar', 'header'}:
            self.reject('unknown input role', category='schema', phase='read')
        key = str(Path(path).resolve())
        proposed = getattr(self.limits, role)
        previous = self._role_caps.get(key)
        if previous is not None and previous <= proposed:
            cap, origin = previous, self._cap_roles[key]
        else:
            cap, origin = proposed, role
        self._role_caps[key] = cap
        self._cap_roles[key] = origin
        self._read_role = origin
        return cap


class _Ops(package._Ops):
    def path(self, path, operation):
        try:
            return super().path(path, operation)
        except OSError as error:
            self.context.record(error=error, phase='path')
            raise

    def read(self, path, role):
        try:
            return super().read(path, role)
        except OSError as error:
            self.context.record(error=error, phase='read_binding')
            raise

    def inventory(self, root):
        try:
            yield from super().inventory(root)
        except OSError as error:
            self.context.record(error=error, phase='inventory')
            raise


class Owner(package.Owner):
    """Explicit opt-in composed owner. Original exceptions and graph semantics survive."""
    def __init__(self, policy=Policy(), checkpoint=lambda: None):
        if type(policy) is not Policy:
            raise TypeError('policy must be an exact Policy')
        state = vars(policy)
        if (any(type(key) is not str for key in state)
                or set(state) != {'version', 'limits', 'units', '_limits_pin', '_units_pin'}
                or type(state.get('version')) is not str or state['version'] != VERSION
                or state.get('limits') is not state.get('_limits_pin')
                or state.get('units') is not state.get('_units_pin')
                or type(state.get('limits')) is not MappingProxyType
                or not _matches(state.get('units'), _UNITS, MappingProxyType)):
            raise ValueError('invalid policy snapshot')
        # Revalidate a snapshot whose frozen dataclass storage was bypassed.
        values = state['limits']
        if (len(values) != len(_UNITS)
                or any(type(key) is not str or key not in _UNITS
                       or type(value) is not int for key, value in values.items())):
            raise ValueError('invalid policy snapshot')
        validated = Policy(limits=dict(values))
        if not _matches(state['limits'], validated.limits, MappingProxyType):
            raise ValueError('invalid policy snapshot')
        self.context = _Context(policy, checkpoint)
        self._ops = _Ops(self.context)
        self._handles = []
        self._busy = False
        # This profile rejects runtime mismatch before path resolution or reads.
        if not package._SUPPORTED:
            self.context.reject('unsupported Package copy runtime',
                                category='unsupported_runtime', phase='bootstrap')

    def load(self, entry, *, locked=False, source_overrides=None):
        try:
            return super().load(entry, locked=locked, source_overrides=source_overrides)
        except BaseException as error:
            self.context.record(error=error, phase='load')
            raise

    def unchanged(self, handle):
        try:
            return super().unchanged(handle)
        except BaseException as error:
            self.context.record(error=error, phase='revalidation')
            raise
