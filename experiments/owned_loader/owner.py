"""Finite read-admission integration, not a complete bounded production loader.

Trusts the ordinary Python runtime and private implementation. Namespace hooks
listed below are rejected; arbitrary concurrent mutation/reflection is not a
sandbox boundary. Graph/depth/path/edge quotas are deliberately not claimed.
"""
from dataclasses import dataclass
import copy
import inspect
import json
from pathlib import Path
import tomllib

from hepta import modules, packages, parser, lexer
from hepta._loader_ops import LegacyLoaderOps
from experiments.request_load.context import Context, Limits, Rejected

# Trusted bootstrap identities. Public aliases may already be replaced: compare
# those against canonical originals, not against their possibly patched value.
_PARSE, _TOKENIZE = parser.parse, lexer.tokenize
_JSON, _TOML = json.loads, tomllib.loads
_BINDINGS = (
    (modules, 'load_package', packages._LEGACY_LOAD_PACKAGE),
    (packages, 'load_package', packages._LEGACY_LOAD_PACKAGE),
    (modules, 'package_snapshot', packages._LEGACY_PACKAGE_SNAPSHOT),
    (packages, 'package_snapshot', packages._LEGACY_PACKAGE_SNAPSHOT),
    (modules, 'verify_lock', packages._LEGACY_VERIFY_LOCK),
    (packages, 'verify_lock', packages._LEGACY_VERIFY_LOCK),
    (modules, 'find_manifest', packages._LEGACY_FIND_MANIFEST),
    (packages, 'find_manifest', packages._LEGACY_FIND_MANIFEST),
    (modules, 'parse', _PARSE), (modules, 'tokenize', _TOKENIZE),
    (parser, 'parse', _PARSE), (lexer, 'tokenize', _TOKENIZE),
    (modules, 'json', json), (packages, 'json', json),
    (packages, 'tomllib', tomllib),
    (json, 'loads', _JSON), (tomllib, 'loads', _TOML),
)


class _Context(Context):
    def check(self):
        super().check()
        # A callback may swallow nested rejection; never reopen terminal state.
        if self.closed:
            self.reject('request context is terminal')
        # Check after the caller's checkpoint too: it may replace a namespace.
        for namespace, name, expected in _BINDINGS:
            if getattr(namespace, name, None) is not expected:
                self.reject('replacement hook is not admitted: ' + name)
        if inspect.getattr_static(modules.LoadedProject, 'unchanged', None) is not modules._LEGACY_UNCHANGED:
            self.reject('replacement revalidation hook is not admitted')


class _Ops(LegacyLoaderOps):
    def __init__(self, context):
        self.context = context
        self.roles = {}
        self.lexical_roles = {}
        self.bindings = {}

    def hook(self, hook, original):
        self.context.check()
        if hook is not original:
            self.context.reject('replacement hook is not admitted')

    def revalidation_hook(self, project, original):
        self.context.check()
        if type(project) is not modules.LoadedProject or inspect.getattr_static(project, 'unchanged', None) is not original:
            self.context.reject('replacement revalidation hook is not admitted')

    def read(self, path, role):
        self.context.check()
        lexical = str(Path(path).absolute())
        key = str(Path(path).resolve())
        previous_target = self.bindings.get(lexical)
        if previous_target is not None and previous_target != key:
            self.context.reject('admitted input binding changed')
        if role == 'revalidation':
            if lexical not in self.lexical_roles:
                self.context.reject('revalidation input has no admitted role')
            role = self.lexical_roles[lexical]
        elif role not in {'source', 'manifest', 'lock', 'sidecar', 'header'}:
            self.context.reject('unknown input role')
        for old in (self.roles.get(key), self.lexical_roles.get(lexical)):
            if old is not None and getattr(self.context.limits, old) < getattr(self.context.limits, role):
                role = old
        self.roles[key] = self.lexical_roles[lexical] = role
        self.bindings[lexical] = key
        data = self.context.read(path, role)
        if str(Path(path).resolve()) != key:
            self.context.reject('admitted input binding changed during read')
        return data

    def inventory(self, root):
        return self.context.inventory(root)

    def json(self, loads, data, path):
        self.hook(loads, _JSON)
        return self.context.json(data, path)

    def toml(self, loads, data, path):
        self.hook(loads, _TOML)
        return self.context.toml(data, path)

    def tokenize(self, tokenize, text, path):
        self.hook(tokenize, _TOKENIZE)
        return self.context.tokenize(text, path)

    def parse(self, parse, text, path):
        self.hook(parse, _PARSE)
        # Deliberately retain two admitted lexing passes, no token cache or
        # token-provenance transfer is claimed by this narrow integration.
        return self.context.parse(text, path)


@dataclass(eq=False, frozen=True)
class _OwnedGraph:
    project: modules.LoadedProject
    _owner: object

    def unchanged(self):
        return self._owner.unchanged(self)


class Owner:
    """Experimental private entry point. No production caller selects it."""
    def __init__(self, limits=Limits(), checkpoint=lambda: None):
        defaults = Limits()
        for name in ('packages', 'package_depth', 'package_edges', 'module_edges',
                     'path_checks', 'modules', 'module_depth'):
            if getattr(limits, name) != getattr(defaults, name):
                raise ValueError('unsupported normal-loader limit: ' + name)
        self.context = _Context(limits, checkpoint)
        self._ops = _Ops(self.context)
        self._handles = []
        self._busy = False

    def _enter(self):
        try:
            self.context.check()
            if self._busy:
                self.context.reject('reentrant owner operation is not admitted')
            self._busy = True
        except BaseException:
            self.context.closed = True
            raise

    def _authority_copy(self, deepcopy, value, name):
        """Legacy one-argument copy; subclasses may admit selected map copies."""
        try:
            return deepcopy(value)
        finally:
            del deepcopy, value

    def load(self, entry, *, locked=False, source_overrides=None):
        self._enter()
        try:
            if source_overrides is not None:
                self.context.reject('source overrides are not admitted by this experimental profile')
            graph = modules._load_project(entry, locked=locked, ops=self._ops)
            handle = _OwnedGraph(graph, self)
            # Disk revalidation authority must not alias report/public graph maps.
            authority = copy.copy(graph)
            for name in ('source_bytes', 'bindings', 'package_state', 'package'):
                setattr(authority, name, self._authority_copy(copy.deepcopy, getattr(graph, name), name))
            self._handles.append((handle, authority))
            return handle
        except BaseException:
            self.context.closed = True
            raise
        finally:
            self._busy = False

    def unchanged(self, handle):
        self._enter()
        try:
            authority = next((graph for known, graph in self._handles if handle is known), None)
            if authority is None:
                self.context.reject('graph handle does not belong to this owner')
            self._ops.revalidation_hook(handle.project, modules._LEGACY_UNCHANGED)
            return modules._revalidate(authority, ops=self._ops)
        except BaseException:
            self.context.closed = True
            raise
        finally:
            self._busy = False
