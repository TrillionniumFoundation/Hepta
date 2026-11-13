"""Explicit selection between reviewed bundle and single-image Core families.

The original selectors keep their bundle and in-process scheduling protocols.
The CONTROL selectors name independent single-image ABIs. Both selectors for
one owner are rejected before admission; a captured selection, including None,
cannot be replaced by a later callback. This module performs no backend policy.
"""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
import importlib
import os


@dataclass(frozen=True, eq=False)
class _Route:
    family: str | None
    owner: object
    admission: object = None
    primary_admission: object = None


class _FamilySelection:
    def __init__(self, name, bundle_module, control_module, bundle_selector,
                 control_selector, installed, control_admit,
                 primary_family='bundle', primary_admit=None):
        self.name = name
        self.bundle_module = bundle_module
        self.control_module = control_module
        self.bundle_selector = bundle_selector
        self.control_selector = control_selector
        self.installed = installed
        self.control_admit = control_admit
        self.primary_family = primary_family
        self.primary_admit = primary_admit
        self._unscoped = object()
        self._route = ContextVar(name + "_explicit_family", default=self._unscoped)

    def _modules(self):
        # All names above are fixed source literals, never manifest fields.
        return (importlib.import_module("." + self.bundle_module, __package__),
                importlib.import_module("." + self.control_module, __package__))

    def _captured(self, bundle, control):
        old = bundle._OWNER.get()
        new = control._OWNER.get()
        old_scoped = old is not bundle._UNSELECTED
        new_scoped = new is not control._UNSELECTED
        if not old_scoped and not new_scoped:
            return self._unscoped
        old_admission = old if old_scoped else None
        old_owner = (None if old_admission is None else old_admission.owner) if self.primary_admit else old_admission
        new_admission = new if new_scoped else None
        new_owner = None if new_admission is None else new_admission.owner
        if old_owner is not None and new_owner is not None:
            raise ValueError(self.name + " bundle and CONTROL scopes overlap")
        if old_owner is not None:
            return _Route(self.primary_family, old_owner, primary_admission=old_admission if self.primary_admit else None)
        if new_owner is not None:
            return _Route("control", new_owner, new_admission)
        return _Route(None, None)

    def _select(self, namespace):
        captured = self._route.get()
        if captured is not self._unscoped:
            return captured
        bundle, control = self._modules()
        captured = self._captured(bundle, control)
        if captured is not self._unscoped:
            return captured
        old_path = os.environ.get(self.bundle_selector)
        new_path = os.environ.get(self.control_selector)
        if old_path and new_path:
            raise ValueError(self.name + " requires one explicit native family")
        if old_path:
            if self.primary_admit:
                admitted = getattr(bundle, self.primary_admit)(old_path, namespace)
                return _Route(self.primary_family, admitted.owner, primary_admission=admitted)
            return _Route(self.primary_family, getattr(bundle, self.installed)(old_path, namespace))
        if new_path:
            admitted = getattr(control, self.control_admit)(new_path, namespace)
            return _Route("control", admitted.owner, admitted)
        return _Route(None, None)

    def selected(self, namespace):
        return self._select(namespace).owner

    def observe(self):
        """Return captured scope, family and owner without selecting or admitting."""
        captured = self._route.get()
        if captured is self._unscoped:
            captured = self._captured(*self._modules())
        if captured is self._unscoped:
            return False, None, None
        return True, captured.family, captured.owner

    def active(self):
        scoped, family, owner = self.observe()
        return family, owner

    @contextmanager
    def _bind(self, selected):
        bundle, control = self._modules()
        previous_route = self._route.get()
        previous_bundle = bundle._OWNER.get()
        previous_control = control._OWNER.get()
        try:
            # Record every prior value before set. Losing a set() return value
            # or an intermediate STORE cannot leak a selection after unwind.
            primary = selected.primary_admission if self.primary_admit else selected.owner
            bundle._OWNER.set(primary if selected.family == self.primary_family else None)
            control._OWNER.set(selected.admission if selected.family == "control" else None)
            self._route.set(selected)
            yield
        finally:
            try:
                self._route.set(previous_route)
            finally:
                try:
                    control._OWNER.set(previous_control)
                finally:
                    bundle._OWNER.set(previous_bundle)

    @contextmanager
    def scope(self, namespace):
        selected = self._select(namespace)
        with self._bind(selected):
            yield

    def identity(self, namespace):
        selected = self._select(namespace)
        if selected.owner is None:
            return b""
        bundle, control = self._modules()
        with self._bind(selected):
            if selected.family == self.primary_family:
                raw = bundle._bundle_implementation_identity(namespace)
            elif selected.family == "control":
                raw = control.native_implementation_identity(namespace)
            else:
                raise ValueError(self.name + " captured family is outside its inventory")
        return selected.family.encode("ascii") + b"\0" + raw


lowering_family = _FamilySelection(
    "native Core lowering", "hia_core_lowering_selection",
    "hia_core_lowering_control_selection",
    "HEPTA_HIA_CORE_LOWERING_MANIFEST", "HEPTA_HIA_CORE_LOWERING_CONTROL_MANIFEST",
    "installed_core_lowering", "_admit")
emitter_family = _FamilySelection(
    "native Core emitter", "hia_core_emitter_selection",
    "hia_core_emitter_control_selection",
    "HEPTA_HIA_CORE_EMITTER_MANIFEST", "HEPTA_HIA_CORE_EMITTER_CONTROL_MANIFEST",
    "installed_core_emitter", "_admit")

plan_family = _FamilySelection(
    "native machine plan", "hia_machine_plan_native",
    "hia_machine_plan_control_selection",
    "HEPTA_HIA_MACHINE_PLAN_MANIFEST", "HEPTA_HIA_MACHINE_PLAN_CONTROL_MANIFEST",
    "installed_machine_plan", "_admit", primary_family="plan-v1",
    primary_admit="_admit_family")

elf_family = _FamilySelection(
    "native ELF object", "hia_machine_object_selection",
    "hia_machine_elf_selection",
    "HEPTA_HIA_MACHINE_OBJECT_MANIFEST", "HEPTA_HIA_MACHINE_ELF_MANIFEST",
    "installed_machine_object", "_admit")
