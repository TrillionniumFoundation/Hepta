"""Independent code templates for explicit patch-policy definition admission.

The passive functions at the end are never invoked by this component. Their
code objects constrain the two already loaded public definitions; they are
neither foreign business-policy ports nor historical module provenance.
"""
from __future__ import annotations

from dataclasses import dataclass
from types import CodeType, FunctionType

_TYPE = type
_CODE_FIELDS = (
    'co_argcount', 'co_posonlyargcount', 'co_kwonlyargcount', 'co_nlocals',
    'co_stacksize', 'co_flags', 'co_code', 'co_names', 'co_varnames',
    'co_freevars', 'co_cellvars', 'co_name', 'co_qualname', 'co_exceptiontable',
)


def _constant_equal(left, right):
    if _TYPE(left) is not _TYPE(right):
        return False
    if _TYPE(left) is CodeType:
        return _code_equal(left, right)
    if _TYPE(left) is tuple:
        return len(left) == len(right) and all(
            _constant_equal(a, b) for a, b in zip(left, right))
    if _TYPE(left) is slice:
        return (_constant_equal(left.start, right.start)
                and _constant_equal(left.stop, right.stop)
                and _constant_equal(left.step, right.step))
    if left is None or left is Ellipsis:
        return left is right
    if _TYPE(left) in (bool, int, str, bytes):
        return left == right
    return False


def _code_equal(left, right):
    # Only filename/line-position metadata is excluded. No unknown constant
    # equality protocol is executed while deciding the definition domain.
    return (_TYPE(left) is CodeType and _TYPE(right) is CodeType
            and all(_constant_equal(getattr(left, key), getattr(right, key))
                    for key in _CODE_FIELDS)
            and _constant_equal(left.co_consts, right.co_consts))


@dataclass(frozen=True, eq=False)
class Definition:
    function: object
    code: object
    namespace: object
    builtins: object

    def current(self, value):
        return (_TYPE(value) is FunctionType and value is self.function
                and value.__code__ is self.code
                and value.__globals__ is self.namespace
                and value.__builtins__ is self.builtins
                and value.__defaults__ is None and value.__kwdefaults__ is None
                and value.__closure__ is None)


def capture_definitions(namespace):
    """Called during explicit admission, never by a policy effect/CLI import."""
    if (_TYPE(namespace) is not dict
            or any(_TYPE(key) is not str for key in dict.keys(namespace))):
        raise ValueError('patch definition namespace is not an ordinary module dictionary')
    result = {}
    for name, expected in POLICY_CODES.items():
        value = dict.get(namespace, name)
        if (_TYPE(value) is not FunctionType or value.__globals__ is not namespace
                or value.__closure__ is not None or value.__defaults__ is not None
                or value.__kwdefaults__ is not None or _TYPE(value.__builtins__) is not dict
                or not _code_equal(value.__code__, expected)):
            raise ValueError('patch public definition differs from its independent template: ' + name)
        result[name] = Definition(value, value.__code__, namespace, value.__builtins__)
    builtins = result[next(iter(result))].builtins
    if any(record.builtins is not builtins for record in result.values()):
        raise ValueError('patch public definitions have different builtin mappings')
    return result


# PASSIVE_FROZEN_POLICIES: appended mechanically from complete original bodies.


def _check_patch_interface(original, verified, interface_policy):
    before = {f["name"]: function_signature(f, include_return_loans=True)
              for f in original.as_dict()["functions"]}
    after = {f["name"]: function_signature(f, include_return_loans=True)
             for f in verified.as_dict()["functions"]}
    changed = sorted(name for name in set(before) | set(after)
                     if before.get(name) != after.get(name))
    if changed and interface_policy != "migrate":
        _reject("interface change needs explicit v2 migrate policy: " + ", ".join(changed[:8]))
    return changed

def apply_program_patch(document, request):
    from .hia_program import verify_program
    original = verify_program(document)
    candidate, schema, interface_policy, edit_count = _prepare_program_patch(original, request)
    # Existing consumers retain full base and candidate checking, including v8
    # returned-loan interfaces. A digest never waives resource obligations.
    verified = verify_program(candidate)
    changed = _check_patch_interface(original, verified, interface_policy)
    receipt = {
        "schema": "hepta.hia.patch-result.v1", "ok": True,
        "status": "verified_unpublished", "before_sha256": original.sha256,
        "after_sha256": verified.sha256, "edits": edit_count,
        "edit_domain": "independently_verified_normalized_core",
        "original_input_sha256": getattr(original, "input_sha256", original.sha256),
        "interface_changes": changed,
        "claims": {"whole_module_rechecked": True, "behavior_equivalence_proved": False,
                   "native_executed": False},
    }
    if schema == PATCH_SCHEMA_V2:
        receipt["schema"] = "hepta.hia.patch-result.v2"
        receipt["interface_policy"] = interface_policy
        receipt["claims"]["interface_preserved"] = not changed
        # A complete self-contained Core has no external client graph.
        # Explicit migration only permits, never proves, downstream ABI safety.
        receipt["claims"]["external_callers_revalidated"] = False
    return verified, receipt

POLICY_CODES = {
    '_check_patch_interface': _check_patch_interface.__code__,
    'apply_program_patch': apply_program_patch.__code__,
}
