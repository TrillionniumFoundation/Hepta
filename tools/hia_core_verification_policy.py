"""Exact original hia_program.py policy for offline HIA authoring.
The selected runtime never imports or executes these Python bodies.
JSON, regex and existing Core providers retain their explicit boundaries.
"""

def _reject(message, code="E_HIA_PROGRAM"):
    raise HIAProgramRejected(message, code)


def verify_program(program) -> VerifiedProgram:
    """Check standalone operations and every CFG edge; no source/hash authority.

    Even a manually constructed VerifiedProgram is parsed and fully rechecked.
    Caller-owned dictionaries and decoded dictionaries never back execution.
    """
    if isinstance(program, VerifiedProgram) and program.structured_bytes is not None:
        if type(program.structured_bytes) is not bytes:
            _reject("structured input must be immutable canonical bytes", "E_HIA_FORMAT")
        checked = verify_program(program.structured_bytes)
        if (checked.structured_bytes != program.structured_bytes
                or checked.canonical_bytes != program.canonical_bytes):
            _reject("structured input and executable core differ", "E_HIA_CORE")
        return checked
    data, raw = _decode(program)
    if (type(data) is dict and type(data.get("schema")) is str
            and data["schema"] in COMPOSITE_SCHEMAS):
        from .hia_program_composite import elaborate_program
        # The entire input was bounded/strictly decoded above.  The whole
        # generated program is independently checked, with no receipt bypass.
        core = verify_program(elaborate_program(data))
        return VerifiedProgram(core.canonical_bytes, raw)
    if type(data) is dict and data.get("schema") == SCHEMA_V2 and "types" in data:
        _reject("historical nominal v2 requires import_legacy_composite_v2; "
                "the primitive v2 namespace cannot infer a producer profile",
                "E_HIA_VERSION_COLLISION")
    from .hia_core_admission_native import selected_core_structure
    selected = selected_core_structure(data, raw)
    if selected is not None:
        return VerifiedProgram(raw)
    functions, block_maps = _primitive_structure(data)
    interfaces = _function_interfaces(functions)
    for fn in functions.values():
        _verify_function(data["schema"], fn, block_maps[fn["name"]], interfaces)
    return VerifiedProgram(raw)
