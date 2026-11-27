"""Complete retained patch policies; consumed only by the offline generator."""

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
