"""Experimental LLVM entry dispatch, outside production native admission.

Keep the complete reverified Core body on both paths. Only the equality-guarded
call substitutes zero; LLVM may inline it. The generic call is kept out of line
to avoid forcing its callee-saved frame onto the empty path. No Core instruction,
resource action, checked operation or native argument check is manually erased.
"""
from hashlib import sha256

from hepta import hia_program_llvm as native
from hepta.hia_program import verify_program


def emit_candidate(program, selections):
    verified = verify_program(program)
    original = native.emit_program_llvm(verified)
    document = verified.as_dict()
    if (type(selections) is not dict or not 1 <= len(selections) <= 128
            or not all(type(k) is str and type(v) is str for k, v in selections.items())):
        raise ValueError("bounded function/length selections required")
    emitter = native._Emitter(document, original.target, verified.scalar_entrypoints)
    text, checked = original.text, []
    for index, fn in enumerate(document["functions"]):
        if fn["name"] not in selections:
            continue
        argument = selections[fn["name"]]
        params = fn["params"]
        if (fn["name"] not in original.exports or type(argument) is not str
                or len(fn["returns"]) != 1 or fn["returns"][0] not in native._WIDTHS
                or sum(p["name"] == argument and p["type"] == "usize" for p in params) != 1):
            raise ValueError("integer-returning scalar export with actual usize argument required")
        selected = next(i for i, p in enumerate(params) if p["name"] == argument)
        old = emitter.wrapper(fn, index)
        if text.count(old) != 1:
            raise ValueError("canonical wrapper missing or ambiguous")
        ordinary = ", ".join(native._llvm_type(p["type"]) + " %a" + str(i) for i, p in enumerate(params))
        zero = ", ".join(native._llvm_type(p["type"]) + (" 0" if i == selected else " %a" + str(i))
                         for i, p in enumerate(params))
        call = native._return_type(fn["returns"]) + " @__hia_fn_" + str(index)
        result = native._llvm_type(fn["returns"][0])
        replacement = "\n".join([
            old.splitlines()[0], "entry:", "  %is_empty = icmp eq i64 %a" + str(selected) + ", 0",
            "  br i1 %is_empty, label %zero, label %ordinary", "zero:",
            "  %zero_result = call " + call + "(" + zero + ") alwaysinline",
            "  ret " + result + " %zero_result", "ordinary:",
            "  %result = call " + call + "(" + ordinary + ") noinline", "  ret " + result + " %result", "}"])
        text = text.replace(old, replacement, 1)
        checked.append({"function": fn["name"], "argument": argument, "parameter_index": selected,
                        "canonical_wrapper": old, "candidate_wrapper": replacement})
    if len(checked) != len(selections) or len(text.encode()) > native.MAX_LLVM_BYTES:
        raise ValueError("unknown selection or candidate LLVM exceeds bound")
    return text, {"schema": "hepta.hia.experimental-zero-dispatch.v1", "core_sha256": verified.sha256,
                  "canonical_llvm_sha256": original.sha256, "candidate_llvm_sha256": sha256(text.encode()).hexdigest(),
                  "wrappers": checked, "native_profile": original.profile, "target": original.target,
                  "exports": list(original.exports), "production_admission": False,
                  "backend_refinement_proved": False, "performance_qualified": False}
