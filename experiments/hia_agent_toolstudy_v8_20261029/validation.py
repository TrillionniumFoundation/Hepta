"""Same native/type/resource gates for complete files and real node tools."""
from __future__ import annotations

import copy
from pathlib import Path
import time

from experiments.hia_agent_factorial_v4_20261028 import evaluator, fixtures
from experiments.hia_agent_factorial_v6_20261028.prompts import public_feedback
from experiments.hia_agent_structured_v7_20261029 import editing, rust_syntax
from hepta.hia_program_tools import decode_json
from tools.provider_adapter.llama_cpp_engine import canonical


def _public_feedback(task, record):
    if record.get("build") is not None:
        built = record["build"]
        value = public_feedback(task, built, record.get("public"))
        value["diagnostic"] = built.get("error") or built.get("compile", {}).get("stderr", "")
    else:
        value = {"build_status": record["status"], "diagnostic": record.get("error", ""), "public_cases": [],
                 "public_argument_order": ["a", "b", "c"]}
    value["project_source_updated"] = record.get("accepted") is True
    value["before_revision"] = record["before_revision"]
    value["after_revision"] = record["after_revision"]
    return value


def evaluate(task, language, interface, session, captured_query, text, output, clang, rustc):
    """No oracle/reference import; hidden evaluation belongs to terminal caller."""
    if interface not in {"full", "node"}:
        raise ValueError("E_TOOLSTUDY_INTERFACE")
    folder = Path(output)
    if interface == "node":
        try:
            if type(text) is not str or len(text.encode()) > editing.MAX_RESPONSE_BYTES:
                raise ValueError("E_TOOLSTUDY_RESPONSE_BYTES")
            decoded = decode_json(text)
            if type(decoded) is not dict or set(decoded) != {"edits"}:
                raise ValueError("E_TOOLSTUDY_EDITS_ENVELOPE")
            # Bind the exact query captured BEFORE the model request. Never
            # query again here and rebase an old response onto a new revision.
            response = session.response(captured_query, decoded["edits"])
        except ValueError as exc:
            folder.mkdir(parents=True, exist_ok=False)
            result = {"accepted": False, "status": "response_rejected", "before_revision": session.revision,
                      "after_revision": session.revision, "hidden_evaluated": False,
                      "error": {"type": type(exc).__name__, "message": str(exc)}}
        else:
            result = session.apply(response, folder)
        result["feedback"] = _public_feedback(task, result)
        evaluator.save(folder / "STUDY_EVALUATION.json", result)
        return result
    started = time.monotonic_ns()
    folder.mkdir(parents=True, exist_ok=False)
    before = session.revision
    result = {"accepted": False, "status": "response_rejected", "before_revision": before,
              "after_revision": before, "hidden_evaluated": False, "source_published": False}
    try:
        if before != captured_query["source_revision"] or session.query() != captured_query:
            raise ValueError("E_TOOLSTUDY_STALE_FULL_SOURCE")
        decoded = decode_json(text)
        # Original finite admission still enforces required function names,
        # signatures, unchanged files, provider calls, owner and effect rules.
        evaluator.parse_files(task, language, text, primitive_parameter_into=True)
        if language == "rust":
            for name, source in decoded["files"].items():
                rust_syntax.parse_function(source)
        else:
            for name, function in decoded["files"].items():
                original = task["original_hia"][name]
                if (function["entry"] != original["entry"] or function["effects"] != original["effects"]
                        or [block["id"] for block in function["blocks"]] != [block["id"] for block in original["blocks"]]):
                    raise ValueError("E_TOOLSTUDY_HIA_FIXED_TOPOLOGY_EFFECTS")
        built = evaluator.build(task, language, text, folder / "candidate", clang, rustc, primitive_parameter_into=True)
        observed = (evaluator.execute(built, task, task["public_cases"], task["public_expected"])
                    if built["status"] == "compiled" and built["native_built"] else None)
        result.update(build=built, public=observed, status=observed["status"] if observed else built["status"])
        if built["status"] == "infrastructure_failure" or observed and not observed["artifact_unchanged"]:
            result["status"] = "infrastructure_failure"
        elif observed and observed["status"] == "correct":
            proposed = {**copy.deepcopy(task["unchanged_" + language]), **decoded["files"]}
            revision = editing.digest(proposed)
            result.update(accepted=True, after_revision=revision)
            # A full response is a terminal validation candidate. There is no
            # subsequent edit on an accepted candidate in this study, and no
            # rejected candidate is ever installed or merged.
    except Exception as exc:
        result.update(accepted=False, after_revision=before,
                      status="response_rejected" if isinstance(exc, ValueError) else "infrastructure_failure",
                      error={"type": type(exc).__name__, "message": str(exc)})
    result["wall_ns"] = time.monotonic_ns() - started
    result["feedback"] = _public_feedback(task, result)
    evaluator.save(folder / "STUDY_EVALUATION.json", result)
    return result

