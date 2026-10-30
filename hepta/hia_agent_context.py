"""Bounded, snapshot-bound views for maintaining existing primitive HIA.

A view is an information request, never a new program or admission cache. The
whole input is verified on every request. Selected function definitions are
unmodified, so the existing hia.patch.v1/v2 grammar can edit the same snapshot.
All patches still go through hia_program_tools.apply_program_patch.
"""
from __future__ import annotations

from hashlib import sha256

from .hia_agent_assembly import CORE_SCHEMAS, render_assembly
from .hia_opcodes import opcode_catalog
from .hia_program import verify_program
from .hia_program_tools import (HIAEditRejected, MAX_INPUT_BYTES,
                                bounded_json_wire, function_signature)


CONTEXT_SCHEMA = "hepta.hia.agent-context.v1"
SLICE_SCHEMA = "hepta.hia.agent-opcode-slice.v1"
MEASUREMENT_SCHEMA = "hepta.hia.agent-payload-measurement.v1"
MAX_FOCUS_FUNCTIONS = 32
MAX_EXTRA_OPCODES = 64


def _wire(value):
    return bounded_json_wire(value, MAX_INPUT_BYTES, ensure_ascii=False)


def _reject(message):
    raise HIAEditRejected("E_HIA_CONTEXT: " + message)


def _names(value, limit, label, *, allow_empty=False):
    if (type(value) not in (list, tuple) or len(value) > limit
            or (not value and not allow_empty)
            or any(type(name) is not str for name in value)
            or len(set(value)) != len(value)):
        _reject(label + " must be a bounded list of unique names")
    return sorted(value)


def _checked(document):
    checked = verify_program(document)
    data = checked.as_dict()
    if checked.structured_bytes is not None or data["schema"] not in CORE_SCHEMAS:
        _reject("context requires explicit primitive Core v6/v7/v8; use the existing adapter first")
    return checked, data


def _view(checked, data, focus, extra_opcodes):
    functions = {fn["name"]: fn for fn in data["functions"]}
    selected = _names(focus, MAX_FOCUS_FUNCTIONS, "focus")
    extras = _names(extra_opcodes, MAX_EXTRA_OPCODES, "extra_opcodes", allow_empty=True)
    if any(name not in functions for name in selected):
        _reject("unknown focus function")
    selected_set = set(selected)
    calls = []
    used = set(extras)
    for fn in data["functions"]:
        for block in fn["blocks"]:
            for index, instruction in enumerate(block["ops"]):
                if fn["name"] in selected_set:
                    used.add(instruction["op"])
                if instruction["op"] == "call":
                    calls.append({"caller": fn["name"], "callee": instruction["attrs"]["function"],
                                  "block": block["id"], "index": index})
    outgoing = [call for call in calls if call["caller"] in selected_set]
    incoming = [call for call in calls if call["callee"] in selected_set]
    boundary = sorted(({call["callee"] for call in outgoing}
                       | {call["caller"] for call in incoming}) - selected_set)
    catalog = opcode_catalog(data["schema"])
    available = {row["name"] for row in catalog["instructions"]}
    if not used <= available:
        _reject("extra opcode is unavailable in this exact Core schema")
    # A sliced catalog has its own schema and hash. Its complete-catalog hash
    # is a lookup identity, not a claim that omitted instructions were sent.
    sliced = {key: value for key, value in catalog.items()
              if key not in {"schema", "catalog_sha256", "instructions"}}
    sliced.update(schema=SLICE_SCHEMA, complete_catalog=False,
                  complete_catalog_sha256=catalog["catalog_sha256"],
                  complete_instruction_count=len(catalog["instructions"]),
                  instructions=[row for row in catalog["instructions"] if row["name"] in used])
    sliced["slice_sha256"] = sha256(_wire(sliced)).hexdigest()
    result = {
        "schema": CONTEXT_SCHEMA,
        "snapshot_sha256": checked.sha256,
        "program_envelope": {key: value for key, value in data.items() if key != "functions"},
        "focus": selected,
        "functions": [functions[name] for name in selected],
        "boundary_interfaces": [function_signature(functions[name], include_return_loans=True)
                                for name in boundary],
        "incoming_calls": sorted(incoming, key=lambda row: (row["caller"], row["block"], row["index"])),
        "outgoing_calls": sorted(outgoing, key=lambda row: (row["caller"], row["block"], row["index"])),
        "available_functions": sorted(functions),
        "omitted_body_count": len(functions) - len(selected),
        "opcode_slice": sliced,
        "continuation": {
            "more_bodies": "request another context with the same document and selected function names",
            "more_opcodes": "request extra_opcodes, or use hepta hia catalog --schema with the exact Core schema",
            "patch": "existing hepta.hia.patch.v1/v2; expected_sha256 must equal snapshot_sha256",
            "admission": "hepta.hia_program_tools.apply_program_patch rechecks the entire current module",
        },
        "claims": {
            "whole_input_verified": True, "selected_bodies_complete": True,
            "selected_definitions_unchanged": True, "complete_direct_call_boundary": True,
            "complete_behavioral_dependencies": False, "standalone_executable_program": False,
            "digest_grants_admission": False, "native_execution": False,
            "model_productivity_proved": False,
        },
    }
    result["context_sha256"] = sha256(_wire(result)).hexdigest()
    _wire(result)  # Refuse oversized output; never silently truncate a view.
    return result


def focused_context(document, functions, *, extra_opcodes=()):
    """Read full selected bodies and exact direct call interfaces from Core.

    Incoming/outgoing call sites are navigation metadata, not a whole-program
    semantic impact proof. A caller must request omitted bodies if needed.
    There is no persistent state and no caller-supplied cache receipt.
    """
    checked, data = _checked(document)
    return _view(checked, data, functions, extra_opcodes)


def measure_payloads(document, functions, *, extra_opcodes=()):
    """Count actual canonical UTF-8 bytes; do not estimate model tokens/time.

    Full JSON/assembly baselines include the complete version-specific catalog.
    The focused envelope contains its actual boundary and navigation overhead.
    A focused envelope may be larger; negative savings are retained.
    """
    checked, data = _checked(document)
    view = _view(checked, data, functions, extra_opcodes)
    catalog = opcode_catalog(data["schema"])
    assembly = render_assembly(checked)
    complete_json = _wire({"program": data, "opcode_catalog": catalog})
    complete_assembly = _wire({"assembly": assembly, "opcode_catalog": catalog})
    focused = _wire(view)
    result = {
        "schema": MEASUREMENT_SCHEMA,
        "snapshot_sha256": checked.sha256,
        "context_sha256": view["context_sha256"],
        "unit": "actual UTF-8 bytes of the declared envelopes, without a trailing newline",
        "bytes": {"core_canonical": len(checked.canonical_bytes),
                  "assembly_source": len(assembly.encode("utf-8")),
                  "complete_json_with_catalog": len(complete_json),
                  "complete_assembly_with_catalog": len(complete_assembly),
                  "focused_json_with_opcode_slice": len(focused)},
        "savings_bytes": {"from_complete_json": len(complete_json) - len(focused),
                          "from_complete_assembly": len(complete_assembly) - len(focused)},
        "envelope_sha256": {"complete_json": sha256(complete_json).hexdigest(),
                            "complete_assembly": sha256(complete_assembly).hexdigest(),
                            "focused": sha256(focused).hexdigest()},
        "comparison_scope": "one authored information request; omitted bodies/catalog may require later requests",
        "model_requests": 0, "model_tokens": None, "model_wall_ns": None,
        "claims": {"lossless_selected_definitions": True,
                   "full_program_semantic_compression": False,
                   "model_efficiency_improvement": False,
                   "whole_task_payload_savings": False},
    }
    _wire(result)
    return result
