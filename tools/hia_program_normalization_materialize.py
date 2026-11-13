"""Independent HIA materialization authoring input recovered from retained bytes.

The original Python BODY was not retained.  This new loader consumes the exact
eleven HIA functions preserved in the pre-compiler r10 WIP checkpoint. Their
exact 41578-byte prefix and original digest remain independently pinned. The
standalone input appends the real transitive helper closure from the separate
normalization authoring source, so the whole .hepta also receives ordinary Core
admission. Only the original eleven functions are rebound into the generated
program; no final output is read and no helper stub replaces an import.
"""
from __future__ import annotations

from hashlib import sha256
from pathlib import Path

from hepta.hia_agent_assembly import assemble_program

SOURCE_SHA256 = "ca2b5dd0560cc27cb4b5c684978d8a9a62402d79d5f91c2515eb9f3168898e24"
FRAGMENT_BYTES = 41578
FRAGMENT_SHA256 = "eb56e6922b6b47524ef7005bb15d886221e34deaa46794b7805ab819c6473008"
FRAGMENT_FUNCTIONS = tuple("f" + str(index) for index in range(66, 77))
# These twelve real helpers were derived from the independent authoring AST
# (generate_hia_program_normalization.py c52291ef; encoding.py 53eb5b06), using
# shared Builder 073f641c. Only their function/call identities were rebound.
CLOSURE_SHA256 = "ecdb7562ebc06dafc9d015cf4c9fbc3a4d77cc3847c709dfd78a93b02311a514"
CLOSURE_FUNCTIONS = (
    "f2", "f3", "f4", "support_f7", "f8", "f9", "support_f10", "f11", "f12",
    "support_f79", "support_f81", "support_f82",
)
EXPORTS = {
    "norm_mat_start": (0, ("mutbuf", "mutbuf", "u64"), "u32"),
    "norm_mat_next": (2, ("mutbuf", "mutbuf"), "u32"),
    "norm_mat_ack": (10, ("readbuf", "mutbuf", "mutbuf"), "u32"),
}
IMPORTS = {
    "f2": ("norm_read", ("readbuf", "u64", "u64"), "u64"),
    "f3": ("get", ("mutbuf", "u64"), "u64"),
    "f4": ("put", ("mutbuf", "u64", "u64"), "u64"),
    "f8": ("norm_issue", ("mutbuf", "mutbuf", "u64", "u64", "u64", "u64"), "u32"),
    "f9": ("norm_error", ("mutbuf", "mutbuf", "u64"), "u32"),
    "f11": ("norm_done", ("mutbuf", "mutbuf", "u64"), "u32"),
    "f12": ("norm_schedule", ("mutbuf", "u64", "u64"), "u32"),
}


def exported_bindings(first_id):
    if type(first_id) is not int or first_id < 0:
        raise ValueError("invalid materialization fragment function offset")
    names = {name: "f" + str(first_id + offset)
             for name, (offset, _, _) in EXPORTS.items()}
    signatures = {name: (list(params), result)
                  for name, (_, params, result) in EXPORTS.items()}
    return names, signatures


def fragment_functions(names, signatures, first_id):
    """Parse fresh independent input and bind only its explicit call closure."""
    exported, exported_signatures = exported_bindings(first_id)
    if any(names.get(name) != identity or signatures.get(name) != exported_signatures[name]
           for name, identity in exported.items()):
        raise ValueError("materialization exported signatures or identities differ")
    path = Path(__file__).with_suffix(".hepta")
    raw = path.read_bytes()
    if sha256(raw[:FRAGMENT_BYTES]).hexdigest() != FRAGMENT_SHA256:
        raise ValueError("retained materialization fragment bytes differ")
    if (sha256(raw[FRAGMENT_BYTES:]).hexdigest() != CLOSURE_SHA256
            or sha256(raw).hexdigest() != SOURCE_SHA256):
        raise ValueError("materialization standalone helper closure bytes differ")
    document = assemble_program(raw).as_dict()
    if (document.get("schema") != "hepta.hia.program.v8"
            or document.get("module") != "program_normalization_materialize"
            or set(document) != {"schema", "module", "functions"}
            or tuple(function["name"] for function in document["functions"])
               != FRAGMENT_FUNCTIONS + CLOSURE_FUNCTIONS):
        raise ValueError("materialization fragment inventory differs")
    mapping = {name: "f" + str(first_id + offset)
               for offset, name in enumerate(FRAGMENT_FUNCTIONS)}
    for original, (name, params, result) in IMPORTS.items():
        if name not in names or signatures.get(name) != (list(params), result):
            raise ValueError("materialization import signature differs: " + name)
        mapping[original] = names[name]
    if len(set(mapping.values())) != len(mapping):
        raise ValueError("materialization import or local identity collision")
    functions = document["functions"][:len(FRAGMENT_FUNCTIONS)]
    for name, (offset, params, result) in EXPORTS.items():
        function = functions[offset]
        if ([p["type"] for p in function["params"]] != list(params)
                or function["returns"] != [result]):
            raise ValueError("materialization retained export differs: " + name)
    observed_imports = set()
    for function in functions:
        function["name"] = mapping[function["name"]]
        for block in function["blocks"]:
            for operation in block["ops"]:
                if operation["op"] != "call":
                    continue
                target = operation["attrs"].get("function")
                if target not in mapping:
                    raise ValueError("materialization call leaves the explicit closure")
                if target in IMPORTS:
                    observed_imports.add(target)
                operation["attrs"]["function"] = mapping[target]
    if observed_imports != set(IMPORTS):
        raise ValueError("materialization import inventory differs")
    return functions
