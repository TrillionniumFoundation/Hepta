"""The common standalone executable authority and explicit legacy imports.

New HIA inputs go directly to verify_core and need no source. Legacy inputs
retain their original source-authentication gate during conversion; after
conversion only the resulting typed operations are executed. The scalar path
translates actual old SSA instructions/PHIs, rather than replaying the source
through a second high-level compiler. The executable path decodes its actual
structured operations and lowers that checked AST. This is not a refinement
proof, and the old source profiles do not widen the standalone profile.
"""
from __future__ import annotations

import json

from .hia_program import SCHEMA, VerifiedProgram, verify_program


verify_core = verify_program


def from_executable_core(document, *, source, path=None, project_sha256=None,
                         module=None) -> VerifiedProgram:
    from .executable_core import decode_executable_core
    from .hia_program_source import lower_program
    program, checked = decode_executable_core(document, source=source, path=path,
                                               project_sha256=project_sha256)
    return verify_core(lower_program(program, checked, module=module))


def _refs(node):
    """References in an expression, without mistaking metadata for execution."""
    if not isinstance(node, dict):
        return set()
    result = {node["ssa_ref"]} if node.get("operation") == "name" else set()
    for child in node.get("operands", []):
        result.update(_refs(child))
    return result


def _successors(term):
    if term["kind"] == "goto":
        return [term["target"]]
    if term["kind"] == "branch":
        return [term["then"], term["else"]]
    return []


def _convert_scalar_function(fn, original):
    """Close globally named SSA over explicit block arguments and edge values."""
    blocks = {block["id"]: block for block in fn["blocks"]}
    definitions = {p["ssa_name"]: p["type"] for p in fn["parameters"]}
    phi_in, phi_defs, local_defs, uses = {}, {}, {}, {}
    for ident, block in blocks.items():
        phi_in[ident] = {
            phi["result"]["ssa_name"]: {edge["from"]: edge["ssa_ref"]
                                         for edge in phi["incoming"]}
            for phi in block["phis"]}
        phi_defs[ident] = set(phi_in[ident])
        local_defs[ident] = set(phi_defs[ident])
        used = set()
        for phi in block["phis"]:
            definitions[phi["result"]["ssa_name"]] = phi["result"]["type"]
        for ins in block["instructions"]:
            used.update(_refs(ins["ssa_value"]) - local_defs[ident])
            if ins.get("definition") is not None:
                definition = ins["definition"]
                definitions[definition["ssa_name"]] = definition["type"]
                local_defs[ident].add(definition["ssa_name"])
        term = block["terminator"]
        used.update(_refs(term.get("condition")) - local_defs[ident])
        used.update(_refs(term.get("value")) - local_defs[ident])
        uses[ident] = used

    # Standard backwards liveness, including the predecessor-selected PHI
    # inputs. No zero/uninitialized stand-ins for unavailable predecessor data.
    live = {ident: set(uses[ident]) for ident in blocks}
    for _ in range(len(blocks) + 1):
        changed = False
        for ident, block in reversed(list(blocks.items())):
            required = set(uses[ident])
            for target in _successors(block["terminator"]):
                incoming = set(live[target])
                incoming.update(table[ident] for table in phi_in[target].values())
                required.update(incoming - local_defs[ident])
            if required != live[ident]:
                live[ident] = required
                changed = True
        if not changed:
            break
    else:
        raise ValueError("E_HIA_IMPORT: scalar liveness did not converge within CFG bound")

    entry = fn["entry"]
    entry_refs = [p["ssa_name"] for p in fn["parameters"]]
    if not live[entry] <= set(entry_refs) or phi_defs[entry]:
        raise ValueError("E_HIA_IMPORT: non-parameter reference at scalar entry")
    param_refs = {ident: (entry_refs if ident == entry else
                          sorted(live[ident] | phi_defs[ident])) for ident in blocks}
    block_ids = {ident: "b" + str(i) for i, ident in enumerate(blocks)}
    params = {ident: [{"name": "p" + str(i) + "_" + str(j), "type": definitions[ref]}
                       for j, ref in enumerate(param_refs[ident])]
              for i, ident in enumerate(blocks)}
    result_blocks = []
    serial = 0
    effects = set()
    binary = {"+": "int.add.checked", "-": "int.sub.checked", "*": "int.mul.checked",
              "==": "compare.eq", "!=": "compare.ne", "<": "compare.lt",
              "<=": "compare.le", ">": "compare.gt", ">=": "compare.ge"}
    for ident, block in blocks.items():
        env = {ref: p["name"] for ref, p in zip(param_refs[ident], params[ident])}
        ops = []

        def expr(node):
            nonlocal serial
            kind, value = node["operation"], node["value"]
            if kind == "name":
                try:
                    return env[node["ssa_ref"]]
                except KeyError as exc:
                    raise ValueError("E_HIA_IMPORT: predecessor value is not available") from exc
            args = [expr(child) for child in node["operands"]]
            if kind in {"int", "bool"}:
                op, attrs = "const", {"value": value}
            elif kind == "binary" and value in binary:
                op, attrs = binary[value], {}
            elif kind == "unary" and value == "-":
                op, attrs = "int.neg.checked", {}
            else:
                raise ValueError("E_HIA_IMPORT: unsupported verified scalar expression")
            if op.endswith("checked"):
                effects.add("trap")
            serial += 1
            name = "v" + str(serial)
            ops.append({"op": op, "args": args,
                        "out": [{"name": name, "type": node["result_type"]["type"]}],
                        "attrs": attrs})
            return name

        def edge(target):
            args = []
            for ref in param_refs[target]:
                incoming = phi_in[target][ref][ident] if ref in phi_in[target] else ref
                if incoming not in env:
                    raise ValueError("E_HIA_IMPORT: incomplete live edge inventory")
                args.append(env[incoming])
            return {"target": block_ids[target], "args": args}

        for ins in block["instructions"]:
            value = expr(ins["ssa_value"])
            if ins.get("definition") is not None:
                env[ins["definition"]["ssa_name"]] = value
        term = block["terminator"]
        if term["kind"] == "goto":
            lowered_term = {"op": "jump", **edge(term["target"])}
        elif term["kind"] == "branch":
            lowered_term = {"op": "branch", "cond": expr(term["condition"]),
                            "then": edge(term["then"]), "else": edge(term["else"])}
        elif term["kind"] == "return":
            lowered_term = {"op": "ret", "values": [expr(term["value"])]}
        else:
            raise ValueError("E_HIA_IMPORT: unsupported scalar terminator")
        result_blocks.append({"id": block_ids[ident], "params": params[ident],
                              "ops": ops, "term": lowered_term})
    return {"name": fn["name"], "params": params[entry],
            "returns": [original["return_type"]["type"]], "effects": sorted(effects),
            "entry": block_ids[entry], "blocks": result_blocks}


def from_scalar_core(core, *, program, checked, project_sha256,
                     module=None) -> VerifiedProgram:
    """Import authenticated old HIA SSA, consuming actual PHIs and operations."""
    from .hia_core import HIAScalarCore
    from .llvm_ssa_backend import emit_scalar_ssa_llvm
    if not isinstance(core, HIAScalarCore):
        raise ValueError("E_HIA_IMPORT: expected the legacy HIA scalar snapshot")
    ssa, cfg, _ = core.qualified_for(program, checked, project_sha256=project_sha256)
    # Establish the exact old executable subset without invoking any compiler.
    emit_scalar_ssa_llvm(ssa, cfg)
    scalar, control = json.loads(ssa.canonical_json), json.loads(cfg.canonical_json)
    if ([fn["name"] for fn in scalar["functions"]] !=
            [fn["name"] for fn in control["functions"]]):
        raise ValueError("E_HIA_IMPORT: SSA/CFG function inventories differ")
    functions = [_convert_scalar_function(fn, orig)
                 for fn, orig in zip(scalar["functions"], control["functions"])]
    return verify_core({"schema": SCHEMA, "module": module or program.name,
                        "functions": functions})


def execute_core(program, function, arguments, **limits):
    from .hia_program_runtime import execute_program
    return execute_program(verify_core(program), function, arguments, **limits)


def build_core(program, output, *, clang="clang", kind="shared",
               target="x86_64-unknown-linux-gnu"):
    from .hia_program_llvm import build_program_native
    return build_program_native(verify_core(program), output, clang=clang, kind=kind, target=target)
