"""Finite source-qualified execution oracle for the existing HIA i32/u32 SSA.

This interprets *verified* SSA values and CFG transitions, not source AST or
LLVM text. It provides an independent finite differential oracle for the
existing scalar native emitter. It is not a second compiler, a resource IR
interpreter, a general soundness proof, or an authorization to publish code.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import re

from .hia_core import HIAScalarCore
from .llvm_ssa_backend import emit_scalar_ssa_llvm

_IDENT = re.compile(r"[A-Za-z_][A-Za-z_0-9]*\Z")
_LOW = {"i32": -(1 << 31), "u32": 0}
_HIGH = {"i32": (1 << 31) - 1, "u32": (1 << 32) - 1}
_OPERATORS = {"+", "-", "*", "==", "!=", "<", "<=", ">", ">="}
_MAX_STEPS = 1_000_000


class HIAOracleRejected(ValueError):
    """Unsupported program, malformed inputs, or unqualified source."""


class HIAOracleTrap(ArithmeticError):
    """A defined checked-arithmetic trap; compare with native child abort."""


class HIAOracleBudgetExceeded(RuntimeError):
    """Execution limit, NOT a semantic trap or proof of nontermination."""


def _reject(reason: str) -> None:
    raise HIAOracleRejected("E_HIA_ORACLE: " + reason)


def _type(kind: str) -> dict:
    return {"type": kind, "args": [], "length": None}


@dataclass(frozen=True)
class HIAScalarOracle:
    """Prepared one-source finite value oracle, not an authoritative receipt.

    Instantiate through prepare_scalar_oracle to force live checked-source
    replay and an exact native-emitter-profile check first.
    """
    core_sha256: str
    ssa_sha256: str
    project_sha256: str
    ssa_canonical_json: str
    return_words: tuple[tuple[str, str], ...]

    def run(self, function: str, arguments: tuple[int, ...] | list[int], *,
            max_steps: int = 20000) -> int:
        if (type(function) is not str or _IDENT.fullmatch(function) is None
                or type(arguments) not in (tuple, list)
                or type(max_steps) is not int or not 1 <= max_steps <= _MAX_STEPS):
            _reject("invalid function, argument collection or finite step budget")
        # Keep the prepared executable graph as immutable canonical bytes,
        # not a publicly mutable tuple of nested dictionaries. Refuse drift
        # from the exact prepared SSA digest on *every* evaluation.
        if type(self.ssa_canonical_json) is not str:
            _reject("prepared executable graph has invalid wire type")
        try:
            if sha256(self.ssa_canonical_json.encode("utf-8")).hexdigest() != self.ssa_sha256:
                _reject("prepared SSA bytes have changed")
            functions = json.loads(self.ssa_canonical_json).get("functions")
        except HIAOracleRejected:
            raise
        except (UnicodeError, ValueError, TypeError, AttributeError) as exc:
            raise HIAOracleRejected("E_HIA_ORACLE: malformed prepared SSA bytes") from exc
        if type(functions) is not list:
            _reject("missing SSA functions")
        found = [fn for fn in functions if type(fn) is dict and fn.get("name") == function]
        if len(found) != 1:
            _reject("missing or ambiguous exported scalar function")
        fn = found[0]
        types = fn.get("scalar_types")
        parameters = fn.get("parameters")
        if type(types) is not dict or type(parameters) is not list:
            _reject("SSA function inventory is malformed")
        entry = fn.get("entry")
        if type(entry) is not str or len(parameters) != len(arguments):
            _reject("wrong argument count or entry block")
        if (type(self.return_words) is not tuple or
                any(type(x) is not tuple or len(x) != 2 or
                    type(x[0]) is not str or type(x[1]) is not str for x in self.return_words)):
            _reject("return type inventory has invalid shape")
        words = dict(self.return_words)
        if len(words) != len(self.return_words) or len(words) != len(functions):
            _reject("return type inventory must match each unique function")
        word = words.get(function)
        if word not in _LOW or any(type(ty) is not str or ty != word
                                   for ty in types.values()):
            _reject("only one homogeneous signed or unsigned 32-bit type")
        for p in parameters:
            if type(p) is not dict or p.get("type") != word:
                _reject("parameter type does not match LLVM scalar profile")
        registers: dict[str, int] = {}
        for p, arg in zip(parameters, arguments):
            if type(arg) is not int or not _LOW[word] <= arg <= _HIGH[word]:
                _reject("argument is not an in-range machine integer")
            name = p.get("ssa_name")
            if type(name) is not str or name in registers:
                _reject("invalid duplicate SSA argument definition")
            registers[name] = arg
        blocks = fn.get("blocks")
        if type(blocks) is not list or any(type(b) is not dict for b in blocks):
            _reject("invalid SSA basic blocks")
        by_id = {b.get("id"): b for b in blocks}
        if len(by_id) != len(blocks) or entry not in by_id:
            _reject("invalid or duplicate SSA block identity")
        spent = 0

        def tick() -> None:
            nonlocal spent
            spent += 1
            if spent > max_steps:
                raise HIAOracleBudgetExceeded("E_HIA_ORACLE_BUDGET: finite interpreter limit")

        def expr(node: object, depth: int = 0) -> bool | int:
            tick()
            if (depth > 64 or type(node) is not dict or node.get("node") != "expr"
                    or type(node.get("operands")) is not list):
                _reject("unrecognized/deep executable SSA expression")
            kind, typ, operands, value = (node.get("operation"), node.get("result_type"),
                                          node["operands"], node.get("value"))
            if kind == "int" and not operands and typ == _type(word):
                if type(value) is int and _LOW[word] <= value <= _HIGH[word]:
                    return value
                _reject("integer literal out of range")
            if kind == "bool" and not operands and typ == _type("bool"):
                if type(value) is bool:
                    return value
                _reject("boolean literal has wrong type")
            if kind == "name" and not operands and typ == _type(word):
                key = node.get("ssa_ref")
                if type(key) is str and key in registers:
                    return registers[key]
                _reject("undefined SSA value")
            if kind == "unary" and value == "-" and len(operands) == 1 and word == "i32" and typ == _type(word):
                arg = expr(operands[0], depth + 1)
                if type(arg) is not int:
                    _reject("unary minus requires an integer")
                result = -arg
                if not _LOW[word] <= result <= _HIGH[word]:
                    raise HIAOracleTrap("E_HIA_ORACLE_TRAP: checked unary negation overflow")
                return result
            if kind == "binary" and len(operands) == 2 and value in _OPERATORS:
                lhs, rhs = expr(operands[0], depth + 1), expr(operands[1], depth + 1)
                if type(lhs) is not int or type(rhs) is not int:
                    _reject("arithmetic/comparison requires two machine integers")
                if value in {"+", "-", "*"} and typ == _type(word):
                    answer = (lhs + rhs if value == "+" else
                              lhs - rhs if value == "-" else lhs * rhs)
                    if not _LOW[word] <= answer <= _HIGH[word]:
                        raise HIAOracleTrap("E_HIA_ORACLE_TRAP: checked arithmetic overflow")
                    return answer
                if value in {"==", "!=", "<", "<=", ">", ">="} and typ == _type("bool"):
                    return {"==": lhs == rhs, "!=": lhs != rhs, "<": lhs < rhs,
                            "<=": lhs <= rhs, ">": lhs > rhs, ">=": lhs >= rhs}[value]
            _reject("operation lies outside the executable i32/u32 LLVM profile")

        current, predecessor = entry, None
        while True:
            tick()
            block = by_id[current]
            phi_results: dict[str, int] = {}
            for phi in block.get("phis", []):
                tick()
                if predecessor is None:
                    _reject("entry block unexpectedly requires predecessor PHI")
                edges = phi.get("incoming") if type(phi) is dict else None
                dest = phi.get("result") if type(phi) is dict else None
                if type(edges) is not list or type(dest) is not dict or dest.get("type") != word:
                    _reject("malformed PHI")
                matching = [edge for edge in edges if type(edge) is dict and edge.get("from") == predecessor]
                if len(matching) != 1:
                    _reject("PHI must have one incoming predecessor edge")
                ref = matching[0].get("ssa_ref")
                dst = dest.get("ssa_name")
                if (type(ref) is not str or ref not in registers or type(dst) is not str
                        or dst in phi_results):
                    _reject("undefined or multiply-defined PHI version")
                phi_results[dst] = registers[ref]
            # All PHI operands read the predecessor's old environment.
            registers.update(phi_results)
            block_definitions = set(phi_results)
            for op in block.get("instructions", []):
                tick()
                if type(op) is not dict:
                    _reject("invalid instruction")
                result = expr(op.get("ssa_value"))
                dest = op.get("definition")
                if dest is not None:
                    if (type(dest) is not dict or dest.get("type") != word
                            or type(result) is not int or
                            type(dest.get("ssa_name")) is not str or
                            dest["ssa_name"] in block_definitions):
                        _reject("assignment has incompatible or repeated SSA destination")
                    registers[dest["ssa_name"]] = result
                    block_definitions.add(dest["ssa_name"])
            terminator = block.get("terminator")
            if type(terminator) is not dict:
                _reject("unterminated SSA block")
            kind = terminator.get("kind")
            if kind == "return":
                result = expr(terminator.get("value"))
                if type(result) is not int or not _LOW[word] <= result <= _HIGH[word]:
                    _reject("return value is not the native result type")
                return result
            if kind == "goto":
                next_block = terminator.get("target")
            elif kind == "branch":
                condition = expr(terminator.get("condition"))
                if type(condition) is not bool:
                    _reject("branch condition must have boolean type")
                next_block = terminator.get("then") if condition else terminator.get("else")
            else:
                _reject("unsupported SSA terminator")
            if type(next_block) is not str or next_block not in by_id:
                _reject("branch refers to missing basic block")
            current, predecessor = next_block, current


def prepare_scalar_oracle(core: HIAScalarCore, program, checked, *,
                          project_sha256: str) -> HIAScalarOracle:
    """Require live source replay and the *existing* LLVM emitter profile.

    Successful finite observations may be used for differential test records,
    but never imply a formal backend proof or model all external effects.
    """
    if not isinstance(core, HIAScalarCore):
        _reject("verified HIA scalar core required")
    ssa, cfg, verification = core.qualified_for(
        program, checked, project_sha256=project_sha256)
    native = emit_scalar_ssa_llvm(ssa, cfg)
    if native.verification_sha256 != verification.sha256 or native.source_ssa_sha256 != ssa.sha256:
        _reject("independent source SSA verification differs from native emitter")
    functions = json.loads(ssa.canonical_json).get("functions", [])
    original = json.loads(cfg.canonical_json).get("functions", [])
    if type(functions) is not list or type(original) is not list or len(functions) != len(original):
        _reject("matching SSA/source CFG function inventory required")
    qualified = []
    for fn, source in zip(functions, original):
        if type(fn) is not dict or type(source) is not dict or fn.get("name") != source.get("name"):
            _reject("SSA/source function identity differs")
        ret = source.get("return_type")
        word = ret.get("type") if type(ret) is dict else None
        if word not in _LOW or ret != _type(word):
            _reject("only homogeneous checked 32-bit native return values")
        qualified.append((fn["name"], word))
    return HIAScalarOracle(core.sha256, ssa.sha256, project_sha256,
                           ssa.canonical_json, tuple(qualified))
