"""Bounded structural elaboration of standalone HIA nominal resource programs.

This module is part of ``verify_core``.  It is not a producer receipt or a
source-language escape hatch: every generated instruction and edge is checked
again by the primitive closed-SSA verifier.  Nominal values are products of
primitive capabilities.  Enum inactive owner slots are real empty owners and
are consumed on every case edge.  Local stored loans keep their original
primitive identity; no integer or raw pointer can manufacture a loan.

Composite v4 carries primitive parameter-bound return annotations through the
same elaborator into primitive v8. Aggregate stored-loan results and loans in
partial states remain prohibited; the primitive verifier checks actual origins
and owner/parent/child suspension after all nominal aliases are expanded.

Tasks use an explicit cooperative state machine.  A poll executes only when
requested, cancellation runs a checked state-consuming function exactly once,
and a completed result must be taken.  There are no background threads,
preemptive cancellation, or destructor promises after a trap/budget stop.
"""
from __future__ import annotations

from dataclasses import dataclass

from .hia_program import (EFFECTS, MAX_BLOCKS, MAX_FUNCTIONS, OWNERS, BYTE_RESOURCES, RESOURCES, SCALARS,
                          TYPES, _ident, _keys, _names, _reject)
from .hia_schema import (CANONICAL_CORE_SCHEMA, COMPOSITE_OPERATIONS_BY_SCHEMA,
                         COMPOSITE_PROFILE, COMPOSITE_SCHEMA, COMPOSITE_SCHEMAS,
                         COMPOSITE_SCHEMA_V3, COMPOSITE_SCHEMA_V4, composite_core_schema,
                         LEGACY_COMPOSITE_OPERATIONS)

SCHEMA = COMPOSITE_SCHEMA
PROFILE = COMPOSITE_PROFILE
MAX_DEFINITIONS = 128
MAX_INSTANTIATIONS = 128
MAX_TYPE_DEPTH = 32
MAX_FLAT_FIELDS = 512
MAX_FIELDS = 64
MAX_VARIANTS = 32
MAX_GENERATED_NAMES = 8192
MAX_ELABORATED_VALUE_SLOTS = 32768
MAX_PARTIAL_DECLARATION_STEPS = 32768
_PREFIX = "h2internal_"


def _name(value, where):
    result = _ident(value, where)
    if result.startswith(_PREFIX):
        _reject(f"{where}: identifier uses the elaborator namespace", "E_HIA_NAME")
    return result


@dataclass(frozen=True)
class _Type:
    key: str
    kind: str
    flat: tuple[str, ...]
    fields: tuple = ()
    variants: tuple = ()
    state: object = None
    result: object = None
    poll: str | None = None
    cancel: str | None = None
    linear: bool = False
    record: object = None

    @property
    def has_loans(self):
        return any(t in {"readbuf", "mutbuf"} for t in self.flat)

    @property
    def owns(self):
        if self.kind == "primitive":
            return self.key in OWNERS
        if self.kind in {"task", "partial_record"}:
            return True
        if self.kind == "record":
            return any(t.owns for _, t in self.fields)
        return any(t.owns for _, fields in self.variants for _, t in fields)


class _Types:
    def __init__(self, definitions, *, recursive_chain=False, partial_records=False):
        if type(definitions) is not list or len(definitions) > MAX_DEFINITIONS:
            _reject("invalid nominal type inventory", "E_HIA_LIMIT")
        self.definitions, self.cache, self.active = {}, {}, set()
        self.recursive_chain = recursive_chain
        self.partial_records = partial_records
        self.declared_partials = []
        self.collecting_declarations = True
        self.partial_declaration_steps = 0
        self.known_loan_cache = {}
        self.primitive_types = TYPES if recursive_chain else TYPES - {"chain"}
        for item in definitions:
            if type(item) is not dict or type(item.get("kind")) is not str:
                _reject("nominal type requires a kind", "E_HIA_TYPE")
            kind = item["kind"]
            fields = {"record": {"fields"}, "enum": {"variants"},
                      "task": {"state", "result", "poll", "cancel"}}.get(kind)
            if fields is None:
                _reject("unknown nominal type kind", "E_HIA_TYPE")
            _keys(item, {"name", "params", "kind"} | fields, "nominal type")
            name = _name(item["name"], "nominal type")
            if name in self.primitive_types or name in self.definitions:
                _reject("duplicate/reserved nominal type", "E_HIA_TYPE")
            params = item["params"]
            if type(params) is not list or len(params) > 16:
                _reject("invalid type parameter list", "E_HIA_TYPE")
            for param in params:
                _name(param, "type parameter")
                if param in self.primitive_types or param == name:
                    _reject("reserved type parameter", "E_HIA_TYPE")
            if len(params) != len(set(params)):
                _reject("duplicate type parameter", "E_HIA_TYPE")
            if kind == "task" and params:
                _reject("task protocols have concrete state/result signatures", "E_HIA_TYPE")
            self.definitions[name] = item
        # Check even unused declarations.  Instantiation is separately bounded.
        for item in definitions:
            params = set(item["params"])
            if item["kind"] == "record":
                self._fields(item["fields"], params)
            elif item["kind"] == "enum":
                variants = item["variants"]
                if type(variants) is not list or not 1 <= len(variants) <= MAX_VARIANTS:
                    _reject("enum requires 1..32 variants", "E_HIA_TYPE")
                seen = set()
                for variant in variants:
                    _keys(variant, {"name", "fields"}, "enum variant")
                    name = _name(variant["name"], "variant")
                    if name in seen:
                        _reject("duplicate enum variant", "E_HIA_TYPE")
                    seen.add(name)
                    self._fields(variant["fields"], params)
            else:
                self._reference(item["state"], params)
                self._reference(item["result"], params)
                _name(item["poll"], "task poll function")
                _name(item["cancel"], "task cancellation function")
        # By-value declaration cycles are ill-formed even when never used.
        # Generic parameters themselves are leaves, so Pair<Pair<u8,u8>,u8>
        # remains a finite, admissible nested instantiation.
        graph = {}
        for name, item in self.definitions.items():
            found, pending = set(), [item]
            while pending:
                node = pending.pop()
                if type(node) is dict:
                    for key, child in node.items():
                        if key in {"type", "state", "result"}:
                            references = [child]
                            while references:
                                ref = references.pop()
                                if type(ref) is str and ref in self.definitions and ref not in item["params"]:
                                    found.add(ref)
                                elif type(ref) is dict:
                                    if "partial" in ref:
                                        references.append(ref["partial"])
                                    else:
                                        found.add(ref["name"])
                                        references.extend(ref["args"])
                        elif key in {"fields", "variants"}:
                            pending.append(child)
                elif type(node) is list:
                    pending.extend(node)
            graph[name] = found
        visited, active = set(), set()

        def visit(name):
            if name in active:
                _reject("recursive by-value nominal declarations", "E_HIA_TYPE")
            if name in visited:
                return
            active.add(name)
            for target in graph[name]:
                visit(target)
            active.remove(name)
            visited.add(name)
        for name in graph:
            visit(name)
        self.collecting_declarations = False
        # A declaration does not become well formed merely because lowering
        # erases it unused. Concrete partial references must satisfy the same
        # constraints as instruction/signature references. Symbolic generic
        # applications retain unknown loan-free obligations for instantiation,
        # but may not hide an already known stored loan.
        for ref, params in self.declared_partials:
            if not self._has_parameters(ref, params):
                self.resolve(ref)
            elif self._known_loans(ref["partial"], {name: None for name in params}):
                _reject("partial record fields may not contain stored loans", "E_HIA_LOAN")

    def _fields(self, fields, params):
        if type(fields) is not list or len(fields) > MAX_FIELDS:
            _reject("nominal fields exceed the finite profile", "E_HIA_LIMIT")
        seen = set()
        for field in fields:
            _keys(field, {"name", "type"}, "nominal field")
            name = _name(field["name"], "field")
            if name in seen:
                _reject("duplicate nominal field", "E_HIA_TYPE")
            seen.add(name)
            self._reference(field["type"], params)

    def _reference(self, ref, params, depth=0):
        if depth > MAX_TYPE_DEPTH:
            _reject("type reference nesting exceeds budget", "E_HIA_LIMIT")
        if type(ref) is str:
            if (ref == "chain" and not self.recursive_chain
                    and ref not in self.definitions and ref not in params):
                _reject("recursive chain types require composite v2", "E_HIA_TYPE")
            if ref in self.primitive_types or ref in params:
                return
            _name(ref, "type reference")
            if ref not in self.definitions or self.definitions[ref]["params"]:
                _reject("unknown or unapplied nominal type", "E_HIA_TYPE")
            return
        if type(ref) is dict and "partial" in ref:
            if not self.partial_records:
                # Preserve the old schemas' exact malformed-reference category.
                _keys(ref, {"name", "args"}, "generic type reference")
            _keys(ref, {"partial", "initialized"}, "partial record type")
            initialized = ref["initialized"]
            if type(initialized) is not list or len(initialized) > MAX_FIELDS:
                _reject("invalid partial-record field inventory", "E_HIA_LIMIT")
            for name in initialized:
                _name(name, "initialized record field")
            if len(initialized) != len(set(initialized)):
                _reject("duplicate initialized record field", "E_HIA_INIT")
            self._reference(ref["partial"], params, depth + 1)
            base = ref["partial"]
            name = base if type(base) is str else base.get("name")
            # A naked parameter has no record-kind constraint in this version.
            # Generic applications such as Box<T> have a known declaration;
            # their remaining loan-free condition is rechecked on resolution.
            if ((type(base) is str and name in params) or name not in self.definitions
                    or self.definitions[name]["kind"] != "record"):
                _reject("partial type requires a declared nominal record", "E_HIA_TYPE")
            fields = [field["name"] for field in self.definitions[name]["fields"]]
            if [field for field in fields if field in set(initialized)] != initialized:
                _reject("initialized fields must exist in declaration order", "E_HIA_INIT")
            if self.collecting_declarations:
                self.declared_partials.append((ref, frozenset(params)))
            return
        _keys(ref, {"name", "args"}, "generic type reference")
        name = _name(ref["name"], "generic type name")
        args = ref["args"]
        if (name not in self.definitions or type(args) is not list or
                len(args) != len(self.definitions[name]["params"])):
            _reject("generic type arity mismatch", "E_HIA_TYPE")
        for arg in args:
            self._reference(arg, params, depth + 1)

    def _has_parameters(self, ref, params):
        self._partial_declaration_step()
        if type(ref) is str:
            return ref in params
        if "partial" in ref:
            return self._has_parameters(ref["partial"], params)
        return any(self._has_parameters(arg, params) for arg in ref["args"])

    def _partial_declaration_step(self):
        # Symbolic generic declarations can repeat a still-unknown leaf many
        # times without instantiating a concrete flat layout. Bound that work
        # independently, rather than relying on the eventual layout limit.
        self.partial_declaration_steps += 1
        if self.partial_declaration_steps > MAX_PARTIAL_DECLARATION_STEPS:
            _reject("partial declaration analysis budget exceeded", "E_HIA_LIMIT")

    def _known_loans(self, ref, bindings, depth=0):
        """Follow symbolic type arguments without choosing a fake instance.

        Each bound argument carries its original lexical environment. None is
        an unknown type parameter, not a claim that the parameter is loan-free.
        Concrete resolution independently checks every eventual instantiation.
        """
        self._partial_declaration_step()
        if depth > MAX_TYPE_DEPTH:
            _reject("nominal layout nesting exceeds budget", "E_HIA_LIMIT")
        key = (self._symbolic_reference(ref, bindings), depth)
        if key not in self.known_loan_cache:
            self.known_loan_cache[key] = self._known_loans_uncached(ref, bindings, depth)
        return self.known_loan_cache[key]

    def _symbolic_reference(self, ref, bindings, depth=0):
        """Memo key for the known-loan predicate, not a concrete type instance."""
        self._partial_declaration_step()
        if depth > 2 * MAX_TYPE_DEPTH:
            _reject("symbolic type argument nesting exceeds budget", "E_HIA_LIMIT")
        if type(ref) is str:
            if ref in bindings:
                bound = bindings[ref]
                return (("unknown",) if bound is None else
                        self._symbolic_reference(bound[0], bound[1], depth + 1))
            return ("type", ref)
        if "partial" in ref:
            return ("partial", self._symbolic_reference(ref["partial"], bindings, depth + 1),
                    tuple(ref["initialized"]))
        return ("application", ref["name"], tuple(self._symbolic_reference(arg, bindings, depth + 1)
                                                  for arg in ref["args"]))

    def _known_loans_uncached(self, ref, bindings, depth):
        if type(ref) is str:
            if ref in bindings:
                bound = bindings[ref]
                return False if bound is None else self._known_loans(bound[0], bound[1], depth)
            if ref in self.primitive_types:
                return ref in {"readbuf", "mutbuf"}
            name, args = ref, []
        elif "partial" in ref:
            return self._known_loans(ref["partial"], bindings, depth + 1)
        else:
            name, args = ref["name"], ref["args"]
        item = self.definitions[name]
        nested = {param: (arg, bindings) for param, arg in zip(item["params"], args)}
        if item["kind"] == "record":
            children = [field["type"] for field in item["fields"]]
        elif item["kind"] == "enum":
            children = [field["type"] for variant in item["variants"] for field in variant["fields"]]
        else:
            children = [item["state"], item["result"]]
        return any(self._known_loans(child, nested, depth + 1) for child in children)

    def resolve(self, ref, bindings=None, depth=0):
        bindings = bindings or {}
        if depth > MAX_TYPE_DEPTH:
            _reject("nominal layout nesting exceeds budget", "E_HIA_LIMIT")
        if type(ref) is str and ref in bindings:
            return bindings[ref]
        if type(ref) is str and ref in self.primitive_types:
            return _Type(ref, "primitive", (ref,), linear=ref in RESOURCES)
        self._reference(ref, set(bindings))
        if type(ref) is dict and "partial" in ref:
            base = self.resolve(ref["partial"], bindings, depth + 1)
            return self.partial_record(base, ref["initialized"])
        if type(ref) is str:
            name, args = ref, []
        else:
            name = ref["name"]
            args = [self.resolve(arg, bindings, depth + 1) for arg in ref["args"]]
        key = name + "<" + ",".join(t.key for t in args) + ">"
        if key in self.cache:
            return self.cache[key]
        if key in self.active:
            _reject("recursive by-value nominal layout", "E_HIA_TYPE")
        if len(self.cache) + len(self.active) >= MAX_INSTANTIATIONS:
            _reject("generic instantiation budget exceeded", "E_HIA_LIMIT")
        self.active.add(key)
        item = self.definitions[name]
        env = dict(zip(item["params"], args))
        field_types = lambda fields: tuple((f["name"], self.resolve(f["type"], env, depth + 1))
                                          for f in fields)
        kind = item["kind"]
        if kind == "record":
            fields = field_types(item["fields"])
            flat = tuple(p for _, t in fields for p in t.flat)
            typ = _Type(key, kind, flat, fields=fields, linear=any(t.linear for _, t in fields))
        elif kind == "enum":
            variants = tuple((v["name"], field_types(v["fields"])) for v in item["variants"])
            flat = ("u32",) + tuple(p for _, fields in variants for _, t in fields for p in t.flat)
            if any(t.has_loans for _, fields in variants for _, t in fields):
                _reject("enum payloads cannot contain loans in composite v1", "E_HIA_LOAN")
            typ = _Type(key, kind, flat, variants=variants,
                        linear=any(t.linear for _, fields in variants for _, t in fields))
        else:
            state = self.resolve(item["state"], env, depth + 1)
            result = self.resolve(item["result"], env, depth + 1)
            if state.has_loans or result.has_loans:
                _reject("task state/results may not retain loans", "E_HIA_LOAN")
            # Every task carries a real zero-length owner token.  Even when
            # state/result are entirely scalar, the independent primitive
            # verifier therefore enforces task linearity after erasure.
            flat = ("u8", "buffer") + state.flat + result.flat
            typ = _Type(key, kind, flat, state=state, result=result,
                        poll=item["poll"], cancel=item["cancel"], linear=True)
        if len(flat) > MAX_FLAT_FIELDS:
            _reject("flattened nominal layout exceeds budget", "E_HIA_LIMIT")
        self.active.remove(key)
        self.cache[key] = typ
        return typ

    def partial_record(self, base, initialized):
        """A structural typestate whose missing fields have no primitive slot."""
        if not self.partial_records or base.kind != "record":
            _reject("partial type requires a nominal record in composite v3", "E_HIA_TYPE")
        if base.has_loans:
            _reject("partial record fields may not contain stored loans", "E_HIA_LOAN")
        selected = set(initialized)
        fields = tuple((name, typ) for name, typ in base.fields if name in selected)
        if tuple(name for name, _ in fields) != tuple(initialized):
            _reject("initialized fields must exist in declaration order", "E_HIA_INIT")
        key = "partial<" + base.key + ";" + ",".join(initialized) + ">"
        if key in self.cache:
            return self.cache[key]
        if len(self.cache) + len(self.active) >= MAX_INSTANTIATIONS:
            _reject("generic/partial instantiation budget exceeded", "E_HIA_LIMIT")
        flat = ("buffer",) + tuple(p for _, typ in fields for p in typ.flat)
        if len(flat) > MAX_FLAT_FIELDS:
            _reject("flattened partial-record layout exceeds budget", "E_HIA_LIMIT")
        typ = _Type(key, "partial_record", flat, fields=fields, linear=True, record=base)
        self.cache[key] = typ
        return typ


@dataclass
class _Value:
    typ: _Type
    names: tuple[str, ...]
    external: bool = False
    consumed: bool = False


def _param(name, typ):
    return {"name": name, "type": typ}


def _ins(op, args=(), outputs=(), **attrs):
    return {"op": op, "args": list(args), "out": [_param(*p) for p in outputs], "attrs": attrs}


def _jump(target, args):
    return {"op": "jump", "target": target, "args": list(args)}


def _branch(cond, yes, no):
    return {"op": "branch", "cond": cond,
            "then": {"target": yes[0], "args": list(yes[1])},
            "else": {"target": no[0], "args": list(no[1])}}


def _ret(values):
    return {"op": "ret", "values": list(values)}


class _Elaborator:
    def __init__(self, document, *, legacy=False):
        _keys(document, {"schema", "module", "types", "functions"}, "nominal program")
        if type(document["schema"]) is not str or document["schema"] not in COMPOSITE_SCHEMAS:
            _reject("unsupported nominal program schema", "E_HIA_SCHEMA")
        if legacy and document["schema"] != SCHEMA:
            _reject("legacy nominal adapter only targets composite v1", "E_HIA_SCHEMA")
        _name(document["module"], "module")
        self.document, self.serial, self.value_slots = document, 0, 0
        self.parameter_loan_returns = document["schema"] == COMPOSITE_SCHEMA_V4
        self.nominal_operations = (LEGACY_COMPOSITE_OPERATIONS if legacy else
                                   COMPOSITE_OPERATIONS_BY_SCHEMA[document["schema"]])
        self.types = _Types(document["types"],
                            recursive_chain=document["schema"] != SCHEMA,
                            partial_records=document["schema"] in {COMPOSITE_SCHEMA_V3, COMPOSITE_SCHEMA_V4})
        functions = document["functions"]
        if type(functions) is not list or not 1 <= len(functions) <= MAX_FUNCTIONS:
            _reject("invalid nominal function inventory", "E_HIA_FORMAT")
        self.functions, self.signatures, self.return_loans = {}, {}, {}
        self.helpers, self.helper_names = [], {}
        for fn in functions:
            fields = {"name", "params", "returns", "effects", "entry", "blocks"}
            if self.parameter_loan_returns and type(fn) is dict and "return_loans" in fn:
                fields.add("return_loans")
            _keys(fn, fields, "function")
            name = _name(fn["name"], "function")
            if name in self.functions:
                _reject("duplicate nominal function", "E_HIA_NAME")
            params = self.parameters(fn["params"])
            if type(fn["returns"]) is not list:
                _reject("function returns must be a list", "E_HIA_TYPE")
            returns = tuple(self.types.resolve(t) for t in fn["returns"])
            if any(t.has_loans and (not self.parameter_loan_returns or t.kind != "primitive")
                   for t in returns):
                _reject("stored loans may not escape a function", "E_HIA_LOAN")
            if self.parameter_loan_returns:
                origins = fn.get("return_loans", [None] * len(returns))
                if type(origins) is not list or len(origins) != len(returns):
                    _reject("nominal return_loans must match the return arity", "E_HIA_LOAN")
                parameters = dict(params)
                for typ, origin in zip(returns, origins):
                    if typ.kind != "primitive" or typ.key not in {"readbuf", "mutbuf"}:
                        if origin is not None:
                            _reject("nonloan nominal result requires a null return_loans entry", "E_HIA_LOAN")
                    elif (type(origin) is not str or origin not in parameters
                          or parameters[origin].kind != "primitive"
                          or parameters[origin].key not in {"readbuf", "mutbuf"}
                          or typ.key == "mutbuf" and parameters[origin].key != "mutbuf"):
                        _reject("nominal borrowed result must name a primitive input loan with sufficient permission",
                                "E_HIA_LOAN")
                self.return_loans[name] = tuple(origins)
            effects = fn["effects"]
            if (type(effects) is not list or any(type(e) is not str or e not in EFFECTS for e in effects)
                    or len(set(effects)) != len(effects)):
                _reject("unknown/duplicate nominal function effect", "E_HIA_EFFECT")
            self.functions[name] = fn
            self.signatures[name] = (params, returns)
        # Concrete tasks, including unused declarations, must name a full
        # checked polling/cancellation protocol; no foreign function contracts.
        for definition in document["types"]:
            if definition["kind"] == "task":
                self.check_task(self.types.resolve(definition["name"]))

    def fresh(self):
        # Enforce this *while* expanding, before constructing the next
        # instruction/block/parameter.  The outer JSON limit alone does not
        # bound repeated enum padding or generic aggregate expansion.
        if self.serial >= MAX_GENERATED_NAMES:
            _reject("nominal elaboration expansion budget exceeded", "E_HIA_LIMIT")
        self.serial += 1
        return _PREFIX + str(self.serial)

    def reserve_values(self, parameters):
        # Structural product aliases can carry hundreds of scalar slots while
        # emitting no new primitive instruction/name.  Bound those too, before
        # allocating repeated flattened value tuples.
        self.value_slots += sum(len(typ.flat) for _, typ in parameters)
        if self.value_slots > MAX_ELABORATED_VALUE_SLOTS:
            _reject("nominal elaborated value-slot budget exceeded", "E_HIA_LIMIT")

    def parameters(self, value):
        if type(value) is not list:
            _reject("parameters must be a list", "E_HIA_FORMAT")
        result, seen = [], set()
        for param in value:
            _keys(param, {"name", "type"}, "nominal parameter")
            name = _name(param["name"], "parameter")
            if name in seen:
                _reject("duplicate nominal parameter", "E_HIA_SSA")
            seen.add(name)
            result.append((name, self.types.resolve(param["type"])))
        return tuple(result)

    def flat_parameters(self, params):
        flat, values = [], {}
        for name, typ in params:
            names = (name,) if typ.kind == "primitive" else tuple(self.fresh() for _ in typ.flat)
            flat.extend(_param(n, t) for n, t in zip(names, typ.flat))
            values[name] = _Value(typ, names, external=typ.has_loans and not typ.owns)
        return flat, values

    def constant(self, ops, typ, value):
        name = self.fresh()
        ops.append(_ins("const", outputs=[(name, typ)], value=value))
        return name

    def zeros(self, flat_types, ops):
        result = []
        for typ in flat_types:
            if typ == "buffer":
                zero = self.constant(ops, "usize", 0)
                owner, ok = self.fresh(), self.fresh()
                ops.append(_ins("buffer.try_new", [zero], [(owner, "buffer"), (ok, "bool")]))
                result.append(owner)
            elif typ == "chain":
                owner = self.fresh()
                ops.append(_ins("chain.empty", outputs=[(owner, "chain")]))
                result.append(owner)
            elif typ in {"readbuf", "mutbuf"}:
                _reject("cannot invent an inactive loan", "E_HIA_LOAN")
            else:
                result.append(self.constant(ops, typ, False if typ == "bool" else None if typ == "unit" else 0))
        return tuple(result)

    @staticmethod
    def drop_padding(names, types, ops):
        for name, typ in zip(names, types):
            if typ in OWNERS:
                ops.append(_ins("owner.drop", [name]))
            elif typ in {"readbuf", "mutbuf"}:
                _reject("inactive padding contains a loan", "E_HIA_LOAN")

    def check_task(self, typ):
        if typ.poll not in self.functions or typ.cancel not in self.functions:
            _reject("task protocol names a missing function", "E_HIA_CALL")
        params, returns = self.signatures[typ.poll]
        if len(params) != 1 or params[0][1] != typ.state or len(returns) != 1:
            _reject("task poll must consume one state and return one step enum", "E_HIA_TYPE")
        step = returns[0]
        variants = dict(step.variants)
        if (step.kind != "enum" or set(variants) != {"pending", "ready"}
                or len(variants["pending"]) != 1 or variants["pending"][0][1] != typ.state
                or len(variants["ready"]) != 1 or variants["ready"][0][1] != typ.result):
            _reject("task poll result must be pending(state) | ready(result)", "E_HIA_TYPE")
        params, returns = self.signatures[typ.cancel]
        if len(params) != 1 or params[0][1] != typ.state or returns:
            _reject("task cancellation must consume one state and return no values", "E_HIA_TYPE")
        return step

    def helper(self, typ, operation):
        key = (typ.key, operation)
        if key in self.helper_names:
            return self.helper_names[key]
        step = self.check_task(typ)
        name = self.fresh()
        self.helper_names[key] = name
        effects = {"trap"}
        if any(t in OWNERS for t in typ.flat):
            effects.add("alloc")
        if operation == "poll":
            effects.update(self.functions[typ.poll]["effects"])
        if operation == "cancel":
            effects.update(self.functions[typ.cancel]["effects"])
        returns = typ.result.flat if operation == "join" else () if operation == "close" else typ.flat
        blocks = []

        def block():
            ident = self.fresh()
            names = tuple(self.fresh() for _ in typ.flat)
            value = {"id": ident, "params": [_param(n, t) for n, t in zip(names, typ.flat)],
                     "ops": [], "term": None}
            blocks.append(value)
            return value, names

        entry, values = block()
        failed_names = tuple(self.fresh() for _ in typ.flat)
        failure = {"id": self.fresh(), "params": [_param(n, t) for n, t in zip(failed_names, typ.flat)],
                   "ops": [], "term": {"op": "trap", "code": "user"}}
        if operation != "cancel":
            run, active = block()
            needed = {"start": 0, "poll": 1, "join": 2, "close": 3}[operation]
            expected = self.constant(entry["ops"], "u8", needed)
            matches = self.fresh()
            entry["ops"].append(_ins("compare.eq", [values[0], expected], [(matches, "bool")]))
            entry["term"] = _branch(matches, (run["id"], values), (failure["id"], values))
            token = active[1]
            state = active[2:2 + len(typ.state.flat)]
            result = active[2 + len(typ.state.flat):]
            if operation == "start":
                tag = self.constant(run["ops"], "u8", 1)
                run["term"] = _ret((tag,) + active[1:])
            elif operation == "join":
                self.drop_padding((token,) + state, ("buffer",) + typ.state.flat, run["ops"])
                run["term"] = _ret(result)
            elif operation == "close":
                self.drop_padding((token,) + state + result, ("buffer",) + typ.state.flat + typ.result.flat, run["ops"])
                run["term"] = _ret([])
            else:
                self.drop_padding(result, typ.result.flat, run["ops"])
                emitted = tuple(self.fresh() for _ in step.flat)
                run["ops"].append(_ins("call", state, zip(emitted, step.flat), function=typ.poll))
                # Even the standalone erased program retains an exhaustive
                # discriminant guard; a changed core cannot reinterpret an
                # invalid poll result as a pending state.
                limit = self.constant(run["ops"], "u32", 1)
                valid = self.fresh()
                run["ops"].append(_ins("compare.le", [emitted[0], limit], [(valid, "bool")]))
                carried_types = ("buffer",) + step.flat
                carried = (token,) + emitted
                checked_names = tuple(self.fresh() for _ in carried_types)
                checked_block = {"id": self.fresh(), "params": [_param(n, t) for n, t in zip(checked_names, carried_types)],
                                 "ops": [], "term": None}
                invalid_names = tuple(self.fresh() for _ in carried_types)
                invalid_block = {"id": self.fresh(), "params": [_param(n, t) for n, t in zip(invalid_names, carried_types)],
                                 "ops": [], "term": {"op": "trap", "code": "user"}}
                run["term"] = _branch(valid, (checked_block["id"], carried), (invalid_block["id"], carried))
                blocks.extend([checked_block, invalid_block])
                run, token, emitted = checked_block, checked_names[0], checked_names[1:]
                cursor, slots = 1, {}
                for variant, fields in step.variants:
                    width = sum(len(t.flat) for _, t in fields)
                    slots[variant] = emitted[cursor:cursor + width]
                    cursor += width
                ready_index = [v for v, _ in step.variants].index("ready")
                index = self.constant(run["ops"], "u32", ready_index)
                ready = self.fresh()
                run["ops"].append(_ins("compare.eq", [emitted[0], index], [(ready, "bool")]))
                succeeded = self.constant(run["ops"], "u8", 2)
                running = self.constant(run["ops"], "u8", 1)
                tag = self.fresh()
                run["ops"].append(_ins("select", [ready, succeeded, running], [(tag, "u8")]))
                run["term"] = _ret((tag, token) + slots["pending"] + slots["ready"])
        else:
            cleanup, active = block()
            stopped, stopped_values = block()
            unchanged, terminal = block()
            two = self.constant(entry["ops"], "u8", 2)
            live = self.fresh()
            entry["ops"].append(_ins("compare.lt", [values[0], two], [(live, "bool")]))
            entry["term"] = _branch(live, (cleanup["id"], values), (stopped["id"], values))
            three = self.constant(stopped["ops"], "u8", 3)
            valid = self.fresh()
            stopped["ops"].append(_ins("compare.le", [stopped_values[0], three], [(valid, "bool")]))
            stopped["term"] = _branch(valid, (unchanged["id"], stopped_values), (failure["id"], stopped_values))
            unchanged["term"] = _ret(terminal)
            token = active[1]
            state = active[2:2 + len(typ.state.flat)]
            result = active[2 + len(typ.state.flat):]
            cleanup["ops"].append(_ins("call", state, [], function=typ.cancel))
            self.drop_padding(result, typ.result.flat, cleanup["ops"])
            tag = self.constant(cleanup["ops"], "u8", 3)
            padding = self.zeros(typ.state.flat + typ.result.flat, cleanup["ops"])
            cleanup["term"] = _ret((tag, token) + padding)
        blocks.append(failure)
        self.helpers.append({"name": name, "params": entry["params"], "returns": list(returns),
                             "effects": sorted(effects), "entry": entry["id"], "blocks": blocks})
        return name

    def function(self, fn):
        blocks = fn["blocks"]
        if type(blocks) is not list or not 1 <= len(blocks) <= MAX_BLOCKS:
            _reject("invalid nominal block inventory", "E_HIA_CFG")
        entries, signatures, flattened, environments, definitions = {}, {}, {}, {}, set()
        for block in blocks:
            _keys(block, {"id", "params", "ops", "term"}, "nominal block")
            ident = _name(block["id"], "block")
            if ident in entries:
                _reject("duplicate nominal block", "E_HIA_CFG")
            entries[ident] = block
            params = self.parameters(block["params"])
            self.reserve_values(params)
            signatures[ident] = params
            flattened[ident], environments[ident] = self.flat_parameters(params)
            if type(block["ops"]) is not list:
                _reject("block operations must be a list", "E_HIA_FORMAT")
            current = [name for name, _ in params]
            for ins in block["ops"]:
                _keys(ins, {"op", "args", "out", "attrs"}, "nominal instruction")
                if type(ins["op"]) is not str or type(ins["attrs"]) is not dict:
                    _reject("invalid nominal instruction", "E_HIA_FORMAT")
                if (ins["op"].startswith(("record.", "enum.", "task."))
                        and ins["op"] not in self.nominal_operations):
                    _reject("nominal operation is outside the selected input profile",
                            "E_HIA_OPCODE")
                _names(ins["args"], "instruction arguments")
                declared_outputs = self.parameters(ins["out"])
                self.reserve_values(declared_outputs)
                current.extend(name for name, _ in declared_outputs)
            for name in current:
                if name in definitions:
                    _reject("nominal SSA value defined twice", "E_HIA_SSA")
                definitions.add(name)
        _name(fn["entry"], "entry")
        if fn["entry"] not in entries or signatures[fn["entry"]] != self.signatures[fn["name"]][0]:
            _reject("nominal entry parameters differ from signature", "E_HIA_CFG")
        result = []
        for block in blocks:
            env = environments[block["id"]]
            ops = []

            def value(name):
                _name(name, "value reference")
                if name not in env:
                    _reject("undefined/nonlocal nominal value", "E_HIA_SSA")
                item = env[name]
                if item.consumed:
                    _reject("use of consumed nominal value", "E_HIA_RESOURCE")
                return item

            def consume(name):
                item = value(name)
                if item.typ.linear:
                    item.consumed = True

            def outputs(ins, expected):
                declared = self.parameters(ins["out"])
                if tuple(t for _, t in declared) != tuple(expected):
                    _reject("nominal output type/arity mismatch", "E_HIA_TYPE")
                return [name for name, _ in declared]

            def record_field(item, field):
                _name(field, "projected record field")
                if item.typ.kind not in {"record", "partial_record"}:
                    _reject("field access requires a record", "E_HIA_TYPE")
                offset = 1 if item.typ.kind == "partial_record" else 0
                for name, typ in item.typ.fields:
                    if name == field:
                        return offset, typ
                    offset += len(typ.flat)
                if (item.typ.kind == "partial_record"
                        and field in dict(item.typ.record.fields)):
                    _reject("use of an uninitialized record field", "E_HIA_INIT")
                _reject("unknown nominal field", "E_HIA_TYPE")

            def move_field(names, typ):
                # Actual owner moves make a borrowed field fail the independent
                # primitive checker; a structural alias must not evade it.
                moved = []
                for name, part in zip(names, typ.flat):
                    if part in OWNERS:
                        fresh = self.fresh()
                        ops.append(_ins("owner.move", [name], [(fresh, part)]))
                        moved.append(fresh)
                    else:
                        moved.append(name)
                return tuple(moved)

            def live_required():
                return {name for name, item in env.items()
                        if item.typ.linear and not item.consumed and not item.external}

            def check_transfer(arguments, implicit=(), consumed=()):
                seen = set()
                for name in arguments:
                    item = value(name)
                    if item.typ.linear:
                        if name in seen:
                            _reject("nominal linear value duplicated on edge", "E_HIA_RESOURCE")
                        seen.add(name)
                if not (live_required() - set(consumed)).issubset(seen):
                    _reject("edge drops a live nominal value", "E_HIA_RESOURCE")
                return tuple(implicit) + tuple(value(n).typ for n in arguments)

            def edge(raw, implicit_types=(), implicit_names=(), consumed=()):
                _keys(raw, {"target", "args"}, "nominal edge")
                target = _name(raw["target"], "edge target")
                _names(raw["args"], "edge arguments")
                if target not in entries:
                    _reject("nominal edge names a missing block", "E_HIA_CFG")
                actual = check_transfer(raw["args"], implicit_types, consumed)
                if actual != tuple(t for _, t in signatures[target]):
                    _reject("nominal edge types differ", "E_HIA_TYPE")
                return {"target": target, "args": list(implicit_names) + [x for n in raw["args"] for x in value(n).names]}

            for ins in block["ops"]:
                op, args, attrs = ins["op"], ins["args"], ins["attrs"]
                actual = [value(name) for name in args]
                declared = self.parameters(ins["out"])
                if op == "record.begin":
                    _keys(attrs, set(), op)
                    if (actual or len(declared) != 1
                            or declared[0][1].kind != "partial_record"):
                        _reject("record.begin requires one empty partial-record output", "E_HIA_TYPE")
                    out, typ = declared[0]
                    if typ.fields:
                        _reject("record.begin cannot initialize a field", "E_HIA_INIT")
                    env[out] = _Value(typ, self.zeros(("buffer",), ops))
                elif op == "record.take":
                    _keys(attrs, {"field"}, op)
                    if len(actual) != 1 or actual[0].typ.kind not in {"record", "partial_record"}:
                        _reject("record.take requires one record", "E_HIA_TYPE")
                    item = actual[0]
                    offset, typ = record_field(item, attrs["field"])
                    base = item.typ.record if item.typ.kind == "partial_record" else item.typ
                    remainder = self.types.partial_record(base,
                        [field for field, _ in item.typ.fields if field != attrs["field"]])
                    out, rest = outputs(ins, [typ, remainder])
                    consume(args[0])
                    token = item.names[:1] if item.typ.kind == "partial_record" else self.zeros(("buffer",), ops)
                    selected = item.names[offset:offset + len(typ.flat)]
                    env[out] = _Value(typ, move_field(selected, typ))
                    before = item.names[1:offset] if item.typ.kind == "partial_record" else item.names[:offset]
                    env[rest] = _Value(remainder, token + before + item.names[offset + len(typ.flat):])
                elif op == "record.insert":
                    _keys(attrs, {"field"}, op)
                    if len(actual) != 2 or actual[0].typ.kind != "partial_record":
                        _reject("record.insert requires partial record and field value", "E_HIA_TYPE")
                    item, supplied = actual
                    _name(attrs["field"], "initialized record field")
                    base = item.typ.record
                    all_fields = dict(base.fields)
                    if attrs["field"] not in all_fields:
                        _reject("unknown nominal field", "E_HIA_TYPE")
                    if attrs["field"] in dict(item.typ.fields):
                        _reject("record field is already initialized", "E_HIA_INIT")
                    if supplied.typ != all_fields[attrs["field"]]:
                        _reject("inserted record field type differs", "E_HIA_TYPE")
                    initialized = set(dict(item.typ.fields)) | {attrs["field"]}
                    typ = self.types.partial_record(base,
                        [field for field, _ in base.fields if field in initialized])
                    out = outputs(ins, [typ])[0]
                    consume(args[0])
                    consume(args[1])
                    fields, offset = {}, 1
                    for field, field_type in item.typ.fields:
                        fields[field] = item.names[offset:offset + len(field_type.flat)]
                        offset += len(field_type.flat)
                    fields[attrs["field"]] = supplied.names
                    env[out] = _Value(typ, item.names[:1] + tuple(
                        name for field, _ in typ.fields for name in fields[field]))
                elif op == "record.finish":
                    _keys(attrs, set(), op)
                    if len(actual) != 1 or actual[0].typ.kind != "partial_record":
                        _reject("record.finish requires one partial record", "E_HIA_TYPE")
                    item = actual[0]
                    if item.typ.fields != item.typ.record.fields:
                        _reject("record.finish requires every field initialized", "E_HIA_INIT")
                    out = outputs(ins, [item.typ.record])[0]
                    consume(args[0])
                    ops.append(_ins("owner.drop", item.names[:1]))
                    env[out] = _Value(item.typ.record, item.names[1:])
                elif op == "record.abandon":
                    _keys(attrs, set(), op)
                    if len(actual) != 1 or actual[0].typ.kind != "partial_record":
                        _reject("record.abandon requires one partial record", "E_HIA_TYPE")
                    item = actual[0]
                    if item.typ.fields:
                        _reject("record.abandon requires every field moved out", "E_HIA_INIT")
                    outputs(ins, [])
                    consume(args[0])
                    ops.append(_ins("owner.drop", item.names[:1]))
                elif op == "record.make":
                    _keys(attrs, set(), op)
                    if len(declared) != 1 or declared[0][1].kind != "record":
                        _reject("record.make needs one nominal record output", "E_HIA_TYPE")
                    out, typ = declared[0]
                    if tuple(v.typ for v in actual) != tuple(t for _, t in typ.fields):
                        _reject("record fields differ from nominal declaration", "E_HIA_TYPE")
                    for name in args:
                        consume(name)
                    env[out] = _Value(typ, tuple(x for v in actual for x in v.names),
                                      external=all(v.external or not v.typ.linear for v in actual) and not typ.owns)
                elif op == "record.unpack":
                    _keys(attrs, set(), op)
                    if len(actual) != 1 or actual[0].typ.kind != "record":
                        _reject("record.unpack requires a record", "E_HIA_TYPE")
                    item = actual[0]
                    names = outputs(ins, [t for _, t in item.typ.fields])
                    consume(args[0])
                    offset = 0
                    for name, (_, typ) in zip(names, item.typ.fields):
                        env[name] = _Value(typ, item.names[offset:offset + len(typ.flat)], item.external)
                        offset += len(typ.flat)
                elif op == "record.get":
                    _keys(attrs, {"field"}, op)
                    if len(actual) != 1 or actual[0].typ.kind not in {"record", "partial_record"}:
                        _reject("record.get requires a record", "E_HIA_TYPE")
                    offset, typ = record_field(actual[0], attrs["field"])
                    if typ.linear:
                        _reject("linear fields require consuming record.unpack/take", "E_HIA_RESOURCE")
                    name = outputs(ins, [typ])[0]
                    env[name] = _Value(typ, actual[0].names[offset:offset + len(typ.flat)])
                elif op == "record.borrow":
                    # Borrow the *original* primitive field capability. The
                    # aggregate remains live; there is no copied owner or
                    # forged descriptor, and the primitive checker enforces
                    # exclusivity, parent suspension and eventual loan end.
                    _keys(attrs, {"field", "mode"}, op)
                    if len(actual) != 1 or actual[0].typ.kind not in {"record", "partial_record"}:
                        _reject("record.borrow requires a record", "E_HIA_TYPE")
                    if type(attrs["mode"]) is not str or attrs["mode"] not in {"read", "mut"}:
                        _reject("record.borrow mode must be read or mut", "E_HIA_LOAN")
                    offset, typ = record_field(actual[0], attrs["field"])
                    if typ.kind != "primitive" or typ.key not in BYTE_RESOURCES:
                        _reject("record.borrow requires a primitive owner/view field",
                                "E_HIA_TYPE")
                    loan_type = self.types.resolve("mutbuf" if attrs["mode"] == "mut" else "readbuf")
                    name = outputs(ins, [loan_type])[0]
                    env[name] = _Value(loan_type, (name,))
                    ops.append(_ins("borrow." + attrs["mode"],
                                    [actual[0].names[offset]], [(name, loan_type.key)]))
                elif op == "enum.make":
                    _keys(attrs, {"variant"}, op)
                    if len(declared) != 1 or declared[0][1].kind != "enum":
                        _reject("enum.make needs an enum output", "E_HIA_TYPE")
                    out, typ = declared[0]
                    _name(attrs["variant"], "constructed variant")
                    variants = dict(typ.variants)
                    if attrs["variant"] not in variants or tuple(v.typ for v in actual) != tuple(t for _, t in variants[attrs["variant"]]):
                        _reject("enum payload differs from selected variant", "E_HIA_TYPE")
                    for name in args:
                        consume(name)
                    tag = self.constant(ops, "u32", [v for v, _ in typ.variants].index(attrs["variant"]))
                    flat = [tag]
                    for variant, fields in typ.variants:
                        if variant == attrs["variant"]:
                            flat.extend(x for v in actual for x in v.names)
                        else:
                            flat.extend(self.zeros(tuple(p for _, t in fields for p in t.flat), ops))
                    env[out] = _Value(typ, tuple(flat))
                elif op == "enum.tag":
                    _keys(attrs, set(), op)
                    if len(actual) != 1 or actual[0].typ.kind != "enum":
                        _reject("enum.tag requires an enum", "E_HIA_TYPE")
                    name = outputs(ins, [self.types.resolve("u32")])[0]
                    env[name] = _Value(self.types.resolve("u32"), actual[0].names[:1])
                elif op.startswith("task."):
                    _keys(attrs, set(), op)
                    if op == "task.create":
                        if len(declared) != 1 or declared[0][1].kind != "task" or len(actual) != 1:
                            _reject("task.create needs state and one task output", "E_HIA_TYPE")
                        out, typ = declared[0]
                        self.check_task(typ)
                        if actual[0].typ != typ.state:
                            _reject("task state type differs from protocol", "E_HIA_TYPE")
                        consume(args[0])
                        tag = self.constant(ops, "u8", 0)
                        token = self.zeros(("buffer",), ops)
                        env[out] = _Value(typ, (tag,) + token + actual[0].names + self.zeros(typ.result.flat, ops))
                    else:
                        if len(actual) != 1 or actual[0].typ.kind != "task":
                            _reject("task operation requires one task", "E_HIA_TYPE")
                        typ = actual[0].typ
                        if op == "task.state":
                            name = outputs(ins, [self.types.resolve("u8")])[0]
                            env[name] = _Value(self.types.resolve("u8"), actual[0].names[:1])
                        elif op in {"task.start", "task.poll", "task.cancel", "task.join", "task.close"}:
                            operation = op[5:]
                            expected = [typ.result] if operation == "join" else [] if operation == "close" else [typ]
                            names = outputs(ins, expected)
                            consume(args[0])
                            flat_out = []
                            for name, outtyp in zip(names, expected):
                                parts = tuple(self.fresh() for _ in outtyp.flat)
                                env[name] = _Value(outtyp, parts)
                                flat_out.extend(zip(parts, outtyp.flat))
                            ops.append(_ins("call", actual[0].names, flat_out, function=self.helper(typ, operation)))
                        else:
                            _reject("unknown task operation", "E_HIA_OPCODE")
                elif op == "call":
                    _keys(attrs, {"function"}, op)
                    callee = _name(attrs["function"], "callee")
                    if callee not in self.signatures:
                        _reject("unknown nominal callee", "E_HIA_CALL")
                    params, returns = self.signatures[callee]
                    if tuple(v.typ for v in actual) != tuple(t for _, t in params):
                        _reject("nominal call argument types differ", "E_HIA_CALL")
                    names = outputs(ins, returns)
                    for name, item in zip(args, actual):
                        if item.typ.owns:
                            consume(name)
                    flat_out = []
                    for name, typ in zip(names, returns):
                        parts = (name,) if typ.kind == "primitive" else tuple(self.fresh() for _ in typ.flat)
                        env[name] = _Value(typ, parts)
                        flat_out.extend(zip(parts, typ.flat))
                    ops.append(_ins("call", [x for v in actual for x in v.names], flat_out, function=callee))
                else:
                    if any(v.typ.kind != "primitive" for v in actual) or any(t.kind != "primitive" for _, t in declared):
                        _reject("primitive instruction cannot reinterpret a nominal value", "E_HIA_TYPE")
                    if op in {"owner.move", "owner.drop", "loan.end", "chain.try_push", "chain.pop"}:
                        for name in args:
                            consume(name)
                    for name, typ in declared:
                        env[name] = _Value(typ, (name,))
                    ops.append({"op": op, "args": [x for v in actual for x in v.names],
                                "out": [_param(name, typ.key) for name, typ in declared], "attrs": attrs})
            term = block["term"]
            if type(term) is not dict or type(term.get("op")) is not str:
                _reject("missing nominal terminator", "E_HIA_CFG")
            op = term["op"]
            current = {"id": block["id"], "params": flattened[block["id"]], "ops": ops, "term": None}
            result.append(current)
            if op == "jump":
                _keys(term, {"op", "target", "args"}, "jump")
                target = edge({"target": term["target"], "args": term["args"]})
                current["term"] = {"op": "jump", **target}
            elif op == "branch":
                _keys(term, {"op", "cond", "then", "else"}, "branch")
                cond = value(term["cond"])
                if cond.typ.key != "bool":
                    _reject("nominal branch condition must be bool", "E_HIA_CFG")
                current["term"] = {"op": "branch", "cond": cond.names[0],
                                   "then": edge(term["then"]), "else": edge(term["else"])}
            elif op == "ret":
                _keys(term, {"op", "values"}, "return")
                _names(term["values"], "return values")
                values = [value(n) for n in term["values"]]
                if tuple(v.typ for v in values) != self.signatures[fn["name"]][1]:
                    _reject("nominal return types differ", "E_HIA_TYPE")
                for name in term["values"]:
                    consume(name)
                if live_required():
                    _reject("return leaves a live nominal value", "E_HIA_RESOURCE")
                current["term"] = _ret([x for v in values for x in v.names])
            elif op == "trap":
                _keys(term, {"op", "code"}, "trap")
                current["term"] = dict(term)
            elif op == "match":
                _keys(term, {"op", "value", "cases"}, "enum match")
                matched = value(term["value"])
                if matched.typ.kind != "enum":
                    _reject("match requires a nominal enum", "E_HIA_TYPE")
                cases = term["cases"]
                if type(cases) is not list:
                    _reject("match cases must be a list", "E_HIA_CFG")
                case_map = {}
                for case in cases:
                    _keys(case, {"variant", "target", "args"}, "match case")
                    variant = _name(case["variant"], "matched variant")
                    _names(case["args"], "match case arguments")
                    if variant in case_map:
                        _reject("duplicate match case", "E_HIA_CFG")
                    case_map[variant] = case
                    if matched.typ.linear and term["value"] in case["args"]:
                        _reject("matched linear enum cannot also escape on its case edge", "E_HIA_RESOURCE")
                if set(case_map) != {v for v, _ in matched.typ.variants}:
                    _reject("enum match must be exhaustive", "E_HIA_CFG")
                # All needed values travel through the decision blocks.  The
                # ordinary verifier independently checks every capability edge.
                carry = []
                carry_types = []
                seen = set()
                for item in env.values():
                    if item.consumed:
                        continue
                    for name, typ in zip(item.names, item.typ.flat):
                        if name not in seen:
                            seen.add(name)
                            carry.append(name)
                            carry_types.append(typ)
                mapping = dict(zip(carry, carry))
                cursor = 1
                for index, (variant, fields) in enumerate(matched.typ.variants):
                    width = sum(len(t.flat) for _, t in fields)
                    payload = matched.names[cursor:cursor + width]
                    target = edge({"target": case_map[variant]["target"], "args": case_map[variant]["args"]},
                                  [t for _, t in fields], payload, [term["value"]])
                    arm_names = tuple(self.fresh() for _ in carry)
                    arm_map = dict(zip(carry, arm_names))
                    arm = {"id": self.fresh(), "params": [_param(n, t) for n, t in zip(arm_names, carry_types)],
                           "ops": [], "term": None}
                    selected = set(payload)
                    self.drop_padding([arm_map[n] for n in matched.names[1:] if n not in selected],
                                      [t for n, t in zip(matched.names[1:], matched.typ.flat[1:]) if n not in selected], arm["ops"])
                    arm["term"] = _jump(target["target"], [arm_map[n] for n in target["args"]])
                    result.append(arm)
                    expected = self.constant(current["ops"], "u32", index)
                    matches = self.fresh()
                    current["ops"].append(_ins("compare.eq", [mapping[matched.names[0]], expected], [(matches, "bool")]))
                    if index + 1 == len(matched.typ.variants):
                        invalid_names = tuple(self.fresh() for _ in carry)
                        invalid = {"id": self.fresh(), "params": [_param(n, t) for n, t in zip(invalid_names, carry_types)],
                                   "ops": [], "term": {"op": "trap", "code": "user"}}
                        result.append(invalid)
                        current["term"] = _branch(matches, (arm["id"], [mapping[n] for n in carry]),
                                                  (invalid["id"], [mapping[n] for n in carry]))
                    else:
                        next_names = tuple(self.fresh() for _ in carry)
                        next_block = {"id": self.fresh(), "params": [_param(n, t) for n, t in zip(next_names, carry_types)],
                                      "ops": [], "term": None}
                        current["term"] = _branch(matches, (arm["id"], [mapping[n] for n in carry]),
                                                  (next_block["id"], [mapping[n] for n in carry]))
                        result.append(next_block)
                        current = next_block
                        mapping = dict(zip(carry, next_names))
                    cursor += width
            else:
                _reject("unknown nominal terminator", "E_HIA_CFG")
        lowered = {"name": fn["name"], "params": flattened[fn["entry"]],
                   "returns": [p for t in self.signatures[fn["name"]][1] for p in t.flat],
                   "effects": fn["effects"], "entry": fn["entry"], "blocks": result}
        if self.parameter_loan_returns:
            # Primitive borrowed formals retain their original names when
            # flattened. A nominal owner/partial result contributes only null
            # positions, including its private linear token. No aggregate
            # field name or source annotation can manufacture a loan origin.
            lowered["return_loans"] = [origin for typ, origin in zip(
                self.signatures[fn["name"]][1], self.return_loans[fn["name"]]) for _ in typ.flat]
        return lowered

    def lower(self):
        functions = [self.function(fn) for fn in self.document["functions"]]
        functions += self.helpers
        if len(functions) > MAX_FUNCTIONS or any(len(f["blocks"]) > MAX_BLOCKS for f in functions):
            _reject("elaborated program exceeds core inventory budget", "E_HIA_LIMIT")
        exports = sorted(name for name, (params, returns) in self.signatures.items()
                         if all(t.kind == "primitive" and t.key in SCALARS for _, t in params)
                         and all(t.kind == "primitive" and t.key in SCALARS for t in returns))
        return {"schema": composite_core_schema(self.document["schema"]), "module": self.document["module"],
                "exports": exports, "functions": functions}


def elaborate_program(document, *, legacy=False):
    """Elaborate a detached, structurally bounded document; caller rechecks core.

    The public verifier performs UTF-8/JSON/duplicate-field/depth/size checking
    before this function.  Direct callers gain no VerifiedProgram or execution
    authority from this function alone.
    """
    return _Elaborator(document, legacy=legacy).lower()
