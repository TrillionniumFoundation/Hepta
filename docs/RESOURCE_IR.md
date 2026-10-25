# Independently checked resource and loan IR

`hepta.resource-ir.v3` is a typed JSON control-flow graph with explicit resource
transitions. `hepta/resource_ir.py` verifies that graph without importing the
Hepta parser, source checker or source AST. This is additional checking of a
resource abstraction. It does not replace the existing native Rust gate.
The standalone verifier also accepts concrete legacy v1 and generic v2 graphs.

`hepta/resource_lowering.py` translates a successfully checked AST into the
graph; the pipeline invokes the independent verifier. The translator is ordinary Python
code; source-to-IR refinement has not been proved. Neither native backend
consumes this IR. Copied values have abstract scalar semantics, so successful
resource verification does not prove arithmetic, bounds, scalar definite
initialization, effects, panic behavior or functional correctness.

## What is checked

The verifier derives owned types from its type table. `Buffer<u8>` is owned;
concrete structs, enums and `Result` containing owned data are owned. A JSON
`owned: false` assertion cannot suppress this derivation. Primitive and
`Buffer` identities, concrete aggregate arguments, complete typed payloads and
function signatures are checked. Recursive value types and unsupported type
kinds are rejected.

Generic function parameters are opaque, function-scoped Copy or Owned types.
Every generic body is verified, including uninstantiated declarations. Calls
carry type arguments whose scopes, constraints and substituted aggregate shapes
are checked independently. `OWNED_GENERICS.md` details that finite profile.

Each function has parameter modes, a typed return signature, local storage,
an entry block, basic blocks and explicit terminators. The verifier propagates
three kinds of state through every reachable edge: initialized owner places, active loans
and enum-variant facts. All incoming states at a block must be identical,
including incoming loop backedges. This strict rule permits deterministic
worklist checking without a source checker or guessed loop invariant. It can
reject programs requiring more expressive joins or loop invariants.

| Operation | Checked transition |
| --- | --- |
| `acquire` | A modeled buffer constructor creates a new owner. |
| `move` | A live owner is consumed and transferred into distinct, vacant storage of the same type. |
| `drop` | A live owner is consumed; no loan into it may remain. |
| `take_field` | An initialized owned struct-field subtree moves to a distinct typed owner slot. |
| `init_field` | A moved-out field is restored from a distinct typed owner; its mutable local parents must remain initialized. |
| `forget` | Local aggregate storage leaves scope only after all owned leaves are consumed and no loan remains. |
| `pack` | Every aggregate field has the declared type; owned fields transfer into the aggregate. |
| `unpack` | All payloads receive distinct typed destinations; owned aggregate storage is consumed. Enum unpacking requires the matching switch-edge fact. |
| `borrow` | A live place grants a read or mutable loan with compatible pointee type and no conflicting loan. |
| `end_borrow` | An active loan ends. Ending a missing loan is rejected. |
| `use` | Direct or loan-mediated reads and writes respect mutability and outstanding loans. |
| `call` | The declared internal signature consumes owner arguments and checks borrowed arguments and results. |
| `foreign` | The same signature rules apply, and an explicit unproved external obligation must be present. |

`branch` explores both successors; copied conditions are abstract. `switch`
must cover every declared enum variant and records a separate fact on each
edge. `return` consumes an owned return value or transfers a declared returned
loan, then requires every remaining local owner and loan to be gone. Normal
and early returns use the same rule. An infinite loop need not have a return;
termination and resource release after nontermination are not claimed.

Unknown operations and terminators fail closed, including in unreachable
blocks. Every structural branch target must exist. Semantic transitions are
checked on reachable blocks. Tables, types, path depth, block counts and the
total operation count have explicit bounds.

## Field loans and returned views

A place is `{ "root": "v0", "path": ["left"] }`. Different known fields of
the same struct can be borrowed independently. An ancestor and its descendant
overlap. Array, buffer and slice indexing uses the conservative `"*"` path
element, so two dynamic indices into one region are treated as overlapping
even if source values might happen to differ.

A mutable loan is exclusive. Read loans can coexist. Passing the same loan
to more than one call argument is rejected if either corresponding parameter
is mutable; shared read/read argument use is permitted. Moving, dropping or
overwriting an owner with an active loan is rejected. Borrowed inputs are
never treated as locally owned values that a callee can destroy.

A returned borrow must originate in one declared `read` or `mut` parameter,
and a mutable return requires a mutable origin. V3 supports explicitly selecting
one input from several borrowed parameters; v1/v2 require a unique input. An
internal function body must establish that relation with its return
transition. The caller conservatively retains the entire argument region
for a returned view, because a call signature does not describe the precise
projection selected inside the callee. Chained views, copied results from
borrowed scalars, and writes through temporary mutable views are supported.
This model deliberately loses some field precision across a call.

External declarations retain these unproved requirements: ABI, aliasing,
effects, lifetime and ownership. Each external declaration binds an obligation
whose status is exactly `assumed_not_verified`; every `foreign` operation
must reference it. Omitting the declaration, changing that status to verified,
or dropping the call's obligation is rejected. A passing report with such
declarations has status `resource_cfg_verified_with_external_assumptions`.
There is no claim that a foreign implementation satisfies those assumptions.

## Source lowering profile

The implemented source translator handles concrete `Buffer<u8>`, owned
structs/enums/`Result`, `buffer`/`try_buffer`, explicit whole-owner and named field movement,
aggregate construction, consuming matches, `drop`/`release`, direct field
and index access, temporary `read`/`mut` borrows, calls, returned views,
`if`, short-circuit booleans, early return, `for` and `while`. Loop bodies
must return to the header with the same owner and loan state. All imported
functions in the resolved project are translated and checked.
Finite Copy/Owned function constraints and whole fresh-owner transfers are
also modelled; the IR does not rely on concrete specialization sampling.
Nested partial moves, field restoration, lexical cleanup checks and explicit
returned origins are detailed in [PARTIAL_PLACES.md](PARTIAL_PLACES.md).

Unsupported constructs fail with `E_RIR_LOWER_UNSUPPORTED`, or a more
specific resource-verifier diagnostic when a produced graph violates the
model. These include raw pointers, tasks/channels/concurrency, task resource
clauses, unbound or unsupported generic constraints, moves through indexed or
borrowed storage, first-class stored references, unmodeled builtins,
projection from temporary nonborrowed aggregates, and mode-changing borrowed
returns that need an explicit reborrow transition. Concrete generic
aggregate instances are supported. A supported source may still be rejected
by the Rust gate, and a Rust-accepted source outside this profile may be
rejected by this translator.

## API and independent use

Export the resolved project with the normal native gate, then extract its graph:

```sh
python -m hepta resource-ir examples/owned/main.hepta > /tmp/owned-export.json
python -c 'import json; print(json.dumps(json.load(open("/tmp/owned-export.json"))["resource_ir"]))' > /tmp/owned.resource-ir.json
python -m hepta.resource_ir /tmp/owned.resource-ir.json
```

The last command imports no parser or source checker. It accepts only the
graph schema, rejects duplicate JSON keys and inputs above 16 MiB, and returns
a JSON diagnostic on failure. `source_binding_verified=false` remains explicit:
the graph's supplied source hashes are correlation metadata. The source export
command also supports `--frontend-only`; that status remains incomplete and
cannot be promoted to native qualification by a passing graph check.

```python
from hepta.checker import check
from hepta.modules import load_project
from hepta.resource_lowering import lower_resource_ir

project = load_project("examples/owned/main.hepta")
checked = check(project.program)
graph = lower_resource_ir(
    project.program, checked, project_sha256=project.identity
)
```

The source-independent verifier can run in a fresh process given only the
serialized graph:

```python
import json
from hepta.resource_ir import verify_resource_ir

with open("program.resource-ir.json", encoding="utf-8") as stream:
    report = verify_resource_ir(json.load(stream))
assert report["ok"], report["diagnostics"]
```

The graph carries source and optional project hashes for correlation, not a
proof of correspondence. The successful verifier report includes a canonical
JSON hash, reachable block/exit counts, operation count, derived owned types
and external obligations. It does not rerun the frontend. `lower_resource_ir`
requires the exact AST objects whose expression types appear in `checked`.

Every graph and report retains false claims for source-to-IR refinement,
native code generation from this graph, whole-language soundness, external
contract proofs, termination, and scalar-value semantics. Attempting to
upgrade those claims in the submitted graph is itself rejected.

## Executed qualification

Run the graph tests:

```sh
python -m unittest tests.test_resource_ir -v
```

Run independent serialization checks and actual native execution:

```sh
RUSTC=/path/to/rustc python -m tools.validate_resources \
  --output /tmp/new-resource-qualification.json
```

The tool refuses to overwrite an existing report. For each project it uses
the existing native Rust gate, lowers the checked source, writes a JSON
graph, verifies the serialized graph in a fresh process without importing
`hepta.parser` or `hepta.checker`, then compiles and runs the source using the
existing Rust backend. The binary is not generated from the resource graph.

The earlier concrete-only host qualification remains archived under
`evidence/production_v4_final/qualifications/independent_resource_ir.json`.
The current qualifier executes all three projects below; the latest complete
release report must bind its results to the source snapshot being assessed.

| Project | Functions | Reachable blocks | Normal/early exits | Resource operations | Native result |
| --- | ---: | ---: | ---: | ---: | --- |
| `examples/owned/main.hepta` plus imported `buffers.hepta` | 6 | 30 | 9 | 60 | exit 0 |
| `examples/resource_ir/returned_views.hepta` | 8 | 11 | 8 | 46 | exit 0 |
| `examples/owned_generics/main.hepta` plus imported `operations.hepta` | 7 | 18 | 10 | 71 | exit 0 |

The report records source hashes, Rust compiler identity, native validation,
artifact digests and eleven rejected mutations of graphs lowered from these
actual projects. The unit suite additionally covers missing foreign
obligations, unequal branch states, duplicate owned payload transfers,
read/read reuse, known-disjoint fields, prefix overlap, conservative indices,
live loans at return, raw-pointer rejection and malicious type/claim changes.
The generic library includes six checked abstract generic bodies and sixteen
generic calls; added attacks include missing type arguments, false constraints,
escaped parameters and removal of a generic destructor. Unit regressions also
reject false substituted aggregate layouts and leaks in uncalled generic bodies.
These observations qualify the tested profile; they are not a proof of the
translator or a universal memory-safety theorem.

The CLI retains each serialized graph beside its report in a fresh
`<report-stem>.graphs/` directory. Each project records the file digest, byte
count and canonical JSON identity actually returned by the independent
verifier. Final release archives include these graph files, so inspecting or
rechecking the independently validated IR does not require trusting a textual
success summary or regenerating the graph. Neither existing reports nor
their graph directories are overwritten.
