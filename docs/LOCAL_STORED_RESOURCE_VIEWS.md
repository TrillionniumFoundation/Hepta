# Local stored slice views in independent resource IR v4

This profile adds an actual stored-loan state machine to the existing resource
verifier and source lowerer. It does not introduce another parser, type checker,
or executable intermediate language. Programs without view declarations retain
resource IR v3. The data-only verifier continues to accept v1–v3.

The common workload is `examples/resource_views/owned_buffer.hepta`. It uses
`Box<Buffer<u8>>`, `forward<T: Owned>`, a fallible `Result` constructor, shared
view copies, an exclusive view, explicit destruction, an early return, and a
post-allocation rejection path. The generic owner and local lifetime record
coexist in the same checked program. Type parameters and lifetime parameters
on one declaration remain unsupported.

## Supported source shape

```hepta
struct Bytes<'a> { data: read 'a [u8] }
struct Edit<'a> { data: mut 'a [u8] }

fn inspect(owner: read Buffer<u8>) -> u8 effects {panic} {
    let first = Bytes { data: read owner };
    let copied = first;
    return copied.data[0];
}
```

A view record has one lifetime and exactly one direct `[u8]` reference field.
Its instances are local values with an inferred region. The lowerer supports
construction from an existing compatible loan, shared copies, exclusive moves
and explicit drops, `len(view.data)`, and indexed reads/writes. Declared owner
fields preserve their disjoint places; unknown indices remain conservative.
Immediate borrowed parameters and return values retain the existing resource
IR rules, and a returned compatible slice loan can initialize a local view.

Shared view loans end at their lexical block exit, including explicit returns.
Each copied local retains its own live loan. An exclusive view must be moved or
dropped explicitly; moving it transfers its loan. This is a conservative
lexical model, not general nonlexical lifetime inference. In particular, put
shared views in a block that ends before moving or dropping their owner:

```hepta
if size > 0 {
    let view = Bytes { data: read owner.value };
    assert(view.data[0] == 7);
}
drop(move owner);
```

The profile deliberately rejects stored-view parameters or returns, named
function lifetime parameters, nested or multiple-field view records, mixed
type/lifetime parameters, stored views hidden in arrays or generic arguments,
arbitrary view field types, reassignment of a stored reference, and reborrowing
a stored field as another function argument. These restrictions are checked,
including unused unsupported declarations; they are not evidence flags that
can be switched on to bypass missing rules.

## Independent graph rules

The v4 descriptor for `Bytes<'_>` is:

```json
{"kind":"view","name":"Bytes","field":"data","mode":"read","pointee":"[u8]"}
```

| Operation | Required transition |
| --- | --- |
| `bind_view {dest,loan}` | Consume an existing transient loan with exactly the view's permission and pointee; retain its owner/place in the view slot. |
| `copy_view {src,dest}` | Copy only a live shared view into a distinct empty slot. Both slots retain the origin. |
| `move_view {src,dest}` | Transfer only a live exclusive view into a distinct empty slot; invalidate the source. |
| `use_view {src,mode}` | Require a live view. Writing additionally requires an exclusive view in a mutable local. |
| `end_view {src}` | End exactly that live stored view and invalidate its slot. |

Stored loans occupy separate verifier state from temporary loans. Consequently
`end_borrow` cannot release a loan after `bind_view`. Every owner move, drop,
field transfer, storage overwrite, and direct place access checks both kinds
of loan. Ordinary `use`, `move`, `drop`, and aggregate operations cannot erase
a stored view's permission or lifetime. View types cannot be hidden in another
resource type or supplied as generic arguments. CFG joins and loop backedges
compare stored-loan states in addition to owners, transient loans, and variant
facts. Normal and early exits reject outstanding views/owners.

The JSON verifier imports neither `hepta.parser` nor `hepta.checker`.
`lower_resource_ir` uses the existing checked AST and then requires independent
verification. `verify_resource_source(entry, graph)` reloads the actual source,
runs the existing mandatory native reference check, reconstructs the canonical
semantic document and resource projection, and compares the complete graph.
A balanced but altered graph, including a renamed view-field description,
cannot pass as evidence for the unchanged source.

## Exact capability receipts

Successful v4 verification adds `stored_views` with profile
`local_single_u8_slice_records_v1`. Successful source replay copies that exact
object to `source_binding.independent_stored_views`. Both explicitly record
that interprocedural stored regions and generic/lifetime composition were not
checked by this profile.

The general frontend `borrowed_storage.independent_resource_ir_supported`
flag remains `false`. It describes the broader explicit-lifetime-record
profile, which includes shapes this verifier cannot represent. It must not be
interpreted as negating the narrower v4 result, or be changed to `true` merely
because one local profile is supported.

## Static guarantees, runtime observations, and assumptions

| Layer | What is established here | Remaining boundary |
| --- | --- | --- |
| Hepta checker | Existing types, effects, affine moves, and supported stored-reference structure. | No new general region solver or trait system. |
| Independent v4 verifier | Owner/loan transitions and joins of this supplied resource projection; no conflicting access or declared normal-exit leak in its model. | Copied scalar values are abstract. No source refinement, termination, or executable code semantics proof. |
| Native reference check | Actual Rust 1.90 metadata checking of emitted code, including its region and alias rules. | Rust backend/toolchain correctness remains trusted. No fallback when checking fails. |
| Native execution | The fixed exported workload returns the expected results, survives injected fallible allocation refusal, and releases measured Rust allocations after each call. | Finite host observations; no arbitrary-allocation or all-program recovery claim. |
| Runtime | Existing slice bounds/overflow checks, `try_buffer` allocation failure, and explicit destruction. | Panic-abort does not provide unwind cleanup; the IR verifies normal/early return paths. |
| External environment | The recorded Rust compiler, C caller compiler/linker, allocator wrapper, target ABI, runtime and host execute their contracts. | The counter observes allocations through the instrumented Rust global allocator; it does not measure unrelated C allocator traffic or prove hardware behavior. |

The native program is compiled from the existing Rust emitter, not from the
resource graph. Passing source replay does not prove the emitter refines the
graph. A later LLVM implementation must establish its own supported scope and
native execution evidence; this change adds no LLVM or C backend support.

## Reproduction and evidence

With the repository's pinned Rust toolchain available:

```sh
python -m unittest tests.test_resource_views
python -m tools.qualify_resource_views --output /tmp/new-resource-views.json
```

`RUSTC`/`--rustc` select the existing native toolchain. `TMPDIR` selects the
temporary native build location. The qualifier retains the independently read
graph beside the new JSON report. It refuses existing report/graph paths.
Reports inside the checkout use a repository-relative retained graph path.

The native qualification links a real Rust static library with a C caller and
observes nine calls: normal success, pre-allocation rejection, post-allocation
rejection, early return after an exclusive view, two allocation refusals, and
subsequent recovery calls. A counted global allocator rejects the chosen
65,519-byte request. Every call must leave the count at zero; the refusal count
must be exactly two. The process output, exit status, build identity, instrumented
source hash, current compiler/source identities, graph verification, and fresh
source replay are retained and cross-checked. Temporary native build products
are identified by their hashes and are not retained after the run.

`validate_report` rechecks consistency against current source and graph bytes
without rerunning native programs. It is not authentication of arbitrary
third-party JSON. Failed attempts retain earlier successful stages, graph
identity, the failure reason, and any interrupted process's partial output
bytes. A successful report cannot be manufactured by changing a failure's
status flag or replacing an integer exit/result with a boolean.

The focused regression run for this change executed 152 tests across stored
views, resource IR/CLI/source replay, partial places, owned generics, and the
preexisting broader borrowed-storage suite: zero failures and zero skips.
The new file contributes 25 tests, including seven actual Rust rejections also
rejected by the independent resource rules, three structural frontend
rejections, branch/backedge checks, source-replay tampering, 20 qualification
receipt mutations, failure retention, and timeout-byte retention. Rejected
source candidates are only compiled for checking and never executed.
