# Returned-loan contracts in Agent interfaces

Primitive Core v8 binds each borrowed result to an original loan parameter with
`return_loans`. This relationship is part of the function interface: identical
parameter and return types can still select a different caller-owned resource.
Whole-module admission does not prove that this interface change preserves
caller behavior.

| Admitted Core | Local query | Atomic batch | Inspection |
| --- | --- | --- | --- |
| Primitive v1–v7; current composite normalization | `hepta.hia.edit-query.v2` | `hepta.hia.edit-batch-query.v2` | `hepta.hia.inspect.v1` |
| Primitive v8 | `hepta.hia.edit-query.v3` | `hepta.hia.edit-batch-query.v3` | `hepta.hia.inspect.v2` |

Every displayed v8 function and callee signature includes an arity-matched
`return_loans`. Scalar and owner results use `null`; loan results name input
loan parameters. Omitted all-null annotations are displayed explicitly.
Function headers, callee views and deduplicated batch signatures retain this
contract. Renderers reject missing, malformed, unbound or permission-escalating
contracts, and batch rendering rejects conflicting signatures.

Presentation has only the supplied view: a structurally plausible forged
origin cannot be distinguished from a real origin without the source. Applying
an edit still reconstructs the entire query from the actual verified snapshot
and compares exact bounded JSON bytes. A forged origin, protocol downgrade or
altered metadata never grants permission to apply a candidate. Neither a
displayed digest nor a valid-looking signature replaces canonical admission.

Whole-function patch interface comparison includes normalized `return_loans`.
Patch v1 and v2 `interface_policy=preserve` reject origin reassignment, even
when all ordinary types remain identical. Explicit v2 `migrate` can admit the
changed self-contained module after ordinary verification. Its receipt still
states that external callers have not been revalidated. The patch impact
observer uses the same normalized interface view, retains old and new call
edges, and reports direct and transitive callers. An omitted versus explicit
all-null annotation has one interface meaning.

## Independent proof and Rust boundaries

The existing acyclic scalar and compositional optimization proof profiles are
qualified only for primitive v1–v7. They return `unknown` for v8, including an
unchanged scalar-only v8 module, before solver or resource-skeleton admission.
An older proof receipt cannot qualify new returned-loan semantics. Their
original different CFG, resource and call boundaries remain intact. The route
inventory derives the current admitted primitive range from the version
registry while stating the separate proof range explicitly.

The separately implemented Rust byte-owner execution profile now supports
finite v8 returned loans under `bounded-cfg-byte-owner-loan-returns-v4`.
Its owned static receipt uses `rust-owner-shadow.v2`; older versions retain
their old receipt/profile. See [the independent Rust contract](HIA_RUST_RETURNED_LOANS_V8.md).
An Agent query or edit receipt does not grant that execution qualification.
Rust scalar-only execution still refuses v8 and chain execution remains
unsupported. External lifetimes, whole-language soundness and native refinement
are outside these finite contracts.

## Converged presentation controls

PR #330 (`91225c023b3d61bd8b87bfbd16ac5990c3fb0a62`) also added batch presentation
controls on its older branch. The current v2 baseline already preserves mixed
snapshot refusal, duplicate instruction refusal and signature/block conflict
checks, with additional control-reachable CFG context. This increment retains
those current mechanisms, adds #330's string-typed outer snapshot requirement
and reuses its regression cases. It does not replace the newer v2 view with
the older v1 representation.

These tests establish finite editing mechanism behavior. They are separate
from the prospectively repaired atomic maintenance study and do not establish
a model success-rate, token-cost or development-cost advantage.
