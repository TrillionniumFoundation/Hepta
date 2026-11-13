# Native call and primitive erasure

## Recovery identity and qualification boundary

This document and `tests/test_hia_call_primitive_native.py` were reconstructed
after the temporary executor filesystem was lost. They are new files. The
former document and test file were not recovered in full, and their historical
test results do not qualify these replacements.

The generator, HIA program, installed bridge, and original reference branch
were recovered byte for byte from the independently verified
`call-independent-review-ad640-r1.tar.gz` archive. That archive has SHA-256
`686c3b9924e1306c082a0dbb5a0851fa707e49ac515b7d21f629afbeb9f3c151`.
Its frozen source commit was
`ad640f10405d2637b0a18fe106957307e36df27b`, tree
`69a905cf99e830b7bc2b0c07a7adafd6565bfe16`.

| Retained item | SHA-256 |
| --- | --- |
| HIA source | `3a475754f80a361407230052cefd28f5dd80aa42ac3585f47d88581d0c2ed4d5` |
| Native machine image | `6beb3484515aaf5ea94498a26b88932439217324693102802982b3f1ce3e9143` |
| Python bridge at the frozen commit | `e1897d101841e6a9bd5b61372736e316ea89736c6ca2d556455be9c5b26039ef` |
| Actual authoring generator | `2a38fd3f1feaa645f1b23e00ef30d94f4f8b7b5c8d1399ad1de9413f17a0c839` |
| Original call/primitive semantic `if` AST | `3d7b6d0c4d014f0928ed6a15ac72319e963c26c9916dadf93ecde7f98d8f1ab1` |
| Former test file, not recovered | `abcba5dac94ae14f4359850dc7562b603f2aa59eb81edeeed184947e37c543da` |
| Former document, not recovered | `160c674c14635f4f136d1c4aad2c594bffacf422bd15e49b7976a707d341d0a3` |

The retained development manifest identifies compiler
`0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8`.
It is a development image, not a current-source cold qualification.
The historical development report records 24 passing tests: 17 call owner
tests and 7 generic graph tests. The separate immutable review records 193
differential cases, 1457 malformed packet cases, and a complete 4,198,912
element call argument result. Those are observations about the frozen source
and historical harnesses. The replacement suite requires its own execution.

## Owned behavior

`examples/hia_bootstrap/call_primitive.hiaasm` owns ordinary nominal calls and
the erasure of primitive instructions in an admitted nominal function. Its
decisions include:

- Call attribute inventory, callee identifier admission, and signature lookup.
- Exact argument and return type correspondence, including distinct nominal
  identities with equal primitive layouts.
- Output reparse ordering, ordered linear consumption, and generated-name
  allocation.
- Complete returned Core instructions, consumed-value flags, and output
  bindings, including the prefix produced before a semantic refusal.
- Primitive nominal-type guards and the original consuming-operation set:
  `owner.move`, `owner.drop`, `loan.end`, `chain.try_push`, and `chain.pop`.

The installed bridge copies already held object identities into descriptor
IDs. It forwards two explicit requests to the existing signature and type
owners, and decodes the HIA-produced complete result. It does not implement a
second call lookup, type comparison, ownership policy, or instruction plan.

The primitive Core verifier still validates the generated instruction and
whole program. A native erasure result is not execution authority. In
particular, an unfamiliar primitive opcode or its raw attributes can survive
this erasure stage and be refused by the ordinary later Core check, preserving
the previous error order.

## Continuation protocol and publication order

The private input is a typed object array containing phase, generated-name
counter, operation, attributes, type descriptors, deduplicated held values,
argument references, declared outputs, signature inventory, and reparsed
outputs. Repeated argument aliases refer to the same held value descriptor.
Nominal type identities are transported by exact object identity rather than
display names, hashes, or Python semantic equality.

For a valid call the sequence is:

1. Phase 0 checks the attributes and callee name, then requests the signature
   inventory. Invalid attributes and names refuse before that callback.
2. Phase 1 looks up the callee and compares argument types, then requests output
   reparse. An absent callee or argument mismatch refuses before output reparse.
3. Phase 2 compares the reparsed outputs, consumes owned arguments in order,
   allocates generated names, and returns the complete Core call and bindings.

Primitive erasure uses phase 0 and requests neither callback.
The driver performs at most three native steps per `lower()` invocation.
This is an in-process continuation protocol; it is not a persistent request
journal or a promise of replay resistance for externally retained private
packets. A callback exception propagates from that invocation.

The result header has eight little-endian u64 fields: `HIACPR01` magic,
semantic error, final counter, request, payload size, and three zero reserved
words. The payload contains exactly `ops`, `consumed`, `values`, and `query`.
The adapter checks extents, exact scalar types, phase/request correlation,
counter bounds, graph structure, and immutable input bytes before returning a
result. The elaborator publishes the returned counter, operations, consumed
flags, and completed bindings before raising its semantic error. This retains
the original partial-state order.

For example, a call that consumes an owner and then exhausts its generated-name
budget may return the consumed flag and completed earlier bindings while
emitting no call instruction. Replacing that result with an empty generic
failure would lose observable state and is not permitted.

## Storage and lossless graphs

| Region or bound | Limit |
| --- | ---: |
| Private encoded input | 256 MiB |
| Native output | 64 MiB |
| Native workspace | 32 MiB |
| Generated-name counter | 8192 |
| Held value and argument inventories | 262144 each |
| Type descriptor inventory | 524288 |
| Signature inventory | 1024 |
| Primitive width of one nominal type | 512 |
| Declared output primitive slots | 32768 |

These private transport limits do not relax the public source or Core limits.
The checked-in generator also remains within the existing native compiler
function, block, instruction, and block-parameter budgets.

The generic graph codec can reference original encoded nodes and concatenate
original arrays. Thus a repeated 512-slot argument can be represented without
repeating all of its strings in the native output frame. Decoding still creates
the complete logical argument list; it does not truncate, summarize, hash, or
replace that list with a promise. The source document and its later public
value-slot/Core rejection remain unchanged.

## Selection, installation, and cold admission

`HEPTA_HIA_CALL_PRIMITIVE_MANIFEST` selects the installed native owner. The
manifest binds the HIA source, executable image, schema, and compiler identity.
Missing, malformed, stale, or mismatched selected artifacts refuse. They do not
authorize execution of `_reference_call_primitive`. An unselected process
retains the existing reference route until a later repository-wide cutover.

Installed resources are package-owned. The wheel controls run with an empty
`PATH`, disable the hosted call branch, and prevent importing authoring tools.
They compare the complete canonical Core bytes, then remove or change the
installed HIA resource and require a refusal.

The replacement fixture has separate development and cold paths:

- `HEPTA_HIA_CALL_PRIMITIVE_DEVELOPMENT_MANIFEST` uses a supplied, source-bound
  development artifact. It confers no cold qualification.
- `HEPTA_HIA_CALL_PRIMITIVE_COLD_REPORT` uses the normal standalone builder and
  its matching-source cold admission for candidate `call-primitive`.
- Supplying both refuses before temporary fixture creation. With neither set,
  the existing B1/B2 development bootstrap route is used and labelled as such.

No fixture silently skips a missing native image, compiler, machine linker,
wheel prerequisite, or nested regression. Qualification requires actual
completion and separate reporting of every failure and incomplete run.

## Replacement controls

The new `CallPrimitiveSourceTests`, `CallPrimitiveAdapterTests`, and
`CallPrimitiveNativeTests` separate source reproduction, synthetic transport
negatives, and actual HIA execution. The actual controls cover:

- Exact complete Core across public nominal schemas, with the hosted call
  branch disabled; execution of scalar and resource examples.
- The original mutation categories for callee guards, argument shapes,
  output reparse failures, raw primitive attributes, consumed aliases, name
  budgets, callback order, resolver caches, and complete state prefixes.
- The 1457 original malformed packet mutations with immutable input and
  output/workspace canaries.
- Independent HIA VM versus machine execution for complete output frames and
  the full workspace, including both callback requests and partial refusals.
- 8201 repeated 512-slot arguments, zero-width return inventories, exact
  output-slot capacity, private bounds, and concurrent independent results.
- The unchanged 75-case nominal resource and returned-loan suite with the
  hosted call owner disabled, with zero skips or expected failures.
- Composition with seven other native nominal owners while all corresponding
  hosted branches are poisoned.
- A real emitted-machine call that transfers an allocated owner, observes
  allocation refusal, and proves the expected allocation/free counts.
- An actual wheel install, absence of authoring imports, complete result
  equality, and refusal after selected resource corruption or removal.

The replacement `constant_program`, `call_program`, and
`duplicate_owner_program` fixtures are newly authored. Only the documented
constant fixture contract (first function, no parameters, first `u32` constant
37) was known exactly enough to preserve. The replacements are not presented
as recovered historical fixture bytes.
