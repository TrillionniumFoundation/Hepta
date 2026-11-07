# HIA fixed-Core native self-hosting

This is a real, deliberately bounded self-hosting compiler for a fixed subset of
`hia-asm.v1` / `hepta.hia.program.v8`. The complete compiler is
`examples/hia_bootstrap/selfhost.hiaasm`. Its scanner, parser, semantic verifier,
control-flow checker, x86-64 encoder and relocation writer are HIA functions.
It accepts that entire source file as ordinary input bytes and produces the next
compiler as executable machine bytes. The old `compile_constant` component and
its explicitly open qualification remain separate.

Run the source-bound qualification on Linux x86-64:

```sh
python tools/qualify_hia_selfhost.py --output /tmp/hia-selfhost.json
python -m unittest tests.test_hia_selfhost
```

The qualification creates an evidence directory next to the JSON report. It
retains source inputs, the B0 build receipt, each generated image, every native
invocation receipt, and checksums. A passing exit requires every check to pass.

## Fixed seed and actual generation chain

| Generation | Executed compiler | Input | Output construction |
|---|---|---|---|
| B0 | Existing Python HIA assembler, Core verifier, direct x86 backend; GNU ld | Complete checked-in HIA compiler source | Seed shared library with explicit borrowed-byte export `f0` |
| B1 | That seed's **native HIA compiler** | Complete compiler source | HIA emits a flat x86-64 image |
| B2 | The B1 image | Complete compiler source | HIA parses, verifies and emits the B2 image |
| B3 | The B2 image | Complete compiler source | HIA parses, verifies and emits the B3 image |

B1, B2 and B3 must be byte-identical. They are actual executable compiler
artifacts. Their input is the full source, including all compiler functions;
lexing the source or compiling a separate small example does not close the gate.

`tools/generate_hia_selfhost.py` is a reproducible **authoring aid** that lowers a
restricted development notation into checked-in HIA assembly. It is used to edit
the source before B0. It is neither shipped inside the compiler nor imported by
the successor loader. The qualification itself reads the checked-in assembly;
it does not run this authoring aid. There are no source-hash dispatch tables,
precompiled successor blobs, Python callbacks, runtime token streams, or host
parse/code-generation calls in successor compilation.

`tools/hia_selfhost_child.py` uses only the Python standard library. It hashes
and copies input bytes, loads the sealed B0 shared library or maps a successor
image read/write then changes it to read/execute, and calls the fixed ABI. It
asserts that no `hepta.*` or compiler authoring modules are loaded. The loader
never rewrites instruction bytes, builds an object, resolves relocations,
interprets Core or links a successor. The HIA compiler handles every relative
call and branch relocation in its output.

The report's claims are specific to this fixed subset. It does not claim that
all HIA opcodes, modules or target architectures are self-hosted, nor that the
compiler has a formal refinement proof. Finite test evidence and a bootstrap
fixed point do not constitute such a proof.

## The chosen Core subset

The input is ordinary HIA assembly with the fixed header
`hia-asm.v1 hepta.hia.program.v8 selfhost`. Names are numeric: contiguous `f0`,
`f1`, ... functions; contiguous `b0`, `b1`, ... blocks within each function;
and `vN` SSA values. Function signature variables are `v0`, `v1`, ... and the
entry block must exactly reproduce their names and types. SSA numbers elsewhere
need not be contiguous, but each definition must be unique in its function.
Only ASCII spaces and LF separate tokens. Decimal unsigned literals forbid
leading zeroes and are checked for `u64` overflow. The grammar recognizes the
explicit JSON attribute forms that these operations require.
The existing assembly grammar's adjacency rules are retained: a declaration or
edge name, opcode, `ret`, `effects`, or `entry` directly precedes its opening
parenthesis; `entry(bN)` and `->` remain contiguous. Required separators before
effect/entry clauses, between branch targets and before instruction attributes
cannot be removed. Optional spaces inside parameter/argument lists remain valid.

| Area | Accepted constructs |
|---|---|
| Values | `u64`, `usize` (64 bits), `u32`, `u8`, `bool`, borrowed `readbuf` and `mutbuf` parameters |
| Constants | Typed integer literals and `true` / `false` boolean literals |
| Integer operations | `int.add.wrap`, `int.sub.wrap`, `int.mul.wrap`, `bit.and`, `bit.or`, `bit.xor`, checked left/right shifts |
| Conditions | Unsigned `compare.eq`, `ne`, `lt`, `le`, `gt`, `ge`; `bool.and`, `bool.or`, `bool.not` |
| Casts | `int.cast` with `{"mode":"wrap"}` between integer types |
| Bytes | `buffer.len`, `buffer.load`, `buffer.store` |
| Calls | Scalar-return `call` to a later numbered function, with exact parameter/return types |
| Control flow | `ret`, `jump`, `branch` with explicit, typed block arguments |
| Effects | Every function explicitly declares `effects(read,write,trap)` |

The compiler returns the generated image size on success, `0xffffffff` for
invalid/unsupported input, and `0xfffffffe` for insufficient output or workspace
capacity. B0 uses the existing packed ABI-status plus Core-result wrapper. Flat
successors return a zero-extended Core `u32`; their wrapper relies on the
qualification caller to provide live, disjoint allocations and does not add a
public arbitrary-pointer validation interface. The Core compiler itself checks
its source/output extents and required workspace before parsing.

Each function returns exactly one scalar; returned loans and owners are excluded.
There are no allocations, deallocations, foreign calls, callbacks, arbitrary
pointers, recursion, exceptions, indirect branches or host library imports in
the subset. The fixed exported function `f0` accepts exactly three buffers
`(readbuf, mutbuf, mutbuf)` and returns `u32`. Private helper functions can have
scalar and borrowed-buffer parameters.

The native verifier checks grammar, literal widths, unique SSA definitions,
block-local scope, operation arity/types, buffer permissions, call signatures,
edge signatures, existing targets and graph reachability. Inbound edges to
`b0` are forbidden. Calls must target a later function, making recursion and
backward calls invalid. Repeated mutable buffer arguments in one call or edge
are rejected. Every edge also rejects repeated `readbuf` SSA arguments, matching
Core's linear capability transfer rule, even on a statically untaken branch.
Calls may pass the same read-only loan more than once. Buffers can only originate in parameters and flow through checked
edges/calls; the subset cannot create aliases by producing new buffer values.
The host supplies disjoint live allocations at the external entrypoint.

The bounds are part of the compiler profile:

| Resource | Maximum |
|---|---:|
| Source bytes / output capacity | 1,048,576 each |
| Workspace required | 1,048,576 bytes |
| Functions | 128 |
| Blocks per function / all functions | 256 / 1,536 |
| Function or block parameters / call or edge arguments | 16 |
| SSA variable index per function | 2,047 |
| Instructions across the module | 3,072 |
| Relative relocations | 12,000 |

These bounds also bound stack frames and the accepted Core structure. Numeric
function order bounds native call depth. The chosen op/argument/block limits
keep the corresponding Core JSON below its structural-node and byte bounds.
The text frontend's separate general-purpose presentation limits are not
reimplemented as a dependency of the native compiler.

## Parse, validate and generate

Compilation runs three passes over private source bytes:

1. Parse all functions/blocks, check local types and SSA scope, and collect
   signatures and block-edge metadata. Check target validity and reachability.
2. Parse again, validate forward calls and edge signatures against the complete
   metadata, and count the exact encoded output size without writing output.
3. After the full validation and capacity checks succeed, parse again and emit
   actual machine bytes, then apply HIA-written relative relocations.

For rejected source or insufficient output capacity, output bytes remain
unchanged. Workspace is scratch state and may change on failure. Determinism of
these passes depends on the caller supplying private, nonconcurrently modified
source and disjoint output/workspace; the qualification loader makes those
copies. Workspace need not initially contain zeroes; B3 deliberately runs with
nonzero scratch contents.

Integer widths are normalized after wrapping operations and casts. Generated
buffer accesses check the index against the carried loan length. Checked shifts
check their type's bit width. Failed runtime bounds/shift checks execute `ud2`;
this is a trap, with no promise of transactional rollback for an arbitrary
compiled program. The compiler's transactional output property applies to its
validation/capacity rejection path.

Generated functions use only caller-saved registers and `rbp`. SSA values live
in frame slots; edge arguments use temporary slots so parallel transfers remain
correct even on loops. Calls pass an argument array and a result slot. The
emitter touches each stack page while reserving a frame. The flat image's first
instruction is its SysV entry wrapper; all calls and branches are relative and
there are no external symbol relocations.

## Modification experiment

The qualification makes one explicit, guarded source edit in the HIA wrapper
emitter: replace its stack-reservation constant `64` with `80`. Both values keep
16-byte stack alignment, but generated machine code must change.

B3 compiles the modified source into M1. M1's outer wrapper was emitted by B3,
so it still reserves 64 bytes. Its HIA emitter now generates 80-byte wrappers.
M1 then compiles the same modified source into M2, whose outer wrapper must
actually contain `sub rsp, 80`. M2 compiles the modified source into M3; M2 and
M3 must be identical. M1 and M2 must differ, and the final modified fixed point
must differ from the original fixed point. This is a code-generation change
propagating across compiler generations, not just a source-comment change.

Both original and modified compilers also compile and execute
`examples/hia_bootstrap/bytesum.hiaasm`. That separate program exercises a loop,
branch arguments, a forward function call, byte loads and stores, casts,
wrapping `u32` multiplication and XOR. Its results are checked against an
independent host integer oracle, including empty input and repeated byte ranges.
The acceptance report additionally requires rejection of malformed tokens,
integer overflows, duplicate/out-of-scope SSA, missing/unreachable blocks, wrong
edge/call types, recursion/backward calls, mutable aliases and read-only writes.
It separately checks read-only edge duplication versus legal read-only call
aliases, and rejects syntax that violates the shared assembly adjacency rules.

## Trust and operational boundaries

B0 retains the existing Python Core verifier/direct backend/ELF writer and GNU
linker as seed dependencies. Its exact implementation and source hashes are in
the evidence. After B0, the loader, operating system and hardware remain trusted;
Python no longer performs parsing, verification or code generation. Successor
images need no assembler, linker or libc calls themselves.

Each native invocation runs in a fresh process with 10 CPU seconds, 20 seconds
of parent wall time, 256 MiB address space, 8 MiB stack and bounded file output.
These are resource guards, **not an OS security sandbox**. This helper is for
qualification of source-bound trusted compiler artifacts; it is not an exposed
connector that executes arbitrary uploaded native files. Integration with
worker/catalog identity and deployment gates remains the candidate's separate
responsibility.
