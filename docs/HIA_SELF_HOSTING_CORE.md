# HIA fixed-Core native self-hosting

This is a real, deliberately bounded self-hosting compiler for a fixed subset of
`hia-asm.v1` / `hepta.hia.program.v8`. The complete compiler is
`examples/hia_bootstrap/selfhost.hepta`. Its scanner, parser, semantic verifier,
control-flow checker, x86-64 encoder and relocation writer are HIA functions.
It accepts that entire source file as ordinary input bytes and produces the next
compiler as executable machine bytes. The old `compile_constant` component and
its explicitly open qualification remain separate.

Run the source-bound qualification on Linux x86-64:

```sh
python tools/qualify_hia_selfhost.py --output /tmp/hia-selfhost.json
python tools/replay_hia_selfhost_cold.py --output /tmp/hia-selfhost-cold.json
python -m unittest tests.test_hia_selfhost tests.test_hia_selfhost_contract
```

The qualification creates an evidence directory next to the JSON report. It
retains source inputs, the B0 build receipt, each generated image, every native
invocation receipt, raw child stdout/stderr, and checksums. A passing exit
requires every check to pass.

## Fixed version and support identity

The machine-readable [support contract](HIA_SELFHOST_CORE_SUPPORT.json) names
the current profile identifier, the sole target, the seed and successor ABIs,
resource limits, supported and excluded features, and SHA-256 identities for
the compiler assembly, authoring aid, loader, qualification, test fixtures and
complete Python seed package. It is checked before B0. A stale source file,
changed loader, or broadened support declaration fails that check. To review
and regenerate the contract after an intentional source change, run:

```sh
python tools/generate_hia_selfhost_contract.py
python tools/generate_hia_selfhost_contract.py --check
```

The static contract is a support and identity declaration, not a successful
execution receipt. The runtime qualification additionally records the exact
B0 shared-library digest, actual loaded seed modules, CPython executable and
version, GNU linker identity, source closure, and original and modified native
generations. Git commit/tree metadata is supplementary; actual file hashes
remain authoritative, including when a worktree is dirty. No commit identifier
is embedded in its own source lock.

The cold runner copies only these pinned source files into a newly created
directory. It starts isolated CPython with site packages disabled, a fresh
home and temporary directory, no inherited Python path, and no seed, successor
or bytecode caches. It rebuilds B0 and executes the entire qualification there,
then verifies the exported and original bytes again. The original source tree
is not on the child's import path. This establishes source/process/cache cold
replay on the measured host; it is not a new VM or an independent toolchain.

B0 and the dependent B1/B2/B3/M1/M2/M3 generation chain run sequentially. The
independent qualification families then run in at most two isolated host-oracle
Python processes at a time, with separate output directories for each family
and compiler. Each worker verifies the same pinned source manifest and inputs;
the parent requires every original/modified family result, rejects duplicate
checks, and retains each request, process receipt, output and error log. No
native successor process is reused: every individual compile or execution still
starts its disposable stdlib-only child with its existing limits. This is a
qualification-harness scheduling change, not a compiler speedup or a cached
qualification. All cases and the cold runner's 180-second computation deadline
remain required. The real worker intervals are recorded in the final report.
The coordinator observes every scheduled future and updates a retained phase
index as results arrive. It records every exception, including failures before
a worker starts, and refuses the batch if any phase raises or has a false check.

Cold replay uses a dedicated Linux child subreaper to own the qualification
process and ordinary descendants, including the normal linker capture's new
sessions. The 180-second computation limit includes supervisor startup. A
separate three-second cleanup budget cannot admit late qualification results.
The owner retains process identities and wait observations, and reports cleanup
as confirmed only after all directly owned and adopted children have been
reaped and the kernel reports `ECHILD`. Cold replay preserves its original ten
checks and adds an eleventh cleanup check. A timeout, nonzero qualification exit,
unconfirmed cleanup or mismatched owner identity cannot produce a cold PASS.
The observed child list is not a complete historical inventory of descendants
that exited and were reaped normally. This remains process lifecycle control
on the current host, not a security sandbox.

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

The qualification host separately assembles reference programs and uses the
Core VM and direct native backend as independent comparison oracles after B0.
Consequently the report records `python_parser_or_codegen_after_B0: true` and
`host_reference_codegen_after_B0: true`. Its narrower
`python_parser_or_codegen_in_successor_compilation: false` describes the actual
B0/B1/B2/B3 and modified compiler generation chain. These distinct scopes must
not be collapsed into a claim that all later qualification avoids Python.

The v13 allocator-contract tests also compile a separate host C witness after
B0. Reports therefore record `external_assembler_after_B0: true` and
`host_native_fixture_compilation_after_B0: true`, with
`external_assembler_in_successor_compilation: false`. The C object is linked
only into explicitly named qualification artifacts; it is not part of the
successor compiler or the production runtime.

## Current bounded compiler profile

This section describes the current machine-readable compiler contract. The
version-specific paragraphs and sections below retain the scope and evidence of
their named versions; an earlier version's exclusions are historical, not the
current support boundary. The [support contract](HIA_SELFHOST_CORE_SUPPORT.json)
distinguishes the fixed compiler entry ABI, internal calls and explicit scalar
exports. This bounded compiler does not replace the complete Core checker.

The flat-image input is ordinary HIA assembly with the header
`hia-asm.v1 hepta.hia.program.v8 selfhost` in the legacy compiler-entry example.
Ordinary module labels without explicit exports also select flat output. Explicit
`selfhost_elf` selects the bounded ELF object profile described below, while an
explicit scalar export list selects ELF independently of the ordinary module name.
Function names are unique Core ASCII identifiers of at most 128 bytes; the first
definition supplies the legacy entry ABI, and explicit exports select their named
scalar wrappers.
Block names are unique bounded ASCII identifiers within each function. The
declared entry may appear at any source position, as introduced in v28, with
at most 256 blocks per function.
SSA and formal names use the same bounded ASCII identifier spelling, with at most
2,048 distinct names per function. The entry block must exactly reproduce the
signature names and types; each body definition is unique in its function.
Names that look like numeric indices are names, not workspace addresses.
Only ASCII spaces and LF separate tokens. Decimal integer magnitudes forbid
leading zeroes and are checked for `u64` overflow; signed types additionally
admit an adjacent minus sign and enforce their mathematical width bounds. The grammar recognizes the
explicit JSON attribute forms that these operations require.
The existing assembly grammar's adjacency rules are retained: a declaration or
edge name, opcode, `ret`, `effects`, or `entry` directly precedes its opening
parenthesis; `entry(label)` and `->` remain contiguous. Required separators before
effect/entry clauses, between branch targets and before instruction attributes
cannot be removed. Optional spaces inside parameter/argument lists remain valid.

For example, the existing `nonfirst_entry_source()` qualification fixture declares
its entry last and returns `7`. Its entry parameters still reproduce the function
signature exactly:

```text
hia-asm.v1 hepta.hia.program.v8 selfhost
fn f0(v0:readbuf,v1:mutbuf,v2:mutbuf) -> (u32) effects() entry(later)
block earlier()
  v3:u32 = const() {"value":7}
  ret(v3)
block later(v0:readbuf,v1:mutbuf,v2:mutbuf)
  jump earlier()
end
```

| Area | Accepted constructs |
|---|---|
| Values | All Core integers (`u8/u16/u32/u64/usize`, `i8/i16/i32/i64/isize`), `bool`, `unit`, borrowed `readbuf` and `mutbuf`; owned `buffer` and `chain` only in `selfhost_elf` or explicit scalar-export ELF |
| Constants | Typed signed/unsigned integer literals, `true` / `false` booleans and `null` for `unit` |
| Integer operations | `int.add.wrap`, `int.sub.wrap`, `int.mul.wrap`, `int.add.checked`, `int.sub.checked`, `int.mul.checked`, `int.div.checked`, `int.rem.checked`, `int.neg.checked`, `bit.not`, `bit.and`, `bit.or`, `bit.xor`, checked left/right shifts |
| Conditions | Signed/unsigned `compare.eq`, `ne`, `lt`, `le`, `gt`, `ge`; boolean `compare.eq` / `compare.ne`; `bool.and`, `bool.or`, `bool.not` |
| Selection | `select(bool, T, T) -> T` for all Core integer types, `bool`, and `unit`; true chooses the second operand, false the third; resources are excluded |
| Casts | `int.cast` with `{"mode":"wrap"}` or `{"mode":"checked"}` between all ten Core integer types |
| Bytes | `buffer.len`, `buffer.load`, `buffer.store`, `buffer.swap`, `buffer.fill`, `buffer.fill_range`, `buffer.copy`, `buffer.copy_range`, `buffer.move_within` |
| Local loans | `borrow.read` from shared or mutable views; `borrow.mut` from mutable views; `loan.end` for live local childless loans; exact root/parent flow through branches and loops |
| Owned buffers, ELF only | `buffer.new`, `buffer.try_new`, `owner.move`, `owner.drop`; borrowing and linear transfer of owned buffers |
| Owned chains, ELF only | `chain.empty`, `chain.try_push`, `chain.pop`, `chain.is_empty`, `chain.head_read`, `chain.head_mut`; typed move/drop and closed head-loan graphs |
| Calls | Direct `call` with zero to three scalar, owned or parameter-bound borrowed results, exact signatures and an acyclic non-self call graph; direct self calls immediately return their exact result tuple in order |
| Control flow | `ret`, `jump`, `branch` with explicit, typed block arguments |
| Effects | Any ordered duplicate-free subset of `alloc,read,write,trap`, including `effects()`; required operation and full callee effects must be declared |

Integer operations use all ten Core integer types; booleans and `unit` remain
separate. `bit.not` complements exactly the declared width. Checked addition
traps when the mathematical sum leaves the declared type's range, and
checked subtraction traps when the left operand is smaller than the right.
An arithmetic trap uses `UD2`, as do bounds and shift traps. A trap occurs
before later effects; stores completed before it remain observable. Arbitrary
program execution has no rollback guarantee.

The v15 profile adds checked unsigned casts and boolean equality. Checked casts
preserve the mathematical value when it fits the target width, including
same-width `u64` / `usize` and all widening casts. A narrowing cast traps on any
lost high bit before subsequent effects; earlier stores remain observable.
Boolean equality accepts matching `bool` operands and returns `bool`.
Ordering comparisons still require integers, and casts still exclude booleans
and resources. Both cast modes require the existing quoted JSON attribute.
The extension keeps every source, output, workspace, instruction, block and SSA
limit unchanged. It does not add signed integers, `unit`, general result shapes,
arbitrary identifiers, modules or new foreign interfaces.

Language qualification compares the independent Core VM and mathematical
results for all 25 unsigned checked-cast pairs. Each pair also has a native
input-dependent fixture, and every narrowing pair includes overflow just above
the target limit and at the source maximum, with and without a prior store.
The same boolean equality programs read all four truth-table inputs. Original
B3 and mutated M3 compile and execute these witnesses. These are finite source
and behavior observations, not a proof of complete Core correctness.

The compiler returns the generated image size on success, `0xffffffff` for
invalid/unsupported input, and `0xfffffffe` for insufficient output or workspace
capacity. B0 uses the existing packed ABI-status plus Core-result wrapper. Flat
successors return a zero-extended Core `u32`; their wrapper relies on the
qualification caller to provide live, disjoint allocations and does not add a
public arbitrary-pointer validation interface. The Core compiler itself checks
its source/output extents and required workspace before parsing.

Internal functions return zero to three scalar, owned buffer/chain or
parameter-bound borrowed values. Returned loans require the explicit formal-origin
contract introduced in v23; the complete result tuple must match each call and
return. More than three internal results remains outside this compiler profile.
For a result tuple containing a borrowed view followed by a scalar,
`return_loans(["input",null])` binds the view to the borrowed formal `input`;
the origin must retain sufficient permission through calls and control flow.
Direct self calls must be followed immediately by the exact result tuple in
order, including `ret()` for a zero-result call, and reuse the declared entry.
The flat profile has no owned types or allocator imports. The explicit ELF
profile adds the four owned-buffer and six chain operations described below, using the closed
`calloc/free` import set. Callbacks, arbitrary pointers, non-tail or mutual
recursion, exceptions, indirect branches and arbitrary host imports remain
excluded. The legacy compiler entrypoint `f0` accepts exactly three buffers
`(readbuf, mutbuf, mutbuf)` and returns `u32`. Private helper functions can have
scalar and borrowed-buffer parameters, and ELF helpers can consume owned buffers and chains.
Explicit scalar exports have a separate public ABI: zero to sixteen non-unit
scalar parameters and zero or one scalar/unit result. The three-result internal
call limit does not broaden either public entry ABI.

The native verifier checks grammar, literal widths, unique SSA definitions,
block-local scope, operation arity/types, buffer permissions, call signatures,
edge signatures, existing targets and graph reachability. Inbound edges to
the declared entry block are forbidden. The native HIA checker records the
complete directed call graph, rejects missing targets, and marks functions whose non-self callees are
already acyclic. After at most one pass per function, every function must be
marked. Backward calls are admitted when they do not create a cycle. A direct
self call is excluded from that graph only after the parser enforces the exact
tail shape. Non-tail self calls and all mutual cycles are rejected, including
cycles in unused helper functions. Repeated mutable buffer arguments in one call or edge
are rejected. Every edge also rejects repeated `readbuf` SSA arguments, matching
Core's linear capability transfer rule, even on a statically untaken branch.
Calls may pass the same read-only loan more than once. Views originate from
parameters or checked borrow operations. ELF-owned allocations introduce fresh
roots; move, drop and owner-taking calls require no live descendant loans.
The host supplies disjoint live allocations at the external entrypoint.

The bounds are part of the compiler profile:

| Resource | Maximum |
|---|---:|
| Source bytes / output capacity | 1,048,576 each |
| Workspace required | 1,048,576 bytes |
| Functions | 128 |
| Blocks per function / all functions | 256 / 1,536 |
| Function or block parameters / call or edge arguments | 16 |
| Internal SSA variable index per function | 2,047 |
| Instruction results / internal function results | 3 / 3; exported functions retain their separate ABI restrictions |
| Instructions across the module | 8,192 |
| Core JSON structural nodes | 262,144 |
| Relative relocations | 12,000 |

These bounds also bound stack frames and the accepted Core structure. The
checked non-self graph bounds live native frames by the 128-function limit;
each admitted tail self call adds zero frames.
The call graph and its marks occupy bytes 858,368 through 875,775 of the
existing 1 MiB workspace, after the complete relative-relocation table; they
do not overlap live parser, SSA or relocation state. Every compilation clears
this state, including when the caller supplies nonzero scratch contents.
Each native parse pass counts the exact corresponding Core JSON nodes, including
containers, declarations, parameters, instruction results, attributes and both
branch arms. The optional `alloc` effect contributes its own node even when no
allocating instruction appears in that function. Header word 248 records the count; the count starts at four for
the root object, schema, module and function-list nodes. More than 262,144 nodes
is rejected before any output write. The maximum instruction count does not
bypass the general Core's structural budget.

The current grammar also bounds canonical Core JSON bytes. Reserving the entire
1 MiB assembly payload for identifier and literal bytes, plus 1,024 bytes for the
root, 1,024 per function, 1,024 per block and 512 per instruction gives at most
6,947,840 bytes, below the general Core's 8 MiB limit. ASCII identifiers need no
JSON escaping. These bounds retain the 16-argument/parameter limit, at most three
instruction results, one optional attribute and 64-bit integer magnitudes.
`buffer.try_new` has two results and one argument; `chain.try_push` and
`chain.pop` have three results and at most two arguments. Direct calls may also
have up to three results. All fit the same conservative structural allowance
after source payload bytes have been counted separately.
The text frontend's separate general-purpose presentation limits are not
reimplemented as a dependency of the native compiler.

### v5 capacity qualification

The previous v4 profile allowed 3,072 instructions; v5 raised this to 8,192
without increasing source, output or workspace bytes, stack/CPU/address-space
limits, or child deadlines. The v5 compiler contained 3,044 instructions.
v6 retained these limits and all exact capacity fixtures while adding the tail
self-call checker and lowering. v8 retains the same limits while adding three
unsigned integer operations and scalar selection. The current instruction count is recorded by
the authoring aid and each B0/generation receipt. Those early profiles excluded
returned resources, non-tail/mutual recursion, arbitrary identifiers and general
external linking; later sections describe the subsequent result and identifier
extensions. The v12 owned-buffer and v13 chain extensions retained these capacity
limits.

The relocation table remains 12,000 records in the same workspace layout.
An instruction contributes at most one call relocation, a block at most two
edge relocations, and each public scalar wrapper one call. The optional shared
chain destructor adds exactly two allocator calls. Since v28, each function can
add one initial entry jump. With up to 128 explicit exports, the current upper
bound is `128 + 8192 + 2*1536 + 128 + 2 = 11522`. The historical legacy
single-wrapper bounds were 11395 at v28 and 11267 before the entry-order extension.
Each source chain drop calls that single helper; its two free sites are not
duplicated per source instruction.
Relocations are counted during preflight as well as emission. Every displacement
lies within the checked 1 MiB output, well inside signed x86-64 `rel32` range;
the ELF writer still emits its existing ELF64 fields and resolved `.text`.

Qualification executes 3,072-, 3,073- and 8,192-instruction programs using both
the original and modified compilers. An independent Core VM checks the same
operations and calls, with only the unused borrowed entry parameters removed
to expose a scalar entry. The 8,192-operation result is 8,176. Its ELF `.text`
must equal the flat image; one-byte-short output is transactionally refused.
8,193 operations are valid general Core but refused by this fixed native profile.

Separate 910,057-byte fixtures have exactly 262,144 and 262,145 structural nodes.
The general Core accepts the first and rejects the second. Native parsing must
make the same structural decision: the first reaches output-capacity preflight,
while the second returns invalid-source with error 58 before output changes.
All source bytes, raw invocation logs, output hashes, counters and independent
reference outcomes are retained, including the refusal cases. These checks run
inside the source-only cold replay and do not weaken its acceptance conditions.

The historical v5 upgrade replay consumes the retained v4 B3 image and source from
the exact `894d2dfce54ff25271b8de2c18c902394484d5cc` source release. Their expected
SHA-256 digests are pinned in the replay tool, and its original receipt must
agree. It first demonstrates the old 3,073-operation refusal, then has that
same native v4 compiler compile the 3,044-operation v5 source. U1 compiles U2,
U2 compiles U3, all three must match, and U3 must compile and execute the
8,192-operation case. This upgrade uses no Python parser/code generator or
external assembler/linker. It does reuse, rather than freshly rebuild, the
historical v4 B3; the independent v5 cold replay still starts from B0.

Run that historical replay from the pinned v5 source release. Its script refuses
to apply the v4-to-v5 label to a v6 or later checkout: v4/v5 did not admit self calls, and
this round does not claim a native-only historical upgrade into the new source.

```sh
python tools/replay_hia_selfhost_upgrade.py \
  --previous-evidence <retained-v4-qualification.evidence> \
  --output <new-upgrade-report.json>
```

### v6 direct tail self calls

This section records the v6 single-scalar-result form and its original evidence.
The current zero-to-three result tuple and declared-entry rules are summarized
above; the later result and entry-order extensions preserve same-frame lowering.

A direct call to the current function is admitted only when it is the last
instruction of its block and the immediately following terminator is
`ret(vN)` for exactly that call's result. A following arithmetic instruction,
edge, branch, or return of a different value is refused with error 59. The call
still passes the ordinary arity, exact type, scalar return, SSA and mutable
alias checks. Both parse passes before output writing check the tail shape;
invalid tail syntax therefore leaves the output allocation unchanged.

Lowering first copies every actual argument into the existing call scratch
slots. It then copies all staged words into `b0` parameter slots and emits one
relative jump to `b0`, after the function prologue and its stack probes. This
parallel copy preserves exchanged scalar arguments and both words of borrowed
buffers. It does not overwrite the original result pointer at `rbp-8`, push a
return address, allocate another frame, or execute a second prologue. A later
ordinary return stores through that original pointer and returns to the
original caller. Self-call relocations use the existing block relocation kind;
the v5 relocation upper bound is unchanged. Header word 256 stores the pending
result plus one and is reset at every block; word 248 remains the exact Core
node counter.

This is a bound on stack growth, not a termination proof. Just as accepted
ordinary loops can run forever, a tail self call need not decrease an argument.
The unchanged child limits enforce 10 CPU seconds, a 20-second parent deadline,
256 MiB address space and an 8 MiB stack. General recursion and mutual tail
cycles remain excluded.

The compiler itself uses a recursive `emit_bytes` helper: `emit4` and `emit8`
call it with 4 and 8 remaining bytes. Thus every B0/B1/B2 compiler actually
executes the new form while compiling its complete successor; B1=B2=B3 and the
modified M2=M3 chain must still hold. B0 retains its ordinary native call
implementation and executes only the bounded 4/8-byte recursion. Successors
perform the checked same-frame lowering.

Qualification retains independent recursive Core VM observations for scalar
argument exchange at depths 0, 1, 62, 63 and 127 and for recursive byte copies.
The buffer VM wrapper allocates, initializes and inspects owners; its recursive
helper is unchanged from the native fixture. Native output and scalar results
must agree in both the original and modified compilers. A separate 1,000,001
iteration fixture uses SSA index 2047, a 33,328-byte frame and a closed integer
recurrence oracle (each step exchanges arguments and adds the remaining count)
under the same 8 MiB stack cap. Its recursive VM call-budget refusal is
explicitly retained and is not reported as a VM deep-recursion success.
Tail-related type/arity/alias refusals, valid-general-Core non-tail refusals,
one-byte-short output and matching flat/ELF `.text` are part of the cold replay.

## v14 unsigned 16-bit scalar semantics

The v14 compiler admits `u16` constants, all of the existing unsigned integer
operations, wrap casts, comparison and selection, and `u16` helper parameters,
block arguments and single scalar returns. Constants must lie in `0..65535`.
Wrapping operations normalize to 16 bits; checked shifts require an amount below
16. Checked addition and multiplication compare the full result with its
normalized value, while subtraction, division, remainder and negation retain the
existing unsigned trap conditions. Boolean and byte-buffer element types remain
distinct.

The new internal type code follows the existing resource codes. Resource and
owner classification therefore uses explicit closed sets throughout parameters,
argument duplication, calls, edges, capability graphs and ownership operations.
A scalar cannot become a resource merely because its code is numerically larger.
The language qualification includes repeated scalar call/edge arguments and a
same-frame tail-call recurrence with `u16` swaps and wrapping results, alongside
all five unsigned widths, all 25 width pairs of wrap casts and arithmetic traps.
The original and modified compiler images both execute these finite witnesses.

The 1 MiB source/output/workspace, 1,536-block, 8,192-instruction, native child
and cold replay time limits are unchanged. Signed scalar types, returned
resources, general multiple-result calls and general compiler correctness remain
outside the claim. This extension does not turn the fifty opcode names into
coverage of all Core inputs.

## Parse, validate and generate

Compilation runs three passes over private source bytes:

1. Parse all functions/blocks, check local types and SSA scope, and collect
   signatures, block-edge metadata and the direct-call graph. Check target
   validity, block reachability and absence of call cycles.
2. Parse again, validate all calls and edge signatures against the complete
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

## Borrowed-resource batch: byte swap

Version 4 adds `buffer.swap(mutbuf, usize, usize)`, with no result binding.
It preserves the existing borrowed-buffer lifetime model and original size
limits. Both indices are compared with the carried buffer length before either
pointer is formed or either byte is read or written. Equal valid indices are a
no-op; equal invalid indices still trap. The instruction exchanges exactly two
bytes without allocating storage or creating a new loan. Read-only buffers,
incorrect index types, result bindings and incorrect arities are rejected.

The qualification records a separate resource batch for the original and the
modified fixed-point compiler. Its independent general Core reference runs
before B0 and uses owned allocation, borrowing, initialization, swapping,
loads, loan ending and owner cleanup to expose the resulting bytes. The native
program uses the supported borrowed parameters. Nine cases cover both swap
directions, interior bytes, equal indices, either invalid operand, the maximum
`usize` value and an empty extent. Five malformed programs are independently
rejected by both checkers. A native ELF swap object must contain the same text
bytes as the flat image from the same compiler.

For each runtime trap, the loader's optional qualification-only shared output
mapping retains the actual bytes after the child terminates with `SIGILL`.
Each failing swap must leave its input bytes unchanged. A positive control
performs a store before a failing swap: the retained output must contain that
store, confirming that the observer sees actual writes and that an arbitrary
program has no rollback guarantee. The loader does not catch signals or change
native control flow. The report preserves preimage/output hashes, independent
results, child exit status, raw logs and wall time, including failed executions.

This batch does not add allocation, owner movement, new loans, returned loans
or recursion to Selfhost-Core. Those constructs remain outside the fixed
profile; the general Core reference's broader ownership support is not evidence
that the native self-hosting checker implements it. These finite cases are
regression evidence rather than a general checker or refinement proof.

### v8 unsigned integer and scalar selection extension

The v8 HIA scanner, type/arity checker and machine emitter added
`bit.not`, `int.add.checked`, `int.sub.checked` and scalar `select`. This brings
the then-declared input operation set to 28 of the 50 general Core operations. It did not
expand the ABI, owned resources, external linking, resource limits or the
separate Safe Core machine-validation profile.

The emitter checks the machine carry/borrow flag immediately after 64-bit
addition/subtraction. Narrow addition also compares its full sum with its
normalized `u8` or `u32` result, so overflow cannot be hidden by truncation.
The verifier requires one matching integer operand for `bit.not` and two
matching integer operands for checked addition/subtraction, with one matching
result and no attributes.

The integer emitter is HIA helper `f44`; scalar selection is helper `f45`.
Both are appended after the original `f0` through `f43`, preserving their
identities and keeping every compiler function
within the unchanged SSA-index and per-function block limits. Qualification
checks those limits on the compiler's own complete input source as well as on
boundary fixtures.

The v8 language inventory included 700 independent scalar value
oracles. Every new operation also runs with operands decoded from runtime
input bytes in each of the four widths. The general Core VM executes those
input-dependent bodies through an owned-buffer reference wrapper before B0.
B3 and mutated M3 compile and execute all native fixtures. Separate refusal
cases cover arity, result/operand types, boolean and buffer misuse, unexpected
attributes and out-of-range literals. Forty arithmetic-trap cases per compiler
cover unsigned overflow and underflow, including 64-bit carry and narrow
overflow without a 64-bit carry. Shared output retains a prior store and
excludes a later store after a trap; no-prior-store controls retain the whole
preimage. The arithmetic VM reference verifies each trapping operand pair;
the shared native output supplies the memory-order observations.

Selection requires a boolean condition and two matching scalar values of
`u8`, `u32`, `u64`, `usize` or `bool`, with the same result type. True selects
the second operand; false selects the third. The machine emitter uses full-word
moves and a conditional move on the condition. Forty scalar selection witnesses
cover both conditions for each type and the complete boolean truth table.
Twenty-eight additional observations vary input bytes while keeping each type's
program unchanged; every integer result is observed as all eight output bytes.
Thirteen selection refusal cases cover arity, condition, value/result type,
resource misuse, omitted results and an undefined third operand.

The cold qualification also executes a separate 64-case selection batch from
`tools.hia_selfhost_select`: independent Core references run before B0, and
both B3 and mutated M3 compile five native fixtures that read the condition
and both values from input bytes. Each returns the selected low 32 bits and
writes all eight result bytes, including for boolean results. Both conditions,
the complete boolean truth table, zero, maximum values and the high-bit
boundaries of all four unsigned types are observed. Each compiler also
rejects 13 invalid programs, preserves output on insufficient compilation
capacity, and produces matching flat and ELF text. These supplementary
observations are reported separately from the 700 scalar witnesses and the
28 input-dependent selection observations in the language inventory.

```sh
python -B tests/test_hia_selfhost_language_coverage.py --generate-inventory
python -B tools/generate_hia_selfhost_contract.py
python -B tests/test_hia_selfhost_language_coverage.py --output <new-report.json>
```

Regeneration produces declarations and input identities. Only the subsequent
qualification report records execution, including failed runs and all raw
child logs. The finite cases and fixed points are not an all-input compiler
correctness proof.

## Modification experiment

The qualification makes one explicit, guarded source edit in the HIA wrapper
emitter (`f13`, bound by the support contract): replace its stack-reservation
constant `64` with `80`. Both values keep
16-byte stack alignment, but generated machine code must change.

B3 compiles the modified source into M1. M1's outer wrapper was emitted by B3,
so it still reserves 64 bytes. Its HIA emitter now generates 80-byte wrappers.
M1 then compiles the same modified source into M2, whose outer wrapper must
actually contain `sub rsp, 80`. M2 compiles the modified source into M3; M2 and
M3 must be identical. M1 and M2 must differ, and the final modified fixed point
must differ from the original fixed point. This is a code-generation change
propagating across compiler generations, not just a source-comment change.

Both original and modified compilers also compile and execute
`examples/hia_bootstrap/bytesum.hepta`. That separate program exercises a loop,
branch arguments, a forward function call, byte loads and stores, casts,
wrapping `u32` multiplication and XOR. Its results are checked against an
independent host integer oracle, including empty input and repeated byte ranges.
The acceptance report additionally requires rejection of malformed tokens,
integer overflows, duplicate/out-of-scope SSA, missing/unreachable blocks, wrong
edge/call types, invalid recursive-call signatures, mutable aliases and read-only writes.
It separately checks read-only edge duplication versus legal read-only call
aliases, and rejects syntax that violates the shared assembly adjacency rules.

## General Core expansion batch: arbitrary acyclic call order

Version 2 removes the earlier requirement that every callee have a larger
function number. The compiler assembly itself is now emitted in source order
and contains real backward calls, so B1 through B3 must use the new native
graph checker to rebuild the full compiler. The authoring aid does not sort
the functions into a topological order to avoid that requirement.

The additional independent checks retain both original and modified compiler
outputs for a bytesum program containing a backward call, a complete 128-function
chain with backward edges, wrong backward-call signatures, missing and
out-of-range callees, direct recursion, mutual recursion and an unused cyclic
helper component. Failed compilation must leave source and output unchanged.
Scalar helper results are compared with the independent general Core interpreter
before B0, and complete borrowed-byte programs run against an independent host
integer oracle after self-compilation. Their source bytes, admission differences
and native outputs are retained in the same evidence directory.

Non-tail and mutual recursion are valid in the general Core but remain outside
this finite self-hosting profile. Direct self-tail calls are admitted by the v6
rules above, including bounded same-frame argument staging and cycle checks;
those cases must not be reported as unsupported by the current compiler. V12
adds bounded ELF-owned allocation and transfer, and v13 adds dynamic chains; returned resources and
a general resource/effect checker remain excluded in the support matrix.

## Object expansion batch: HIA-written ELF64 ET_REL

The opt-in module spelling `selfhost_elf` selects
`hepta.hia.selfhost.elf64-relocatable.v1` for programs without allocator calls.
For the common flat/ELF subset it changes only the output container. V12 also
admits four ELF-only owned-buffer operations, and v13 adds the six dynamic-chain
operations with the same allocator import profile below.
In HIA functions `f38`, `f39` and `f41`, the legacy object writer
compiler emits the ELF64 little-endian x86-64 relocatable header, `.text`, a
three-entry symbol table with only `f0` exported, both string tables and a
nonexecuting `.note.GNU-stack`. Internal relative calls/branches remain resolved
by HIA. There are no undefined symbols, external relocations or host imports.

All object bytes come directly from native HIA compilation. Python transports
and independently inspects the resulting bytes without constructing or repairing
the ELF object. `readelf` checks headers, sections, symbols and relocations;
`objdump` disassembles the actual `f0` wrapper. GNU ld then links the emitted
object into a shared library under `-z defs -z noexecstack -z relro -z now`.
The linked compiler rebuilds its complete original/modified source, and linked
bytesum objects execute against the host integer oracle. The extracted `.text`
must be byte-identical to the corresponding flat image in both compiler versions.

The flat B0→B3 and M1→M3 chains still use no linker after B0. The additional
object qualification deliberately invokes GNU ld after those chains; its
separate command identities, logs, object/shared hashes and execution receipts
are retained. Insufficient object capacity and rejected source leave output
unchanged, including the ELF header. Object overhead consumes the same 1 MiB
output limit; no compiler or runtime resource limit is increased.

The object route does not implement arbitrary imports or relocations, arbitrary
public exports, a linker written in HIA, executable ELF images or other ELF
targets. V12 adds only the closed allocator imports below. The seed's existing
Python ELF writer remains a distinct dependency.

## Trust and operational boundaries

B0 retains the existing Python Core verifier/direct backend/ELF writer and GNU
linker as seed dependencies. Its exact implementation and source hashes are in
the evidence. After B0, the loader, operating system and hardware remain trusted;
Python no longer performs parsing, verification or code generation in the
successor compilation path. Flat successor images need no assembler, linker or
libc calls. Owned ELF programs additionally trust ordinary linkage, loading and
the `calloc/free` contract; the separate direct backend used as a qualification
oracle does not construct the successor's objects.

Each native invocation runs in a fresh process with 10 CPU seconds, 20 seconds
of parent wall time, 256 MiB address space, 8 MiB stack and bounded file output.
These are resource guards, **not an OS security sandbox**. This helper is for
qualification of source-bound trusted compiler artifacts; it is not an exposed
connector that executes arbitrary uploaded native files. Integration with
worker/catalog identity and deployment gates remains the candidate's separate
responsibility.

## v9 unsigned checked arithmetic

The native compiler now accepts unsigned `int.mul.checked`, `int.div.checked`,
`int.rem.checked` and `int.neg.checked` for u8/u32/u64/usize. Unsigned MUL checks
its high half and then the declared narrow width. Division and remainder check
zero before DIV and clear the high dividend word. Unsigned negation returns zero
only for zero input. Invalid arithmetic executes UD2 before subsequent writes;
earlier writes remain observable. The current inventory has 824 scalar witnesses, 120 arithmetic trap cases per
compiler and 171 refusal cases per compiler. Input-dependent reference
observations are split into batches of at most 16 scalar results, preserving the
shared 128-result byte-observation limit. The input operation inventory is 32/50.
Signed types, owned resources and the remaining general Core obligations remain
outside this profile. Native finite witnesses and fixed points remain separate
from an all-input compiler correctness proof.


### v10 bulk borrowed buffers

Five bulk operations added in v10 compile in HIA and execute as self-contained x86-64
instructions in flat images and HIA-written ELF objects. No imported libc
routines or host compilation are used. Source, output, workspace, block, SSA,
and instruction limits remain unchanged. V10 coverage was 37 of the general Core's
50 opcodes; ownership, borrow creation and chain operations were unsupported.
This count is not full-language selfhosting or an all-input correctness proof.

Copies require a mutable destination and a shared source with distinct live
roots, preserved by the entry ABI and checked call/edge transfers. Range checks
first establish offset <= extent, then count <= extent - offset. Both ranges
are checked before the first write. Valid empty ranges at the end are admitted;
beyond-end offsets trap even at zero count. Empty ranges skip pointer arithmetic.
Overlapping moves run backward when the destination follows the source and
forward otherwise. Every returning path restores the clear x86 direction flag.
Earlier stores remain observable after later traps; no program rollback is promised.

The independent general Core VM and a Python byte oracle run 58 cases before
B0. B3 and mutated M3 each compile/execute them, reject 34 malformed signatures,
and compare flat/ELF text for all five operations. Cases include both overlap
directions, empty and exact boundaries, maximum usize values, too-short buffers,
and observable stores before a trap. Cold replay includes these witnesses.
Finite observations retain the host/ABI assumptions and do not prove the general
compiler, ISA, loader, resource or FFI semantics.

### v11 explicit borrowed-view lifetimes

The v11 HIA-written checker and emitter added `borrow.read`, `borrow.mut` and
`loan.end` for the existing readbuf/mutbuf resource profile, bringing its
inventory to 40/50 opcodes. Its owned allocation/transfer/drop gap is partially
addressed by the v12 ELF-only extension below and its chain gap by v13;
returned resources and general Core signatures, types and effects remain outside the profile.

Every live loan carries a root and a parent. A parent with live children is
suspended for byte access and calls; extent inspection remains valid as in Core.
Shared siblings may coexist, exclusive siblings may not, and reborrows preserve
the root. Only a local childless loan can end. An ended value remains an SSA
definition and cannot be used or redefined. Ordinary returns require all local
loans to have ended. These checks operate on input operations and capability
state, including non-entry-reachable call-graph checks already required by v10.

CFG edges must carry every local loan and each selected capability's root and
parent exactly once. The sixteen existing trailing bytes of each block record
encode a four-bit root index and four-bit parent index per parameter. A separate
known bit distinguishes an unseen incoming graph from valid all-zero metadata.
Predecessors must agree on the renamed graph. Phase zero first checks the full
source and records each block's source offset. The first discovery of an incoming
graph adds its block to a per-function queue with 256 slots. A queued block that
was previously parsed without an incoming graph is checked once more from its
recorded offset. Later predecessors must still match the already known graph;
processing does not merge inconsistent roots or parents. Unchecked blocks at
the end are unreachable and rejected. Output sizing begins only after this
validation completes. Each block has at most one queued replay, including
reverse source order and cycles, without reparsing the whole module.

Before that replay, only definitions tagged with the selected block are cleared.
This prevents future instruction capabilities from an earlier unchecked visit
from appearing live, while retaining the ordinary duplicate-definition check.
Full-source instruction, node, relocation and import counters are preserved
across these local validation visits. The queue uses workspace bytes 926480
through 928527 inside the existing allocation. Source, output, workspace,
function, block, SSA, instruction and Core node ceilings are unchanged. The
separate CFG suite retains 12 successful Core VM witnesses and 14 invalid Core
inputs, then checks both original and mutated native compilers under the
unchanged ten-second child CPU limit. These finite observations are not a
general correctness or performance proof.

Authoring removes an identity join when only one branch continues. Boolean
expressions made solely of names, constants, comparisons and total wrapping
scalar operations use boolean instructions; expressions containing calls,
reads or checked shifts retain short-circuit control flow. These authoring
changes reduce the compiler's own block/SSA usage without raising input limits.
The emitted HIA remains independently admitted and compiled through B0/B1/B2/B3.

The loan helper has 23 independent Core VM result/byte cases and 39 invalid Core
cases. They cover nested and sibling borrowing, mutable/shared permissions,
callee use, source-order reversal, branch joins, loop backedges and root/parent
index fifteen and maximum valid SSA index 2047. Six valid general-Core cases
with resource result indices 2048, 8192 and UINT64_MAX are refused by the fixed
native profile before capability state is written. Rejections include suspended parents, duplicate/end/use-after-end
operations, missing ancestors, dropped loans and disagreeing join roots/parents.
Original and mutated successor compilers compile and execute the cases and
compare flat/ELF text for three loan programs. Existing bulk, integer, trap,
capacity, cold replay and language witnesses remain required. Finite tests and
a fixed point do not establish an all-input compiler or machine proof.

### v12 owned buffers with closed ELF allocator imports

The actual native parser, capability checker, x86 encoder and ELF writer admit
`buffer.new`, `buffer.try_new`, `owner.move` and `owner.drop` for `buffer` owners
in modules named `selfhost_elf`. At the v12 checkpoint the flat module retained
its 40-operation set and the ELF module had 44 of the general Core's 50 opcodes. Both the owned type and
all four operations are refused in flat modules before any output write.
Recursive chain operations were outside the v12 result and are handled by the
v13 extension below. General Core input shapes and an all-input
compiler-correctness proof remain outside both results.

The fixed public entry remains `(readbuf, mutbuf, mutbuf) -> u32`. Internal
functions may accept owned buffers and must consume or transfer them. Calls
still return one scalar. Only `buffer.try_new` has two instruction results,
in the exact order `(buffer, bool)`; this does not add a multiple-result
function ABI. Definitions are validated before capability metadata is written,
including duplicate and out-of-range SSA results. Each produced owner has a
new root; moves and owner-taking calls consume the old SSA capability. A live
descendant loan prevents moving, dropping or passing an owner. Edge transfers
carry all live owners and their descendants, and predecessor graphs must agree.
Normal return cannot leak an owner. A program trap still stops later effects
without rolling back earlier writes or promising cleanup after termination.

An allocation size is `usize`. Zero creates a live empty logical owner with
pointer and length zero; `try_new(0)` reports success. Positive sizes no larger
than `INT64_MAX` call `calloc(1, size)`. Null or a larger size makes `try_new`
produce an empty owner and false, or makes `buffer.new` execute the existing
Core allocation-trap convention (`UD2` in this successor). Dropping a nonempty
owner calls `free`; dropping an empty owner only consumes its capability. No
new Core trap is assigned to release. These are the ordinary libc allocation
and lifetime assumptions used by the existing direct backend. The earlier
conditional mmap/munmap experiment is not used by this profile.

The allocator object profile is
`hepta.hia.selfhost.elf64-allocator-relocatable.v1`: one exported `f0`, two
undefined function symbols `calloc` and `free`, and `.rela.text` containing
only `R_X86_64_PLT32` call records with addend -4. Native HIA writes every byte,
including symbols and relocation entries. A read-only independent inspector
checks the exact closed object shape, `readelf` reads the object, and GNU ld
links it with libc under the existing RELRO/NOW/nonexecuting-stack options.
The existing child loads the result without an owned-runtime loader rewrite.
Programs that emit no allocator calls retain the legacy object shape.

Compiler source, output and workspace remain bounded at 1 MiB each. Heap
allocations belong to the compiled program and come from libc, not from the
compiler workspace. The current child address-space/CPU/stack limits remain
unchanged. The same 12,000-record relocation table holds internal and allocator
call records: every source instruction contributes at most one call relocation,
so the v12 upper bound was 11265; v13 adds two shared helper sites as described
above. The exact structural-node counter
counts both `try_new` results.

`tools/qualify_hia_selfhost_owned_elf.py` freezes source fixtures and compares
actual successor output against the independent general Core VM and direct
native backend. It observes full output bytes, return values, earlier stores
before allocation traps, resource ledgers in the VM, short-output refusal and
ownership/type/effect rejection. A VM heap-budget stop is recorded separately
from semantic optional-allocation failure. Both B3 and mutated M3 run this
suite as part of the main qualifier; source-only cold replay runs it again.
Raw source, generated objects, inspection, linker logs and child receipts are
retained. Finite witnesses do not establish general allocator, ABI, resource,
ISA, linking, loading or compiler refinement proofs.

### v13 dynamic owned chains under the same ELF allocator contract

The explicit ELF profile now includes all 50 Core opcode names. The flat profile
still has 40. This inventory says which operation names have implemented
bounded input shapes; it does not mean full Core self-hosting. Signed and other
scalar types, general multiple-result calls and returns, returned owners and
parameter loans, arbitrary identifiers and the full effect grammar remain
outside the admitted profile. The public entry remains the same borrowed
three-buffer function returning one `u32`.

`chain.empty` creates a live logical empty chain. `chain.try_push` consumes one
free chain and one free buffer and returns exactly `(chain, buffer, bool)`.
Success links a fresh 24-byte node containing the payload pointer, payload
length and previous head, returning an empty fallback buffer and true. A null
allocation returns both original resources in fresh owner names and false.
`chain.pop` consumes a free chain and returns the same three result types. A
nonempty pop frees the node and transfers its payload and tail; an empty pop
returns an empty chain, empty buffer and false. The third result uses the
already reserved output-vector slot; the source, output, workspace, SSA, block
and instruction budgets remain unchanged.

Head loans carry the chain's root and parent capability, including through
nested borrowed views, calls and exact block-argument renaming. Shared head
loans can coexist; exclusive loans conflict with siblings. Children must end
before their parent, and a chain with a live head descendant cannot be moved,
dropped, pushed, popped or consumed by a call. `chain.is_empty` is legal while
a head loan is live. Ordinary byte operations and `buffer.len` do not accept a
chain; ordinary `borrow.read` and `borrow.mut` also require their declared
buffer/view types. Borrowing an empty chain head traps for bounds, preserving
earlier observable writes.

Chains use the existing 16-byte SSA slot with a head pointer and zero spare
word. Runtime nodes come from libc, never the compiler's workspace. Push and
pop preserve their inputs across libc calls in fixed 32-byte temporary stack
space. Destruction uses one shared internal machine helper that iterates with
a 16-byte local frame and frees each payload and node. Node count therefore
does not create recursive destructor frames. The HIA writer emits this helper
once only when needed and resolves its ordinary internal relative calls.

The helper's local machine branches are authored before B0 and become literal
bytes in ordinary HIA emission functions. Successor HIA parses and checks new
chain programs, chooses those lowering functions, writes all object bytes and
records the `calloc`/`free` relocations itself. Python is not involved in that
successor translation. Independent host VM and direct-backend references are
identified separately in qualification reports, including when they execute
after B0.

The chain qualifier includes empty and nonempty transfers, both empty-head
traps with and without a prior write, shared and nested exclusive head loans,
and 5,000-node construction/pop and iterative-destruction loops. An independent
Core VM resource ledger checks normal-return ownership and loan closure; actual
linked successor output is compared with a separately emitted direct backend
and explicit byte/result oracles. Original B3, mutated M3, cold replay and the
existing flat/owned language corpus remain required. These finite observations
do not establish general resource, allocator, ABI, ISA or compiler refinement.

The independent flow corpus adds thirteen successful call/CFG/loan programs
and seventy-five refusals. Nineteen refusals are valid general Core outside
the declared profile; the other fifty-six violate Core typing or ownership.
This distinction includes general multiple-result function calls and returns,
which remain unsupported despite the complete opcode-name inventory.

A separate ordinary allocator witness binds `calloc`, `malloc` and `free`
only in its own linked test objects. Six cases select a real allocator call
to return NULL, covering preserved failed-push inputs, retry, a failed optional
payload allocation and mandatory allocation traps with and without an earlier
write. Shared counters and logical allocation events remain observable after
defined traps; no signal is caught and no post-trap cleanup is claimed. A
seventh, no-failure control observes 5,000-node native destruction. Event
replay checks every successful allocation against one free, including payloads
and nodes; a passing normal return requires zero live storage and no foreign
or repeated free. The host VM uses an explicit allocator-failure index, never
a heap-budget stop, as its corresponding contract input. These are finite
controlled allocator observations, not an allocator or loader theorem.

Independent review found an earlier compiler-trap regression at an out-of-profile
block parameter such as `v8192:chain`: declaration validation failed but parsing
continued into capability metadata. The parser now stops immediately after a
failed parameter definition and before any incoming capability graph is loaded;
function-signature failures also stop their caller. Four positive block-parameter
cases use the exact `v2047` boundary. Twenty-four valid-Core/profile refusals cover
function and block parameters of all four resource types at `v2048`, `v8192` and
`UINT64_MAX`. The original minimal failure and pre-fix qualification evidence are
retained separately from the repaired source's final qualification.


## v16 exact effect declarations and propagation

The HIA-written parser now accepts every subset of Core's four declared effects
in every order, including a pure `effects()` function. Unknown, duplicated and
malformed effect entries are refused. The retained function record carries the
complete four-bit effect mask; it uses the same workspace bytes as the former
allocation flag. Every declared entry contributes exactly one Core structural
node, preserving the original 262,144-node ceiling.

The native checker requires each operation's static effects from the independent
Core opcode contract. `int.cast` in checked mode additionally requires `trap`,
even when its particular value fits or the conversion widens; wrapping casts do
not gain that effect. Calls require the callee's complete declared set to be a
subset of the caller's set. This applies to forward, backward and unused
functions and does not infer authority from a caller further up the graph.
Mandatory allocation requires `alloc,trap`, optional allocation and release
require `alloc`, chain-head borrowing requires `read,trap`, and a whole-buffer
fill requires `write` without adding a bounds trap. Existing resource and type
checks remain separate requirements.

The qualifier derives 101 valid Core/VM observations and 64 refusals before B0.
The 65 possible ordered declarations cover all 16 effect sets. Native B3 and
mutated M3 each compile and execute the 16 canonical declarations plus all 65
orders in one called-function batch and the operation/call witnesses, then check
all 64 refusals with unchanged output bytes. This produces 232 finite checks;
it does not establish an all-input compiler refinement proof. The current
compiler itself has 1,530 blocks and 6,060 instructions inside the unchanged
1,536-block and 8,192-instruction ceilings. Its source, output and workspace
ceilings remain 1 MiB apiece; child CPU, wall-time and cold-replay budgets remain
unchanged.

The implementation reconciles a prior unpublished effect-parser candidate with
the v15 checked-cast source. The prior candidate's results remain observations
of its own older source. Current-source qualification and source-only cold replay
must pass separately. Signed scalars, general result shapes, returned resources,
full identifiers/modules and general machine/compiler correctness remain open.

## v17 bounded scalar result tuples and CFG compaction

The authoring aid's short-circuit lowering removes one empty forwarding block
per effectful Boolean tail. The short-circuit edge carries its existing value
directly to the join; the evaluated arm still executes in a distinct block.
This is a semantics-preserving CFG change, including guarded reads and checked
shifts. On the v16 compiler it reduces blocks from 1,530 to 1,454 while retaining
6,060 instructions, leaving space for the separately versioned extension below.

The v17 native parser, verifier and encoder admit internal function/call/return
tuples containing one, two or three of `u8`, `u16`, `u32`, `u64`, `usize`, `bool`.
Every call result and returned value is checked in order against the complete
signature. Direct self-tail calls must immediately return every exact result in
the same order. Swapping/replacing those names or inserting an operation remains
outside the tail-call profile. Ordinary forward/backward calls and CFG edges
retain their existing effect, ownership and graph checks.

The public `f0(readbuf,mutbuf,mutbuf)->u32` entry is unchanged. Internal result
words occupy the first 24 bytes of the existing 32-byte private result area,
at 8-byte strides. The function record stores the count at byte 184 and up to
three types at bytes 192/200/208, inside the existing 320-byte record. No source,
output, workspace, function, block, SSA, instruction, native-child or cold-replay
limit is raised. The authored compiler has 94 functions, 1,526 blocks and 6,275
instructions; its largest SSA index is 1,937.

The new `multi` qualification family retains 43 input cases from 13 programs:
all six scalar types, mixed triples, forward/backward calls, branch returns,
loop-carried values, self-tail calls, borrowed arguments and consumed owned
arguments. Full-width little-endian result bytes are compared with an independent
Core VM and explicit tuple oracles. Original B3 and modified M3 compile flat and
ELF outputs; linked images are actually invoked. The owned-argument witness uses
the existing explicit allocator ELF profile. Seventeen refusals distinguish
invalid Core from valid Core outside the bounded profile. Four-result functions,
resource-bearing returns and changes to the public entry remain refused.

The 255-iteration tail case calls the scalar helper directly in the reference VM
to stay within its unchanged 256-frame budget; the other references add an
owned allocation wrapper around the unchanged native body. The native self-tail
path uses the same frame at every iteration. Neither observation proves general
termination or a native stack bound for arbitrary programs.

This is a language extension: v16 rejects the new tuple programs. It does not
claim unconditional all-input equivalence between the v16 and v17 compilers.
Finite regression on the previously admitted subset and explicit new-program
acceptance are reported separately. Signed types, unit/empty results, returned
owners/loans, arbitrary identifiers, module graphs and general linking remain
open; the scalar supplied-ELF proof service is not widened by this change.
Exact-source execution reports, rather than this support declaration, determine
which native, cold-replay and language gates actually passed.

## v18 empty internal result tuples

Internal `fn fN(...) -> ()` and `_ = call(...)` are now ordinary native
zero-result calls. `ret()` is valid only for an empty signature. This does not
allow discarding a callee's scalar results, changing the public `f0` ABI,
returning owners/loans, skipping effects or leaking owned resources. An empty
self-call remains legal only immediately before `ret()` and uses the same-frame
entry jump. Structural node accounting starts with the signature-independent
base, then adds the actual result count, avoiding unsigned `count - 1` underflow.

The existing `multi` family retains its 43 scalar-tuple cases and 17 refusals.
It additionally checks 20 empty-result observations across seven programs:
empty bodies, input-dependent writes, backward calls, both branch arms, loops,
same-frame self-tail calls and consumed owner cleanup. Seven new refusal cases
cover invented results, an unsupported void public entry, non-immediate tail
returns, leaked owners, live child loans and missing write effects. All accepted
observations are checked by the independent Core VM before B0, then by both B3
and modified M3 in flat/ELF formats where applicable. This is finite evidence,
not a claim that the complete HIA language or Python toolchain has been replaced.

## v19 exact packed-byte keyword selection

The keyword recognizer packs at most 32 input bytes into four ordinary `u64`
values and selects a token by equality of the complete bytes **and length**.
This is not hash dispatch or dispatch on the compiler source identity. Inputs
longer than 32 bytes return unknown before any byte load; unknown, NUL-bearing,
prefix and suffix inputs do not acquire a keyword token. All reads and variable
shifts retain ordinary HIA bounds/shift checks. The authoring aid's `choose`
notation lowers to the existing eager typed `select` Core instruction.

The full compiler uses 1,370 of the unchanged 1,536 CFG blocks and 6,890 of 8,192
instruction slots; the keyword function itself uses 15 blocks. Version 18 used
1,522 blocks, so this recovers 152 blocks without moving workspace regions or
raising source/output/workspace/SSA/relocation limits. Function identities and
the public ABI remain unchanged. `tests.test_hia_selfhost_keywords` checks the
actual generated compiler's capacity rather than accepting a declared number.

A separate `keyword` native qualification family includes every keyword,
unknown suffix/mutation inputs, empty/NUL/long strings, and offsets 0 and 3.
All 510 reference observations are independently evaluated before B0, then
executed by the B3 and modified M3 compiled lookup functions in both flat and
ELF forms. Compiling the compiler's own source exercises nonzero scanner offsets
and the ordinary scanner-to-keyword interface. This is finite execution evidence,
not a whole-language or all-input equivalence proof.

## v20 complete scalar type admission inside the fixed Core profile

The native HIA compiler admits all ten Core integer types plus `bool` and `unit`.
Signed decimal constants enforce exact width bounds, including i64/isize MIN;
`unit` requires the exact `null` literal. Narrow signed slots are sign extended.
Signed ordered comparisons use signed conditions; checked shifts reject negative
counts and right shift is arithmetic. Checked add/subtract/multiply/negate consume
OF immediately, then check narrow normalization. Signed quotient and remainder
both reject MIN/-1 at every width, and zero divisors trap before IDIV. The latter
uses a sign-extended dividend and truncates toward zero, matching the Core VM.

Checked sign-changing casts reject a source with its top machine bit set before
normalization, preventing `u64::MAX -> i64` and `i64(-1) -> u64` from being admitted
merely because their machine bits coincide. Same-sign narrowing compares the
exact source against the normalized result. Wrapping casts use the target width.
Internal scalar calls/results, selection and block transfers also admit these
new types; the public entry remains exactly `(readbuf,mutbuf,mutbuf)->u32`.

The signed and scalar-cast qualification families independently evaluate every
input-dependent scalar observation and trap with the general Core VM before B0.
Ordinary observations are batched into straight-line programs with fresh SSA
names and relocated input/output byte indices: no test operand is compiled into
code and no result byte is dropped. Each original case ID remains in `input_cases`.
Native B3/M3 run every batch in flat and ELF form; real UD2 witnesses separately
observe output before/after failed operations. The existing unsigned witness
matrix is retained rather than rewritten to infer signed behavior.

Keyword reference observations now use ordinary Core wrapper calls in groups of
16, preserving each exact input length, fresh owned buffers, call and observed
result. Every group is independently reverified by the VM; no forged/cached
verification receipt is trusted. Full batch reports and each result projection
are retained. This reduces repeated verification of identical helper bodies
without dropping witnesses, reusing native children or changing the cold budget.

Disposable native children additionally clear Linux dumpability after exec.
`RLIMIT_CORE=0` alone does not prevent a piped crash collector from running; such
a collector could copy input mappings and delay a real SIGILL beyond its existing
wall deadline. Clearing dumpability changes neither the UD2 signal nor output
observation and does not turn these loaders into security sandboxes. The parent
worker, system crash-handler settings and other processes are not changed.

This closes scalar type admission within the fixed numeric-name profile, not
whole HIA selfhosting. Arbitrary identifiers/modules/linking, composites,
resource-bearing returned values, general runtime/build/CLI and service rewrites
remain explicitly open. No full compiler refinement theorem is claimed.

The native keyword fixture additionally executes length-prefixed banks of at
most 31 inputs through a normal HIA loop and the exact compiler keyword helper.
Each bank writes one full eight-byte token per original input. The independent
VM checks both the individual lookup observations and the whole bank wrapper;
every original case ID is retained in `input_cases`. Native children remain
fresh per bank, format and compiler. The reference JSON stores shared source
identities instead of serializing the identical lookup program for every input.
Scalar batches adapt to the actual SSA-definition and instruction counts; a
three-operand select cannot be packed into an over-capacity twelve-case batch.
The initial over-capacity refusal and CI cold timeout remain failed observations,
not passing receipts. No witness, output byte or original compiler limit is
removed to obtain the later run.

## v21 owned-result transfer inside the fixed Core profile

Internal `selfhost_elf` calls may return zero to three values mixing scalars,
owned buffers and owned chains. Private results now use three 16-byte slots in a
64-byte area; frame overhead is 576 bytes rather than 544. This is an explicit
private ABI change, not a source/output/workspace limit increase. The public
`f0(readbuf,mutbuf,mutbuf)->u32` entry remains unchanged. Scalars occupy slot word
zero; resource results transfer both descriptor words. The callee consumes its
owner without freeing it and the caller establishes a fresh live root. A
returned owner cannot retain a live descendant loan, be returned twice, or leave
a sibling owner behind. Exact ordered self-tail tuples preserve the original
result pointer and reuse the same frame.

`tools.hia_selfhost_owner_results` adds input-dependent VM/native witnesses for
full-width buffer descriptors, three-owner tuples, scalar/owner ordering,
backward transfers, empty/fallible allocation, a nonempty returned chain and
owner-carrying self tails. Unsafe lifetime variants remain rejection controls.
At v21, returned borrowed views still required a provenance contract that was
not yet implemented; v23 adds the bounded formal-origin contract below.
Neither this change nor a bootstrap fixed point establishes
a rewrite of the full HIA toolchain or an all-input refinement proof.

## v22 explicit terminal Core errors

The HIA compiler admits `trap allocation`, `trap bounds`,
`trap division_by_zero`, `trap overflow` and `trap user`. The declared `trap`
effect is required and the exact terminator structure contributes three Core
nodes. The emitted UD2 terminates the current native child; this borrowed-byte
ABI does not return a machine-readable trap-code word. Independent VM evidence
records the semantic code and actual earlier output writes. Traps in scalar and
void callees, input-dependent branch choice and trapping with live owner/loan
state are qualified separately from normal-return cleanup. An error path is not
rewritten to a successful return or reported as normal owner destruction.

The pre-B0 Core oracle inventory runs in fresh isolated processes, at most two
at once under the existing qualification budget. Source/family/payload hashes
and actual child PIDs are checked before B0; every B/M generation remains
sequential. This scheduling does not reuse native witness children, relax their
limits, or establish full-language/whole-stack correctness.

## v23 parameter-bound borrowed results

The bounded native compiler admits internal readbuf/mutbuf results only with
`return_loans(["vN",null,...])` matching the result tuple. The named formal must
be a borrowed input with sufficient permission. A returned loan must retain that
exact formal origin through CFG renaming, have no children, and be external or
a direct child of an external input. Every result is checked before any returned
capability is consumed. Callers receive both descriptor words and a local child
loan tied to the actual argument. The public f0 ABI is unchanged.

One signature-only pass precedes the original semantic/size/write passes, so
forward-call result origins are available before checking any body. The first
pass does not admit resource graphs; all bodies are checked on the second pass.
The unchanged 1 MiB scratch reserves one byte per SSA and one byte per block
parameter for formal identity; these are distinct from root/parent and block ID.
No source, SSA, block, operation, relocation or execution deadline was raised.
This remains a finite canonical subset, not a whole-language/whole-stack claim.


## v24 syscall-only executable compiler entry

The `selfhost_exec` module selects a static Linux x86-64 ET_EXEC image. The HIA
compiler emits its ELF headers, entry and rel32 patches itself. Its kernel entry
uses only mmap/read/write/exit, with a non-writable executable PT_LOAD and a
non-executable GNU_STACK; there is no PT_INTERP, libc or dynamic loader. The
existing borrowed-buffer f0 ABI remains unchanged behind that entry. Entry
memory is three disjoint 1 MiB regions in one anonymous private RW mapping.

The filter accepts no arguments, reads source from stdin and writes compiled
bytes to stdout. Exit codes are 0 success, 2 invalid source, 3 source/output
capacity, 4 I/O/mmap failure and 64 unexpected argument. The bounded stdin read
admits exactly 1 MiB and detects one byte beyond that bound. EINTR and partial
reads/writes are handled in the machine entry; inherited SIGPIPE may terminate
a closed-pipe write. Failed writes are not atomic filesystem publication: some
prefix may already have escaped. No arbitrary filename opening is implemented.
Owned/chain runtime operations remain in the separate libc-linked object profile,
not this borrowed-buffer executable profile.

The CLI qualification has independent Core VM byte-program observations and
Core-admitted source/output-capacity fixtures established before B0. It runs
E1/E2/E3 direct-kernel fixed points for both original and genuinely modified
compiler source, plus an executable-only original-to-modified M1/M2/M3 chain
(M1 differs from M2, M2 equals M3, M3 differs from original), compares unrelated
executable and flat compilation output,
and retains error exits for malformed input, extra arguments, over-capacity
input/output, closed stdin, /dev/full and RLIMIT_AS-induced mmap failure.
Each observed process is owned through the existing dedicated Linux subreaper;
its Python setup helper replaces itself via execve and does not compile or run
the successor. This is a finite executable filter, not replacement of the full
production CLI, installer, package/module build pipeline, worker or interpreter.
Source declarations here do not imply that execution gates have passed; use the
fresh source-bound cold report for actual results.


### Conditional failure-guard sharing

The authoring aid can replace exactly `if condition: fail(workspace, constant)`
with a call to one HIA-authored conditional helper. It does not predicate the
failure effect: the helper branches before invoking the original `fail`, and
false guards do not access workspace bytes. The condition retains its original
short-circuit lowering. Only a mutable-buffer name and an integer constant are
eligible arguments; expressions that could read/trap, return statements,
multiple statements and else arms are not moved or speculated. The helper is
excluded from its own rewrite. This is source authoring only, not a native
source-identity dispatch or relaxed checker. VM controls compare both forms,
including ordered effects, empty-buffer false guards, true bounds traps and an
ineligible effectful argument. Existing capacity and timing bounds remain.


## v25 exact-byte general function names

Definitions and quoted direct-call targets admit unique Core ASCII names
`[A-Za-z_][A-Za-z_0-9]{0,127}`, including names that coincide with grammar
keywords. The Core `__hia_` prefix and native runtime function names remain
reserved. The first function definition has the existing three-buffer/u32
source ABI; the emitted external symbol remains `f0`. This is not general
exports/linking, module names or block/SSA renaming. Blocks, parameters and SSA
spelling retain their previous numeric bounds and canonical spelling.

The signature prepass records source offset, length and a 32-bit filter hash in
the existing 320-byte function record at offsets 240/248/256. Lookup searches
at most 128 entries, requires matching length and every actual source byte,
and never chooses behavior from a hash alone. The actual equal-hash names
`aaB` and `aba` have different runtime functions in the independent witnesses.
No string copy or new workspace allocation is needed; source bytes remain
immutable throughout compilation. Identifier temporaries use offsets 456,
464 and 472 in the existing state region. All original capacity limits remain.

The first pass discovers all names/signatures only. It does not admit placeholder
self-tail identities or call graph edges. Full semantic checking and the call
DAG pass occur after every definition is known, so both forward references and
cycles are checked by real resolved identity. The lexer exposes general word
spelling; numeric SSA/block/quoted-origin parsing occurs only in its required
context, preserving overflow, leading-zero, quoted-output and adjacency checks.

Before-B0 Core references cover named scalar calls, grammar-keyword and maximum
length names, equal hashes with different values, parameter-bound returned loans,
CFG and exact self-tail returns, the 128-function boundary, and invalid/reserved/
duplicate/undefined names. The native name family compares flat and linked ELF
observations from original and modified compilers. Complete alpha-renaming of
the compiler uses independently reverified source: R1/R2 must equal the relevant
canonical compiler bytes, and the named syscall-only compiler must reproduce
its own executable directly through kernel exec. The two former numeric-name
profile refusals retain their original case IDs as admitted language witnesses.
These are finite gates, not an all-input compiler refinement or whole-stack claim.


## v26 exact-byte general SSA and formal names

The previous numeric-name restriction is replaced with source-byte interning.
ASCII Core identifiers up to 128 bytes include contextual keyword names, typed
underscore, leading-zero suffixes and arbitrary numeric-looking suffixes.
The `__hia_` namespace remains reserved as in Core. Identifiers are never used
as offsets derived from their spelling. The internal SSA index range remains
0..2047, limiting the number of distinct names, not numeric suffix magnitudes.

An open-addressing table occupies workspace [955152,1004304) with 2048 24-byte
records (source offset, byte length, dense internal ID). Each function clears
its slots before parsing its signature. Formal names and entry/body names share
this map, preserving exact signature/entry names and quoted return-loan origins.
At most 2048 probes are permitted, including a full-table hit and a new-name
refusal. Hash collisions are resolved by mandatory full source-byte equality.
A multiplicative 32-bit spread selects the initial slot; the full bounded probe
and byte-comparison rules still decide identity. The count and identifier
scratch fields are disjoint from graph/loan metadata.
The public 1MiB workspace limit is unchanged.

Typed-instruction lookahead distinguishes contextual keyword definitions from
terminators without consuming the token; typed `_` remains distinct from an
effect-only `_ = ...` result. Existing definition/type/dominance/resource checks
still use the dense identity, so interning is not semantic admission. Undefined
uses, duplicate definitions, mismatched entry names, malformed names, oversized
identifiers and 2049 distinct values are negative controls.

All 53 prior name-only resource exclusions retain their IDs and source bytes
as positive VM/direct-native/linked-successor execution cases (24 parameter,
2 allocation-result,6 owned-flow,15 chain-flow and6 borrowed-view). The original numeric boundary
regression and failed historical receipts remain retained. General function and
SSA names do not implement block/module names, composite grammar or the full
runtime/build/release toolchain. Current-source execution receipts must be
obtained for this extension; historical v25 results do not qualify v26.


## v27 exact-byte block names and bounded lexical discovery

Block declarations, entry names and both forward/backward branch targets now
resolve through an exact-byte256entry per-function table. It occupies workspace
[1004304,1010448) with24byte(source offset,byte length,filter hash) records and
count at488. It does not overlap the SSA/formal-origin/call-graph tables or grow
the public1MiB scratch allocation. Shared exact identifier lookup returns its
explicit count sentinel; function lookup still applies its own128function limit.

A discovery pass saves/restores all six lexer state fields and visits the first
word of each source line. It records only actual block headers, distinguishes
typed contextual keyword names, and skips other line bodies without interpreting
them. This is NOT admission: every byte, declaration, operation, resource edge
and CFG is still checked by the complete original passes. No instruction or
constant is accepted because discovery skipped its text. Duplicate, undefined,
malformed, oversized and reserved labels are rejected transactionally. Source
order assigns indices, preserving all existing CFG/capability/relocation checks.
In the v27 profile, the entry still had to be the first block; a valid-Core
later-entry program was retained as an explicit unsupported-profile control.
The v28 extension below removes that restriction and retains the same program
as a positive control.

The compiler's obsolete numeric-name reader is removed after every use migrated
to exact identifiers. That v27 compiler fit 118 functions, 1,287 blocks and 7,678 operations.
Independent controls include actual equal-hash aaB/aba branch targets with
different results, contextual block/end/ret labels and typed keyword SSA names,
128byte labels, complete256block and1536total-block graphs, forward-source
capability joins, backedges and whole-compiler function/SSA/block alpha-renaming.
Formal fresh source replay is required; the v26 receipts do not qualify v27.

The development authoring aid also composes empty parameter-only forwarding
blocks and removes unobserved scalar edge parameters by backwards liveness.
All operation operands, returns and branch conditions are liveness roots;
entry parameters and every resource parameter are always retained. No operation
is removed, including checked operations whose result is unused. Edge arguments
are substituted simultaneously, preserving permutations. Empty forwarding
cycles retain their blocks and divergence. The ordinary Core verifier checks
both input and result. This reduces the authored compiler from1502 to1287blocks
and504741 to424706source bytes, with all7678operations retained. It does not
optimize user inputs, relax their validation, raise limits, or assert equal VM
step costs. VM controls cover ordered byte effects, scalar permutations, loops,
external/local loan graphs, returned origins, owner/chain cleanup and an unused
checked division that must still trap on zero.

## v28 declared entry at any block-source position

The declaration-order block table is unchanged. Each function records the
resolved entry index at record offset264. Entry parameter agreement, external
capability/origin initialization, incoming-entry prohibition and CFG replay now
use that exact index, not a hard-coded block zero. Function prologues copy ABI
formals and then jump to a nonfirst entry; self-tail calls jump to that same
entry after complete parallel argument staging, without a new frame/prologue.
The worklist permits ordinary source-block zero and excludes exactly the entry.

At v28, an additional possible jump per function raised the legacy single-wrapper
relocation derivation to 11,395, still below the unchanged 12,000-record limit. The canonical
Core byte bound now explicitly includes the complete1MiB source payload for
arbitrary128byte ASCII identifiers, rather than assuming old numeric spellings:
1MiB+1024+128*1024+1536*1024+8192*512=6947840bytes, below Core's8MiB limit.
These are derived bounds, not increases to the source/output/workspace,
instruction/SSA/CFG/node/relocation admission limits.

The exact former later-entry exclusion is retained byte-for-byte as a positive
input. Twenty observations of sixteen programs include entry-last and
entry-middle 256/1536-block graphs, reverse capability joins, loop backedges,
scalar parallel tail arguments and parameter-bound read/mutable loan tail
returns. Six negative controls retain wrong entry names/types/arity, incoming
edges, wrong returned-loan origins and conflicting branch-join roots.

A separate native unittest gate also moves every entry in the whole original
and modified compilers to the last or middle declaration position. Each must
reproduce R1/R2 for its own source, reproduce its corresponding canonical
compiler from canonical source, and reproduce a static ET_EXEC compiler through
kernel execution. Reordered compiler images need not equal canonical image
bytes: block layout and dense SSA numbering can change. Reordered owned-buffer
and chain CFG witnesses execute through each new successor with independent VM
references. This extra finite gate does not replace the complete cold replay or
raise its deadline. Development implementation requires fresh current-source
cold, language, native and clean-source execution before qualification is claimed.

The packed keyword matcher retains its exact length and every occupied packed
word comparison. It no longer compares wholly unoccupied trailing words against
zero for each candidate: under the required length equality, the zero-initialized
packing loop cannot have written those words. Partial final words still compare
all 64 bits. No hash shortcut, prefix acceptance, input rewrite, test removal,
capacity increase or deadline increase is involved. Boundary mutation controls
cover lengths 1/8/9/16/17/24/25/32, zero-padding aliases and nonzero source offsets;
the existing independent Core/native exact-keyword observations remain required.

## v29 ordinary module identifiers

The native header parser accepts ordinary Core ASCII module identifiers,
including contextual keywords, underscore,128-byte labels and names that are
reserved only for functions. Labels must be unquoted and must not begin with
Core's reserved `__hia_` prefix. A module label is not a source dispatch key.
The two existing explicit `selfhost_elf`/`selfhost_exec` output profile selectors
retain their object/executable ABIs; all other accepted labels select flat code.
This is not a module/import/export graph or a general object linker.

The exact former `unsupported-module-name` negative input remains unchanged and
is now a positive witness. Fifteen further labels and eight invalid names cover
length, grammar, prefix and quoting boundaries. Original and modified whole
compiler sources with ordinary renamed module labels must each reproduce the
matching compiler through two native generations, in addition to all existing
spelling-only alpha and executable observations. Fresh current-source execution
is required; v28 receipts do not qualify the changed v29 implementation.

## v30 explicit multiple scalar exports

An optional `exports(name,...)` line after the header selects a HIA-written
ELF64 object, independent of the ordinary module label. The list resolves exact
source names after full function/signature discovery. All private bodies still
undergo ordinary validation; only listed functions are published. The legacy
borrowed `f0` flat/object ABI remains when this line is absent. An explicit list
with `selfhost_exec` is rejected rather than selecting an ambiguous stdin ABI.

Up to128 exports fit the unchanged128-function limit. Public signatures admit
0..16 non-unit scalar parameters and zero or one scalar/unit result. SysV AMD64
wrappers normalize register and stack arguments, including dirty upper bits and
signed values; unit results use zero. Resource-bearing public parameters and
multiple results still lack this reviewed C ABI. Private resource and tuple
functions retain their existing semantics. Loader lifecycle-hook and reserved libc-import symbols are
refused, including allocator names even when the current body has no imports. Empty, duplicate, undefined, oversized and malformed lists are rejected
before any output publication.

Exact names and wrapper extents occupy48-byte records in workspace
[1010448,1016592), within the unchanged1MiB workspace. The ELF writer builds real
variable-length string and symbol tables, hides internal functions, and adjusts
calloc/free relocation indices to the explicit symbol count. The conservative
relative-call bound is now11522 (128wrappers+8192instructions+2*1536blocks+
128entryjumps+2destructorcalls), below the unchanged12000 relocation limit. The
existing6947840 canonical-Core byte bound includes the complete assembly payload
and fixed header; export-name bytes are part of that payload, not a new budget.

Word helper byte accesses are unrolled in their original low-to-high order;
failed accesses retain prior byte stores rather than acquiring a new all-eight
precheck. Independent VM and native controls cover little-endian high bits,
misalignment, zero/short/full buffers, final valid positions, partial writes and
maximum-u64 invalid offsets. This change reduces compiler execution work without
raising source/output/workspace/operation limits or the180-second cold deadline.

Finite export witnesses compare independent Core VM results with actual
HIA-generated objects linked by the host C linker and invoked by a disposable
stdlib-only process. The cold runner repeats them for original and modified
successors, after independent references complete before B0. These are finite
execution checks, not an all-input proof. The host linker, Python authoring,
reference verifier, release and wider runtime authorities remain; a general
module graph/linker and whole-stack rewrite are still open.

## v65 bounded scans over live compiler state

The native compiler now avoids two kinds of redundant verifier traversal.
Neither change adds a supported source form or enlarges a source, output,
workspace, function, block, instruction, SSA, call-depth or time limit.

Every usable SSA name is interned densely in the current function's name table.
Its issued index is strictly below the current name count. Definition replay,
borrow-conflict checks, loan transfers and owner release therefore scan that
entire issued range instead of also scanning unused entries up to 2048. The
original initialization of the complete private arrays is retained. Definitions
and capabilities outside the issued range cannot be live; an invalid name still
fails at the unchanged lookup or admission boundary. The maximum valid issued
index remains 2047. This is not a change to alias or resource policy.

Call-graph readiness is monotonic after signature and body discovery. A ready
function has already checked all 128 possible edge slots and established that
every recorded callee is ready. Its immutable edges need no further traversal.
Unready functions still check the complete edge range, including out-of-range
targets, in the original order on each bounded pass. The readiness table is
cleared before discovery; the same number of passes and final cycle-refusal
check remain. Undefined-target and cycle refusal codes are unchanged.

Development comparisons retained the predecessor and candidate images, actual
input/output bytes, return status and observed workspace header. They include
zero and nonzero initial scratch, original and changed compiler source,
maximum-function and reverse-order maximum-block programs, boundary names,
invalid edges and borrowed/owned resource cases. Development timings vary with
the host and do not establish an overall cold-replay speedup. Current-source
cold replay, original and modified fixed points, all existing qualification
families and language controls remain required. A separate bulk-initialization
experiment was reverted and is not part of this implementation.
