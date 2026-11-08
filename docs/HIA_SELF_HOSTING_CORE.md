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
python tools/replay_hia_selfhost_cold.py --output /tmp/hia-selfhost-cold.json
python -m unittest tests.test_hia_selfhost tests.test_hia_selfhost_contract
```

The qualification creates an evidence directory next to the JSON report. It
retains source inputs, the B0 build receipt, each generated image, every native
invocation receipt, raw child stdout/stderr, and checksums. A passing exit
requires every check to pass.

## Fixed version and support identity

The machine-readable [support contract](HIA_SELFHOST_CORE_SUPPORT.json) names
`selfhost-core-linux-x86_64-v13`, the sole target, the seed and successor ABIs,
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

## The chosen Core subset

The flat-image input is ordinary HIA assembly with the fixed header
`hia-asm.v1 hepta.hia.program.v8 selfhost`. Explicit `selfhost_elf` selects the
bounded ELF object profile described below. Names are numeric: contiguous `f0`,
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
| Values | `u64`, `usize` (64 bits), `u32`, `u8`, `bool`, borrowed `readbuf` and `mutbuf`; owned `buffer` and `chain` only in `selfhost_elf` |
| Constants | Typed integer literals and `true` / `false` boolean literals |
| Integer operations | `int.add.wrap`, `int.sub.wrap`, `int.mul.wrap`, `int.add.checked`, `int.sub.checked`, `int.mul.checked`, `int.div.checked`, `int.rem.checked`, `int.neg.checked`, `bit.not`, `bit.and`, `bit.or`, `bit.xor`, checked left/right shifts |
| Conditions | Unsigned `compare.eq`, `ne`, `lt`, `le`, `gt`, `ge`; `bool.and`, `bool.or`, `bool.not` |
| Selection | `select(bool, T, T) -> T` for `u8`, `u32`, `u64`, `usize`, and `bool`; true chooses the second operand, false the third; resources are excluded |
| Casts | `int.cast` with `{"mode":"wrap"}` between integer types |
| Bytes | `buffer.len`, `buffer.load`, `buffer.store`, `buffer.swap`, `buffer.fill`, `buffer.fill_range`, `buffer.copy`, `buffer.copy_range`, `buffer.move_within` |
| Local loans | `borrow.read` from shared or mutable views; `borrow.mut` from mutable views; `loan.end` for live local childless loans; exact root/parent flow through branches and loops |
| Owned buffers, ELF only | `buffer.new`, `buffer.try_new`, `owner.move`, `owner.drop`; borrowing and linear transfer of owned buffers |
| Owned chains, ELF only | `chain.empty`, `chain.try_push`, `chain.pop`, `chain.is_empty`, `chain.head_read`, `chain.head_mut`; typed move/drop and closed head-loan graphs |
| Calls | Scalar-return direct `call`, exact signatures, acyclic non-self call graph; direct self calls in the checked tail form below |
| Control flow | `ret`, `jump`, `branch` with explicit, typed block arguments |
| Effects | `effects(read,write,trap)` or `effects(alloc,read,write,trap)`; allocation, drop and calls to allocating functions require `alloc` |

All integer operations use `u8`, `u32`, `u64` or `usize`; booleans remain
separate. `bit.not` complements exactly the declared width. Checked addition
traps when the mathematical sum exceeds that width's unsigned maximum, and
checked subtraction traps when the left operand is smaller than the right.
An arithmetic trap uses `UD2`, as do bounds and shift traps. A trap occurs
before later effects; stores completed before it remain observable. Arbitrary
program execution has no rollback guarantee.

The compiler returns the generated image size on success, `0xffffffff` for
invalid/unsupported input, and `0xfffffffe` for insufficient output or workspace
capacity. B0 uses the existing packed ABI-status plus Core-result wrapper. Flat
successors return a zero-extended Core `u32`; their wrapper relies on the
qualification caller to provide live, disjoint allocations and does not add a
public arbitrary-pointer validation interface. The Core compiler itself checks
its source/output extents and required workspace before parsing.

Each function returns exactly one scalar; returned loans and owners are excluded.
The flat profile has no owned types or allocator imports. The explicit ELF
profile adds the four owned-buffer and six chain operations described below, using the closed
`calloc/free` import set. Callbacks, arbitrary pointers, non-tail or mutual
recursion, exceptions, indirect branches and arbitrary host imports remain
excluded. The fixed exported function `f0` accepts exactly three buffers
`(readbuf, mutbuf, mutbuf)` and returns `u32`. Private helper functions can have
scalar and borrowed-buffer parameters, and ELF helpers can consume owned buffers and chains.

The native verifier checks grammar, literal widths, unique SSA definitions,
block-local scope, operation arity/types, buffer permissions, call signatures,
edge signatures, existing targets and graph reachability. Inbound edges to
`b0` are forbidden. The native HIA checker records the complete directed call
graph, rejects missing targets, and marks functions whose non-self callees are
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
| SSA variable index per function | 2,047 |
| Instruction results / function results | 3 / 1; two for `buffer.try_new`, three for `chain.try_push` and `chain.pop` |
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
branch arms. Header word 248 records the count; the count starts at four for
the root object, schema, module and function-list nodes. More than 262,144 nodes
is rejected before any output write. The maximum instruction count does not
bypass the general Core's structural budget.

The unchanged grammar also bounds canonical Core JSON bytes. Conservative
budgets of 1,024 bytes for the root and each function's own fields, 2,048 bytes
per block excluding its operations, and 512 bytes per operation give at most
7,472,128 bytes, below the general Core's 8 MiB limit. These bounds use the
fixed identifier lengths, 16-argument/parameter limit, single optional attribute
and unsigned 64-bit literal limit. `buffer.try_new` has two results and one
argument; `chain.try_push` and `chain.pop` have three results and at most two
arguments. None has attributes, and all remain within the same conservative
512-byte per-operation bound; other instructions have at most one result.
The text frontend's separate general-purpose presentation limits are not
reimplemented as a dependency of the native compiler.

### v5 capacity qualification

The previous v4 profile allowed 3,072 instructions; v5 raised this to 8,192
without increasing source, output or workspace bytes, stack/CPU/address-space
limits, or child deadlines. The v5 compiler contained 3,044 instructions.
v6 retained these limits and all exact capacity fixtures while adding the tail
self-call checker and lowering. v8 retains the same limits while adding three
unsigned integer operations and scalar selection. The current instruction count is recorded by
the authoring aid and each B0/generation receipt. Returned resources,
non-tail/mutual recursion, arbitrary identifiers and general external linking
remain outside the current profile. The v12 owned-buffer and v13 chain
extensions retain these capacity limits.

The relocation table remains 12,000 records in the same workspace layout.
An instruction contributes at most one call relocation, a block at most two
edge relocations, and the wrapper one call. The optional shared chain destructor
adds exactly two allocator calls: `1 + 8192 + 2*1536 + 2 = 11267`.
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
`examples/hia_bootstrap/bytesum.hiaasm`. That separate program exercises a loop,
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
Predecessors must agree on the renamed graph. A bounded phase-zero reparse
handles a predecessor located later in the source; parsing advances to output
sizing only after all reachable blocks have been checked with known incoming
graphs. At most 1,536 discovery rounds are allowed. Source, output, workspace,
function, block, SSA, instruction and Core node ceilings are unchanged.

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
