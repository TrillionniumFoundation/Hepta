# HIA native self-host compiler and cold qualification

The complete bounded compiler is `examples/hia_bootstrap/selfhost.hepta`.
Its scanner, parser, semantic verifier, control-flow and resource checker,
x86-64 encoder, relocation writer and object writer are HIA functions. It
accepts its entire source as ordinary bytes and produces an executable
successor. The current profile is
`selfhost-core-linux-x86_64-v95-bounded-recursion`.

The authoritative declarations are the source-bound
[support contract](HIA_SELFHOST_CORE_SUPPORT.json), native metadata and actual
cold catalog. This document explains their meaning. A declaration, Git commit,
generated inventory or checked-in qualification record is not a new successful
execution. [CURRENT.md](CURRENT.md) identifies the current acceptance result.

## Native source and generation chain

The cold build uses admitted independent HIA seed assembly, projection and
backend roots. The native production graph rebuilds its required roots and
constructs the actual tools, reference programs, plans and descriptor. HIA owns
semantic compilation, plan construction, inventory and contract production,
descriptor binding, qualification, report generation and strict admission.
Bounded assembly adapters perform the required syscalls and machine-call
mechanisms. Their exact sources and embedded bytes remain in the same identity
closure. Development generators and historical hosted tools are not required
runtime stages.

| Generation | Actual input and executed implementation | Required observation |
| --- | --- | --- |
| B0 | Independent native seed pipeline compiles the complete HIA compiler source | A newly constructed executable target compiler |
| B1 | B0 compiles the complete source | Actual HIA-produced successor bytes |
| B2 | B1 compiles that same source | Entire B2 equals B1 |
| B3 | B2 compiles that same source | Entire B3 equals B2 |
| M1 | An original compiler compiles the deliberately changed compiler source | Changed-source first generation |
| M2 | M1 compiles the changed source | M2 differs from M1 |
| M3 | M2 compiles the changed source | M3 equals M2 and differs from B3 |

The modification changes the HIA wrapper reservation from 64 to 80 bytes.
The actual rebuilt generations and subsequent original/modified behavior
checks establish the declared causality experiment. Copying a known image,
repeatedly invoking an initial seed or merely tokenizing one's source cannot
satisfy these gates. Byte equality concerns the complete produced images.

## Language and ABI

Input is line-based `hia-asm.v1` with an explicitly admitted primitive Core
schema. The compiler source uses v9; v8 remains admitted within its own
operation set. Ordinary module labels without explicit exports select flat
output. `selfhost_elf` selects the bounded object profile; an explicit
`exports(name,...)` also selects ELF. `selfhost_exec` selects the reviewed
executable compiler entry and cannot be combined with an ambiguous export list.

Identifiers use bounded ASCII `[A-Za-z_][A-Za-z_0-9]{0,127}`. Functions, blocks
and SSA/formal names have their respective uniqueness scopes. Reserved Core
names and the `__hia_` namespace are refused. The declared entry can occur
anywhere in source order; its arguments exactly match the function signature.
Names resembling numbers remain names, not workspace addresses. ASCII space
and LF, canonical decimal magnitudes, signed width bounds and the assembly
grammar's adjacency and attribute rules remain required.

| Area | Current bounded support |
| --- | --- |
| Values | All ten integer types, `bool`, `unit`, borrowed `readbuf`/`mutbuf`; owned `buffer`/`chain` in the admitted ELF profile |
| Arithmetic | Wrapping and checked integer arithmetic, checked division/remainder/negation/shifts, bit operations, signed/unsigned comparisons, checked/wrapping casts and scalar selection |
| Byte memory | Byte load/store/swap, fill/range fill, copy/range copy and overlapping move; v9 additionally admits fixed-width little/big-endian u64 loads and stores |
| Loans | Shared/exclusive borrowing, childless loan end, exact parent/root and capability-graph flow, parameter-bound returned loans |
| Owned resources | Buffer allocation/try-allocation/move/drop and chain creation/push/pop/head loans; exact linear ownership and descendant checks |
| Calls | Exact direct signatures with zero to six internal scalar, owner or parameter-bound loan results; direct and mutual recursion under private runtime budgets |
| Control flow | Typed returns, jumps, branches, loops, explicit supported Core traps, complete reachability and no inbound entry edges |
| Effects | Duplicate-free declared subsets of `alloc,read,write,trap`; complete instruction and callee obligations |

Fixed-width v9 memory operations check the full eight-byte range before any
access or store. Unaligned offsets are permitted. A failed word store writes
no byte. Older schemas reject these opcodes; bytewise helper sequences retain
their own ordered partial-write semantics. Borrowing, alias and lifetime rules
are not relaxed by the word operations.

Checked arithmetic traps before later effects when its mathematical result is
outside the declared type. Signed division truncates toward zero and rejects
zero divisors and `MIN/-1`. Native traps use `UD2`; earlier completed stores
remain observable. Compilation and execution do not acquire a general rollback
guarantee. Explicit internal effects and all checked widths remain part of
admission, including instructions on untaken paths.

The compiler entry has three buffers `(readbuf, mutbuf, mutbuf) -> u32`.
The six native arguments are source pointer/length, output pointer/length and
workspace pointer/length. Success returns the positive produced byte count;
`0xffffffff` means invalid or unsupported source and `0xfffffffe` means
insufficient capacity. The initial borrowed wrapper retains its packed ABI
status plus Core result. Flat successors return zero-extended Core u32.
Callers supply live disjoint allocations with no concurrent source mutation.

Explicit scalar exports admit zero to sixteen non-unit scalar parameters and
zero or one scalar/unit result. They normalize register and stack inputs,
including dirty high bits. Up to 128 unique named exports resolve exact bytes;
private functions remain checked but unpublished. Internal six-result support
does not broaden this public ABI. Resource-bearing public signatures, arbitrary
callbacks, arbitrary native pointers and additional host imports remain outside
this bounded compiler entry.

## Unchanged compiler resource limits

| Resource | Maximum |
| --- | ---: |
| Source / output / compiler workspace | 1,048,576 bytes each |
| Functions | 128 |
| Blocks per function / whole module | 256 / 1,536 |
| Parameters or call/edge arguments | 16 |
| Distinct SSA names per function | 2,048 |
| Internal instruction/function results | 6 |
| Instructions per module | 8,192 |
| Core structural nodes | 262,144 |
| Relative relocations | 12,000 |
| Explicit scalar exports | 128 |
| Live recursive frames | 256 |
| Private recursive frame bytes | 6,291,456 |

Direct self calls immediately returning their exact result tuple reuse the
current frame with parallel argument staging. Non-tail self and mutual calls
use independently checked frames. Depth and frame-byte guards run before
callee effects. Budget exhaustion traps; it is not a VM exception report and
does not establish native/VM resource-report equality. Loops and tail recursion
remain subject to external CPU and wall budgets; termination is not proved.

The verifier checks all names and signatures before semantic call-graph
validation, including non-entry-reachable recursive functions. It enforces
unique definitions, typed operations and edges, resource permission, loan
origins, exact graph joins and complete effect declarations. Repeated mutable
call arguments and duplicated capability edge transfers refuse; permitted
read-only call aliases retain their existing semantics. Source, operation and
structural limits are independent and cannot replace each other.

Owned ELF output uses the closed `calloc`/`free` contract, reviewed descriptors
and an iterative chain destructor. Allocation and loader assumptions remain
explicit. The source workspace is not an allocation heap. General module
linkage, arbitrary symbols/relocations, all composite resource results and
unbounded arities are outside this compiler profile. The product's separate
native Core/module programs have their own contracts.

## Complete cold execution

```sh
hia-cold-build --source ABS_SOURCE --bootstrap ABS_BOOTSTRAP --output NEW_ABS_BUILD
hia-cold --source ABS_SOURCE --output NEW_ABS_COLD --toolchain ABS_TOOLCHAIN --bundle ABS_DESCRIPTOR
hia-source-bootstrap --source ABS_SOURCE --cold ABS_COLD --bootstrap ABS_BOOTSTRAP --output NEW_ABS_BUILD
```

Each output above denotes its own new directory. The toolchain and descriptor
must be the matching captured products of the native construction recipe.
The cold catalog requires all 60 phases: 21 independent reference phases, the
base generation chain, and original/modified checks for all 19 qualification
families. The source pools and node plans retain the complete case inventory.
Reference results must exist before the target compiler chain can consume them.
Independent phases may be reordered only with preserved dependency bindings,
case identities, source indices and input bytes.

The process owner starts the 180-second computation allowance before supervised
qualification startup. At most two phases execute concurrently, one archive
job runs at a time, no more than two archive jobs wait, and no more than four
phase results remain unsealed. The separate three-second cleanup allowance
cannot admit late computation. All directly owned and adopted children must
be reaped, with actual kernel `ECHILD` and the retained owner receipt confirming
empty ownership. Timeout, nonzero status, missing receipt, identity mismatch or
unconfirmed cleanup cannot produce cold PASS.

The native driver captures complete child input/output and journals every
required execution. The archive seals exact results and verifies complete
physical bytes and decoded member bytes. Compression and back references
preserve these checks; neither a hash-table hit nor a cached source name is
equality evidence. The final report binds actual sources, tools, plans,
generation images, family results, observer, process lifetime and resource caps.

The report schema is `hepta.hia.selfhost-cold-replay.v2`; the success status is
`NATIVE_COLD_SELFHOST_REPLAY_PASS`. Its strict native admission checks the full
current source inventory, support contract, exact catalog, required truth
fields, generation fixed points, all original/modified families and lifecycle
limits. The actual caller-supplied B3 digest is part of that request. Successful
admission returns `HIAADC01`, that digest and the admitted source count. Unit
report fixtures are not complete execution evidence.

## Source closure and release closure

Actual bytes, not paths or Git labels alone, define the source and tool
closure. The native exporter captures the declared files; execution uses
sealed input descriptors. Original and exported observations are rechecked
before success. Contract generation consumes the native source inventory and
metadata and must reproduce the captured contract exactly. A placeholder
contract or a newly computed hash inserted into an old report is refused.

After actual cold admission, the native source-bootstrap plan rebuilds the
source builder and its kit through two generations, checks B3 and ordinary
build capabilities, and publishes source/tool/cold-input receipts. The ordinary
package, installation, Worker activation and installed whole-source rebuild
must then pass with the same source and role identities. Only those actual
results can close complete native delivery.

This establishes the tested source-built executable chain and its finite
behavior controls. It does not prove all compiler behavior, the complete HIA
language, hardware ISA, kernel or allocator sound. Native process ownership
is lifecycle enforcement on the measured host, not a security sandbox for
arbitrary machine code. Those limits remain part of the final contract.
