# Owned Core operations: reusable helpers and remaining admission work

## Result and scope

The experimental helper profile is `selfhost-owned-linux-x86_64-mmap-v1`.
It is separate from the default Selfhost-Core support inventory. It does not
close general Core self-bootstrap, change the default allocator contract, or
establish compiler/machine refinement.

The unchanged 37-operation compiler source with SHA256
`1f8bcdf1c541d5f8ee7595dfc3905746874fd89455ca32c46ec329233030f68b`
compiled a 77,449-byte HIA author program into a 99,438-byte native emitter.
That emitter then executed the proposed helper functions to generate eleven
owned-runtime machine fixtures. All eleven ran successfully against their
declared return or trap expectations. No Python emitter runs in either native
successor step. The independent general Core verifier/VM passed twelve
reference cases and rejected sixteen malformed resource-flow cases.

The helper-generated programs run with **zero compiler workspace bytes**. One
allocates and checks every byte of a 2 MiB + 17-byte owner. Another creates and
iteratively drops 5,000 chain nodes and their payloads. These observations
confirm that the prototype does not repurpose the compiler's fixed 1 MiB
workspace as a hidden program heap or equate the SSA count with dynamic owner
count. They remain finite observations under the stated runtime assumptions.

Source components:

- `tools/hia_selfhost_owned_runtime.py`: seventeen ordinary authoring functions
  in `SOURCE`, using the existing `load_var`, `store_var`, `emit_bytes` helpers.
- `tools/hia_selfhost_owned_cases.py`: ordinary general Core assembly, independent
  verifier refusals, allocation-failure injection, and resource observations.
- `tools/qualify_hia_selfhost_owned_runtime.py`: unchanged native selfhost compiler
  -> HIA helper author -> generated native fixtures, with retained raw evidence.
- `tests/test_hia_selfhost_owned_runtime.py`: semantic boundary checks and the
  native qualification path.

## The ten operations and their existing semantics

The authority is `hepta/hia_opcodes.py`, the canonical capability transitions
in `hepta/hia_program.py`, and actual execution in
`hepta/hia_program_runtime.py`. The current general direct backend implements
the same object shape in `hepta/hia_program_native.py`.

| Operation | Results | Declared effects | Required behavior |
| --- | --- | --- | --- |
| `buffer.new` | `buffer` | `alloc, trap` | Fresh zeroed storage; zero length succeeds without an allocator attempt; failure traps. |
| `buffer.try_new` | `buffer, bool` | `alloc` | Success returns a real owner and true; failure returns an empty owner and false. Zero length is successful. |
| `owner.move` | same owner type | none | Consume the input name and transfer ownership to a fresh name. No live loan may remain. |
| `owner.drop` | none | `alloc` | Release an unborrowed buffer or iteratively release the payload and 24-byte storage of every chain node. |
| `chain.empty` | `chain` | none | A real empty chain capability, with no node allocation. |
| `chain.try_push` | `chain, buffer, bool` | `alloc` | Allocate one 24-byte node. Success transfers payload and old chain into the new chain and returns an empty fallback owner. Failure returns the original chain and payload in fresh names. |
| `chain.pop` | `chain, buffer, bool` | `alloc` | Nonempty: release one node and transfer its payload and tail. Empty: return an empty chain, empty payload owner, and false. |
| `chain.is_empty` | `bool` | none | Inspect chain emptiness without consuming it. |
| `chain.head_read` | `readbuf` | `read, trap` | Shared loan of the head payload, rooted in the chain capability. Empty head access traps. |
| `chain.head_mut` | `mutbuf` | `read, trap` | Exclusive loan of the head payload, rooted in the chain capability. Empty head access traps. |

The general object-size model refuses sizes above `INT64_MAX`. For optional
allocation this produces an empty owner/false without an allocator attempt;
mandatory allocation traps. A finite interpreter heap limit is different:
`buffer.try_new(8192)` under a 4096-byte VM heap budget reports
`budget_exceeded`, not an allocation result. The reference cases preserve this
distinction and also show that a preceding empty allocation does not consume
the deterministic failure-injection sequence.

The 5,000-node reference run observes 10,000 allocations, 10,000 frees, 15,000
logical owners created/dropped, and a 125,000-byte peak logical payload/node
extent. Every live owner, chain, node, local-loan and byte counter is zero at
normal return. The kernel prototype has additional page/VMA overhead; these
logical Core counters do not measure its actual resident memory or economic
cost.

## Why the allocator choice must remain explicit

The existing direct backend assumes `calloc`, `malloc`, and `free`, with fresh
nonaliasing zeroed buffers, 24-byte chain nodes, and successful release of a
valid allocation. Its assumptions already name libc and the loader.

The experimental inline profile instead uses the Linux x86-64 raw syscall
ABI: private anonymous `mmap` for nonempty storage, and `munmap` of the exact
allocation length. It has no dynamic symbols or external relocations. It
checks the raw negative-errno range instead of confusing it with libc's
`MAP_FAILED` convention. Empty owners make no syscall. Failure of an allocation
retains the defined Core failure/transfer behavior. Chain destruction uses a
constant amount of native stack regardless of chain length.

Linux anonymous mapping supplies zero-initialized pages. The syscall register
convention and mapping rules are documented by the upstream Linux man-pages:
[syscall(2)](https://man7.org/linux/man-pages/man2/syscall.2.html) and
[mmap/munmap(2)](https://man7.org/linux/man-pages/man2/mmap.2.html).

**Release success is an extra visible assumption of this prototype.** Even
valid `munmap` can fail in an environment that cannot create required VMA
metadata. `owner.drop` does not declare a Core trap, so this implementation
must not silently introduce one. A failed release terminates with UD2 as a
runtime-contract failure; qualification does not classify it as a newly
defined Core `owner.drop` trap or prove it cannot occur. Allocation availability
and physical overhead also differ from libc. Thus these helpers cannot be
substituted into the default profile and called equivalent without resolving
the runtime contract.

The ordinary allocation-failure fixture requests `1 << 62` bytes in the
existing limited native child and observes an empty owner/false. This is not
claimed to reproduce the VM's injected allocation-failure sequence. Chain-node
allocation failure is checked by the independent VM fixture; the native run
does not claim to have forced every node-allocation failure site.

## Fixed compiler workspace is sufficient for metadata, not a program heap

The current compiler already reserves sixteen bytes per SSA value. It can
represent a buffer as `(pointer, length)` and a chain as `(head, 0)` without
changing the SSA table or stack slot width. A node remains exactly three
machine words: payload pointer, payload length, successor pointer. Dynamic
objects can outnumber SSA identities, as the loop witness demonstrates.

Appending only the seventeen helper authoring functions to the unchanged
37-operation generator passed canonical Core verification at 66 functions,
1401 blocks, 4083 operations and maximum SSA index 1996. This stays within the
existing 128-function, 1536-block and `v0..v2047` limits. It does not establish
that every later parser/capability extension fits those limits; remeasure the
actual integrated compiler and preserve capacity refusals.

For three operation outputs, a proposed scratch layout is count at byte 288
and three `(SSA id, type)` pairs at byte 296, ending before byte 344. These are
separate from the loan-check state at 264/272/280, the retained function count
at 1024, and the function table beginning at 4096. The metadata must be reset
for each instruction. The prototype helpers take explicit SSA destinations
and do not depend on this proposed scratch layout.

## Minimal parser and capability work before owned admission

The existing assembly syntax already expresses multiple outputs without a
new language construct:

```text
v3:buffer,v4:bool = buffer.try_new(v2)
v8:chain,v9:buffer,v10:bool = chain.try_push(v6,v7)
```

The selfhost parser currently reads one output, rejects output types >= 6,
and stores only one result word. It must parse a bounded result vector, check
each definition and result type/arity before emission, account for every
output node, and store complete descriptor pairs. Merely allowing commas or
removing the resource-type refusal is insufficient.

The loan-graph implementation can support buffer/chain owners, but the type
distinction is semantic. A root with parent zero is an external caller loan
only for a view type; an owner with parent zero remains a locally accountable
resource. In particular:

- New owners and chain-transfer outputs become fresh roots. Move/drop and
  consuming calls invalidate the old capability only after every guard passes.
- Moving, dropping, pushing or popping an owner must reject any still-live
  descendant loan, not merely one direct child.
- Every normal return and every CFG edge must preserve or consume all local
  owners/loans; merging predecessors must agree on the renamed capability graph.
- Calls consume owner arguments exactly once and must reject aliased exclusive
  views. Repeating a resource argument cannot be permitted because its type is
  outside the old readbuf/mutbuf range.
- `buffer.len` may accept a buffer owner, but memory load/store still require
  a checked view. Old checks such as `type >= 6` become unsound when `chain`
  is added and must be replaced with exact allowed-type sets.
- Actual `alloc` effects are required even for an empty `chain.pop` or empty
  `owner.drop`. The old fixed `effects(read,write,trap)` grammar cannot admit
  these operations faithfully. Callee effects must propagate through calls.

The sixteen negative fixtures include missing allocation effects, malformed
multi-result types/arity, duplicated result names, a correctly typed duplicate
chain edge, leaked/consumed owners, moves/drops while borrowed, push/pop while
borrowed, and conflicting head loans. They currently establish canonical
checker behavior; they are not evidence that the unfinished selfhost parser
rejects those inputs.

## General multi-result call/return is a separate ABI change

Supporting the three-result ownership operations does not automatically add
general multi-result function returns. The current selfhost function header
requires one scalar return, and calls use a result address at
`-frame + 512`. With `frame = (max_ssa + 2) * 16 + 544`, only 32 bytes separate
that address from the final local SSA slot. A `(chain, buffer, bool)` return
needs 40 packed bytes or 48 bytes using uniform 16-byte result slots and would
overlap that slot.

For a bounded three-result internal ABI using uniform slots, increasing that
frame suffix from 544 to 560 gives 48 bytes. A broader sixteen-result ABI would
need 256 result bytes and a suffix of 768. The function record can keep its
320-byte size for sixteen return types: existing parameter types occupy bytes
48..175, a return-type vector can occupy 176..303, and two metadata words remain
at 304 and 312. Return counts, effect masks, call checks, result copying,
tail-self-call checks and return-loan origin contracts must change together.
These are design bounds, not implemented or qualified default behavior.

## Route that retains the current libc assumptions

If the goal is the same allocator contract as the general direct backend,
the smallest conceptual route is an explicit runtime import ABI rather than
using compiler workspace for storage:

- Relocatable ELF output can declare the existing closed libc imports and
  produce their symbol/relocation records; the ordinary linker then binds them.
- Flat output needs a versioned loader-supplied runtime table, or a separate
  linked profile. A table should use a new explicit entry ABI, not reinterpret
  caller workspace bytes as arbitrary function pointers.
- One possible internal convention reserves a callee-saved runtime register,
  saves/restores it in the public wrapper, and carries the trusted table across
  internal calls. The loader must bind the exact allocator functions and retain
  their lifetimes with the image. Source Core never gains raw-pointer authority.
- The existing relocation bound assumes at most one call relocation per input
  instruction. Resource operations can make more than one allocator call, so
  that bound and the capacity witnesses must be recalculated.

No loader or default runtime ABI was changed by this experiment. That binding,
the complete resource verifier, the output grammar and same-source cold replay
are concrete dependencies before claiming the ten operations are admitted by
the original compiler profile.

## Reproduce

From a checkout containing the unchanged seed compiler and these four source
files, on Linux x86-64 with the existing linker dependency:

```bash
python -B tools/qualify_hia_selfhost_owned_runtime.py --output NEW_DIRECTORY
```

Or retain the unit/native suite evidence:

```bash
HIA_SELFHOST_OWNED_EVIDENCE=NEW_DIRECTORY \
  python -B -m unittest tests.test_hia_selfhost_owned_runtime -v
```

The output directory must not already exist. It contains the helper author
source, seed receipt, every native input/artifact, request, stdout/stderr,
return/trap observation and `qualification.json`. The report explicitly keeps
`selfhost_owned_opcodes_admitted`, `full_core_closed`,
`default_allocator_profile_changed`, and `universal_refinement_proved` false.
