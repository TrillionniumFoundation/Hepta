# HIA self-hosted chain qualification — v13

## Result and scope

The frozen v13 HIA-written compiler implements the six dynamic chain operations
in its explicit `selfhost_elf` profile. After an independently reproduced
parameter-boundary defect was fixed, the final source passed 37 source tests,
1,127 native qualification checks, 10 cold-replay checks with a fresh nested
1,127-check native qualification, and 910 language qualification checks. The
independent reviewer additionally reran eight exact parameter-boundary cases
against the final original and modified fixed-point compilers.

The ELF input inventory now contains all 50 general Core opcode names within
the documented bounded profile. The flat input inventory remains 40. These
counts do not establish complete general Core language support or a compiler
correctness theorem. General multiple-result calls and returns, returned
resources, the general type/signature/effect surface, arbitrary syntax and
general linking remain outside the admitted profile. General machine, allocator,
ABI, ISA and loader correctness are not proved by this qualification.

The status of this delivery is **SCOPED_CHAIN_V13_PASS_FULL_CORE_HOLD**. It is a
source and executable-evidence handoff; publishing, integrated-head CI and the
public-install identity belong to the integration work that consumes it.

## Frozen identities

| Subject | Identity |
| --- | --- |
| Profile | `selfhost-core-linux-x86_64-v13` |
| HIA source bytes | 439,709 |
| HIA source SHA-256 | `d57f0350174ade6347077b72e2679ac083f103a7b38698efe7c4d227304beb91` |
| Original B1 = B2 = B3 SHA-256 | `d20dbc1426ffaf0369a24b884ff30e0ae675b8ea24ea130a361abafeee9fbdaa` |
| Original successor image bytes | 717,245 |
| Modified M1 SHA-256 | `5ab668068284f5cf0abaacb61b560071ff80b8fe5910f4e96107649cf7b39c4f` |
| Modified M2 = M3 SHA-256 | `a692195b44655cc4850065e527330a3594762143af38eb94bb0fa8c64fb05a34` |
| Compiler shape | 85 functions, 1,503 blocks, 5,772 instructions, largest SSA identifier 1,912 |
| Changed/new source files | 24; exact bytes, SHA-256 and Git blob IDs in `source-files.json` |
| Source-file manifest Git blob | `069366eb6ab32181ed4994b32d3b0606a5fd4521` |

The support contract records 247 source files. Each qualification source
manifest additionally records the support contract itself, for 248 entries.
The main, cold wrapper, cold nested qualification and language reports have
identical source manifests. Every entry and all 24 delivery files were reread
after the gates and matched the frozen identities.

## Implemented behavior

`chain.empty` creates an empty linear owner. `chain.try_push` consumes a chain
and a buffer and produces exactly `(chain, buffer, bool)`. On successful node
allocation, the resulting chain owns the input buffer and the fallback buffer
is empty. When the allocator returns NULL, the resulting owners carry the
unchanged chain and payload and the boolean is false. Both paths use fresh SSA
owner names and preserve the ownership obligations.

`chain.pop` also produces exactly `(chain, buffer, bool)`. A nonempty pop frees
the node, returns its tail and payload, and reports true. An empty pop returns
an empty chain and empty buffer and reports false. Nodes occupy 24 bytes:
payload pointer, payload length and next pointer. Chain SSA values retain the
existing 16-byte descriptor layout, with a zero spare word.

`chain.head_read` and `chain.head_mut` create views tied to the chain root in
the existing root/parent/active capability graph. Shared siblings, exclusive
loans, descendants, CFG renaming, branch joins, loops and consuming calls use
the same static lifetime checks as owned-buffer and borrowed-view operations.
A live head loan prevents moving, popping, pushing, dropping or consuming its
chain. `chain.is_empty` can inspect the chain while a head loan is live. Ordinary
buffer operations and ordinary buffer borrows do not accept a chain value.

Dropping a chain uses one shared machine helper emitted only when needed. It
iteratively frees every payload and node with a fixed local frame. It does not
grow a machine call stack with chain length. Ordinary `calloc` and `free`
imports use the same explicit libc contract as the owned-buffer ELF profile;
the 1 MiB compiler workspace is not a heap for compiled programs.

All normal paths must close every owned root and local loan. Trapping paths
retain the existing semantics: they do not promise automatic resource cleanup.
NULL is a real allocator result in the witnesses, separate from a verifier,
interpreter or native child resource-budget refusal.

## Resource limits and relocation accounting

No source, output, workspace, block, SSA, function, instruction or child-process
limit was increased. Source/output/workspace remain 1 MiB each; SSA identifiers
stop at 2,047; the compiler admits at most 1,536 blocks, 256 blocks per function,
128 functions, 8,192 instructions and 12,000 relative relocations. General
function result arity remains one. The exact chain push/pop instructions admit
three outputs; `buffer.try_new` admits two.

The shared destructor adds exactly two allocator call sites. With at most one
relocation per admitted instruction, two per block and the initial entry, the
derived bound is `1 + 8192 + 2*1536 + 2 = 11267`, below the unchanged 12,000-slot
table. The authoring helper assembles only literal emitter fragments before B0;
the successor HIA compiler performs parsing, checking, native emission,
relocation recording and ELF construction itself.

## Qualification coverage

| Gate | Final outcome | Retained report |
| --- | --- | --- |
| Source checks | 37 / 37 | `chain-v13-source-tests-final-02.log` |
| Main native qualification | 1,127 / 1,127 | `chain-v13-native-final-02.json` |
| Cold replay | 10 / 10; nested native 1,127 / 1,127 | `chain-v13-cold-final-02.json` and its `.cold/qualification.json` |
| Existing scalar/buffer/language qualification | 910 / 910 | `chain-v13-language-final-02.json` |
| Independent fixed-boundary review | 8 / 8 | `chain-v13-independent-review-final.json` |

For each final B3 and M3, the chain suite contains 29 executable positive cases
and 99 refusals. This includes the independently authored 13 positive/75
refusal flow suite, basic dynamic chain cases, and the new parameter regression
matrix. Refusals distinguish invalid general Core from valid Core inputs
outside the bounded compiler profile.

The separately scoped allocator suite runs seven cases for each final compiler.
Each case compares the successor-produced native object with an independent
host direct-backend object and a Core interpreter reference. Six cases select
an actual allocator attempt that returns NULL, including node-allocation retry,
payload retention and the mandatory-allocation trap. The control constructs
and drops a 5,000-node chain. Each native control arm records 10,000 successful
allocations and 10,000 frees, with no live allocations or foreign frees at
return. Counter files retain trap-before-exit observations as well as ordinary
returns. All source snapshots in these runs were unchanged when rechecked.

## Reproduced defect, repair and retained history

The independent reviewer submitted a 304-byte, valid general Core program whose
block parameter was `v8192:chain`. This input is outside the bounded profile
and should be refused. Both pre-fix compilers instead terminated with SIGILL
while leaving the output bytes unchanged. `define` rejected the SSA identifier,
but `parse_params` still recorded it, and `loan_incoming` used the rejected
identifier to address the capability table beyond the 1 MiB workspace.

The repair stops immediately after a failed parameter definition, after function
parameter parsing, and before materializing incoming block capabilities.
The exact original 304 bytes are retained. The independent reviewer confirmed
that both repaired B3 and M3 now return INVALID for that input, for v2048 and
for the largest unsigned 64-bit identifier, while preserving input/output
bytes. Both compilers accept the legal v2047 boundary.

The new committed regression source covers function and block parameters for
`readbuf`, `mutbuf`, `buffer` and `chain` at identifiers 2048, 8192 and UINT64_MAX:
24 valid-Core/profile refusals. Four positive block cases use identifier 2047.
The prior independent 13/75 flow fixtures were kept byte-for-byte unchanged.

The pre-fix 1,071-check main qualification and its successful cold replay are
retained as historical observations. They do not qualify the repaired source
and did not cover this defect. The original SIGILL receipts and the new eight
independent review receipts are separate immutable archives. Earlier independent
allocator runs used pre-fix B3 `233bf7bc...` and M3 `90ca756f...`; the final main
and cold qualifications reran the allocator suite using the repaired images.

## Execution provenance and assumptions

The final main report records these six fields explicitly:

| Claim field | Value |
| --- | --- |
| `python_parser_or_codegen_after_B0` | true |
| `python_parser_or_codegen_in_successor_compilation` | false |
| `host_reference_codegen_after_B0` | true |
| `external_assembler_after_B0` | true |
| `external_assembler_in_successor_compilation` | false |
| `host_native_fixture_compilation_after_B0` | true |

Python/Core references execute after B0 as independent qualification oracles.
A host C compiler and assembler build the allocator witness object. Ordinary
linking binds only the test subject/reference objects to its wrapped allocator
entrypoints. No such host translator or assembler produces successor compiler
generations. The original and changed-source fixed points both rebuild from
their actual HIA inputs, with no source-hash dispatch or embedded successor.

The finite qualification trusts the existing B0 Python assembler, verifier,
direct backend and ELF writer; GNU ld; libc and the system dynamic loader;
the standard-library child launcher; Linux x86-64 hardware; and the documented
caller-owned, live, exclusive buffer contract. Native bounds checks do not
prove external pointer provenance or liveness. The cold replay exports only
sources into fresh directories/processes/home and disables Python site state;
it remains a shared-host replay, not a virtual machine or security sandbox.

`compiler_correctness_formally_proved` and `whole_HIA_language_self_hosted` remain
false. This report makes no economic-benefit claim and does not close unrelated
online deployment, Agent adoption or general machine-proof blockers.

## Evidence handling

`evidence-manifest.json` maps each final and historical artifact to a repository
path, Git blob ID, SHA-256, encoding and local original. The full native, cold
and language archives retain individual inputs, outputs, compiler generations,
Core/direct observations, child requests and receipts, logs and complete JSON
reports. Each archive contains a path/byte-count/SHA-256 index and every archive
member was reread independently after compression. ASCII `.tar.xz.b64` blobs
decode to the exact recorded XZ bytes before extraction.

The original failure ZIP is Git blob
`e55178bd6c2d9722078f9ef6cb2e173d72760dc0`. The fixed-review ZIP is
`173c6fa463a5172d8ae070c753cf02a781333c52`, and its report is
`827dae85433f9d56b35116569ae8f3e10df1f6f0`. None replaces or overwrites the
pre-fix evidence. The source files remain frozen while the integrating checkout
adds its independent changes and reruns source CI on that resulting identity.
