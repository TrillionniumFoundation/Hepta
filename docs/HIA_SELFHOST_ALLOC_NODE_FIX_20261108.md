# Selfhost-Core v13: optional allocation-effect node accounting

The final source passed **37 source checks, 1,131 native qualification checks,
910 language checks, and 10 cold-replay checks**. The cold replay rebuilt the
compiler from its exported source and independently repeated all 1,131 native
checks. These results apply to the source and machine identities below. They
do not transfer an earlier v13 qualification to a later integrated commit.

This is a narrow correction to the existing v13 structural-node budget. It
does not add input-language features or close general Core self-hosting.

## Reproduced defect

The native header parser charged a function for its three mandatory effect
strings, but did not charge the optional fourth `alloc` effect. Canonical Core
counts that string as one structural node. A function may declare an unused
`alloc` effect, so this discrepancy does not require a runtime allocation.

Starting from the existing exact-limit fixture, adding `alloc` to the entry
header changes its canonical tree from 262,144 to 262,145 nodes. The general
Core checker rejects the resulting tree. The pre-fix native compiler instead
recorded 262,144 nodes and reached output-capacity preflight. With the retained
32-byte output buffer, it returned `NO_SPACE` (`4294967294`) with parser error
zero, instead of the required `INVALID` (`4294967295`). Source and output bytes
remained unchanged. This observation establishes incorrect node accounting and
refusal classification; it does not show an over-budget executable being
produced.

The original failing source is retained byte for byte, with SHA-256
`edb85695e21bedd6a1a74cd338ecd9a3f670d9f9401099f888bf01b25d76e7f2`.
It is exactly the new `allocating=True, over=True` regression input.

Two pre-fix executions were recorded against each of two image pairs:

| Pair | B3 SHA-256 | M3 SHA-256 | Recorded result |
| --- | --- | --- | --- |
| Earlier v13, before the parameter-boundary correction | `233bf7bcdde5102beba1791c2922f1b8a994c0ccb3a2e83f2bcbc9bb0c802a1e` | `90ca756f9697b5e37514377ce5e7436f18e6be24846002a6f24acc79583a39cb` | Both miscounted the same input and returned `NO_SPACE` |
| Parameter-corrected v13, source `d57f0350…` | `d20dbc1426ffaf0369a24b884ff30e0ae675b8ea24ea130a361abafeee9fbdaa` | `a692195b44655cc4850065e527330a3594762143af38eb94bb0fa8c64fb05a34` | Both independently reproduced the same discrepancy |

The first directory name was initially mistaken for the latest image pair in
the discussion. Its receipts always contained the actual earlier hashes. An
independent review caught the attribution error; the second reproduction
checked the latest image bytes against their expected hashes before execution.
Both original records are retained without rewriting the first observation.

## Minimal change and boundary controls

The executable change is one call in `parse_function`:
`account_nodes(w, 1)` immediately after recognizing the optional `alloc`
effect. Every parse pass resets its structural count to four before processing
the source. The added charge is therefore once per declared effect per pass,
including CFG replay, rather than an accumulating charge across passes.

The fixture renderer now renders the document's actual effect list. Its new
allocation-effect variants have exact canonical node counts:

| Input | Construction | Fixed B3 and M3 |
| --- | --- | --- |
| 262,144 nodes with `alloc` | Add the effect and replace one unused two-operand addition with a constant, reducing the tree by one node | Reach capacity preflight; `NO_SPACE`, error 0, recorded count 262,144 |
| 262,145 nodes with `alloc` | Add only the effect to the original exact-limit fixture | Refuse during semantic parsing; `INVALID`, error 58, recorded count 262,145 |

Both variants retain the same fixed 32-byte output capacity and nonzero initial
workspace. Every observation checks unchanged source and output bytes. The
existing non-allocating exact/over-limit cases remain in the suite. Independent
recursive counting and structural comparison confirmed the four node counts
and the precise one-node changes.

Two existing test methods were extended with these observations; their method
inventory was not increased. The main native qualification gains four checks:
the two new cases through both the original and mutated compilers. Existing
loan selection still uses the exact `original-loan-` / `modified-loan-` prefixes
and requires 142 successful loan checks.

The public `f0(readbuf, mutbuf, mutbuf) -> u32` ABI and all input/output,
workspace, operation, block, function, SSA and relocation limits remain the
same. The compiler has 85 functions, 1,503 blocks and 5,774 operations. The
previous 5,772-operation source gains a literal and the accounting call.

## Final identities and qualification

The implementation was copied from the integrated source associated with
commit `50c1578b4d4597e3070a9abc3700c9aacbf99851`, tree
`87b106d1e76337e02bda5e7a9132c4854c601b00`. Exact file digests, rather than a
synthetic local Git HEAD, identify the independent qualification directory.

| Subject | Exact identity |
| --- | --- |
| Final compiler source, 439,790 bytes | `6e9b171db3b078919e3a37c40e3b097136ac3221f0e19b872da42eb765193de1` |
| Mutated compiler source | `ca8173dfad0748b45a4ba92542fbc16233e88b584064d1decf1f3b53a01a2af0` |
| B1 = B2 = B3, 717,337 bytes each | `0c15464be69d656d825a654e45e1929fd583de7aa92ce88aba4822932462b26a` |
| M1 | `0fb12742e05c18b0e899a0eed5eebcffa24f6602a5611d1beda01084622c5005` |
| M2 = M3 | `03898791a30b8f1c2fdd059291142bf1bb49a824d3b80befab81f850452af4f5` |

The cold source export contains the same 249-file qualification closure,
including the support contract. Its fresh B0, original generations and
mutated generations reproduce the final main-run identities. The language
qualification also binds the same source closure. The cold boundary is
source/process/cache isolation on the same host, not a separate virtual
machine or an independent hardware implementation.

| Final check | Result |
| --- | --- |
| Existing source, contract, language-source, owned-flow and chain test methods | 37 / 37 |
| Complete original/mutated native qualification | 1,131 / 1,131 |
| Source-only cold replay | 10 / 10, with a fresh complete 1,131 / 1,131 nested qualification |
| Language qualification | 910 / 910 |
| Existing capacity, loan-prefix and provenance assertions replayed over the retained final native report | 3 / 3; no additional native compilation or execution |

The language run retains 66 positive programs and 250 refusals per compiler,
824 scalar witnesses, and 136 trap cases per compiler. The complete native
qualification also repeats the existing owned/chain and allocator-null
observations; their scope is unchanged by this correction.

An earlier development run passed its 1,131 native checks while the source
suite held at 36/37 because two language-inventory identity fields still named
the pre-fix generator and assembly. The inventory and support contract were
regenerated, the complete source suite rerun, and the final native, cold and
language qualifications run again against the resulting frozen closure. That
development source snapshot, failure log and native records are retained
separately. They are not substituted for final qualification.

## Evidence and scope

The evidence manifest under
`review-evidence/hia-selfhost-alloc-node-fix-20261108-5e6c/` identifies both
pre-fix failure archives, the development archive, all three final qualification
archives, independent static-review records and the final summary. Each raw
archive retains source/input bytes, machine bytes, requests, receipts,
stdout/stderr and a per-file SHA-256 index. Every indexed file was read back
from its archive and independently checked before expanded scratch copies were
released. Historical v13 `d57f0350…` / 1,127-check evidence remains historical.

The result is **PASS for this accounting correction within
`selfhost-core-linux-x86_64-v13`**. Its property is observed structural-budget
enforcement at the retained boundaries, plus the specified native, language and
source-only replay regressions. The subject is the exact source and images in
the table, and checker/harness identities are bound by the source manifests.

The observations assume the existing borrowed-buffer caller contract, Linux
SysV AMD64 execution, ordinary libc allocation/linkage, and the identified
Python seed/reference tools, native runner, kernel and hardware. Host reference
code generation, ordinary linking and the allocator-witness C compilation are
still used after B0 during qualification. Successor compilation itself uses
the preceding HIA-generated image and no Python parser/code generator or
external assembler. All six explicit provenance fields remain in the native
report; no global claim that all post-B0 qualification is host-tool-free is
made.

This does not establish a general compiler-correctness theorem, full ISA/ABI
refinement or complete Core self-hosting. General multiple-result calls and
returns, returned resources/parameter loans and the other declared v13 gaps
remain outside its implemented profile. The separate v14 CFG work is paused
and is not part of this fix or its qualification.
