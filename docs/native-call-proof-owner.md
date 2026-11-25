# Native direct-call proof owner checkpoint

The sealed HIA-native direct-call owner is qualified for its private framed ABI. This checkpoint does not close the public call-proof facade or the full native release.

## Actual executable

- Image: 3272019 bytes, SHA-256 4073a3a1092cc33ca724544347d68f0a960e3312455a525e324c65c2fa5ce917.
- The native source compiler compiled the ten embedded HIA roles and HIA packer. The native packer output was byte-for-byte equal to independent mechanical layout.
- Execution used an anonymous sealed captured ELF and empty PATH. Original Python/Z3/Core VM were independent development oracles, never native runtime dependencies.
- The role inventory and exact source/evidence digests are in native-call-proof-owner.json.

## Semantics and limits

The owner freshly admits and canonicalizes both sides before selection, checks both public selections before either closure, checks both closures before exact signature identity, and enforces the original expansion limit after signature comparison. The solver processes actual call closures and fresh bottom-up native summaries. Every SAT witness is replayed through the independent native reference projection and Core VM against the original call bodies.

The existing limits remain 16 functions, 32 blocks, 512 operations, 32 expansions, 32 inputs, 16 returns and a 1–10000 millisecond proof budget. HIAMCP01 has the existing relative budget; HIAMCP02 accepts one caller-owned absolute monotonic deadline. Preparation keeps original admission/profile refusal priority; all summary, search, replay and identity steps use the same deadline. This is not a hard process timeout.

The private owner workspace is 1920 MiB. The solver keeps its existing 512 MiB state, and two bounded summary pools each hold at most 256 MiB. Replay allocates the existing VM stride for all 16 admitted acyclic call frames, inside the dead linker-request area. No VM, compiler or call-profile limit was raised.

## Qualification

| Gate | Actual cases | Result |
| --- | ---: | --- |
| semantics-v2 | 20 | PASS |
| private-api-v1 | 73 | PASS |
| faults-v1 | 188 | PASS |
| general-faults-v1 | 74 | PASS |
| profile-v1 | 35 | PASS |
| summary-faults-v1 | 180 | PASS |

The semantic cases include signed/unsigned arithmetic, tuple and unit results, zero-result traps, 32-parameter and 16-result calls, guarded division, first-trap ordering, repeated callees, nested summaries, and actual normal-return replay at 16 levels and 32 expansions.

The fault gates execute every real native component and inject one malformed component result, a transport failure, deadline exhaustion, identity change, reply/formula corruption, summary/closure/link corruption, or bounded-storage fault. All rejected cases remain unknown with no counterexample or positive proof claim. Controlled clocks establish state-machine behavior, not wall-time performance.

The original admitted-Core profile matrix checks all limit boundaries, recursion, cyclic CFGs, private/missing selections, unqualified schema, resource effects, exact type identity and cross-side refusal order. Already-expired HIAMCP02 preserves prior profile/selection refusals and retains fresh canonical verification for undecided deadline outcomes.

## Preserved failures and next gate

The first author attempt used an unsupported author-language break statement. The second image passed initial cases but returned unknown during normal-return SAT replay: the real VM reported required workspace growth because the owner had reserved only one frame. Version 3 reserves all admitted frames and passed the complete replay matrix. Both failed attempts and the actual debug trace remain external evidence until final custody archival.

Public normalization, typed selectors and exact diagnostic/receipt shaping are still pending. This checkpoint does not authorize activation, deletion of old installations, or claims that the whole repository is native-only.
