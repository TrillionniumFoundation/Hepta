# MV strict admission through the live runtime

This component adds an explicit strict constructor profile. It does not mark the complete public multiversion API or the final release as qualified.

## Input and lifetime

The generation initializer `HIAMVGX2` uses the original 128-byte generation frame. It is accepted only for operation 0; byte offset 48 must be zero, and offset 120 carries the integer conversion policy captured by the containing runtime: zero, or 640 through 2147483647. Its normalizer calls use the qualified `HIAMVNQ2` / `HIAMVPS2` path. Raw verification runs before normalization, including the original UTF-8, byte, structural, integer-conversion and historical v2/types checks. Normalization has the original unbounded wait semantics. Per-export proof and build budgets are unchanged.

The effects constructor `HIAMVEX5` uses the original 256-byte frame and is accepted only for operation 0. Offset 240 carries the captured integer policy; offset 248 remains zero. The runtime retains this policy in its own state and applies it to every later preparation. Later publication requests do not supply or replace it. Existing EX1, EX2, EX3 and EX4 profiles retain their previous validation.

The strong handle owner accepts EX5 in the existing constructor payload. The provider adds `HIAMVBC2` solely for its create operation with an EX5 payload; BC1 still requires EX3. The public `HIAMVBQ1` snapshot/publication/retain/drop/reply protocol is unchanged. A final typed factory must validate real option values and run the whole verify_program owner before constructing this internal frame. The private raw 8 MiB bound is not a substitute for that public factory.

## Native construction

All four policies and their packers were compiled from the captured HIA sources with sealed compiler SHA256 `494833999e25ac74ea6ad1de41235c01bfa036951f212604026cb8be686c78af`. The HIA packers produced actual relocatable objects; the closed HIA linker produced the loaded shared objects. No target result was used as an expected semantic result.

| Composition | Private pack request | Roles |
| --- | --- | ---: |
| Generation | HIAMVGK2 | 31 |
| Effects | HIAMVEK3 | 49 |
| Strong handles | HIAMVHK3 | 50 |
| BG provider | HIAMVBK2 | 52 |

The four role vectors add the shared raw verifier to the strict admission component. Their actual order, source and image hashes are in the qualification JSON. Whole image and individual role bounds remain unchanged. The previous private pack formats are not relabeled as accepting a different vector.

## Actual qualification

The same four newly built images passed 301 recorded groups and private pack checks:

- 27 generation groups, including all 16547 original probe vectors and actual proof, build, load and execution.
- 137 strict generation checks: 122 fresh original raw admission/profile pairs and 15 private guards.
- 17 complete original runtime snapshot comparisons through the legacy constructor and another 17 through EX5; 47 actual effect calls in each arm, with actual artifact, seal and mapping checks.
- 7 strong-handle lifecycle groups with 24 actual calls.
- 8 provider groups with 18 actual calls through BC1 and the same 8 groups with 18 calls through BC2. Both use real constructor, publication, token cancellation, retained replies and final resource release.
- 12 new/old profile separation and captured-policy guards.
- 17 private/short-output checks for each of the four native packers.

Time, allocated addresses, kernel inode identities and compiled artifact identity can differ between actual original/native arms. The comparison only normalizes those independently rechecked observations; it retains all state, counts, ordering, errors and optional field shapes.

The first strict generation test attempt reached its assertions and then hit a Python fixture buffer-export error on fixture disposal. The separate v2 fixture releases its own exported view before closing the mapping. That failed attempt remains in external evidence; the completed v2 run supplies the 137 passing checks.

## Remaining public integration

This checkpoint does not claim complete original exception propagation. The provider still distinguishes original mapped errors, allocation failure, and unresolved dependency errors. A committed token/selection is authoritative even when later report construction fails. Full original diagnostic/errno/loader exception transport and the final typed public program factory remain separate work. It does not authorize cleanup, activation, or transfer of a frozen cold report to a changed source tree.
