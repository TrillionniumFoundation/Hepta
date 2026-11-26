# Native Clang artifact admission and independent LLVM recomputation

This checkpoint qualifies two private native image-admission profiles. It does not qualify the public ScalarMultiversionRuntime constructor, complete Clang preparation, public mutation cleanup, or the whole native runtime.

The current production integration target is VI04. It captures the actual artifact before invoking the fixed HIA LLVM emitter, compares that fresh result with the actual producer receipt, inspects the ELF, seals and loads the observed bytes, resolves the requested symbols, and observes their actual mapping. No caller-supplied LLVM digest is accepted by VI04.

## Native entry and ownership

All entries use the six-word ABI `(input, input_n, output, output_n, work, work_n)`. The caller owns the stable work mapping until every actual retirement result has been consumed. The image holder occupies the first 160 MiB. The matching retirement entry uses this exact holder; copying the holder or reconstructing a receipt does not transfer ownership.

| Profile | Image entry | Stable work | Request |
| --- | --- | --- | --- |
| VI03 compatibility | hia_generation_lease_owner_clang_image | at least 160 MiB | HIAMVI03 |
| VI04 independent emission | hia_generation_lease_owner_clang_fresh_image | at least 336 MiB | HIAMVI04 |

VI04 exports `hia_generation_lease_owner_clang_fresh_image_retire`. Its request is the original 24-byte `HIAMVRT1` frame. All inherited retirement status, refusal, retry and unowned-path behavior remains the original native retirement contract.

## VI04 request

The fixed header is 256 bytes, followed by the filesystem path, actual scalar ABI, actual JSON build receipt, and actual canonical Core, in that order.

| Offset | Field |
| --- | --- |
| 0 | HIAMVI04 |
| 8, 16, 24 | Path, ABI and receipt byte lengths |
| 32..63 | Captured Core SHA-256 |
| 64..95 | Captured input SHA-256 |
| 96..127 | Zero; no caller LLVM digest |
| 128..159 | Actual producer artifact SHA-256 |
| 160 | Canonical Core byte length, 1 through 8 MiB |
| 168..255 | Zero |

Existing exact scalar ABI limits, artifact limits, receipt limits, path validation and no-output-write refusal rules are retained. Core text is copied into a HIALLV01 request for the fixed native LLVM component. LLVM work is 192..320 MiB and its emitted bytes occupy 320..336 MiB. These spans do not overlap the original image holder. The implementation does not increase the original compiler budgets, the 4 MiB individual role limit, or the 16 MiB native text limit.

The 512-byte HIAMVIR1 response preserves the original image fields and adds:

| Offset | Field |
| --- | --- |
| 160..191 | Actual independently emitted LLVM SHA-256 |
| 192 | Actual LLVM byte length |
| 200 | 1 only after independent emission and hashing complete |

The comparison covers the original seven receipt fields: Core SHA, input SHA, LLVM IR SHA, actual artifact SHA, actual artifact bytes, x86-64 target, and shared kind. The artifact is opened and captured before Core emission or receipt parsing. New error 25 denotes independent Core emission failure. An absent artifact therefore wins over malformed Core or malformed receipt.

## Mechanical assembly

VI04 has eight fixed roles: image policy, SHA, ELF inventory, mapping observation, JSON capture, retirement, retirement state and LLVM. Native packing and native linking are checked against an independent development byte layout. The LLVM role is the already qualified HIA LLVM capsule, 1,371,977 bytes with SHA-256 9680cd4b85115668c3ce3d6365cfbd8b1bb3f98cb8fc0463f1e526adf28e6875. There is no Python runtime policy callback.

When this image policy is combined with the complete Clang producer, the enclosing static assembly must use the same fixed LLVM code body. The standalone qualification component contains its one required LLVM role. It does not establish that final enclosing assembly.

## Actual qualification

VI03 compatibility passed its original 16 groups, including 17 wire guards. VI04 passed 18 groups, including 22 wire guards, and 23 native packer refusal cases. The normal case uses the real Clang-produced ELF and checks actual native calculate(35) = 42 and wrapping calculate(2**64-1) = 6 against the original VM. The entire fresh IR byte sequence and digest are compared with the original emitter oracle.

VI04 also rejects independently changed, valid Core after hashing and emitting it; rejects a malformed Core only after actual artifact capture; rejects seven receipt mutations and three captured binding mutations; retains original malformed ELF and symlink rules; and performs actual same-holder retirement with descriptor balance. Nine HIA modules were compiled twice with the original 813,129-byte compiler and produced identical outputs. No compiler budget or assertion was relaxed.

A failed development run is preserved: the first changed-Core fixture incorrectly added an unsupported top-level name field and failed in the original verifier before entering that case. The corrected fixture changes an existing valid constant and first independently verifies that its emitted IR differs. A separate initial packer guard setup failed because the development sentinel had the wrong byte count; its preserved output is superseded by the corrected actual native refusal run.

## Clang deadline and cancellation boundary

HIAMVBC1 fields 24 and 32 retain their private enclosing deadline/cancellation facts. The Clang adapter must not introduce polling, early killing, or a shortened Clang limit from these fields. Original discovery probes remain 10 seconds each, compilation 60 seconds, and reaping 3 seconds.

The original public constructor and ordinary publish do not poll a publication token inside _prepare. Conditional publication checks, in order, the current generation/epoch, cancellation, preparation budget, committed token and capacity before admission. After admission/proof it checks cancellation before budget, then enters the complete preparation. After preparation, the selection and token locks protect another current-generation check, cancellation-before-budget check, committed-token check and the actual swap. The new native enclosing GEN and publication wrapper must preserve those checks and their exception priority. The old sealed-tool GX1 deadline/cancellation protocol remains a separate compatibility domain.

## Remaining integration

The public Runtime constructor, real Value parameter validation and exception handoff, GEN custody registration before image retirement, native probes, publication mutation cache pruning, and final single-Value assembly still require their own actual coupled qualification. This checkpoint sets those whole/public flags false. Production dependencies are HIA and mechanical assembly; Python author/oracle hashes are retained only as development provenance.
