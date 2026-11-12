# Group 9 code 4: reference-contract reachability

## Conclusion and scope

Under the exact original reference contract, no legitimate public input that completes both required validations reaches code 4. The branch reports a disagreement between two results that the reference algorithm constructs identically except for the primitive schema label. It is a defensive invariant check.

This is a pinned-source derivation, not an executed native proof. The complete native comparator and its diagnostic remain in place. The frozen first-CI delivery `e726ce8964d23aad18e9cfedc728c267824c126a` retains all **22 public cases and 48 private controls**, every original quota, and the complete old/new output comparison. No public code-4 witness has been produced. The private mismatch controls do not count as public coverage.

## Exact subject

The original API is `hepta.hia_core_upgrade.import_legacy_composite_v2`, at reference commit `0ef9541b2fc12f4b01ab5078b05d0b304cfa90f5`. Its final failure text is:

> E_HIA_UPGRADE: nominal adapter changed primitive operations/CFG/effects

The R9 native importer represents this as group 9, code 4. It obtains the comparison from actual role 29 after two separate successful child admissions. The new diagnostic extension only preserves and renders this original terminal; it does not choose the semantic comparison outcome.

The complete source identities, source-line excerpts, legacy-reference census, and actual historical image identities are in `CODE4_SOURCE_FACTS.json`. The reference module is named **hia_core_upgrade.py**. The original comparison author is the R9 build-r3 frozen `38973d1c7971c52c2ffbb9583e709aa2bac700ce`, not the earlier build-r1 `b4669d4d42c970f485a42c5b5dac671846dc7e51`.

## Preconditions

1. The pinned original modules and ordinary built-in JSON/Python value semantics remain unchanged. No monkeypatch, replacement semantic callback, concurrent mutation of private detached data, or forged internal state is part of the public input.
2. The reference argument concerns the constructor, types, function, helper, and outer reference branches. An optional selected implementation must separately satisfy the same semantics and input-ownership contract before the result is extended to that implementation. The existence of an optional selection path is not itself such a proof.
3. The final comparison is reached. This means the raw decode, exact root keys and historical schema check, complete legacy lowering, primitive-v1 validation, renamed-input validation, complete target lowering, and primitive-v6 validation have all succeeded. An earlier language error, allocation failure, limit failure, timeout, or process failure does not supply a code-4 example.

For the native corollary there are two additional premises: the fixed executor must give both fresh children the correct immutable source and return their actual full admitted canonical Core buffers; and all involved native owners, serialization, compilation, and comparison must implement their specified semantics. This analysis does not prove that entire native premise.

## Derivation from the original owner

Let D be the detached, canonicalized original historical nominal document. The explicit importer first checks exactly schema/module/types/functions and the historical nominal-v2 spelling. It then makes a new outer dictionary R and changes only R.schema to composite.v1.

Let L(R) denote successful reference elaboration with legacy=True, and N(R) successful ordinary reference elaboration. The two elaborators start fresh. Their type flags, type layouts, signatures, value-slot counters, generated-name serial, helper cache, function/block/instruction array order, and parameter-loan policy are identical because they use the same composite.v1 source.

The reference initializer has only two legacy-sensitive choices. Its extra schema guard requires composite.v1, which R already has. Its other choice is the nominal-operation set. The exact schema module defines:

- legacy: record.make, record.unpack, record.get, enum.make, enum.tag, and the seven task operations;
- composite.v1: that same set plus record.borrow.

The only later read of self.nominal_operations is the instruction profile guard in _reference_function. The guard is evaluated for every declared instruction in every declared block and function, before lowering its operation. Success has no side effect. Therefore, when L(R) succeeds, no input instruction can take a behavior enabled only by the target's extra record.borrow membership. Both successful runs take the same remaining lowering branches with the same state, generating the same names, flattened values, instructions, attributes, CFG, helpers, effects, and exports. L(R) = N(R) as complete Core values.

The input's detachment matters. _decode returns a fresh strict canonical value. The lowerer's state and emitted containers are private; _reference_lower returns a newly constructed outer dictionary. It may retain read-only references to effects or primitive attributes, but it does not mutate those input containers. Setting old_payload.schema therefore cannot alter R.schema. The old primitive verifier itself decodes a detached copy before its semantic checks. The second decode of R preserves its values and list order; the source was already canonicalized, so it cannot introduce a new dictionary traversal order.

The importer sets the legacy output's schema to primitive v1 and verifies that complete result first. This is an essential restriction: a new primitive operation cannot be smuggled into the historical profile merely by changing the structured schema. A successful primitive verification returns VerifiedProgram(raw), where raw was produced before the semantic checks; it does not transform instructions or resource flow. VerifiedProgram.as_dict only decodes those immutable canonical bytes.

The ordinary target verification elaborates R again and independently admits the complete primitive-v6 Core. Finally the importer decodes the old checked Core, replaces its schema with v6, and compares the complete value against the newly checked Core. Since L(R) and N(R) are equal, this replacement removes their only intentional difference. The original inequality is false.

This is an implication about executions that reach the comparison. It does not require assuming that every legacy input is accepted by the newer validation or every size boundary survives the rename. For example, record.borrow is rejected by the earlier legacy profile check; a v6-only primitive operation is rejected by the earlier primitive-v1 verifier; and a two-byte renamed-input overflow is rejected at its original later byte gate. None reaches code 4.

## Exact native comparison contract

The historical R9 controller performs an old child call, validates its actual complete terminal, and keeps its old Core and digest. Only then does it apply the renamed-byte gate. It next runs the new child, validates that terminal, and invokes role 29 with the complete old and new Core extents. Phase 31 validates the comparison magic, returned size, result range, both actual lengths, and all reserved words before accepting different=1 as code 4.

The original role 29 requires nonempty inputs no larger than 8 MiB and validates the exact suffixes containing primitive v1 and v6. Its output flag is set if complete lengths differ, or any byte differs except the single version digit at length-3. It continues through the complete comparison; this is not a digest-only decision.

For these canonical Core objects the root keys are exports/functions/module/schema, so sorted compact serialization places schema last. The strings ending in v1 and v6 have the same length. Given the reference equality and native custody/refinement premises, every other byte and both lengths are equal, so role 29 returns different=0. The code-4 branch is then unreachable in that native execution.

This does not authorize weakening role 29, substituting a stored digest, skipping either child admission, or treating an arbitrary buffer with a matching header as an issued Core result. Those controls remain necessary to detect implementation defects and state corruption.

## Coverage and failure accounting

The two useful claims remain separate:

- **Reference contract:** code 4 is conditionally unreachable for legitimate public input that completes all earlier checks.
- **Native defensive behavior:** a private mismatch can exercise the real code-4 continuation, full diagnostic bytes, GROW/COPY/PROTECT sequence, terminal binding, and permanent rejection rules. That is private protocol coverage.

If the unchanged actual ELF returns code 4 for a legitimate public input, preserve the complete input, both child receipts, both complete canonical Core buffers, the actual comparison result, and all source/image identities. Such a result is a concrete implementation/refinement/custody counterexample. Do not rewrite the public oracle to accept the fixed enum message or call it an expected public rejection.

The original ordinary verify_program entry does not select this historical importer implicitly: it rejects ambiguous nominal-v2 input with types at its explicit version-collision guard. This proof concerns the separately selected historical importer only.

## Work performed

This review read the complete pinned source bytes and inspected the relevant importer, schema, verification, elaboration, and R9 comparison/controller paths; checked full UTF-8 byte lengths, SHA-256, and Git blob identities in JavaScript; and recorded the exact legacy/nominal-operation occurrence inventory. It did **not** run Python AST, source generation, assembly, B3, VM, native code, or any target qualification. The unchanged pending 22+48 plan is not counted as executed by this document. Whole Worker, ordinary installation, namespace authority, and complete native refinement remain open.
