# Native GenerationLease lifecycle and snapshot ABI repair

The independently executable HIA lifecycle facet now performs `GenerationLease.__enter__`, `close`, `__exit__`, copy refusal, deepcopy refusal, and owned-reference retention/release through the actual multiversion carrier. The request contains an operation and a registered capability. A caller cannot supply an open/closed Boolean, a function entry, a runtime address, or a proof result in the request.

This is a qualified component for the enclosing public runtime owner. It does not claim that the complete `ScalarMultiversionRuntime` constructor and methods, typed `GenerationInfo` owner, or typed `GenerationLease.call` have been composed. `whole_native_runtime`, `whole_public_api_equivalence`, and `final_aggregate_claimed` remain false. The source-bound enclosing constructor still needs to own and capture the carrier context for this facet. The qualification program is external development tooling and is not a product dependency.

## Native artifacts and source binding

The native compiler is the self-contained `hia-source-build` image with SHA256 `494833999e25ac74ea6ad1de41235c01bfa036951f212604026cb8be686c78af`. Every one of the 50 source modules used by the qualification driver was compiled twice; corresponding outputs were identical. The 49-role carrier was built by the HIA handles packer and HIA runtime linker. No Rust, LLVM, clang, or C policy implementation is used in that construction.

The lifecycle product is 39,884 bytes, SHA256 `c1e1cb7be1b071f2a55a17881aac3a030c9fad988a0e0628233c06482ccbf970`, and has no dynamic imports. It consists of a fixed 304-byte mechanical prefix and one actual compiled HIA policy. Its policy is 39,580 bytes, SHA256 `eab5b7d2e6ceb1ef6be97826812db06be8d119241913539349097185a44a55dc`. The readable prefix is in `tools/hia_generation_lease_public_lifecycle_bridge.S`; independently assembling that file reproduces the packer's prefix exactly and produces no relocations.

The enclosing carrier used in this qualification is 8,520,464 bytes, SHA256 `f2a3e9c9d774bf00f58b119478349f0162b29f389b73c0b04cbf3062bd6ab5cc`. It retains the existing `libc.so.6` mechanical dependency. Its ordered 49-role source paths, flat pins, native object pin, and ELF pin are recorded in the JSON ledger. Three explicit public-runtime roles add the lease-admission protocol; the old handles, effects, and state source files remain unchanged, preserving their use by other products, including PublicationCancellation.

| New or corrected HIA role | Flat bytes | Flat SHA256 |
| --- | ---: | --- |
| `multiversion_runtime_public_handles` | 192,215 | `05cd996f29a76a19fb79daa2f5aeb3f6d6819a12fb8f8a373e270a0cfa82d3dd` |
| `multiversion_runtime_public_effects` | 561,063 | `961173b8b1910bd1c26e600cdb7da98a052c3bc6c2cff0d4174fb19474a75c6c` |
| `multiversion_runtime_public_state` | 210,263 | `64f07cb504dea039e346cb5b1f333bb1d9541bbd53640e136046bee9c71b0221` |
| `multiversion_runtime_snapshot_capture` | 303,926 | `3c8d4e621b1dc8f1d282dc3ce40c1d9b696f6afc947198be5645181c7d9e7c41` |
| `generation_lease_public_lifecycle` | 39,580 | `eab5b7d2e6ceb1ef6be97826812db06be8d119241913539349097185a44a55dc` |
| `generation_lease_public_lifecycle_packer` | 15,071 | `245de4be764db86c3b6aa69d43f8b659c68ccd8b04667a29dff53ea2048c901b` |

## Six-word native entry and captured context

`hia_generation_lease_lifecycle(source, source_bytes, output, output_bytes, context, context_bytes)` keeps the existing six-word calling convention. The output requires 100,679,680 bytes: 16 KiB of facet continuation plus the existing 96 MiB carrier output extent. The mechanical prefix rejects null, short, wrapping, overlapping, or unaligned context views before writing. HIA validates the frame and captured context, obtains the real process identity, and performs actual capability lookup before a method can act.

The read-only 128-byte `HIAGLC01` context is created and kept alive by the source-bound enclosing owner. It contains the actual carrier entry at offset 8, the strongly owned carrier context at 16, its extent at 24, and the creator process identity at 32. The remaining bytes are zero. These fields are private captured dependencies; they are not fields in a public request and are not a substitute for the enclosing constructor. A forked process is rejected before the carrier call.

The exact 64-byte request is `HIAGLQ01`, followed by the operation at offset 8 and the real registered capability's three words at offsets 16, 24, and 32. Offsets 40 through 63 are zero.

| Operation | Public meaning | Successful result |
| ---: | --- | --- |
| 0 | `__enter__()` | Same lease capability, with no extra owning reference |
| 1 | `close()` | None; repeated close succeeds |
| 2 | `__exit__(*unused)` | None; forwards the actual close operation |
| 3 | `__copy__()` | The original `MultiversionRejected` exception |
| 4 | `__deepcopy__(memo)` | The same original copy exception; memo is not inspected |
| 5 | Internal owning-reference retention | A fresh reference capability to the same lease |
| 6 | Internal owning-reference release | None; the final reference runs the real finalizer |

This component is an instance-method boundary. Public language-level argument binding and the other methods remain the responsibility of the enclosing typed owner. In particular, the unused exit arguments and deepcopy memo are not converted into an invented wire value.

The 128-byte result header is `HIAGLR01`. Status is at offset 8; result kind is at 16; a result capability occupies 24, 32, and 40; the original error code is at 48; error JSON length is at 56; the actual child status, process identity, retained-owner flag, and finalizer status occupy 64, 72, 80, and 88. Error JSON begins at 128. Kinds are 0 for None, 1 for the same self capability, and 2 for a fresh owning reference. Status 0 is success; 1 is a rejected capability or wrong owner kind; 2 is allocation failure; 3 is lifecycle/process rejection; 4 is an original public exception; 5 is dependency failure.

The original exception strings are preserved:

- `E_HIA_MULTIVERSION: generation lease is closed`
- `E_HIA_MULTIVERSION: leases have one close owner; acquire another lease instead of copying`

## Independent private require-open protocol

The original lease-info operation remains valid after the lease closes. It therefore cannot implement `__enter__` or the closed-state check required by `call`. The public-runtime roles introduce the independent private magic `HIAMVLA1`, rather than assigning new meaning to an old reserved field.

The new inner frame is exactly 256 bytes with operation 0. The handles layer admits it only for a real registered lease, kind 2, and only when bytes 16 through 255 are initially zero. It pins that actual lease and injects its private identity before calling the effects role. Effects verifies the fixed frame and routes the request to the independent `HIAMVC03` coordinator operation 12. The coordinator performs the actual lease lookup, takes its existing mutex, asks the real retention owner to require open, and releases the mutex without calling a scalar function or allocating an information snapshot. It neither receives nor trusts a caller's open-state flag.

The old EX3 info flag at inner offset 120 remains rejected when nonzero by the complete carrier. The native effects parser alone had a broader domain, but the old handles admission already required this lease field to be zero. Qualification tests this refusal explicitly, as well as successful closed-lease info with the zero field. The original magic and its rejected byte domain are not widened.

A later typed-call composition must perform the original function and argument checks while the same lease mutex remains held. Calling this standalone require-open operation and then validating arguments outside the mutex does not establish that method's original atomic semantics. This qualification makes no typed-call equivalence claim.

## Snapshot return-ABI defect found by real finalization

Rebuilding the exact `ecd688626409d1adcf4e04a7a535c1b2c45a13ce` roles and executing a real constructor, lease, close, info, reference release, and runtime close exposed a pre-existing defect. The native generation was retired and its directory removed, but the runtime returned status 35 and retained its owner with finalizer status 5. Retrying cleanup did not resolve it.

The current snapshot renderer uses a u32 result: a size query returns `0xfffffffe`, successful rendering returns 0, and the required extent is stored in its owned workspace at offset 0. The snapshot capture continuation still compared the query result with the u64 value `0xfffffffffffffffe` and compared successful rendering with the output length. A real successful query reported 1,330 required bytes with no renderer error and was nevertheless converted into error 9. The old published composition ledger referred to a different renderer image with the older return convention.

The two corrected call sites in `generate_hia_multiversion_runtime_snapshot_capture.py` now require:

- Query: actual return `0xfffffffe`, nonzero owned workspace length, and no workspace error.
- Rendering: actual return 0, owned workspace length equal to the allocated extent, and no workspace error.

Only then can the capture publish its detached snapshot or cleanup-history entry. On refusal it follows the existing owned cleanup path. The complete new HIA capture source is generated from the corrected authoring source. The exact old source is reconstituted only as an isolated diagnostic during qualification; it is not retained as an alternative product.

Seven native private-continuation negative controls cover the old u64 query result, success without size negotiation, zero required extent, query error, the old success-as-length convention, changed successful extent, and successful return with a recorded renderer error. Every case goes to owned cleanup and publishes neither a snapshot nor history. The actual old-carrier failure remains recorded in the ledger. The fixed carrier then passes the same full finalization path.

## Actual qualification

`tools/qualify_hia_generation_lease_public_lifecycle.py` runs the real normalizer, proof engine, native builder, seal/load path, finite native probes, and scalar call. Their bytes are placed in actual sealed memfds; requests contain SHA256 values computed from those same owned images. They are not supplied proof acknowledgements. The executable pins used by this run are recorded in the JSON ledger.

The complete run passed:

- 50 source modules compiled twice with identical outputs, native carrier packing/linking, and exact mechanical-prefix verification.
- 18 malformed packer requests refused without writing output.
- 10 comparisons with the unchanged original `GenerationLease` class's reference-retention branch, including repeated close and exact exception class/message. Native retention and resource lifetime are tested independently in the same run.
- 383 native public lifecycle calls, 72 main carrier calls, and 8 additional carrier calls for the runtime-before-last-lease sequence.
- 42 forged or wrong-kind calls and 7 foreign-context calls rejected through real registry lookup.
- 16 invalid view guards, 6 malformed public frames, 9 malformed private reserved fields, and the private protocol applied to a runtime capability, all refused.
- Eight threads using retained references, with 192 actual require-open calls spanning both open and closed observations.
- Twelve concurrent drops of one reference, with exactly one successful drop and eleven refusals.
- Forty-eight final-drop/pin races, observing 24 successful enters and 24 safe stale-capability refusals in this run.
- Fork refusal followed by continued parent usability.
- Closed info and a detached snapshot remaining valid after all runtime/lease finalizers complete.
- Both runtime/lease shutdown orders, with no remaining registered references, objects, or retained finalizers; unchanged open-descriptor sets; and empty artifact parents.

The normalizer/proof/builder arguments select actual owned executable files. Rebuild and rerun from a checkout containing the referenced source roles:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. python tools/qualify_hia_generation_lease_public_lifecycle.py \
  --compiler /absolute/path/to/hia-source-build \
  --normalizer /absolute/path/to/hia-normalizer \
  --proof /absolute/path/to/hia-native-scalar-proof \
  --builder /absolute/path/to/hia-build-object \
  --output /absolute/path/to/new-qualification-directory
```

The output directory must be new. The driver verifies the compiler pin and records every input source and flat pin, both carrier builds, executable image pins, baseline failure, original-class comparisons, negative controls, native calls, finalizer state, and limits of the claim in `qualification.json`. Its committed record is `docs/HIA_GENERATION_LEASE_PUBLIC_LIFECYCLE.json`.

## Native packing and integration requirements

The lifecycle packer consumes exact `HIAGLPK1`: a 64-byte header with count 1 at offset 8, policy length at 16, and zeros at 24 through 63, followed immediately by that compiled policy. The policy is nonempty and at most 4 MiB. The native packer patches its sole relative call displacement at offset 201, then appends the policy; it introduces no dynamically selected role.

The carrier keeps `HIAMVHK2` and its ordered 49 roles. For this public-runtime construction, the original handles/effects/state positions are filled with the three explicit public-runtime sources listed above, and the snapshot-capture position uses the corrected existing source. All other role positions use the current original source paths. The complete ordered list is in the ledger and driver.

The enclosing owner must create and own the captured carrier/context, bind this exact product to the public method dispatch, and retain that context through every invocation. Source authority and release product registration are handled by the final assembly owner; this document does not assert that the complete enclosing owner has already been registered. Existing PublicationCancellation files and pins are unchanged.
