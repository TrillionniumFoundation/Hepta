# HIA native local instruction policy

The explicit `HEPTA_HIA_INSTRUCTION_POLICY_MANIFEST` candidate implements the
complete primitive local instruction contract, not the compiler's smaller
accepted instruction subset. All 50 catalog instructions, v1–v8 availability,
exact attribute inventories, operand/result arities and same-type/group rules,
exact-width integer/bool/unit literals and checked-cast effects execute in HIA.
Borrow operand-type failures retain their loan classification; wrong arities
remain type failures. Call callee interfaces are deliberately not decided here.

The input is a generic exact-kind, little-endian length-delimited value tree:
each value has `u64 tag`, `u64 payload_bytes`, payload. Tags are null=0, bool=1,
integer decimal=2, float text=3, UTF-8 string=4, array=5, dictionary=6, other=7.
Arrays/dictionaries start with a `u64` element/pair count. The root array is
`[schema, opcode, operand_types, result_types, attributes]`. Native code validates
the entire transport before policy, with checked extents and a bounded explicit
stack. Floats never become integers, booleans never become integers, and a host
integer subclass never becomes an exact integer. Integer bounds are checked
digit by digit without u64 overflow. Host code transmits values, allocates
buffers, selects pinned images and materializes the returned four-effect mask;
it does not precompute the policy decision.

The transport accepts up to 32 MiB, 1,048,576 nodes, depth 128: these are not a
smaller replacement for the complete Core 8 MiB/262,144-node/depth-64 profile.
Full call argument and attribute payload witnesses exceed the native compiler's
16-argument profile; this candidate does not impose that compiler restriction.
Both mutable buffers are private scratch and do not contain a published result.

The strict builder binds the entire current cold-source manifest, profile,
compiler and image; a different cold source is refused before output creation.
Selected missing, malformed or rejecting manifests never call the old checker.
The old opcode checker remains the unchanged unselected default and test oracle.

**Not closed:** SSA liveness, guard/loan/owner transitions, callee contracts,
typed CFG transfers/exact joins/return cleanup, composite normalization, generic
Core verification, host transport/build/install/runtime and Agent persistence.
Reading catalog guard metadata after native local admission is still host work.
This is neither an all-input refinement proof nor native-only production.

The selector is unselected only when its environment variable is absent. An explicitly present empty value is rejected before image loading or entry into the hosted reference. Remove the variable to use the unselected reference path; an empty assignment does not disable selection.
