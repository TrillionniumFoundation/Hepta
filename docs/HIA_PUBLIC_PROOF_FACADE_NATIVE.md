# Unified native public proof owner

This checkpoint qualifies the actual unified executable for primitive scalar proofs, scalar-call proofs and bounded unrolling. It is independent of production activation: the canonical entry and the complete new NDU/background/multiversion composition are not activated by this checkpoint.

The same HIA owner performs typed value admission, original-priority program normalization and function selection, fresh native proof execution, result binding, process cleanup and receipt handling. Its mechanical adapter moves bounded buffers, invokes the fixed embedded HIA roles and performs the syscalls selected by HIA. It contains no Python or Rust proof implementation.

The current image contains 16 payloads and five borrowed primitive roles. All inputs and the native packer were captured and pinned before packaging; an independent mechanical ELF-layout construction matched the actual HIA packer's complete bytes. The complete image remains within its original 16 MiB bound, and child images retain the original 8 MiB bound. Neither compiler caps nor proof and transport deadlines were widened.

## Public and typed qualification

The exact image recorded in the companion JSON passed 130 typed public cases (134 actual parent invocations), 113 primitive semantic cases, 20 call semantic cases, 60 call-profile cases, 337 normalization cases and nine cancellation/signal cases. Typed tests include the original timeout types and field locations, exact retained input types, original left-to-right admission priority for unhashable function selectors, fresh verification of claimed receipts, 1,048,577-, 16,777,217- and 67,108,864-byte claimed receipts, wrong-binding refusal and a 16 MiB function string retained in both public fields.

A genuine call-selection mismatch was fixed by checking the freshly verified first program's actual original schema before reproducing the original set-membership TypeError. The parser walks structure and string escapes; it does not infer the schema from an unrelated normalizer header flag or search arbitrary raw substrings.

A separate genuine large-receipt failure was fixed by passing the untrusted claimed receipt only to receipt-selection and fresh-verification steps. The step that constructs a fresh proof receipt no longer receives an unrelated old receipt. The later claimed-receipt validation remains mandatory. Earlier failed evidence remains distinct from the final successful run.

## Bounded workflow

The same final executable passed all 85 public bounded cases and the original 53,749-parameter concentrated case. The latter preserved the original E_HIA_LIMIT refusal before encoding an oversized generated program; the public Core budget remains 8 MiB. This uses the qualified semantic Core cursor fix and retains all original admission and resource-flow decisions.

Positive native proof reasons and identities are compared to the same executable's raw native entry. The qualification does not label the HIA solver as Z3 or fabricate the identity of a removed artifact. The independent original implementation remains an external test oracle only.

The companion JSON binds the precise image, source changes, payload inventory, native call-receipt component and every current qualification report. These are evidence for this proof owner; subsequent complete production composition requires fresh matching installation, tool, actual-agent and cleanup/rebuild gates.
