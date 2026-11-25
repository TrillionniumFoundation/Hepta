# Native verification process profile without an invented deadline

The fixed captured process owner now accepts an independent HIAMVPS2 profile for the two actual verification roles: 1 (hia-admit-agent-json) and 4 (hia-verify-core-json). Word 24 must be zero. This preserves the original verify_program behavior, which has no explicit verification deadline. The process still uses real monotonic observations, bounded polling, owned sealed executable/input/output descriptors, direct-child reaping, and the existing cleanup paths.

HIAMVPS1 retains its complete original request and rejection domain, including its nonzero absolute deadline and all four roles. A zero deadline remains invalid under profile 1. Profile 2 rejects roles 0, 2, 3, and 5, and rejects any nonzero deadline. All other request fields and reserved-byte checks are unchanged. This private profile does not add a caller-selectable program, shell, executable path, or verification claim.

The native bridge is unchanged (266 bytes, no undefined imports). The new HIA policy was compiled twice by the captured native source compiler; actual native HIA packing and shared linking were repeated with byte-identical products.

## Qualification

The new product passed all 57 original process behaviors, including the actual normalizer, actual native scalar proof engine, and the fresh P3 native shared-object builder. It also passed 52 original private/descriptor controls and all 36 actual syscall fault/short-write controls. Those controls use ptrace at the unchanged adapter syscall instruction, preserve real short-write bytes, and verify child reaping.

Fourteen new-profile cases passed. Both verification roles completed a real 150 ms child under profile 2 while the equivalent profile-1 10 ms deadline expired. Invalid role/deadline combinations remained atomic refusals. Actual cancellation and ownership cleanup remained effective. The final evidence includes the actual image and every complete report.

This closes the process transport extension. It is a dependency of the separate complete verify_program owner; the transport itself makes no semantic source-verification claim.
