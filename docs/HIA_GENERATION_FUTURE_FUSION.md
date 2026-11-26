# Native Runtime and Future fusion

The fixed 62-role capsule exports `hia_generation_lease_owner` and
`hia_background_optimizer_future_public` from one native image. Every Future
Value bridge resolves directly to the same embedded Value body used by the
Runtime owner. The native owner captures and checks the real Value context;
no caller callback or fabricated child context is admitted.

## Native construction

The retained compiler builds every HIA role twice. The new HIAGFUP1 packer
takes 62 logical role lengths in a 512-byte header, performs complete byte
comparison before sharing identical position-independent role bodies, and
emits the existing seven-section ET_REL profile. The native runtime linker
produces the shared image with two fixed exports. The original per-role
4 MiB and total-text 16 MiB bounds remain. The 54-role Runtime and nine-role
Future packer protocols retain their original separate domains.

This qualified build has 55 unique physical bodies, removes 686,499 duplicate
code bytes and contains exactly one 2,630,604-byte df131fc9 Value image.
It has 132 negative fusion-packer controls, with poisoned output unchanged.

## Actual behavior

Fourteen original resource and owner cases pass, including both Future
close orders, concurrent last references, real unlink denial and native
retry, active constructor destruction refusal, typed calls and original
tool custody. Both Future cases assert equal actual native Value code
addresses and equal Value arena addresses. Original behavior assertions
and budgets remain intact; only the QA loader selects the second export
from the same shared object.

The JSON receipt records source and product hashes plus the original
case results. This component does not grant whole Runtime, constructor,
background worker, LLVM path, production activation or old-stack removal.
Final source combinations must be rebuilt and qualified together.
