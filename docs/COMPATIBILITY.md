# Version and backend compatibility policy — 0.2 prototype

Hepta 0.2.0 is a research prototype. The version identifies a tested source
snapshot, not a stable language or library ABI promise. A change to syntax,
types, effects, linear-resource rules, lowering or observable runtime behavior
requires updated specifications and positive/negative conformance evidence.
The existing frontend/Rust path remains the reference executable path for the
implemented subset. Every additional backend reports its actual supported
profile; unsupported constructs reject before claiming native success.

The independent C11/GCC path currently targets the documented 64-bit host
profile. It uses GCC optimization and debug tooling as external dependencies;
it is independent of rustc, not independent of every compiler backend. Source
mapping, source-level debug information, full language parity and an independent
machine-code optimizer remain open. Generated C can be retained for inspection.

Only explicitly declared supported C-ABI values use C boundary layout/calling
conventions. Internal layouts, mangled module names, runtime structures and
compiler JSON implementation details outside named schemas are not stable ABI.
C import probes are tied to their measured host and source metadata. Object
compilation, emulated execution and physical-host C qualification are separate
claims.

`hepta.patch.v1` remains usable for single-source edits without imports.
`hepta.patch.v2` binds a loaded project and one target body. They use the same
cooperative source locks. Unknown request keys and stale identities reject;
there is no silent upgrade that weakens a caller's requested contract. The
protocol deliberately does not establish functional equivalence. Package lock
files must be refreshed explicitly after approved source changes.

The checked-in toolchain locks and release evidence identify supported tools.
Dependency lock hashes provide reproducible source identity, not signed package
authenticity. Remote registries, dependency resolution across version ranges,
signed release distribution and automated language migration are not present.
No released 1.0 compatibility policy is claimed by this prototype.
