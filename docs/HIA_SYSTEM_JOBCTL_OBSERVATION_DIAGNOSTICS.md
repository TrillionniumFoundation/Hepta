# Native Jobctl observation diagnostics

STATUS, READ and CANCEL preserve the original error ordering, syscall errors,
typed serde errors and raw UTF-8 lossy stderr. The original decoded JSON success
responses are compared as Values; stderr is compared byte for byte.

The observation owner retains pending-vs-terminal and second-observation rules.
Its recoverable I/O state records the original error before cleanup. Typed
Record, Exit and retained-Value failure spans call the shared action 26 facet
with the whole original raw JSON and original reader mode, preserving first
error and line/column semantics. No malformed terminal becomes terminal proof.

The shared diagnostic renderer uses phases 2060 through 2069. Streamed systemctl
stderr has no trim or smaller capture budget; 64 KiB chunks retain incomplete
UTF-8 suffixes across reads. The renderer owns and closes the transferred fd.
Root entry releases the registry flock and closes its fd before first stdout
or stderr publication. Observation stdout resumes at phase 684 through shared
2080 through 2082. Internal PTY cancellation suboperation 3 keeps its own original
cleanup and produces no public diagnostic.

## Qualification

The frozen original runtime Jobctl SHA256 is
`7bf17e04c22270fa5182df6aeda7fc9b524202ba3405f20519f48b91141308c9`.
The native 21-component image is 4,148,631 bytes, SHA256
`26af3b80677fdb5bae4997dc14add6282f9fde7fe48aba1f0d09cb603a02ebb7`.
It uses the unchanged four-MiB package limit and v95 source seed
`494833999e25ac74ea6ad1de41235c01bfa036951f212604026cb8be686c78af`.

All 80 native packer controls and all 261 original observation cases pass,
including exact stderr SHA comparison. The additional 48 streaming cases
compare complete raw bytes, including malformed UTF-8 across chunk boundaries
and 64 MiB plus one byte. Five blocked-output cases use a filled pipe and a
/proc syscall witness before a second process tests flock. Original and current
native release the lock; the retained old native image holds it as a negative
control. The 15-process test preserves responses and stderr after draining.

Evidence root:
`cleanup-audit-20261124T0745Z/system-jobctl-observation-diagnostics-v5/`.

| Evidence | SHA256 |
| --- | --- |
| observation-exact/qualification.json | ba6e17e9d7c31c3d663111ac6e850a37eef07e25a1a528c47a32f77fc964b0dc |
| stream-stderr/qualification.json | 5733c795c8da3bcd858ae69563043dd3bdf1cf7b76597d9a820d6bd48a25e29a |
| stream-stderr/exact-byte-verification.json | 2cbe5074901e4b21c90e723a6a2465cc6b02047cc077286e20281e12abe97c44 |
| lock-publication-v2/qualification.json | cfe288b5107ad594268a85f20e271094f39b98dae30e0346e9dc0023cae75b53 |

The first new lock observer report is retained separately: its added success
stdout byte-order assertion was stricter than the original Value comparison.
The corrected observer preserves the original response criterion and all
actual blocked-write/lock and raw-stderr checks. No production behavior or
original assertion was weakened. Full START/Supervisor and systemd gates are
maintained by the shared Jobctl release qualification, using the same image.
