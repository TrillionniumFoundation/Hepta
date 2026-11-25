# Native multiversion constructor handoff

The component captures the actual fixed native constructor, sends the exact
admitted Core with the fixed `hia-build-shared` role, checks its captured build
report, and rechecks the captured constructor identity. It does not publish a
runtime generation. Complete native preparation orchestration, error ordering
and coordinator integration remain separate obligations.

The six-word `hia_mv_prepare_build` entry takes `HIAMVBF1`, a 256-byte header:
zero at 8; sealed constructor FD at 16; absolute transport deadline at 24;
aligned private cancellation pointer or zero at 32; Core, ABI and path lengths
at 40, 48 and 56; expected complete constructor SHA256 at 128; other fields zero.
Core, `HIAMVAB1` and an absolute non-NUL output path follow. Core is bounded by
8 MiB, the original profile has 1..16 exports with 0..16 scalar arguments, and
the path is at most 4,095 bytes. The process image cap remains 8 MiB. Workspace
is 128 MiB; output is at least 512 bytes plus a successful captured report.

The native policy duplicates an actual sealed 0500 regular anonymous image,
checks its complete bytes, computes actual Core/ABI hashes, and invokes the
existing qualified process owner. Standard output is bounded by 1 MiB and
standard error by 64 MiB. It verifies the direct native schema/profile/target,
actual Core identity, scalar exports, native construction claims and ELF report
shape. Receipt numbers use the original JSON decoder token span fields +24/+32.
A receipt remains insufficient to authorize execution; actual file custody,
ELF inspection, sealing, loaded symbol mapping and independent probes follow.

The reply `HIAMVBR1` has a 512-byte header and the captured JSON at offset 512.
Status at 8 is 0 success, 1 child failure, 2 transport failure, 3 binding failure,
4 short report output. Detail is at 16, raw wait status at 24, reported artifact
length at 32, start/wall nanoseconds at 40/48, input lengths at 56/64/72, report
length at 80. On a completed nonzero child, stdout/stderr FDs at 88/96 are
transferred exactly once; the caller owns and closes them. Otherwise owned
capture FDs are closed. Hashes at 128/160/192/224/256/288 bind the constructor,
Core, ABI, artifact, object and machine text. Text length is at 320. Malformed
private input returns `0xfffffffd` before an owned child or path effect.

The current constructor is the fresh P3 native publication, 3,819,682 bytes,
SHA256 `539ce9aab49b6f3e04517a511b08a6351421f86b978e03510ea3220e90f231e0`.
It is explicitly different from the missing historic e646 image. Its existing
native publication and custody receipt remain separate provenance.

Actual qualification completed 18 fresh constructions covering 283 original
signatures and all 16,547 original finite vectors. Every artifact was loaded
from its exact just-published pathname, using one holder for sealing, loaded
mapping checks, complete HIA VM comparison, native scalar ABI calls and native
retirement. All 11 scalar types and arities 0..16 were covered. Every probe used
the original 4,224-step and 256-frame budgets. The actual path disappeared only
through that holder's native retirement; the file descriptor set returned to
its prior state. This campaign took 74.969 seconds and passed all groups.

The image also passed 82 actual constructor/private frame/receipt/capture
negative controls and 29 native packaging controls. Receipt corruption was
introduced only by an external QA observer after a real constructor completed.
The product policy rejected changed claims and bindings; it did not consume a
caller-supplied verification flag. Complete reports, source pins, actual image
pins and the preserved earlier failure boundaries are in the JSON companion.
