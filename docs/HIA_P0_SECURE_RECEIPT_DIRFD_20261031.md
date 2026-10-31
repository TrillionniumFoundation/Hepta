# HIA P0 — directory-FD-bound, no-symlink evidence receipt publication

## Exact basis and concrete check/use defect

This is a separate P0 admission-identity repair stacked on the previously
integrated #470 head `8d7c297d123b50b9156cacbc19a5cec77c14f8c0`.

The source-bound qualifier already rejects an evidence path resolved inside
the worktree, binds git queries to the repository root, counts started/stopped
unittest identities, and checks worktree cleanliness after tests. However,
it calls _verified_receipt_destination(output) and *later* performs
`output.parent.mkdir(...)` plus `output.open("x")` using the original string.
An external mutable parent can be replaced by a symlink into the repository
between these two operations. The original pre-write clean-worktree check
would still say clean, while a receipt is unexpectedly written in-tree.

## Fix, scope, and independent negative control

Keep the exact HIA source and test contracts. Replace only evidence output
publication with `_write_immutable_receipt`, which:

- refuses relative paths and unsafe components;
- traverses absolute directory components relative to an already opened root
  directory fd with `O_DIRECTORY|O_NOFOLLOW`, creating any absent components
  with directory-relative mkdir;
- verifies the actually opened directory fd is not within the source tree;
- uses `O_EXCL|O_NOFOLLOW|O_CREAT` against that same anchored parent and
  writes an fsynced, mode-0600 immutable-once receipt, with a directory fsync;
- fails closed without a silent path-open fallback if Linux /proc or
  directory-relative no-follow facilities are unavailable.

Deterministic adversarial tests switch an already accepted outside path's
parent to an inside-worktree symlink before publication. Separate controls
refuse links pointing outside too, direct in-worktree writes, relative paths,
and a second write to an existing receipt. Positive controls verify identical
JSON bytes, nested directory creation and private file mode.

This qualifies only receipt path immutability under the supported Linux
pathname/direct-file-descriptor model. It is **not** a guarantee against a
privileged attacker moving an already opened directory inode, a proof of
entire test-binary provenance, or full durable crash-safe publication: disk
write failure may retain an incomplete no-clobber file and must never be
interpreted as an accepted receipt.

## Exact-head tests

```sh
python -B -m unittest tests.test_hia_three_lane_gate -v
python -B -m tools.qualify_hia_three_lane --suite gate --output /tmp/hia-dirfd-gate.json
python -B -m tools.qualify_hia_three_lane --suite core --output /tmp/hia-dirfd-core.json
python -B -m tools.qualify_hia_three_lane --suite native --output /tmp/hia-dirfd-native.json
```

## P0–P7

All eight production gates remain OPEN. This is a P0 source/test evidence
admission hardening only. No safety certificate, NDU net-benefit proof,
C++ unrestricted translation, unbounded global optimality, or P7 durable
exactly-once restart is authorized. The existing DENY_ALL research policy
remains in force until independent final-source qualification.
