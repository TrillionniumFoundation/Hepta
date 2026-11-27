# Restore the original complete cold-owned budget

Review of the 3ad78 Core wiring checkpoint found that the existing cold-owned
process cap had been changed from 240 to 900 seconds to include new native
construction orchestration. There was no separate original 240-second gate,
so that change did not preserve the original qualification boundary.

This correction restores the complete cold-owned cap to 240 seconds, including
preseed, construction and export. The native inner 60-phase / 14-check / 180+3
gate is unchanged. The subsequent, separately owned C/CPython development
transport build retains its explicit 900-second budget; it cannot grant a
native release or whole-stack qualification.

The two existing campaign controls now require 240 seconds for native cold
replay and 900 only for the separate bridge build. Failed/legacy cold still
prevents that bridge from starting. All 74 original selected controls were
executed again: 74 passed, zero failures, errors or skips, 8.747143441 seconds.
The complete method IDs, original output and harness are retained. The log
SHA-256 is d3ab8c87da8514ac3341bed99fa3d05d2f43a6cef38b5607ef92f88b6b627a0a.

This is structural/physical/Git validation with deliberately synthetic compiler
fixtures. No new native cold or complete transport campaign was executed.
The earlier 3ad78 evidence is preserved without relabelling its tested bytes.

A follow-up whole-patch review also restored the original workflow step cap
from 35 to 11 minutes. Every original job/step timeout in hia-core.yml now
matches the canonical base exactly. AST inspection of every changed production
Python file finds only one new budget call: the separate 900-second bridge
build. The complete 240-second cold owner, 180+3 inner gate, and 11-minute step
are all required. The preceding 74 controls executed the same Python product
bytes; this workflow limit correction is a static check, not an execution claim.
