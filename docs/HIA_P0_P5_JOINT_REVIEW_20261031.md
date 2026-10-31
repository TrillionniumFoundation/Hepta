# HIA P0 + P5 same-source merge checkpoint

First parent: `33d989298adbf5923bef164bd3aa17224b105428` (P5 actual native research/cost evidence intake).
Second parent: `29246ef7fae6277a29f1712c352eec8f6d1e6a4f` (P0 mutable Core + UTF-8 input fixes).
The P5 parent has the exact #418 blob for `hepta/hia_program.py`,
so we select the P0 implementation of that path without reworking it.
All seven P5 modified files remain inherited from the first parent.
The four P0 scoped paths remain byte-identical to their parent blobs.

The dedicated CI executes P0 + P5 + native GCC ELF observer and agent
opcode/catalog integration on a single exact commit. Earlier parent
passes cannot substitute for this merged source run. This integration
is DRAFT / DENY_ALL and must not be deployed without independent review.

P0-P7 all retain their strict closure gates: native semantic refinement,
provenance and exception safety, real multi-target ABI, full C/C++ migration,
strong real Rust/C++ optimization baselines, genuinely positive NDU complete
cost holdout, unseen Agent task advantage, and durable native final-use,
generation fencing, recovery, rollback and physical hardware experiments.
