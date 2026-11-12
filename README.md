# Shared frame R4 — independent CPython 3.14.4 development

This branch contains only an external development harness. It checks out the
authentic published product `4b19af89a766593f7d5f1cc2db256e81aba7afcb`
(`1bc7c90996e1910ad66ba771b0bfee1d5bfa655c`, 3,153 files) separately.
It never changes a product or audit ref and never assigns a new HEAD to an
uncommitted candidate.

The first finite overlay is the exact saved joint R2 source packet
`0d2a9613a4aa37102448b5847bc4eab452a2573f`: 51 paths, 3,181 files,
content tree `a9a2b5ec40d176a7684a03ca2859190abd982db0`. The original R3
Core-label and 120 CALL/BoolOp observations execute on that baseline first.
Any observed equivalence failures are retained under their original statuses.
A completed baseline observation is not a passing equivalence qualification.

The subsequent 13-path R4 overlay is immutable source packet
`440f47786b68dc4b162ee205712aa8eaa0449494`: 3,184 files,
content tree `3e67be1f7a92ce418c0625b13ef8e948f143b7c0`.
It changes CALL temporary transfer, BoolOp onward retirement, two generated
images, and the finite tests/registration for those changes. It retains every
original Core method and caller assertion. The local source qualification is
CPython 3.12.14 development only; it does not supply a cold report here.

The actual interpreter must be CPython 3.14.4 on Linux x86-64. The retained
669,494-byte compiler with SHA-256
`81b6fad94493546b5bf3f858248f25b19aded88bf8f3aaad18140aa317dac109`
is explicitly admitted only as development input. All six Code/ELF/Plan/Core
images are compiled afresh using the original 20-second compilation bound.

Three independent gates then run: the complete 60-test component/lifecycle/
checker panel; all 124 tests comprising 23 current Core controls, the original
51 machine callers and the original 50 Core callers; and the original 44 Plan
callers. Each retains its original 1,800-second outer supervisor and all
original inner limits. The latter gates still run if an earlier test gate
fails. Full source byte/mode identity and all actual manifest/image identities
are checked around each gate. Original tool and harness identities are also
compared before and after.

Every report, process receipt, log, generated image, original baseline
observation, frozen input and evidence manifest is uploaded even on failure.
No current-cold, full-stack, default activation or old-owner deletion claim is
made. The two Emission EOF whitespace changes independently owned by the root
integration are not silently copied into this R4 source.
