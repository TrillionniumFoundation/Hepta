# HIA selfhost v10 control-flow and wire-limit evidence

This increment is based on source `2598f4309791d3a023cd5df585ad26810b20c744` (v9).
It adds explicit `trap` lowering and common source line limits to the actual HIA compiler.
It does not claim full Core coverage or general machine correctness.

## Result

- Ordinary input opcode coverage remains **32/50**.
- Accepted Core terminators increase from **3 to 4**: `ret`, `jump`, `branch`, `trap`.
- Exactly the five Core trap codes are accepted: `user`, `overflow`, `division_by_zero`, `bounds`, `allocation`.
- The x86-64 lowering executes UD2 at the trap position. Earlier stores remain observable; the caller does not continue after a taken trap.
- The native flat ABI exposes process termination, not a structured reason-code result. This evidence does not establish native reason-code reporting.
- The source preflight enforces 16,384 lines and 16,384 bytes per line before output writes, including dirty workspace rejection. LF does not count toward the line byte budget; a final empty line counts toward the line-count budget.
- Earlier profile documentation explicitly disclosed that presentation limits were omitted. The fresh v9 contrast records an admission difference, not a newly alleged security or semantic breach.
- Existing jump signature and self-tail-call restrictions remain.

## Verification

Source-only tests:

```text
python -B -m unittest tests.test_hia_selfhost.SelfhostSourceTests tests.test_hia_selfhost_contract.SelfhostContractTests tests.test_hia_selfhost_language_coverage.SelfhostLanguageSourceTests -v
24 tests passed
```

Fresh cold replay:

```text
python -B tools/replay_hia_selfhost_cold.py --output /workspace/scratch/19251cd2be73/core-audit-evidence/v10-cold.json
COLD_SELFHOST_REPLAY_PASS — outer 10/10 checks
SELF_HOSTED_FIXED_CORE_PASS — inner 461/461 checks
```

The 98 added control checks cover both the original and mutated third-generation native compilers:
40 actual UD2 trap executions, 20 dynamically untaken normal returns, 30 transactional refusals,
and 8 successful exact 16 KiB line-boundary executions. References are independently validated
before the first bootstrap generation. Raw child requests, sources, outputs, receipts and process results
are retained in the archive.

Fixed point B1 = B2 = B3:

```text
d31cf07b9f574fa270981e91b59a4cfd84a57e7b0b4a1178fb2ef693e8caf5cb
```

Mutated M1:

```text
6aa2e5eec1d93f59ba468f15c668b7d6cb8f5f5cf171cd85a3979ceb61cf1dd5
```

Mutated M2 = M3, distinct from M1 and B3:

```text
bc7739f9effb24adf062bc7dbefb6c0078131420c2597072d0c3c4c9d2d04d6b
```

Cold source manifest canonical SHA256:

```text
4b037f5e66775a729b2ac9229261b1f46881d62f2142d8939b8825fed7656728
```

## Retained archive

`raw-evidence.tar.xz` contains the cold source-only export, complete qualification evidence,
source test log, compact summary and fresh v9 before observations.

- Size: 1,611,388 bytes
- SHA256: `7a41c22e8b0d1db6728c9dc29096f53421a0c7abe20f2382cb4fa3674e314de3`
- Git blob SHA: `4a60161ea90ba73d610fe4f17a3f5c1cbda65298`

The v9 observations are fresh invocations of the immutable compiler from the prior exact-source CI artifact.
Its image SHA256 is `c9f79900a795ffcdcd5148511f5174b403830e10ca7ce398bc138b1dca9a6bd2`.
Lost earlier-session outputs were not recreated or relabeled as retained evidence.

## Scope and final composition

This is native test evidence under a bounded Linux x86-64 profile and explicit shared-host trust,
not a universal compiler, ABI, FFI, resource, loader or ISA proof. Ordinary input operation coverage
is still 32/50. A composed source release must regenerate the support contract and rerun its own
exact-source qualification; the checks here identify this isolated increment.
