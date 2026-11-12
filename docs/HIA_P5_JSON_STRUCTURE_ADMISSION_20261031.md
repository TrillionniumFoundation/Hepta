# HIA P5 — node/depth preflight for research evidence, 2026-10-31

## Original P5 blocker

The full-cost comparison, Linux native observer registration and native paired
sample replay all enforced immutable-wire byte budgets before JSON decoding,
including the earlier UTF-8 allocation repair. However, a valid small-byte
JSON document can still contain a huge array of tiny values or deep nesting.
Calling the complete `json.loads` before enforcing a node/depth budget
materializes an unbounded number of Python objects relative to the
program's declared structural admission budget.

## Narrow source-exact hardening

Reuse the existing independent `hepta.hia_json_preflight.preflight_hia_json`
scanner, with identical immutable text passed to the subsequent native JSON
decoder. The limits are deliberately conservative and explicit:

| Entry point | Max wire bytes | Max value nodes | Max depth |
|---|---:|---:|---:|
| `hia_full_cost_gate._wire` | 262,144 | 65,536 | 64 |
| `hia_native_process_observer._parse` | 262,144 | 65,536 | 64 |
| `hia_native_paired_replay._read` | 8,388,608 | 262,144 | 64 |

The preflight rejects duplicate decoded field spellings, invalid JSON and
non-integer numbers, all of which were already invalid for the strict
research measurement profile. It does not introduce a new JSON semantic
authority: accepted values still pass the original strict decoder,
domain checks, registration identity, cost, source, observation, and
three-way economic comparison. All receipts keep `DENY_ALL`.

## Test and evidence

```sh
python -B -m unittest tests.test_hia_evidence_json_structure tests.test_hia_bounded_research_wire tests.test_hia_full_cost_gate tests.test_hia_paired_holdout -v
python -B -m unittest tests.test_hia_native_process_observer tests.test_hia_native_paired_replay -v
```

The new tests deny more-than-65,536 and more-than-262,144-node documents
**before the complete decoder can run**, block depth beyond 64 on both
immutable bytes and Unicode text, preserve accepted canonical input
digest/value and reject escaped duplicate keys. The existing real Linux
C/ELF controls are mandatory and cannot be silently skipped.

## Explicit non-claims

This closes only the selected research JSON structural-admission deficit
within the stated input bounds. It is not a process-level memory ceiling,
OS sandbox, independent observer attestation, source-to-machine proof,
NDU > DP/Fixed net-benefit confirmation, or P0–P7 production certification.
Do not deploy or merge without exact final-head negative and native evidence.
