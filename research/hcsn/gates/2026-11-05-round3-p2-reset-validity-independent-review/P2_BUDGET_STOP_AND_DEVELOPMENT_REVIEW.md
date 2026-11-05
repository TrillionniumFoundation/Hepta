# P2 reset-validity: retained budget stop and development failure

## Verified outcome of the original registered execution

The campaign registered at commit `b9571fb1de3c420ceaea27152f59898e36795dfe` ended as **INCOMPLETE_RETAINED**. Three planned configurations completed 300 updates; HCSN seed 719 stopped at 173 updates when the original 180-second training CPU budget was exhausted. The retained record contains 1073 updates in total. Training consumed 180.109695956 CPU seconds; the entire campaign consumed 181.443367942 CPU seconds. This is a soft-budget stop, with 0.109695956 seconds of training overshoot, not a completed experiment within the original allocation.

The registered failure branch operated as written: **no heldout panel was constructed or scored**. The report has no heldout-construction timestamp, no per-run heldout or query archive fields, and the original artifacts directory contains exactly four weight archives. It does not contain heldout query archives. Conditional-erasure witnesses and mapped heldout verification were likewise not executed in this branch; no such results should be invented or backfilled into it.

The independent audit verified the registration commit's actual protocol and six source-file bytes, current source hashes, checkpoint hashes, all retained loss/gradient-array lengths and finiteness, numeric parameter initialization, and the training-stream digests and query-label counts. It reconstructed 600 distinct training-data batches to verify the three required stream-prefix endpoints: seed 613 at update 300, and seed 719 at updates 173 and 300. This involved **zero training fits**. All four weight archives contain finite model state dictionaries; optimizer state was not saved.

## Independent development replay

The implementation agent disclosed a post-hoc diagnosis on the already registered `multi_reset` development panel, with dataset digest `419aa18a467d4294ec17b17790b59a2385089ac578226fd29ac5f11a178cbea0`. This is the development panel of 16 sequences and 224 queries, not any of the nine heldout panels. Independent grammar parsing and checkpoint replay confirmed the disclosed integer counts:

| Mode | Seed | Retained updates | Resets at query tokens | Resets at literal RESET tokens | Effective writes at true value tokens |
| --- | --- | ---: | ---: | ---: | ---: |
| Ordinary | 613 | 300 | 224 / 224 | 19 / 32 | 37 / 160 |
| HCSN | 613 | 300 | 224 / 224 | 30 / 32 | 13 / 160 |
| Ordinary | 719 | 300 | 224 / 224 | 1 / 32 | 0 / 160 |
| HCSN | 719 | 173 | 224 / 224 | 1 / 32 | 4 / 160 |

For every checkpoint, all query binding logits are exactly **−6**, and every query predicts UNKNOWN. The 160 queries whose correct answer is a known value all fail; the 64 genuinely UNKNOWN queries all succeed. Consequently, each replay has query accuracy **64/224 = 28.5714%** and **0/16 exact sequences**. There are zero UNKNOWN false accepts, but this is accompanied by complete failure to retrieve known answers. Integer event and query statistics matched exactly. Independently reduced means of FP32 soft event probabilities differed by at most `1.7881393432617188e-7`, consistent with the different reduction layout; these tiny mean differences do not affect any hard event or reported count.

This observed failure has a direct forward mechanism: reset at the query erases memory and validity before readout, forcing binding score zero and UNKNOWN probability `sigmoid(6)`. It should not be described merely as address cross-talk, lingering stale memory, or a lack of writes. Several models do perform writes; they also erase the stored information at every queried read. This replay establishes the output-level failure mechanism. It does not establish why optimization converged there or identify a unique training intervention that would prevent it.

## What the reset-window and zero-UNKNOWN criteria do and do not show

All four development replays contain a learned reset in every RESET-to-first-query window because the endpoint query itself always resets. Thus a window count alone cannot establish that the controller recognized the visible RESET command at its occurrence. The correct interpretation is **a reset happened by the first query**. The substantial difference between literal-command reset counts and query reset counts makes this qualification concrete.

Likewise, a controller that always answers UNKNOWN has zero UNKNOWN false accepts. The full registered criterion does not accept that behavior: it also requires at least 95% query accuracy and 90% exact-sequence accuracy on every registered panel, plus the other mechanism conditions. The present development result fails those quality requirements decisively. There was no erroneous formal heldout pass, because this execution never entered the heldout branch.

The generic `stale_answers_emitted` statistic can include UNKNOWN as the previous answer when the current target is known. In this failure, those emissions must not be narrated as resurrection of an old known value. Known-target rejection, unknown-target false acceptance, and emission of an old known value are separate outcomes.

## Files and reproducibility

- `incomplete-and-development-audit-v2.json` records the final portable independent verification. It repeats the same checks after extracting the shared parser into its own fixed file; the scientific counts are unchanged. The earlier audit is retained.
- `audit_reset_validity_incomplete.py` reproduces the verification without fitting or constructing heldout panels.
- `reset_review_parser.py` provides the independent grammar parser imported by the verifier.
- `audit_reset_validity_results.py` is the separate completed-campaign verifier. Its completed-campaign path was not executed for this original incomplete run.

Example:

```bash
python audit_reset_validity_incomplete.py \
  --root /path/to/candidate-repository \
  --registration-repo /path/to/repository-containing-registration-commit \
  --output /fresh/path/incomplete-audit.json
```

Both scripts and this report are internal independent-review artifacts, not external attestation. Any subsequently registered completion attempt must retain this original incomplete record and separately charge its additional execution. Replaying the partial configuration from its seed because no optimizer state exists is an additional actual fit execution, even when its fixed model configuration and data sequence are unchanged. The original result remains incomplete regardless of a later completion outcome.
