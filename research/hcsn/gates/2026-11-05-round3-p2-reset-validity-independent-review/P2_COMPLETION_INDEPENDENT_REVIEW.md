# P2 reset-validity: independent review of the completed fixed configuration set

## Conclusion

The additional registered execution completed all four fixed 300-update configurations. Independent replay verified the reported negative result: **every one of the four checkpoints predicts UNKNOWN on every one of the 9888 registered heldout queries**. Each model rejects all 5851 known-answer queries and correctly rejects the 4037 UNKNOWN queries. Each has **0 exact sequences out of 864**, spread across the nine panels. The registered reset-gap criterion remains false.

This is a failure to preserve and retrieve known information under the fixed training design. Zero UNKNOWN false accepts, observed reset events, and successful conditional erasure are real measurements here, but none establishes successful memory when every query is rejected. The same heldout streams are evaluated by all four checkpoints; they are not four independent sets of data or 39,552 independent experimental units.

## Execution provenance and budget accounting

The original campaign registered at `b9571fb1de3c420ceaea27152f59898e36795dfe` remains `INCOMPLETE_RETAINED`: three 300-update fits plus HCSN seed 719 at update 173, with no heldout evaluation in that original execution. Its immutable report has SHA256 `b97e502b7063b0cb30f440d9f66cf10c834fdfacac9e4af1af78619017f0c485`.

The completion protocol was publicly registered at **`fa8eb7413d72762f51e61144c36912047dfce240`**, before the additional replay fit and before any heldout construction. It preserves the original architecture, model seeds, data streams, optimizer, final-update checkpoint policy, heldout panels, and acceptance criteria. The protocol discloses the already observed negative development result. Its inherited `development.fit_count_before_registration=0` refers to the original registration; there were four actual prior attempts at the time of this completion registration.

Three final checkpoints were reused without training and verified by hash. Because the original run did not retain optimizer state, the fourth configuration was restarted from the same numeric initialization and replayed for 300 updates. Before any heldout panel was constructed, the runner checked all 173 retained prefix losses, all 173 preclip gradient norms, the data-stream digest and 13,700 query labels, and the entire model checkpoint after update 173. The tensor guard compares dtype, shape, and C-order bytes, including signed zeros. The independent audit verifies the stored traces, immutable inputs, and the implemented runtime guard; it does not claim to have retrained that prefix independently or to possess the original intermediate Adam states.

| Cost/accounting item | Recorded value |
| --- | ---: |
| Original actual fit attempts | 4 |
| Additional actual fit attempts | 1 |
| Total actual fit attempts | **5** |
| Distinct final fixed configurations | 4 |
| Original optimizer updates | 1073 |
| Additional optimizer updates | 300 |
| Total actual optimizer updates | **1373** |
| Repeated prefix updates | 173 |
| Total actual training query labels processed | 119300 |
| Original training CPU seconds | 180.109695956 |
| Additional training CPU seconds | 48.845148235 |
| Combined training CPU seconds | 228.954844191 |
| Additional campaign CPU seconds | 58.745328462 |
| Combined recorded campaign CPU seconds | **240.188696404** |

The original 180-second budget did not pass. Completion is an explicitly charged continuation, not a relabeling of that failure. The combined campaign figure adds the two runner CPU measurements; it is not an end-to-end energy or production-efficiency measurement and excludes separately performed review work.

## Heldout results

All four configurations have the same query predictions and the following accuracies. Each panel contains 96 sequences; all four models have zero exact sequences on every panel.

| Registered panel | Queries | Known targets, all rejected | UNKNOWN targets, all correct | Query accuracy |
| --- | ---: | ---: | ---: | ---: |
| MQAR, in distribution | 384 | 384 | 0 | 0% |
| MQAR, long distractors | 384 | 384 | 0 | 0% |
| Overwrite | 384 | 384 | 0 | 0% |
| State tracking | 1152 | 1152 | 0 | 0% |
| Contextual false writes | 384 | 384 | 0 | 0% |
| Irregular time | 720 | 626 | 94 | 13.0556% |
| Short intervals | 720 | 624 | 96 | 13.3333% |
| Repeated visible resets | 2304 | 1529 | 775 | 33.6372% |
| Reset without rebinding | 3456 | 384 | 3072 | 88.8889% |

The apparently high 88.8889% on reset-without-rebinding is exactly the panel's UNKNOWN-label fraction, 3072/3456. The models fail every pre-reset known-answer query and therefore every full sequence. This is why query accuracy must be accompanied by known-answer recall and exact-sequence performance.

Read-only inspection of the archived query events additionally confirms **9888/9888 query positions trigger reset for every checkpoint**. All query binding logits are exactly −6. Since reset clears both stored values and validity before reading, the factorized output places probability `sigmoid(6)`, approximately 0.997527, on UNKNOWN. This directly identifies the observed forward failure as erasure at the queried read. It is not evidence that old known values survived the reset. Questions about the optimization dynamics leading into this state require the separate mathematical/autograd analysis; this audit does not infer them from accuracy alone.

## Reset criteria, witnesses, and the stale-answer metric

All required reset windows are covered, but the window includes the first query after each visible RESET. A controller resetting at every query therefore satisfies the window count without reliably identifying the command at its occurrence. The precise claim is that an event occurred by the first query, not that the visible command was correctly recognized at its own token.

All four separately declared development witnesses pass independent replay. Both local calls produce reset=1; memory, validity, and older context are exactly zero; the retained previous context equals the current embedding; and perturbing prior memory/validity yields identical output and returned state. These are valid conditional-erasure observations. They neither supply semantic supervision to the model nor demonstrate useful memory or autonomous regeneration.

The recorded `stale_answers_emitted` total is 3576 per model, but its legacy eligibility mask admits UNKNOWN=4 as the prior answer. Splitting the outcome from archived arrays gives:

- **Old known-value emissions:** 0 per model.
- **UNKNOWN predictions counted as a prior answer:** 3576 per model.
- **Known-target false rejections:** 5851 per model.
- **UNKNOWN-target false accepts:** 0 per model.

The original metric is retained for provenance; it must not be described as 3576 leaked old known values. The failure here is complete rejection of available known answers.

## What the independent audit executed

The portable verifier made no training fit and added no new quality panel. It verified actual registration-commit protocol/source bytes, current frozen source hashes, original evidence hashes, reused-checkpoint provenance, replay-prefix trace consistency, final optimizer-checkpoint file hashes, and event ordering relative to heldout construction. An independent adjacent-triple grammar parser checked every regenerated target, while archived query arrays supplied independent query/sequence/error counts.

The verifier then replayed all **36 fixed model × panel combinations**. Archived hard events, query predictions, probabilities, and binding logits matched the fixed checkpoint outputs exactly. NLL reconstructed from the archived FP32 probabilities differed from the original FP32 cross-entropy reduction by at most `1.082577804289997e-6`; all integer counts and accuracy rates matched. Separately, **18 mapped Put+linear panel replays** yielded identical events and zero maximum log-probability difference for the two HCSN checkpoints on this dataset. This empirical equality does not repeal the retained general FP32 near-threshold counterexample.

The four conditional-erasure witnesses were independently replayed as described above. The original acceptance logic was recomputed without relaxing its thresholds: all four models fail the registered gap criterion. Passing these artifact checks means the negative result is reproducible; it is not a scientific pass, a full HCSN acceptance suite, or external attestation.

## Reproduction files and hashes

Place `audit_reset_validity_results.py` and `reset_review_parser.py` together. Run with a fresh output path:

```bash
python audit_reset_validity_results.py \
  --root /path/to/candidate-repository \
  --registration-repo /path/to/repository-containing-registration-commit \
  --evidence /path/to/candidate-repository/research/hcsn/gates/2026-11-05-round3-p2-reset-validity-completion-results.json \
  --output /fresh/path/completion-audit.json
```

The verifier refuses to overwrite an existing output. `completion-independent-audit.json` contains the actual independent result from this review. The original incomplete execution is separately covered by `audit_reset_validity_incomplete.py`, `incomplete-and-development-audit-v2.json`, and `P2_BUDGET_STOP_AND_DEVELOPMENT_REVIEW.md`.

| Item | SHA256 |
| --- | --- |
| Completion protocol | `a41c7aa2763a494fc11abbc52a47355c81fc4cba8322109a56326e4ccbf26d1f` |
| Frozen model | `7ebeaf9069bdd547a2e41d607345a3ce3b29c300d93acf187bdfb51ebc99a02d` |
| Frozen completion runner | `d840ccfaec094c571933fcc572b5f80ad804bd659dbdcd45ab990d2fa8ff5063` |
| Completed campaign report | `b057a0764b4931a28ce13aea7e61a680ac78d38306818d4573daf4b914f9815c` |
| Independent completed-campaign verifier | `5c97fc1242de050ed58b9124f85c1a919bc8b73efcfe0ed0aa15f1694c2e24ff` |
| Independent grammar parser | `29b763ef3b19cd8ef4595dc8efbf26e8bc013c51d8f7fa0c314ef9f61a4a83fc` |

The conclusions apply to this bounded symbolic grammar and these fixed training configurations. They do not establish a failure theorem for every use of HCSN, nor do they validate complete HX, optimal QVI, arbitrary language memory, Selective Copy, or autonomous reset learning.
