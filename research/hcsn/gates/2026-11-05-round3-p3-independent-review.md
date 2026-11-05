# P3 round3 independent implementation and evidence review

2026-11-05 UTC. Internal computational cross-review; no external scientific
attestation, HCSN phase admission, or production authorization is implied.

## Result

The revised inference adapter and recorded experiment pass the inspected
source-label, calibration, causal-state, and control-accounting contracts.
The reviewer did not modify the primary source or remote branch.

**Defect found and repaired:** attempt 1 used the label ledger's `slot_ids`
to decide whether any candidate was valid. The corrected adapter takes
occupancy from actual model state, or from observed-image counts for a full
sequence, and masks invalid candidates before selection. Mutating every
source ID, slot ID, and target now leaves acceptance, chosen slot, and margin
unchanged. Labels affect correctness scoring only.

**Repair replay:** independently compared the preserved attempt-1 gzip with
the v2 result. All six trained models' saved 240-step loss/gradient-norm traces
and complete final parameter dictionaries are exactly equal. Calibration,
per-row panel outputs, and source-pair diagnostics are exactly equal in all
15 seed/control records. Timing is excluded from this equality claim. There
are no saved intermediate parameter snapshots, so none are claimed compared.

## Actual independent checks

The audit uses ordinary Python queues, without calling `source_targets()`,
to replay observations, FIFO eviction, multiple correct source slots, missing
text, and physical ages. It then restores the six saved fitted checkpoints.

- **105 model-panel replays:** final memory contents/ages, source labels,
  predictions, integer denominators, and metrics reproduce exactly.
- **15 calibration replays:** all 332 retained source-present margins per
  record and the lower empirical 5th-percentile threshold reproduce exactly.
- **15 slot-permutation checks:** query-only logits permute exactly when
  candidate slots, masks, and ages are permuted together.
- **15 metadata-mutation checks:** inference outputs remain independent of
  external labels after the repair.
- All three paired seeds have exactly 322 trainable parameters in both
  learned modes and identical initial parameter tensors. Mapped Put+linear
  is an evaluator of Call/Put, not an extra independently selected fit.
- The independent queue sees 20 multi-positive calibration queries and 3 in
  a separate training-domain probe; these retain every correct slot.

This is accounting and semantic verification. The implementation owner's
11 focused tests are a separate scoped regression count, not full-HCSN
scientific acceptance. This audit does not add new training or tune thresholds.

## Interpretation that must remain in the report

1. **Ceiling:** ordinary aligned recall is already 98.21–99.11%; the fixed
   requirement for at least +2 percentage points on every present panel is
   therefore unattainable on these realized baselines. Preserve its failure,
   but do not treat it as a universal refutation of all free-boundary ideas.
   Actual paired scores also provide no independent Call/Put gain here.
2. **Irregular-time scope:** the target is inserted at the final step in
   that panel, so its age is zero. Only distractor ages vary. Older-target
   retrieval under irregular delays remains a separate question.
3. **Single direction:** this is positive-text-query to visual-FIFO source
   matching. Text has no recurrent hidden state. It is not bidirectional
   temporal fusion, natural video alignment, or missing-content inference.
4. **NONE semantics:** NONE means the source image is absent from the observed
   buffer. A different image can still match the text's meaning. Edited
   SugarCrepe captions are evaluated only against their own source image;
   they are never labelled false for all distractors.
5. **Dependence:** seeds and caption rows reuse 97 original test images on a
   previously evaluated subset. Image-cluster intervals are descriptive,
   not external independent validation. Raw cosine is already near ceiling
   on these four-slot random-distractor queries.

## Portable audit

`audit_p3_alignment.py` defaults `--root` to the current directory and
`--evidence` to the recorded v2 JSON or its gzip under
`research/hcsn/gates/`. Explicit evidence paths accept plain JSON and `.gz`.
It requires a fresh `--output` and refuses to overwrite it.

```sh
OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 MKL_NUM_THREADS=1 \
python /path/to/audit_p3_alignment.py --output /tmp/fresh-p3-review.json
```

The final portable version was also actually executed against gzip evidence
with the repository as current directory; all checks passed. The JSON receipt
records current code, input, and auditor hashes. No scientific or production
gate was modified.
