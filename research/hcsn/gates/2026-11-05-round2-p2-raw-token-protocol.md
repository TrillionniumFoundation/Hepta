# Round 2 P2 — fixed local raw-token protocol

Base: `8e352b84a1286836d156a281e28956d07a60157e`.
This protocol is written before the full experiment; it is local exploratory
registration, not an independent scientific acceptance authority.

## Minimum sufficient tasks for this increment

- Selective Copy: retain **all three values in order** among irrelevant raw
  symbols, then emit all requested values. Report whole-sequence exact match.
- MQAR: four raw key/value bindings and four queries in a new key order. The
  learner receives no parsed keys, per-key memory, key one-hot routing or masks.
- Overwrite: repeat bindings to the same key; newest valid value must win.
- State tracking: queries interleaved with writes; a future update must not
  influence an earlier answer.
- Repeated commanded regeneration: only an observed RESET token signals new
  logical state. No external hidden-state zeroing or episode ID is supplied.
  Old bindings must become UNKNOWN until rebound. This is not autonomous
  boundary crossing or a learned spike-time law.
- Independent elapsed times are model inputs; the token is an instantaneous
  observation with elapsed time since the previous observation. This changes
  the old duration-scaled write semantics deliberately. Very short intervals
  are tested, without pretending that the old continuous-write no-go is fixed.

## Frozen experiment

- Model seeds: 101, 211, 307 (new relative to the prior 11/23/37 studies).
- HCSN simplified stopping Call/Put channels vs ordinary softplus pair, same
  recurrent architecture, 48 state dimensions, 16 embedding dimensions,
  exactly 10,197 learned parameters per model, paired initialization/data.
- 600 Adam updates; batch 24; learning rate .003; gradient clip 1; one CPU
  thread. No test-driven checkpoint selection, tuning or early stopping.
- Training batches mix five tasks; fresh deterministic streams per update.
  Query answers are the sole loss. Answers are never teacher-forced as input.
- The ordinary pair matches the signed update-logit slope at the channel
  origin under the shared initial channel weights. This is not global slope
  or FLOP equality. Both full training times and gradient statistics are kept.
- Put+linear is evaluated as an exact canonical-weight reparameterization of
  HCSN, with forward/gradient tests; it is not an independent extra capacity.
- Calibration seed 730001 is observed only after training, with no selection.
- Fixed held-out seeds 841001–841009, including longer distractor spans,
  overwrites, state tracking, four visible resets, independent irregular time
  and 0.005–0.02s event intervals. No sample may be discarded on failure.
- Local operational threshold: every panel, across every model seed, query
  accuracy >=.95 and whole-sequence accuracy >=.90. Report failures honestly;
  passing this finite threshold would not close the full scientific P2 gate.
- Missing final write: four equally likely values yield identical observed
  token sequences. Information upper bound is 25% (or abstention), not a
  requirement to hallucinate the missing value.
- Old noisy duration-scaled CTMC: report analytic incompatible rate bounds
  for 1% write error at 0.02s and 1% retention error at noise .01 over 4096s.

## Still required outside this increment

Autonomous endogenous boundary/event learning, sampled event-time gradients,
unknown real inputs, real encoder generalization, global quality/energy
qualification and independently signed evidence remain OPEN.
