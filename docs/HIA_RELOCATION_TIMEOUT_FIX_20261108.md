# Relocation fake-child timeout fixture repair

The `relocation-runner-b` CI job at source `ffa64c93dd4c51190fda8c0f647481a31ffbcf07`
failed `test_complete_failure_replay_and_spawn_semantics`: the timeout case's
capture did not replay as complete. The original assertion is retained.

The fixture previously multiplied the collector clock by 100 before process
startup. Its 60-second deadline could therefore expire before child output;
the same multiplier also reduced the two-second cleanup allowance to about
20 milliseconds of host time. Host startup and persistence scheduling became
part of a test intended to exercise a complete diagnostic checkpoint.

The repaired fixture keeps its test clock at zero until the actual sink has
returned from appending and fsyncing all eleven marker records. Only then does
it advance to the unchanged 60-second timeout. Cleanup advances with ordinary
host monotonic time. Missing checkpoints have a separate finite five-second
fixture readiness guard; a late marker cannot replace an already expired guard.
The actual PTY, child process, default marker parser, raw writes, fsync calls,
cleanup and independent evidence replay all still execute.

Production collector and runner source bytes are unchanged. No production
deadline, replay condition, missing-output control or acceptance gate is relaxed.
These are harmless fake-Python-child controls, not Lean proof execution.

Validation retained under
`review-evidence/relocation-timeout-marker-20261109/`:

- The original CI failing method passed locally before the change; that result
  does not replace its retained CI failure.
- Reinstating the original 100x clock with a two-second delayed child reproduces
  an expected failure: zero observed markers instead of eleven.
- The complete modified runner module passed 33 tests, including full inverse
  replay, hostile evidence cases, the original failing method and the delayed
  child regression. Final focused controls also cover the readiness guard.
- CI inventory construction checks all 712 distinct test IDs, including every
  prior ID and the three new methods. Relocation has 68 IDs; runner shards A/B
  each have 11, inverse has one and grammar/numeric bounds have ten.

The local reports remain separate observations. Required CI must pass again for
the resulting source commit before this source candidate is promoted.
