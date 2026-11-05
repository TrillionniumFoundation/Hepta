# HCSN P2 Iteration 42 — validity-vector cross-talk counterexamples

**Research Draft only. All P0–P6 OPEN; production activation false.** Independent algebraic replay of the *exact* validity update in `research/hcsn/p2_reset_validity.py` (Draft #512). This is a latent reachability counterexample, **not** an observed failure of trained weights. The trained four-model reset-validity campaign already fails whole-sequence quality and stays negative.

## Subroutine and independent rational witness

With an assumed correctly detected write and no reset, the source uses `v <- v+(1-v·k)k` for a normalized learned address `k`. The binding logit is `12*(v·k-0.5)`. The value-class softmax is multiplied by `sigmoid(binding_logit)`, hence the *total* mass assigned to known values equals that sigmoid, regardless of the value readout.

1. **Previously stored key becomes UNKNOWN without a reset.** In a 2D subspace of the 16-dimensional key address, write `k1=(1,0)` then `k2=(-3/5,4/5)`. Exact rational recurrence gives `v=(1/25,32/25)`; on re-reading `k1`, projection `1/25`, logit `-5.52`, known mass `0.003989865148994104` (<0.005).
2. **Never-written address becomes KNOWN.** Write two orthogonal addresses `k1=(1,0)`, `k2=(0,1)`. Then `v=(1,1)`; query unwritten `k3=(3/5,4/5)`. Projection is exactly `7/5`, logit `10.8`; known mass `0.9999796009127201` (>0.99997). Projection is not confined to [0,1].
3. **Reset positive control.** Exact erasure makes `v=0` and known mass `sigmoid(-6)=0.0024726231566347743`. Both counterexamples occur *without* a reset.
4. **FP32 control.** Single-precision operand rounding preserves both misclassifications for this construction (see raw JSON).

These are reachable mathematical *input address sequences* if learned `address` emits the stated vectors. They do **not** prove that any actual pretrained/learned checkpoint encounters these keys or that the model's event controller correctly chooses writes; the failed training campaign has not done so. They are not a proof against all vector memories or calibrated probabilistic membership models. A higher-dimensional explicit per-key validity representation or independently calibrated key-identity check would change state cost and must face matched FLOP/parameter and OOD evaluation.

## Reproduce and strict fail-closed behavior

From the repository root, using Node.js with standard library only:

```sh
node research/hcsn/p2_validity_cross_talk_reference.mjs > /tmp/hcsn42.json
diff -u research/hcsn/gates/2026-11-05-iteration42-validity-cross-talk-raw.json /tmp/hcsn42.json
set +e
node research/hcsn/p2_validity_cross_talk_reference.mjs --strict >/tmp/hcsn42-strict.json
code=$?
set -e
test "$code" -eq 2
cmp /tmp/hcsn42.json /tmp/hcsn42-strict.json
```

Only bounded in-tool JavaScript arithmetic of the same recurrence has been executed in this run; the committed Node CLI and its strict exit were **not** independently executed on OS hardware, and no external reviewer has signed the evidence. All evidence remains Draft/HOLD. P0 HX Eq8/11/12/A7, QVI and low precision; P1 matched slope/FLOP; P2 real dynamic barriers and heldout MQAR; P3/P4 pretrained 4-modal independent heldout; P5 CPU/GPU/energy/p95/p99; P6 medium quality-cost frontier all remain OPEN. Keep negative controls, no main merge or signature/activation changes.
