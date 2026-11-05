# P2 frozen hard-reset model: local gradient review

Date: 2026-11-05. Scope: source mathematics and synthetic autograd only. **0 fits, 0 optimizer steps, no checkpoints or datasets opened, no heldout access, no source changes.**

## Finding

The frozen model has a conditional first-order learning dead zone at a supervised query whose hard reset is 1. Reset simultaneously zeros the read address, matrix memory, and binding-validity state. Both query outputs multiply two zero factors. Consequently, the task loss sends exactly zero first-order STE gradient to the current write/reset events and to all embedding, address, value, and controller parameters through this query. This is an algebraic loss of gradient after the STE, not merely a small sigmoid derivative.

The claim is conditional. State sensitivities to the reset event remain nonzero, and a later query with hard reset 0 can send a corrective STE gradient to that earlier reset. Readout parameters can still learn the known-value class prior. This review therefore does **not** establish global unlearnability, an irreversible optimizer fixed point, task-level performance, or a scientific gate closure.

The parent team's development observation that all supervised queries of the examined checkpoints reset is consistent with this mechanism; this review did not reopen or independently count those development examples. The original completion budget and empirical acceptance decision remain the P2 experiment's responsibility.

## Sources and invariant

The reviewed source is `p2-work/research/hcsn/p2_reset_validity.py`, SHA-256:

```
7ebeaf9069bdd547a2e41d607345a3ce3b29c300d93acf187bdfb51ebc99a02d
```

The reproducer verifies that digest before and after execution. It imports the unchanged `RawResetValidityMemory.forward`. It also inspected `RawDeltaMemory.__init__` in `p2_associative_memory.py` to verify that `address` is a linear map **without a bias**, and `gate_channels` in `p2_round2_raw_tokens.py` to cover the ordinary, HCSN, and mapped Put+linear parameterizations. Dependency digests are recorded in `autograd_evidence.json`.

Instrumentation wraps `hard_event` and `F.normalize` with observers that return the original output tensor unchanged, and adds recording hooks to the address and readout modules. All observers are restored after each forward. There is no forced event, custom backward, replacement model forward, optimizer, dataset generation, or trained checkpoint in this probe. Diagnostic coefficients and two token embeddings are assigned directly and explicitly, without fitting; their resulting learned-event probabilities are then checked.

## 1. Forward and immediate backward calculation

Use `r` for the hard reset event, `w` for the hard write event, `s=1-r`, incoming matrix `M`, validity vector `v`, previous token embedding `p`, and current value vector `z`. Let `A` be the bias-free address map, and let `eps=1e-8` be the actual normalization floor. The frozen code is exactly:

```
M0 = s M
v0 = s v
k  = normalize(A(s p), eps)
a  = s w
M+ = M0 + a (z - M0 k) k^T
v+ = v0 + a (1 - v0^T k) k
read = M+ k
bound = (v+)^T k
```

At the hard-forward point `r=1`, all of `s`, `k`, `a`, `M+`, `v+`, `read`, and `bound` are zero. The preserved state is `(0, 0, current, 0)`, as intended by the conditional erasure contract.

For finite inputs, in a sufficiently small neighborhood of `s=0`, the normalization floor is active and

\[
k(s)=s h,\qquad h=A p/\varepsilon.
\]

The updates are then

\[
M^+(s)=sM+s^2wzh^\top-s^4w(Mh)h^\top,
\]

\[
v^+(s)=sv+s^2wh-s^4w(v^\top h)h.
\]

The two query outputs become

\[
\operatorname{read}(s)=s^2Mh+s^3wz\|h\|^2-s^5w(Mh)\|h\|^2,
\]

\[
\operatorname{bound}(s)=s^2v^\top h+s^3w\|h\|^2-s^5w(v^\top h)\|h\|^2.
\]

Both derivatives with respect to `s`, and therefore `r`, are zero at `s=0`. The same result follows directly from the product rule: `d(M+k) = (dM+)k + M+(dk)`, with both forward factors zero. Derivatives with respect to the write event are zero because its only state effect is multiplied by `s*k`. The finite positive normalization floor makes the local derivative well-defined; this is not a singular zero-vector differentiation assumption.

`hard_event(q) = hard(q) + (q - detach(q))` gives a unit surrogate derivative from event to soft probability. Multiplying that unit derivative by the zero downstream derivative still gives zero. The sigmoid need not be saturated. In the FP64 immediate probes, the reset probabilities are approximately `0.92493069` for ordinary gating and `0.98071575` for HCSN/Put+linear, with strictly positive sigmoid derivatives.

### Consequence for known and unknown predictions

`bound=0` fixes the binding logit to `12*(0-.5)=-6`. Therefore

\[
P(\mathrm{UNKNOWN})=\sigma(6)=0.9975273768433653,
\]

\[
\sum_{j\in\mathrm{known}}P(j)=\sigma(-6)=0.0024726231566348.
\]

UNKNOWN is necessarily the argmax, regardless of the readout class prior. For a known target `y`, the exact-arithmetic loss is

\[
L_y=\operatorname{softplus}(6)-\log P(y\mid\mathrm{known}),
\]

so the binding contribution alone is `6.00247568513773`. For an UNKNOWN target, the exact-arithmetic loss is `softplus(-6)=0.00247568513773`. Floating arithmetic may introduce small normalization roundoff, but cannot recover a core gradient across the exact zero products.

The task signal itself is present: in a representative FP64 known-target probe, `dL/d(binding_logit)=-0.9975273768433652` and `dL/d(read)=[-0.1711884672964426, 0.29544908599436687]`. They are cut off by the zero factors further upstream.

## 2. Exactly which paths vanish

For a loss evaluated only at a query with `r=1`, in this frozen forward:

| Path | Immediate query-loss gradient | Reason |
|---|---:|---|
| Current hard/soft write event | 0 | Effective write and read address both vanish |
| Current hard/soft reset event | 0 | Both read and binding are zero-factor products |
| Controller layers, channel weights and biases | 0 through this query | Their outputs enter only the event paths |
| Address and value maps | 0 through this query | No surviving first-order read/binding path |
| Embeddings and earlier recurrent state | 0 through this query | The query has no additional direct token path |
| First readout linear weight | 0 at zero read | Input to this weight is exactly zero |
| First readout bias | May be nonzero | It changes the class prior at zero input |
| Final readout weight and bias | May be nonzero | They also change the class prior |

In the actual probe, all non-readout parameters are connected in autograd and return tensors of exact zeros; they are not mislabeled unused inputs. The first readout bias, final weight, and final bias have nonzero gradients. The final bias's maximum absolute gradient is `0.7087051350789729`.

If **every supervised query of a batch** takes hard reset 1, and the loss is only the frozen model's query-answer loss, adding those losses preserves zero gradients for the whole non-readout core. Unsupervised intermediate states do not independently supply a loss. This is a conditional batch statement, not proof that all future batches or optimizer states remain in that regime. Other batches, future non-reset queries, explicit additional objectives, or existing optimizer momentum may move parameters. No such extra objective is executed by this review.

## 3. Why a later query can still help

Although the current output Jacobians vanish, the persistent-state Jacobians do not. Holding the current event coordinates independent, at `r=1`:

\[
\frac{\partial M^+}{\partial r}=-M,\qquad
\frac{\partial v^+}{\partial r}=-v,\qquad
\frac{\partial\mathrm{older}^+}{\partial r}=-p,\qquad
\frac{\partial\mathrm{previous}^+}{\partial r}=0.
\]

The derivative of the current key with respect to reset is `-A p/eps`, not zero. In the synthetic example it is `[-60000000, -80000000]`; it cannot contribute to the current output because it is multiplied by zero matrix/validity values. All persistent-state derivatives with respect to the current write event are zero at this reset point.

A subsequent non-reset step can project those state sensitivities onto a nonzero read address. For a later loss `L`, the first reset event therefore has the surrogate gradient

\[
\frac{\partial L}{\partial r_t}
= -\langle\nabla_{M_t}L,M_{t-1}\rangle
  -\langle\nabla_{v_t}L,v_{t-1}\rangle
  -\langle\nabla_{\mathrm{older}_t}L,p_{t-1}\rangle.
\]

This is a gradient of the implemented STE computation, not the classical derivative of the discontinuous hard-event forward map.

A two-token run with actual events `[(write=0,reset=1),(write=0,reset=0)]` gives the following FP64 decomposition. The only supervised loss is at the second token:

| Contribution to first reset gradient | Ordinary, older-context controller disabled | Ordinary, older-context controller enabled |
|---|---:|---:|
| Matrix state | -0.005094357815502916 | -0.005094357815502916 |
| Validity state | 9.155540807761216 | 9.155540807761216 |
| Older contextual token | 0 | 0.005641249902590986 |
| Preserved current token | 0 | 0 |
| Total `dL/dr_first` | 9.150446449945713 | 9.156087699848305 |

The first write-event gradient remains exactly zero. The second write-event gradient is `-11.881942908943008`, showing an available path to correct a missing write on a non-reset query. HCSN and Put+linear have the same nonzero memory/validity route; with contextual feedback their first-reset gradient is approximately `9.154607888952144`, reflecting the gate parameterization's different context derivative.

The two steps were run both as sequential state-carrying calls and as one joined sequence; their checked output discrepancy is below `2e-6`. The split is only to expose the intermediate state for gradient decomposition. There is no detach between the two differentiable calls.

## 4. Executed evidence and limits

`review_autograd.py` runs these 36 deterministic synthetic cases on the frozen implementation:

| Cases | Modes | Dtypes | Count | Required observation |
|---|---|---|---:|---|
| One known-target query, reset=1, write=0 or 1 | Ordinary, HCSN, Put+linear | FP32, FP64 | 12 | Exact zero non-readout and current-event gradients |
| Three supervised known queries, all reset=1 | All three | Both | 6 | Exact zero core gradients for the summed batch loss |
| One known query, reset=0 | All three | Both | 6 | Nonzero core gradients, excluding a global-unlearnability claim |
| Reset followed by a non-reset query, contextual feedback on/off | All three | Both | 12 | Nonzero first-reset gradient and verified chain-rule decomposition |

All 36 cases pass. The no-reset ordinary FP64 control has maximum absolute core-parameter gradient `4.215679798552383`. The script uses the same cross-entropy form as the existing answer-training path, including its already normalized log-score input. It records every named parameter's gradient connectivity, exact nonzero count, maximum absolute value, and norm; event, address, key, read, binding, input-state, and intermediate-state gradients are retained as numeric arrays.

This is independent evidence for a mathematical failure mechanism. It does not estimate failure frequency, compare trained-model quality, replace the preregistered completion budget, or authorize changing a frozen experiment. Any redesign of read addressing, erasure ordering, gate supervision, or reset bias needs a separately registered follow-up. In particular, simply computing an old-state address before erasure would need a renewed finite-arithmetic safety analysis, because the frozen ordering was also introduced to avoid overflow before masking.

## Reproduction and files

```
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 \
/workspace/scratch/a20378baf59f/.venv/bin/python \
/workspace/scratch/4a81596942e6/p2-gradient-review/review_autograd.py
```

- `review_autograd.py`: executable source, with frozen-source checks and exact-gradient assertions.
- `autograd_evidence.json`: complete machine-readable 36-case evidence.
- `execution.json`, `execution.log`: actual command, runtime, exit code, stdout/stderr.
- `SHA256SUMS.txt`: digests of the review deliverables.

The JSON and digest manifest are read back after writing. The original P2 model source remains unchanged.
