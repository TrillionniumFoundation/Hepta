# HCSN P2 Iteration 40 — a second, independent obstruction to two-state MQAR

**Research Draft only; all P0–P6 OPEN; `production_activation=false`.** No change to signature, FinalUse or main. Source fork at #512 head `38603831fceb606c85b2c373de5e379d49fb567f` (revalidate HEAD before committing).

## Precise, limited claim

Take an episode with `k` independent fair binary values written under fixed, value-independent timing. After the entire write stream, a keyed query `J` is selected uniformly and revealed. The only write-dependent quantity the decoder can observe is a **single terminal two-state mode** `S ∈ {0,1}`. Query index `J` is observed; past event times, count/history, analog weight/caches, write-dependent clocks, and other storage are *not* observed. This deliberately includes arbitrary optimal stochastic two-state CTMC write gates and perfect zero-hazard blank retention, because any such terminal state is still just one bit.

Let `X∈{0,1}^k` be the written vector. Any deterministic mode decoder is specified by two k-bit reconstructions `u` and `v`, one per state. For fixed `u,v` the optimal encoder chooses the closest codeword in Hamming distance. If their Hamming distance is `d`, exact mean per-query success is

`1/2 + E[|Binomial(d,1/2)-d/2|]/k`.

Since symmetric random-walk absolute deviation is nondecreasing in step count (by conditional Jensen), the optimum uses `d=k` complementary prototype strings, implemented by a majority encoder. Thus the exact globally optimal random-query success is

`A_k = 1/2 + [sum_{j=0}^k binom(k,j)|2j-k|] / [2 k 2^k]`.

Stochastic encoders/decoders cannot exceed a deterministic extreme point for this linear expected-reward problem. For answering **all k queries** from the same terminal state with no fresh information, at most two complete output vectors are possible; exact whole-vector accuracy is at most `2/2^k` (capped at 1). More generally `M` terminal states give a whole-vector cap `min(M,2^k)/2^k`.

This **does not apply to an HCSN with continuous analog memory, observable event history, multiple Cells, attention/KV cache, external state, write-dependent timing side channels, or a recurrent reader with access to stored content**. It is a counterexample to using the exact two-state Markov-renewal *mode alone* as sufficient state for scalable Selective Copy/MQAR, not a result about the original He–Xiong equations or global QVI.

## Independent execution and results

The closed-form binomial sum is implemented independently of an exhaustive decoder-codebook enumerator. All codebooks of length 1..6 are enumerated; exact rational fractions agree. Four independent majority-encoder Monte Carlo controls use 30,000 episodes each and seeds 11,23,37,41; each difference is within 1.12 normal standard deviations, not a scientific proof on its own.

| Values k | Best one-random-query accuracy (exact) | Best all-k-answers exact accuracy |
|---:|---:|---:|
| 2 | 0.750000 | 0.500000 |
| 4 | 0.687500 | 0.125000 |
| 8 | 0.636719 | 0.0078125 |
| 16 | 0.598190 | 0.0000305176 |
| 32 | 0.569975 | 0.000000000466 |

**9/9 local tests passed.** The independent `--strict` command was **actually run**, returned exit code `2`, and wrote byte-identical JSON to the nonstrict generator. This local mathematical verifier is *not* an external independent research attestation, and remains FAIL-CLOSED.

## Reproduction (Python standard library; no model weights)

From the repository root:

```bash
PYTHONPATH=research/hcsn python -m unittest discover -s research/hcsn -p test_p2_terminal_capacity_bound.py -v
PYTHONPATH=research/hcsn python research/hcsn/p2_terminal_capacity_bound.py > /tmp/hcsn40.json
cmp /tmp/hcsn40.json research/hcsn/gates/2026-11-05-iteration40-terminal-capacity-raw.json
set +e
PYTHONPATH=research/hcsn python research/hcsn/p2_terminal_capacity_bound.py --strict > /tmp/hcsn40-strict.json
code=$?
set -e
test "$code" -eq 2
cmp /tmp/hcsn40.json /tmp/hcsn40-strict.json
(cd research/hcsn && sha256sum -c gates/2026-11-05-iteration40-SHA256SUMS.txt)
```

The SHA list covers source, independent enumerator tests, raw JSON and logs; the report itself is hashed there too. No Full HCSN, P1 fair FLOP, P3–P4 encoder/heldout, P5 energy/p95/p99, or P6 medium-scale acceptance follows. All prior positive narrow submodel results and negative results from #468/#481/#486/#503/#512/#513/#526/#527 must be preserved unchanged. In particular the iteration 38 exponential blank leakage is a **distinct** loss mechanism: this new capacity obstruction still holds under ideal zero-leak retention.
