# Adaptive full-cost candidate reuse follow-up

This separately registered experiment follows the complete negative study at
`c9954b70afbe03d23b682aeef28c41057d8d52b1`. Its independent `byte_sum`
controls showed finite delivery savings that did not recover candidate
preparation. Selecting that kernel and a longer reuse horizon after seeing
those observations is adaptive. A different held-out seed does not make this
an unbiased confirmation. The earlier failures and negative results remain
unchanged, including the absence of measured NDU incremental value.

The new fixed horizon repeats `[4093,4093,4093,4093,4093,4093,127,4097]`
32 times, producing exactly 256 deliveries in each fresh session. This fits
the existing 256-execution owner bound without raising any production limit.
It includes repeated guard fallback. All nine episodes use seed 197 and 65,535
native calls per delivery. Three cyclic Latin groups compare baseline,
guarded and guarded+narrowed images.

Every episode freshly proves, builds and seals its baseline. Candidate arms
additionally use the original independent candidate proof and native-build
path. There is no receipt import, candidate-result cache or new NDU decision.
The production `hepta/` implementation is unchanged. The same scalar ABI,
sealed driver, lease checks and independent checksum oracle remain in use.

Preparation, proof/build/sealing, text inspection, execution, checks, evidence
writes and cleanup are included in the episode wall time. The report splits
these costs and separately shows nested driver time. Source/tool admission,
driver build, dispatch and final identity costs are charged once per
standalone strategy. Earlier receipts account for 199.343918199 seconds of
build/study/diagnostic work; that amount is retained separately and included
in the cumulative tracked cost. It is not represented as every development,
download, approval or archival cost.

Each candidate must beat the paired complete baseline cost in **all three**
groups, after all correctness, identity, fresh-proof, native-text and release
gates pass. A favorable mean cannot hide a nonpositive pair. Both candidates
must pass for the overall cost gate. No sample is removed. The fixed horizon
will not be adjusted again after these observations; a new negative result
ends this follow-up as negative.

```sh
python tools/qualify_hia_candidate_amortization.py \
  --output /absolute/external/new-amortization-run \
  --prior-cost-audit /absolute/ndu-four-arm-host-20261030.ARITHMETIC_AUDIT.json \
  --clang /absolute/clang --objcopy /absolute/objcopy
```

The collector requires committed clean source and writes registration before
any native build or delivery. Performance execution requires the separately
arranged quiet measurement window. The protocol is frozen before that run.
Even a positive finite result is a small-kernel reuse observation, not a
legacy-application win, statistical significance, universal compiler
superiority or NDU benefit. Authority remains `DENY_ALL` and
`safety_certificate=false`.
