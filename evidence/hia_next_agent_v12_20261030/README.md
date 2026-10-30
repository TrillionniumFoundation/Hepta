# P7 V12: complete same-source capacity, failed calibration and actual main refusal

This package records the actual V12 campaign on clean source commit
`44e34b7a9ecd6bf1b3ad6093d21bba10d2a18304`, tree
`835555fb35dbdcf867724ef7a0bb1a6616270217`. V12 is an adaptive follow-up on the
same tasks and model after the retained V11 failures. It is not a new independent
holdout, a successful Agent productivity comparison or a qualified main study.

## Observed results

Capacity passed 19/19 authored reference controls, with 95 actual independent
CLI tokenizer calls, including 76 complete rendered-request checks. Capacity
submitted zero generation requests. These references are capacity controls,
not model answers or model task successes.

The actual pinned model then attempted all three Rust-node calibration tasks,
three attempts each: **0/3 tasks correct, nine requests and nine responses**.
Raw SSE events, observed output token IDs, per-request usage and the attempt
ledger agree on **21,025 input + 2,279 output = 23,304 tokens**. Unknown-usage
requests, human answer repairs and terminal hidden evaluations were all zero.

All nine model outputs conform to their retained public JSON schema. This is
only the decoder-envelope result. The actual whole-candidate gates observed:

- Scalar arithmetic task: one real compiler rejection, then two wrong results.
- Two-file signature task: three rejections for types outside the disclosed
  scalar/Vec<u8> grammar.
- Owner-flow task: three rejections for trailing tokens outside the selected
  fragment.

These are not the earlier V11 extra-field errors. Decoder-format compliance did
not establish syntax, type, owner, resource or functional correctness. The
complete public editable-node catalogue remained in the decoder; reference
answer nodes and replacement values were not selected for the model. Actual
SSE answer text equals the captured answer, and the host-wrapped edits equal
those model edits, with the captured query and revision bound to each attempt.

The real main CLI was invoked and returned 1 with
`E_TOOLSTUDY_NO_QUALIFIED_MODEL`. It created no main output directory, constructed
no main engine and submitted no main generation requests or task cells. The
failed fresh 3/3 gate was not bypassed or inherited from historical results.
Capacity and calibration model services were recorded exited with complete
finalization. This does not attest to arbitrary escaped processes or a hostile
host.

## Identities and preserved context

The model is the same 2,740,937,888-byte Qwen3.5-4B-Q4_K_M.gguf, SHA-256
`00fe7986ff5f6b463e62455821146049db6f9313603938a70800d1fb69ef11a4`.
The retained runtime closure contains the pinned server, tokenizer and 38 shared
library names/payloads. The recorded engine lifetime inventories contain the
server plus those 38 companions; the CLI tokenizer is additionally bound by the
40-member tool inventory. These are payload/producer identity checks, not a
runtime-loader or hostile-host attestation. The model and runtime were reused;
there was no new download or restoration attempt in this V12 campaign.

Every outer stage retains raw Git source inventories before and after, with
6,685 files and the same commit/tree. Both capacity and calibration retain the
222-file experiment source snapshot and the fixed protocol bindings. The outer
launcher, its actual output, resource samples, model-service logs, tokenizer
receipts, SSE responses, failed candidates, compiler diagnostics and all
qualification results are included. Actual compiled candidate binaries are
retained as evidence; no model weights or system runtime binaries are copied.

`context/` retains development failures and corrected regressions, pre-run
independent review/source snapshots, and the independent Draft202012Validator
review of all nine actual output envelopes. `review/P7_PEER_REVIEW.json` retains
the independent read-only answer/query/usage/classification review. Neither
review generated model answers or reran the model.

`historical/V11_REFERENCE.json` records the original V11 archive and manifest
identities under `evidence/hia_agent_v11_integrated_20261030`. V11 acquisition
costs and failures retain their original source and evidence; they are not
repackaged, relabeled or promoted to V12 qualification.

## Cost accounting

The actual outer intervals are capacity 98.915811914 seconds, calibration
610.943766376 seconds and main refusal 5.167062658 seconds. Their sum is
715.026640948 seconds. Capacity inner 95.839747342 seconds and calibration inner
607.661534770 seconds are included in the outer intervals; do not add them again.
Outer intervals include raw-source preflight/postflight and stream identities,
but exclude final outer receipt serialization and shell startup.

Full human/Agent development and review cost remains unknown, not zero. Earlier
model acquisition cost remains in the original V11 archive. Archive compression,
packaging and each offline readback have their own retained actual receipts;
they are preservation overhead, not model-generation cost or productivity gains.
Both verifier versions and both actual successful readbacks are retained. No
verification failure was discarded, and these audits created zero generations.

## Portable bounded offline verification

From this package directory run:

```sh
python3 -B verify_evidence.py \
  --archive p7-v12-20261030.tar.xz \
  --manifest p7-v12-20261030.manifest.json \
  --archive-sha256 537e0a9da3d220fc1b745756c12031a4d4a171dc52848cd80661dfcd81025a0d \
  --manifest-sha256 2ee83396b3427254461ed5037e8693644315d3c21bc6a08af59bb42346946d2c \
  --output verification-new.json
```

The output must not already exist. On the qualified POSIX host the verifier
uses only Python's standard library. It opens each archive/manifest input once
with no-follow regular-file checks, reads bounded immutable bytes, hashes those
same bytes, and decodes that same snapshot using a 64 MiB XZ decoder-memory
limit. It does not reopen the archive for parsing. Compressed input is capped
at 64 MiB, manifest at 8 MiB, decoded tar/aggregate members at 256 MiB, individual
members at 16 MiB, member count at 4,096 and retained semantic text at 128 MiB.
These are parsing/framing limits, not a Python process RSS or CPU theorem.

The verifier does not extract or execute archived code, import the repository,
run a model/compiler/candidate, or use the network. It rehashes every member,
checks exact source/tool/runtime/protocol/query bindings and actual footer/SSE
usage, and verifies the public Rust response envelope against an independently
constructed all-editable-ID schema. This is a finite integrity/consistency audit,
not a proof of language safety, compilation refinement, general productivity or
the authenticity of a hostile producer. Native/type/owner/resource/functional
admission remain separate gates, and this evidence does not enlarge them.
