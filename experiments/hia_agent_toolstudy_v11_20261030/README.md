# V11: one prospective Qwen3.5 candidate

This is an adaptive follow-up after the complete V9 and V10 failures. It keeps
the V9 task messages, task order, edit interfaces, validators, references,
hidden cases, output/history/native budgets and 3/3 qualification requirement.
It changes one model and its model-specific template binding. No earlier
capacity control or qualification grants V11 eligibility. No old result is
rescored, replaced or rerun.

The protocol is committed locally before any capacity or generation run.
It is **not publicly preregistered**. The integrated source commit that actually
runs must remain clean and unchanged through capacity, qualification and main.
An intermediate child-branch commit is not evidence of a later integrated run.

## Integrity review before any model execution

Independent review of the first V11 source found that runtime helpers could
establish an arbitrary initial hash baseline, and that exceptions in final
identity or shutdown checks could prevent the terminal report from being
saved. These are repaired prospectively before any model load or generation.
The initial source remains in Git history; the actual later run must bind the
repaired integrated source and perform fresh controls.

`runtime.py` now enforces the exact server, tokenizer and all local shared
library members from the already pinned b11669 archive: 40 entries, consisting
of 30 regular files and ten symlinks. Independent and implementing reviewers
both rehashed the 17,851,611-byte archive and every selected member. Executable
roles, the complete companion filename set, regular/symlink type, link target,
resolved directory, payload byte count and SHA-256 must match. Python or an
arbitrary helper cannot establish a replacement runtime baseline. This does
not attest mapped libraries outside the archive: the system loader, external
library search, OS and hardware remain part of the trusted environment.

`accounting.py` registers engine counters and service records before identity,
close or evidence writes. Each finalization operation is isolated and timed;
failure or a returned false identity keeps the result incomplete. Per-phase
source/tool/model rechecks run independently, and terminal reports retain the
measurements even if a file disappears. CLI costs are retained in memory as
soon as each call starts, so a later receipt-file error cannot erase that call.
Main summarization uses the already frozen protocol, rather than rereading a
file whose failure was just reported.

Missing counters stay unknown. A validated terminal SSE receipt can retain
exact cost after response-file persistence fails, but it cannot turn that
failed submission into a model success or qualification. A usage record and
its duplicate terminal receipt are counted once. Incomplete streams retain
known input and output lower bounds with an unavailable total. Fault-injection
tests load no model and cover false identities, thrown identity/close errors,
deleted source/tool/model files, receipt persistence failure and partial SSE.

## Candidate and provenance

The measured artifact is **Unsloth's Q4_K_M GGUF**, not a Qwen-published GGUF or
an attested reconstruction of the original weights.

| Identity | Fixed value |
| --- | --- |
| Original model | `Qwen/Qwen3.5-4B` |
| Original revision | `851bf6e806efd8d0a36b00ddf55e13ccb7b8cd0a` |
| Quantization repository | `unsloth/Qwen3.5-4B-GGUF` |
| Quantization revision | `e87f176479d0855a907a41277aca2f8ee7a09523` |
| Filename | `Qwen3.5-4B-Q4_K_M.gguf` |
| GGUF bytes | `2740937888` |
| GGUF SHA-256 | `00fe7986ff5f6b463e62455821146049db6f9313603938a70800d1fb69ef11a4` |
| License declared by both publishers | Apache-2.0 |
| Runtime | llama.cpp `b11669`, commit `620d2225cc436ab0b001e3200e590e3b286ef9ab` |

The [official model card at the pinned revision](https://huggingface.co/Qwen/Qwen3.5-4B/blob/851bf6e806efd8d0a36b00ddf55e13ccb7b8cd0a/README.md)
reports LiveCodeBench v6 55.8 and BFCL-V4 50.3 for 4B. These publisher-reported
benchmarks justify testing a distinct candidate; their settings differ from
this fixed, small, non-thinking study. They do not establish proficiency with
Hepta's node contract or grant qualification. The selected quantization has
not independently reproduced those benchmark scores here.

The public Qwen organization index did not expose Qwen3.5-4B/9B GGUF repositories
at selection time; the two corresponding guessed official repository APIs
returned HTTP 401. The published original 4B safetensors total 9,319,828,096
bytes, which exceeds this host's available disk before conversion. The single
smaller quantization was selected prospectively, not by Hepta task outcomes.

`provenance/` retains the exact official config, tokenizer config, model card
and license; exact quantizer metadata/card; pinned llama.cpp model/tokenizer
source; acquisition receipts; and the V10 protocol/runner sources used for
comparison. Every provenance file is bound by the protocol and source snapshot.
The actual GGUF was downloaded once, checked against both published size and
SHA-256, and inspected only for metadata before source freeze. Download cost
was 41.630981373 seconds, separately retained; inference requests were zero.

## Template and tokenizer boundary

The official tokenizer config is 16,710 bytes with SHA-256
`316230d6a809701f4db5ea8f8fc862bc3a6f3229c937c174e674ff3ca0a64ac8`.
Its template and the actual GGUF template are **not identical**. The GGUF changes
the default thinking branch and a tool-argument rendering branch. The new
adapter sends the fixed `chat_template_kwargs: {"enable_thinking": false}`
option on every actual `/apply-template` request. It checks every rendering
against the pinned official plain user/assistant, non-thinking branch before
generation. No system message, task example, selected node or answer is added.

The native server's `/apply-template` endpoint calls its normal
`oaicompat_chat_params_parse` path at the pinned runtime. The inference method,
syntax-only grammar, SSE validation, output budget and cost accounting are the
unchanged V8 implementation. There is no change to `/completion` generation
fields. The empty think block is part of the model's published non-thinking
generation suffix and is charged as input tokens.

Only the existing `[user]` and `[user, assistant, user]` history shapes are
allowed. Official outer-whitespace trimming is checked as model formatting;
the complete raw messages and output remain separately retained. An assistant
response containing `</think>` is refused before another request because the
official reasoning parser would remove part of that complete prior response.
This refusal keeps all prior cost and never repairs a candidate answer.

Capacity requires all 19 real native/reference/resource/terminal-hidden
controls, all 76 complete rendered-message checks, and **95 independent CLI
token-ID comparisons**. The CLI uses `--no-escape`; reference responses also
use `--no-bos`. It compares the actual GGUF's tokenizer with the same pinned
runtime's independent executable. This does not prove upstream vocabulary or
quantization equivalence. No generation endpoint is called by capacity.

## Resources and execution order

The GGUF has `qwen35` architecture, 32 blocks with eight full-attention blocks,
and 24 gated-delta recurrent blocks. b11669 includes that architecture's actual
implementation. This source support is not a substitute for loading and
validating the exact artifact.

At the unchanged 8,192-token context and one slot, an architectural estimate
is 268,435,456 bytes of f16 attention KV and approximately 52,690,944 bytes of
recurrent/conv state. Weights plus these buffers and estimated process/scratch
space suggest approximately 3.6–4.6 GB of RAM. This is not a measured peak or
hard bound. The host has about 10.45 GB total RAM and no swap; parent regression
must finish before any model load. Disk reserve after download was
1,423,552,512 bytes. No vision projector is needed for these text-only tasks.

Run only after the integrated source is frozen and the parent grants the
resource window:

1. Actual runtime preflight and 19 capacity controls, no generation.
2. If all capacity controls pass, one fresh three-task Rust-node qualification
   with unchanged 1,536 output tokens, 8,192 context tokens, three submissions
   per cell, four threads, seed zero, greedy decoding and 900 seconds per
   request. Timeout ends that cell; no timeout retry of that same cell.
3. Run the unchanged 16-cell main only if all three qualification tasks pass
   and source/model/tools/capacity identities and complete token costs match.
   Otherwise retain all failures and demonstrate refusal before engine startup.

Unknown output usage stays unknown and makes the total unavailable. A summary
boolean cannot override missing usage, stale identities, a failed hidden gate,
or an unqualified model. Reference success is never model success. A failed
capacity or qualification ends this candidate experiment; no prompt tuning,
task substitution, candidate replacement or repeated model selection occurs.

All results are descriptive on a shared development host. Even full completion
does not prove general productivity, long-term maintenance, language soundness,
or a universal Hepta advantage. P7 is pending until actual execution records
exist; this source preparation alone does not complete it.
