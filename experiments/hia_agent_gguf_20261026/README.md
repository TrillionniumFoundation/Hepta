# Owned GGUF HIA/Rust repair pilot

`inputs.lock.json` freezes the official model revision and CPU runtime archive
before inference. Download the exact URLs, verify byte length and SHA-256, and
extract the runtime into a new directory. Weights are dependencies, not Git
artifacts. The runtime records the actual executable and shared-library hashes
and rechecks them and the model after the run.

```bash
python tools/qualify_hia_agent_gguf.py \
  --binary /absolute/path/to/llama-server \
  --model /absolute/path/to/qwen2.5-coder-1.5b-instruct-q8_0.gguf \
  --model-sha256 507de59046601282ba768a9789900e6ccf60ed93ddf346730b7c68eb0715bc47 \
  --output-dir /new/output/directory \
  --clang /usr/lib/llvm-20/bin/clang \
  --rustc /absolute/path/to/rustc \
  --threads 4
```

All compiler sources must remain unchanged during the run. The protocol starts
its own offline inference process on a private Unix socket, verifies the peer
PID/UID on every request, and enables no generated execution tools. Generated
Rust is constrained to a finite single-site expression/function domain; HIA is
independently verified and the entire surrounding context must match the frozen
task. Every accepted candidate is compiled and executed against separate
arithmetic test oracles.

The plan is written before the first generation. Both exact-format eligibility
probes must pass. The four tasks compare HIA versus Rust and full-function
replacement versus semantic edits in a 2x2 design, rotating arm order and using
the same response capacity and two-attempt limit. Native positive and negative
controls must actually execute. A failed compile is not a passing negative
control. Timeouts, malformed responses, rejected repairs and wrong native
results remain in the record. Attempts with unknown token counts are explicitly
incomplete; they never have zero implied token cost.

The outputs retain model prompts, rendered templates, token IDs, native input
artifacts and binaries, execution output, and observed input/output token and
elapsed costs. Completion requests, received responses and validated model
runs have separate counters. The latter is what `actual_model_runs` counts.

This small pilot does not establish general coding success, independent task
families, human maintenance cost, overall development cost, or superiority over
Rust. Quantization, model choice, disclosed repair sites and the restricted edit
domain limit the inference. The older failed SmolLM2 preflight remains separate
historical evidence; it is not overwritten or relabeled.
