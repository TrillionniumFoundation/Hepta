# Read-only audit of the three-arm Agent study

This directory is outside the frozen v4 evaluator. Its scripts do not generate
model answers, alter submissions, compile programs, rerun native candidates, or
change the registered scores. `readout.py` reconstructs costs and descriptive
gates from the retained suite and the exact independently frozen source snapshot.

```bash
python readout.py \
  --suite /absolute/extracted/agent-suite \
  --snapshot /absolute/extracted/frozen-source \
  --output /tmp/new-readout-directory
```

The audit checks exact scheduled descriptors and model families; source,
protocol, registration and tool bindings; owned-process shutdown and cell
boundary identities; raw, parsed and returned completion consistency; token
budgets and complete-versus-unknown usage; public-only second-attempt feedback;
submitted source, canonical Core, object and final executable identities; and
the registered arithmetic, provider and call-argument requirements. Admitted
assembly is reparsed with the exact frozen frontend solely to check its
source-to-Core identity. No VM or native program is executed by the audit.

The two representation arms use the same canonical Core and evaluator. The
readout separately recomputes assembly-versus-Rust and assembly-versus-JSON
gates for maintenance and API upgrade. Duplicate cells, foreign model/source
identities, missing boundary costs, or unknown token totals cannot produce an
advantage claim. An absent or inconsistent evidence file rejects this readout;
it does not create a model success or a repaired observation.

`archive_evidence.py` archives original bytes with a complete per-file manifest,
then reads every archive member back and rejects any source drift. Absolute
paths inside original receipts remain unchanged; the readout rebases only paths
under their exact recorded model root, which supports auditing an extracted
archive elsewhere. Model weights and the third-party runner are identified by
their pinned hashes and retained preparation receipts rather than included in
the experiment archives.

## Reconstructing the published raw archive

The original `raw-suite-01.tar.xz` is distributed as two exact byte parts because
its single-blob publication returned a transport error. The source archive is
unchanged. [ARCHIVE_PARTS.json](ARCHIVE_PARTS.json) records each part's length and
SHA-256, their order, and the original complete archive identity. No observations
were rewritten or omitted. Run this from the repository root with a new output:

```bash
python experiments/hia_agent_assembly_v4_readout_20261030/join_raw_archive.py \
  --output /tmp/agent-raw-suite.tar.xz
```

The utility verifies both parts and all 16,332,396 reconstructed bytes before
publishing the output without replacing an existing file. The complete SHA-256
must be `813bb5dcb8f33ea1f28b8734ef3af5028c58124b666773c4f6b1d735f3a1c306`.
[ARCHIVE_RECONSTRUCTION.json](ARCHIVE_RECONSTRUCTION.json) retains the successful
actual byte-for-byte reconstruction check. These distribution costs are separate
post-experiment work and do not revise the registered model costs or results.

## Interpretation limits

Reference controls, hostile controls, tokenizer capacity measurements, mocked
orchestration controls, and readout controls are not model completions. Missing
timeout output counts remain unknown; retained server progress lines are not
substituted for a complete usage receipt. A lower known subtotal cannot pass a
token-efficiency gate.

Model outer intervals contain control reruns, identity hashing, server startup,
restarts, inference, validation and shutdown. Their nested subintervals are
reported for attribution and must not be summed again into the same total.
Parallel downloads also cannot be added as elapsed wall time. Human engineering
time and complete economic cost remain unmeasured. Four arithmetic tasks and
two small quantized model families do not establish large-project productivity
or general language superiority.

The full source snapshot may contain unrelated files that differ from the final
published repository tree. The registration binds the 31 actual study
dependencies; it records its modified base commit and does not claim that the
entire snapshot is the final published tree. The preceding v3 negative study is
retained without rescoring.
