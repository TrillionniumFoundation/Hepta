# Cross-file 2 × 2 pilot

See [the full design and protocol](../../docs/CROSSFILE_AGENT_EVAL.md).

```bash
python -m experiments.crossfile_eval verify
python -m experiments.crossfile_eval probe
python -m experiments.crossfile_eval qualify-fixtures --output fresh-qualification.json
```

There are five paired Rust/Hepta tasks and four arms. Qualification executes
trusted reference-edit scripts and native hidden tests; **it invokes no AI
model**. Provider runs require a frozen plan, exact model revisions, real usage
receipts and a working namespace sandbox. Missing, failed and timed-out cells
remain in the planned denominator. Human time without an observation is `null`.

The semantic-tool arms share function/body/declaration operations. Rust's
bounded token index is not a complete Rust AST; Hepta's study session is not the
durable production workspace v4. Reports state both limits explicitly.
