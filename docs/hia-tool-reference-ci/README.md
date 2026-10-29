# Native reference CI on the current unified source

`tools/qualify_hia_agent_tool_references.py` runs the **existing 19 human
reference responses** against the current checked-out Core and real structured
edit adapters. It has no model, server, or tokenizer argument, starts no
inference process, and performs no tokenizer capacity check. Its distinct
receipt schema is `hepta.agent.real-node.native-references.v1`.

The wrapper leaves every existing V8 experiment file and protocol unchanged.
It reuses the registered cell order, source-derived queries, original reference
builder, `validation.evaluate`, and the existing `evaluator.execute`. The
three qualification fixtures and sixteen four-arm main fixtures retain their
original public and terminal hidden inputs, expected results, VM checks, and
native resource requirements. This checks integration with the **new recorded
source**, rather than relabelling the earlier `33c46cd` capacity/model evidence.

## Invocation

Run on a clean committed checkout, with output outside the checkout:

```sh
/usr/bin/python3 -B tools/qualify_hia_agent_tool_references.py \
  --output "$RUNNER_TEMP/hia-tool-native-references" \
  --clang /path/to/clang \
  --rustc /path/to/rustc
```

The existing native evaluator requires its normal Linux file-seal support and
working compiler toolchains. No GGUF, inference runtime, tokenizer executable,
LLM environment variable, model download, or network request is required.
Existing shared utility imports are reused without starting their inference
engine classes.

For each registered cell the wrapper:

1. Checks the source and compiler/interpreter identity boundary.
2. Uses the actual session's query and existing complete human reference. It
   saves the complete query/reference input and hashes of the fixture, public
   cases, and terminal hidden cases before validation.
3. Passes the reference verbatim to the existing full/node validation path.
   It does not supply any model answer or repair a failed answer.
4. Runs the existing terminal hidden native/resource evaluator only after an
   accepted, actually compiled reference has passed the public native, artifact,
   resource, and VM gates.
5. Saves the actual public/hidden records, per-row source/tool identities, and
   result. An exception is a failed row, not a skip. Identity drift stops further
   work and lists the missing IDs. A post-execution identity read failure retains
   the already executed row while rejecting it.

Exit status is zero only for **exactly all 19 registered rows, all passed, with
source and tools unchanged**. The source identity includes the existing study
dependency set plus this wrapper and its mock tests. The tool identity binds
the actual Clang, Rust compiler, Python interpreter, and `fcntl` implementation.
These file identities are not hardware or complete operating-system attestation.

## Output and interpretation

`PLAN.json` binds the clean source commit, source snapshot, protocol, tools,
exact cell order, and fixture input hashes. Each cell retains `INPUT.json`,
the unchanged validator's candidate/build/public files, `TERMINAL_HIDDEN.json`
when eligible for that execution, and `ROW.json`. `REFERENCES.json` keeps all
actual rows, errors, missing IDs, counts, identity results, and whole-run time.

Every receipt explicitly records:

- `model_requests = 0` and `tokenizer_invocations = 0`;
- `agent_successes = 0`;
- `capacity_qualified = false` and `model_qualified = false`.

Even 19/19 native reference successes cannot satisfy V8's model qualification,
authorize the four-arm model main, demonstrate tokenizer capacity, or establish
Agent productivity. The positive controls are engineering evidence for the
recorded integration source. They are not a performance experiment, a language
soundness proof, or a result on the user's physical `dot` machine.

## Local verification scope

`tests/test_hia_agent_tool_references.py` contains pure mock boundary tests.
They cover the complete existing 19-cell registry, missing cells, verbatim
reference forwarding, failed-build/public gates, hidden resource/artifact
failure, whole-run failure accounting, source drift, post-row identity read
failure, and refusal to write CI output into the clean checkout. Mock executions
explicitly disallow subprocess creation.

Those tests validate wrapper orchestration only. They cannot be reported as
19 native successes. The actual compiler/native reference executions are left
to the remote CI run on its exact committed source.
