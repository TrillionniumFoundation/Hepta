# Independent readout of Agent v3

These tools are outside the frozen evaluator source directory. They read the
retained evidence and perform **no inference, compilation, native execution,
candidate repair, or rescoring**.

## Final result

[`READOUT.json`](READOUT.json) is the compact integration artifact, schema
`hepta.agent.matched-v3.acceptance-readout.v1`. It records 16/16 cells attempted,
0 correct cells, 30 requests, 26 complete responses, and four timeouts. Both
family/stratum gates and the joint gate are false. The output token subtotal
10,953 is a lower bound; complete output/combined usage stays null. Input usage
is complete at 30,496 tokens.

[`RESULT.md`](RESULT.md) contains the matched per-language tables and
[`RESULT.json`](RESULT.json) retains all derived fields and 323 bound evidence
identities. [`DIAGNOSIS.md`](DIAGNOSIS.md) describes response behavior;
[`DIAGNOSIS.json`](DIAGNOSIS.json) also includes exact response text and native
compiler/admission diagnostics. Reference and hostile controls are not counted
as model answers. No old frozen result is changed.

`readout.py` checks registration/source identities, exact cell order, unique
request-to-transport binding, decoder envelope, token IDs and counts, raw and
parsed response equality, candidate binary hashes, public and hidden split
identities, provider contracts/call counts/arguments, and recorded aggregate
arithmetic. It recalculates the two preregistered stratum gates. Missing usage
stays unknown. Recorded absolute evidence paths are rebased strictly below each
original model root, allowing a lossless archive to be audited after extraction
to a different directory.

It also checks the registered protocol and fixture bytes, scheduled task/stratum
descriptors, submitted source against candidate source/Core, Core/object/binary
hashes, and native-observation binding to the exact compiled artifact. These
are audit checks on retained evidence, not a new compiler-correctness proof.

`diagnose.py` describes envelope compliance, unchanged provider/consumer source,
repeated responses, admission failures and public native failures. It preserves
the distinction between a profile refusal and incorrect executed semantics.
Rust source equality is whitespace-normalized; HIA equality compares decoded
function objects. These equalities are descriptive, not semantic proofs.

```bash
python3 -B experiments/hia_agent_matched_v3_readout_20261028/readout.py \
  --suite /path/to/losslessly/extracted/cohort \
  --output /path/to/new/readout
python3 -B experiments/hia_agent_matched_v3_readout_20261028/diagnose.py \
  --suite /path/to/losslessly/extracted/cohort \
  --output /path/to/new/diagnosis
```

Both commands refuse to overwrite an existing output directory. Native/model
artifacts and raw failures remain part of the original evidence. These tools
cannot turn a failed registered gate into a successful one.

`acceptance.py` assembled `READOUT.json` once, after both independent readouts
and lossless raw archives existed. It verifies the readout/diagnosis suite and
source identities, each audited evidence file against the current raw suite,
and archive-member identities against the audited model evidence. It preserves
the distinction between request time, native validation, boundary hashing,
reference controls, engine lifecycle, outer wall time, preparation, and archive
costs. Nested timing components must not be added again to outer process time.
Human labor, tool development, and money remain unmeasured.

Independent review of these presentation scripts identified missing stale-data
rejection checks before the final readout was generated. Those checks were
added here; the frozen evaluator and model observations were untouched. The
final audit, diagnosis, and compact assembly each passed on their first actual
execution. All source identities in the registered closure remained unchanged.
