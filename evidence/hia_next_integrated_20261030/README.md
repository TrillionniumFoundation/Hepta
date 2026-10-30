# Exact-source next-stage delivery

The implementation actually exercised by the complete remote CI and the fresh
focused experiments is **44e34b7a9ecd6bf1b3ad6093d21bba10d2a18304**, tree
**835555fb35dbdcf867724ef7a0bb1a6616270217**. The implementation branch stays at
that commit. This separate delivery branch adds documentation and inert evidence.
Its commit is not relabelled as a new execution of the compiler or experiments.

Read [the Chinese report](../../docs/HIA_NEXT_STRICT_RESULTS_20261030.md) and
[RESULT.json](RESULT.json) for the actual stage decisions. **The user's full
P0–P7 conditions are not all met.** Current full CI passes; the P4/P5 net-benefit
gates remain false, and the P7 model prerequisite is 0/3 with main refused.
General source/native refinement, whole-language safety, broader Rust authority,
general C++ migration and general dynamic recovery remain unproved.

## Review entry points

| Package | Contents |
| --- | --- |
| [Current and historical CI](../hia_next_ci_20261030/README.md) | Three official ZIP/API records, per-method and per-harness readback, exact current-source qualification |
| [Finite Rust resources](../hia_next_resource_20261030/README.md) | Current 116 Rust tests, 51 focused methods, 296 Rust processes and bounded logical payload profile |
| [Migration and execution context](../hia_next_migration_context_20261030/README.md) | Real changed-body stb upgrade, source/readback fixes, 46 context methods, historical foreign failures |
| [NDU study](../hia_next_stb_ndu_20261030/README.md) | Both actual full studies, the original analysis failure, closed-ledger repair and negative economic observations |
| [Real model followup](../hia_next_agent_v12_20261030/README.md) | Public decoder, 19 capacity controls, all nine raw model responses, complete known usage and actual main refusal |
| [Root readback](root-readback/FINAL_RESULT.json) | Readback after copying the exact 117 frozen package files; initial CI invocation path error preserved |

The 4,266 Python methods, 1,846 critical methods and 447 matrix selectors overlap;
do not sum them as independent coverage. The 116 Rust tests appear in 21 result
blocks: 20 Running harnesses and one Doc-tests harness, including zero-test blocks.
Historical package wording such as “21 binaries” is preserved as originally
written; the raw Cargo transcript determines this precise denominator.

## Pure offline checks

From a repository or ZIP root, the delivery inventory can be checked without
executing any compiler, archive program or model:

```sh
python3 -B evidence/hia_next_integrated_20261030/verify_delivery.py --root .
```

`DELIVERY_FILES.json` covers all new package bytes, root review records and both
delivery documents, except that self-referential inventory itself. For an
externally pinned check supply `--manifest-sha256` from the post-publication
receipt. The verifier only proves inventory consistency and the recorded false
claim flags; it does not authenticate an arbitrary manifest or rerun experiments.

Each package README supplies its separate bounded, standard-library verifier.
Choose a new output path when running it; preserve original verification files.
For CI use absolute paths for `--pins` and `--manifest` unless running from that
package directory. The root's original wrong relative-path invocation, traceback,
source and 36,241,913 ns cost are preserved alongside the successful followup.
All six root readbacks together took 3,478,709,197 ns and produced no new native
test observations or model answers. Packaging/readback times are separate from
application timing and do not represent full human or Agent development cost.

## Reproduce the implementation

For full regression or new native/model experiments, checkout the exact
implementation commit in a separate checkout and follow its pinned workflow and
the original PLAN/protocol inside the relevant package. The recorded CI used
the actual toolchain, Linux seals and independently pinned NDU inputs; a local
environment missing them is not equivalent. The large model/toolchain payloads
are not duplicated in this source delivery. Their hashes, origins, actual
parameters and reuse boundaries are retained in the evidence.

The current full run is
[41061115481](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41061115481).
The official ZIP is retained locally with its official SHA-256, so reviewing
the package does not depend on future Actions artifact retention.

## Publication and history

`source-publication/` preserves the original source transfer attempts and
receipts, including the old workflow-permission rejection and the subsequently
authorized publication through the existing GitHub connector. No credentials or
repository permissions were changed. Receipts that observed CI in progress are
historical snapshots; the final CI API and ZIP records live in the CI package.

`work/hia-p0-p7-integrated-20261030` remains the tested implementation branch.
`delivery/hia-p0-p7-44e34b7-20261030` is its documentation/evidence child. The final
remote ref/tree and downloadable ZIP identities are recorded after publication
outside this self-contained commit, avoiding a self-referential commit identity.
No main-branch merge is part of this delivery.
