# HIA Agent edit context v2: explicit branch consequences

`hepta.hia.edit-query.v2` and `hepta.hia.edit-batch-query.v2` extend the
existing snapshot-bound editor. Core instruction semantics, patch permissions
and mandatory whole-module verification are unchanged.

The v1 value-only context could display a changed branch condition but omit
both successor bodies when the condition was not an explicit block argument.
For example, changing `compare.lt` to `compare.gt` can swap two constant
returns without propagating any changed SSA value into either successor.
Displayed terminators could also reference an omitted independent producer.

The v2 view now closes every displayed terminator's value inputs. It follows
explicit SSA argument flow as before. When an affected value controls a
branch, it additionally includes **all operations** in both reachable
successor regions, including no-result stores and resource cleanup. A region
may include blocks after reconvergence: this is a conservative reachability
view, not a precise control-dependence proof or an inferred memory-alias graph.
The `control_reachable` Boolean records that distinction independently of
`affected_params`.

Downstream cycles use a monotone fixed point. A cycle reaching the selected
block rejects the compact view and requires full-module context. The shared
limits are 256 displayed operations, 64 blocks including the selected block,
and the existing bounded JSON byte/node/depth admission. Oversized regions
reject; no truncation is represented as a complete context.

Atomic batch rendering deduplicates overlapping regions and retains every
site. Application reconstructs all queries from the same immutable program
before applying selected fields and revalidating the final whole module.
Old v1 queries are rejected explicitly; clients regenerate a query against
the desired source snapshot. Historical v1 experiments remain historical
evidence and are not relabeled as v2 experiments.

Run the executable regression controls with:

```sh
python -m unittest tests.test_hia_edit_control_context tests.test_hia_edit_query \
  tests.test_hia_edit_cfg_context tests.test_hia_edit_batch \
  tests.test_hia_cfg_render_convergence tests.test_hia_context_render_input \
  tests.test_hia_cli_seven_stage -v
```

The controls exercise the existing Core verifier and interpreter, actual
branch-result changes, owner cleanup, atomic two-site edits, stale snapshots,
old-schema rejection, forged flags and both operation/block limits. They are
mechanism tests; no real-model productivity result or source/native refinement
claim follows from context completeness. Alias effects, interprocedural
behavior, general task usefulness and whole-project qualification remain open.
