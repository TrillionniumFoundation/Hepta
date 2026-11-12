# Independent guarded optimization review

No false-verification P0/P1 was identified in `hia_inductive.py` and
`hia_guarded_optimization.py`. Admission binds the full base and fast Core; the
only allowed delta is a same-position unsigned checked-add to wrapping-add.
The independent checker discharges guarded entry, every CFG edge and each
removed-check obligation at its actual position. Successful resource/call scalar
outputs are fresh typed unconstrained values; prior scalar traps remain in the
path condition. The complete original fallback is canonically regenerated.
Native publication rechecks composed identity, artifact bytes and checker/solver
identity before and after publication.

Two actual short counterexamples are retained in `guarded_counterexamples.json`.
An unrelated `n <= 16` guard cannot bound an effect-produced `buffer.len`; the
checker finds the possible `length + 1` overflow and rejects. Valid input names
`gf_x` and `x` collide under the current clone prefix. Composed Core independently
rejects the duplicate SSA name before proof (zero solver obligations). This is a
fail-closed naming/support boundary, not incorrect acceptance.

The separate near-zero runtime accounting regression uses a controlled clock
only to exercise the policy threshold. It is not native execution or performance
evidence. The real native owned-state qualification remains separate.
