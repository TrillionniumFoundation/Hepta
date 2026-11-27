# Reconstructed Store source history, 2026-11-27

This commit reconstructs the missing admission relation from exact Git source
bytes at ce0267659487d202056e32f0f0713dec32b7772d,
e0cf34e25a37eb14447e402c062c660b482d77f2, and
72740bdbc2e755e3f1c087327854cc2b6b390f4e and their recorded predecessors.
Every complete old and new source was independently checked against its
previously recorded SHA-256. git-source-inputs.json retains each exact input.

The earlier local-only commits 060099 and 699626 and their 2cc18f2a fixture
were unavailable when this work ran. This is a new v2 relation, not a claim
that those Git objects, fixture serialization or earlier execution logs were
recovered. The new 22718-byte fixture has SHA-256
2d32911a179bc7e2b00865d07985844018011d7f9a69f9ba7a84f839290118ff.

The data-only inverse resides in tools/hia_frozen_component_sources.py and
imports no product, builder, oracle or test helper. Qualification accesses the
same code through tests/hia_store_source_history.py. It binds five complete
files, both new dependencies, both exact moved function bodies, the selected
capture root, and terminal rereads. The actual reviewed_source entry rejects
a reverted Evaluation test mixed with current production sources; neither a
hash fast-path nor a caller-selected temporary root can bypass that check.

The original b332 composition admission was executed from its exact Git source
and refused the current later composition; that original failure is retained.
The reconstructed admission then passed the original three Store source tests,
both complete caller terminal admission methods, both complete independent
readback source methods, and sixteen new focused negative/positive controls:
23 unittest methods, zero failures and zero skips. The original 89-file Store
inventory, 21 definitions, original fixtures, caller lists and budgets were
unchanged. Existing component_authoring_history inversion remains in place.

These are source admission results. The actual 112-method native caller run,
its new native-v2 data-only readback, and whole-product closure are not claimed.
