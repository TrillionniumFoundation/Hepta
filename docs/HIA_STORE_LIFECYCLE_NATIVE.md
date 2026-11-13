# Store lifecycle policy

An explicit `HEPTA_HIA_STORE_LIFECYCLE_MANIFEST` selects the complete original
`AgentStore.__init__` and `AgentStore.close` policy. Construction captures an
admitted image before the original lifecycle effects. The resulting Store keeps
that capability for close; a later selector change does not change its route.
An initially unselected Store continues to close through the retained original.
The public service uses these ordinary Store entry points without test patches.

The selected image owns the original branches, provider ordering, nested cleanup
handlers, error selection and close sequence. SQLite, filesystem operations,
CPython object and exception operations, and the four existing child owner
factories remain providers. This component is not a host-free worker.

The private per-instance capability is additional adapter state held in an
identity-indexed weak-reference table. It does not inspect or replace business
Store attributes and does not call a Store's hash or equality methods. The
table holds no strong reference back to the Store. Capabilities are not
reconstructed from dictionaries or proof evidence. The Service includes its
actual held capability in checker selection. A new Store performs fresh
manifest, source and image admission.

## Build and qualification

`python -B tools/build_hia_store_lifecycle.py --output OUTPUT --compiler B3
--cold-report COLD_REPORT` requires the complete matching cold source contract.
The original compiler-child limit remains 20 seconds, with 1 MiB workspace and
output. An explicitly requested development build or manifest grants no cold
qualification.

The component uses the environment prefix `HEPTA_HIA_STORE_LIFECYCLE` and exactly
one of `_COLD_REPORT`, `_DEVELOPMENT_COMPILER`, or `_DEVELOPMENT_MANIFEST`.
`_EVIDENCE` selects the parent evidence directory. Its complete native group is
`tests.test_hia_store_lifecycle_native.StoreLifecycleNativeTests`.

`python -B tools/qualify_hia_store_lifecycle.py --evidence OUTPUT --cold-report
COLD_REPORT --caller-group GROUP` retains the original `agent` 48, `namespace`
35, and `ledger` 48 groups, each with its original 1800-second limit and all
original test inputs and deadlines. They execute separately. The observer
poisons both retained policy methods and both fixed aliases in the test process;
child processes inherit the explicit selector.

The owner-local exception extension preserves nested handled exceptions and the
outer cleanup iterator. Original R1 failures and R2 development observations are
retained separately. Their success is not transferred to this production-route
revision. Default activation, current-cold qualification and full-stack native
closure require their respective actual gates.
