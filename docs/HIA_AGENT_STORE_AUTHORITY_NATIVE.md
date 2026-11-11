# AgentStore reference and profile authority in HIA

This candidate adds an explicit `HEPTA_HIA_AGENT_STORE_AUTHORITY_MANIFEST`
selection to ordinary `AgentStore.put`, `_ref`, `get`, `resolve_uri`, `profile`
and `check_profile`. The old six methods are retained under `_reference_*`
names. Their complete ASTs, including decorators, are unchanged except for the
names. `json` and `get_json` keep their existing calls through the ordinary
entry points. No default selection, deletion or deployment is part of this
change.

## Authority and external operations

The HIA continuation chooses the actual SQL query and parameter graph, handles
the absent-row branches, compares issued references and expected profiles,
enforces retained artifact kind, selects the file publication/read route,
constructs new IDs/URIs and profile records, and decides when metadata may be
decoded. It constructs small output and SQL parameter graphs in its own arena;
the bridge only materializes the specified nodes and original foreign values.
Builtin structural/scalar comparison uses the existing HIA equality kernel.
Opaque leaves keep explicitly requested Python rich comparison and truth
observations, including their exception and mutation behavior.

`resolve_uri` deliberately does not introduce a URI grammar. The existing API
looks up the exact value through SQLite and accepts only a retained issuance.
Unknown values, SQLite binding errors and invalid artifact bytes retain their
original ordering. A spelling alone never grants authority.

The following owners remain external and are not claimed as native here:

- `keys(ref, ...)` retains the existing exact-dict/set/foreign-key field-shape
  admission before the artifact lookup.
- SQLite executes the selected SQL. Locking, transactions, schema, persistence,
  crash durability and concurrency remain in SQLite and the existing host.
- File operations use the separately selected artifact publication owner when
  present. Its unselected immutable-file writer and stable reader remain
  hosted, including race verification, cleanup and filesystem exceptions.
- JSON codecs, bounded wire and SHA use their existing independently selected
  owners. This change does not force their selectors or pre-encode arguments.
- UUID, attributes, item access, method dispatch and opaque object callbacks
  remain real foreign observations at the point requested by HIA.

The bridge retains real method dispatch for nested `_ref`, `get`, `json` and
`get_json` calls. Each ordinary entry observes its own explicit selector; no
Python-computed authority result is passed to HIA as a decision table. A
selected missing or mismatching image fails without entering a retained method.

## Protocol and limits

`HIASTA02` has a fresh zeroed private workspace, a bounded initial packet and
sequence/opcode-bound continuation acknowledgements. Every foreign request is
consumed before performing the operation. Repeated observation, continuation
after a foreign exception, and continuation after a terminal/refused result
are rejected without repeating an effect. SQL success acknowledgements are
created only after the real operation returns. There is no finally stage that
can manufacture a successful journal or file result after an exception.

The existing 64 MiB artifact and independently applied JSON limits are not
expanded. Initial development hit the compiler's existing 2048 value-slot
bound in a literal initializer; the original refusal is retained. The corrected
generator splits only the same ordered literal stores across small HIA helpers.
It uses the original compiler and profile.

The shared comparison transport has the same explicit foreign-extension
limits as the worker owner: arbitrary CPython recursive-resource exhaustion
thresholds are not equivalent to the iterative HIA walker, and an interpreter
without stored-hash dictionary iteration cannot support arbitrary foreign keys
without adding a visible hash callback. These are unclosed extension domains,
not evidence of whole-store or all-Python-input replacement. Object allocation
identity, finalizer timing and adversarial mutation of private bridge state are
not covered by the ordinary builtin/ref/profile contract.

## Qualification status

The branch starts at `f6893c2691e4038f924e44950c4ced845532ad0b`. Development
source was copied and independently checked against every one of its 1664
non-experimental/non-review-evidence Git leaves. This is explicitly a partial
development source population, not a complete Git checkout or cold identity.
The development compiler is the existing `0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8`
image. Reusing that compiler does not qualify the new source.

Development revision 4 has an actual native compile and 15 complete dedicated
test methods: independent Core execution, six unchanged retained ASTs, real
SQLite state/trace/reopen comparisons, publication routing, profile numeric
and foreign comparison controls, transactional and nontransactional failures,
one-shot protocol controls, exact 64 MiB admission, and an actual wheel child
under `-I -S -B` with an empty PATH. The installed child uses the packaged HIA
resource, forbids all six retained owners and checks the installed identity.
The tests record complete loaded/executed IDs, zero anomalies and source/image
identities; this remains CPython 3.12 development evidence.

Two actual counterexamples were found after the first ordinary successful
comparison and retained separately. Revision 2 omitted one repeated row SHA
observation before the hosted stable read. Revision 3 bound several foreign
callables and path attributes after argument observations, whereas the original
Python expressions bind them first. Revision 4 restores those observation
points and versions the callback protocol as `HIASTA02`. Its dedicated suite
includes both counterexamples. The original compiler refusal and both failed
comparisons are not relabelled as passes.

`tools/qualify_hia_agent_store_authority_callers.py` runs the original five Agent
modules without exclusions, forbids all six retained store owners, records
every actual native mode and original Agent tool call, and requires nonempty
identical loaded/chosen/executed IDs and no failure, error, skip, expected
failure or unexpected success. Tools which do not perform store operations are
reported separately; they are not assigned invented store entries. The strict
cold path builds from the complete matching source closure and retains its
build when `--evidence-dir` names a new directory. The explicit development
path cannot be relabelled as qualified cold.

The first selected caller run completed all 67 inherited/original test IDs in
the five modules. It recorded one error because a declared historical GGUF
provenance input was absent and one skip because pinned Z3 was absent. Those
original observations remain a failed development gate. All eleven Agent tools
entered the native store, but those original modules do not call `resolve_uri`;
their test count is not presented as URI coverage.

The next development candidate adds a separate mandatory real SQLite URI
control without changing the original loaded test IDs. It compares issuance,
known and unknown URI lookups, exact bytes, SQL traces, artifact metadata and
close/reopen state while the selected side forbids all six retained owners.
Its closure includes the generator, HIA source, bridge, builder, oracle fixture,
dedicated tests and caller driver. The profile label is
`selfhost-core-linux-x86_64-v68-agent-store-authority-development`; existing
compiler limits and capabilities are unchanged. The 23 omitted declared
historical files were hydrated from exact canonical Git leaves, and Z3
`4.15.4.0` was installed into a private development environment before another
caller run. This is still a partial development source population.

The updated caller and URI gates have not executed at this source checkpoint.
No complete equivalence, matching-source cold, complete regression or native
durability pass is asserted.
