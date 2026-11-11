# HIA ordinary request-journal owner

This explicitly selected component moves ordinary request-journal decisions
into executable HIA. It does not replace SQLite, the full AgentStore, or the
eleven business-method implementations. The retained call owner remains the
default until a separately qualified installation is explicitly selected.

The checked-in source is **examples/hia_bootstrap/agent_journal.hiaasm**,
authored by **tools/generate_hia_agent_journal.py**. It composes the existing HIA
JSON arena, exact binary64 canonicalization and SHA-256 algorithms. There is no
generated lookup table of past requests or Python-computed replay decision.
**hepta/hia_agent_journal_native.py** owns executable/buffer custody, foreign
Python values and the mechanical SQL bridge.

## Ownership

| Operation | Owner in the selected path |
| --- | --- |
| Original tool/arguments canonical bytes and request SHA-256 | HIA |
| Known tool admission and original request identity | HIA |
| Top-level key admission and canonical key/tool SHA-256 | HIA |
| Digest conflict before state inspection | HIA |
| Reserve, completed replay and nonterminal unknown decisions | HIA |
| Successful hia_verify replay route | HIA |
| Cached JSON grammar, hierarchy, syntax reasons and status routing | HIA |
| Cached BLOB UTF-8 validation, first error span and reason | HIA |
| Cached scalar values, lazy selected float conversion, Python objects | Foreign value bridge |
| Response and cost-details canonical bytes and write instructions | HIA |
| Transaction begin/commit/rollback, SELECT/INSERT/UPDATE and clocks | Hosted SQLite bridge |
| Resource URI authority and alias argument expansion | Existing service/store |
| Schemas, installation/context/budget checks and business methods | Existing owners |
| Verification replay evidence checks, slot/lease semantics and migration | Existing owners |

The HIA key limit is 1–192 Unicode codepoints. It is intentionally checked
before the catalog's full schema and regular expression. A key that is later
rejected by the schema still claims its original arguments. A changed retry
cannot turn that rejected claim into a new effect. Resource aliases retain
their original request digest; their cost tool name changes to hia_read only
after alias expansion succeeds.

## Ordinary transaction order

The host supplies actual observed row columns. HIA decides whether the row is
absent, conflicts, can replay, or has an unknown result. For an absent row,
the bridge inserts running intent, then sends HIA a reservation acknowledgement
after SQL reports success and before COMMIT. That ordering preserves the
retained implementation's behavior if COMMIT subsequently fails.

Completed replay returns the fully materialized cached value. It does not
reexecute the business method or update the request. Successful replay does
not add a cost row. A verification replay first checks the retained evidence
through the existing verification replay gate; a failed gate can record a
rejection cost, as in the retained implementation, without replacing the
original completed request.

Adopt/rollback keeps the effect and completed response UPDATE inside one
SQLite transaction. HIA emits the exact response bytes. After UPDATE succeeds,
the bridge sends a response acknowledgement before COMMIT. If COMMIT reports
an error after rollback, the running intent remains unknown. If COMMIT actually
succeeded but acknowledgement was lost, the original completed response stays
replayable even when the first caller observed a rejection.

A newly introduced native protocol or buffer-custody failure is a separate
fail-stop boundary. The bridge does not call the failed image again and does
not write a terminal response or cost. If this happens during an atomic effect
transaction, SQLite rolls the effect back; an already committed running
reservation remains unknown. Missing cost evidence is not a measured zero
cost and does not establish complete accounting.

The same fail-stop applies to non-domain exceptions throughout the call,
including KeyboardInterrupt, SystemExit and MemoryError between a successful
SQL operation and entry into its acknowledgement helper. The bridge preserves
the original exception and does not enter the image from finally. Ordinary
domain refusals and SQLite error responses retain their prior framing and
transaction behavior. Every exception from an empty acknowledgement phase
is a protocol failure, since that phase has no payload rejection domain.

Every phase acknowledgement is checked by HIA. Repeated, premature and
out-of-order acknowledgements refuse. A reservation acknowledgement is issued
only after an observed successful SQL INSERT; a response acknowledgement is
issued only after an observed successful SQL UPDATE.

## Raw protocol

The entry point has the existing three-buffer native ABI:
agent_journal(input:readbuf, output:mutbuf, workspace:mutbuf) returns u32.

| Stage | Input | Result |
| --- | --- | --- |
| 0 | Original request JSON | Continue, key lookup, resource alias or refusal |
| 1 | Actual digest/state columns, or null | Reserve, cached response or refusal |
| 2 | Empty; successful SQL INSERT observed | Reservation acknowledgement |
| 3 | Cached response JSON | Replay, verification replay or root-type refusal |
| 4 | Empty; alias expansion succeeded | Continue as read while preserving original identity |
| 5 | Empty; existing business gates succeeded | Ordinary or atomic effect |
| 6 | Completed atomic response JSON | Journal UPDATE instruction when reserved |
| 7 | Empty; successful response UPDATE observed | Response acknowledgement |
| 8 | Terminal response JSON, or empty | Cost/journal instructions, or no writes |
| 9 | Exact installed catalog bytes | Bind the catalog SHA embedded in HIA |
| 10 | Original cached SQLite BLOB bytes | UTF-8 admission, or exact byte span and codec reason |

The session's 512-byte state is private to one call. The image carries it
between phases; the host does not synthesize digest matches or replay states.
State cannot be supplied through ordinary tool arguments.

The Python-call boundary additionally supplies raw builtin type tags for a
tuple-valued tool argument, because JSON itself erases tuple/list distinctions.
HIA uses these facts to distinguish an unknown hashable tuple from its first
nested unhashable list or dictionary. The bridge does not call Python hash or
perform tool membership. Non-TEXT SQLite columns carry their actual storage
class as foreign observations; HIA owns the resulting conflict/unknown choice.
The HIA refusal distinguishes a directly unhashable key from a tuple containing
the first unhashable component. Foreign exception framing follows the actual
interpreter's dict-key wording (independently exercised on Python 3.12 and
3.14); it does not perform another hash or membership test in the bridge.

The raw JSON profile is 8 MiB, 262144 nodes and depth 128. The ordinary
interpreter's integer conversion limit is supplied as a profile observation.
All finite binary64 values use the composed HIA conversion/printing kernels
for identity and terminal canonical bytes. Cached numbers are materialized in
source order by the existing foreign conversion bridge, preserving lazy
converter selection and conversion-error priority.

Stage 10 is a codec check before JSON size admission, so it can inspect a BLOB
larger than 8 MiB without consuming the JSON arena or node budget. This preserves
the original decode-before-size error order. The bridge constructs a
UnicodeDecodeError from HIA's start, end and reason; it does not decode or scan
the input. For cached grammar refusals, the image composes the shared HIA
preflight reasons with the complete HIA lexical number projection. When that
projection repairs an invalid original number, HIA also supplies the original
grammar reason, Unicode character offset, line and column; the bridge only
constructs the existing foreign JSONDecodeError object. The independently selected Agent-data
arena retains its distinct generic-error and size-before-codec profile; the
operator's selector is a raw protocol observation, not a parse decision.
Explicit Agent-data and preflight images are readmitted at cache consumption,
after the prior codec/size guards and before grammar, even when the argument
snapshot already admitted them. Mid-call manifest, image, source or selector
changes retain the selected loader's custody rules. An unchanged manifest key
can retain its already admitted immutable mapping when the backing image file
changes; this is the previous loader behavior, and cached replay still costs
nothing. A changed manifest image reference must undergo fresh hash admission.
The controls distinguish that replay from an actual admission rejection and
check both response contents and whether a cost row was written.

Response and cost-details output each have their own 8 MiB channel. Their
combined size is not subject to a new 8 MiB limit. This avoids narrowing the
retained service's separate serialization operations. Header extents, flags,
stage actions, immutable identity, input bytes and output/workspace canaries
are checked before any returned instruction is used.

Clock observations are passed directly to SQLite as their original decimal
TEXT. Request start and cost wall-clock fields are not narrowed to a machine
integer.

## Selection and installed identity

**HEPTA_HIA_AGENT_JOURNAL_MANIFEST** selects an operator-owned manifest with
schema hepta.hia.agent-journal-native.v2 and state magic HIAJRN02. The common immutable image loader
checks the manifest shape, exact source SHA and image SHA. HIA then hashes
and checks the actual installed catalog bytes on every selection, including
warm-cache selections. A selected source/catalog/image admission failure does
not fall back to the retained call owner.

The generated source is included in the native source resource list and
MANIFEST.in; installed implementation identity therefore includes the adapter
and HIA source. Installed operation does not import checkout tools or search
an unrelated checkout for missing resources.

The build function in tools/build_hia_json_preflight.py accepts the candidate
name agent-journal and builds only from a complete matching-source cold report.
A compiler with the same executable hash from an older source tree is not a
new-source cold qualification. Development reuse is recorded separately and
is insufficient for promotion.

## Independent regression and current limits

**tests/test_hia_agent_journal_native.py** separates source/Core-VM tests from
actual native tests. Native tests require either
**HEPTA_HIA_AGENT_JOURNAL_COLD_REPORT** or the explicitly development-only
**HEPTA_HIA_AGENT_JOURNAL_DEVELOPMENT_MANIFEST**; supplying both refuses.

The tests compare independent JSON/SHA oracles; exact ordinary rejection
responses and request/cost rows against the retained owner; Unicode key and
finite-number boundaries; actual artifact effects, restart and no-effect
replay; a real killed process; real SQLite COMMIT failures; protocol failures
before/after acknowledgements, including BaseException subclasses; exact
cached syntax, UTF-8 BLOB, numeric, type and selector behavior;
buffer canaries; maximum-size separate output channels; and installed wheel
source/catalog binding with tools and the retained call owner forbidden.

**tools/qualify_hia_agent_journal_callers.py** separately forces the selector
through existing Agent service, proof, lease, machine-choice, campaign,
native candidate and both ordinary worker request suites (eight modules).
It forbids the retained call owner, records actual native stage
returns, requires all eleven tools to enter the selected driver, and reports
all loaded, chosen and executed test IDs, failures, skips, expected failures,
unexpected successes and explicit development exclusions. PASS requires a
nonempty chosen set, exact execution count and ID sequence, all eleven tools,
and no failed, skipped or expected-failure outcomes. Cold runs cannot
exclude tests. It does not relabel the ordinary default regression as
selected-owner coverage. Subprocesses inherit the selector; their native
entries are not silently counted as parent-process observations.

Detailed syntax and byte-codec error controls compare the full returned wire,
cost rows and unchanged cached data to the retained owner. These finite
controls do not constitute an all-input equivalence proof. Development image
results are bound to their exact source/image digests and do not replace a
matching-source cold build or the ordinary default regression.

The remaining state migration includes durable artifact/reference namespace
ownership, context and budget transitions, slot/version/lease state,
multiwriter arbitration, crash recovery/compaction and deployment promotion.
SQLite still provides the durable transaction boundary. No old implementation
or stored data is removed by this change.

For the executor-loss and reconstructed-source provenance, see
**HIA_AGENT_JOURNAL_RECOVERY_WIP_20261111.md**. Historical lost-image
observations must never be transferred to the reconstructed bytes.
