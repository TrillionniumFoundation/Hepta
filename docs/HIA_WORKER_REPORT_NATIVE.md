# HIA worker control, report and multi-image custody candidate

This candidate is not a wholly native worker. Historical upstream development
observations below are not matching-source qualification of this tree.
The standalone lower-level report loader accepts
`HEPTA_HIA_WORKER_REPORT_MANIFEST`; the ordinary worker deliberately rejects
ambient executable selectors. It requires BOTH administrator options:
`--native-helpers-manifest worker-v2.json` and
`--expected-native-helpers-sha256 <exact-sha256>`.

The v2 top-level schema is `hepta.hia.native-helpers.v2`, with exactly
`schema`, `target`, `abi`, `helpers_bundle`, `helpers_bundle_sha256`,
`report_bundle`, `report_bundle_sha256`. Target and ABI are unchanged from v1.
The pinned helper child uses the ORIGINAL v1 single-image format and must
include the native worker-request image. All 24 old helper contracts and their
factory guards remain unchanged. The report child pins BOTH source-bound
policy and generic JSON-wire manifests and their exact bytes. The operator
may compose them using `tools/build_hia_worker_report.py --helpers-bundle ...`;
this builds a pin but never activates a service.

The bridge captures ordinary, non-symlink, bounded files using the existing
owner/permission/identity guard. Both new companion manifests, sources and
images are validated before their mappings. Images come only from captured
bytes; runtime loaders reuse exact registered factory/source/schema keys.
Selection, file, PID/thread and complete environment restoration guards remain
in force. The report's optional `native_helpers_sha256` is now constructed in
HIA from the adopted installation identity, in its original tenth position.
Missing helper identities retain the lower-level nine-field profile.

Pure lower-level policy differentials intentionally do not enter main's custody
or its outer exception handler. They are NOT ordinary worker acceptance.
Separate ordinary-main and installed-wheel tests use the actual request,
policy and wire images through a real pinned v2 scope. The original main
parser, custody entry and terminal error handler remain unchanged.

The HIA policy drives mode checks, administrator pins, service construction and
call/close sequencing, complete post-call manifest comparison, exception
correlation, UNKNOWN routing, callback order, Unicode message slicing, report
field access, virtual report construction and final output. The generic HIA wire
owner sees the entire report, including all parent dictionaries, in one graph.
The host never builds a report dictionary or encodes the response separately.

The Python boundary supplies exact builtin type, length, identity, child,
codepoint, integer magnitude and IEEE observations. It also performs explicitly
requested IO, attribute access, calls and opaque leaf comparison. CPython raw
dictionary iteration and known-hash lookup preserve stored key hashes when that
runtime observation is exported. A build without it uses public `PyDict_Next`
and pure exact-builtin hash observations for str/bytes/int/float/bool/None keys.
It refuses other key types without invoking an additional foreign `__hash__`.
Neither observation decides manifest equality. Stateful foreign
callbacks remain foreign effects and their order is controlled by HIA.

Request admission retains its existing independent selection point after stdin.
`HEPTA_HIA_WORKER_REQUEST_MANIFEST` selects the existing native request owner.
When that selector is absent, `_reference_admission` is an explicitly retained
request validator. Installation IO and hashing, service methods, SQLite journal
durability and the external runtime process owner remain outside this candidate.
The native formatter selector is captured and admitted at the original final
wire entry point. Arbitrary untrusted observers or corrupted private
continuations are outside the native ABI trust boundary.

## Protocol and preserved order

The policy entry uses `HIAWKR02`, a 112-byte initialization packet and sequenced
continuation replies. Replies have eight unsigned 64-bit header slots, followed
only by the requested codepoint/magnitude chunk or stored dictionary hash. The
program checks opcode, sequence, error tag and exact packet extent before
consumption. Each string/magnitude observation is at most 1024 words. The
workspace is private and initialized by the adapter; arbitrary corrupted
continuations and fabricated object facts are not an untrusted-input sandbox.

HIA also chooses the active handled-exception handle for every foreign effect.
The adapter temporarily activates exactly that object, restores the raw
traceback and ambient context-chain links altered by activation, and restores the caller's prior
handled-exception context after the effect. This keeps `sys.exception()` and
the actual exception chain visible during close and error callbacks. An UNKNOWN
replacement changes the reported exception value, while the original handled
exception remains active until the handler ends. Final report construction and
wire encoding run after that interval. Version 1 lacked this preservation; its
eight original context counterexamples remain evidence, not passing controls.
The first version 2 adapter also lost a foreign callback's ambient-chain
mutation when CPython broke a cycle during the next activation. Four actual
ordinary-worker counterexamples are retained separately. The corrected bridge
snapshots raw links with identity-based cycle detection and restores them
before the requested callback, never after it; real callback mutations and new
traceback frames therefore remain observable.

Native virtual handles occupy the high half of the unsigned 64-bit namespace.
HIA owns their kind, pair table, UTF-32 literals, slices and concatenations.
Foreign values retain their original low handles, so sharing and cycles are not
lost during transport. Python can materialize native scalar text for requested
attribute names and text IO, but cannot materialize a virtual dictionary.

The policy keeps initial installation observation outside the protected worker
region; checks administrator worker/backend/catalog pins before stdin; marks
service entry immediately before resolving and calling `service.call`; and
closes the service after either a successful call or an exception. A close
exception overrides the pending call exception. Only successful call and close
permit the final installation observation. A changed complete manifest is
adopted before stale/UNKNOWN routing. Report catalog identity remains the
request value, while worker/backend identities use the adopted manifest.

Correlation checks exact dictionary type and presence of the four original
fields without reading their values. An entered-service exception is replaced
with UNKNOWN before reading any of its properties. Otherwise the error callback
order is UUID, code, message, retry; slicing is by 4096 Unicode codepoints,
typename fallback is untruncated, and report fields are read after those
callbacks. Uncorrelated empty messages remain a single stderr newline. Error
callbacks, report graph validation and output IO remain outside the original
catch region. The caught classes remain ValueError/OSError/TypeError/
OverflowError/RecursionError; other exceptions propagate after required close.

## Development checks and unresolved scope

The dedicated development runs exercised 17 distinct test methods: 13 methods
in one source/native run and four additional composition/SQLite/wheel methods.
Both runs had zero failures, errors or skips. They cover independent Core VM
execution of the virtual report, actual native byte/order comparisons, 160
seeded numeric/container comparisons, effectful leaf/key observations, 35
foreign exception location/class controls, callback mutations, 4095/4096/4097
codepoint boundaries, complete report byte/node/depth budgets, protocol
refusals/canaries, source/manifest rebinding, independent request selection,
actual SQLite close/reopen replay/conflict/running UNKNOWN, and an actual wheel
ordinary entry with no authoring import or retained report owner. These are
development controls, not matching-source cold or whole-project qualification.

Native fixture output normally uses an automatically cleaned temporary
directory. `HEPTA_HIA_WORKER_REPORT_FIXTURE_EVIDENCE` instead names a new
create-only directory which remains after success or failure. It retains the
matching-source build when selected, request composition image, SQLite state,
manifest binding fixtures, built wheel and extracted installation. The wheel's
reproducible source/build staging copy is still removed before extraction to
limit disk use. An externally selected development bundle is referenced rather
than copied. The source-only negative builder's temporary directory and the
independent VM child's in-memory state are not included in this fixture tree;
their test output must be captured by the caller.

One concrete extension-domain mismatch remains open. The current native frame
budget comes from `sys.getrecursionlimit()`, which is not CPython's builtin
comparison C recursion budget. On the observed CPython 3.12.14 build, with that
limit set to 1000, independently constructed extension lists at depth 1000
compare successfully in the retained worker but reach the candidate's native
frame limit and return UNKNOWN. Depths 128, 500, 700, 749, 750, 900 and 999 matched
in the retained observations. CPython's separate C recursion/stack policy must
not be replaced by a guessed version table or a hosted whole-manifest fallback.
Ordinary `installation_manifest()` returns exactly three hash strings and does
not produce this extension shape. Arbitrary foreign recursive resource
exhaustion is explicitly not closed, and this candidate does not claim all
Python graph resource behavior to be equivalent.

The observed pinned CPython 3.14.4 build does not export private `_PyDict_Next`.
The adapter therefore uses public iteration for its ordinary string-key
manifests. Foreign dictionary keys on a runtime without stored-hash iteration
are a second explicit unsupported extension boundary; the adapter propagates a
profile RuntimeError before additional foreign hashing or report output. This
is not represented as equivalent to successful retained comparison. An
independent control checks both the public builtin path and this refusal even
on a runtime where private iteration is available.

The public-iterator change has three focused local controls and nine actual
CPython 3.14.4 controls using the transferred worker policy/wire images and
source subset. The latter reused a separate, read-only 416 source tree for
foreign service/store dependencies; all uploaded pins and that tree's HEAD
remained unchanged, and the remote job exited 0. This is a portability witness,
not a complete checkout or installed-wheel qualification on that interpreter.
Exact logs, uploaded bytes and terminal process receipts are retained under
`experiments/hia_worker_report_development_20261111/portable-r2`.

The builder's `--development` mode records `DEVELOPMENT_ONLY_NOT_MATCHING_SOURCE_COLD`.
Production qualification must use `--cold-report` for the current source closure.
No deployment, default selector activation or deletion of retained owners is part
of this feature checkpoint.
