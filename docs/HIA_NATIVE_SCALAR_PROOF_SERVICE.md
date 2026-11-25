# Native scalar proof service checkpoint

This checkpoint implements a standalone native HIA proof owner for the original
primitive acyclic scalar profile. The service performs fresh structural Core
admission, canonicalization, exact public entry selection, graph construction,
bounded Boolean solving or exhaustive small word search, independent Core
counterexample replay, deadline checks, native closure identity checks and
receipt serialization. A mechanical assembly adapter only transports byte
spans and performs fixed Linux clock, mapping and standard input/output calls.

This is a qualified component checkpoint. The native general solver is not
connected in this image, and the full public proof API, call closures, bounded
recursive proof profiles, multiversion integration and final release admission
are still open. The receipt does not establish whole-language soundness,
machine-checked implementation correctness or execution authority.

## Private request and response

The process takes no command-line arguments. Standard input is one complete
private frame and then EOF. Successful protocol processing exits zero and
writes a single frame, including when the mathematical result is unknown.
Malformed private input exits 65 with no receipt; unexpected argv exits 64,
input extent overflow exits 3, and transport failure exits 74.

The request header is 64 bytes: `HIAMVP01`, mode, timeout milliseconds,
function-name bytes, before-Core bytes, after-Core bytes, zero, zero.
Each numeric word is unsigned little endian 64 bits. The tail is the exact
function name, before Core and after Core. Mode 1 is totality and requires
no after document. Mode 2 is translation and requires both documents.
Timeout is 1–60000 milliseconds; each Core is 1 byte through 8 MiB.
A nonempty function name is an ASCII Core identifier of at most 128 bytes.
An empty name requests the original single-function inference rule.

The reply header is 64 bytes: `HIAMVR01`, mode, result, JSON byte count,
elapsed proof nanoseconds, zero, zero, zero. Result is 0 unknown, 1 proved,
or 2 disproved. The remainder is one JSON receipt. This private frame is not
the user-facing Python-shaped API and is not accepted as prior proof evidence.

## Admission, order and evidence identity

Translation freshly admits and canonicalizes both documents before checking
either schema, selection or proof profile. Both schemas are checked before
default inference. Default inference requires one function in each document;
the before function's name must exist after. Public membership and exact
parameter/return types are checked before either function profile. The before
profile is checked before the after profile. Exact types distinguish usize
from u64 and isize from i64.

Original program/input hash fields bind canonical Core, as the original
primitive proof APIs do. Additional request hash fields bind the exact received
JSON bytes. The subject repeats the selected function and canonical hashes.
The checker identity names the actual complete embedded native ELF; a second
HIA SHA pass checks that identity at closure. The source-identity digest is
the SHA256 of its compact, sorted identity object. The service never reports
the development oracle or a missing external solver as the executing checker.

All proof phases share one monotonic deadline starting before admission.
Late completion and changed or unavailable closure identity clear proof claims.
This is cooperative stage checking and does not claim a hard process execution
timeout. A consumer must freshly bind and recompute at the point of use.

## Solver and replay

The existing fast graph, Boolean and small exhaustive-word engines keep their
original capacities. Structural nontrapping DAGs and exactly identical typed
graphs have explicit native methods. A fast-engine capacity refusal is not
promoted to an all-input proof. In this checkpoint cases requiring the separate
general solver remain unknown with an explicit unconnected-general reason.

A SAT model is first checked against the native word circuit and then replayed
through the separately compiled original Core projector and native Core VM.
Signed narrow arguments are sign-extended for the VM ABI while the word witness
retains its original bit width. First trap order, Boolean/unit values, casts,
checked arithmetic, joins and exact signedness are preserved.

The output reports only the selected primitive function and exact requested
property. It explicitly leaves backend refinement, resource bounds, universal
profile claims and implementation soundness unproved. Serialized receipts do
not authorize executable publication.

## Runtime components and storage

The eight embedded roles are: native proof policy, private nonalias SHA,
structural Core admission, canonical JSON, scalar graph/preflight, existing
CNF/word engine, original Core-to-reference-wire projector and native reference
VM. The native HIA packer binds those roles into the fixed adapter. There is no
Python, Rust, C or Z3 runtime fallback in the produced executable.

Private memory is a 256 MiB work mapping, 256 KiB response area and bounded
request area. Role views are disjoint where their ABI requires it. Canonical
JSON receives its original node/depth controls in work bytes 48/56, not output.
Selection records occupy independent work ranges so the second Core cannot
overwrite the first signature. The request and embedded image are read-only.

The author scripts and native build driver are development tools. The HIA
sources and mechanical adapter define the runtime. The accompanying JSON
pins source bytes, the actual native compiler, role images, final ELF and all
qualification reports; it does not activate this checkpoint.

## Qualification

- 16 original semantic tests made 113 actual standalone native calls, with
  independent original Core replay of every counterexample.
- 100 actual original-API refusal comparisons matched status, exact reason,
  function, structural verification and canonical hashes/claims.
- 197 actual HIA-role fault checks exercised malformed stage results,
  transport faults, selection and graph layouts, solver/replay failures,
  deadline expiry and changed closure identity.
- 66 process/private-ABI/native-packer controls covered malformed frames,
  capacity boundaries and byte-identical reconstruction of the full ELF.
- 376 independent SHA comparisons covered padding, random inputs, 8 MiB,
  canaries and invalid spans.
- The graph's separate record includes 477 sources / 2864 exact successful
  graphs, 31 refusals and 487 sources / 1463 exact selection-only records.

No test is described as a complete native runtime, full general proof profile,
cold release gate or final publication. Failed development reports remain
outside the source tree until final evidence custody and cleanup.
