# Native multiversion runtime snapshot formatter

This component emits the complete public `ScalarMultiversionRuntime.snapshot()`,
`_cleanup_snapshot()`, path pin, retirement task, observation, directory cleanup,
and retirement error dictionaries from facts captured by their native owners.

It is a pure formatter. It performs no filesystem, loader, lease, publication,
or proof operation. A successful report is not permission to retry a failed
native release. The capture owner retains the live generation and pin owners,
takes the original selection lock, observes the actual directory, and supplies
the fixed producer records described in
[the ABI](HIA_MULTIVERSION_RUNTIME_SNAPSHOT_ABI.md).

## Runtime source closure

The runtime construction uses these three sources:

- `examples/hia_bootstrap/multiversion_runtime_snapshot.hepta`
- `examples/hia_bootstrap/multiversion_runtime_snapshot_packer.hepta`
- `tools/hia_multiversion_runtime_snapshot_bridge.S`

The two HIA sources are compiled by the existing native source builder. The
second HIA product consumes `HIAMVSPK`, three little endian u64 words
`(policy_flat_bytes, 0, 0)`, and the actual policy flat. It produces the complete
callable flat. There is no assembler, Python, Rust, or host formatter in this
construction path. The readable assembly records the fixed 175-byte mechanical
view and return adapter embedded in the HIA packer.

The development author embeds the qualified CPython 3.14 / Unicode 16 printable
table and the observed Linux C-locale errno strings in the HIA source. Neither
the table JSON nor a language runtime is read by the product.

## Behaviour preserved

Generations and cleanup `pending` are sorted by their full nonnegative integer
keys. Numeric comparison uses decimal length and lexicographic digits. A
bottom-up merge sort uses two u64 index arrays in the caller's private work
view. Duplicate captured keys are rejected.

`pending_identity_releases` follows the original pending dictionary's insertion
order, followed by the directory entry when it is pending. The two public
orders are intentionally different. Generations, epochs, active leases,
attempts, and disk attempts are emitted from their entire canonical decimal
strings. There is no new 64-bit integer, 128-generation, 128-pending, or aggregate
8 MiB limit. Only the two original recent-event histories have the original
128-entry maximum.

Both original reference and native decoder key orders are represented, including
the placement of errors relative to status and finished timestamps. Generation
information is the exact already-validated native information JSON, with the
original four snapshot fields appended. Caller-created opaque JSON does not
constitute an admissible production capture.

The formatter uses the captured query flags. It does not reconstruct a resource
release claim from an apparently closed descriptor number. Fenced records carry
the last attested header and the actual policy error; their flags remain those
returned by the owner. The current damaged state memory cannot replace that
header.

Filename bytes use UTF-8 with surrogate escape. Text uses UTF-8/WTF-8. JSON uses
the original ASCII escape form. Native errno errors reproduce the original
`OSError` subclass, errno, Python pathname repr, and message truncated to 1024
Unicode characters. Non-errno loader failures require the actual `dlerror`
message; a `dlclose` return value is never treated as an errno. Unknown or
uncaptured errors are not replaced with empty strings.

## Memory and return ABI

The callable product has the fixed six-word ABI
`(source, source_size, output, output_size, work, work_size) -> u64`.
Nonempty views must be valid, nonoverlapping spans without endpoint overflow.
There is no alignment restriction. Adjacent views and a zero-length output view
remain valid.

The work extent is at least 65536 bytes plus 16 bytes per member of the larger
generation/pending list. The first pass validates framed records, validates
text and decimals, orders keys, and measures the complete output. Output bytes
are written only after successful validation and sufficient output capacity.

The public return is the full JSON byte count, or:

| Return | Meaning | Work metadata |
| --- | --- | --- |
| `UINT64_MAX` | Invalid private capture or memory views | First capture offset/reason at 16/24 when available |
| `UINT64_MAX - 1` | Output too small | Exact required output bytes at 0 |
| `UINT64_MAX - 2` | Work too small | Exact work requirement at 8 when at least 16 work bytes exist |

All refusal paths leave output untouched. The original compiler accepts a u32
public policy return. The HIA policy therefore returns a private status and
writes the full length to work offset 0; the fixed mechanical adapter translates
the status or loads that full u64. The compiler's accepted profile is unchanged.
A native packed stub returning `2**32 + 5` confirms that the adapter does not
truncate successful lengths.

## Qualification and limits of this checkpoint

The adjacent JSON ledger binds the exact sources, policy, packer, complete
product, compiler, original oracle source files, and reports.

The qualification includes:

- Two source-bound native builds with byte-identical policy and packer outputs,
  followed by actual native packing of the complete product.
- 192 original retirement/error cases, including both reference/native dictionary
  ordering, every observed Linux errno 0–133, unknown and signed errno values,
  surrogate text, and truncation boundaries.
- 619 complete snapshot/cleanup and refusal cases against the original methods:
  actual original dictionary ordering, 257 generations, 137 pending tasks,
  100001-digit integers, a 9.5 MB event, exact work/output limits, malformed
  framing, duplicate keys, and poisoned/canary-protected buffers.
- 17928 actual native error-format calls covering all 1114112 Unicode code
  points, every raw byte, random invalid UTF-8, quote choice, and truncation,
  compared with the original `OSError`/repr implementation.
- Native packer, full-u64 return, unaligned/adjacent/zero-output views, overflow,
  overlap, and construction-capacity controls.
- Fresh real retirement-state transitions and filesystem observations, including
  open/fstat/lstat/unlink/close, failed acquisition, a nonempty directory retry,
  actual task retirement, and a state corruption followed by last-attested
  diagnostic output.

The pure formatter and its mechanical construction are qualified here. The
public MV runtime's lock-held capture, history retention, last-attested state
capture, live provider, and final installed dispatch still require their own
combined qualification. This checkpoint does not claim that those remaining
runtime components, the final aggregate cold gate, or production activation
have passed.

## Development reproduction

Set HIA_MV_SNAPSHOT_QA_ROOT to a new private output directory and HIA_MV_SNAPSHOT_COMPILER to the exact qualified 494833 native source builder. Run tools.build_hia_multiversion_runtime_snapshot, then the qualify_hia_multiversion_runtime_snapshot modules (base, full, unicode, views, controls). The state module additionally consumes actual-retirement-state.flat built from the frozen retirement_state.hepta for its original effect oracle. These Python modules are development qualification drivers only and are not runtime authority or production inputs. All original source hashes and retained reports are in the JSON ledger.
