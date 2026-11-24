# Native root Jobctl observation owner

The three HIA companions implement the original privileged Jobctl STATUS,
READ and CANCEL decisions, terminal evidence, retained scratch observation and
the private continuations used by START/PTY. The shared control, Request,
Record, process, atomic writer and final syscall adapter have separate owners.
This is a component contract; it is not a claim that the complete privileged
supervisor or the whole runtime has been qualified.

## Continuations and workspace

The observation entry has the shared six-argument HIA ABI: startup HIAARG02
bytes, a 128-byte mechanical plan, and exactly 128 MiB of owned workspace. It
returns action 1 for a requested Linux syscall, action 8 to advance the shared
control, action 9 for Record, action 10 for SHA, action 11 for process capture,
action 13 for typed terminal evidence, or action 14 for the Value companion.
An invalid observation returns action 0 to the shared failure path.

| State | Meaning |
| --- | --- |
| `w[0]`, `w[8]` | Current phase and previous mechanical result |
| `w[40]` | Original operation: 3 STATUS, 4 READ, 5 CANCEL |
| `w[48]`, bytes 8192 | Job ID length and NUL-terminated bytes |
| `w[56]`, bytes 8320 | Unit length and NUL-terminated bytes |
| `w[64]`, bytes 8704 | Owned registry job-directory length and bytes |
| `w[72]`, `w[80]`, `w[88]` | Log cursors and original read limit |
| `w[368]` | Existing public STATUS/CANCEL registry flock descriptor |
| `w[41440]` | START reuse; a Record has already been loaded |
| `w[52800]`, `w[52808]` | Private suboperation and return phase |
| `w[52816]`, `w[52824]` | Bound/present flag and nonempty InvocationID flag |
| `w[52832]`, `w[52840]` | InvocationID bytes within workspace and length |

Action 6 routes phases 200–299 and 400–699 to the observation owner. Suboperation
0 is the public operation or reused START status. Suboperation 1 queries original
systemctl properties without binding. Suboperation 2 queries and binds, including
the original first-bind atomic Record publication. Suboperation 3 performs the
internal PTY cancellation, reacquires the registry lock, and always resumes the
specified continuation, including failure; it writes no public response.

Internal cancellation replaces the loaded Record, so START freezes its original
reply before calling it. Bytes 104–106 MiB are typed Witness scratch during
terminal observation and the frozen START reply only after START has dropped its
original lock and will enter solely PTY wait or internal cancellation. CANCEL
does not write this range. The two uses do not overlap in the control flow.

The observation owns fields 56800–58000, response bytes 80–88 MiB, properties
buffers 88–96 MiB, raw receipt/witness/retained files 96–99 MiB, log/hash buffers
at 99 MiB, a property index at 108–112 MiB, and normalized Value bytes 114–118
MiB. Typed Record data at 118 MiB and START command/Spec areas are preserved.
Process-owned fields 51200–52748 and scratch 68–78 MiB are not retained across
process calls. The original 8192-byte stdin prefetch at 98304 is not overwritten.

## Typed terminal and Value companions

Action 13 receives the input offset and length in the plan. Its mode is
`w[54000]`: 0 decodes Exit, 1 decodes Witness, 2 checks capture consistency, and
3 projects required fields from an already canonicalized retained-scratch
Value. Result 1 means success; 0 means invalid. Mode 3 is only reachable after
the Value companion accepts the whole document.

Exit, Witness, OutputCapture and StreamCapture preserve both serde derive map
and positional sequence forms. Known duplicate map fields remain errors.
Required fields, trailing defaults, exact integer ranges, enum forms and
IgnoredAny handling retain the original distinctions. An unknown typed field
can be ignored even when the same bytes would be invalid in a known Value field.
The retained-scratch check is a whole Value object check, so it does not acquire
the positional struct behavior.

Action 14 is the same six-buffer pure call used by canonical JSON. The derived
`system_jobctl_value.hepta` shares the algorithm in
`generate_hia_mcp_canonical.py` (requires the Value fix 80e3a019). It has an
8 MiB output and a 37,765,240-byte workspace for 524,289 nodes. The caller places
mode 0 or 1 in the first output word: mode 0 preserves the 126 remaining serde
container levels inside typed Exit, and mode 1 preserves the 127 levels of a
whole retained Value. Duplicate decoded keys use the final value; overwritten
values still undergo complete validation. The original 1 MiB file metadata
bound and applicable +1 growth-byte behavior remain separate from this arena.

## Preserved behavior

STATUS observes owned terminal evidence before boot and process state. It
observes again after the systemctl probe, before propagating a probe or first-bind
publication failure. A terminal receipt published during that probe takes
precedence. A missing path and a path whose parent is not a directory remain
different observations. Versioned unreadable/invalid receipts and absent or
mismatched witnesses remain pending; they do not become missing or successful.

READ retains original cursor checks, 1–16384-byte page limits, UTF-8 replacement
text, exact lowercase byte hex, absent-log rules and witnessed capture lengths.
It does not copy a confirmed Exit's scratch_cleanup field into a read reply.
Retained scratch is negative evidence only, including when output logs reach EOF.

CANCEL checks boot identity, unit description and InvocationID, preserves the
first-bind write, calls fixed `systemctl stop -- UNIT`, then atomically persists
the cancelled launch state. It does not substitute terminal observation for the
original cancel checks. Internal cancellation explicitly unlocks and closes its
own registry descriptor before resuming PTY cleanup. Both process capture memfds
are closed on normal and recoverable paths.

The process transport itself spools both streams without a new byte cap. The
current properties parser has explicit 4 MiB raw/decoded workspace allocations
and a bounded property index; this component gate does not establish equivalence
for an arbitrarily large substituted systemctl response. Exact error text,
actual systemd/DynamicUser launch and complete supervisor qualification also
remain outside the observation component gate.

## Independent qualification

The two reusable qualifier tools compare with an oracle compiled from the
unchanged published Rust Jobctl definitions and exercised functions, source SHA
`575e7b74f26f7ddada5f19ffafd6b9597307b565ac69de3c8091346fa516dc81`.
The observation gate requires an explicit private mount namespace; it binds
independent filesystem and fixed-command facts only inside that namespace.
Image hashes and original source identity are checked before and after the run.

The matching-v95 checkpoint uses the native source compiler with SHA
`494833999e25ac74ea6ad1de41235c01bfa036951f212604026cb8be686c78af`.
Its 152 typed cases cover Exit/Witness/capture and struct sequences. Its 261
whole observation cases compare acceptance, JSON values, command observations
and persisted Record/tree effects, including races, duplicates, UTF-8, depth
neighbors and wide Values near the original file limit. Detailed receipts and
the earlier failing images are retained in the integration qualification area.

These sources must also be composed with the final shared Record/control growth
handling and the final START/supervisor adapter and requalified there. A result
from an older compiler or a different component combination cannot supply the
final image pin.
