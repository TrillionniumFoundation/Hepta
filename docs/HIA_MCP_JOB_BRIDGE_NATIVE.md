# Native HIA durable MCP job bridge

The `mcp_job_bridge_*.hepta` policies implement the durable scheduling portion
of the Linux HIA provider in its Operator and Isolated modes. They preserve the original Worker request,
transport digest, fixed profile argv, durable job key, observation flow and
typed pending/terminal responses. The bridge executes existing admitted HIA
job owners; it does not independently recreate their job metadata protocols.

This component is distinct from the capability-free MCP connection fixture.
It does not implement JSON-RPC negotiation, configuration admission, argument
schemas or capture-path normalization. The parent service performs those
existing admissions and supplies both canonical original arguments and the
canonical normalized arguments. It also owns MCP request-audit begin/finish.
The bridge retains the original durable-job audit events.

The original optional `HostConfig.native_jobs` remains optional. No capability
is inserted into the canonical host or profile, and choosing a transport does
not change the Worker request, profile hash, transport digest or durable key.
The original stored `system_jobctl` flag selects observation of an existing job.

| Configuration and stored route | Native transport |
|---|---|
| Operator with explicit `native_jobs` | Original explicit entry path and admitted role pins |
| Operator with absent or null `native_jobs` | Fixed administrator-installed `/usr/local/libexec/hepta-runtime-job-entry` |
| Isolated with absent or null `native_jobs` and `system_jobctl=true` | Original fixed `sudo -n /usr/local/libexec/hepta-runtime-jobctl` |
| Explicit `native_jobs` with `system_jobctl=true` | Original refusal; no alternate submission |

The `compat` HIA policy serializes the original Jobctl START, STATUS and READ
requests as one JSON line. The installed HIA Jobctl owns privilege, systemd,
process custody, terminal publication and Scratch cleanup. The bridge consumes
its original public status and page values. Operator None uses the existing
sealed HIA Job Entry/Submit/Observation roles in place of the former Python
transport helpers. Those Python helpers remain only an external comparison
oracle for this component's qualification, not a dispatch fallback.

The fixed entry must be visible to the actual user systemd manager. A mount
visible only to the SSH process does not establish that installation fact.
The original CPUQuota=100 and profile MemoryMax remain requested; consequently
systemd unavailability cannot silently select an unbounded detached backend.
Missing or non-executable fixed entries preserve the original uncertain job;
restoring the entry does not authorize relaunch of that job.

## Executable contract

`hia-mcp-job-bridge` takes exactly one argv entry (argv0). Its entire stdin is
one strict-EOF `HIAMBI01` envelope. A successful invocation exits 0, emits one
typed domain JSON response of at most 524,288 bytes, and emits no stderr.
`accepted` and `unknown` are successful typed observations. Refusal exits 65
with empty stdout. The parent must not turn refusal, timeout or a lost reply
into a new request key or a second effect submission.

The bridge image is a static ELF containing seventeen exact HIA flat images and
a fixed Linux syscall adapter. The adapter only gathers bounded input and
environment bytes, translates buffer offsets and executes policy-selected
syscalls/companions. `sha256_stream`, `job_terminal_receipt` and
`mcp_canonical` are the unchanged existing companions. In particular, the
terminal receipt and canonical-number policies are not reimplemented by the
host adapter.

The independently sealed `/usr/bin/ssh` image and its dynamic loader/library
requirements remain mechanical host dependencies. They are not HIA-language
implementations and must be stated separately in release claims.

## Outer bootstrap envelope

All integers are unsigned little-endian 64-bit words. The fixed header is
`<8s7Q>` (64 bytes):

| Offset | Field |
|---|---|
| 0 | `HIAMBI01` |
| 8 | MCJB business byte length |
| 16 | actual parent process ID |
| 24 | absolute monotonic deadline in nanoseconds, or `u64::MAX` |
| 32 | role count, exactly 12 |
| 40 | fence directory UTF-8 byte length |
| 48 | self-owner byte length |
| 56 | flags: bit 0 required fence; bit 1 owner lease; bit 2 replay cache |

Twelve 64-byte `<QQQ32sQ>` role records follow: role ordinal, inherited sealed
descriptor, raw ELF byte length, raw 32-byte SHA256, reserved zero. Descriptors
must be distinct. Images have all four seals (`F_GET_SEALS == 15`) and their
complete bytes, ELF type and target machine are independently checked.

| Role | Existing executable |
|---|---|
| 1 | `hia-worker-prepare` |
| 2 | `hia-job-receipt` |
| 3 | `hia-job-entry` |
| 4 | `hia-job-submit` |
| 5 | `hia-job-observation` |
| 6 | `hia-job-cancel` |
| 7 | `hia-job-launch` |
| 8 | `hia-job-supervisor` |
| 9 | `hia-agent-mcp-terminal` |
| 10 | `hia-agent-mcp-response-schema` |
| 11 | fixed `/usr/bin/ssh` |
| 12 | `hia-agent-mcp-proof-schema` |

The production service uses flags 6 or 7 and appends a 40-byte `<8s4Q>` lease:
`HIAOWN02`, canonical state-directory descriptor, `controller.owner.lock`
descriptor, `controller.lock` descriptor, replay-cache descriptor. All four
descriptors are distinct from one another and from the twelve roles.

The parent retains the two original exclusive flock locks for its entire
service lifetime. The bridge validates current path/descriptor identities,
ownership and modes, adopts the inherited open descriptions, then obtains a
separate POSIX whole-file write lock (`F_SETLKW`) on the owner-lock inode.
That process-owned lock serializes independent bridge processes sharing the
parent's flock open descriptions. It remains held until bridge exit. Helpers
do not inherit the POSIX lock and close unrelated descriptors on exec.

The replay descriptor is an 8,388,608-byte memfd: initially all zero, mode
0600, current UID, zero links, seals exactly `F_SEAL_SEAL | F_SEAL_SHRINK |
F_SEAL_GROW` (7). The parent never interprets or resets its contents and keeps
the same descriptor throughout the service lifetime. HIA manages two 4 MiB
slots, exact SHA256 payload custody and generation commits. A successful
predecessor scan retains up to 65,536 original host/key SHA256 identities.
Under unchanged authority, predecessor and epoch, a changed predecessor
registry stamp refuses admission rather than interpreting removed old jobs
as new identities. New-root/epoch failed scans preserve the previous slot.
The final eight-byte slot magic is published only after the entire new slot.

The previous 32-byte `HIAOWN01` lease (flags 2/3), and the no-lease flags 0/1,
remain for earlier component fixtures only. They do not establish the new
service-lifetime replay guarantee. Flags 4/5 are invalid.

Raw fence directory, self-owner and MCJB bytes follow the role table and any
lease. The parent captures the administrator's
`HEPTA_EFFECT_OWNER_FENCE_DIR`, `HEPTA_EFFECT_OWNER_SELF`, and
`HEPTA_EFFECT_OWNER_FENCE_REQUIRED`. DIR/SELF are paired and nonempty; SELF is
`v4` or `v11`. REQUIRED is either unset or exactly `1`. An explicit required
fence cannot be omitted. The bridge owns shared fence locking, document
admission and predecessor replay policy.

## MCJB business envelope

The 72-byte `<8s8Q>` header begins with `HIAMJB01`, then seven lengths and a
reserved zero word. The seven fragments are:

1. Canonical typed `HiaWorkerProfile` JSON.
2. Canonical selected `HostConfig` JSON.
3. Original canonical tool-argument JSON.
4. Admitted, normalized canonical tool-argument JSON.
5. Canonical JSON tool-name string.
6. Physically canonical runtime state-directory UTF-8 bytes.
7. Exact 64-byte lowercase catalog SHA256.

The first five fragments are each bounded by 524,288 bytes; the state path is
bounded by 4096 bytes. The total outer input remains within 4 MiB. The parent
uses the existing typed serializer/default rules and existing canonical HIA
owner. It must not substitute arbitrary raw configuration JSON for the typed
profile. Original and normalized arguments remain separate so path capture
does not change the original transport digest.

Public tools follow the original eleven ordinals: describe, artifact, read,
context, inspect, candidate, verify, emit, evaluate, adopt, rollback. The
internal twelfth tool is `hia_resource_read`, with the original explicit
`{"uri": ..., "max_bytes": 65536}` arguments. Its typed response uses the
existing `hia_read` response schema (ordinal 3). Verify uses proof-schema
role 12. The parent remains responsible for the resource-read MCP envelope.

## Durable observations and limits

The HIA provider builds the original `HIAWPR01` and `HIAJID01` inputs to role
1. Full request digest and fingerprint, exact profile argv, Worker stdin,
SSH target, execution mode and the selected original registry record are
preserved. An existing key with changed bound data refuses. An uncertain
launch acknowledgement never triggers a replacement job.

Registry records use the original typed serde semantics, including duplicate
known-field refusal and the original defaults: omitted `execution_mode` is
`isolated`, omitted `system_jobctl` is false, and omitted `launch_state` is
`launched`. An omitted mode matches only an Isolated binding; it cannot match an Operator
binding. The stored system-jobctl flag is preserved independently of that mode. Unknown fields pass through a separate iterative `IgnoredAny` lexer
before known fields are decoded. This preserves serde's handling of ignored
isolated Unicode escapes, ignored invalid UTF-8 bytes, large numeric tokens,
and deeply nested unknown values. Known strings and root field names retain
their ordinary strict Unicode decoding. The original encoded record byte
limits remain in force; ignoring fields does not grant a larger input budget.

`tools/generate_hia_mcp_typed_json.py` supplies the shared authoring text
`IGNORED_VALUE`. Its `ignored_value(w, start, end, stack, capacity)` function
returns the first byte after a complete value or `NONE`. Callers supply a
nonoverlapping bounded byte stack and their own strict known-field decoder.
This helper is compiled into the registry policy, with no additional runtime
role or host-language parser.

Operator remote calls use existing `HIAJEX01`, `HIAJSB01` and `HIAJOBQ1`
owners. Each call keeps its original budget: START 20 seconds, zero-wait
STATUS 10 seconds, READ 15 seconds. The original fixed system Jobctl calls
retain their separate 20-second budget and 16 KiB page limit. The profile timeout belongs to the Worker workload, not to
the bridge as a whole. There is no invented 15-second total provider deadline.

Terminal output requires the same publication witness, lifecycle/owner facts,
durable complete streams, retained sizes, nonce and final proof. At most
524,288 combined stdout/stderr bytes are retained. Reads use four concurrent
16 KiB pages per window. Every child is joined, every page is validated, and
only the contiguous prefix is retained on error. Final publication is checked
again before the existing terminal-report and response/proof schema owners
can produce a completed domain result.

The canonical companion is byte-identical to the service's companion.
Semantic JSON comparison preserves serde number variants and treats finite
floating `-0.0` and `0.0` as equal, without equating integer and floating 1.
Positive terminal composition remains constrained by the unchanged terminal
receipt owner's existing node and byte limits; it is not a claim about every
possible JSON value outside those owners' admitted domains.

## Building and qualification

`tools/generate_hia_mcp_job_bridge.py` is authoring-only. Its `--check` mode
verifies the checked-in HIA sources against the authoring representation.
No Python or Rust implementation executes inside the bridge.

`tools/qualify_hia_mcp_job_bridge_sources.py` accepts `--bootstrap`,
`--cold-receipt`, and a new `--output` directory. It compiles every checked-in
HIA policy/companion with the native source compiler, natively builds a small
standalone bridge packer, then natively links the complete image. The existing
1 MiB observer budget is unchanged; the complete composition passes through
the existing 8 MiB standalone native filter. The gate checks exact embedded
flat bytes and malformed/missing role-packet refusal. This is a source custody
gate; whole-service routing and fresh-host configuration are separate gates.

Current component evidence includes genuine sealed `/usr/bin/ssh`, actual
native controller/configuration binding, a matching complete Worker Store,
same-job completed response equality against frozen Rust v26, bootstrap and
lease refusal, two-slot predecessor drift refusal, and POSIX lock contention.
The original eleven-tool client campaign and the parent service's complete
stdio integration have independent recorded outcomes. A release must name
the exact successful evidence rather than treating compilation as service
qualification.

## Optional-route qualification

The v95 source compiler with SHA256
`494833999e25ac74ea6ad1de41235c01bfa036951f212604026cb8be686c78af`
compiles the seventeen-component bridge to 2,304,109 ELF bytes with SHA256
`77fa2e20d397d4ce708d64ba59c0b4f10c2b41436fffbb11ceaf60cdc19a849a`.
The outer twelve-role and HIAOWN02 contracts remain unchanged.

`tools/qualify_hia_mcp_job_bridge_optional.py` consumes a prepared private
real-SSH fixture. It uses the frozen Rust provider as an external oracle and
requires a matching complete native Worker installation. Its ten actual user
systemd cases cover fresh None execution, null/absent equivalence, explicit
Some observation, both directions of original/native job creation and
observation, and missing/non-executable entry recovery without relaunch.
The fault entry must resolve inside the explicit QA directory; the qualifier
does not modify the host installation.

Independent Isolated composition cases use real OpenSSH and the fixed sudo
Jobctl path, both original and HIA Jobctl images, and an actual native Worker
report. Their systemd command results and terminal publication are explicit
external fixtures, so they do not establish a real DynamicUser/system-systemd
end-to-end result. They compare original root request digests, None/null,
Some refusal, complete report pages, corrupt witness/nonce/capture, inverse
original-created job observation, and fixed-entry failure recovery. A
separate five-page fixture appends 65,536 legal JSON whitespace bytes to the
actual report; it is explicitly attributed to the publication fixture, not
to the Worker process's stdout. The unchanged 61 descriptor/lease refusals
and seven predecessor-cache/concurrency cases also pass on this bridge.
