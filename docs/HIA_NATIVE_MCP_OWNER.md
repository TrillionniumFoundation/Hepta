# Standalone native HIA MCP process owner

The service owns public HIA MCP negotiation, SDK typed-envelope admission,
configuration capture, controller custody, scheduling, cancellation, durable
request audit and job transport in checked-in HIA. Its x86-64 adapter translates
bounded memory plans to Linux syscalls. Installed execution has no Python or Rust
continuation.

## Process and custody

`hia-mcp-service` takes four administrator-owned inputs: configuration path and
SHA256, controller manifest path and SHA256. It captures authenticated original
configuration bytes and nineteen controller roles into independently checked,
sealed descriptors. The original lifetime controller locks remain held. A fixed
sealed-size writable memfd carries predecessor replay state across requests.
The complete native job bridge and request-audit daemon are embedded with their
SHA256 identities; temporary build paths do not select their implementation.

The SDK framing limit is 16 MiB **including the newline**. CRLF counts both bytes.
An oversized line is discarded through its newline and later valid frames still
run. An unterminated frame at EOF is discarded. Empty and pre-initialization
connections retain the frozen runtime's unsuccessful EOF status; established
sessions can end successfully. HIA business admission separately preserves the
8 MiB raw request, 262,144-node, depth-128 and 524,288-byte canonical argument
budgets. A wider SDK envelope does not widen those business limits.

Up to 32 request workers run concurrently. Ping, discovery and cancellation stay
responsive. Each worker stages its complete response in a private memfd; the
parent admits it after the worker exits. Native cooperative cancellation matches
the normalized SDK request ID and returns `-32800`; previously published durable
jobs remain published. This is the native custody contract, not a claim that the
predecessor Rust handler's advisory cancellation effects were identical.

## Configuration and protocol

Typed configuration preserves serde struct/sequence and optional-field behavior.
Unknown RuntimeConfig, HostConfig and PrivilegedAction fields use iterative
IgnoredAny scanning. HiaWorkerProfile and native-job pin records reject unknown
fields. Known typed fields remain checked even when a later map value replaces
an earlier one. Native job transports are genuinely optional; a present record
must carry its complete original roles and pins.

The service advertises `hepta-hia` and its HIA tools/resources. The frozen general
Rust server advertises `rmcp` plus filesystem-related capabilities. Differential
qualification checks both complete, separate profiles and compares negotiated
protocol, envelopes, IDs, responses and errors exactly. It does not silently
normalize away arbitrary initialization differences or claim migration of the
unrelated general filesystem tool catalog.

## Source-complete construction

`tools/generate_hia_mcp_release.py` declares every audit, bridge and service
component. Its HIA packer host independently recompiles a packer's source and
compares the complete image before allowing packing. The host's 64 MiB buffers
are transport buffers; the compiler's existing 1 MiB source/image/workspace and
128-function, 1,536-block, 8,192-instruction limits remain unchanged.

The ordinary `release_stage_additional.hiastd` recipe captures, compiles, hashes
and packages all three products in the final native stage. It reuses the native
DAG's existing concat, extent, digest and sealed-execution operations. Exact
byte comparison independently checks each complete ELF against the mechanical
adapter template and its compiled components, including all relocations, child
ELF sizes and SHA256 fields. Generic filters and sequential bundles retain their
actual layouts; the existing Pager-specific checker remains unchanged. The
explicit bootstrap builder is `tools/build_hia_mcp_service.py`; it requires a
matching cold compiler/report and records exact sources, components and products.
A development seed result is marked as such and is not a matching-cold receipt.

## Reproducible gates

`tools/qualify_hia_mcp_service_protocol.py` retains the independent 1,050-envelope
corpus, the original adversarial stdio corpus, explicit boundary cases and
post-initialization legacy/modern controls. It requires pinned executable and
manifest inputs, retains raw input/stdout/stderr, checks both frozen server
profiles and rejects changed inputs. `--framing-only` selects the bounded framing
subset for a targeted installed-artifact check. Explicitly pipelined stdio cases
are correlated by full response identity and multiplicity; initialization must
remain first. All original arrival-order records are retained. Other cases
retain ordered comparison. The frozen Rust runtime produced two arrival orders
in forty identical-input control runs. The independent readback rechecks every
raw input and response rather than changing prior execution evidence.

`tools/qualify_hia_mcp_service_owner.py` covers actual process custody, nineteen
role pin/size mutations, locks, responsive pending ping, Unicode cancellation,
64 concurrent exact schema errors and descriptor recovery. The source-complete
development-seed service `8497a2adcdaa7d76c6717876446fc1d499c2f80d9a1c98755d50ac1c0a2a6536`
passed all 1,146 protocol cases in independent readback, all 96 fresh stream,
control and framing cases, and all 75 process-owner cases. Twenty raw arrival
order differences remain recorded. These are component evidence; the changed
final matching-cold service must be checked under its own pin.
The actual eleven-tool campaign, same-job replay, durable audit, isolated Jobctl,
matching final release and installed replay are independent required gates.
