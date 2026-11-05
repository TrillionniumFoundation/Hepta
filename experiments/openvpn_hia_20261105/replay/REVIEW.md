# Independent packet/replay review

## Scope

The reviewer did not modify the packet generator, adapter, C control, primary
differential test or benchmark files. The replay harness and runner are additional
independent sources. Full protocol, authentication, key selection and tunnel
performance remain outside the replay test.

## Codec observations

The HIA Core follows the unmodified OpenVPN 2.7.8 ordering for ordinary short/long
packet IDs: output reset on ordinary read; consumption of the first four bytes
and partial decoded state on a truncated long timestamp; sender timestamp
initialization and ID increment before space refusal; partial append/prepend
updates; signed `time_t` comparison at normal ID rollover; 32-bit wire narrowing;
48-bit epoch packet ID extraction and 16-bit epoch return.

A successful eight-byte epoch read can return epoch zero while still consuming
the buffer and updating the decoded ID. A truncated epoch read preserves the
receiver. Epoch decoding does not access `packet_id_net.time` at all. Those
observations must be reflected by the C adapter as well as the Core.

The parent review correctly identified that an ordinary output-only receiver may
be uninitialized on entry. The early adapter's reads of receiver ID/time were
therefore invalid, even though tests initialized those fields and compared equal.
The epoch adapter likewise must not read/write the `time` field. These findings
require fresh adapter compilation; old green codec results do not close them.

The experimental adapter's admissible buffer capacities are bounded at 65,536
bytes, and it now attempts to reject overlap between packet state, buffer
metadata and wire allocation. This is narrower than arbitrary malformed C
structures. Allocation liveness remains the native caller's obligation.

## Replay harness

`packet_replay_differential.c` executes unmodified upstream replay routines on two
independent states. One stream uses original C decode and the other the HIA
adapter. It compares every observable scalar receive field, send fields,
circular-list headers, and every allocated ring slot after decoding, reaping,
`packet_id_test` and accepted additions. It specifically compares rejected-call
`max_backtrack_stat` changes, not merely accept/reject booleans.

Coverage includes duplicate IDs, gap/reordering, expired unseen gaps, jumps outside
the window, remote timestamp regression, new timestamp series, local clock
regression, truncation, maximum 32-bit/48-bit IDs, TCP sequential mode, windows
0/1/8/64/65,536 and expiry 0/5/600. Fixed epoch-42 decoding and invalid epoch-zero
return are covered; current/retiring epoch key lookup is not.

The original replay code is not copied into a substitute implementation. The
standalone runner compiles `packet_id.c`, `buffer.c` and `otime.c` from the frozen
upstream source; its only support substitutions are diagnostic logging and
assertion/OOM termination. Assertions and OOM abort rather than returning success.

## Preserved observations and final fresh result

The initial historical run used the old 16:25 adapter object. It recorded 70,663
input observations, 275,509 complete state comparisons, 53 rejected calls changing
`max_backtrack_stat`, 3,619 reaps and zero differences. This does not qualify the
later receiver/alias fixes; its separate `SCOPE.txt` identifies the measured old
adapter SHA.

A fresh build attempt subsequently captured a real compilation failure in an
intermediate adapter edit: `input_len` was referenced from ordinary
`hia_packet_id_read` without a declaration. In that snapshot, the epoch-specific
publish change was in the wrong function, and ordinary write state had also been
zeroed. The failing snapshot and raw compiler output are retained in
`fresh-attempt1`. That incomplete source was subsequently corrected as whole
functions by the packet implementation owner.

The final fresh run in `final/validation.json` used the frozen corrected adapter
and `packet-run-final2/packet.o` with its matching HIA native receipt. It passed
70,663 inputs and 275,509 complete state comparisons with zero differences,
including 53 rejected calls changing `max_backtrack_stat`, 3,619 reaps, and
569,535,048 ring-storage bytes compared. The run detected no input source changes.
It freshly compiled the adapter rather than reusing either historical object.

Final adapter source SHA-256:
`3464486d59c3ad95572c83be4e706c431082590203b859a5f6c23c9a98fb9e03`.
Final linked replay binary SHA-256:
`620beea35f2b0c56caa49eeac391643861cdb59e6c46111b028ca6ce9e8609d3`.

`run_replay.py` snapshots the three local sources, freshly builds the adapter,
records input/dependency/tool/object hashes and commands, detects source changes,
and refuses an existing output directory. Both prior attempts remain intact.
Replay-window implementation is still official C in both streams; no claim of a
HIA replay-window rewrite, authentication, crypto epoch key management, or real
tunnel acceptance follows from this check.

## Performance interpretation

The revised 18-sample benchmark uses all six orders of official C, raw HIA byte ABI
and HIA application adapter, with predetermined warmups. It separately measures
its C byte-ABI control and retains the earlier runs. These are loop-average
nanoseconds per call, not per-request latency percentiles.

The C byte-ABI control marshals state and delegates to a separately compiled
upstream function; HIA can inline its internal Core implementation. Thus the
control is useful for the actual interface cost but does not establish equal
optimizer visibility or language-wide kernel speed. All flags should be recorded,
including `-fPIC`, which the HIA compiler always supplies. C controls should match
that flag when making a matched-compilation comparison. Shared host scheduling,
hot tiny inputs and absence of TUN/DCO traffic prevent deployment conclusions.
