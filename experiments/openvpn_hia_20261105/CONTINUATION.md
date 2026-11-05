# Continuation after the initial OpenVPN / HIA delivery

Base: `5a699214b974c1af95a8044315f0818a2f72064f` (draft PR #695).
The initial five-stage report and every original failure/timing remain in
[README.md](README.md). This continuation changes the packet generator and one
targeted LLVM inlining hint, strengthens the actual tunnel observer, and prepares
a separate disposable target-VM experiment. **The target-VM runtime gates are
not closed by the local results below or by publishing an executable workflow.**

## Implemented and measured locally

The finite foreign wrapper previously called an outlined Core body. Eight-byte
wire stores also retained eight separate bounds branches. The new candidate
inlines only explicitly selected foreign exports and exposes exact bounded
indices to the existing checked byte operations. No admission check, caller
lifetime rule, IR-origin check, packet error or partial-failure transition was
removed. The C adapter is unchanged.

The candidate passed 44 regression methods, 228,336 codec inputs / 456,672 full
comparisons, 15,504 real guard-page cases, admission/receiver/ownership checks,
and C-side ASan plus fatal UBSan. Executable `.text` decreases from 2,822 to 2,632
bytes; object-file bytes decrease from 4,744 to 4,224. The new object SHA-256 is
`05d189d73cb75e49ef251ba8a7fe97bb36f837b3bb3936fe3b907614233e7c31`.

One complete fixed comparison retained 432 batches: four modes, 18 observations,
six arms, 1,000,000 calls per arm/batch. The result is mixed. The adapter's median
paired new/old ratios are 0.8967 (long write), **1.0475 (long read)**, 0.9274
(epoch write), and 0.9849 (epoch read). Epoch-read's separate new median is higher
than the old median despite that paired statistic. Both summaries and every
recorded slow observation remain; no universal speedup is claimed. The candidate
adapter path still takes **4.51–6.89 times the original C batch-average time**.
See [the complete diagnosis, protocol and data](perf2/README.md) and the
[independent sample audit](review/perf2-independent-sample-audit.json).

Two comparison-driver failures preceded the completed run. The first stopped
before timing because it compared ELF section indices instead of section names
and identical bytes. The second crashed in an incorrectly formatted `printf`
after the first six-arm timing group; buffered observations were lost and cannot
be reconstructed. Both failed source snapshots, commands and diagnostics are
retained. Neither failure changed the candidate.

## Candidate application and replay revalidation

The exact new packet object and unchanged adapter were linked with the same 99
official application objects. The actual local application run again passed six
crypto self-tests, all nine UDP/TLS `--dev null` scenarios, and both encrypted
UDP replay/tag-corruption orientations. The current corrected observer and all
four-entry HIA trace gates were used directly for this fresh run. This is new
candidate execution, not a reinterpretation of the initial delivery's logs.

The fresh official-C replay-window comparison also passed: 70,663 inputs,
275,509 complete-state comparisons, zero differences, including 53 rejected
inputs that change backtrack statistics. The replay implementation remains C.

Evidence: [application receipt](baseline-application/continuation-candidate1/application-receipt.json),
[application sessions](baseline-application/continuation-candidate1/application/baseline.json),
[adversarial UDP](baseline-application/continuation-candidate1/udp/udp-probe.json),
[fresh replay](replay/continuation-candidate1/validation.json), and
[retained-file manifest](review/continuation-integration.json). Private PKI and
native executables were excluded from this repository evidence.

## Remaining target execution

The local container still lacks TUN, effective/bounding capabilities and an
enabled `ovpn` kernel implementation. Its updated preflight receipts remain
negative. The old single-trial runner has been strengthened to bind a newly
created interface, source-specific route, actual interface and kernel peer
counter changes, timeout output and process cleanup. See the
[independent target review](review/TARGET_REVIEW.md) and its retained negative
observations. Local UDP/parser tests do not prove target TUN/DCO behavior.

The new dedicated GitHub-hosted Linux workflow uses exact action commits and
the original verified Clang 20.1.8 packages. It freezes the actual VM image,
kernel/configuration, module, OpenSSL/libraries, official source closure,
application objects and binaries before traffic. It uses the kernel's available
official `ovpn` module or builds a separately pinned official backport. It does
not attempt to elevate or bypass the restricted local container.

The [fixed target plan](target_host/plan.json) is a separate **finite pilot**:

- Seven positive real-tunnel behavior combinations, two certificate-rejection
  cases, exact payload and encrypted ingress/reinjection observations, rekey and
  reconnect, with HIA entry traces only in diagnostic cases.
- Fifty-four ordered performance sessions and 216 five-second bidirectional
  workloads: all six C-user/HIA-user/C-DCO orders, three rounds, three UDP sizes
  at fixed offered load plus TCP. The official DCO server and common non-epoch
  profile are fixed; two-userspace epoch compatibility is a separate matrix.
- Original C userspace/DCO tunnel profiling, with full failure reporting if
  sampling is unavailable. Raw DWARF stack bytes stay private; only fixed symbol
  fields, commands, hashes and reports enter the public evidence.
- Exact interface/netns/peer identity and kernel byte-counter deltas, both
  application process CPU and explicitly scoped vCPU activity, sampled RSS,
  complete raw iperf outputs and retained losses/errors.
- Independent rejection of an empty, incomplete, stale or internally inconsistent
  target receipt; process exit zero alone cannot satisfy acceptance.

The matrix has a fixed 1,800-second execution budget. Build provisioning has a
900-second budget; the job allows 55 minutes including cleanup and upload. This
pilot does not silently replace the longer multi-rate, two-role deployment grid
in [TUN_DCO_ACCEPTANCE.md](TUN_DCO_ACCEPTANCE.md), nor qualify WAN, physical NIC,
cross-host or production performance. Execution and observed runtime status must
be reported separately after the target job is actually run.

## Published execution request and offline analysis

The executable target source was published as
`4365b1dd708d1ff61fdf721e2102737995d498b7`. The complete remote Git tree matches
the local frozen continuation; the publication manifest is retained in
[continuation-publication.json](review/continuation-publication.json).

[Dedicated run 41998233420](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41998233420)
was triggered by that push. Its observed allocation/execution status and raw
observations are recorded separately in
[target execution status](target-results/run-41998233420/STATUS.md). A queued
request does not establish a build, tunnel, profile, or performance result.

The [offline analyzer](ANALYZE_TARGET.md) is also complete. It preserves all fixed
case/workload positions, partial/failing observations, both receiving directions,
UDP losses/jitter, whole-interval process CPU/RSS and all paired ratios. Its
parser checks use explicitly synthetic software vectors and establish no runtime
performance. It emits no target result when no actual build or matrix receipt
exists. This later analyzer/evidence work does not modify the frozen target
execution inputs or launch a second target matrix.
