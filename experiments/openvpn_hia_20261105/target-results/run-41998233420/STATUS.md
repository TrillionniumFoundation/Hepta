# Real target execution: allocation still pending

The target request is published and queued. **The target has not executed, and
its TUN, DCO, real-tunnel profile and performance acceptance gates remain open.**

## Last actual observation

| Field | Observed value |
| --- | --- |
| Observed at | 2026-11-05 09:13:01 UTC |
| Dedicated run | [41998233420](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41998233420) |
| Job | `127146634828`, `native-tun-dco` |
| Source commit | `4365b1dd708d1ff61fdf721e2102737995d498b7` |
| Status / conclusion | `queued` / `null` |
| Runner ID / name | `0` / empty |
| Executed steps | Empty list |
| Time since request creation | 17 minutes 22 seconds |

The eight successful observations in this retained monitoring interval all show
the same unallocated state. The raw metadata's `started_at` timestamp alone does
not prove execution when the job remains queued with no runner or steps. The
service did not provide a queue reason. There is no actual build or experiment
failure log to diagnose yet.

The executable workflow remains the original queued request. This evidence and
the offline analyzer do not change its frozen execution inputs. When a runner is
allocated, the queued workflow supplies its own bounded build, matrix, independent
verification, cleanup and nonsecret artifact upload. Its result must still be
examined before any open acceptance gate is closed.

## Five-stage status

| Requested stage | Evidence completed | Evidence still required |
| --- | --- | --- |
| Freeze official baseline | Exact official source, compiler and local configuration; original self-test profile; frozen target build and plan | Executed target kernel/module/OpenSSL identity, real-tunnel hotspots and DCO runtime proof |
| Minimal external buffer ABI | Finite synchronous contract, admission/alias/lifetime/boundary checks and regression validation | None within the documented finite ABI profile |
| Real HIA kernel and replay evaluation | Packet-ID codec differential, complete state changes, guard pages, unchanged C replay-window comparison | None within the implemented packet-ID/replay-evaluation scope |
| Official OpenVPN integration | Complete application link; fresh crypto, UDP/TLS null-device, rekey/reconnect and encrypted replay/tag checks | Seven real TUN behavior cases and two target certificate-rejection cases |
| Fair performance comparison | Complete six-arm local microkernel observations, preserved regressions and failed drivers | Two real profiles; 54 C-user/HIA-user/C-DCO sessions and 216 bidirectional workloads |

The local environment's actual preflight is also retained and negative: it cannot
provide the required TUN/DCO execution. A workflow file, parser check, empty
artifact or queued job is insufficient to close these runtime gates. The finite
target pilot also keeps its documented shared-VM/selected-vCPU scope and does not
qualify the longer production deployment grid.

## Evidence and continuation entry points

- [Monitoring summary](monitoring-summary.json) and [final full response](poll-008-job.json).
- [Observation hashes](sha256-manifest.json); one unsupported direct job-URL read is preserved as a tool error, not classified as a workflow failure.
- [Frozen target protocol](../../target_host/README.md) and [plan](../../target_host/plan.json).
- [Offline analysis instructions](../../ANALYZE_TARGET.md), which require actual build or matrix receipts and retain missing and failed positions.
- [Continuation and local results](../../CONTINUATION.md).
