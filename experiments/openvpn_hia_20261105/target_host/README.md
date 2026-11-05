# Dedicated target VM: real TUN, `ovpn`, and bounded comparison

This directory supplies the target-host continuation of the frozen local
OpenVPN/HIA experiment. It creates real devices and sends real application data
only when run on a separately provisioned Linux test VM. At the source freeze on
2026-11-05, the current workspace still had no effective capabilities, no
`/dev/net/tun`, and no `ovpn` implementation. Its negative preflight correctly
returned 2, recorded all runtime gates as false, created no namespaces, and
removed its new private directory. Local parser and probe checks are not TUN or
DCO runtime evidence. The target VM's actual verdict is its `target-result.json`.

## Entry points and frozen sources

- `build.sh` / `build.py` install the declared target dependencies, verify the
  exact Clang package/binary hashes, freeze the runtime, build official OpenVPN,
  run the real native HIA qualification, and link C, HIA, and diagnostic HIA
  application binaries. `source-lock.json` fixes the downloads and build flags.
- `run_matrix.py` executes the finite design in `plan.json`. It does not acquire
  privileges, install modules, dispatch CI, or alter a host route/firewall.
- `dco_peer_stats.py` reads actual `ovpn` generic-netlink peer counters from the
  calling namespace. It never sends peer/key mutations.
- `payload_probe.py` and `encrypted_capture.py` provide sequence-checked payloads,
  exact ciphertext capture/reinjection, and independent incoming-frame witnesses.
  Their contracts and limits are detailed in `PROBE_PROTOCOL.md`.
- `verify_result.py` independently checks the completed inventory, executed
  identities, runtime evidence, command-output hashes, and public-artifact scope.
- The dedicated workflow is `.github/workflows/hia-openvpn-target-host.yml`.
  Its push filter is restricted to the work branch and the experiment's execution
  inputs. It can also be started manually. It uses a fresh `ubuntu-24.04` VM.

OpenVPN is fixed at **2.7.8**, commit
`dc1f569087135894ac2703aeabd7a960ee9452d4`; its complete release archive is checked
against SHA-256
`c070d1d2440b5a6fca6c2c68645c98cd492116ac36ef4f0946177115532c8e36` and the existing
545-file source-closure manifest. Application C and HIA links use the same
Clang 20.1.8, OpenSSL, configuration, `-O3 -g -fPIC`, and no LTO. Diagnostic entry
counters are excluded from every performance and profile application.

The target build first tries the VM kernel's existing official **`ovpn`** module
and records the actual kernel, configuration, module metadata and file hash.
If that implementation is unavailable, it builds the official backport at commit
`5fa9098115f7e8fe0d4519864410339557ba16e6`, tag
`ovpn-net-next/main-7.3.0-rc2-2026100801`. The 82,416-byte codeload archive is fixed
by SHA-256
`66e0813f00c84fb5bcbd71a97db00c3b49c12afca43aa4a51ddb3f1190d7d994`. Its patched
module sources are already in the archive; no full Linux source download or
`get-ovpn` target is needed. The build uses the current kernel's headers and
configuration, then loads the module through normal VM administration. A module
load or runtime compatibility failure is retained as a blocker.

## Fixed matrix and time bounds

The controller budget is **1,800 seconds**. The workflow has a separate bounded
subprocess deadline and a final cleanup step. A deadline records incomplete and
unattempted cases; it never shrinks the planned inventory to manufacture a pass.

| Part | Fixed cases | Purpose |
| --- | ---: | --- |
| Epoch behavior, both ends DCO off | 4 | C/C, C/HIA, HIA/C, HIA/HIA real tunnels |
| Common non-epoch behavior, fixed C DCO server | 3 | C off, HIA off, and C DCO clients |
| Untrusted client certificate | 2 | C and HIA clients; explicit chain error and zero delivered payload |
| Original application/kernel profile | 2 | C off and C DCO clients, fixed C DCO server |
| Performance sessions | 54 | Three rounds of all six orders of the three client arms |
| Performance workloads | 216 | Each session: UDP 64/512/1200 bytes and TCP, five seconds each |

Each performance workload runs in both directions. UDP offers 100 Mbit/s per
direction. TCP uses one stream in each direction. There is no omitted warmup,
outlier removal, retry selection, or diagnostic trace. Both application endpoints
use verbosity 3 and a 3,600-second renegotiation setting. The server and its
generator use the first allowed CPU; the client and its generator use the second.
The selected CPUs and the full allowed set are recorded. All three arms use the
same DCO server and actual negotiated non-epoch AES-256-GCM profile.

Every case receives new named server/client network namespaces. A veth pair
connects only these namespaces with `192.0.2.1/30` and `192.0.2.2/30`. The actual
VPN addresses are `10.77.0.1` and `10.77.0.2`, MTU 1400. There is no forwarding,
NAT, bridge, default route, or public peer added to the host.

## Runtime evidence required for a pass

### Actual path and DCO

Each traffic interval has before/after `ip -d -s -j link`, addresses, and
source-specific route receipts. Both actual tunnel links must carry growing
receive/transmit byte and packet counts on unchanged ifindexes and namespace
identities. The source address must belong to that exact interface. The expected
device kind is `tun` or `ovpn`; a requested DCO arm silently falling back to
userspace fails.

For every DCO endpoint the controller additionally queries
`OVPN_CMD_PEER_GET`. It requires the same single peer and all eight counters,
rejects missing/reset counters or changed scope, and requires positive VPN and
link byte deltas in both directions. Netlink request/reply bytes, sequence,
kernel sender, attribute width, command/version and helper hash remain available
for audit, including failed queries. Counter queries occur outside measured
traffic and do not require verbosity 6 in a benchmark.

### Authentication, replay, rekey, and reconnect

Positive behavior cases use diagnostic verbosity 6 and a separate traced HIA
binary. The epoch cases must exercise all four HIA read/write entry points with
zero ABI failures; common non-epoch cases must exercise ordinary read/write with
no epoch entry calls. These cases are not timing samples.

Each case first sends 40 distinct, checked 256-byte payloads and receives their
exact echoes. With no other long data flow active, the capture helper records an
actual outgoing OpenVPN data datagram. The original receiver remains alive for
the complete experiment. For each replay or bit flip, an independently bound
server-side raw socket must witness the exact expected ciphertext hash on incoming
veth traffic with valid IPv4/UDP checksums, after submission. The old receiver
must still be alive after that witness and a further observation window; its final
receipt must end after every such window. Final payload counters must contain no
extra, duplicated, or corrupted delivery.

Same-epoch actions are bracketed by unchanged initial-session identities and zero
soft resets. A userspace server must emit a new corresponding replay or tag-error
line for each action. Later logs cannot retroactively satisfy that gate. On a DCO
server, exact ingress plus no payload delivery and subsequent valid delivery
establish the bounded rejection behavior; cumulative byte counters do not identify
a particular kernel rejection reason.

Cross-rekey actions require two completed TLS/key transitions in the same initial
session. A soft-reset message alone does not count: userspace key installation or
DCO key installation and swap must follow the successful TLS handshake. A fresh
payload probe then passes before old ciphertext is injected again. A requested
client `SIGUSR1` must subsequently produce a new initialization, a newly logged
matching negotiated profile, and another successful fresh payload probe. Old
session/port ciphertext is tested separately and described with that scope.

A continuous sequence-numbered flow records losses throughout the transitions;
all missing packets and errors remain in its receipt. It cannot substitute for
the strict fresh probes. The two negative certificate cases use a client with a
correct client-auth purpose but an untrusted CA, require a concrete server chain
verification error, no client VPN address/initialization, all declared send
attempts, an alive server, and zero receiver packets. No plaintext route is
created to make the blocked client appear connected.

### Performance and profile

Each workload retains raw client/server iperf JSON, process exit/timeout status,
all numeric summary fields, OpenVPN user/system CPU ticks, sampled RSS, host CPU
ticks, exact link/peer deltas and session identities. The two required local
receiver summaries are `client.end.sum_received_bidir_reverse` and
`server.end.sum_received`; each must report positive bytes, duration, and rate.
Data received in only one direction cannot pass. Failure before traffic, malformed
JSON, a counter query error, or early process death still writes a failed
`*-measurement.json`. Remaining fixed workloads are attempted within the budget.

The host CPU counters cover only the two selected vCPUs. If the VM has additional
CPUs, these counters do not measure whole-machine CPU cost. `taskset` constrains
the userspace endpoints and generators; it does not constrain all DCO kernel
workers or other kernel activity. Work scheduled on other CPUs can therefore be
absent from the recorded CPU totals. The same boundary applies to the CPU-limited
profile, and the comparison must retain this limitation when reporting offload
cost or savings.

The two 10-second profile cases sample `cpu-clock` at 99 Hz on the two case CPUs
with DWARF call graphs. A successful C-off profile requires samples of the actual
client OpenVPN PID and resolved kernel symbols. Both profiles require actual
sample records. Missing `perf` access or symbols remains a failure; gprof is not
relabelled as a complete process/kernel profile.

Raw `perf.data` can contain private user-stack bytes. It stays under the private
work directory and is deleted. Public artifacts contain its hash and commands,
`perf report`, and `perf script` restricted to
`comm,pid,tid,time,event,ip,sym,dso`. Private PKI keys and TLS-auth material are also
generated only in the private work directory and removed. Certificates, synthetic
payload evidence and encrypted frame captures may be published.

## Execution and receipts

`build-env.json` is the interface from the build step to the controller. It
contains absolute `c`, `hia`, `hia_trace`, `source`, `build`, optional `perf`, and
`ld_library_path` fields. The workflow passes these to:

```text
run_matrix.py --c C --hia HIA --hia-trace HIA_TRACE --source OPENVPN_SOURCE
  --build OPENVPN_BUILD --out PUBLIC/tunnel --private-work PRIVATE
  --budget-seconds 1800 [--perf PERF]
```

The output and private directories must be new/empty and new, respectively. The
controller writes `PUBLIC/tunnel/target-result.json` before performing any
namespace operation. Its schema is `hepta.openvpn-hia.target-matrix.v1` and includes:

- `complete`, explicit acceptance `gates`, and planned/passed/attempted/failed counts;
- every one of the 65 case IDs, its fixed arms/order, status and receipt path;
- exact application, official source closure, configuration and helper hashes;
- host/CPU scope, private-material cleanup and resource cleanup results.

Success requires all eight gates, all 54 performance cases and 216 workloads,
all behavioral/authentication/profile cases, and cleanup. A zero subprocess exit
without this complete receipt is rejected by `verify_result.py`.

The controller owns only namespaces recorded by name, inode and host boot ID. It
stops its own subprocess groups and deletes only those resources. The workflow's
unconditional fallback invokes:

```text
run_matrix.py --cleanup-state PUBLIC/tunnel/owned-namespaces.json
```

That cleanup also checks each PID's network-namespace identity before signaling
it. It neither enumerates arbitrary namespace names for deletion nor alters
unrelated interfaces. Public command outputs and partial failure receipts remain
available after cleanup.

## Interpretation limits and primary references

This design can close the real-device/path and finite behavior blockers on its
actual VM. It yields a controlled comparison within one shared hosted VM and its
local namespace/veth topology. It does not by itself establish WAN, hardware-NIC,
production capacity, exclusive CPU ownership, locked frequency, or deployment
benefit across other kernels. The receipt permanently keeps
`production_performance_qualified: false` and retains all regressions and loss.

- [OpenVPN 2.7.8 DCO documentation](https://github.com/OpenVPN/openvpn/blob/dc1f569087135894ac2703aeabd7a960ee9452d4/README.dco.md)
- [Official ovpn backports at the fixed commit](https://github.com/OpenVPN/ovpn-backports/tree/5fa9098115f7e8fe0d4519864410339557ba16e6)
- [GitHub-hosted runner VM and administration model](https://docs.github.com/en/actions/using-github-hosted-runners/about-github-hosted-runners)
- [Ubuntu 24.04 runner image contents; runtime image remains separately frozen](https://github.com/actions/runner-images/blob/main/images/ubuntu/Ubuntu2404-Readme.md)
- [ESnet iperf 3.16 bidirectional receiver summary logic](https://github.com/esnet/iperf/blob/3.16/src/iperf_api.c)
