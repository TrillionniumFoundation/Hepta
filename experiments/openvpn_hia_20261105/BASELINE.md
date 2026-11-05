# Official OpenVPN baseline and application evidence

## Result and scope

The frozen OpenVPN 2.7.8 application builds and runs locally with Clang 20.1.8. Its original C packet-ID calls can be redirected at the ELF link boundary to the independently compiled HIA object and C layout adapter. The same official application objects, OpenSSL libraries and configuration are retained. The final application uses the exact `packet-run-final2/packet.o` and `adapter.o` that passed the differential suite.

Six actual application crypto self-tests passed: C and HIA each with AES-256-GCM, AES-256-CBC and CHACHA20-POLY1305, for every length from 1 through 1,768. Nine real UDP loopback sessions passed the scoped checks: C/C, C-server/HIA-client and HIA-server/C-client, each with a positive session, rejected certificate identity, and rejected untrusted CA. Positive sessions negotiate TLS, exchange encrypted OpenVPN ping records, rekey, and reconnect after a real SIGUSR1. These are `--dev null` application/control/data-crypto probes. They do not carry IP payload through TUN.

A local UDP relay then duplicated one observed encrypted data packet and changed one byte in another copy, in each direction, for both mixed C/HIA orientations. Each endpoint rejected the replay and the authentication tag, remained alive, initialized once and completed subsequent rekeys. The relay only transforms locally generated experimental ciphertext; it does not synthesize a fake successful implementation.

**Real TUN acceptance, DCO runtime acceptance and tunnel performance qualification remain false.** Actual host evidence: `CapEff=0`, `CapBnd=0`, `/dev/net/tun` is absent, and the running kernel configuration says `# CONFIG_OVPN is not set`. `CONFIG_TUN=y` and `CONFIG_NET_NS=y` alone do not make either operation available. The binary includes DCO support, but `--version` reports `DCO version: N/A`. There was no privilege escalation, module loading, route change or namespace workaround.

## Exact source and build freeze

| Item | Frozen value |
| --- | --- |
| Official release | [OpenVPN v2.7.8](https://github.com/OpenVPN/openvpn/releases/tag/v2.7.8), published 2026-10-07T14:18:17Z |
| Annotated tag | `7cf7ae23c051533d42aff2e4fa265d779d422cf1` |
| Source commit | `dc1f569087135894ac2703aeabd7a960ee9452d4` |
| Official release archive | `openvpn-2.7.8.tar.gz`, SHA256 `c070d1d2440b5a6fca6c2c68645c98cd492116ac36ef4f0946177115532c8e36` |
| Source closure | All 545 regular archive files compared with the extracted source before execution |
| Compiler | Ubuntu Clang 20.1.8; exact executable and package hashes in `toolchain-lock.json` |
| Application C flags | `-O3 -g -fno-omit-frame-pointer`; ordinary configure warning/C11 flags also apply |
| Instrumented profile only | The same application build with `-pg` added to compile and link |
| OpenSSL | System 3.0.13; exact linked library hashes in `toolchain-lock.json` and `ldd` logs |
| Disabled optional components | LZO, LZ4, PAM authentication plugin, down-root plugin, upstream unit-test runner |
| DCO | Built into the application; runtime unavailable on this kernel |

The release, tag reference and annotated tag API responses are saved under `baseline-provenance/`. `baseline-lock.json` records their hashes, archive closure, configure choices, build identities and extracted development-package hashes. The tag API returned `unknown_key` for its signature verification; this work does not claim an independently verified release-signing key. Direct shell GitHub API requests returned HTTP 403; the GitHub connector subsequently retrieved the exact metadata. The source archive download itself succeeded and matched its frozen digest.

The source verifier fails before running a binary when the archive digest is wrong or any expected regular source file is absent or modified. It does not simply label an arbitrary input source directory as the frozen commit. `baseline-validation.json` and `baseline-observer-review.json` retain the relevant negative checks.

## Integration and trace evidence

`baseline_link.mk` is included after the official generated `src/openvpn/Makefile`. It reuses `$(openvpn_OBJECTS)`, the official `$(LINK)` command, `$(openvpn_LDADD)` and libraries. GNU ELF `--wrap=packet_id_read`, `packet_id_write`, `packet_id_read_epoch` and `packet_id_write_epoch` redirect external application call sites to the C field-layout adapter, which synchronously calls the HIA exports. There is no native C fallback implementation in that adapter. The original upstream sources and original executable remain available.

The diagnostic binary adds a second layer of link wrappers around the four `ovpn_hia_*` exports. `openvpn_hia_trace.c` reports aggregate entry counts and high-word ABI errors at process exit, without recording payloads, keys or addresses. An uninstrumented HIA binary is also linked. Diagnostic trace binaries must not be used for performance comparisons.

The authoritative application result is **`baseline-application/integration-run-final2/baseline-reviewed-v2.json`**. Its traces establish all four exports actually ran in each positive mixed session:

| HIA endpoint | `read` | `write` | `read_epoch` | `write_epoch` | ABI errors |
| --- | ---: | ---: | ---: | ---: | ---: |
| HIA client / C server | 28 | 32 | 12 | 12 | 0 |
| HIA server / C client | 32 | 28 | 12 | 15 | 0 |

Each HIA crypto self-test separately reports 1,768 ordinary reads and 1,768 ordinary writes, with zero ABI errors. The null-device encrypted ping sessions cover the epoch entries that ordinary crypto self-test mode does not exercise. Certificate-negative cases have zero HIA calls because TLS certificate verification rejects the session before authenticated data-channel setup; that is preserved explicitly.

| Scoped application check | C/C | C server / HIA client | HIA server / C client |
| --- | --- | --- | --- |
| Both endpoints initialize | Pass | Pass | Pass |
| Completed rekeys per server/client, after review | 4 / 4 | 4 / 4 | 4 / 4 |
| Client initializes again after SIGUSR1 | Pass | Pass | Pass |
| Wrong certificate name rejected, no endpoint initialized | Pass | Pass | Pass |
| Untrusted CA rejected, no endpoint initialized | Pass | Pass | Pass |
| HIA positive session invokes all four exports | N/A | Pass | Pass |
| HIA ABI errors | N/A | 0 | 0 |

Identity-name rejection and trust-chain rejection are precise certificate-authentication tests. They do not cover every OpenVPN authentication mode. Raw logs retain transient TLS key-sync errors during the deliberately forced reconnect; these are not removed from the evidence.

### Observer correction retained

Independent review found that an initial parser counted one server-side reconnect key installation as a rekey: a prior soft-reset log was followed by `TLS: Initial packet`, a new session and new keys. The corrected observer ends a rekey candidate at any new-session initial packet, initial trusted-session promotion, initialization completion or hard restart. A rekey requires successful TLS-channel and incoming/outgoing epoch-key initialization within the same remaining segment. Positive HIA session gates also require each of the four export counts to be positive, rather than only a positive sum.

No session was rerun to repair its verdict. The original `baseline.json`, original raw logs, first review and final `baseline-reviewed-v2.json` are all retained. The final review checks original log hashes and states that it is derived from those same logs. `runner-executed.py` preserves the exact original runner and matches the original recorded hash. `baseline_review.py` creates a fresh review file and refuses to overwrite a previous one. Three new-session counterexamples and genuine pre-reconnect rekeys are checked in `baseline-observer-review.json`.

### Actual encrypted replay and corruption

`baseline_udp_replay.py` relays between two real OpenVPN processes through two local UDP sockets. It waits for both endpoints to initialize, then observes actual `P_DATA_V2` records, forwards the authentic packet, sends one exact duplicate, and sends one copy with its final byte flipped. It leaves control-channel datagrams intact and continues forwarding normal traffic.

For both mixed orientations, each receiving endpoint logged one `bad packet ID (may be a replay)` rejection and one `packet tag authentication failed` rejection. Both processes stayed up, initialized only once and completed later TLS/key rekeys. HIA epoch counts were 11 reads / 10 writes as client and 11 reads / 9 writes as server, with zero ABI errors. Full commands, ciphertext digests, injection counts and logs are in `baseline-application/udp-adversarial-final2/`. This covers actual replay and AEAD-rejection behavior for encrypted pings; it does not imply routed TUN traffic.

## Native failure semantics preserved by the boundary

The source of truth is [packet_id.c at the frozen commit](https://github.com/OpenVPN/openvpn/blob/dc1f569087135894ac2703aeabd7a960ee9452d4/src/openvpn/packet_id.c), together with [packet_id.h](https://github.com/OpenVPN/openvpn/blob/dc1f569087135894ac2703aeabd7a960ee9452d4/src/openvpn/packet_id.h) and [buffer.h](https://github.com/OpenVPN/openvpn/blob/dc1f569087135894ac2703aeabd7a960ee9452d4/src/openvpn/buffer.h).

| Native operation | Observable contract relevant to integration |
| --- | --- |
| Short packet ID | Four bytes, network-order 32-bit packet counter |
| Long packet ID | Eight bytes: network-order 32-bit counter followed by 32-bit time |
| Ordinary read failure | Receiver id/time are initialized to zero. A long read with 4–7 available bytes consumes the first four bytes, sets id and then fails while time remains zero |
| Ordinary write failure | First-time initialization and counter increment occur before buffer writes. Append/prepend failure can leave partial byte/buffer/state changes |
| Counter rollover | Ordinary 32-bit rollover is permitted only for long form when `now > p->time` |
| Epoch format | Eight bytes, network order: high 16-bit epoch plus low 48-bit counter |
| Epoch read | A short buffer returns zero without changing id or time. A full zero-epoch record also returns zero but still consumes eight bytes and updates id. Time is never read or written |
| Epoch write | Time initialization and counter transition precede the final buffer operation; the counter is bounded to 48 bits |
| Replay-window scope | Upstream replay code remains active in the full application. Rejection can change diagnostic backtrack statistics; zero mutation on every rejection is not a valid assumed contract |

In particular, a C caller can pass an uninitialized ordinary receiver because the original read initializes it. The final adapter does not pre-read receiver fields. Epoch decoding also avoids reading or writing the unused time field. Raw external ABI invalid-range rejection is a distinct condition from native valid-input partial failure.

## What the original profile says

The original unmodified OpenVPN source was separately built with `-pg` and profiled with `/usr/bin/gprof`. First, 64 default-MTU processes per cipher were run. The GCM profile accumulated **no time samples**; its exact call counts and zero-sample failure are retained under `baseline-profile/profile-run1/`.

The subsequent scoped run used four processes per cipher with `--test-crypto --tun-mtu 60000 --verb 0`. Each process executes the original self-test lengths through 60,168 bytes. Aggregate ordinary packet-ID read, write, replay-test and replay-add counts are each 240,672 per cipher. The flat-profile sample distribution is:

| Cipher | `test_crypto` share of sampled executable time | Packet-ID observation |
| --- | ---: | --- |
| AES-256-GCM | 98.62% | Each ordinary codec/replay operation called 240,672 times; no self-time samples assigned to these operations |
| AES-256-CBC | 96.53% | `packet_id_read` 0.41%, `packet_id_write` 0.20%; coarse 10 ms sampling |
| CHACHA20-POLY1305 | 98.76% | No self-time samples assigned to ordinary codec functions |

The official self-test creates random data, copies buffers and compares every resulting payload byte in `test_crypto`. The expanded MTU amplifies that verification workload. Dynamic OpenSSL shared-library internal functions are not instrumented, and their time is not fully represented by this executable profile. These percentages are not a whole-process or network CPU breakdown. They do **not** show packet-ID coding as a dominant deployed hotspot, and they cannot establish a tunnel speedup. The kernel implementation is justified here as a finite, verifiable integration slice, not as a demonstrated end-to-end bottleneck.

## Reproduction

The local build is outside the repository under `openvpn-baseline/`. No extracted source, binary, PKI key or generated test certificate needs to enter Git.

1. Download the exact official release archive and verify its SHA256 above. Extract to an external source directory.
2. Use the Clang 20.1.8 compiler frozen in `toolchain-lock.json`; provide OpenSSL, cap-ng and libnl/genl development headers. This run extracted development `.deb` files into `openvpn-baseline/host-tools` and did not perform a global installation.
3. Set `SOURCE`, `ARCHIVE`, `BUILD`, `CC`, `PKG_CONFIG`, optional `DEP_PREFIX`, and the local compiler/library `LD_LIBRARY_PATH`, then execute `baseline_build.sh`. It verifies the entire archive closure, configures out of tree, retains configure/build logs and rejects a build without compiled DCO support. Set `PROFILE=1` only for a separate profiling build.
4. Build the HIA packet object and adapter with the packet harness. Include `baseline_link.mk` after the generated official `src/openvpn/Makefile`, passing `HIA_OBJECT`, `HIA_ADAPTER` and `HIA_OUTPUT`. For diagnostics only, compile and pass `HIA_TRACE=openvpn_hia_trace.o`.
5. Run the main application verifier, using a new output directory:

```sh
python3 tools/openvpn_hia_baseline.py \
  --source "$SOURCE" --archive "$ARCHIVE" \
  --c-binary "$BUILD/src/openvpn/openvpn" \
  --hia-binary "$HIA_TRACE_BINARY" \
  --out "$NEW_RESULT_DIRECTORY" --control --require-hia-trace
```

The verifier generates short-lived test keys in the result's `ephemeral-pki/` directory with restrictive permissions. Keep that directory in scratch. Save only the nonsecret command logs and JSON; the retained repository evidence contains no private key files.

For the encrypted UDP probe, use a completed baseline whose binaries and observer have not changed:

```sh
python3 experiments/openvpn_hia_20261105/baseline_udp_replay.py \
  --baseline "$NEW_RESULT_DIRECTORY/baseline.json" \
  --out "$NEW_UDP_RESULT_DIRECTORY"
```

The reviewed historical run retains its original observer snapshot separately; a new run uses the corrected current observer. Do not point the current UDP tool at a historical observer hash without reproducing that exact observer or using a newly executed baseline.

## Unfinished real-tunnel and DCO acceptance

`tunnel_trial.py` provides a future-host trial harness. The read-only current-host preflights have actually executed and returned exit 2; their blocker receipts are in `tunnel-preflight-userspace/` and `tunnel-preflight-dco/`. The actual tunnel branch is staged and **has not executed on this host**.

On an administrator-provisioned test host, supply an explicit OpenVPN configuration, dedicated interface, tunnel source/peer addresses, and a remote peer already running OpenVPN and iperf3. The harness records binary/config hashes, waits for initialization, checks the actual interface kind and route to the traffic target, runs iperf3 bound to the tunnel address, captures local OpenVPN CPU ticks and complete output, and cleans up its process. DCO trials require an actual `ovpn` interface and a `DCO device ... opened` log; falling back to userspace cannot pass the DCO gate. A single completed trial still leaves `performance_qualified=false`.

The required comparison remains three distinct measurements: the finite native C/HIA codec kernel, identical OpenVPN configurations with DCO disabled, and the official C application with actual DCO. For the latter two, use the same hosts, cipher, transport, MTU, workload sizes/directions, affinity and offered loads; alternate/repeat cases, retain losses and all regressions, report application/kernel CPU separately, and preserve real offload interface/peer counters. Authentication/replay/reconnect/rekey qualification must also be repeated with real IP traffic. Kernel benchmark gains and null-device success do not complete those gates.
