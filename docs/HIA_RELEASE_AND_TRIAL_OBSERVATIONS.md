# Native release comparison and inference failure observations

The seven-track increment adds implementation and measurement coverage. It
does not establish Rust performance parity, AI coding productivity, universal
resource safety, or whole-program optimality.

## Strong release baseline

`tools/qualify_hia_release_parity.py` freezes the source, input protocol and
tool identities before any native measurements. It executes the existing
fallible owned-byte allocation/fill/checksum/release kernel through C, C++,
safe Rust, and the production Hepta Core-to-LLVM object path.

The `optimized-release-v1` profile explicitly uses Rust opt-level 3, fat LTO,
one codegen unit, panic abort, omitted frame pointers and overflow checks off.
Seed addition still uses `wrapping_add`. The workload bounds the length at
65536 and sums bytes into u64, so disabling implicit overflow checks does not
change the registered arithmetic contract. C and C++ use O3 and thin LTO.
Hepta retains its ordinary O3 object backend. Different compiler versions,
runtime implementations and link-time IR availability remain disclosed;
identical code-generation flags are not claimed. The previous checked,
instrumented build profile remains available and remains the default of the
existing NDU campaign.

Three old sizes and seven additional sizes receive three seeds and 21 samples
per seed. These are 63 observations of a batch of 64 calls per backend/size.
The reported p99 is the observed maximum of those batches, not a per-call tail
guarantee. The extra sizes were not used by the earlier campaign; they are
authored finite holdouts, not external production traffic. This is one kernel,
not an application suite. No optimizer sees or tunes against the measurements.

Each actual child checks results against an independent periodic-byte formula
and probes the native allocator: empty allocation, successful allocation and
release, refused allocation, peak requested/usable size and final live state.
Every sample and timeout is retained. Missing, duplicate or padded cohorts
reject. Source, tool and generated-library identity drift invalidates the
observation. Campaign elapsed time includes build, validation, loading,
measurement and cleanup; nested command timings are not added a second time.
Human effort, historical tool acquisition and energy remain unknown.

The result may be a valid negative performance observation. Failing the
registered median/tail thresholds must not turn into an infrastructure retry
or be hidden behind a passing correctness result.

## Owned model process observations

`tools/provider_adapter/llama_cpp_engine.py` now retains an attempt record even
when template rendering, tokenization, transport, response validation or the
generation deadline fails. A known input count is kept; unobserved output
usage remains null. The wall budget is shared across template, tokenizer and
completion stages. A timer shuts down the exact owned Unix socket so a slow
HTTP body cannot continually renew a per-read timeout. Scheduler latency and
process startup still prevent a hard real-time guarantee.

The raw completion body is saved before rejecting a server that has exited.
HTTP framing distinguishes a complete response from a truncated body. Partial
bytes remain evidence but do not increment the complete-response counter.
Unsupported unframed responses reject. None of these records grant permission
to accept generated code or fabricate token counts.

Closing the engine writes the owned subprocess return code, whether shutdown
requested terminate/kill, completion counts, elapsed lifetime and before/after
cgroup observations. Repeated close preserves the original receipt. The
cgroup may contain unrelated jobs, so even an OOM counter change never proves
that this model was killed by OOM. The receipt explicitly leaves that causal
claim false.

Tests include a real nonzero-exit child, real timed-out compiler-process output,
a real slow Unix-socket response, missing token evidence and finite-cohort
tampering. These are transport and accounting checks, not model answers or
evidence that one programming language helps an AI agent code better.
