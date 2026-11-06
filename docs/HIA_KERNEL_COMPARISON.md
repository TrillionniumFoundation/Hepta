# Registered comparison of complete HIA Linux images

This driver admits actual complete Linux images, freezes eight actions before any
boot in a cell, executes each action in a new disposable KVM VM, and reports a
five-block paired comparison. It does not build kernels. Its unit tests and native
arithmetic fixtures are not kernel performance observations. No NDU advantage is
assumed, and a failed image, native call, serial trace, or interrupted boot stops
the campaign without a retry or a replacement seed.

The machine-readable preregistration is
`experiments/hia_linux_full_20261106/COMPARISON_PROTOCOL.json`. The actual execution
entry point is `tools/qualify_hia_kernel_comparison.py`. Source and artifact hashes,
the phase schedule, all requests and responses, complete QEMU command receipts,
raw serial bytes, and unaggregated guest samples remain in the campaign directory.

## Four complete images and eight policies

The admitted artifacts are `stock`, `hia-original`, `hia-o3`, and `hia-os`, from
the same Linux 6.18.60 archive/configuration and LLVM 20.1.8 toolchain. Each HIA
image must have a complete successful import build, legacy build/boot checks,
all configured target C and assembly reconstructed through HIA, zero C fallback,
and a closed compiler/host-tool/derivation/final-object inventory. HIA variants
use separate build roots, ledgers, and retained-program roots. Generated HIA
bundles are not assumed identical. Identical resulting image hashes are allowed
and reported honestly.

The native adapter's `O2` slot means the **original per-translation-unit backend
flags**, including Kbuild's O2/Os mixtures. It does not mean a uniform `-O2` kernel.
The `O3` and `Os` slots refer to independently imported full images with their
explicit backend policy. Every image also needs a separate actual KVM `all`
qualification with the same static guest, seed 20261106, 1024 iterations, CPU
placement 0,1, collector, QEMU dependencies, and kernel release. Qualification
timing never becomes training data; qualification can occur while another image
is being compiled.

| Arm | Actual decision implementation | State and model |
| --- | --- | --- |
| stock | Registered fixed image | No calibration or search needed for delivery |
| hia-static | Registered original HIA image | No calibration or search needed for delivery |
| best-fixed | One training-only image selection | Four-phase public objective; frozen before heldout |
| greedy | Python instantaneous utility | Same complete feasibility information; only first actions with a feasible suffix |
| ordinary-mpc | Python finite-horizon enumeration | Current public target held across the horizon |
| independent-same-objective | Independent native Rust integer control | Its own prior weights; no NDU response or opaque state input |
| fixed-ndu | Actual production Rust NDU adapter | Actual native fixed mode and returned state lineage |
| dynamic-ndu | Actual production Rust NDU adapter | Actual returned next_request_state/revision lineage |

The independent Rust control and production adapter use the same Rust 1.95.0
release toolchain and cold-process JSON calling mode. Python independently
recomputes preference convergence and every candidate term, recursive value,
feasibility decision, frontier, and selected first image. The independent Rust
decision is completed before either NDU call. Its previous weights come only from
its own previous response. No Python policy is renamed NDU. Python versus Rust
runtime differences are not interpreted as a framework advantage.

## Training, prediction, and a real shared prediction budget

Calibration consists of three separate KVM `all` boots for each image, using
training seeds 20261107, 20261108, and 20261109. All twelve requests, run IDs, output
directories and exact QEMU argv are written before the first calibration boot.
Each phase's five measured repetitions first become one median per boot. A single
boot cannot provide three independent calibration observations. Training and
qualification IDs, output directories and raw-log hashes must be disjoint.

Before calibration and heldout boots, a bounded visible-`/proc` observation must
show no compiler, make, Cargo, linker or other QEMU process. This gate is not an
exclusive-host claim. The recorded host profile uses two different physical cores
on one socket/NUMA node, schedutil, unlocked frequency, and nonexclusive cores.
Calibration plans must postdate all four completed build receipts. Qualification
observations are never used by the predictor.

Prediction uses the latest nine independent boot medians for each image/phase,
starting with its three training boots and adding only complete past cells. All
adaptive arms see the same completed history. Partial current-cell observations
and future heldout outcomes are excluded. Stage zero is the public current phase;
the remaining three stages use an exact rational Markov distribution learned
from training and completed phase transitions, with one Laplace pseudocount per
ordered phase pair. The controller does not receive the future phase schedule.

The horizon contains all **81 complete image paths plus literal abstain**. There
is no score pruning. At each image/stage, the model averages observed phase
duration predictions under that stage's phase distribution, converts nanoseconds
to Q32 microseconds using nearest ties-to-even, and sums the four stage costs.
The shared budget is the same model's complete four-stage `hia-original` path
cost. This retains a feasible incumbent and creates actual cross-stage resource
coupling. Every planner receives the same full candidates and budget. Greedy
maximizes its immediate objective only among first images with a feasible suffix.
This is a **prediction budget**, not a real-time deadline guarantee or a calibrated
safety probability. Actual timing remains reported even when predictions err.

Latency utility is Q32 `100 * stock training median / predicted or observed
median`; size utility is Q32 `100 * stock bzImage bytes / selected image bytes`.
Image size is not runtime RAM. Public target weights are respectively
`[1,0]`, `[3/4,1/4]`, `[1/2,1/2]`, `[1,0]` for syscall/process/pipe,
anonymous memory, tmpfs, and UNIX/loopback TCP. These targets are registered QoS
inputs; the experiment does not claim that NDU learns the targets. Genesis/fixed
weights are `[3/4,1/4]`, eta is 1/4, residual tolerance is 4096 raw Q32 units, and
at most 64 steps are permitted. Discount is 7/8, terminal utility is zero, and
switch cost is zero because all actions are already separate cold boots. Risk
and uncertainty are unmodeled zero, not certified probabilities. If the entire
optimal frontier does not have a common first image, abstain executes the
incumbent for the full workload and incurs all actual costs.

## Lifecycle and inputs

Create one input JSON with schema `hepta.hia.kernel-comparison.input.v1`:

```json
{
  "schema": "hepta.hia.kernel-comparison.input.v1",
  "campaign_id": "full-linux-r1",
  "driver_source_commit": "EXACT_40_HEX_COMMIT",
  "driver_source_manifest": "/absolute/driver-source.json",
  "collector": {
    "path": "/absolute/qualified/tools/hia_linux_system_benchmark.py",
    "source_commit": "e3d2deac454993c8f70fd9182eff7f379d9375d1"
  },
  "native_summary": "/absolute/kernel-ndu-dev-r1/native-build-summary.json",
  "ordinary_control_summary": "/absolute/kernel-ordinary-dev-r1/native-build-summary.json",
  "guest_build_receipt": "/absolute/guest-bench-dev-r2/STATIC_BUILD.json",
  "host_profile": "/absolute/host-profile-r1/RESULT.json",
  "qemu": "/absolute/qemu-system-x86_64",
  "qemu_data": "/absolute/qemu-data",
  "qemu_modules": "/absolute/qemu-modules",
  "bios": "/absolute/bios.bin",
  "images": {
    "stock": {"build_receipt": "/absolute/stock/RESULT.json", "qualification": "/absolute/stock-kvm/RESULT.json"},
    "hia-original": {"build_receipt": "/absolute/hia-original/RESULT.json", "qualification": "/absolute/original-kvm/RESULT.json"},
    "hia-o3": {"build_receipt": "/absolute/hia-o3/RESULT.json", "qualification": "/absolute/o3-kvm/RESULT.json"},
    "hia-os": {"build_receipt": "/absolute/hia-os/RESULT.json", "qualification": "/absolute/os-kvm/RESULT.json"}
  },
  "external_runtime_evidence": []
}
```

The source manifest is `{"commit":"EXACT_COMMIT","files":{"repository/path":"git_blob_sha1"}}`.
It must bind these four comparison files and the two unchanged helper files
`tools/hia_linux_full_inventory.py` and `tools/qualify_hia_linux_baseline.py`.
Materialize those blobs from the named commit and independently check the Git blob
hash; a claimed commit string alone is insufficient. The comparison code also
binds its executable source files for every subsequent action. Native source and
qualified collector commits/blobs are pinned in the driver.

Commands are explicit; importing the module starts nothing:

```sh
python3 tools/qualify_hia_kernel_comparison.py calibrate --spec /absolute/spec.json --output /absolute/calibration-new
python3 tools/qualify_hia_kernel_comparison.py register --spec /absolute/spec.json --calibration-result /absolute/calibration-new/RESULT.json --output /absolute/campaign-new
python3 tools/qualify_hia_kernel_comparison.py plan-next --output /absolute/campaign-new --phase syscall_process_pipe --seed 20261200
python3 tools/qualify_hia_kernel_comparison.py execute-next --output /absolute/campaign-new
```

Call `execute-next` eight times in the registered order; then call `plan-next`
with the next public phase/seed from the frozen registry. Twenty complete cells
produce five blocks × four phases × eight arms = 160 actual single-phase boots.
Run `evaluate --output /absolute/campaign-new` only after all succeed. There is no
automatic rerun command. A process interrupted after marking an invocation in
flight cannot be silently restarted. A new campaign means a new preregistration,
with failed prior evidence retained.

Register performs the expensive whole-target/retained-HIA/program-index/final-
object closure once. Evaluate repeats it once at the end. Per-boot checks cover
the frozen registry chain and actual selected image, config, guest, source,
QEMU/BIOS/dependencies, and CPU placement; they do not rescan thousands of HIA
units. Calibration performs receipt/hash admission without the repeated full
target-file traversal. Every accepted serial trace is reparsed by the bound
collector from raw UTF-8 bytes, preserving CRLF, with PREEXECUTION, TRACE and the
sole command receipt required to agree. The common deterministic initramfs is
independently rebuilt from the bound static guest at admission.

## Statistics, costs and limits

Each boot retains two warmups and five measured repetitions, operation counts,
checksums, correctness, CLOCK_MONOTONIC_RAW durations and process rusage. Report
guest ns/op by phase, QEMU whole-wall time, controller wall/CPU/service time,
net delivery wall, and image bytes. Five whole blocks are the independent
clusters. The exhaustive paired block bootstrap has 3125 resamples and reports
95% percentile intervals and exact rational point estimates. Twenty phase cells
and 100 within-boot measured repetitions are not independent cluster counts.
The comparisons are descriptive and have only five block clusters.

Static delivery pays only its own required image preparation and qualification.
It is not charged the three-image search, twelve-boot calibration, or an unused
native adapter. Other arms pay their necessary image/calibration preparation;
only the actual native implementation's preparation is charged. Build receipts
retain individual wall and child CPU costs. Parallel build intervals are merged
for active time and their actual start/end window is reported as observed
makespan, including disclosed idle gaps; the sum of parallel walls is not called
elapsed deployment time. Concurrent builds are not isolated build-speed tests.

Shared feedback is not free: results report direct delivery with supplied past
feedback and a separate scenario charging acquisition of all shared boot
feedback. Common model/candidate construction is charged to each adaptive arm
when estimating standalone controller cost, while actual once-per-cell planning
wall is also retained. Native decision wall includes request/state preparation,
JSON serialization/parsing, durable request/response logs and cold-process I/O;
the inner process wall and native service time remain separate fields. Independent
Python arithmetic verification is recorded as audit cost. Admission/audit/statistical-processing costs are separated
from controller mathematics. Unamortized setup and amortization at 1, 10, 100,
1000 and 10000 four-phase cold-boot cycles are reported. Break-even is conditional
on the observed workload/cost regime and is unreachable without positive measured
per-cycle savings.

If independent-same-objective and dynamic-NDU select the same images, there is no
NDU-specific decision gain demonstrated by this experiment. Their real native
implementation costs remain comparable. Identical stock/original image bytes
must not be turned into a claimed HIA speedup from timing noise. Cold boots do not
measure seamless live kernel replacement. Hash/lineage checks detect mutation,
reuse and inconsistent evidence; they are not cryptographic proof against an
operator fabricating all files. Preserve the outer HeptaRuntime durable job ID,
terminal exit, output-complete/output-durable evidence and frozen schedule along
with the final report. The driver never invents those outer runtime attestations.

## Local verification

```sh
python3 -m unittest discover -s tests -p test_hia_kernel_comparison.py -v
```

The suite checks exact signed arithmetic, the complete path denominator,
nontrivial prediction budgets and one-raw-unit feasibility boundaries, greedy
suffix feasibility, abstention, data-partition/refusal gates, terminal failure,
five-block statistics and cost ownership. Its synthetic values are deliberately
not formatted as accepted build/collector receipts and cannot register a real
comparison campaign.
