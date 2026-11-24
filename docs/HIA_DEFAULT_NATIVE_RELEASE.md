# Native production and explicit reference distributions


## Ordinary native production wheel

On Linux x86-64, `python -m pip install .` builds and installs a native
production wheel. The archive contains the HIA dispatcher, the complete public
Core command set, the supplied-artifact verifier, native scalar NDU, the three
native MCP service programs, native system Jobctl, required HIA sources and data,
and distribution records. It also requires the complete source-attested
`store.hiapack` and its byte-identical `hia-release` installer. The package also includes `hia-source-contract`, the native source inventory
contract producer. It validates the supplied metadata and inventory; it does not
create a cold qualification report. The package contains
the Worker, controller and every declared release member; the public commands
and complete service installation therefore come from the same admitted source,
compiler, cold report and final native package. It does not contain the
`hepta` Python package, Python scripts, Rust programs or CPython extensions.
Python is a source packaging prerequisite, not an installed runtime dependency.

The builder admits the complete current cold report before creating its
output. It binds every native executable and required resource to the actual
source-derived build, validates complete ELF program headers, and generates
the wheel hashes, RECORD and directory records through the HIA wheel owners.
It does not construct a Python base wheel on this production path.

The complete package builder automatically compiles its release bootstrap from
the current cold source and invokes `hia-release-build` with an empty PATH. That
HIA owner runs the same release DAG as the standalone product, including the
native MCP, NDU and Jobctl outputs. The builder accepts no external package
argument. It checks the exact declared member set, final source attestation,
all bytes and modes, and an independent native install/verify readback.

The wheel stores the full archive at `share/hia/store.hiapack` under the installation
prefix. Its distribution records contain `native-components/release-build.json`,
`native-components/release-finalize.json` and `native-package-bindings.json`.
Use the recorded package SHA-256 with `hia-release install` and
`hia-release verify` to create a new private depot from these exact installed
bytes. The resulting digest directory contains the original `hia-worker-install`
and controller installer, with their original private-directory rules.

All public companion bytes must equal their corresponding complete-package
members. The public `hia` dispatcher uses the existing source-bound HIA wheel
layout owner to admit pip's script-directory modes while binding the exact same
package role hashes. Its source and compilation receipt are retained separately;
the complete private package is never patched.

Use a fresh output directory with an already qualified current compiler:

```sh
python -B tools/build_hia_default_release.py \
  --compiler /qualified/current/B3.image.bin \
  --cold-report /qualified/current/cold.json \
  --output /new/private/native-production
```

`tests.test_hia_native_distribution` inspects the actual archive, installs it
through pip, verifies all RECORD entries and executable modes, installs and
verifies the contained complete package into a private depot, checks every
original member and mode, and runs the original Core edit, impact, object, checked-build, register-build and NDU
observations against the installed programs with an empty PATH. Missing
programs, substituted scripts, changed receipts and missing resources refuse
the distribution. Source and installed byte inventories are checked again
after execution.

These package gates do not activate a worker, migrate durable state or qualify
the entire product. Those final service and adoption gates remain independent.

## Explicit hosted reference and development wheels

The remaining sections describe the retained hosted API artifact. It is
excluded from the ordinary production wheel and is selected explicitly:

```sh
python -m pip wheel . --config-settings hia.reference-wheel=true
python -B tools/build_hia_default_release.py --reference \
  --compiler /qualified/current/B3.image.bin \
  --cold-report /qualified/current/cold.json \
  --output /new/private/reference-api
```

The reference archive retains the exact original Python APIs and independently
reproducible controls. Its provenance is `reference-only`, and it does not claim
that retained reference bodies have been removed. Editable builds likewise
remain development artifacts. Historical installed-API fixtures now select
this reference profile explicitly; their results never qualify the production
archive. The independent original semantic assertions remain unchanged.

The explicit reference builder packages the existing complete `full_cost.hepta`
owner with its image, child manifest and a fixed helper-bundle digest. Installing
this Linux x86-64 candidate makes the ordinary `assess_full_cost` call use HIA
without a native selector in the environment. The ordinary worker likewise
captures that package-owned bundle before service effects.

A strict matching-cold wheel supplies a HIA shared ELF linker and independent
ELF inventory for `hia build --backend native --kind shared`. It also supplies
the separate HIA verified linker for `hia build --backend auto --kind shared`
and the checked, scalar and SIMD verification APIs. This replaces external
linkage, not the machine proof policy: the existing independent verifier still
validates the final bytes before publication. Development and portable wheels
do not select these ELF owners by default. An explicitly different linker
argument retains the existing API behavior unless an administrator already
selected a pinned HIA linker.

The standalone executable release also supports the explicit native shared
command without Python, LLVM, or an external linker. It links the admitted
direct object, independently checks the linked ELF and its expected exports,
and publishes the shared artifact with both the object and shared SHA-256
values in the receipt. For a supported scalar Core program, `--backend auto --kind shared`
invokes the verified linker and publishes the final machine-proof receipt.
The implicit local ISA and the selectors `native`, `sse2`, `avx2` and
`avx512` produce the same shared object and machine proof for this scalar
program. The dispatcher carries each explicit fixed ISA to the verified compiler.
For the sum, all-zero predicate and copy kernels over byte buffers, the
fixed targets `sse2`, `avx2` and `avx512` select the corresponding HIA
backend. The implicit target and `native` select the widest supported ISA
across all CPUs in the process affinity mask, including OS support for the
required registers. The standalone prover checks the submitted Core graph,
object relocations and linked instructions.

The checked-in pin is `None`. Source checkouts and ordinary portable wheels keep
their existing defaults and the two retained Python arithmetic bodies. This
change constructs and checks the next default artifact; it does not delete those
bodies, replace SQLite or the Python worker, or activate a production release.

## Platform and public behavior

The active Core CI jobs run on Ubuntu, and native executable profiles declare
Linux x86-64. The portable Python distribution has only a Python >=3.11
requirement. Twenty-five original full-cost/holdout/wire methods have no OS gate;
thirteen real process-observation methods require Linux. The absence of a broader
formal platform promise is not permission to narrow those portable APIs.

When the base wheel contains the CPython Slot extension, the candidate keeps
that wheel's exact CPython ABI tag (for example, `cp314-cp314-linux_x86_64`).
Without the extension it uses `py3-none-linux_x86_64`. Both variants declare
`Root-Is-Purelib: false` and distinguish development from matching-cold builds.
An incompatible target refuses the candidate; the portable source profile is
still available unchanged.
All original full-cost input domains, report fields and refusal ordering remain.

## Reference construction and bootstrap order

```sh
python -B tools/build_hia_default_release.py --reference \
  --compiler /qualified/current/B3.image.bin \
  --cold-report /qualified/current/cold.json \
  --output /new/private/default-native
python -B tools/qualify_hia_default_release_callers.py \
  --package-build /new/private/default-native/build.json \
  --evidence /new/private/default-native-callers
```

The strict builder validates the completed cold report against the full current
source identity before creating its output. It compiles the full-cost owner, direct
linker and independent inventory, checks their compiler output receipts, captures the ordinary package inputs,
and builds an actual ordinary wheel with the existing setup hook. Every production
Python module and packaged source is checked against captured source bytes.

The builder writes the deployment pin to
`hepta/_data/native/default/full_cost/pin.json`. Wheel `RECORD` binds the pin,
the image bundles and the executable scripts. The build report records every
derived member and the final artifact digest. Each installed Python module is
byte-identical to its cold source.

The installed worker hashes the source modules and their declared resources.
The loader separately checks the data pin against the actual cold report,
source inventory, bundles and binder. Existing installations with a pin
declaration in the Python module retain their original RECORD verification.

`--development` is an explicit, mutually exclusive construction mode. Its pin,
wheel build tag, component receipt and package report remain development-scoped.
It cannot supply a matching-source cold qualification.

## Default and administrator custody

The source pin module ships in every package. The loader checks its recorded
identity and the separate deployment data. Removing the data file, changing
its bytes, or selecting different physical inputs causes admission to fail.
Native selection occurs at
the original lazy full-cost admission point, after the same validated arm inputs.
The captured bundle, child manifest, HIA source, image, pin and installed inventory are checked before
and after native entries. No runtime authoring or compiler import is required.

The worker first retains its original ambient-selector and incomplete-pair
refusals. Without administrator flags it then binds the package bundle using its
fixed digest. Scope ownership, file identity, environment restoration and terminal
attestation continue through `native_helpers_scope`.

An explicit administrator bundle takes precedence as a complete executable set.
The default resolver never supplements it. If that scope lacks the full-cost
owner, calling full cost refuses instead of using package or generic-loader code.
An explicit valid alternate full-cost bundle works through its captured image.

## Retained reference arithmetic and compatibility controls

The component controls build and install a real candidate outside the checkout,
forbid both original arithmetic bodies, and check actual HIA calls without
selector variables. They exercise the ordinary worker and restarted service,
explicit bundle precedence and omissions, ambient selection, independent public
threads, missing/corrupt package inputs and warm custody. A real portable wheel
control keeps the previous API available on other host observations.
Repeated ordinary calls also require each image to disappear by reference-counted
cleanup with cyclic GC disabled; the image and its captured custody do not retain
each other through the construction lookup table. Pin and inventory file reads
use an explicit 8 KiB buffer without enlarging their existing read bounds.

The caller qualifier runs all 38 unchanged methods in the six complete original
modules retained by `qualify_hia_full_cost_callers`. It records every planned,
started and stopped identity, actual native calls, installation provenance and
before/after source and package hashes. No skip, expected failure or omitted
method is accepted. `full_cost_0daf86d.py.txt` remains the independent frozen oracle.

Deleting `_reference_arm` and `_reference_decision` is a later, explicit default
transition after matching-current-cold artifact and installed-default gates pass
and the remaining platform distribution contract is settled. Their 26 lines remain in the explicit reference source and distribution;
the ordinary native production wheel excludes them. This reference candidate
does not claim whole-native delivery.
