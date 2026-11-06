# Reproducible HIA candidate delivery

HIA is a typed virtual assembly language for AI Agent authored programs and
verified optimization. Its standalone Core has independent semantics, ownership
and resource checking, an interpreter and direct LLVM compilation. This candidate
packages that implementation; each broader application, performance and production
claim still requires its own exact-source evidence.

## One source identity

The release entry is `tools/build_hia_candidate.py`. Its default requires a clean
Git checkout and an absent output directory outside that checkout. It records the
full commit and tree IDs, every installed Python module and HIA package data file,
the packaging configuration, the two build/verification tools and bundled smoke
inputs. The full, sorted source roster has its own SHA-256. The manifest also
captures the actual schema/opcode/route registry, compiler identity, LLVM emitter
identity and the target/ABI scope from the same source. A source change during the
build rejects the candidate.

Inventory imports use an isolated Python process with a new empty bytecode-cache
prefix. `-B` alone still reads valid `.pyc` files; the explicit prefix prevents a
checkout cache from changing the recorded inventory or archive. Existing source
caches are preserved.

Each candidate receives a PEP 440 local package version:

`0.2.0+hia.g<12-digit-Git-ID>.s<12-digit-source-seal>`

The complete identities remain in the manifest; abbreviated version components
are labels, never authority or proof of compatibility. The base language package
version remains 0.2.0. Development builds require `--allow-dirty`, record that fact,
and are refused by clean verification unless the verifier receives that same
explicit development option.

The default branch and older PRs are discovery/history. They do not replace this
candidate's full commit or prove this candidate passed older experiments. The
existing `tools/release_check.py` and production blocker ledger remain applicable
to broader release claims.

## Build twice, compare, install from exact bytes

Run from the intended clean checkout, using two new sibling output directories:

```sh
python tools/build_hia_candidate.py --output-directory ../hia-candidate-a
python tools/build_hia_candidate.py --output-directory ../hia-candidate-b
cmp ../hia-candidate-a/SHA256SUMS ../hia-candidate-b/SHA256SUMS
python tools/verify_hia_candidate.py --candidate-directory ../hia-candidate-a \
  --output ../hia-candidate-installed.json
```

The wheel uses sorted entries, fixed ZIP timestamps and modes, and stored bytes
rather than a platform-dependent compressor. The manifest and `SHA256SUMS` have no
wall clock, host path, temporary directory or build-tool version. Rebuilding the
same source snapshot therefore produces byte-identical bundle files. Verification
receipts contain their actual observed command paths and are separate artifacts.

The bundle contains a standard pure-Python wheel, `candidate-manifest.json`,
`SHA256SUMS`, the exact source `pyproject.toml`, two HIA inputs and a standalone
`verify_hia_candidate.py`. It can be
transferred and checked without the checkout:

```sh
python verify_hia_candidate.py --candidate-directory . \
  --expected-manifest-sha256 <full-sha256-from-the-trusted-build-receipt>
```

The SHA-256 manifest checks integrity and binding; it is not a signing key or an
independent release attestation. Pin its full digest from the trusted build receipt
when transferring a candidate. Neither a file's name nor a newly recalculated hash
makes an untrusted replacement a release.

The verifier checks the exact bundle roster, wheel member roster, packaged source
bytes, embedded candidate identity and every wheel `RECORD` entry. It rejects
symlinks, duplicate members, changed fixtures, unlisted payloads and mismatched
source or manifest digests before installation. The manifest envelopes and file
entries have exact field sets and types; candidate claims must remain false.
Both manifest and embedded identity require canonical finite JSON. Wheel metadata,
dependencies and console entries are reconstructed from the source-bound
`pyproject.toml`; rehashing `RECORD` cannot add an undeclared command.

The verifier installs captured wheel bytes
with `pip --no-index --no-deps --no-compile` in a fresh temporary venv, with imports
isolated from both the checkout and user site packages. Before importing HIA and
again after all smoke checks, an independent parent process compares the complete
installed `hepta/` file roster and every byte hash with the source manifest,
including nested Python modules and `.hia`/`.hiaasm`/`.json` data. It records the
file count and package-manifest hash at both boundaries. The historical top-level
`compiler_hash` remains useful, but does not replace this whole-package check.

## What the installed qualification executes

The installed qualification executes the following from outside the source tree:

- Both bundled HIA inputs through the production verifier, including primitive v8.
- The counter interpreter, requiring `increment(40) == 41`.
- v8 LLVM emission for x86-64, AArch64 and RV64, checking each exact target triple.
- The installed `hepta hia routes` console entry and runtime/compiler identities.
- The packaged quota application when present: initialize 100 units, reserve 40,
  upgrade from v1 to v2, then recover the same state in a fresh process. This
  executes the installed `.hiaasm` resources as well as the Python host interface.

All `hepta` subpackages and their `.hia`, `.hiaasm` and `.json` data are packaged.
No historical experiments, large evidence trees, Rust build output or host tools
are copied into the wheel. The ordinary setuptools configuration also discovers
subpackages and declared HIA data; the deterministic candidate builder does not
substitute a different runtime implementation.

To additionally build and execute the installed counter on a supported Linux
native host, supply an existing actual Clang 20+ executable:

```sh
python tools/verify_hia_candidate.py --candidate-directory ../hia-candidate-a \
  --clang /usr/bin/clang-20 --output ../hia-candidate-native.json
```

The native check retains the production compiler receipt and calls the resulting
shared library. It qualifies that counter on the measured host. Cross-target IR
emission is recorded separately and does not claim target execution. Optional SMT
verification needs the pinned `z3-solver==4.15.4.0` dependency; Rust shadow checking,
AArch64/QEMU execution and research adapters retain their own repository/toolchain
requirements. Those profiles are not made wheel-complete by these smoke checks.

## Regression gate and promotion

```sh
python -m unittest tests.test_hia_candidate_release -v
```

The regression gate builds two byte-identical candidates, installs one in a clean
venv, checks nested package data, and rejects corruption, source/data mismatches,
wrong external pins, symlinks, extra bundle files, output replacement and dirty
source promotion. It also supplies an actual timestamp-valid stale bytecode cache,
reseals unknown fields and an extra console entry, and corrupts installed nested
code/data before or after smoke execution. Its temporary Git repositories and
outputs are isolated from the product checkout.

A delivery can be described as an **installed, reproducible HIA candidate** only
with the candidate manifest, full source identity, equal rebuild digests and its
installed verification receipt. Production qualification, whole-language
soundness, cross-target execution, Agent productivity and NDU net benefit remain
separate explicit claims. These tools never turn them true.
