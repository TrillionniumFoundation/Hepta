# Core retained regression repairs: scoped acceptance, whole delivery OPEN

Qualified implementation: `17bb8c49ec9f259dfd0e1c76ee02b826e508ebef`.
This directory is review-only metadata outside the cold source contract.
All **411** cold-export payloads match that commit's actual Git blobs and the
review tree byte for byte. Source profile:
`selfhost-core-linux-x86_64-v44-retained-core-controls`.

## Actual fresh fixed-source result

**28 stages PASS, 706.099 seconds**, clean source before and after:

- Source controls: **151 PASS**.
- Cold replay: **11/11 + 5,049 native checks**, 110.840 seconds; original
  180-second qualification and three-second cleanup limits unchanged.
- Language witnesses: **1,242 + 10 outer controls PASS**.
- Existing/new components: **193 PASS**; restored independent Core controls:
  **332 PASS**.
- Native child limits/seccomp/side effects/cleanup/mapping/startup controls:
  **30 PASS**, including an actual foreign attempt to restore core dumping.
- Previously failing retained-repository controls: **194 PASS**, including
  the actual source-bound raw-model binary and existing 128-model exhaustive
  frontiers, sessions, historical archive integrity, LLVM, provenance,
  original failed reconciliation, routes and opcode discovery.
- Fresh actual composite execution: **72 ABI calls** on x86-64 and pinned
  AArch64 userspace QEMU, including six bounds traps, two wrong-result and two
  removed-free controls. Not physical-device or general-allocator acceptance.
- Current completed cold archive replay preserves all four independent ELF
  class/flags/symbol/extent mutation controls, with complete custody checks.
- Default/selected Agent controls: **56 each PASS**; real wheel, isolated
  installed worker, native flat/ELF/exec profiles and current B3 installed
  graph/filter PASS.

The real native CI inventory preserves all earlier application/host-region
modules and adds all six process-hardening modules: **36 modules** in total.
No failed, skipped or expected-failing outcome is admitted as a pass.

## Changes and original failures

See the source-bound [runtime fixture rationale](../../docs/HIA_CORE_ONLY_RUNTIME_FIXTURES.md).
The worker disables Linux core dumping before foreign constructors and forbids
reenabling it after seccomp. Passive actual observations distinguished the
system pipe-based collector delay from import/startup overhead. No host-global
collector setting, timeout, cleanup budget or resource cap was relaxed.

Missing research provenance, finite Core target resources, original negative
terminal output and three hash-pinned historical archives are restored exactly.
The exact 611-row historical index is not resealed or shrunk; this does not
claim every historical payload is present. No removed high-level implementation
or compatibility language package is restored. Its orphan test IDs are
explicitly retired without pass credit. Core safety controls remain executable.

The immutable parent `e2fd1c582d7967fb24dab55e6b1c2a2a835929a8` whole-repository
run remains **FAIL**: **3,566 executed tests, 148 failures / 99 errors / zero
skips**, incomplete inventory after class-setup errors. A generic value-role
adapter had incorrectly been supplied to raw-model tests; it is not interchangeable
with the separately source-bound raw-model adapter. Both old failures and the
new correct build receipt are retained. The immutable `17bb8c4...` whole-repository regression completed **PASS**:
**389 modules / 3,590 executed tests / zero failures, errors, skips or expected
failures**, complete static/dynamic inventory; source clean before and after.
Elapsed 1,323.341 seconds; see `full-repository.json` and the exact runner/collector.
This does not qualify whole-native delivery.

The parent cost candidate's actual remote run **42819832134** also remains
**FAIL** at the original cold deadline: source SUCCESS, native 6/11, 28 completed
phases, ten unfinished. Artifact13766420866 and all336 exported Git payloads were
independently checked. Local scoped passes do not establish remote deadline
robustness, and the new source has no remote pass claim.

The actual current-source remote run **42825541295** is also terminal **FAIL**:
source SUCCESS, cold 6/11, 34 phases completed, original/modified names and
exports unfinished. The unchanged 180-second deadline expired; three-second
owned cleanup completed. Later language and application steps were SKIPPED.
Artifact13768367922:49,178,960 bytes, SHA-256
`30af480d9cc3a80ff85a185214ab5093b9e495b56feb0799e5b33c6bb58c99ac`;
all411 exported payloads independently compared to actual review Git blobs.
Local full-repository PASS does not relabel that remote failure.

## Custody and limits

The lossless qualification archive contains **2,584 regular files**,
**362,594,443 uncompressed regular bytes**; every byte and regular-file mode was
compared to its retained original. Archive **50,333,678 bytes**, SHA-256
`826603047077348a25e1e512a216529d9d028146bf9246846adfbd583a3e7978`.
Raw originals and actual prerequisite binaries/receipts remain in the external
evidence area. The large archive is not committed to Git. Reproduction still
requires the explicitly recorded host tools and external prerequisites.

The package has **129 Python files**. Host admission, materialization, wire and
query reconstruction, hashing, patch publication, SQLite and build orchestration
remain dependencies. **All nine whole-native Core/Agent obligations remain
OPEN.** No main/default service/Mac/BIOS change or production activation.
