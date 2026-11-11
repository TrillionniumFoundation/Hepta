# Unified candidate source and retained evidence binding

## Concrete defect

At main 5831f52fada45e076f8f68f198a15c0585e6104f, the worker's installation
manifest includes all declared NATIVE_SOURCE_FILES and PUBLICATION_BUILD_FILES.
That is 34 native language sources and four publication build inputs. The
independent candidate preflight counted Python and discovery documents only.
Its independently computed worker digest therefore could not match the actual
current worker. A clean checkout was insufficient to prepare a joint candidate.

The preflight now reads those literal source inventories without importing or
evaluating the selected contract, snapshots every declared asset, and checks
each actual Git blob against the selected revision. Redefined, computed,
duplicate, escaping and symlinked inventories refuse. Historical workers with
neither optional inventory retain their previous empty native asset domain.

A new current-source regression invokes the actual worker's read-only
installation-manifest command and compares its digest with the independent
inventory. The original 34 preflight tests remain selected in the separate
candidate identity workflow. The new 17 tests cover the actual manifest
comparison and explicit synthetic identity/evidence refusal boundaries.
Synthetic records are never native execution evidence.

## Explicit native helper selection

The optional worker configuration pair is:

- native_helpers_manifest: the already authorized absolute path to the selected
  helper bundle.
- native_helpers_sha256: the SHA-256 of the bundle's exact original bytes.

Both must be present or absent. The manifest path remains subject to the
existing host read and protected-path rules. No host, command, path grant or
write authority is added. The configured pair is passed to the worker's
read-only installation-manifest command, whose actual fourth installation pin
must match. Existing three-pin configurations retain their wire domain.

Preparation runs where the selected source and native helper inputs can
actually be read. A remote path is not translated into a local file or fetched
under another identity. The worker loader remains responsible for validating
each selected helper manifest, actual native image, source identity and ABI.
Preflight rereads the selected bundle's digest before returning and when
reloading the candidate; it does not activate an additional mapping.

## Native support identity

New candidates retain native_support_identity, containing the exact support
contract digest, profile, target, ABI, support-domain digest, syntax digest,
limits digest and complete source-manifest digest.

These fields identify the declared bounded Selfhost-Core domain. They do not
make direct, Selfhost, standalone and ordinary Core support identical. The
complete existing support document remains the authority for limitations such
as internal multi-return bounds, tail recursion, resource ownership, libc
allocation obligations and public ABI restrictions.

The original source_qualified field still means exact source/configuration
identity. It does not mean native execution, whole-candidate acceptance or
deployment.

## Original evidence bundle

Preparation accepts optional --qualification-evidence and
--qualification-evidence-sha256 arguments, supplied together. The input file
has this exact shape:

    {
      "schema": "hepta.hia.unified-candidate-evidence.v1",
      "artifacts": {
        "cold": {"path": "/absolute/original-cold.json", "sha256": "<64 lowercase hex>"},
        "language": {"path": "/absolute/original-language.json", "sha256": "<64 lowercase hex>"},
        "language_assertions": {"path": "/absolute/original-language.assertions.json", "sha256": "<64 lowercase hex>"},
        "native_image": {"path": "/absolute/hia-native", "sha256": "<64 lowercase hex>"},
        "native_build": {"path": "/absolute/build.json", "sha256": "<64 lowercase hex>"}
      }
    }

The inventory can be partial. Every supplied entry must have exact bytes,
a supported schema and compatible source identity; unknown artifact types
refuse. Missing entries stay missing. All source files declared by the support
contract are reread and checked against the selected Git commit, including
files hidden from ordinary Git status with assume-unchanged.

The retained component gates are:

| Gate | Required binding |
| --- | --- |
| cold | Original outer cold report, exact source/profile, all eleven original checks, zero integer exit, unchanged 180-second qualification and 3-second cleanup limits, observed original owner completion/cleanup, and identical three-generation compiler digests. |
| language | Original language report on the same source/profile, complete reported check counts, both compiler modes, the six fixed source/reference/fixed-point checks, exact original ten-test native assertion report, and the same compiler as the cold report. |
| native_image_build | Original agent-stdio build receipt, the three declared dispatch/packer/frontend sources, the exact successful cold report and compiler, actual canonical Linux x86-64 ELF headers/segments and exact executable digest/length. |
| native_worker | Not established by these build reports. Durable ordinary MCP request, replay, unknown-outcome, restart, rollback and lease consumption need their own actual worker qualification. |

A failed original cold report remains failed. A timeout is not repaired by a
later unrelated successful report, and a missing language/native job is not
converted into success. All supplied artifact digests remain in the candidate
for original-result custody. Reloading checks these exact bytes again.

The bundle checks local artifact integrity and consistency of retained finite
component reports. It is not an independent execution attestation, a signature
authority or a proof of all admitted programs. The build record alone does not
prove that MCP used the native image.

## Qualification result and compatibility

Every newly prepared candidate includes qualification.status = HOLD and
whole_candidate_qualified = false until the separate native-worker requirement
is established. Even three passing retained component gates leave this
boundary explicit. Source pinning, supplied capture verification and actual
catalog discovery cannot silently acquire whole-candidate qualification.

The existing unified-candidate.v1 wire format remains additive. Legacy
candidates without the new evidence fields keep their original reading
behavior; all existing source, transport, tool and configuration pins still
apply. The preflight never rewrites an old candidate or treats a changed
preflight implementation as the originally pinned tool.

The separate GitHub workflow preserves the checked-out commit/tree, relevant
source/test digests and the full original unittest log on both success and
failure. Its result covers candidate identity boundaries only. Existing Core,
cold, language and native workflows remain required and unchanged by this
workflow.
