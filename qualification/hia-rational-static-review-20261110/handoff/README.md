# Text handoff v2 — Mac mathematics and static source/ABI review only

Exact source base/current commit 57d8a56db669fabae4d2fabc7d624ebff3911890.
Frozen ten-file overlay closure:
7b79db99ff05a7410586115483b430feb11dd44c6523d15ec2affcd918b963a8
Closed HIA bridge SHA256:
48bc6205f11278c3c665db12cdafb5f06846fee4a25cfcbe3fe549e37f86cdec

Transport is ordinary UTF-8 JSON groups. Each item has path, literal content,
sha256 and byte_count; no archive/base64 is needed. Save MANIFEST.json, all
named GROUP-*.json and reconstruct.py exactly from the private Page. The
coordinator supplies the manifest/reconstructor SHA separately; verify them
before executing. Run:

    python3 reconstruct.py --manifest MANIFEST.json --groups . --output /absolute/new/review-tree
    python3 /absolute/new/review-tree/verify_math.py --output /absolute/new/math-output
    python3 /absolute/new/review-tree/static_review.py --output /absolute/new/static-output

Optional host HIA static verification (NOT native execution):

    python3 /absolute/new/review-tree/static_review.py --output /absolute/new/host-static --hia-static-verify

Python3.11+ standard library suffices on Mac arm64. No Linux .so, linker, master
artifact, native pin, management key, network, paid model, Worker or guest is
needed for the primary tasks. Optional host verification explicitly chooses
HIA_NATIVE_JSON_SCAN=legacy and HIA_NATIVE_NUMERIC=legacy only as STATIC seeds;
it is not normal required-mode or native acceptance.

Audit prefix800 interval math (midpoints at most768 significant decimal digits),
open/closed endpoints, sign/negative zero, subnormal/overflow, full-input scan,
count/sticky and leading-zero/exponent cancellation. Review the exact HIA decimal,
power5, shifted comparison/subtraction, quotient/remainder and RNE source,
including phase/ACK, page identity, alias, cancellation, missing/no-progress and
partial-write paths. Private scratch failure is not a rollback guarantee.
All files under source/ are exact Git base plus exact frozen WIP overlay.

The embedded native qualification tools are inspection-only here. Their original
cloud absolute paths are intentionally preserved. DO NOT run them on Mac or
create a fake /workspace. Native77 power5,256 limb,72 quotient,180 full bridge
(and smoke10) remain CLOUD NOT_RUN. Math/static results cannot fill these counts.
Normal Worker finitefloat is unmigrated. Do not edit the author candidate or
Worker adapter, contact guest/controller, or read/manage keys. Return static
findings/counterexamples/proposed diffs separately. v1 original is unchanged.
