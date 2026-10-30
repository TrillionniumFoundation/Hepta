# P7 V11: fixed Qwen3.5-4B candidate, fresh terminal evidence

This bundle records a completed negative qualification observation on local frozen
source `50c4067399989e7194028576c38c0e783b78cf06`. It was locally frozen before the
run; it was not publicly preregistered. No study source, task, prompt, decoder,
attempt limit, token budget or answer was changed during execution.

## Result and denominator

| Stage | Fresh result | Interpretation |
| --- | --- | --- |
| Capacity and native references | 19/19 reference controls; 95/95 independent tokenizer calls; 76 exact rendered-request checks; 0 generation requests | These are reference/capacity controls, not model coding successes. |
| Model qualification | 0/3 tasks correct; 3 attempts per task; 9 requests and 9 complete responses | The one candidate did not qualify. The process exit code 0 records a valid completed observation, not model eligibility. |
| Main study | Actual CLI exit 1 with `E_TOOLSTUDY_NO_QUALIFIED_MODEL` | Rejected in `validate_qualification`, before output directory creation or engine initialization. There are 0 main cells and 0 main generation requests; the registered 16 cells were not executed. |

| Qualification task | Terminal status | Attempts | Input tokens | Output tokens | Total tokens |
| --- | --- | ---: | ---: | ---: | ---: |
| `json_scalar_reasoning_rust_node` | `observable_wrong` | 3 | 5,791 | 122 | 5,913 |
| `two_file_signature_repair_rust_node` | `response_rejected` | 3 | 7,996 | 2,772 | 10,768 |
| `owner_flow_repair_rust_node` | `response_rejected` | 3 | 8,056 | 603 | 8,659 |
| **Total** | **0/3 correct** | **9** | **21,843** | **3,497** | **25,340** |

Every generation has a retained raw request, SSE stream, terminal usage receipt,
answer and evaluation. There are no unknown-usage requests. No answer was repaired
by a person or host procedure, no model was substituted, and no additional model
trial was performed after this result. The failed qualification cannot establish
a four-arm language/interface advantage or a general claim about the model's
coding capability outside this particular protocol.

## Fixed identities

The candidate is the **Unsloth** `Qwen3.5-4B-Q4_K_M.gguf` quantization, not an
official Qwen GGUF. Its repository is `unsloth/Qwen3.5-4B-GGUF`, revision
`e87f176479d0855a907a41277aca2f8ee7a09523`. The file has **2,740,937,888 bytes** and
SHA256 `00fe7986ff5f6b463e62455821146049db6f9313603938a70800d1fb69ef11a4`.
Official Qwen model/template provenance is pinned to
`851bf6e806efd8d0a36b00ddf55e13ccb7b8cd0a` of `Qwen/Qwen3.5-4B`.

The archive contains the frozen protocol, provenance, 211 source bindings and both
source snapshots, plus identities of the 40 pinned llama b11669 runtime members
and the actual compiler/Python tools. Model weights and system/runtime binaries
are deliberately absent. Official benchmark claims served only as candidate
selection context and did not grant qualification or establish quantization
equivalence.

The original acquisition, deliberate cache eviction, exact-byte restoration and
resource-release receipts are preserved separately. Restoration used one `curl`
attempt with no retry; the file was renamed only after its exact size and full
SHA256 matched. The earlier acquisition receipt was not overwritten.

## Costs and closure

| Measured component | Seconds |
| --- | ---: |
| Original candidate acquisition | 41.630981373 |
| Resource cleanup | 0.588722641 |
| Exact-byte restoration, including verification | 50.896889846 |
| Capacity, outer process | 79.384721413 |
| Qualification, outer process | 697.485887898 |
| Actual main-entry refusal, outer process | 2.874049887 |
| Read-only closure/identity check | 0.232963902 |
| **Sum of those disjoint measured components** | **873.094216960** |

The three phase outer costs total **779.744659198 seconds**. Inner qualification
wall time, cell times and request times are nested in that value. In particular,
the **59.761532163 seconds** of tokenizer CLI work are a capacity subcomponent,
not an additional cost to add again. Restoration's **48.244715598 seconds** of
download time are similarly included in its total above. These are recorded P7
components, not a complete project-cost claim: earlier research and shared-tool
cost allocation are unknown here, not zero. Packaging/readback costs have separate
receipts outside the archive to avoid self-reference.

Capacity and qualification engines finalized and exited normally. A subsequent
read-only scan in the correct PID namespace inspected four processes and found
no model/runtime executable, open-file or mapping references, with no inspection
errors. Source, tools and model identities remained unchanged. The process
resource sampler's `exited_during_observation` flag can also mean an unavailable
`/proc` child entry; it does not establish model peak RSS or runner termination.
Use process return codes and final engine records for closure. Host timing is
descriptive; `performance_timing_qualified` remains false.

## Archive and offline verification

The archive retains **1,355 regular files / 99,539,487 uncompressed bytes**, with
all fresh raw artifacts. Historical V9/V10 protocol/source context is explicitly
separate and is not replayed or inherited as fresh qualification.

- Archive: `p7-v11-20261030.tar.xz`, 3,728,628 bytes.
- Archive SHA256: `27c9c087f92bd4458c6d7c4780ec16a784e8a7c0acf02b4808328fc3b79e529a`.
- Manifest: `p7-v11-20261030.manifest.json`.
- Manifest SHA256: `42a29445c2abb1f25375ee17120784755b5719d1c2b2733625a6d432821aa7ca`.

Run the standalone verifier from this directory, selecting a new output path:

```sh
python3 verify_evidence.py \
  --archive p7-v11-20261030.tar.xz \
  --manifest p7-v11-20261030.manifest.json \
  --archive-sha256 27c9c087f92bd4458c6d7c4780ec16a784e8a7c0acf02b4808328fc3b79e529a \
  --manifest-sha256 42a29445c2abb1f25375ee17120784755b5719d1c2b2733625a6d432821aa7ca \
  --output independent-verification.json
```

It uses the standard library, reads archive members without extraction, and never
executes archived code or uses the network. It checks the external hashes, exact
member set, path/type restrictions, per-file SHA256, source snapshots, capacity
denominators, retained tokenizer records, raw SSE token accounting and the main
refusal. It limits member count, expanded bytes, per-member bytes and retained
semantic-data memory. This verifies retained-data integrity and internal
consistency; it does not independently repeat model inference or cryptographically
attest past execution.

`VERIFICATION.json` and `READBACK_EXECUTION.json` retain the actual successful
full readback. `PACKAGING_RECEIPT.json` records archive creation before that readback;
its pending-readback status is historical, not the final delivery status.
`DELIVERY_INDEX.json` names the final transferable files and their hashes. The
original fresh output tree remains preserved outside this compressed bundle.
