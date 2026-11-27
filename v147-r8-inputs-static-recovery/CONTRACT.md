# R8 input data recovery after environment reset

This is static recovery of data, not a product, compiler, VM, binder, current-cold, or CI execution. The lost paths and their old stat identities are not recreated. Source3180 and the recovered runtime are outside the writable scope.

The fixed mapping contains 948 ordered references and 944 unique original paths. Four references repeat existing paths. The output root is /tmp/hia-r8-inputs-recovery-20261114-dda7; each unique path has a separate regular inode under inputs/. Total unique bytes are 710,690,611; reference bytes including duplicates are 717,016,014. The original mapping and every original row are retained without rewriting the former locator-gap statement; the new compact locator report supplies the resolved index independently.

## Payload coverage

Six actual payload families cover all requested inputs: compact R1–R5 (501 references / 497 paths), file-render-v3 kernel (434), R8 R2 author (5), R8 size author (5), actual size/pack (2), and ordinary B3 (1). All 70 compact parts and all 19 kernel parts were fully read and checked. Complete gzip CRC and all 2,396 compact CAS objects (1,658,896,740 bytes) and 1,353 kernel CAS objects (102,233,729 bytes) were verified. Only required inputs were materialized; unselected logical originals were not expanded.

The three smaller capsules were completely decoded and checked (147, 70 and 84 files respectively). The ordinary B3 was reconstructed from its original three complete ASCII-base64 blobs and fully verified. Restored machine images and ELF files were never executed.

## Permissions and failed first recovery

The first data reader stopped on its explicit mode guard after writing two complete inputs. Both files and all R1 failure/raw records remain. It discovered an additional real boundary: the author-capsule copies of OWNER.json are mode 0644 while the fixed required input is 0600. The independent R2 reader admits only that exact 1,397-byte identity, explicitly applies 0644 to 0600, and preserves the existing exact compiler 0400 to 0644 decision. No bytes change. R2 fully rechecks the two complete R1 outputs and their new stats before reusing them; it does not overwrite or recreate them.

Compact metadata carries exact mode_bits. Kernel metadata carries Git mode classes; new permissions match the frozen required input mapping. Base64 transport does not itself carry filesystem permissions. All restored output modes and new seven-field stats were checked, but none is asserted to be the lost original inode/stat identity.

## Historical limits

R5's six logical VM controls remain five PASS and one original 10M-fuel FAIL. Its existing scope and budgets remain. Two original gaps stay explicit: the first R1 third-case failure buffers were never saved after an observer error, and first generated R1 HIA bytes were overwritten before machine execution. Later captures and this data restoration do not fill either historical gap.

## Custody and verification

The capsule contains the complete recovery metadata, scripts, exact maps, original manifests, part ledger, R1 failure, R2 raw output/outer result, and complete final static manifest. It omits duplicate payloads already recoverable from their fixed original Git publications. The new read-only verify_restored.py is provided for independent review; it has not been executed by this agent. The successful R2 data reader already performed a full readback of all 944 unique inputs and checked the final pathset and stats. Root's independent verification is a separate result.
