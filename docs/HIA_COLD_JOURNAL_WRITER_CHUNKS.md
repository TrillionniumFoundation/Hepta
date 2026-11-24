# Native journal writer chunk extent

The writer emits at most 16,384 raw bytes in one physical chunk. The reader still accepts the existing 65,504-byte raw chunk extent. The AZ01/AZ02/AZ03 formats, four MiB workspace, complete logical records, node counts and all custody checks remain unchanged. This is a physical representation choice, not a change to any qualification program or oracle.

Every chunk still runs the native encoder, native decoder and full raw byte comparison. A proposed backreference still checks the private encoded SHA, the actual prior encoded bytes and a fresh decode of the prior original chunk. No result, logical node or actual child execution is reused. The archive still captures a sealed immutable journal and retains all original hashes and metadata checks.

## Actual comparison

Both choices use the same qualified SHA composite, the same plans and the same independent tool roots. Each variant freshly constructs the base chain, then executes the original chain family with that freshly generated compiler. Historical independent reference inputs are used only for this component performance comparison.

| Phase | Chunk bytes | Driver seconds | Archive seconds | Journal bytes | Logical bytes |
| --- | ---: | ---: | ---: | ---: | ---: |
| Base | 65,504 | 12.032396 | 3.046795 | 16,168,817 | 454,797,516 |
| Base | 16,384 | 12.008408 | 2.963312 | 14,729,518 | 454,797,516 |
| Chain | 65,504 | 9.985718 | 4.187452 | 18,846,547 | 851,530,713 |
| Chain | 16,384 | 10.042676 | 3.804295 | 14,144,120 | 851,530,713 |

All published values match the previous actual run. Every archived file matches the new phase directory byte for byte, including the complete actual journal. The original 18 driver guard cases pass for the new writer. The SHA integration separately passes the original dual 19 archive gates, 47 exporter gates, 41-phase orchestration fixture, 22 CLI refusals and three real archive-overlap controls.

The measured total improvement for these two phases is small, about 0.43 seconds. It does not establish the full 60-phase cold replay or the 180-second wall gate. The final whole replay remains required. Exact products, source hashes and all receipts are recorded in the adjacent JSON.
