# Independent ABI and performance review

This note concerns frozen objects and the interpretation of the next target
experiment. It changes no backend, packet generator, adapter, or benchmark.

## Baseline observed costs

The complete 36-sample-per-arm aggregation remains in
`performance-all-samples.json`, derived from both retained corrected-run2 and
corrected-run3 logs. The old HIA object is
`67e17b4113f8aeca171efb9b1a45909373daddeaae448060c20ec080e0725983`;
the adapter object is
`64c78f6e9e8d04d9887a040460e157aae53a75aac738c996f650e80555e3ea6f`.

| Codec | C median ns/call | Raw HIA median | HIA adapter median | Adapter / C |
| --- | ---: | ---: | ---: | ---: |
| Long write | 4.3811 | 15.0182 | 22.6069 | 5.1601 |
| Long read | 2.9171 | 10.9509 | 18.0197 | 6.1773 |
| Epoch write | 2.8855 | 10.6197 | 17.5664 | 6.0879 |
| Epoch read | 2.1410 | 10.1393 | 14.8110 | 6.9178 |

These are repeated batch-mean times for hot finite inputs on a shared host,
not individual request latency quantiles or a tunnel profile. No samples were
removed. The run2 later LeakSanitizer environment failure remains archived.

The application adapter checks object pointer extents, alignment, descriptor
invariants and overlap before accessing admitted application state. It packs a
32-byte canonical state, calls the foreign ABI, checks ABI/Core result domains,
and publishes ordered application state. The foreign wrapper then checks its
own byte-range/alias contract before entering the Core; the Core also checks
its packet metadata and accesses. These operations are real integration costs.
The raw HIA call already includes foreign admission, so calling it "bare kernel"
without that qualification would be misleading.

Subtracting independent median timings does not identify an exact additive
marshalling/admission cost: branch prediction, instruction layout, optimizer
visibility and the measurement loops can interact. The explicit C byte-ABI
control is useful, but delegates to a separately compiled upstream C function.
It is not evidence that both implementations received identical inlining.
The packet owner has specifically confirmed that the old HIA binary retained an
internal `__hia_fn` call; the new candidate deliberately changes that visibility
through selected foreign-function inlining. Report that code-generation change
alongside matched flags and every version's object hashes.

The proposed six-arm comparison keeps original C, C byte control, old/new raw HIA
and old/new adapters in one invocation with a predeclared Williams-balanced
order. Symbol-renamed object copies must preserve their machine-code sections.
Earlier successful and failed runs must remain, and the new candidate must still
pass complete codec state, boundary, guard-page and integration checks before its
measurements can become the current result. This note does not claim that the
new candidate has achieved a speedup; use its actual retained measurements.

## Tunnel interpretation

Actual measured application CPU must include the cost of OpenVPN's cryptography,
socket/TUN I/O and scheduling; DCO also consumes kernel/softirq CPU. Process-only
CPU can make offload look free. Equal cipher/config text does not by itself give
equal packet format: Linux OpenVPN 2.7.8 DCO does not advertise epoch support.
A fixed official DCO peer gives the three tested endpoint arms a common non-epoch
profile. Preserve both peer identities and the negotiated wire profile.

Diagnostic wrappers, per-packet probes, packet capture and `verb 6` counter logs
are deliberately separate from `verb 3` timing runs with the untraced binary.
A direct read-only kernel peer-counter query before and after timing is acceptable
as explicit setup/teardown evidence; do not include the query or profile sampler
in the elapsed data-transfer interval without applying the same method to every
arm. Shared-host, local-veth, five-second, fixed-rate observations cannot establish
WAN, hardware-NIC or production deployment value. The actual frozen target plan
and all failed workloads belong in the result, not only the samples with a final
iperf `sum_received` object.
