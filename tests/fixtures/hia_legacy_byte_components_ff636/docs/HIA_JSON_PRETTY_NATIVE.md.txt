# HIA JSON byte layout

The HIA program in `examples/hia_bootstrap/json_pretty.hiaasm` measures and emits two-space JSON layout while preserving the lexical bytes of an already admitted compact UTF-8 JSON input. It appends no final newline. It does not decode JSON values or serialize an object graph.

## Entry and buffers

The public `f0` entry takes read-only input, mutable output and a private mutable workspace and returns a zero-extended u32 status. The workspace has a 32-byte header followed by 129 one-byte stack entries, for 161 bytes total in the supported bridge.

| Header offset | Little-endian u64 value |
| --- | --- |
| 0 | Mode: 0 measures; 1 emits. |
| 8 | Successful output byte count. Valid only after status zero. |
| 16 | Error offset; zero after success. |
| 24 | Diagnostic status; must match a nonzero return and be zero after success. |

The component preserves its 8 MiB input profile and 129-entry stack. A successful measurement determines the output extent. There is no additional 8 MiB output limit: layout expansion may produce more output bytes than input bytes. Ordinary address-space allocation limits still apply.

Every nonzero status invalidates the output and length. Callers must check the actual return and diagnostics before using offset 8 or allocating output from it. The source is trusted native code under the existing HIA image loader and process contracts.

## Byte transport and package source

`hepta.hia_json_pretty_native.NativeJsonPretty.format_admitted_compact` accepts exact `bytes`. Each call holds the immutable input and its own workspace through measurement and emission, then returns exactly the successfully emitted bytes. Refused input raises `HiaJsonLayoutRefused` with the actual status and error offset. The bridge does not traverse objects, choose Unicode escaping, sort keys, print text or publish files.

`installed_json_pretty(manifest_path)` uses the shared source-bound HIA image loader with schema `hepta.hia.json-pretty-native.v1`. The Agent source-resource tuple and sdist manifest explicitly include the HIA source. The package build hook copies it to `hepta/_data/examples/hia_bootstrap/json_pretty.hiaasm`. Source selection resolves to the package-owned resource after installation.

The explicit builder is:

```sh
python -B -m tools.build_hia_json_pretty --compiler <compiler-image> --cold-report <current-cold-report.json> --output <new-directory>
```

It uses the existing matching-source cold admission before creating its output directory. A report from an earlier source closure is insufficient. A build manifest pins the actual source, image and compiler digests; it does not activate a service or prove complete application compatibility.

## Scope and qualification

The component has a byte-layout contract. The original CLI output and publication functions also own object conversion, callbacks, Unicode text, nonfinite values and filesystem effect order. Those responsibilities require their own complete HIA replacements and original caller qualification.

Development observations, source round trips, installed-resource checks, matching-source cold qualification and full retained discovery are recorded separately. Adding this source resource does not make those remaining gates pass. Existing FAIL, HOLD and UNKNOWN results retain their original meaning.
