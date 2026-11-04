# Preserve validated inputs when selecting CLI outputs

The ordinary `emit`, `header` and `build` commands refuse a destination that
would replace a known loaded-graph or package-snapshot input, or the verified
owner lock. This is a narrow
extension of the existing loaded-source output guard, not a general ban on
overwriting output files.

## Reproduced loss of package inputs

For a regular application with a valid manifest, source and freshly generated
lock, this command previously succeeded and replaced the manifest with C:

```sh
python -m hepta emit app --locked --backend c --crate-type bin -o app/hepta.toml
```

The same happened when the output named `Hepta.lock` or an unimported `.hepta`
file already read and hashed into the package snapshot. Selecting the loaded
entry source instead was correctly rejected. All these observations used
ordinary temporary files and real GCC validation, without concurrent changes
or special filesystem topology.

## Input boundary

The protected set contains:

- The loaded graph's existing source, imported metadata and retained header
  paths.
- Every file in the already captured package snapshot, resolved relative to
  the owning package root. This includes manifests, unimported package sources,
  present import sidecars, and dependency inputs reached through `../` paths.
- The owner's `Hepta.lock` when `--locked` caused it to be read and verified.

The output check uses the captured inventory rather than re-enumerating the
package. All three output commands share it. Refusal remains a structured
`E_DRIVER` result with exit status 2, before the destination is written or the
final artifact is built. The normal native validation pass can already have
invoked the selected compiler before this output check.

An unlocked owner's lock, dependency locks that this command does not read,
and unimported standalone sibling files are not newly protected. Ordinary
new or existing non-input output files remain supported. No whole-directory
or filename-suffix prohibition is added. This preserves explicit output
overwrite compatibility outside the validated input inventory.

## Validation and limits

Controls exercise real CLI refusal and byte preservation across package
entry forms and output commands, dependency inventories, lock modes, and
ordinary permitted outputs. Positive finite scalar builds execute and check
their return values. Rust controls require the actual pinned compiler; its
absence is an explicit local skip, never a claimed native pass.

The strict gate in `tools/test_cli_input_protection.py` binds a checked-in
ordered inventory. It requires all planned, executed and passed method IDs
to agree, actual GCC and Rust, and zero skips, expected failures or unexpected
successes. The dual-host workflow checks the exact source commit and retains
original identities and logs. Component or earlier-commit results cannot
qualify a new source.

This does not add atomic filesystem observation, race protection, general
transactional output publication, or input guards to low-level backend APIs
and unrelated migration/import commands. Arbitrary foreign link inputs and
the full native compiler dependency closure are not represented by this
inventory. It does not establish whole-language soundness or production
readiness.
