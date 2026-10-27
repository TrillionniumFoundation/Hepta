# Native qualification prerequisites

The complete qualification at source `a04ae789b2348504089e2c3484178998a6f332ba`
failed on GitHub Actions even though the separate four-host ABI workflow
succeeded. The two workflows qualify different properties. The full run is
[40219053582](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40219053582);
the host run is
[40219053468](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40219053468).
A new workflow configuration is not evidence that a subsequent run passed.

## Selected Rust executable

`rustc` can be a rustup proxy. Resolving its symlink and invoking the result as
`rustup -vV` queries the manager instead of the compiler. Hardlink proxies also
need to identify the real compiler for a meaningful executable digest. See the
[upstream proxy documentation](https://rust-lang.github.io/rustup/concepts/proxies.html).

`find_rustc` now resolves recognized symlink/hardlink proxies with
`rustup which rustc` in the caller's directory. Automatic installation is
disabled for this query. A nonzero exit, timeout, multiple paths, relative path,
missing executable or recursive proxy is rejected. The returned executable
still passes the existing complete `rustc -vV` identity gate for **1.90.0**;
selection does not relax that gate.

An explicit argument takes precedence over `RUSTC`, and a missing explicit
selection never falls back. Without either, the repository's checksum-verified
bootstrap location precedes PATH. The full workflow exports its installed
compiler explicitly and records its actual executable identity before any gates.

`tests/test_toolchain_selection.py` contains an explicit argv[0]-dispatch fixture
and a real pinned-compiler build/run. The fixture is not claimed to be an
execution of upstream rustup. Both symlink and hardlink dispatch are tested,
alongside malformed responses, timeout, wrong version and explicit-selection
failure. The native binary actually executes.

## Namespace startup

Ubuntu's AppArmor user-namespace restriction can deny Bubblewrap's loopback
setup even when the package is installed. The workflow loads the **unmodified
distribution profile** from `apparmor-profiles`:

```
/usr/share/apparmor/extra-profiles/bwrap-userns-restrict
```

This is the documented distribution-profile setup in the
[official GitHub Action instructions](https://github.com/openai/codex-security/blob/main/github-action/README.md#runtime).
The profile hash and startup probe are retained in the workflow artifacts. The
workflow asserts that the global `apparmor_restrict_unprivileged_userns` setting
has not changed. It does not disable AppArmor or remove namespace, network,
capability, filesystem or process-boundary checks. A failed startup still fails
the job; it is not replaced by privileged or unconfined execution.

## Scope of the repair

These fixes address toolchain selection and runner prerequisites. They do not
establish compiler soundness, stable performance, a successful whole-candidate
qualification, or the safety of arbitrary foreign code. Each subsequent source
commit must retain its own complete test/gate outcome, including failures.
