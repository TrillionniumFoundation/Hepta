# Dedicated installation document: narrow reconciliation

Main `4fd6b62b442e4198f43bf3595fa9e35b0f438102` deliberately clears the homepage README. This candidate preserves that exact empty blob and restores the public installation discovery contract through root `INSTALL.md`.

Only three paths change relative to that main state: `INSTALL.md`, the public-release workflow and the current discovery guidance in `docs/HIA_RELEASE_ENTRY.md`. The new installation document is byte-identical to the original accepted 81fe README: 5,548 bytes, Git blob `ecab93b61ec96873a62eb0178963ec25dd43679b`, SHA256 `81dcccc0cdd0cdbebc86eb47165a519cbee7f6886d05774302d941afb667d61f`.

The workflow changes only its discovery step. It still requires nonempty instructions, the selected entry command and original lock link, and the same eight locked task inputs with identical hash gates. The other six configured steps are byte-identical. Both original matrix rows, default/no-lock invocation, explicit v16 lock/hash, 35-minute limit, permissions, exact-source fetch, native examples and full installation-manifest equality remain.

The new `hepta.hia.public-source-inputs.v2` record explicitly binds `entry_document.path`, SHA256 and byte count, while separately recording the true empty README identity. Earlier v1 records remain unchanged. All helpers, the shared preflight and both original release locks retain their exact bytes.

The frozen preparer manifest, complete diff and static validation are included. YAML parsing, four Bash syntax checks, three embedded Python AST checks, exact original-document bytes and patch applicability passed without executing the workflow or project/native/solver code. This static result does not replace the reconciled head or actual-main CI.

The [preceding successful main](../hia-main3586-ci-20261109-e5ee/README.md), [empty-README failure](../hia-main4fd-readme-failure-20261109-e5ee/README.md) and [concurrent-state records](../hia-public-entry-concurrent-main-20261109-e5ee/README.md) retain their separate identities and outcomes.

