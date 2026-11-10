set -euo pipefail
. /workspace/scratch/7171658d1560/hia-validation-environment.sh
export HIA_P2_SOURCE_SHA=f142ab4ef99cde30128bfced0f3d6299fc373b43
export RUNNER_TEMP=/workspace/scratch/7171658d1560/validation/f142ab4e-source-workflow
mkdir "$RUNNER_TEMP"
set -euo pipefail
test "$(git rev-parse HEAD)" = "$HIA_P2_SOURCE_SHA"
test -z "$(git status --porcelain --untracked-files=all)"
# Recovery needs the complete ancestry of this exact candidate, not
# every unrelated repository branch/tag fetched by checkout depth 0.
if test "$(git rev-parse --is-shallow-repository)" = true; then
  git -c protocol.version=2 fetch --no-tags --unshallow origin "$HIA_P2_SOURCE_SHA"
fi
test "$(git rev-parse --is-shallow-repository)" = false
test "$(git rev-parse HEAD)" = "$HIA_P2_SOURCE_SHA"
python -m pip install 'jsonschema==4.25.1' 'z3-solver==4.15.4.0'

set -euo pipefail
mkdir "$RUNNER_TEMP/hia-p2-source"
git rev-parse HEAD 'HEAD^{tree}' > "$RUNNER_TEMP/hia-p2-source/source.txt"
python -m pip freeze > "$RUNNER_TEMP/hia-p2-source/dependencies.txt"
python -B - <<'PY' 2>&1 | tee "$RUNNER_TEMP/hia-p2-source/recovery.log"
from hashlib import sha256
import gzip, json, subprocess
from pathlib import Path
root = Path("review-evidence/hia-p2-selfhost-recovery-20261109")
manifest = json.loads((root / "manifest.json").read_text())
assert manifest["original_source_tree"] == manifest["recovered_source_tree"]
for key in ("git_bundle", "original_source_snapshot"):
    item = manifest[key]
    data = Path(item["path"]).read_bytes()
    assert len(data) == item["bytes"] and sha256(data).hexdigest() == item["sha256"]
# Historical recovery is checked against its immutable recovered
# commit, not against a later compiler that intentionally changes it.
subprocess.run(["git", "bundle", "verify", manifest["git_bundle"]["path"]], check=True)
subprocess.run(["git", "fetch", "--no-tags", manifest["git_bundle"]["path"], "HEAD"], check=True)
original = manifest["original_commits"][1]["sha"]
recovered = manifest["recovered_source_commit"]
assert subprocess.check_output(["git", "rev-parse", "FETCH_HEAD"], text=True).strip() == original
assert subprocess.check_output(["git", "rev-parse", original + "^{tree}"], text=True).strip() == manifest["original_source_tree"]
assert subprocess.check_output(["git", "rev-parse", recovered + "^{tree}"], text=True).strip() == manifest["recovered_source_tree"]
subprocess.run(["git", "merge-base", "--is-ancestor", recovered, "HEAD"], check=True)
snapshot = json.loads(gzip.decompress(Path(manifest["original_source_snapshot"]["path"]).read_bytes()))
for path, text in snapshot["files"].items():
    assert subprocess.check_output(["git", "show", original + ":" + path]) == text.encode()
for path, item in manifest["recovered_changed_files"].items():
    data = subprocess.check_output(["git", "show", recovered + ":" + path])
    assert len(data) == item["bytes"] and sha256(data).hexdigest() == item["sha256"], path
subprocess.run(["git", "diff", "--exit-code", original, recovered, "--", *manifest["recovered_changed_files"]], check=True)
print(json.dumps({"status": "SOURCE_RECOVERY_VERIFIED", "changed_files": len(manifest["recovered_changed_files"]), "original_tree": manifest["original_source_tree"]}, sort_keys=True))
PY
python -B -m tools.generate_hia_core_json_cli 2>&1 | tee "$RUNNER_TEMP/hia-p2-source/core-json-cli-generator.log"
python -B -m tools.generate_hia_sha256_stream 2>&1 | tee "$RUNNER_TEMP/hia-p2-source/sha256-stream-generator.log"
python -B -m tools.generate_hia_native_observer 2>&1 | tee "$RUNNER_TEMP/hia-p2-source/native-observer-generator.log"
python -B -m tools.generate_hia_source_types 2>&1 | tee "$RUNNER_TEMP/hia-p2-source/source-types-generator.log"
python -B -m tools.generate_hia_source_lexer 2>&1 | tee "$RUNNER_TEMP/hia-p2-source/source-lexer-generator.log"
python -B -m tools.generate_hia_source_names 2>&1 | tee "$RUNNER_TEMP/hia-p2-source/source-names-generator.log"
python -B -m tools.generate_hia_source_clauses 2>&1 | tee "$RUNNER_TEMP/hia-p2-source/source-clauses-generator.log"
python -B -m tools.generate_hia_source_expressions 2>&1 | tee "$RUNNER_TEMP/hia-p2-source/source-expressions-generator.log"
python -B -m tools.generate_hia_sha256 2>&1 | tee "$RUNNER_TEMP/hia-p2-source/sha256-generator.log"
python -B -m tools.generate_hia_json_preflight 2>&1 | tee "$RUNNER_TEMP/hia-p2-source/json-generator.log"
python -B -m tools.generate_hia_json_decode 2>&1 | tee "$RUNNER_TEMP/hia-p2-source/json-decode-generator.log"
python -B -m tools.generate_hia_json_canonical 2>&1 | tee "$RUNNER_TEMP/hia-p2-source/json-canonical-generator.log"
python -B -m tools.generate_hia_core_json_frontend 2>&1 | tee "$RUNNER_TEMP/hia-p2-source/core-json-frontend-generator.log"
python -B tools/generate_hia_selfhost.py 2>&1 | tee "$RUNNER_TEMP/hia-p2-source/generator.log"
python -B tests/test_hia_selfhost_language_coverage.py --generate-inventory 2>&1 | tee "$RUNNER_TEMP/hia-p2-source/inventory.log"
python -B tools/generate_hia_selfhost_contract.py --check 2>&1 | tee "$RUNNER_TEMP/hia-p2-source/contract.log"
git diff --exit-code

set -euo pipefail
python -B - <<'PY' 2>&1 | tee "$RUNNER_TEMP/hia-p2-source/tests.log"
import json, os, unittest
from pathlib import Path
names = (
    "tests.test_hia_core_json_cli.CoreJsonCliSourceTests",
    "tests.test_hia_selfhost_word_io.WordIOSourceTests",
    "tests.test_hia_sha256_stream_native.Sha256StreamSourceTests",
    "tests.test_hia_source_types_native.SourceTypesSourceTests",
    "tests.test_hia_source_lexer_native.SourceLexerSourceTests",
    "tests.test_hia_source_names_native.SourceNamesSourceTests",
    "tests.test_hia_source_clauses_native.SourceClausesSourceTests",
    "tests.test_hia_source_expressions_native.SourceExpressionsSourceTests",
    "tests.test_hia_source_frontend_native.SourceFrontendCustodyTests",
    "tests.test_hia_sha256_native.Sha256HiaSourceTests",
    "tests.test_hia_json_preflight",
    "tests.test_hia_json_preflight_native.JsonPreflightHiaSourceTests",
    "tests.test_hia_json_decode_native.JsonDecodeHiaSourceTests",
    "tests.test_hia_json_canonical_native.JsonCanonicalHiaSourceTests",
    "tests.test_hia_selfhost_exports.ExportSourceTests",
    "tests.test_hia_core_json_frontend_native.CoreJsonFrontendHiaSourceTests",
    "tests.test_hia_selfhost.SelfhostSourceTests",
    "tests.test_hia_selfhost_contract.SelfhostContractTests",
    "tests.test_hia_selfhost_cli",
    "tests.test_hia_selfhost_names",
    "tests.test_hia_selfhost_returned_loans",
    "tests.test_hia_selfhost_multi_results.SelfhostMultiResultSourceTests",
    "tests.test_hia_selfhost_keywords.SelfhostKeywordTests",
    "tests.test_hia_selfhost_signed.SelfhostSignedTests",
    "tests.test_hia_selfhost_traps.SelfhostExplicitTrapTests",
    "tests.test_hia_selfhost_language_coverage.SelfhostLanguageSourceTests",
    "tests.test_hia_agent_native_tools.ArtifactContractTests.test_discovery_is_readable_and_source_bound",
)
suite = unittest.defaultTestLoader.loadTestsFromNames(names)
result = unittest.TextTestRunner(verbosity=2).run(suite)
passed = (result.wasSuccessful() and result.testsRun > 0 and not result.skipped
          and not result.expectedFailures and not result.unexpectedSuccesses)
report = {
    "schema": "hepta.hia.p2.source-tests.v1",
    "source_sha": os.environ["HIA_P2_SOURCE_SHA"],
    "status": "PASS" if passed else "FAIL", "tests_run": result.testsRun,
    "failures": [{"test": t.id(), "detail": d} for t,d in result.failures],
    "errors": [{"test": t.id(), "detail": d} for t,d in result.errors],
    "skipped": [{"test": t.id(), "reason": d} for t,d in result.skipped],
    "old_temporary_evidence_reused": False,
}
(Path(os.environ["RUNNER_TEMP"]) / "hia-p2-source/tests.json").write_text(json.dumps(report, indent=2) + "\n")
print(json.dumps({k:report[k] for k in ("source_sha", "status", "tests_run")}, sort_keys=True))
raise SystemExit(0 if passed else 1)
PY
test -z "$(git status --porcelain --untracked-files=all)"
