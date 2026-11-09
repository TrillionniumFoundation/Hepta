from __future__ import annotations
import hashlib
import json
from pathlib import Path
import sys
import types

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
LOCK_SHA256 = "9000d6eaa089f6bed92ea07a6561d91381a6f913263f0b1016d4f99e8789c1d3"
PRIOR_LOCK_SHA256 = "1c4b747721bfc215549512287d62febbadfaf7bce3cd2b6baafeed3d67a10c18"
CHECKER_SHA256 = "ff9669c365b4056de643129376a3e4868396745f542adf90ef1fb4c114014542"
ARCHIVE_SHA256 = "e05ffacd052fd71de606457afd3c19d89cb514c346a7b8431085274fb54e353e"

def require(condition, message):
    if not condition:
        raise ValueError(message)

def sha256(raw):
    return hashlib.sha256(raw).hexdigest()

def main():
    checker_path = ROOT / "tools/check_hia_online_readback.py"
    checker_raw = checker_path.read_bytes()
    require(sha256(checker_raw) == CHECKER_SHA256, "existing checker source differs")
    # Reuse the unchanged checker source directly, without importing a .pyc.
    module = types.ModuleType("retained_original_online_checker")
    module.__file__ = str(checker_path)
    exec(compile(checker_raw, str(checker_path), "exec"), module.__dict__)
    retained_lock = (HERE / "release-lock.json").read_bytes()
    public_lock = (ROOT / "releases/hia-current.json").read_bytes()
    require(public_lock == retained_lock, "current public lock is not the original retained CI member")
    require(sha256(retained_lock) == LOCK_SHA256, "retained source CI lock differs")
    lock = module.decode(retained_lock)
    for helper in ("tools/hia_release.py", "tools/hia_candidate_preflight.py"):
        require(sha256((ROOT / helper).read_bytes()) == lock["files"]["hepta"][helper],
                "public entry helper differs from selected source: " + helper)
    provenance = module.decode((HERE / "source-ci-provenance.json").read_bytes())
    require(provenance["artifact_id"] == 13626118637 and
            provenance["source_run_id"] == 42503095942 and
            provenance["source_commit"] == "2598f4309791d3a023cd5df585ad26810b20c744" and
            provenance["artifact_bytes"] == 14730386 and
            provenance["artifact_sha256"] == ARCHIVE_SHA256 and
            provenance["selected"]["release-lock.json"]["sha256"] == LOCK_SHA256 and
            provenance["selected"]["release-lock.json"]["bytes"] == len(retained_lock),
            "original source CI provenance binding differs")
    describe = (HERE / "formal-hia-describe-result.json").read_bytes()
    read = (HERE / "formal-hia-read-result.json").read_bytes()
    current = module.check_readback(retained_lock, LOCK_SHA256, describe, read)
    require(current == module.decode((HERE / "readback-verification.json").read_bytes()),
            "new readback report differs from the retained original-checker result")
    require(current["passed"] is True, "selected source CI lock does not match")
    prior_path = ROOT / "review-evidence/hia-online-readback-20261108-5e6c/evidence/public-release-lock-b408085.json"
    prior = module.check_readback(prior_path.read_bytes(), PRIOR_LOCK_SHA256, describe, read)
    require(prior == module.decode((HERE / "prior-public-lock-mismatch.json").read_bytes()),
            "retained original public-lock mismatch changed")
    require(prior["status"] == "HOLD_INSTALLATION_MISMATCH" and
            prior["matches"] == {"backend_sha256": True, "catalog_sha256": True, "worker_sha256": False},
            "old-lock negative control no longer isolates the worker identity")
    content = module.completed_envelope(read, "read")["result"]["content"].encode("utf-8")
    require((HERE / "formal-manifest.json").read_bytes() == content,
            "separate exact manifest bytes differ")
    report = {
        "schema": "hepta.hia.published-lock-retained-readback-replay.v1",
        "status": "PASS_SOURCE_CI_LOCK_AND_RETAINED_READBACK",
        "passed": True,
        "checker_sha256": CHECKER_SHA256,
        "current_public_lock_equals_original_ci_member": True,
        "public_entry_helpers_equal_selected_source": True,
        "source_ci_archive_sha256": ARCHIVE_SHA256,
        "source_ci_provenance_refetched_by_this_offline_replay": False,
        "capture_precedes_metadata_publication": True,
        "fresh_endpoint_read_performed_by_this_replay": False,
        "current_lock_readback": current,
        "prior_public_lock_control": prior,
    }
    print(json.dumps(report, sort_keys=True, indent=2))
    return 0

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(json.dumps({"passed": False, "status": "HOLD_REPLAY_BINDING", "reason": str(exc)}, sort_keys=True))
        raise SystemExit(1)
