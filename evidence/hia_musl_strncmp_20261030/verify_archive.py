"""Offline byte/source/receipt checks; does not extract or execute archived code."""
import base64
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import tarfile


def require(value, message):
    if not value:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def expected(arguments, refusal):
    count, left, right = arguments
    if count > 8:
        result, attempts, allocations = -259, 0, 0
    elif count == 0:
        result, attempts, allocations = 0, 0, 0
    elif refusal:
        result, attempts, allocations = -256 - refusal, refusal, refusal - 1
    else:
        result, attempts, allocations = 0, 2, 2
        for offset in range(count):
            a, b = (left >> (8 * offset)) & 255, (right >> (8 * offset)) & 255
            if a != b or a == 0:
                result = a - b
                break
    return dict(result=result, attempts=attempts, allocations=allocations, frees=allocations, live=0)


def verify(directory):
    directory = Path(directory)
    manifest = json.loads((directory / "MANIFEST.json").read_text())
    raw = base64.b64decode(b"".join((directory / "executions.tar.xz.base64").read_bytes().splitlines()), validate=True)
    require(len(raw) == manifest["archive_bytes"] and digest(raw) == manifest["archive_sha256"], "archive differs")
    inventory = {row["path"]: row for row in manifest["members"]}
    require(len(inventory) == len(manifest["members"]), "duplicate inventory path")
    members = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:xz") as archive:
        for member in archive:
            path = PurePosixPath(member.name)
            require(member.isfile() and not path.is_absolute() and ".." not in path.parts
                    and member.name in inventory and member.name not in members, "unsafe or unexpected member")
            data = archive.extractfile(member).read()
            wanted = inventory[member.name]
            require(len(data) == member.size == wanted["bytes"] and digest(data) == wanted["sha256"], "member differs")
            members[member.name] = data
    require(set(members) == set(inventory), "member missing")
    results, inputs = {}, []
    for prefix, version in (("baseline", "1.2.5"), ("maintenance/successor", "1.2.6")):
        report = json.loads(members[prefix + "/qualification.json"])
        require(report["ok"] and report["upstream"]["version"] == version, "qualification failed")
        original_root = PurePosixPath(report["commands"][0]["cwd"])
        for row in report["retained_files"]:
            path = prefix + "/" + str(PurePosixPath(row["path"]).relative_to(original_root))
            require(len(members[path]) == row["bytes"] and digest(members[path]) == row["sha256"], "retained receipt differs")
        snapshot = "source/" + report["source_commit"] + "/"
        for path, sha in report["source_bindings"].items():
            require(digest(members[snapshot + path]) == sha, "implementation snapshot differs")
        processes = [json.loads(line) for line in members[prefix + "/processes.jsonl"].splitlines()]
        require([{k: v for k, v in row.items() if k not in ("stdout", "stderr")} for row in processes]
                == report["commands"], "process ledger differs")
        cases = json.loads(members[prefix + "/input-cases.json"])
        require(len(cases) == 386, "input matrix size differs")
        inputs.append(cases)
        observations = [json.loads(line) for line in members[prefix + "/observations.jsonl"].splitlines()]
        seen, commands = set(), set()
        for row in observations:
            key = (row["case"], row["refuse_at"])
            require(key not in seen and 0 <= key[0] < 386 and key[1] in (0, 1, 2), "matrix cell duplicated")
            seen.add(key)
            require({k: row[k] for k in ("case", "category", "arguments", "expected")} == cases[key[0]], "input differs")
            wanted = expected(row["arguments"], row["refuse_at"])
            require(row["resource_expected"] == wanted and set(row["native"]) == {"original_c_native", "hia_llvm_native"}, "oracle or route differs")
            for route, native in row["native"].items():
                index = native["command_index"]
                require(index not in commands, "native process reused")
                commands.add(index)
                process = processes[index]
                require(process["returncode"] == 0 and process["stage"] == "native_observation"
                        and PurePosixPath(process["argv"][0]).name == route
                        and process["argv"][1:] == list(map(str, [*row["arguments"], row["refuse_at"]]))
                        and json.loads(process["stdout"]) == native["observed"] == wanted, "native result differs")
            vm = row["vm"]["observed"]
            stats = vm["resources"]
            require(vm["result"] == wanted["result"] and stats["live_owners"] == 0
                    and stats["loans_started"] == stats["loans_ended"]
                    and [stats[k] for k in ("allocation_attempts", "allocations", "frees")]
                    == [wanted[k] for k in ("attempts", "allocations", "frees")], "VM result differs")
        require(len(seen) == len(observations) == report["completed_cases"] == 1158
                and len(commands) == report["native_observations"] == 2316 and report["vm_observations"] == 1158,
                "matrix incomplete")
        require(digest(members[prefix + "/capture/program.hia.json"]) == report["migration"]["program_sha256"], "Core differs")
        archive_path = "archives/musl-1.2.5.tar.gz" if version == "1.2.5" else "acquisition/musl-1.2.6.tar.gz"
        release = members[archive_path]
        require(digest(release) == report["upstream"]["release_archive"]["sha256"], "release archive differs")
        with tarfile.open(fileobj=io.BytesIO(release), mode="r:gz") as archive:
            for row in report["upstream"]["files"]:
                data = archive.extractfile("musl-" + version + "/" + row["upstream_path"]).read()
                require(data == members[prefix + "/project/" + row["local_path"]], "upstream source was changed")
        results[version] = dict(cases=len(seen), native_observations=len(commands), vm_observations=len(observations),
                                source_blobs_rehashed=len(report["source_bindings"]), source_commit=report["source_commit"])
    require(inputs[0] == inputs[1], "maintenance matrix changed")
    require(members["baseline/capture/program.hia.json"] == members["maintenance/successor/capture/program.hia.json"], "maintenance Core changed")
    update = json.loads(members["maintenance/update.json"])
    require(update["ok"] and update["status"] == "completed_unchanged_body_release_maintenance", "maintenance failed")
    require((directory / "maintenance-report.json").read_bytes() == members["maintenance/update.json"], "visible maintenance report differs")
    return {"ok": True, "members": len(members), "archive_bytes": len(raw), "qualifications": results,
            "artifacts_executed": False, "independent_agent_review": False,
            "claim": "retained bytes and finite receipt consistency, not rerun or all-input proof"}


if __name__ == "__main__":
    print(json.dumps(verify(Path(__file__).resolve().parent), indent=2, sort_keys=True))
