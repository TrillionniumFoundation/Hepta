"""Read only the completed joint R1 artifact; never execute project code."""
from pathlib import Path, PurePosixPath
from hashlib import sha256
import base64
import json
import os
import urllib.error
import urllib.parse
import urllib.request
import zipfile

ARTIFACT_ID = 13963834750
EXPECTED_BYTES = 23776916
EXPECTED_SHA256 = "69fe12afec7767883f3a75e05382e9514b6cb6950a7439f113c970a61d6727f6"
STDERR_SUFFIX = "014-original-core-only-before-generation.stderr"
STDERR_BYTES = 569
STDERR_SHA256 = "390cd5d4b78aa0518aaaf1fa2fa78fcf3ac941f657b2d672137fd4235fed3121"
REPORT_BYTES = 175668
REPORT_SHA256 = "c3dc79df13c48230c93c18e8dde94aff2b7112e895dc74a7536c020fa51c4977"

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None

def require(value, message):
    if not value:
        raise ValueError(message)

def identity(raw):
    return {"bytes": len(raw), "sha256": sha256(raw).hexdigest()}

def main():
    output = Path(os.environ["GITHUB_WORKSPACE"]) / "evidence"
    output.mkdir(exist_ok=False)
    result = {"scope": "READ_ONLY_ORIGINAL_ARTIFACT", "project_tests_executed": False,
              "artifact_id": ARTIFACT_ID, "status": "STARTED"}
    try:
        api = "https://api.github.com/repos/TrillionniumFoundation/Hepta/actions/artifacts/" + str(ARTIFACT_ID) + "/zip"
        request = urllib.request.Request(api, headers={
            "Authorization": "Bearer " + os.environ["GH_TOKEN"],
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"})
        try:
            response = urllib.request.build_opener(NoRedirect).open(request, timeout=60)
        except urllib.error.HTTPError as error:
            require(error.code in (301, 302, 303, 307, 308), "artifact API did not issue a download redirect")
            location = error.headers["Location"]
            require(urllib.parse.urlsplit(location).scheme == "https", "artifact redirect is not HTTPS")
            # The GitHub bearer token never accompanies the storage request.
            response = urllib.request.urlopen(urllib.request.Request(location), timeout=60)
        target = output / "original-joint-r1-artifact.zip"
        with response, target.open("xb") as stream:
            while block := response.read(1 << 20):
                stream.write(block)
        raw = target.read_bytes()
        require(identity(raw) == {"bytes": EXPECTED_BYTES, "sha256": EXPECTED_SHA256},
                "original complete artifact bytes differ from authoritative metadata")
        result["artifact"] = identity(raw)
        with zipfile.ZipFile(target) as archive:
            names = archive.namelist()
            require(len(names) == len(set(names)), "duplicate archive members")
            for name in names:
                path = PurePosixPath(name)
                require(not path.is_absolute() and ".." not in path.parts, "unsafe archive member")
            require(archive.testzip() is None, "original archive CRC differs")
            result["member_count"] = len(names)
            result["members"] = [{"path": row.filename, "bytes": row.file_size,
                                  "compressed_bytes": row.compress_size, "crc32": row.CRC}
                                 for row in archive.infolist()]
            selected = [name for name in names if name.endswith(STDERR_SUFFIX)]
            require(len(selected) == 1, "exact original stderr is not unique")
            failure = archive.read(selected[0])
            require(identity(failure) == {"bytes": STDERR_BYTES, "sha256": STDERR_SHA256},
                    "original failure text differs")
            result["original_failure"] = {"path": selected[0], **identity(failure),
                                          "text": failure.decode("utf-8", "strict")}
            (output / "original-core-only.stderr").write_bytes(failure)
            reports = [name for name in names if name.endswith("/REPORT.json")]
            matching = []
            for name in reports:
                body = archive.read(name)
                if identity(body) == {"bytes": REPORT_BYTES, "sha256": REPORT_SHA256}:
                    matching.append(name)
                    (output / "original-REPORT.json").write_bytes(body)
            require(len(matching) == 1, "source REPORT differs from fully reconstructed original log capsule")
            result["original_report"] = {"path": matching[0], "bytes": REPORT_BYTES,
                                         "sha256": REPORT_SHA256}
        result["status"] = "PASS"
    finally:
        (output / "READBACK.json").write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
        print(json.dumps(result, sort_keys=True))
if __name__ == "__main__":
    main()
