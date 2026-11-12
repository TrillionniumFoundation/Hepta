"""Read only the completed joint R2 artifact; never execute project code."""
from pathlib import Path, PurePosixPath
from hashlib import sha256
import base64
import json
import io
import os
import urllib.error
import urllib.parse
import urllib.request
import zipfile

ARTIFACT_ID = 13967101980
EXPECTED_BYTES = 92730326
EXPECTED_SHA256 = "d5016ec209e9580188942ad975dc0015efa2d9c2fa4e2d3d451e5f4ec9969f07"
STDERR_SUFFIX = "125-complete-original-and-additional-source-controls.stderr"
STDERR_BYTES = 162184
STDERR_SHA256 = "0a611175688f845fc44155853924fb9b1d4bf591d4aa1e1ada3364b566c06edb"
REPORT_BYTES = 2254513
REPORT_SHA256 = "f6993d0d72b9092f08b222bc9182499fb746405632b5db1e67c828a56ef4f71b"

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
        target = output / "original-joint-r2-artifact.zip"
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
            (output / "original-source-controls.stderr").write_bytes(failure)
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
            packets = [name for name in names if name.endswith("/SOURCE-PACKET.json")]
            require(len(packets) == 1, "actual original source packet is not unique")
            packet = archive.read(packets[0])
            require(identity(packet) == {
                "bytes": 9521085,
                "sha256": "0fdf556bc32a78f255fae388b6091d3e781c1ed3c384b0a04ec77db00e85f46d"},
                "original source packet differs from original log capsule")
            result["original_source_packet"] = {"path": packets[0], **identity(packet)}
            (output / "original-SOURCE-PACKET.json").write_bytes(packet)
            result["nested_evidence"] = []
            for name in names:
                if name.endswith("/EVIDENCE.zip"):
                    inner_bytes = archive.read(name)
                    with zipfile.ZipFile(io.BytesIO(inner_bytes)) as inner:
                        inner_names = inner.namelist()
                        require(len(inner_names) == len(set(inner_names)),
                                "duplicate nested original evidence")
                        require(inner.testzip() is None, "nested original evidence CRC differs")
                        result["nested_evidence"].append({
                            "path": name, **identity(inner_bytes),
                            "members": len(inner_names), "all_member_crc": "PASS"})
            require(len(result["nested_evidence"]) == 1, "exact nested evidence archive missing")
        result["status"] = "PASS"
    finally:
        (output / "READBACK.json").write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
        print(json.dumps(result, sort_keys=True))
if __name__ == "__main__":
    main()
