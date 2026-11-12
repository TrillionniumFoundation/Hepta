"""Single GET of a bounded provider file reference. No product execution."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

def require(value, message):
    if not value:
        raise ValueError(message)

def allowed(url):
    p = urllib.parse.urlsplit(url)
    require(p.scheme == "https" and p.hostname and p.username is None and p.password is None,
            "provider transport URL shape differs")
    host = p.hostname.lower()
    require((host.startswith("sdmntpr") and host.endswith(".oaiusercontent.com"))
            or (host.startswith("oaisdmntpr") and host.endswith(".blob.core.windows.net"))
            or (host.startswith("oaisdsorpr") and host.endswith(".blob.core.windows.net"))
            or (host.startswith("oaisdmntpr") and "aws.s3." in host and host.endswith(".amazonaws.com")),
            "provider hostname outside declared transport")
    return host

class Redirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        allowed(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)

def wire(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()

def main():
    a = argparse.ArgumentParser()
    a.add_argument("--private-request", type=Path, required=True)
    a.add_argument("--output", type=Path, required=True)
    args = a.parse_args()
    private = json.loads(args.private_request.read_bytes())
    expected = private["expected"]
    require(type(expected["bytes"]) is int and 0 < expected["bytes"] <= 536870912,
            "only bounded derived artifacts are accepted")
    require(expected["artifact_id"] != 13982129929, "direct original large download forbidden")
    require(type(expected["sha256"]) is str and len(expected["sha256"]) == 64,
            "external artifact digest required")
    host = allowed(private["url"])
    output = args.output
    partial = output.with_name(output.name + ".partial")
    require(not os.path.lexists(output) and not os.path.lexists(partial), "new download names required")
    report = {"schema": "hia.full32-r4.actual-provider-download.v1", "status": "HOLD",
              "expected": expected, "host": host, "configured_proxy_policy": "urllib defaults retained",
              "get_attempts": 0, "redirects_carry_no_authorization_or_cookie": True,
              "partial": str(partial), "output": str(output), "started_ns": time.monotonic_ns()}
    digest = hashlib.sha256(); count = 0
    try:
        opener = urllib.request.build_opener(Redirect())
        request = urllib.request.Request(private["url"], headers={"User-Agent": "HIA-original-custody-reader/1"})
        report["get_attempts"] = 1
        with opener.open(request, timeout=120) as response:
            require(response.status == 200, "provider status differs")
            report["http_status"] = response.status
            value = response.headers.get("Content-Length")
            if value is not None:
                require(int(value) == expected["bytes"], "provider declared length differs")
            fd = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            try:
                while True:
                    value = response.read(min(1048576, expected["bytes"] + 1 - count))
                    if not value: break
                    require(count + len(value) <= expected["bytes"], "provider body exceeds exact size")
                    view = memoryview(value)
                    while view:
                        used = os.write(fd, view); require(used > 0, "partial write refused"); view = view[used:]
                    digest.update(value); count += len(value)
                os.fsync(fd)
                info = os.fstat(fd)
                require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size == count,
                        "download file identity differs")
            finally:
                os.close(fd)
        require(count == expected["bytes"] and digest.hexdigest() == expected["sha256"],
                "external artifact complete seal differs")
        second = hashlib.sha256(); second_count = 0
        fd = os.open(partial, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            before = os.fstat(fd)
            while True:
                value = os.read(fd, 1048576)
                if not value: break
                second.update(value); second_count += len(value)
            after = os.fstat(fd)
            require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                    == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                    and before.st_nlink == after.st_nlink == 1, "readback identity changed")
        finally:
            os.close(fd)
        require(second_count == count and second.hexdigest() == digest.hexdigest(), "independent readback differs")
        os.rename(partial, output)
        report.update(status="FULL_PROVIDER_ZIP_SEAL_AND_INDEPENDENT_READBACK_PASS", independent_readback=True)
    except BaseException as error:
        report["error_type"] = type(error).__name__
        if isinstance(error, urllib.error.HTTPError): report["http_error_status"] = error.code
        if type(error) is ValueError: report["fixed_refusal"] = str(error)
    report.update(bytes_read=count, sha256=digest.hexdigest(), elapsed_ns=time.monotonic_ns()-report["started_ns"])
    with output.with_name(output.name + ".DOWNLOAD.json").open("xb") as f:
        f.write(wire(report)); f.flush(); os.fsync(f.fileno())
    print(json.dumps({k: report[k] for k in ("status", "expected", "bytes_read", "sha256", "elapsed_ns")}))
    return 0 if report["status"] == "FULL_PROVIDER_ZIP_SEAL_AND_INDEPENDENT_READBACK_PASS" else 1

if __name__ == "__main__":
    raise SystemExit(main())
