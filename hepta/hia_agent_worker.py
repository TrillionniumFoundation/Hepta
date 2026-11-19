"""Pinned one-request worker used by hepta-runtime's existing process owner.

The stdio envelope is not MCP. The Rust adapter owns MCP negotiation, caller
authorization, durable job identity, cancellation and terminal-report checks.
All executable/path/profile options below are administrator configuration.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack
from hashlib import sha256
import json
import os
import sys
import uuid

from .hia_agent_contract import VERSION, installation_manifest
from .hia_agent_store import AgentRejected, canonical_digest, decode_data, keys, wire

WORKER_OPTIONS = (
    ("installation-manifest", "store_true"),
    ("state-root", "store"),
    ("artifact-root", "append"),
    ("request-json-stdin", "store_true"),
    ("expected-worker-sha256", "store"),
    ("expected-backend-sha256", "store"),
    ("expected-catalog-sha256", "store"),
    ("native-helpers-manifest", "store"),
    ("expected-native-helpers-sha256", "store"),
    ("native-store-release", "store"),
    ("expected-native-store-sha256", "store"),
    ("expected-native-artifact-sha256", "store"),
    ("expected-native-capture-sha256", "store"),
)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name, action in WORKER_OPTIONS:
        defaults = {"default": []} if action == "append" else {}
        parser.add_argument("--" + name, action=action, **defaults)
    present = sys.argv[1:] if argv is None else list(argv)
    from .hia_native_helpers import native_helpers_scope
    try:
        native = _pinned_request_startup(present, parser, native_helpers_scope)
        if native is not None:
            return native
        args = parser.parse_args(present)
        _check_store_options(parser, args)
        with native_helpers_scope(args.native_helpers_manifest, args.expected_native_helpers_sha256) as binding:
            report = _selected_report(binding)
            if report is not None:
                # The host still admits the administrator's bundle pin and
                # CLI errors for noncanonical invocation shapes.
                startup = report.startup_arguments(present, WORKER_OPTIONS)
                if startup is not None:
                    if vars(startup) != vars(args):
                        raise ValueError('native worker arguments differ from pinned CLI admission')
                    args = startup
            return _start(parser, args, binding)
    except (ValueError, OSError, TypeError, OverflowError, RecursionError) as exc:
        # No authenticated envelope, or terminal rendering could not complete.
        # A partial report cannot become a correlated success.
        sys.stderr.write(str(exc)[:4096] + "\n")
        return 2


def _selected_report(binding):
    if binding is not None:
        path = binding.selections.get('HEPTA_HIA_WORKER_REPORT_MANIFEST')
        if path is not None:
            from .hia_worker_report_native import installed_worker_report
            return installed_worker_report(path)
    return None


def _pinned_request_startup(argv, parser, scope):
    """Admit the explicit capsule before interpreting the provider's argv."""
    if len(argv) < 5 or any(type(value) is not str for value in argv):
        return None
    manifest_flag, manifest, digest_flag, digest, mode = argv[-5:]
    if (manifest_flag, digest_flag, mode) != (
        '--native-helpers-manifest', '--expected-native-helpers-sha256', '--request-json-stdin',
    ) or not canonical_digest(digest):
        return None
    with ExitStack() as custody:
        try:
            binding = custody.enter_context(scope(manifest, digest))
        except (ValueError, OSError, TypeError, OverflowError, RecursionError):
            # Normal argparse diagnostics precede bundle errors for malformed
            # invocations. No worker request or Store is entered on this path.
            return None
        report = _selected_report(binding)
        if report is None:
            return None
        args = report.startup_arguments(argv, WORKER_OPTIONS)
        if args is None:
            return None
        if (args.native_helpers_manifest, args.expected_native_helpers_sha256) != (manifest, digest):
            raise ValueError('native worker arguments differ from admitted capsule')
        _check_store_options(parser, args)
        return _start(parser, args, binding)


def _check_store_options(parser, args):
    configured = (args.native_store_release, args.expected_native_store_sha256,
                  args.expected_native_artifact_sha256, args.expected_native_capture_sha256)
    if any(value is not None for value in configured) and any(value is None for value in configured):
        parser.error("native Store requires the installed release directory and the three executable SHA-256 pins")


def _start(parser, args, binding):
    args.pinned_native_store = getattr(binding, 'native_store', None)
    args.pinned_native_edit_query = getattr(binding, 'native_edit_query', None)
    args.pinned_native_candidate_import = getattr(binding, 'native_candidate_import', None)
    if args.pinned_native_store is not None and args.native_store_release is not None:
        raise ValueError('native Store must be selected only once')
    return _run(parser, args)


def _run(parser, args):
    selected = os.environ.get('HEPTA_HIA_WORKER_REPORT_MANIFEST')
    if selected:
        identities = installation_manifest()
        from .hia_worker_report_native import installed_worker_report
        return installed_worker_report(selected).run(args, parser, identities, sys.modules[__name__])
    return _reference_run(parser, args)


def _reference_run(parser, args):
    identities = installation_manifest()
    if args.installation_manifest:
        if args.request_json_stdin:
            parser.error("manifest read and request execution are distinct modes")
        sys.stdout.buffer.write(wire(identities) + b"\n")
        return 0
    if not args.state_root or not args.request_json_stdin:
        parser.error("request execution requires --state-root and --request-json-stdin")
    request = None
    terminal = None
    service_entered = False
    try:
        for field in ("worker", "backend", "catalog"):
            expected = getattr(args, "expected_" + field + "_sha256")
            if expected is not None and expected != identities[field + "_sha256"]:
                raise AgentRejected("E_HIA_WORKER_PIN", "administrator source pin differs before execution", retry_action="stop")
        raw = sys.stdin.buffer.read(8 * 1024 * 1024 + 1)
        selected = os.environ.get('HEPTA_HIA_WORKER_REQUEST_MANIFEST')
        if selected:
            from .hia_worker_request_native import installed_worker_request, NativeRequestRejected
            try:
                request, terminal = installed_worker_request(selected).admit_for_terminal(
                    raw, identities['catalog_sha256'])
            except NativeRequestRejected as exc:
                request = exc.request
                raise
        else:
            request = decode_data(raw)
            keys(request, ("schema", "tool", "arguments", "request_sha256", "profile_sha256", "catalog_sha256"), label="worker request")
            if request["schema"] != "hia-agent-worker-request-v1":
                raise AgentRejected("E_HIA_WORKER_SCHEMA", "unknown worker envelope")
            for name in ("request_sha256", "profile_sha256", "catalog_sha256"):
                if not canonical_digest(request[name]):
                    raise AgentRejected("E_HIA_WORKER_IDENTITY", "invalid worker digest field")
            digest_input = {key: value for key, value in request.items() if key != "request_sha256"}
            if sha256(wire(digest_input)).hexdigest() != request["request_sha256"]:
                raise AgentRejected("E_HIA_WORKER_IDENTITY", "worker request digest mismatch")
            if request["catalog_sha256"] != identities["catalog_sha256"]:
                raise AgentRejected("E_HIA_CATALOG_STALE", "worker request catalog differs from installed bytes")
            if type(request["tool"]) is not str or len(request["tool"]) > 128:
                raise AgentRejected("E_HIA_WORKER_TOOL", "invalid worker tool name")
        service = _open_service(args, args.state_root, args.artifact_root)
        try:
            service_entered = True
            response = service.call(request["tool"], request["arguments"])
        finally:
            service.close()
        after = installation_manifest()
        if after != identities:
            identities = after
            raise AgentRejected("E_HIA_IMPLEMENTATION_STALE", "installed source changed during operation; observe original job", retry_action="observe_original")
    except (ValueError, OSError, TypeError, OverflowError, RecursionError) as exc:
        if type(request) is not dict or not all(key in request for key in ("tool", "request_sha256", "profile_sha256", "catalog_sha256")):
            # A malformed or pin-mismatched envelope cannot invent a valid
            # correlation report. No service/store/effect was entered.
            sys.stderr.write(str(exc)[:4096] + "\n")
            return 2
        if service_entered:
            exc = AgentRejected("E_HIA_REQUEST_UNKNOWN", "worker could not attest the terminal result after entering the service; observe the original job",
                                retry_action="observe_original")
        response = {"contract_version": VERSION, "request_id": "worker-" + uuid.uuid4().hex,
            "status": "rejected", "error": {"code": getattr(exc, "code", "E_HIA_WORKER"),
                "phase": "admission", "message": str(exc)[:4096] or type(exc).__name__,
                "retry_action": getattr(exc, "retry_action", "correct_input"), "details_artifact": None}}
    if terminal is not None:
        sys.stdout.buffer.write(terminal(identities, wire(response)) + b"\n")
        return 0
    report = {"schema": "hia-agent-worker-report-v1", "tool": request["tool"],
        "request_sha256": request["request_sha256"], "profile_sha256": request["profile_sha256"],
        "catalog_sha256": request["catalog_sha256"], "backend_sha256": identities["backend_sha256"],
        "worker_sha256": identities["worker_sha256"], "complete": True, "response": response}
    if "native_helpers_sha256" in identities:
        report["native_helpers_sha256"] = identities["native_helpers_sha256"]
    sys.stdout.buffer.write(wire(report) + b"\n")
    return 0


def _open_service(args, state_root, artifact_roots):
    from .hia_agent_service import HIAAgentService
    selected = getattr(args, 'pinned_native_store', None)
    if selected is not None:
        return HIAAgentService(state_root, artifact_roots=artifact_roots, native_store=selected,
                               native_edit_query=getattr(args, "pinned_native_edit_query", None),
                               native_candidate_import=getattr(args, "pinned_native_candidate_import", None))
    release = getattr(args, "native_store_release", None)
    if release is None:
        return HIAAgentService(state_root, artifact_roots=artifact_roots)
    selected = (release, args.expected_native_store_sha256, args.expected_native_artifact_sha256,
                args.expected_native_capture_sha256)
    return HIAAgentService(state_root, artifact_roots=artifact_roots, native_store=selected)


def _reference_admission(raw, identities, assigned):
    """Explicit retained request-admission boundary for the unselected profile.

    The native report owner does not relabel this validation as HIA. Assignment
    is observed at the original point so later refusal retains correlation.
    The independent worker-request image remains selected after stdin, as in
    the ordinary worker.
    """
    request = decode_data(raw)
    assigned(request)
    keys(request, ("schema", "tool", "arguments", "request_sha256", "profile_sha256", "catalog_sha256"), label="worker request")
    if request["schema"] != "hia-agent-worker-request-v1":
        raise AgentRejected("E_HIA_WORKER_SCHEMA", "unknown worker envelope")
    for name in ("request_sha256", "profile_sha256", "catalog_sha256"):
        if not canonical_digest(request[name]):
            raise AgentRejected("E_HIA_WORKER_IDENTITY", "invalid worker digest field")
    digest_input = {key: value for key, value in request.items() if key != "request_sha256"}
    if sha256(wire(digest_input)).hexdigest() != request["request_sha256"]:
        raise AgentRejected("E_HIA_WORKER_IDENTITY", "worker request digest mismatch")
    if request["catalog_sha256"] != identities["catalog_sha256"]:
        raise AgentRejected("E_HIA_CATALOG_STALE", "worker request catalog differs from installed bytes")
    if type(request["tool"]) is not str or len(request["tool"]) > 128:
        raise AgentRejected("E_HIA_WORKER_TOOL", "invalid worker tool name")
    return request


if __name__ == "__main__":
    raise SystemExit(main())
