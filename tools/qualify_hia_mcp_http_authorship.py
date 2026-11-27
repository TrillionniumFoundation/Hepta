"""Check each dedicated HTTP source against its existing canonical author."""
from __future__ import annotations
import argparse
from hashlib import sha256
import importlib
import json
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools import generate_hia_mcp_http as http
from tools.generate_hia_mcp_service import document

ROOT = Path(__file__).resolve().parents[1]


def authored_sources():
    values = {}
    for role in ('bootstrap', 'setup', 'stream', 'dispatch', 'scheduler'):
        values[http.source_path(role)] = render_assembly(document(http.component_source(role), 'mcp_http_'+role))
    for role in http.HTTP_COMPONENTS:
        name = 'tools.generate_hia_mcp_http_bootstrap' if role == 'http_boot' else 'tools.generate_hia_mcp_'+role
        values[http.source_path(role)] = importlib.import_module(name).render()
    from tools.generate_hia_mcp_http_presentation import render_reply, render_catalog
    from tools.generate_hia_mcp_http_session_policy import render as render_session
    values[http.COMPANIONS['session']] = render_session()
    values[http.COMPANIONS['reply']] = render_reply()
    values[http.COMPANIONS['catalog']] = render_catalog()
    values['examples/hia_bootstrap/mcp_http_packer.hepta'] = render_assembly(document(http.packer_source(), 'mcp_http_packer'))
    return values


def qualify(output):
    rows = []
    report = {'schema': 'hepta.hia.http-native-authorship.v1', 'passed': False,
              'scope': 'exact canonical author bytes; no execution qualification', 'sources': rows}
    try:
        for path, expected in authored_sources().items():
            raw = (ROOT/path).read_bytes()
            assert raw == expected.encode(), path
            rows.append({'path': path, 'bytes': len(raw), 'sha256': sha256(raw).hexdigest()})
        assert len(rows) == 20
        report.update(passed=True, checked_sources=len(rows))
        return report
    finally:
        output.write_text(json.dumps(report, indent=2)+'\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = qualify(args.output)
    print(json.dumps({'passed': report['passed'], 'sources': len(report['sources'])}))


if __name__ == '__main__':
    main()
