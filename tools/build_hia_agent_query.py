"""Build the complete agent-query HIA owner from physical current cold inputs."""
from __future__ import annotations
import argparse
from pathlib import Path
from tools.hia_cold_compiler import NATIVE_CUSTODY_INPUTS
from tools.hia_current_native_leaf_build import build_leaf

SOURCE_PATH = "examples/hia_bootstrap/agent_query.hepta"
SCHEMA = "hepta.hia.agent-query-native.v1"
INPUTS = (
    SOURCE_PATH, *NATIVE_CUSTODY_INPUTS,
    "tools/build_hia_agent_query.py", "tools/generate_hia_agent_query.py",
    "tools/hia_current_native_leaf_build.py",
    "tests/hia_component_install_fixture.py",
    "tests/test_hia_query_cli_current_native.py",
    "tests/fixtures/hia_query_cli_component_install_preparation_v1.json",
    "tests/fixtures/hia_query_cli_original_v1.tar.gz",
    "tools/hia_word_memory_cases.py",
    "tools/generate_hia_selfhost.py", "tools/generate_hia_sha256.py",
    "tools/generate_hia_json_decode.py", "tools/qualify_hia_selfhost.py",
    "tools/build_hia_source_build.py", "tools/build_hia_json_preflight.py",
    "hepta/hia_agent_query_native.py", "hepta/hia_json_preflight_native.py",
    "hepta/hia_native_helpers.py", "hepta/hia_loaded_source.py",
    "hepta/hia_program.py", "hepta/hia_agent_assembly.py",
    "tests/test_hia_agent_query_native.py",
    "tools/generate_hia_agent_slice.py",
    "tools/generate_hia_core_json_frontend.py",
    "hepta/hia_edit_query.py",
    "tests/test_hia_agent_query_native_integration.py",
)
SOURCES = INPUTS

def build(output, compiler, cold_report):
    return build_leaf(output, compiler, cold_report=cold_report, source_path=SOURCE_PATH,
                      schema=SCHEMA, inputs=INPUTS, label="agent-query")

def build_development(output, compiler):
    return build_leaf(output, compiler, cold_report=None, source_path=SOURCE_PATH,
                      schema=SCHEMA, inputs=INPUTS, label="agent-query")

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--compiler", type=Path, required=True)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--cold-report", type=Path)
    group.add_argument("--development", action="store_true")
    args = parser.parse_args()
    print(build_development(args.output, args.compiler) if args.development
          else build(args.output, args.compiler, args.cold_report))

if __name__ == "__main__":
    main()
