"""Preserve original complete AST digests across Python dump defaults.

Python 3.13 added show_empty=False. The retained independent reference digests
were captured with Python 3.12, which included every empty list field. Request
that same representation where the option exists; do not drop fields, rewrite
nodes or replace the original expected digests.
"""
import ast
import inspect


def reference_ast_dump(node):
    options = {"include_attributes": False}
    if "show_empty" in inspect.signature(ast.dump).parameters:
        options["show_empty"] = True
    return ast.dump(node, **options)
