"""Legacy operations preserve eager I/O and parsing. They impose no budgets."""
import json
import tomllib
from pathlib import Path
from hepta.lexer import tokenize
from hepta.parser import parse


class LegacyLoaderOps:
    def read(self, path, role):
        return Path(path).read_bytes()

    def inventory(self, root):
        return Path(root).rglob('*')

    def json(self, data, path):
        return json.loads(data)

    def toml(self, data, path):
        return tomllib.loads(data.decode('utf-8'))

    def tokenize(self, text, path):
        return tokenize(text, path)

    def parse(self, text, path):
        # Intentionally retains legacy duplicate lexing. An admitted-token API
        # is a separate reviewed change, not part of mechanical extraction.
        return parse(text, path)
