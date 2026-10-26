"""Repository-local Hepta test package.

Explicit identity prevents fixture imports such as ``tests.test_hia_program``
from resolving an unrelated installed third-party ``tests`` package.
"""
