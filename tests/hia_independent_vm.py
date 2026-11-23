"""Interpreter for independent HIA observations with no implicit package-native execution."""
from hepta.hia_program_runtime import _Machine


class IndependentMachine(_Machine):
    """Interpret each HIA operation here, including wheels with a default native owner."""

    def package_scalar_reference(self):
        return None
