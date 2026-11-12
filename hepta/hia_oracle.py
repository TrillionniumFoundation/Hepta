"""Exception protocol shared by the standalone Core/native differential.

The executable reference is hepta.hia_program_runtime, not a source-AST oracle.
"""
class HIAOracleRejected(ValueError):
    pass

class HIAOracleTrap(ArithmeticError):
    pass

class HIAOracleBudgetExceeded(RuntimeError):
    pass
