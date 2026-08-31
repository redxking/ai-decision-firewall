"""Phase 3.1 synthetic-only model evaluation foundations.

This package evaluates model candidates without granting them action authority.
It deliberately contains no historical-data adapter, live connector, broker, or
target interface.
"""

from .benchmark import run_synthetic_benchmark
from .contracts import ModelEvaluationPlan, PlanValidationError

__all__ = [
    "ModelEvaluationPlan",
    "PlanValidationError",
    "run_synthetic_benchmark",
]
