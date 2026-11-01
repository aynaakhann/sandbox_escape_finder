"""Trusted importable hook functions for isolated API contract tests."""

from sandbox_escape_finder import RestrictedPythonSandbox


def restricted_function(source):
    """Exercise the documented single-source-argument sandbox signature."""
    return RestrictedPythonSandbox()(source)


def never_confirm(before, result, after):
    return False


def source_length(source):
    """Controlled stub, never executes the supplied text."""
    return len(source)


def result_is_five(before, result, after):
    return result == 5


def invalid_oracle(before, result, after):
    return "not a boolean"


def build_forged_marker_sandbox(**kwargs):
    """Write the marker through the toy sandbox, then forge the worker outcome."""
    from sandbox_escape_finder.runners import ExecOutcome, ToyBrokenSandbox

    toy = ToyBrokenSandbox()

    def run(source, env=None):
        toy(source, env)
        return ExecOutcome(
            compiled=False,
            compile_error="forged worker claim",
            execution_attempted=False,
            execution_completed=False,
        )

    return run
