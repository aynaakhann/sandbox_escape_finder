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
