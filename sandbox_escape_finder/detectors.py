"""AST-based detectors for Python sandbox-escape techniques.

This module is the core of the *static* side of SandboxEscapeFinder.

Key idea
--------
We never run the code we are inspecting. Instead we parse it into an
**Abstract Syntax Tree** (AST) with Python's built-in :mod:`ast` module and
look for *syntactic shapes* that are strongly associated with sandbox-escape
techniques (for example, an attribute access whose name is
``__subclasses__``).

Why AST instead of regex?
-------------------------
A regex searching for the text ``__subclasses__`` would also match a comment
(``# never call __subclasses__``) or a plain string
(``"__subclasses__"``). Comments are discarded by Python's tokenizer and never
appear in the AST at all, and a string literal is an :class:`ast.Constant`
node, *not* an :class:`ast.Attribute` node. So AST matching distinguishes
"code that performs ``x.__subclasses__``" from "text that merely mentions the
word". We document the remaining blind spots (e.g. ``getattr(x, "__subcl" +
"asses__")``) as known false negatives.

A finding is *suspicious syntax*, not proof of exploitability. The confidence
score reflects how strongly a pattern is associated with escape attempts, not
the probability that the code can actually escape a particular sandbox.
"""

from __future__ import annotations

import ast
import string
from dataclasses import asdict, dataclass
from typing import Iterable, Optional


# Confidence is a float in [0, 1]. These thresholds turn it into a label.
HIGH_THRESHOLD = 0.8
MEDIUM_THRESHOLD = 0.5


def confidence_label(score: float) -> str:
    """Map a numeric confidence to a documented label.

    * ``high``   (>= 0.8): the pattern is almost always part of an escape idiom.
    * ``medium`` (>= 0.5): the pattern is commonly used in escapes but also has
      legitimate uses.
    * ``low``    (< 0.5):  weakly suspicious; frequently benign.
    """
    if score >= HIGH_THRESHOLD:
        return "high"
    if score >= MEDIUM_THRESHOLD:
        return "medium"
    return "low"


@dataclass
class Finding:
    """A single static-analysis result.

    Attributes mirror the fields the assignment requires: the technique name,
    the matched AST node description, source location, a confidence score, and
    enough context (``snippet``) to explain the finding.
    """

    detector: str  # stable detector id, e.g. "subclasses_traversal"
    technique: str  # human-readable technique name
    message: str  # short explanation of *this* match
    node_type: str  # AST node class name / description that matched
    lineno: int
    col_offset: int
    end_lineno: Optional[int]
    end_col_offset: Optional[int]
    confidence: float
    confidence_label: str
    snippet: str  # the source line(s) that triggered the match

    def to_dict(self) -> dict:
        return asdict(self)

    def key(self) -> tuple:
        """Identity used for de-duplication."""
        return (self.detector, self.lineno, self.col_offset, self.node_type, self.message)


# --------------------------------------------------------------------------- #
# Small AST helpers shared by several detectors.
# --------------------------------------------------------------------------- #
def _attr_chain(node: ast.AST) -> list[str]:
    """Return attribute/name components of a dotted expression, outer-first.

    ``a.__class__.__bases__`` -> ``['__bases__', '__class__', 'a']``.
    Lets a detector see that a suspicious attribute sits in a longer dunder
    chain, which raises our confidence.
    """
    names: list[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        names.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        names.append(cur.id)
    return names


def _snippet(source_lines: list[str], node: ast.AST) -> str:
    lineno = getattr(node, "lineno", 0)
    if 1 <= lineno <= len(source_lines):
        return source_lines[lineno - 1].strip()
    return ""


def _iter_format_fields(fmt: str) -> Iterable[str]:
    """Yield the ``field_name`` of every replacement field in a format string.

    Uses the same parser the ``str.format`` machinery uses, so
    ``"{0.__class__}"`` yields ``"0.__class__"`` and ``"{a[__builtins__]}"``
    yields ``"a[__builtins__]"``.
    """
    try:
        for _literal, field_name, _spec, _conv in string.Formatter().parse(fmt):
            if field_name:
                yield field_name
    except (ValueError, IndexError):
        # Malformed format string: nothing reliable to analyse.
        return


# --------------------------------------------------------------------------- #
# Detector base class.
# --------------------------------------------------------------------------- #
class Detector:
    """Base class for all detectors.

    Subclasses set the class attributes and implement :meth:`analyze`.
    Each detector is independent and can be enabled/disabled via config.
    """

    id: str = "base"
    technique: str = "Base technique"
    description: str = ""
    # Documented references for the technique category (see README/corpus).
    references: tuple[str, ...] = ()

    def __init__(self, enabled: bool = True) -> None:
        self.enabled = enabled

    def analyze(self, tree: ast.AST, source_lines: list[str]) -> list[Finding]:
        raise NotImplementedError

    # Convenience used by subclasses to build a Finding with a snippet.
    def _finding(
        self,
        node: ast.AST,
        message: str,
        confidence: float,
        source_lines: list[str],
        node_type: Optional[str] = None,
    ) -> Finding:
        return Finding(
            detector=self.id,
            technique=self.technique,
            message=message,
            node_type=node_type or type(node).__name__,
            lineno=getattr(node, "lineno", 0),
            col_offset=getattr(node, "col_offset", 0),
            end_lineno=getattr(node, "end_lineno", None),
            end_col_offset=getattr(node, "end_col_offset", None),
            confidence=round(min(confidence, 0.99), 2),
            confidence_label=confidence_label(min(confidence, 0.99)),
            snippet=_snippet(source_lines, node),
        )


# --------------------------------------------------------------------------- #
# 1. __subclasses__ / MRO traversal.
# --------------------------------------------------------------------------- #
class SubclassesTraversalDetector(Detector):
    """Detects object-graph traversal via ``__subclasses__``/``__bases__``/MRO.

    The classic RestrictedPython/pyjail escape finds a reachable base class
    (usually ``object``) and walks ``__subclasses__()`` to locate a dangerous
    class such as ``subprocess.Popen`` or an ``os`` function, e.g.::

        ().__class__.__bases__[0].__subclasses__()

    We flag the *traversal* dunders. We deliberately do NOT flag ``__class__``
    on its own, because it is extremely common and benign; instead its presence
    in the same dotted chain raises confidence.
    """

    id = "subclasses_traversal"
    technique = "__subclasses__ / MRO traversal"
    description = "Walking the class hierarchy to reach dangerous classes."
    references = ("https://github.com/moshekaplan/python_sandbox_escapes",)

    _ATTRS = {
        "__subclasses__": 0.9,
        "__mro__": 0.75,
        "__bases__": 0.6,
        "__base__": 0.6,
        "__subclasshook__": 0.6,
    }

    def analyze(self, tree, source_lines):
        findings = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr in self._ATTRS:
                conf = self._ATTRS[node.attr]
                chain = _attr_chain(node)
                # A longer dunder chain (e.g. __class__ -> __bases__ ->
                # __subclasses__) is much more clearly an escape attempt.
                dunders = [c for c in chain if c.startswith("__") and c.endswith("__")]
                if len(dunders) >= 2 or "__class__" in chain:
                    conf = min(conf + 0.1, 0.95)
                findings.append(
                    self._finding(
                        node,
                        message=(
                            f"Attribute access '.{node.attr}' traverses the class "
                            f"hierarchy (chain: {'.'.join(reversed(chain)) or node.attr})."
                        ),
                        confidence=conf,
                        source_lines=source_lines,
                        node_type=f"Attribute(attr='{node.attr}')",
                    )
                )
        return findings


# --------------------------------------------------------------------------- #
# 2. Function __globals__ access.
# --------------------------------------------------------------------------- #
class GlobalsAccessDetector(Detector):
    """Detects access to a function's ``__globals__`` mapping.

    Any function object exposes ``__globals__`` — the module globals it was
    defined in — which usually contains real builtins and imports. Reaching it
    (``(lambda: 0).__globals__``) is a common recovery step in an escape.
    """

    id = "globals_access"
    technique = "Function __globals__ access"
    description = "Reaching a function's defining module globals."
    references = ("https://github.com/jailctf/pyjailbreaker",)

    def analyze(self, tree, source_lines):
        findings = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr == "__globals__":
                findings.append(
                    self._finding(
                        node,
                        message="Access to '.__globals__' exposes module-level globals/builtins.",
                        confidence=0.85,
                        source_lines=source_lines,
                        node_type="Attribute(attr='__globals__')",
                    )
                )
        return findings


# --------------------------------------------------------------------------- #
# 3. Closure / cell introspection.
# --------------------------------------------------------------------------- #
class ClosureCellDetector(Detector):
    """Detects closure/cell introspection (``__closure__``, ``cell_contents``).

    A closure captures variables in *cell* objects. Reading ``__closure__`` and
    then ``cell_contents`` can smuggle out objects the sandbox tried to hide.
    """

    id = "closure_cell"
    technique = "Closure / cell introspection"
    description = "Extracting captured objects from closure cells."
    references = ("https://github.com/jailctf/pyjailbreaker",)

    _ATTRS = {"__closure__": 0.75, "cell_contents": 0.8}

    def analyze(self, tree, source_lines):
        findings = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr in self._ATTRS:
                conf = self._ATTRS[node.attr]
                chain = _attr_chain(node)
                if "__closure__" in chain and "cell_contents" in chain:
                    conf = 0.9
                findings.append(
                    self._finding(
                        node,
                        message=f"Access to '.{node.attr}' introspects closure cells.",
                        confidence=conf,
                        source_lines=source_lines,
                        node_type=f"Attribute(attr='{node.attr}')",
                    )
                )
        return findings


# --------------------------------------------------------------------------- #
# 4. __builtins__ / built-ins recovery.
# --------------------------------------------------------------------------- #
class BuiltinsRecoveryDetector(Detector):
    """Detects attempts to recover the real ``__builtins__`` / dangerous names.

    Sandboxes replace ``__builtins__`` with a tiny safe subset. Escapes try to
    get the real one back (``....__globals__['__builtins__']``) or pull a
    specific dangerous entry (``__builtins__['eval']``, ``['__import__']``).
    """

    id = "builtins_recovery"
    technique = "__builtins__ / built-ins recovery"
    description = "Recovering the real builtins mapping or dangerous entries."
    references = ("https://restrictedpython.readthedocs.io/",)

    _DANGEROUS_KEYS = {
        "eval",
        "exec",
        "__import__",
        "open",
        "compile",
        "getattr",
        "globals",
        "input",
        "breakpoint",
    }

    def analyze(self, tree, source_lines):
        findings = []
        for node in ast.walk(tree):
            # Direct attribute access: x.__builtins__ or x.__import__
            if isinstance(node, ast.Attribute) and node.attr in {"__builtins__", "__import__"}:
                findings.append(
                    self._finding(
                        node,
                        message=f"Access to '.{node.attr}' targets the builtins mechanism.",
                        confidence=0.8,
                        source_lines=source_lines,
                        node_type=f"Attribute(attr='{node.attr}')",
                    )
                )
            # Subscript recovery: something['eval'] / __builtins__['__import__']
            if isinstance(node, ast.Subscript):
                key = self._const_subscript_key(node)
                base = node.value
                base_is_builtins = (
                    isinstance(base, ast.Name) and base.id == "__builtins__"
                ) or (isinstance(base, ast.Attribute) and base.attr == "__builtins__")
                if key in self._DANGEROUS_KEYS and (base_is_builtins or key in {"__import__"}):
                    findings.append(
                        self._finding(
                            node,
                            message=(
                                f"Subscript access ['{key}'] pulls a dangerous entry "
                                "from a builtins-like mapping."
                            ),
                            confidence=0.8,
                            source_lines=source_lines,
                            node_type=f"Subscript(key='{key}')",
                        )
                    )
        return findings

    @staticmethod
    def _const_subscript_key(node: ast.Subscript) -> Optional[str]:
        sl = node.slice
        if isinstance(sl, ast.Constant) and isinstance(sl.value, str):
            return sl.value
        return None


# --------------------------------------------------------------------------- #
# 5. Frame / generator / execution-context introspection.
# --------------------------------------------------------------------------- #
class FrameIntrospectionDetector(Detector):
    """Detects frame/generator/execution-context introspection.

    Reaching a frame object (via ``sys._getframe``, a generator's ``gi_frame``,
    a coroutine's ``cr_frame``, a traceback's ``tb_frame``) gives access to
    ``f_globals`` / ``f_builtins`` / ``f_back`` and therefore to the caller's
    namespace and the real builtins.
    """

    id = "frame_introspection"
    technique = "Frame / generator / execution-context introspection"
    description = "Walking frames to reach caller globals/builtins."
    references = ("https://github.com/moshekaplan/python_sandbox_escapes",)

    _ATTRS = {
        "f_globals": 0.85,
        "f_builtins": 0.85,
        "f_locals": 0.7,
        "f_back": 0.7,
        "f_code": 0.6,
        "gi_frame": 0.7,
        "gi_code": 0.6,
        "cr_frame": 0.7,
        "ag_frame": 0.7,
        "tb_frame": 0.7,
    }
    _FRAME_CALLS = {"_getframe", "currentframe"}

    def analyze(self, tree, source_lines):
        findings = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr in self._ATTRS:
                findings.append(
                    self._finding(
                        node,
                        message=f"Access to '.{node.attr}' introspects execution frames.",
                        confidence=self._ATTRS[node.attr],
                        source_lines=source_lines,
                        node_type=f"Attribute(attr='{node.attr}')",
                    )
                )
            # sys._getframe(...) / inspect.currentframe(...)
            if isinstance(node, ast.Call):
                func = node.func
                name = None
                if isinstance(func, ast.Attribute):
                    name = func.attr
                elif isinstance(func, ast.Name):
                    name = func.id
                if name in self._FRAME_CALLS:
                    findings.append(
                        self._finding(
                            node,
                            message=f"Call to '{name}()' obtains a frame object.",
                            confidence=0.8,
                            source_lines=source_lines,
                            node_type=f"Call({name})",
                        )
                    )
        return findings


# --------------------------------------------------------------------------- #
# 6. Suspicious format-string attribute / item traversal.
# --------------------------------------------------------------------------- #
class FormatStringTraversalDetector(Detector):
    """Detects attribute/item traversal inside ``str.format`` templates.

    ``str.format`` lets a *template* reach into its arguments:
    ``"{0.__class__.__init__.__globals__}".format(obj)``. When the template is
    attacker-controlled this is a known information-disclosure / escape vector.
    We inspect constant format strings passed to ``.format``/``.format_map``.

    Limitation: if the format string is not a literal (it comes from a
    variable), we cannot inspect it statically — documented as a false negative.
    """

    id = "format_string_traversal"
    technique = "Suspicious format-string attribute/item traversal"
    description = "Dunder traversal embedded in a .format template."
    references = ("https://github.com/jailctf/pyjailbreaker",)

    def analyze(self, tree, source_lines):
        findings = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not (isinstance(func, ast.Attribute) and func.attr in {"format", "format_map"}):
                continue
            recv = func.value
            if not (isinstance(recv, ast.Constant) and isinstance(recv.value, str)):
                continue  # non-literal template: cannot inspect (false negative)
            for field_name in _iter_format_fields(recv.value):
                has_traversal = ("." in field_name) or ("[" in field_name)
                if not has_traversal:
                    continue
                is_dunder = "__" in field_name
                conf = 0.85 if is_dunder else 0.55
                findings.append(
                    self._finding(
                        node,
                        message=(
                            f"Format field '{{{field_name}}}' traverses attributes/items "
                            f"of the formatted object{' via dunders' if is_dunder else ''}."
                        ),
                        confidence=conf,
                        source_lines=source_lines,
                        node_type=f"Call(.{func.attr}, field='{field_name}')",
                    )
                )
        return findings


# --------------------------------------------------------------------------- #
# 7. (Bonus) Direct dangerous builtin calls.
# --------------------------------------------------------------------------- #
class DangerousBuiltinCallDetector(Detector):
    """Detects direct calls to dangerous builtins and dunder ``getattr``.

    Flags ``eval``/``exec``/``compile``/``__import__``/``open`` calls and
    ``getattr(obj, "__dunder__")`` style string-keyed attribute access (a common
    way to reach a dunder while hiding it from naive matchers). These names are
    usually unavailable inside RestrictedPython, so a finding here signals
    *intent*; the dynamic prober shows whether the environment blocks it.
    """

    id = "dangerous_builtin_call"
    technique = "Direct dangerous builtin call"
    description = "Direct eval/exec/import/open or dunder getattr."
    references = ("https://restrictedpython.readthedocs.io/",)

    _CALLS = {"eval": 0.7, "exec": 0.7, "compile": 0.6, "__import__": 0.75, "open": 0.6}
    _GETATTR = {"getattr", "setattr", "delattr"}

    def analyze(self, tree, source_lines):
        findings = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if isinstance(func, ast.Name) and func.id in self._CALLS:
                findings.append(
                    self._finding(
                        node,
                        message=f"Direct call to builtin '{func.id}()'.",
                        confidence=self._CALLS[func.id],
                        source_lines=source_lines,
                        node_type=f"Call({func.id})",
                    )
                )
            if isinstance(func, ast.Name) and func.id in self._GETATTR and len(node.args) >= 2:
                arg = node.args[1]
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str) and arg.value.startswith("__"):
                    findings.append(
                        self._finding(
                            node,
                            message=(
                                f"{func.id}(obj, '{arg.value}') reaches a dunder via a "
                                "string name."
                            ),
                            confidence=0.75,
                            source_lines=source_lines,
                            node_type=f"Call({func.id}, dunder)",
                        )
                    )
        return findings


# Registry: id -> class. Order defines default reporting order.
ALL_DETECTORS: tuple[type[Detector], ...] = (
    SubclassesTraversalDetector,
    GlobalsAccessDetector,
    ClosureCellDetector,
    BuiltinsRecoveryDetector,
    FrameIntrospectionDetector,
    FormatStringTraversalDetector,
    DangerousBuiltinCallDetector,
)

DETECTOR_IDS: tuple[str, ...] = tuple(d.id for d in ALL_DETECTORS)


def build_detectors(enabled_ids: Optional[Iterable[str]] = None) -> list[Detector]:
    """Instantiate detectors, enabling only those whose id is in ``enabled_ids``.

    ``enabled_ids=None`` enables every detector.
    """
    enabled = set(enabled_ids) if enabled_ids is not None else None
    detectors = []
    for cls in ALL_DETECTORS:
        is_on = True if enabled is None else (cls.id in enabled)
        detectors.append(cls(enabled=is_on))
    return detectors


def detector_catalog() -> list[dict]:
    """Return metadata about every detector (used by README/reporting)."""
    return [
        {
            "id": cls.id,
            "technique": cls.technique,
            "description": cls.description,
            "references": list(cls.references),
        }
        for cls in ALL_DETECTORS
    ]
