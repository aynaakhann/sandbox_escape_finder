"""An attributed, reproducible corpus of sandbox-escape probes.

Each :class:`PayloadCase` documents a technique, the Python source used to
probe it, where the *technique category* is described, the expected static
detection, and the expected behaviour against an unmodified RestrictedPython
setup (verified empirically against RestrictedPython 8.5 while building this
package).

Provenance honesty
------------------
These probes are *representative* of the technique categories documented in the
reference repositories. They are short, non-destructive demonstrations written
for this package. They are **not** claimed to be verbatim copies of any entry
in those repositories unless the ``provenance`` field says so. Where a probe is
the well-known canonical one-liner for a technique, we say "canonical idiom".

Reproducibility
---------------
``Corpus.ordered(seed)`` returns a deterministic ordering driven by
``random.Random(seed)``. The seed makes the *ordering* (and any future
mutation) reproducible. It does NOT make dynamic *outcomes* reproducible across
machines: compile/exec results depend on the installed RestrictedPython version
and the host Python, which is environment-dependent by nature.
"""

from __future__ import annotations

import random
from dataclasses import asdict, dataclass, field
from typing import Iterator, Optional


# Documented expected dynamic outcomes against unmodified RestrictedPython.
RESTRICTED_COMPILE_REJECTED = "compile_rejected"
RESTRICTED_EXECUTION_BLOCKED = "execution_blocked"
RESTRICTED_EXECUTION_COMPLETED = "execution_completed"


@dataclass
class PayloadCase:
    """One attributed test case."""

    id: str
    category: str
    technique: str
    description: str
    source: str
    reference: str
    provenance: str
    expected_static: Optional[bool]
    expected_detectors: list[str] = field(default_factory=list)
    expected_restricted: str = RESTRICTED_EXECUTION_COMPLETED
    dynamic_note: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


class CorpusError(ValueError):
    """Raised when a corpus/custom-payload definition is invalid."""


# --------------------------------------------------------------------------- #
# Built-in corpus: catalog-derived probes, additional technique checks, controls.
# --------------------------------------------------------------------------- #
_REF_KAPLAN = "https://github.com/moshekaplan/python_sandbox_escapes"
_REF_PYJAIL = "https://github.com/jailctf/pyjailbreaker"
_REF_RP = "https://restrictedpython.readthedocs.io/"
_KAPLAN_EXAMPLE = _REF_KAPLAN + "/blob/master/example.py"
_PYJAIL_GADGETS = _REF_PYJAIL + "/blob/main/jailbreak/gadgets/python/"


def _builtin_cases() -> list[PayloadCase]:
    return [
        PayloadCase(
            id="subclasses_popen",
            category="subclasses_traversal",
            technique="__subclasses__ / MRO traversal",
            description="Walk object subclasses to locate a dangerous class.",
            source="danger = ().__class__.__bases__[0].__subclasses__()\n",
            reference=_REF_PYJAIL + "#example",
            provenance="Reduced from the README class-list chain; __bases__[0] replaces __base__; no shell step.",
            expected_static=True,
            expected_detectors=["subclasses_traversal"],
            expected_restricted=RESTRICTED_COMPILE_REJECTED,
            dynamic_note="Expected to be rejected at compile time (underscore attribute names).",
        ),
        PayloadCase(
            id="func_globals",
            category="globals_access",
            technique="Function __globals__ access",
            description="Reach a function's module globals.",
            source="leaked = (lambda: 0).__globals__\n",
            reference=_PYJAIL_GADGETS + "sys.py",
            provenance="Reduced __globals__ recovery step from sys__wrap_close; uses a local lambda instead of a discovered method.",
            expected_static=True,
            expected_detectors=["globals_access"],
            expected_restricted=RESTRICTED_COMPILE_REJECTED,
            dynamic_note="Observe whether __globals__ attribute access is rejected or allowed.",
        ),
        PayloadCase(
            id="closure_cell",
            category="closure_cell",
            technique="Closure / cell introspection",
            description="Pull a captured object out of a closure cell.",
            source=(
                "def outer(secret):\n"
                "    def inner():\n"
                "        return secret\n"
                "    return inner\n"
                "leaked = outer(42).__closure__[0].cell_contents\n"
            ),
            reference=_REF_RP,
            provenance="Additional closure technique check written for this package; not counted as catalog-derived.",
            expected_static=True,
            expected_detectors=["closure_cell"],
            expected_restricted=RESTRICTED_COMPILE_REJECTED,
            dynamic_note="Observe whether closure attributes are reachable.",
        ),
        PayloadCase(
            id="builtins_subscript",
            category="builtins_recovery",
            technique="__builtins__ / built-ins recovery",
            description="Pull __import__ out of a recovered builtins mapping.",
            source="imp = __builtins__['__import__']\n",
            reference=_KAPLAN_EXAMPLE,
            provenance="Reduced os.__builtins__ import-recovery example to its mapping lookup; no import is invoked.",
            expected_static=True,
            expected_detectors=["builtins_recovery"],
            expected_restricted=RESTRICTED_COMPILE_REJECTED,
            dynamic_note="Observe whether the real builtins mapping is reachable.",
        ),
        PayloadCase(
            id="frame_getframe",
            category="frame_introspection",
            technique="Frame / execution-context introspection",
            description="Reach caller globals via sys._getframe.",
            source="import sys\nleaked = sys._getframe(0).f_globals\n",
            reference=_REF_RP,
            provenance="Additional frame technique check written for this package; not counted as catalog-derived.",
            expected_static=True,
            expected_detectors=["frame_introspection"],
            expected_restricted=RESTRICTED_COMPILE_REJECTED,
            dynamic_note="Observe whether frame access is permitted.",
        ),
        PayloadCase(
            id="generator_frame",
            category="frame_introspection",
            technique="Generator-frame introspection",
            description="Reach a generator's frame and its globals.",
            source="g = (x for x in [1])\nleaked = g.gi_frame.f_globals\n",
            reference=_PYJAIL_GADGETS + "builtins_dict.py",
            provenance="Reduced generator-frame traversal from builtins_dict__gi_builtins; stops at f_globals.",
            expected_static=True,
            expected_detectors=["frame_introspection"],
            expected_restricted=RESTRICTED_COMPILE_REJECTED,
            dynamic_note="gi_frame/f_globals are on RestrictedPython's forbidden-name list.",
        ),
        PayloadCase(
            id="format_string",
            category="format_string_traversal",
            technique="Format-string attribute traversal",
            description="Traverse dunders through a str.format template.",
            source='leaked = "{0.__class__.__init__.__globals__}".format(())\n',
            reference=_REF_RP,
            provenance="Additional format traversal check written for this package; not counted as catalog-derived.",
            expected_static=True,
            expected_detectors=["format_string_traversal"],
            expected_restricted=RESTRICTED_EXECUTION_BLOCKED,
            dynamic_note="RestrictedPython forbids str.format*() at runtime.",
        ),
        PayloadCase(
            id="import_name_call",
            category="builtins_recovery",
            technique="Direct __import__ call",
            description="Call the __import__ builtin directly.",
            source="os = __import__('os')\n",
            reference=_KAPLAN_EXAMPLE,
            provenance="Adapted the documented direct __import__ bypass; targets local standard-library os instead of evil_foo.",
            expected_static=True,
            expected_detectors=["dangerous_builtin_call"],
            expected_restricted=RESTRICTED_COMPILE_REJECTED,
            dynamic_note="'__import__' is an invalid variable name under RestrictedPython.",
        ),
        PayloadCase(
            id="getattr_dunder",
            category="dangerous_builtin_call",
            technique="Dunder getattr",
            description="Reach a dunder through a string-keyed getattr.",
            source="cls = getattr((), '__class__')\n",
            reference=_REF_RP,
            provenance="Additional dynamic-name check written for this package; not counted as catalog-derived.",
            expected_static=True,
            expected_detectors=["dangerous_builtin_call"],
            expected_restricted=RESTRICTED_EXECUTION_BLOCKED,
            dynamic_note="getattr is not provided by safe_builtins (NameError at runtime).",
        ),
        PayloadCase(
            id="plain_import_os",
            category="import_statement",
            technique="Plain import statement",
            description="A plain 'import os' followed by reading os.name.",
            source="import os\nvalue = os.name\n",
            reference=_REF_RP,
            provenance="trivial control; not an object-graph escape technique",
            expected_static=False,
            expected_detectors=[],
            expected_restricted=RESTRICTED_EXECUTION_BLOCKED,
            dynamic_note=(
                "Intentional static false negative: we do not flag plain imports as a "
                "'technique'. RestrictedPython blocks it at runtime (ImportError)."
            ),
        ),
        PayloadCase(
            id="benign_arithmetic",
            category="benign_control",
            technique="Benign arithmetic (control)",
            description="Ordinary safe code; must not be flagged or escape.",
            source="result = len(range(10)) + pow(2, 3)\n",
            reference=_REF_RP,
            provenance="benign control written for this package",
            expected_static=False,
            expected_detectors=[],
            expected_restricted=RESTRICTED_EXECUTION_COMPLETED,
            dynamic_note="Verifies the oracle does not report a false escape on safe code.",
        ),
        PayloadCase(
            id="benign_string_mentions_dunder",
            category="benign_control",
            technique="String mentioning dunders (control)",
            description="A string literal that merely names dangerous dunders.",
            source='note = "reminder: __subclasses__ and __globals__ are dangerous"\n',
            reference=_REF_RP,
            provenance="benign control written for this package",
            expected_static=False,
            expected_detectors=[],
            expected_restricted=RESTRICTED_EXECUTION_COMPLETED,
            dynamic_note=(
                "Demonstrates the AST advantage: a string that mentions dunders is an "
                "ast.Constant, not attribute access, so it is not flagged."
            ),
        ),
    ] + _catalog_cases()


def _catalog_cases() -> list[PayloadCase]:
    """Reduced, non-destructive probes mapped to inspected catalog gadgets.

    Source links and adaptations are stored in each case and listed in README.md.
    None of these probes invokes a shell or targets a host path.
    """
    definitions = [
        ("builtin_self", "builtins_recovery", "Builtin function __self__ recovery",
         "leaked = chr.__self__\n", "builtins_dict.py", "builtins_dict__self",
         False, []),
        ("wrap_close_builtins", "builtins_recovery", "Class initializer globals to builtins",
         "classes = ().__class__.__base__.__subclasses__()\n"
         "leaked = [c for c in classes if 'wrap_close' in str(c)][0].__init__.__globals__['__builtins__']\n",
         "builtins_dict.py", "builtins_dict__wrap_close", True,
         ["subclasses_traversal", "globals_access"]),
        ("sys_modules_builtins", "builtins_recovery", "sys.modules builtins import recovery",
         "import sys\nleaked = sys.modules['builtins'].__import__('sys')\n",
         _KAPLAN_EXAMPLE, "sys.modules['__builtin__'] example, updated to Python 3 builtins",
         True, ["builtins_recovery"]),
        ("os_builtins_import", "builtins_recovery", "Module builtins mapping import recovery",
         "import os\nleaked = os.__builtins__['__import__']('sys')\n",
         _KAPLAN_EXAMPLE, "os.__builtins__ example; harmless standard-library import target",
         True, ["builtins_recovery"]),
        ("builtin_importer", "subclasses_traversal", "BuiltinImporter class discovery",
         "classes = ().__class__.__base__.__subclasses__()\n"
         "leaked = [c for c in classes if 'BuiltinImporter' in str(c)][0].load_module('sys')\n",
         "import_builtin_module.py", "import_builtin_module__builtinimporter",
         True, ["subclasses_traversal"]),
        ("object_dict", "globals_access", "Object dictionary recovery",
         "leaked = (lambda: 0).__dict__\n", "get_obj_dict.py", "get_obj_dict__basic",
         False, []),
        ("generator_back_builtins", "frame_introspection", "Generator caller-frame builtins recovery",
         "g = (g.gi_frame.f_back for x in [1])\n"
         "leaked = [frame for frame in g][0].f_back.f_back.f_builtins\n",
         "builtins_dict.py", "builtins_dict__gi_builtins", True,
         ["frame_introspection"]),
    ]
    cases = []
    for pid, category, technique, source, path, gadget, flagged, detectors in definitions:
        cases.append(PayloadCase(
            id=pid, category=category, technique=technique,
            description=f"Reduced catalog capability probe: {gadget}.", source=source,
            reference=path if path.startswith("https://") else _PYJAIL_GADGETS + path,
            provenance=f"Adapted from {gadget}; supplied dependency steps inline; no shell or file target.",
            expected_static=flagged, expected_detectors=detectors,
            expected_restricted=RESTRICTED_COMPILE_REJECTED,
            dynamic_note="Restricted compilation rejects the introspection attributes before execution.",
        ))
    return cases


class Corpus:
    """A collection of :class:`PayloadCase` objects."""

    #: Keys required when a user supplies a custom payload via config.
    _REQUIRED = ("id", "source")

    def __init__(self, cases: Optional[list[PayloadCase]] = None) -> None:
        self._cases: list[PayloadCase] = list(cases) if cases else []
        self._index = {c.id: c for c in self._cases}
        if len(self._index) != len(self._cases):
            raise CorpusError("Duplicate payload id in corpus.")

    @classmethod
    def builtin(cls) -> "Corpus":
        return cls(_builtin_cases())

    def add_custom(self, definition: dict) -> PayloadCase:
        """Add a user-supplied payload. Validates and fills sensible defaults."""
        if not isinstance(definition, dict):
            raise CorpusError("Custom payload must be a dict.")
        for key in self._REQUIRED:
            if key not in definition:
                raise CorpusError(f"Custom payload missing required key '{key}'.")
        pid = definition["id"]
        if pid in self._index:
            raise CorpusError(f"Custom payload id '{pid}' duplicates an existing case.")
        case = PayloadCase(
            id=pid,
            category=definition.get("category", "custom"),
            technique=definition.get("technique", "Custom payload"),
            description=definition.get("description", ""),
            source=definition["source"],
            reference=definition.get("reference", "user-supplied"),
            provenance=definition.get("provenance", "user-supplied custom payload"),
            expected_static=bool(definition.get("expected_static", False)),
            expected_detectors=list(definition.get("expected_detectors", [])),
            expected_restricted=definition.get("expected_restricted", RESTRICTED_EXECUTION_COMPLETED),
            dynamic_note=definition.get("dynamic_note", ""),
        )
        self._cases.append(case)
        self._index[pid] = case
        return case

    def categories(self) -> list[str]:
        return sorted({c.category for c in self._cases})

    def filter_categories(self, enabled: Optional[list[str]]) -> "Corpus":
        """Return a new corpus containing only the enabled categories.

        ``enabled=None`` keeps everything.
        """
        if enabled is None:
            return Corpus(list(self._cases))
        allowed = set(enabled)
        return Corpus([c for c in self._cases if c.category in allowed])

    def ordered(self, seed: int) -> list[PayloadCase]:
        """Deterministically shuffle the cases using ``seed``."""
        rng = random.Random(seed)
        cases = list(self._cases)
        rng.shuffle(cases)
        return cases

    def get(self, payload_id: str) -> PayloadCase:
        return self._index[payload_id]

    def __iter__(self) -> Iterator[PayloadCase]:
        return iter(self._cases)

    def __len__(self) -> int:
        return len(self._cases)


def load_corpus(config=None) -> Corpus:
    """Build the built-in corpus and append any custom payloads from config."""
    from .config import Config

    cfg = Config.coerce(config)
    corpus = Corpus.builtin()
    for definition in cfg.custom_payloads:
        corpus.add_custom(definition)
    return corpus.filter_categories(cfg.enabled_categories)
