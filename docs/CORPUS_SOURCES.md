# Corpus source map

Reviewed on 2026-10-18 against the two catalogs named by Task 6.
Probes are reduced capability tests, rather than claims of working exploits.
The reductions keep the relevant Python access step and omit shell execution,
external targets, and dependencies that are unnecessary to test rejection.

The corpus has **19 cases**: **12 catalog-derived probes**, 5 additional
technique/control probes, and 2 benign controls. Each source string is unique.
The metadata in `corpus.py` contains the source URL and adaptation for each case.

| Catalog-derived case | Inspected source | Adaptation |
|---|---|---|
| `subclasses_popen` | [pyjailbreaker README example](https://github.com/jailctf/pyjailbreaker#example) | Keep subclass enumeration; use `__bases__[0]` in place of `__base__`; omit shell steps. The historical ID names a capability target, not an executed Popen call. |
| `func_globals` | [sys.py: sys__wrap_close](https://github.com/jailctf/pyjailbreaker/blob/main/jailbreak/gadgets/python/sys.py) | Isolate function-global access using a local lambda rather than locating a class initializer. |
| `builtins_subscript` | [Kaplan example.py](https://github.com/moshekaplan/python_sandbox_escapes/blob/master/example.py) | Reduce the `os.__builtins__` recovery example to the mapping lookup, without importing. |
| `generator_frame` | [builtins_dict.py: builtins_dict__gi_builtins](https://github.com/jailctf/pyjailbreaker/blob/main/jailbreak/gadgets/python/builtins_dict.py) | Reduce generator-frame traversal to reading its globals. |
| `import_name_call` | [Kaplan example.py](https://github.com/moshekaplan/python_sandbox_escapes/blob/master/example.py) | Keep the direct-import bypass; use local standard-library `os` instead of the example's placeholder module. |
| `builtin_self` | [builtins_dict.py: builtins_dict__self](https://github.com/jailctf/pyjailbreaker/blob/main/jailbreak/gadgets/python/builtins_dict.py) | Probe `chr.__self__`; it is blocked dynamically and currently unflagged statically. |
| `wrap_close_builtins` | [builtins_dict.py: builtins_dict__wrap_close](https://github.com/jailctf/pyjailbreaker/blob/main/jailbreak/gadgets/python/builtins_dict.py) | Inline the class-list dependency and stop at the recovered builtins mapping. |
| `sys_modules_builtins` | [Kaplan example.py](https://github.com/moshekaplan/python_sandbox_escapes/blob/master/example.py) | Update Python 2 `__builtin__` to Python 3 `builtins`; target the local `sys` module. |
| `os_builtins_import` | [Kaplan example.py](https://github.com/moshekaplan/python_sandbox_escapes/blob/master/example.py) | Retain the module-builtins import chain; use the local `sys` module. |
| `builtin_importer` | [import_builtin_module.py: import_builtin_module__builtinimporter](https://github.com/jailctf/pyjailbreaker/blob/main/jailbreak/gadgets/python/import_builtin_module.py) | Inline subclass enumeration and request the local `sys` module; no command execution. |
| `object_dict` | [get_obj_dict.py: get_obj_dict__basic](https://github.com/jailctf/pyjailbreaker/blob/main/jailbreak/gadgets/python/get_obj_dict.py) | Apply the object-dictionary access step to a local function; currently unflagged statically. |
| `generator_back_builtins` | [builtins_dict.py: builtins_dict__gi_builtins](https://github.com/jailctf/pyjailbreaker/blob/main/jailbreak/gadgets/python/builtins_dict.py) | Retain caller-frame traversal and builtins access; assign the recovered value instead of returning it from a gadget. |

`closure_cell`, `frame_getframe`, `format_string`, `getattr_dunder`, and
`plain_import_os` are additional checks written for this package. Their metadata
does not claim derivation from a catalog. The two benign cases check arithmetic
and a string merely mentioning dunder names.

The corpus spans several access steps within related chains. Twelve probes do
not mean twelve distinct vulnerability classes. The detector suite separately
tests seven named technique classes with positive and negative examples.

The two unflagged catalog access steps are documented static coverage limits;
they do not escape RestrictedPython in the tested configuration. The dynamic
report preserves that distinction rather than changing expectations to claim
the static analyzer detects every possible technique.
