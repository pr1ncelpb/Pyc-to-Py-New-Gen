# 📦 Python PYC to PY Converter

A powerful Python reverse-engineering tool that reconstructs `.py` source code from `.pyc` files or disassembly dumps. It features a smart cross-version engine that automatically adapts to the target bytecode version.

---

### 📂 Usage

python main.py <input.pyc> <output.py>


## 🎯 DIRECTORY STRUCTURE:

config/
   └── __init__.py                 (Main configuration)

dictionaries/
   ├── __init__.py                 (Dictionary compiler)
   ├── ctypes_primitives.py        (Primitive types)
   ├── ctypes_pointers.py          (Pointer types)
   ├── ctypes_structures.py        (Structures & unions)
   ├── ctypes_windows.py           (Windows types)
   ├── ctypes_loaders.py           (DLL loaders)
   └── ctypes_utilities.py         (Utility functions)

parsers/
   ├── __init__.py                 (File orchestrator)
   ├── pyc_parser.py               (PyC file parser)
   └── source_parser.py            (Source file parser)

generators/
   ├── __init__.py
   ├── code_builder.py             (Code builder)
   ├── syntax_validator.py         (Syntax validator)
   └── bytecode_decompiler.py      (Bytecode decompiler)

enrichers/
   ├── __init__.py
   ├── ctypes_enricher.py          (Ctypes enricher)
   └── import_inferencer.py        (Import inferencer)

analyzers/
   ├── __init__.py
   ├── quality_checker.py          (Quality checker)
   └── compatibility_checker.py    (Compatibility checker)

utilities/
   └── __init__.py                 (Utility functions)

main.py                            (Main entry point)
README.md                          (Documentation)
