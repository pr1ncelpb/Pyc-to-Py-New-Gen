import re
import sys
import ast
import base64
import marshal
import struct
import io as _io
import textwrap
import warnings
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Tuple, Any, Set

warnings.filterwarnings('ignore', category=SyntaxWarning)
from maps import (
    CTYPES_TYPE_MAP, CTYPES_LIBRARY, ALL_CTYPES_FLAT,
    get_ctypes_qualified, is_ctypes_type, list_ctypes_by_bits,
    get_ctypes_category, get_ctypes_description, is_windows_only_ctypes,
    resolve_ctypes_pointer_target, build_ctypes_fields_str, normalize_ctypes_name,
    KNOWN_MODULES, BASE64_MIN_LEN,
    BINARY_OPS, INPLACE_OPS, INPLACE_MAP, COMPARE_OPS,
    SKIP_OPCODES, SKIP_OPCODES_SET, TIER2_OPCODE_NORMALIZE,
)
from engine import BytecodeTranslator, HighLevelReconstructor
from postprocess import PostProcessor, PostProcessorV5, reorder_definitions, SemanticFixer
from bytecode import validate_syntax, _pyc_to_dis_string, _get_pyc_python_version
from ctypes_tools import apply_ctypes_enrichment, CtypesStructureGenerator, ImportInferenceEngine

def _is_python_source(source: str) -> bool:
    """
    Retourne True si `source` est déjà du code Python valide (ou presque),
    plutôt qu'un dump de bytecode `dis`.
    Critères :
      - Contient des instructions dis typiques (LOAD_FAST, STORE_NAME, etc.) → False
      - Parseable par ast.parse → True
      - Sinon, heuristique sur la présence de constructions Python de haut-niveau
    """
    dis_markers = ('LOAD_FAST', 'LOAD_CONST', 'STORE_NAME', 'STORE_FAST',
                   'CALL_FUNCTION', 'RETURN_VALUE', 'Disassembly of')
    first_5k = source[:5000]
    dis_hits = sum(1 for m in dis_markers if m in first_5k)
    if dis_hits >= 3:
        return False

    try:
        import ast as _ast
        _ast.parse(source)
        return True
    except SyntaxError:
        pass

    python_hits = sum(1 for pat in (r'^\s*def ', r'^\s*class ', r'^import ', r'^from ')
                      if re.search(pat, source, re.MULTILINE))
    return python_hits >= 2


def translate_file(input_path: str, output_path: str, verbose: bool = False) -> str:

    if input_path.lower().endswith('.pyc'):
        if verbose:
            print(f'[INFO] Lecture: {input_path}', file=sys.stderr)
        try:
            source = _pyc_to_dis_string(input_path, verbose)
        except Exception as e:
            print(f'[ERROR] Impossible de lire le .pyc: {e}', file=sys.stderr)
            sys.exit(1)

        if verbose:
            dump_path = output_path + '.dis_dump.txt'
            try:
                with open(dump_path, 'w', encoding='utf-8') as f:
                    f.write(source)
                print(f'[INFO] Dump dis → {dump_path}', file=sys.stderr)
            except Exception:
                pass
    else:
        with open(input_path, 'r', encoding='utf-8', errors='replace') as f:
            source = f.read()

    is_python_source = _is_python_source(source)
    if is_python_source:
        if verbose:
            print(f'[INFO] Fichier reconnu comme code source Python — passage direct au SemanticFixer', file=sys.stderr)
        code = source
    else:
        reconstructor = HighLevelReconstructor(source, verbose=verbose)
        code = reconstructor.reconstruct()

        pp = PostProcessorV5(code)
        code = pp.process()

        ok, err = validate_syntax(code)
        if not ok:
            if verbose:
                print(f'[WARN] Syntaxe 1ère passe: {err}', file=sys.stderr)
            pp2 = PostProcessorV5(code)
            lines = pp2._iterative_syntax_fix(code.splitlines())
            code = '\n'.join(lines)
            ok2, err2 = validate_syntax(code)
            if verbose:
                status = '✓ corrigée' if ok2 else f'résiduelle: {err2}'
                print(f'[INFO] Syntaxe 2ème passe: {status}', file=sys.stderr)

    sf = SemanticFixer(code)
    code = sf.fix()

    ok3, err3 = validate_syntax(code)
    if not ok3 and verbose:
        print(f'[INFO] Syntaxe après SemanticFixer: {err3}', file=sys.stderr)

    if not is_python_source:
        code = reorder_definitions(code)

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(code)

    return code


