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
from .structure_generator import CtypesStructureGenerator
from .import_inference import ImportInferenceEngine

def apply_ctypes_enrichment(code: str) -> str:
    code = CtypesStructureGenerator.generate_all_missing(code)
    engine = ImportInferenceEngine(code)
    code   = engine.augment_code_with_missing_imports()
    for old_name, qualified in CTYPES_TYPE_MAP.items():
        if old_name in ('Structure', 'Union', 'Array', 'POINTER', 'cast',
                        'pointer', 'byref', 'sizeof', 'alignment', 'memmove',
                        'memset', 'addressof'):
            continue
        if old_name not in code:
            continue
        safe_old = re.escape(old_name)
        code = re.sub(
            r'(?<![.\w])' + safe_old + r'(?![.\w(])',
            qualified,
            code,
        )
    return code


