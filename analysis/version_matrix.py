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

class PythonVersionCompatibilityMatrix:

    SUPPORTED_VERSIONS: List[Tuple[int, int]] = [
        (3, 10), (3, 11), (3, 12), (3, 13), (3, 14),
    ]

    VERSION_FEATURES: Dict[Tuple[int, int], Dict[str, Any]] = {
        (3, 10): {
            'match_statement':      True,
            'parenthesized_with':   False,
            'exception_groups':     False,
            'variadic_generics':    False,
            'type_aliases':         False,
            'free_threaded':        False,
            'f_string_nesting':     False,
            'pattern_matching':     True,
            'walrus_operator':      True,
            'positional_only_args': True,
            'opcode_PUSH_NULL':     False,
            'opcode_RESUME':        False,
            'opcode_BINARY_OP':     False,
            'opcode_COPY':          False,
            'opcode_CALL':          False,
            'opcode_LOAD_FAST_BORROW': False,
            'cache_entries':        False,
            'exception_table':      False,
            'co_qualname':          False,
            'co_linetable':         False,
            'magic_range':          list(range(3430, 3436)),
        },
        (3, 11): {
            'match_statement':      True,
            'parenthesized_with':   True,
            'exception_groups':     False,
            'variadic_generics':    False,
            'type_aliases':         False,
            'free_threaded':        False,
            'f_string_nesting':     False,
            'pattern_matching':     True,
            'walrus_operator':      True,
            'positional_only_args': True,
            'opcode_PUSH_NULL':     True,
            'opcode_RESUME':        True,
            'opcode_BINARY_OP':     True,
            'opcode_COPY':          True,
            'opcode_CALL':          True,
            'opcode_LOAD_FAST_BORROW': False,
            'cache_entries':        True,
            'exception_table':      True,
            'co_qualname':          True,
            'co_linetable':         True,
            'magic_range':          list(range(3495, 3512)),
        },
        (3, 12): {
            'match_statement':      True,
            'parenthesized_with':   True,
            'exception_groups':     True,
            'variadic_generics':    True,
            'type_aliases':         True,
            'free_threaded':        False,
            'f_string_nesting':     True,
            'pattern_matching':     True,
            'walrus_operator':      True,
            'positional_only_args': True,
            'opcode_PUSH_NULL':     True,
            'opcode_RESUME':        True,
            'opcode_BINARY_OP':     True,
            'opcode_COPY':          True,
            'opcode_CALL':          True,
            'opcode_LOAD_FAST_BORROW': False,
            'cache_entries':        True,
            'exception_table':      True,
            'co_qualname':          True,
            'co_linetable':         True,
            'magic_range':          list(range(3531, 3540)),
        },
        (3, 13): {
            'match_statement':      True,
            'parenthesized_with':   True,
            'exception_groups':     True,
            'variadic_generics':    True,
            'type_aliases':         True,
            'free_threaded':        True,
            'f_string_nesting':     True,
            'pattern_matching':     True,
            'walrus_operator':      True,
            'positional_only_args': True,
            'opcode_PUSH_NULL':     True,
            'opcode_RESUME':        True,
            'opcode_BINARY_OP':     True,
            'opcode_COPY':          True,
            'opcode_CALL':          True,
            'opcode_LOAD_FAST_BORROW': False,
            'cache_entries':        True,
            'exception_table':      True,
            'co_qualname':          True,
            'co_linetable':         True,
            'magic_range':          list(range(3570, 3577)),
        },
        (3, 14): {
            'match_statement':      True,
            'parenthesized_with':   True,
            'exception_groups':     True,
            'variadic_generics':    True,
            'type_aliases':         True,
            'free_threaded':        True,
            'f_string_nesting':     True,
            'pattern_matching':     True,
            'walrus_operator':      True,
            'positional_only_args': True,
            'opcode_PUSH_NULL':     True,
            'opcode_RESUME':        True,
            'opcode_BINARY_OP':     True,
            'opcode_COPY':          True,
            'opcode_CALL':          True,
            'opcode_LOAD_FAST_BORROW': True,
            'cache_entries':        True,
            'exception_table':      True,
            'co_qualname':          True,
            'co_linetable':         True,
            'magic_range':          list(range(3600, 3606)),
        },
    }

    @classmethod
    def get_features(cls, version: Tuple[int, int]) -> Dict[str, Any]:
        return cls.VERSION_FEATURES.get(version, {})

    @classmethod
    def supports_feature(cls, version: Tuple[int, int], feature: str) -> bool:
        features = cls.get_features(version)
        return bool(features.get(feature, False))

    @classmethod
    def minimum_version_for_feature(cls, feature: str) -> Optional[Tuple[int, int]]:
        for ver in cls.SUPPORTED_VERSIONS:
            if cls.supports_feature(ver, feature):
                return ver
        return None

    @classmethod
    def features_diff(cls, v1: Tuple[int, int], v2: Tuple[int, int]) -> Dict[str, Tuple[bool, bool]]:
        f1 = cls.get_features(v1)
        f2 = cls.get_features(v2)
        all_keys = set(f1) | set(f2)
        diff = {}
        for k in sorted(all_keys):
            val1 = bool(f1.get(k, False))
            val2 = bool(f2.get(k, False))
            if val1 != val2:
                diff[k] = (val1, val2)
        return diff

    @classmethod
    def get_magic_versions_table(cls) -> Dict[int, Tuple[int, int]]:
        table = {}
        for ver, features in cls.VERSION_FEATURES.items():
            for magic in features.get('magic_range', []):
                table[magic] = ver
        return table

    @classmethod
    def detect_version_from_bytecode_hints(cls, bytecode_text: str) -> Optional[Tuple[int, int]]:
        hints: Dict[Tuple[int, int], int] = {}
        for ver in cls.SUPPORTED_VERSIONS:
            hints[ver] = 0
        feature_hints = [
            ('LOAD_FAST_BORROW', (3, 14), 5),
            ('CALL_KW',          (3, 14), 3),
            ('LOAD_SPECIAL',     (3, 14), 3),
            ('STORE_FAST_STORE_FAST', (3, 14), 3),
            ('LOAD_LOCALS',      (3, 13), 2),
            ('LOAD_ZERO',        (3, 12), 2),
            ('LOAD_SMALL_INT',   (3, 12), 2),
            ('COPY_FREE_VARS',   (3, 11), 2),
            ('PUSH_EXC_INFO',    (3, 11), 2),
            ('CHECK_EXC_MATCH',  (3, 11), 2),
            ('RESUME',           (3, 11), 1),
            ('PUSH_NULL',        (3, 11), 1),
        ]
        for opcode, min_ver, weight in feature_hints:
            if opcode in bytecode_text:
                for ver in cls.SUPPORTED_VERSIONS:
                    if ver >= min_ver:
                        hints[ver] += weight
        if not any(hints.values()):
            return None
        return max(hints, key=lambda v: hints[v])

    @classmethod
    def compatibility_report(cls, version: Tuple[int, int]) -> str:
        features = cls.get_features(version)
        if not features:
            return f'Version {version[0]}.{version[1]} non reconnue.'
        lines = [f'Compatibilité Python {version[0]}.{version[1]}:']
        for feature, value in sorted(features.items()):
            if feature == 'magic_range':
                continue
            icon = 'OUI' if value else 'NON'
            lines.append(f'  {feature:<35}: {icon}')
        return '\n'.join(lines)


