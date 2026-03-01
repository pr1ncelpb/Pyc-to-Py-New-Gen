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
from .opcode_tables import (
    _get_opcode_table, _MAGIC_TO_VERSION, _HAVE_ARGUMENT, _CACHE_COUNTS,
    _BINARY_OP_NAMES, _cmp_op_name,
)

class PycCodeObject:

    __slots__ = [
        'co_argcount', 'co_posonlyargcount', 'co_kwonlyargcount',
        'co_nlocals', 'co_stacksize', 'co_flags',
        'co_code', 'co_consts', 'co_names', 'co_varnames',
        'co_freevars', 'co_cellvars',
        'co_filename', 'co_name', 'co_qualname',
        'co_firstlineno', 'co_lnotab', 'co_linetable',
        'co_exceptiontable',
        '_py_ver',
    ]

    def __init__(self):
        for s in self.__slots__:
            object.__setattr__(self, s, None)

def _unmarshal_code(data: bytes, py_ver: Tuple[int,int]) -> 'PycCodeObject':

    obj = marshal.loads(data)
    return _wrap_code_object(obj, py_ver)

def _wrap_code_object(co, py_ver: Tuple[int,int]) -> PycCodeObject:

    pco = PycCodeObject()
    pco._py_ver = py_ver
    pco.co_argcount = getattr(co, 'co_argcount', 0) or 0
    pco.co_posonlyargcount = getattr(co, 'co_posonlyargcount', 0) or 0
    pco.co_kwonlyargcount = getattr(co, 'co_kwonlyargcount', 0) or 0
    pco.co_nlocals = getattr(co, 'co_nlocals', 0) or 0
    pco.co_stacksize = getattr(co, 'co_stacksize', 0) or 0
    pco.co_flags = getattr(co, 'co_flags', 0) or 0

    raw = getattr(co, 'co_code', None) or getattr(co, '_co_code', None)
    if raw is None:

        try:
            raw = bytes(co.co_code)
        except Exception:
            raw = b''
    pco.co_code = bytes(raw) if raw else b''
    pco.co_consts = tuple(co.co_consts) if co.co_consts else ()
    pco.co_names = tuple(co.co_names) if co.co_names else ()
    pco.co_varnames = tuple(co.co_varnames) if co.co_varnames else ()
    pco.co_freevars = tuple(co.co_freevars) if co.co_freevars else ()
    pco.co_cellvars = tuple(co.co_cellvars) if co.co_cellvars else ()
    pco.co_filename = getattr(co, 'co_filename', '<unknown>') or '<unknown>'
    pco.co_name = getattr(co, 'co_name', '<module>') or '<module>'
    pco.co_qualname = getattr(co, 'co_qualname', pco.co_name) or pco.co_name
    pco.co_firstlineno = getattr(co, 'co_firstlineno', 1) or 1
    pco.co_lnotab = getattr(co, 'co_lnotab', b'') or b''
    pco.co_linetable = getattr(co, 'co_linetable', None)
    pco.co_exceptiontable = getattr(co, 'co_exceptiontable', b'') or b''
    return pco

def _decode_linetable_310(lnotab: bytes, firstlineno: int, code_len: int) -> Dict[int, int]:

    lineno_map: Dict[int, int] = {}
    lineno = firstlineno
    offset = 0
    lineno_map[0] = lineno
    i = 0
    while i + 1 < len(lnotab):
        d_offset = lnotab[i]
        d_lineno = lnotab[i + 1]
        if d_lineno >= 128:
            d_lineno -= 256
        i += 2
        if d_offset == 0:
            lineno += d_lineno
            continue
        offset += d_offset
        lineno += d_lineno
        lineno_map[offset] = lineno
    return lineno_map

def _decode_linetable_311(linetable: bytes, firstlineno: int) -> Dict[int, int]:

    lineno_map: Dict[int, int] = {}
    lineno = firstlineno
    offset = 0
    i = 0
    while i < len(linetable):
        entry = linetable[i]
        i += 1
        code = (entry >> 3) & 0xF
        length = (entry & 0x7) + 1

        if code == 15:
            offset += length * 2
            continue
        elif code == 14:
            if i < len(linetable):
                i += 1
            offset += length * 2
            continue
        elif code < 10:
            lineno += code
        elif code < 14:
            if i + 1 < len(linetable):
                extra = linetable[i] | (linetable[i+1] << 8)
                i += 2
                if code == 13:
                    lineno += extra
                elif code == 12:
                    lineno -= extra
                elif code == 11:
                    lineno += (extra + 256)
                elif code == 10:
                    lineno -= (extra + 256)

        for j in range(length):
            lineno_map[offset + j * 2] = lineno
        offset += length * 2

    return lineno_map

def _get_lineno_map(co: PycCodeObject) -> Dict[int, int]:

    py_ver = co._py_ver or (3, 12)
    try:
        if py_ver <= (3, 10):
            return _decode_linetable_310(co.co_lnotab or b'', co.co_firstlineno or 1, len(co.co_code))
        else:
            lt = co.co_linetable or co.co_lnotab or b''
            return _decode_linetable_311(bytes(lt), co.co_firstlineno or 1)
    except Exception:
        return {0: co.co_firstlineno or 1}

def _repr_const(val: Any) -> str:

    if val is None:
        return 'None'
    if isinstance(val, bool):
        return str(val)
    if isinstance(val, int):
        return str(val)
    if isinstance(val, float):
        return repr(val)
    if isinstance(val, complex):
        return repr(val)
    if isinstance(val, str):
        return repr(val)
    if isinstance(val, bytes):
        return repr(val)
    if isinstance(val, tuple):
        inner = ', '.join(_repr_const(v) for v in val)
        return f'({inner},)' if len(val) == 1 else f'({inner})'
    if isinstance(val, frozenset):
        inner = ', '.join(_repr_const(v) for v in sorted(val, key=str))
        return '{' + inner + '}'
    if hasattr(val, 'co_name'):

        return f'<code object {val.co_name} at {hex(id(val))}>'
    return repr(val)

