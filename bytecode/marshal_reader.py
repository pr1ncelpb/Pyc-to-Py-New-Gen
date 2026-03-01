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
from .pyc_reader import (
    PycCodeObject, _unmarshal_code, _wrap_code_object,
    _decode_linetable_310, _decode_linetable_311, _get_lineno_map, _repr_const,
)

class MarshalReader:

    FLAG_REF = 0x80

    def __init__(self, data: bytes, py_ver: Tuple[int, int], verbose: bool = False):
        self.data = data
        self.pos = 0
        self.py_ver = py_ver
        self.verbose = verbose
        self._refs: List[Any] = []

    def read(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise ValueError(
                f'Marshal tronqué: besoin de {n} bytes à pos {self.pos}, '
                f'disponible: {len(self.data) - self.pos}'
            )
        r = self.data[self.pos:self.pos + n]
        self.pos += n
        return r

    def read_byte(self) -> int:
        b = self.read(1)
        return b[0]

    def read_short(self) -> int:
        return struct.unpack_from('<H', self.read(2))[0]

    def read_long(self) -> int:
        return struct.unpack_from('<i', self.read(4))[0]

    def read_ulong(self) -> int:
        return struct.unpack_from('<I', self.read(4))[0]

    def read_long64(self) -> int:
        return struct.unpack_from('<q', self.read(8))[0]

    def _reserve_ref(self):

        idx = len(self._refs)
        self._refs.append(None)
        return idx

    def _fill_ref(self, idx: int, obj: Any) -> Any:

        if idx < len(self._refs):
            self._refs[idx] = obj
        return obj

    def load(self) -> Any:

        type_byte = self.read_byte()
        flag_ref = type_byte & self.FLAG_REF
        type_code = type_byte & ~self.FLAG_REF

        ref_idx = self._reserve_ref() if flag_ref else None

        obj = self._load_typed(type_code)

        if ref_idx is not None:
            self._fill_ref(ref_idx, obj)

        return obj

    def _load_typed(self, t: int) -> Any:

        if t == 0x30:
            return None
        if t == 0x4e:
            return None
        if t == 0x54:
            return True
        if t == 0x46:
            return False
        if t == 0x53:
            return StopIteration
        if t == 0x2e:
            return Ellipsis

        if t == 0x69:
            return self.read_long()

        if t == 0x49:
            return self.read_long64()

        if t == 0x6c:

            n = self.read_long()
            sign = 1 if n > 0 else -1
            n = abs(n)
            digits = []
            for _ in range(n):
                digits.append(self.read_short())
            result = 0
            for d in reversed(digits):
                result = result * 32768 + d
            return result * sign

        if t == 0x66:
            n = self.read_byte()
            s = self.read(n).decode('ascii')
            return float(s)

        if t == 0x67:
            data = self.read(8)
            return struct.unpack_from('<d', data)[0]

        if t == 0x64:
            data = self.read(8)
            return struct.unpack_from('<d', data)[0]

        if t == 0x78:
            n = self.read_byte()
            re_s = self.read(n).decode('ascii')
            n2 = self.read_byte()
            im_s = self.read(n2).decode('ascii')
            return complex(float(re_s), float(im_s))

        if t == 0x79:
            re_v = struct.unpack_from('<d', self.read(8))[0]
            im_v = struct.unpack_from('<d', self.read(8))[0]
            return complex(re_v, im_v)

        if t == 0x73:
            n = self.read_ulong()
            return self.read(n)

        if t == 0x62:
            n = self.read_ulong()
            return bytearray(self.read(n))

        if t == 0x75:
            n = self.read_ulong()
            raw = self.read(n)
            return raw.decode('utf-8', errors='replace')

        if t == 0x74:
            n = self.read_ulong()
            raw = self.read(n)
            return raw.decode('utf-8', errors='replace')

        if t == 0x61:
            n = self.read_ulong()
            raw = self.read(n)
            return raw.decode('ascii', errors='replace')

        if t == 0x41:
            n = self.read_ulong()
            raw = self.read(n)
            return raw.decode('ascii', errors='replace')

        if t == 0x7a:
            n = self.read_byte()
            raw = self.read(n)
            return raw.decode('ascii', errors='replace')

        if t == 0x5a:
            n = self.read_byte()
            raw = self.read(n)
            return raw.decode('ascii', errors='replace')

        if t == 0x28:
            n = self.read_byte()
            items = [self.load() for _ in range(n)]
            return tuple(items)

        if t == 0x29:
            n = self.read_byte()
            items = [self.load() for _ in range(n)]
            return tuple(items)

        if t == 0x3c:

            n = self.read_ulong()
            items = [self.load() for _ in range(n)]
            return tuple(items)

        if t == 0x5b:
            n = self.read_ulong()
            items = [self.load() for _ in range(n)]
            return items

        if t == 0x7b:
            d = {}
            while True:
                k = self.load()
                if k is None:
                    break
                v = self.load()
                d[k] = v
            return d

        if t == 0x3e:
            n = self.read_ulong()
            items = frozenset(self.load() for _ in range(n))
            return items

        if t == 0x3f:
            n = self.read_ulong()
            items = set(self.load() for _ in range(n))
            return items

        if t == 0x72:
            idx = self.read_ulong()
            if 0 <= idx < len(self._refs):
                return self._refs[idx]
            return None

        if t == 0x52:
            idx = self.read_ulong()
            if 0 <= idx < len(self._refs):
                return self._refs[idx]
            return None

        if t == 0x63:
            return self._load_code_object()

        char = chr(t) if 32 <= t < 127 else f'\\x{t:02x}'
        raise ValueError(
            f'Type marshal inconnu: {char!r} (0x{t:02x}) à pos {self.pos - 1}\n'
            f'  → Ce fichier .pyc semble utiliser une version Python non supportée\n'
            f'  → ou le fichier est corrompu.'
        )

    def _load_code_object(self) -> 'PycCodeObject':

        pco = PycCodeObject()
        pco._py_ver = self.py_ver

        pco.co_argcount        = self.read_ulong()
        pco.co_posonlyargcount = self.read_ulong()
        pco.co_kwonlyargcount  = self.read_ulong()

        if self.py_ver <= (3, 10):
            pco.co_nlocals = self.read_ulong()

        pco.co_stacksize = self.read_ulong()
        pco.co_flags     = self.read_ulong()

        raw_code = self.load()
        pco.co_code = bytes(raw_code) if raw_code else b''

        raw_consts = self.load()
        pco.co_consts = tuple(raw_consts) if raw_consts else ()

        raw_names = self.load()
        pco.co_names = tuple(raw_names) if raw_names else ()

        if self.py_ver >= (3, 11):

            localsplusnames = self.load()
            localspluskinds = self.load()
            pco.co_varnames = tuple(localsplusnames) if localsplusnames else ()

            varnames = []
            cellvars = []
            freevars = []
            if localsplusnames and localspluskinds:
                kinds = bytes(localspluskinds)
                for i, name in enumerate(localsplusnames):
                    if i < len(kinds):
                        kind = kinds[i]
                        CO_FAST_LOCAL = 0x20
                        CO_FAST_CELL  = 0x40
                        CO_FAST_FREE  = 0x80
                        if kind & CO_FAST_FREE:
                            freevars.append(name)
                        elif kind & CO_FAST_CELL:
                            cellvars.append(name)
                        else:
                            varnames.append(name)
                    else:
                        varnames.append(name)
            pco.co_varnames = tuple(varnames)
            pco.co_cellvars = tuple(cellvars)
            pco.co_freevars = tuple(freevars)
        else:
            raw_varnames = self.load()
            pco.co_varnames = tuple(raw_varnames) if raw_varnames else ()
            raw_freevars = self.load()
            pco.co_freevars = tuple(raw_freevars) if raw_freevars else ()
            raw_cellvars = self.load()
            pco.co_cellvars = tuple(raw_cellvars) if raw_cellvars else ()

        pco.co_filename = self.load() or '<unknown>'

        pco.co_name = self.load() or '<unknown>'

        if self.py_ver >= (3, 11):
            pco.co_qualname = self.load() or pco.co_name

        pco.co_firstlineno = self.read_ulong()

        if self.py_ver >= (3, 11):

            raw_lt = self.load()
            pco.co_linetable = bytes(raw_lt) if raw_lt else b''
            pco.co_lnotab = b''
        else:
            raw_lnotab = self.load()
            pco.co_lnotab = bytes(raw_lnotab) if raw_lnotab else b''
            pco.co_linetable = None

        if self.py_ver >= (3, 11):
            raw_exc = self.load()
            pco.co_exceptiontable = bytes(raw_exc) if raw_exc else b''

        if self.py_ver >= (3, 11):
            pco.co_nlocals = len(pco.co_varnames)
        elif pco.co_nlocals is None:
            pco.co_nlocals = 0

        return pco

