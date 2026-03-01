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
from .post_processor import PostProcessor

class PostProcessorV5(PostProcessor):

    def process(self) -> str:
        lines = self.code.splitlines()

        lines = self._v5_restore_syntax_fix(lines)
        lines = self._v5_deep_clean(lines)
        lines = self._v5_fix_ctypes_struct_vars(lines)
        lines = self._v5_remove_if_pass_artifacts(lines)
        lines = self._clean_artifacts(lines)
        lines = self._remove_redundant_assignments_pp(lines)
        lines = self._fix_try_blocks(lines)
        lines = self._fix_except_ordering(lines)
        lines = self._fix_imports(lines)
        lines = self._fix_for_loops(lines)
        lines = self._fix_invalid_expressions(lines)
        lines = self._fix_trailing_newlines(lines)
        lines = self._fix_return_none(lines)
        lines = self._fix_broken_expressions(lines)
        lines = self._fix_orphaned_indentation(lines)
        lines = self._fix_empty_bodies(lines)
        lines = self._fix_deep_nesting(lines)
        lines = self._iterative_syntax_fix(lines)
        lines = self._v5_final_polish(lines)
        return '\n'.join(lines)

    def _v5_fix_ctypes_struct_vars(self, lines: List[str]) -> List[str]:

        out = []
        in_ctypes_class = False
        ctypes_indent = 0
        CTYPES_BASES_RE = re.compile(r'class\s+\w+\s*\((?:ctypes\.)?(Structure|Union|LittleEndianStructure|BigEndianStructure)\s*\)')

        for line in lines:
            stripped = line.strip()
            if not stripped:
                out.append(line)
                continue
            ind = line[:len(line) - len(stripped)]
            cur_indent = len(ind)

            m_cls = CTYPES_BASES_RE.match(stripped)
            if m_cls:
                in_ctypes_class = True
                ctypes_indent = cur_indent
                out.append(line)
                continue

            if in_ctypes_class and cur_indent <= ctypes_indent and stripped and not stripped.startswith('#'):
                if not stripped.startswith('def ') and not stripped.startswith('class '):
                    in_ctypes_class = False

            if in_ctypes_class and cur_indent > ctypes_indent:
                m1 = re.match(r'^_var_1\s*=\s*(.+)$', stripped)
                if m1:
                    out.append(f'{ind}_type_ = {m1.group(1)}')
                    continue
                m2 = re.match(r'^_var_2\s*=\s*(.+)$', stripped)
                if m2:
                    out.append(f'{ind}_fields_ = {m2.group(1)}')
                    continue
                m3 = re.match(r'^_var_(\d+)\s*=\s*(.+)$', stripped)
                if m3 and int(m3.group(1)) > 2:
                    out.append(f'{ind}_anonymous_ = {m3.group(2)}')
                    continue

            out.append(line)
        return out

    def _v5_remove_if_pass_artifacts(self, lines: List[str]) -> List[str]:

        out = []
        i = 0
        while i < len(lines):
            line = lines[i]
            stripped = line.strip()
            ind = line[:len(line) - len(stripped)] if stripped else ''

            if re.match(r'^if\s+.+:\s*$', stripped):
                body_lines = []
                j = i + 1
                while j < len(lines) and (not lines[j].strip() or
                      (len(lines[j]) - len(lines[j].lstrip())) > len(ind)):
                    body_lines.append(lines[j].strip())
                    j += 1
                real_body = [b for b in body_lines if b and b != 'pass']
                if not real_body:
                    i = j
                    continue

            m_try_raise = None
            if stripped == 'try:' and i + 1 < len(lines):
                next_s = lines[i+1].strip()
                if next_s == 'raise' and i + 2 < len(lines):
                    after = lines[i+2].strip()
                    if re.match(r'^except.*:\s*$', after) and i + 3 < len(lines):
                        exc_body = lines[i+3].strip()
                        if exc_body == 'pass':
                            i += 4
                            continue

            out.append(line)
            i += 1
        return out

    def _v5_restore_syntax_fix(self, lines: List[str]) -> List[str]:

        out = []
        i = 0
        while i < len(lines):
            line = lines[i]
            stripped = line.strip()

            if not stripped.startswith('# SYNTAX_FIX:'):
                out.append(line)
                i += 1
                continue

            ind = line[:len(line) - len(stripped)]
            content = stripped[len('# SYNTAX_FIX:'):].strip()

            if content in ('pass', 'continue', 'break', 'raise'):

                prev_nonblank = ''
                for prev in reversed(out):
                    if prev.strip():
                        prev_nonblank = prev.strip()
                        break

                if prev_nonblank.startswith('# TODO') or prev_nonblank.startswith('# SYNTAX_FIX'):
                    i += 1
                    continue
                out.append(f'{ind}{content}')
                i += 1
                continue

            if re.match(r'^(except|finally|else)\b.*:\s*$', content):

                prev_lines = [l for l in reversed(out) if l.strip()]
                is_dup = False
                for prev in prev_lines[:5]:
                    ps = prev.strip()
                    if re.match(r'^(except|finally)\b', ps):
                        is_dup = True
                        break
                    if not ps.startswith('pass') and not ps.startswith('#'):
                        break
                if is_dup:
                    i += 1
                    continue
                out.append(f'{ind}{content}')
                i += 1
                continue

            m_class = re.match(r'^class\s+(\w+)\s*(\([^)]*\))?\s*:$', content)
            if m_class:
                out.append(f'{ind}{content}')

                i += 1
                continue

            m_fields = re.match(r'^=\s*(\[.+\])\s*$', content)
            if m_fields:
                fields_val = m_fields.group(1)
                out.append(f'{ind}_fields_ = {fields_val}')
                i += 1
                continue

            m_num = re.match(r'^=\s*\d+\s*$', content)
            if m_num:
                i += 1
                continue

            m_sig = re.match(r'^=\s*pyqtSignal\s*\(', content)
            if m_sig:

                out.append(f'{ind}{content}')
                i += 1
                continue

            m_assign = re.match(r'^([A-Za-z_]\w*(?:\.\w+)*)\s*=\s*(.+)$', content)
            if m_assign:
                out.append(f'{ind}{content}')
                i += 1
                continue

            out.append(f'{ind}# TODO (decompile): {content}')
            i += 1

        return out

    def _v5_deep_clean(self, lines: List[str]) -> List[str]:

        lines = self._v5_rename_anon_vars(lines)

        out = []
        signal_counters: Dict[str, int] = {}

        current_class: Optional[str] = None

        for idx, line in enumerate(lines):
            stripped = line.strip()
            if not stripped:
                out.append(line)
                continue

            ind = line[:len(line) - len(stripped)]

            m_class = re.match(r'^class\s+(\w+)', stripped)
            if m_class and not ind:
                current_class = m_class.group(1)
                signal_counters[current_class] = 0
                out.append(line)
                continue

            if stripped.startswith('#'):
                out.append(line)
                continue

            if re.search(r'\bNone\s*\[', stripped):
                out.append(f'{ind}# TODO (decompile): {stripped}')
                continue

            if re.match(r'^=\s*(pyqtSignal|staticmethod|classmethod)\s*[(\[]', stripped):
                cname = current_class or 'unknown'
                cnt = signal_counters.get(cname, 0)
                signal_counters[cname] = cnt + 1

                if 'pyqtSignal' in stripped:
                    varname = f'signal_{cnt}'
                elif 'staticmethod' in stripped:
                    varname = f'_static_method_{cnt}'
                else:
                    varname = f'_class_method_{cnt}'
                out.append(f'{ind}{varname} = {stripped[stripped.index("=")+1:].strip()}')
                continue

            if re.match(r'^=\s*\d+\s*$', stripped):
                continue

            if re.match(r'^=\s*(None|\(\(None,\),\)|\(\))\s*$', stripped):
                continue

            if re.match(r'^=\s*.+', stripped) and not stripped.startswith('=='):
                cname = current_class or 'unknown'
                cnt = signal_counters.get(cname, 0)
                signal_counters[cname] = cnt + 1
                rhs = stripped[1:].strip()
                out.append(f'{ind}_var_{cnt} = {rhs}')
                continue

            if '__MISSING__' in line:
                line = self._fix_missing(line)
                stripped = line.strip()
                if not stripped:
                    continue

            if re.search(r"""(?:'[^']*'|"[^"]*")\.[A-Za-z_]\w*""", stripped):
                line = self._fix_str_attr(line, ind, stripped)
                stripped = line.strip()

            if re.search(r'\.\w+\.value\.\w+\s*=', stripped):
                out.append(f'{ind}# TODO (decompile): {stripped}')
                continue

            if 'NULL + ' in line or 'NULL|self' in line:
                line = re.sub(r'NULL\|self\s*\+\s*', '', line)
                line = re.sub(r'\bNULL\s*\+\s*', '', line)
                stripped = line.strip()

            if stripped in ('__MISSING__', '(__MISSING__)', '__MISSING__,'):
                continue

            out.append(line)

        return out

    def _v5_rename_anon_vars(self, lines: List[str]) -> List[str]:

        out = []
        func_depth = 0
        anon_in_scope: Dict[str, str] = {}
        anon_counter = [0]

        ANON_RE = re.compile(r'\b(__[a-z]__)\b')

        ANON_NAMES = {f'__{chr(c)}__': f'_anon{c - ord("a")}' for c in range(ord('a'), ord('z')+1)}

        for line in lines:
            if ANON_RE.search(line):

                if '__b__.app = __a__' in line:
                    ind = line[:len(line) - len(line.lstrip())]
                    out.append(f'{ind}self.app = None  # TODO: assign app reference')
                    continue

                def replace_anon(m):
                    name = m.group(1)
                    return ANON_NAMES.get(name, name)
                line = ANON_RE.sub(replace_anon, line)
            out.append(line)
        return out

    def _fix_missing(self, line: str) -> str:
        line = re.sub(r'__MISSING__\.perf_counter\b', 'time.perf_counter()', line)
        line = re.sub(r'__MISSING__\.(RUNNING|CLICK_DELAY|CLICKS|ACTIVATION_KEY_TYPE|CPS|MODE)',
                      r'self.\1', line)
        line = re.sub(r'__MISSING__\.sleep\b', 'time.sleep', line)
        line = re.sub(r'__MISSING__\s*\([^)]*\)', 'None', line)
        line = re.sub(r'\b__MISSING__\b', 'None', line)
        line = re.sub(r'\bNone\s*\+\s*', '', line)
        line = re.sub(r'\s*\+\s*None\b', '', line)
        return line

    def _fix_str_attr(self, line: str, ind: str, stripped: str) -> str:
        m = re.match(r"^(\w[\w.]*)\s*=\s*['\"]([A-Za-z_]\w*)['\"]\.(.+)$", stripped)
        if m:
            varname, str_content, attr_chain = m.group(1), m.group(2), m.group(3)
            if varname == str_content:
                return f'{ind}{varname} = {attr_chain}'
            else:
                return f'{ind}{varname} = {str_content}.{attr_chain}'

        def _rep(match):
            content = match.group(1)
            attr = match.group(2)
            if re.match(r'^[A-Za-z_]\w*$', content):
                return f'{content}.{attr}'
            return attr
        new = re.sub(r"""['"]([\w]+)['"]\.([\w]+)""", _rep, line)
        if new != line:
            return new
        return f'{ind}# TODO (decompile): {stripped}'

    def _v5_final_polish(self, lines: List[str]) -> List[str]:

        FATAL = [
            re.compile(r"""(?:'[^']*'|"[^"]*")\.[A-Za-z_]"""),
            re.compile(r'\b__MISSING__\b'),
            re.compile(r'(?<!\w)None\s*\('),
            re.compile(r'\bNone\s*\['),
            re.compile(r'^\s*=\s+'),
        ]
        out = []
        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                out.append(line)
                continue
            ind = line[:len(line) - len(stripped)]
            bad = any(p.search(stripped) for p in FATAL)

            if bad and not stripped.startswith('=='):
                out.append(f'{ind}# TODO (decompile): {stripped}')
            else:
                out.append(line)
        return out

