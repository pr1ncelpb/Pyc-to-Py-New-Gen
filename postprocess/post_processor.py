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

class PostProcessor:

    def __init__(self, code: str):
        self.code = code

    def process(self) -> str:
        lines = self.code.splitlines()
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
        return '\n'.join(lines)

    def _clean_artifacts(self, lines: List[str]) -> List[str]:

        out = []
        for line in lines:
            stripped = line.strip()
            if not stripped:
                out.append(line)
                continue

            if re.match(r"^(\w+\s*=\s*)?__name__\s*$", stripped):
                continue
            if re.match(r"^=\s+\'[A-Za-z_][A-Za-z0-9_.]*\'\s*$", stripped):
                continue
            if re.match(r"^=\s+\([^)]*\)\s*$", stripped):
                continue

            if "NULL|self + " in line:
                line = re.sub(r"\.NULL\|self\s*\+\s*", ".", line)

            if "NULL + " in line:
                line = re.sub(r"NULL\s*\+\s*", "", line)

            m = re.match(r"^(\s*)(\w+)\s*=\s*(\2)\s*$", line)
            if m:
                continue

            out.append(line)
        return out

    def _remove_redundant_assignments_pp(self, lines: List[str]) -> List[str]:

        result = []
        for line in lines:
            stripped = line.strip()

            m = re.match(r'^(\w[\w.]*)\s*=\s*(\w[\w.]*)$', stripped)
            if m and m.group(1) == m.group(2):

                continue
            result.append(line)
        return result

    def _fix_invalid_expressions(self, lines: List[str]) -> List[str]:

        NONE_CALL    = re.compile(r'(?<![.\w])None\s*\(')
        STR_CALL     = re.compile(r"""(?<![.\w])(?:'[^'\\]*(?:\\.[^'\\]*)*'|"[^"\\]*(?:\\.[^"\\]*)*")\s*\(""")
        INT_CALL     = re.compile(r'(?<![.\w\d])(\d+)\s*\(')
        FLOAT_SUBSCR = re.compile(r'(?<![.\w])\.\d+\s*\[|^\.\d+\s*\[')

        result = []
        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                result.append(line)
                continue
            indent_str = line[:len(line) - len(line.lstrip())]

            if stripped.startswith(('def ', 'class ')):
                result.append(line)
                continue

            should_comment = False

            if NONE_CALL.search(stripped):
                should_comment = True

            elif STR_CALL.search(stripped):
                should_comment = True

            elif INT_CALL.search(stripped):
                m = INT_CALL.search(stripped)
                if m:
                    before = stripped[:m.start()]

                    if not before or before[-1] in ' \t=,([{+-*/%&|^~!<>@:':
                        should_comment = True

            elif FLOAT_SUBSCR.search(stripped):
                should_comment = True

            else:

                tc = re.search(r'\)\s*\(', stripped)
                if tc:
                    prefix = stripped[:tc.start() + 1]
                    depth = 0
                    tuple_start = -1
                    for ci in range(len(prefix) - 1, -1, -1):
                        c = prefix[ci]
                        if c == ')':
                            depth += 1
                        elif c == '(':
                            depth -= 1
                            if depth == 0:
                                tuple_start = ci
                                break
                    if tuple_start >= 0:
                        inner = prefix[tuple_start + 1:-1]
                        if ',' in inner and not inner.strip().startswith('lambda'):
                            should_comment = True

            if should_comment:
                result.append(f'{indent_str}# TODO: {stripped}')
            else:
                result.append(line)

        return result

    def _fix_except_ordering(self, lines: List[str]) -> List[str]:

        out = list(lines)
        i = 0
        while i < len(out):
            line = out[i]
            stripped = line.strip()
            if re.match(r'^except\s*:\s*$', stripped):
                indent_lvl = len(line) - len(line.lstrip())

                j = i + 1
                while j < len(out):
                    lj = out[j]
                    if not lj.strip():
                        j += 1
                        continue
                    lj_indent = len(lj) - len(lj.lstrip())
                    if lj_indent <= indent_lvl:
                        break
                    j += 1

                if j < len(out):
                    lj_stripped = out[j].strip()
                    lj_indent = len(out[j]) - len(out[j].lstrip())
                    if lj_indent == indent_lvl and re.match(r'^except\s+\w', lj_stripped):

                        bare_except_block = out[i:j]
                        del out[i:j]

                        k = i
                        while k < len(out):
                            lk = out[k]
                            if not lk.strip():
                                k += 1
                                continue
                            lk_indent = len(lk) - len(lk.lstrip())
                            lk_stripped = lk.strip()
                            if lk_indent == indent_lvl and re.match(r'^except[\s:]', lk_stripped):
                                k += 1
                                while k < len(out):
                                    lk2 = out[k]
                                    if not lk2.strip():
                                        k += 1
                                        continue
                                    if len(lk2) - len(lk2.lstrip()) <= indent_lvl:
                                        break
                                    k += 1
                            else:
                                break
                        for idx2, bl in enumerate(bare_except_block):
                            out.insert(k + idx2, bl)
                        i = k + len(bare_except_block)
                        continue
            i += 1
        return out

    def _fix_deep_nesting(self, lines: List[str]) -> List[str]:

        BLOCK_KEYWORDS = re.compile(
            r'^\s*(if |elif |else:|for |while |try:|except|finally:|with |def |class )'
        )
        MAX_DEPTH = 18

        indent_stack = [0]
        out = []

        for line in lines:
            stripped = line.strip()
            if not stripped:
                out.append(line)
                continue

            cur_indent = len(line) - len(line.lstrip())

            while len(indent_stack) > 1 and indent_stack[-1] >= cur_indent:
                indent_stack.pop()

            block_depth = len(indent_stack) - 1

            is_block_opener = (
                stripped.endswith(':') and
                not stripped.startswith('#') and
                bool(BLOCK_KEYWORDS.match(line))
            )

            if is_block_opener and block_depth >= MAX_DEPTH:
                indent_str = line[:cur_indent]
                out.append(f'{indent_str}# DEEP_NESTING_FLATTENED: {stripped}')

            else:
                out.append(line)
                if is_block_opener:
                    indent_stack.append(cur_indent + 4)

        return out

    def _iterative_syntax_fix(self, lines: List[str]) -> List[str]:

        import ast
        max_iters = 50
        for _ in range(max_iters):
            code = '\n'.join(lines)
            try:
                ast.parse(code)
                break
            except SyntaxError as e:
                msg = str(e.msg) if e.msg else ''
                lineno = e.lineno
                if lineno is None or lineno > len(lines):
                    break

                if 'too many statically nested blocks' in msg:
                    lines = self._fix_deep_nesting_aggressive(lines)
                    continue

                if "default 'except:' must be last" in msg:
                    lines = self._fix_except_ordering(lines)
                    continue

                idx = lineno - 1
                bad_line = lines[idx]
                stripped = bad_line.strip()
                indent_str = bad_line[:len(bad_line) - len(bad_line.lstrip())]
                if stripped.startswith('#'):

                    found = False
                    for offset in range(1, 5):
                        alt_idx = idx + offset
                        if alt_idx < len(lines):
                            alt_stripped = lines[alt_idx].strip()
                            if alt_stripped and not alt_stripped.startswith('#'):
                                alt_indent = lines[alt_idx][:len(lines[alt_idx]) - len(lines[alt_idx].lstrip())]
                                lines[alt_idx] = f'{alt_indent}# SYNTAX_FIX: {alt_stripped}'
                                found = True
                                break
                    if not found:
                        break
                    continue

                lines[idx] = f'{indent_str}# SYNTAX_FIX: {stripped}'

                if stripped.startswith(('def ', 'class ')) and stripped.endswith(':'):
                    cur_indent = len(indent_str)
                    j = idx + 1
                    while j < len(lines):
                        body_line = lines[j]
                        if not body_line.strip():
                            j += 1
                            continue
                        body_indent = len(body_line) - len(body_line.lstrip())
                        if body_indent <= cur_indent:
                            break
                        body_stripped = body_line.strip()
                        if not body_stripped.startswith('#'):
                            body_ind = body_line[:body_indent]
                            lines[j] = f'{body_ind}# SYNTAX_FIX: {body_stripped}'
                        j += 1

                elif stripped.endswith(':') and idx + 1 < len(lines):
                    next_stripped = lines[idx + 1].strip()
                    if not next_stripped or next_stripped.startswith('#'):
                        lines.insert(idx + 1, f'{indent_str}    pass')
        return lines

    def _fix_deep_nesting_aggressive(self, lines: List[str]) -> List[str]:

        BLOCK_KEYWORDS = re.compile(
            r'^\s*(if |elif |else:|for |while |try:|except|finally:|with |def |class )'
        )
        MAX_DEPTH = 15

        indent_stack = [0]
        out = []

        for line in lines:
            if line.strip().startswith('# DEEP_NESTING_FLATTENED:'):
                out.append(line)
                continue
            stripped = line.strip()
            if not stripped:
                out.append(line)
                continue

            cur_indent = len(line) - len(line.lstrip())

            while len(indent_stack) > 1 and indent_stack[-1] >= cur_indent:
                indent_stack.pop()

            block_depth = len(indent_stack) - 1

            is_block_opener = (
                stripped.endswith(':') and
                not stripped.startswith('#') and
                bool(BLOCK_KEYWORDS.match(line))
            )

            if is_block_opener and block_depth >= MAX_DEPTH:
                indent_str = line[:cur_indent]
                out.append(f'{indent_str}# DEEP_NESTING_FLATTENED: {stripped}')
            else:
                out.append(line)
                if is_block_opener:
                    indent_stack.append(cur_indent + 4)

        return out

    def _fix_orphaned_indentation(self, lines: List[str]) -> List[str]:

        SKIP_PATTERNS = [
            r'^=\s+__name__\s*$',
            r"^=\s+'[^']+'\s*$",
            r'^=\s+\(__MISSING__,?\)\s*$',
            r'NULL\|self\s*\+',
            r'\+\s*NULL\|self',
            r'__MISSING__\([^)]*\)\[\d+\]',
        ]
        ARTIFACT_RE = [re.compile(p) for p in SKIP_PATTERNS]

        out = []
        i = 0
        while i < len(lines):
            line = lines[i]
            stripped = line.strip()
            if not stripped:
                out.append(line)
                i += 1
                continue

            is_artifact = False
            for pat in ARTIFACT_RE:
                if pat.search(stripped):
                    is_artifact = True
                    break
            if is_artifact:
                i += 1
                continue

            cur_indent = len(line) - len(line.lstrip())

            if cur_indent % 4 != 0 and not stripped.startswith('#'):

                corrected_indent = round(cur_indent / 4) * 4
                out.append(' ' * corrected_indent + stripped)
                i += 1
                continue

            out.append(line)
            i += 1
        return out

    def _fix_try_blocks(self, lines: List[str]) -> List[str]:

        out = list(lines)
        i = 0
        while i < len(out):
            line = out[i]
            stripped = line.strip()
            if stripped == 'try:':
                try_indent = len(line) - len(line.lstrip())

                has_handler = False
                j = i + 1
                while j < len(out):
                    lj = out[j]
                    if not lj.strip():
                        j += 1
                        continue
                    lj_indent = len(lj) - len(lj.lstrip())
                    if lj_indent < try_indent:
                        break
                    if lj_indent == try_indent:
                        lj_stripped = lj.strip()
                        if lj_stripped.startswith('except') or lj_stripped.startswith('finally'):
                            has_handler = True
                        break
                    j += 1
                if not has_handler:

                    ind = ' ' * try_indent

                    insert_pos = j
                    out.insert(insert_pos, f'{ind}    pass')
                    out.insert(insert_pos, f'{ind}except:')
                    i += 1
                    continue
            i += 1
        return out

    def _fix_empty_bodies(self, lines: List[str]) -> List[str]:

        out = []
        i = 0
        while i < len(lines):
            line = lines[i]
            out.append(line)
            stripped = line.rstrip()
            if stripped.endswith(':') and not stripped.strip().startswith('#'):
                current_indent = len(line) - len(line.lstrip())

                j = i + 1
                while j < len(lines) and not lines[j].strip():
                    j += 1
                if j < len(lines):
                    next_line = lines[j]
                    next_indent = len(next_line) - len(next_line.lstrip())
                    next_stripped = next_line.strip()

                    if next_indent <= current_indent and next_stripped:
                        out.append(' ' * (current_indent + 4) + 'pass')

                    elif next_indent > current_indent:

                        all_comments = True
                        k = j
                        while k < len(lines):
                            kl = lines[k]
                            if not kl.strip():
                                k += 1
                                continue
                            k_indent = len(kl) - len(kl.lstrip())
                            if k_indent <= current_indent:
                                break
                            if not kl.strip().startswith('#'):
                                all_comments = False
                                break
                            k += 1
                        if all_comments:

                            out.append(' ' * (current_indent + 4) + 'pass')
                else:
                    out.append(' ' * (current_indent + 4) + 'pass')
            i += 1
        return out

    def _fix_imports(self, lines: List[str]) -> List[str]:

        import_groups: Dict[str, List[str]] = {}
        import_order = []
        result = []
        i = 0

        import_section_end = 0
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith('from ') or stripped.startswith('import '):
                import_section_end = i
            elif stripped and not stripped.startswith('#'):
                if import_section_end > 0:
                    break

        from_imports: Dict[str, List[str]] = {}
        plain_imports = []
        other_lines = []
        in_imports = True

        for line in lines:
            stripped = line.strip()
            if in_imports:
                m = re.match(r'^from (\S+) import (.+)$', stripped)
                if m:
                    module, names_str = m.group(1), m.group(2)
                    names = [n.strip() for n in names_str.split(',')]
                    if module not in from_imports:
                        from_imports[module] = []
                    for name in names:
                        if name not in from_imports[module]:
                            from_imports[module].append(name)
                    continue
                elif stripped.startswith('import '):
                    if stripped not in plain_imports:
                        plain_imports.append(stripped)
                    continue
                elif stripped == '' or stripped.startswith('#'):
                    if from_imports or plain_imports:
                        pass
                    other_lines.append(line)
                    continue
                else:
                    in_imports = False

            other_lines.append(line)

        result = []
        for imp in plain_imports:
            result.append(imp)
        for module, names in from_imports.items():
            result.append(f'from {module} import {", ".join(names)}')
        if result:
            result.append('')

        for line in other_lines:
            if line.strip():
                result.append(line)
            elif result and result[-1].strip():
                result.append(line)

        return result

    def _fix_for_loops(self, lines: List[str]) -> List[str]:

        out = []
        i = 0
        while i < len(lines):
            line = lines[i]
            if '__for_iter__' in line:
                line = re.sub(r'__for_iter__\((.+)\)', r'\1', line)
            line = re.sub(r'for (\w+) in iter\((.+)\):', r'for \1 in \2:', line)

            stripped = line.strip()

            m_enum = re.match(r'^(for\s+)(\w+)(\s+in\s+enumerate\()', stripped)
            if m_enum:
                var = m_enum.group(2)
                rest = stripped[m_enum.end():]
                ind = line[:len(line)-len(stripped)]
                line = f'{ind}for {var}, _ in enumerate({rest}'

            if re.match(r'^for\s+(\w+)\s+in\s+(\w+\[.+\]):', stripped):
                pass

            out.append(line)
            i += 1
        return out

    def _fix_broken_expressions(self, lines: List[str]) -> List[str]:

        result = []
        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                result.append(line)
                continue
            indent_str = line[:len(line) - len(line.lstrip())]

            if re.search(r'\bOP\d+\b', stripped):
                stripped2 = re.sub(r'\bOP\d+\b', '0', stripped)
                result.append(f'{indent_str}# TODO (decompile): {stripped}')
                continue

            if '<func:' in stripped or '<code object' in stripped:

                if not stripped.startswith('def ') and not stripped.startswith('# TODO'):
                    result.append(f'{indent_str}# TODO (decompile): {stripped}')
                else:
                    result.append(line)
                continue

            if re.search(r'\b__intrinsic_\d+__\b', stripped):
                result.append(f'{indent_str}# TODO (decompile): {stripped}')
                continue

            result.append(line)
        return result

    def _fix_return_none(self, lines: List[str]) -> List[str]:

        out = []
        for line in lines:
            stripped = line.strip()

            if stripped == 'return None':

                out.append(line)
            else:
                out.append(line)
        return out

    def _fix_trailing_newlines(self, lines: List[str]) -> List[str]:

        out = []
        prev_empty = False
        for line in lines:
            is_empty = not line.strip()
            if is_empty and prev_empty:
                continue
            out.append(line)
            prev_empty = is_empty
        return out

