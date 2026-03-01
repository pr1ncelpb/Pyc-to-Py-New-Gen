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
from engine.scope import Instr, StackVal, ScopeInfo, ClosureScopeTracker

class HighLevelReconstructor:

    def __init__(self, source: str, verbose: bool = False):
        self.source = source
        self.verbose = verbose
        self.blocks: Dict[str, Tuple[str, List[str]]] = {}

        self._parse_all_blocks()

        self._closure_tracker: Optional[ClosureScopeTracker] = None
        self._build_closure_tracker()

    def _parse_all_blocks(self):

        lines = self.source.splitlines()
        current_name = '__module__'
        current_addr = ''
        current_lines = []
        module_lines = []
        found_first_disassembly = False

        for line in lines:
            stripped = line.strip()
            m = re.match(r'^Disassembly of <code object (\w+) at (0x[0-9a-fA-F]+)', stripped)
            if m:

                if not found_first_disassembly:
                    module_lines = current_lines
                else:
                    key = f'{current_name}@{current_addr}'
                    self.blocks[key] = (current_name, current_lines)
                found_first_disassembly = True
                current_name = m.group(1)
                current_addr = m.group(2).lower()
                current_lines = []
            else:
                current_lines.append(line)

        if found_first_disassembly and current_lines:
            key = f'{current_name}@{current_addr}'
            self.blocks[key] = (current_name, current_lines)

        self.blocks['__module__@'] = ('__module__', module_lines)

    def _build_closure_tracker(self):

        try:
            self._closure_tracker = ClosureScopeTracker(self.blocks, self._parse_instrs)
            self._closure_tracker.build()
        except Exception:
            self._closure_tracker = None

    def reconstruct(self) -> str:

        out_lines = []
        out_lines.append('# ─────────────────────────────────────────────────────')
        out_lines.append('# Décompilé par Ultra Bytecode Translator v7.0')
        out_lines.append('# Python 3.10-3.14 — Reconstruction haute fidélité')
        out_lines.append('# Points couverts: classes, ctypes, décorateurs,')
        out_lines.append('#   imports intelligents, closures/nonlocal, for/while,')
        out_lines.append('#   héritage, assignations redondantes, Base64,')
        out_lines.append('#   annotations de type, f-strings, docstrings,')
        out_lines.append('#   opcodes Tier-2 spécialisés (3.13/3.14)')
        out_lines.append('# ─────────────────────────────────────────────────────')
        out_lines.append('')

        module_code = self._gen_module_level()
        out_lines.extend(module_code)

        result = '\n'.join(out_lines)

        result_lines = result.splitlines()
        result_lines = self._fold_fstring_concatenations(result_lines)
        result = '\n'.join(result_lines)

        return result

    def _parse_instrs(self, lines: List[str]) -> List[Instr]:
        instrs = []

        RE = re.compile(
            r'^'
            r'\s*(?:(\d+|--)\s+)?'
            r'(?:\s*(>>)\s+)?'
            r'(?:\s*\d+\s+)?'
            r'(?:(L\w+|[A-Z]\d+):\s*)?'
            r'([A-Z][A-Z0-9_]+)'
            r'(?:\s+(-?\d+))?'
            r'(?:\s+\((.*)\)|\s+(to\s+\d+))?'
            r'\s*$'
        )
        EXC_RE = re.compile(r'^\s*(L\w+)\s+to\s+(L\w+)\s+->\s+(L\w+)')
        in_exc_table = False
        for raw_line in lines:
            stripped = raw_line.strip()
            if not stripped:
                continue
            if stripped.startswith('ExceptionTable'):
                in_exc_table = True
                continue
            if in_exc_table:
                m_exc = EXC_RE.match(raw_line)
                if m_exc:
                    instrs.append(Instr(
                        lineno=None, label=None,
                        opcode='__EXCTABLE_ENTRY__',
                        arg=None,
                        raw_arg=f'{m_exc.group(1)},{m_exc.group(2)},{m_exc.group(3)}',
                        src_line=raw_line,
                    ))
                    continue
                elif stripped and not stripped.startswith('L'):
                    in_exc_table = False
                else:
                    continue
            if stripped.startswith('Disassembly of'):
                continue
            m = RE.match(raw_line)
            if not m:

                m = RE.match(stripped)
            if not m:
                continue
            lineno_s, jump_marker, label, opcode, arg_s, comment, to_target = m.groups()
            lineno = None
            if lineno_s and lineno_s not in ('--',):
                try:
                    lineno = int(lineno_s)
                except:
                    pass
            arg = int(arg_s) if arg_s is not None else None
            # "to N" without parens → store as raw_arg
            raw = comment or to_target or ''
            # ">>" marker → this offset is a jump target, use as label if no explicit label
            if jump_marker == '>>' and not label and arg_s is not None:
                label = f'T{arg_s}'
            # Also update any jump instructions that reference this offset as "to N":
            # We keep raw_arg as-is; we'll resolve offsets to labels in a second pass
            instrs.append(Instr(
                lineno=lineno,
                label=label,
                opcode=opcode,
                arg=arg,
                raw_arg=raw,
                src_line=raw_line,
            ))

        for instr in instrs:
            normalized = TIER2_OPCODE_NORMALIZE.get(instr.opcode)
            if normalized:
                instr.opcode = normalized

        # ── Post-pass: résoudre les "to N" vers des labels ────────────────
        # Dans le format de dis Python standard, les sauts ont raw_arg='to N'
        # où N est l'offset cible. On crée des labels sur les instructions
        # cibles et on met à jour raw_arg pour utiliser ces labels.
        self._resolve_jump_offsets_to_labels(instrs)
        # ─────────────────────────────────────────────────────────────────
        return instrs

    def _resolve_jump_offsets_to_labels(self, instrs: List[Instr]) -> None:
        """
        Résout les raw_arg de forme 'to N' (offset numérique) en labels
        de forme 'to L_N' sur les instructions.

        Crée également des labels sur les instructions cibles
        si elles n'en ont pas encore.

        Fonctionne aussi sur la notation >> (déjà traduite en Tn par le parser).
        """
        JUMP_OPS = {
            'JUMP_FORWARD', 'JUMP_BACKWARD', 'JUMP_ABSOLUTE',
            'JUMP_BACKWARD_NO_INTERRUPT', 'JUMP_NO_INTERRUPT',
            'POP_JUMP_IF_FALSE', 'POP_JUMP_IF_TRUE',
            'POP_JUMP_IF_NONE', 'POP_JUMP_IF_NOT_NONE',
            'POP_JUMP_FORWARD_IF_FALSE', 'POP_JUMP_FORWARD_IF_TRUE',
            'POP_JUMP_BACKWARD_IF_FALSE', 'POP_JUMP_BACKWARD_IF_TRUE',
            'POP_JUMP_FORWARD_IF_NONE', 'POP_JUMP_FORWARD_IF_NOT_NONE',
            'POP_JUMP_BACKWARD_IF_NONE', 'POP_JUMP_BACKWARD_IF_NOT_NONE',
            'FOR_ITER', 'SEND', 'JUMP_IF_FALSE_OR_POP', 'JUMP_IF_TRUE_OR_POP',
        }

        # Build offset → instr index map from src_line
        # The src_line format: "   N  OPCODE  arg  (comment)"
        # We extract the offset N from src_line
        offset_to_idx: Dict[int, int] = {}
        for ii, instr in enumerate(instrs):
            if instr.src_line:
                m = re.search(r'^\s*(?:\d+\s+)?(?:>>\s+)?(\d+)\s+[A-Z]', instr.src_line)
                if m:
                    try:
                        off = int(m.group(1))
                        offset_to_idx[off] = ii
                    except ValueError:
                        pass

        if not offset_to_idx:
            return  # No offsets found (L-label format, not needed)

        # For each jump with "to N" raw_arg, find target and assign label
        label_counter = [0]

        def get_or_create_label(target_idx: int) -> str:
            if instrs[target_idx].label:
                return instrs[target_idx].label
            label_counter[0] += 1
            lbl = f'L{label_counter[0]}'
            instrs[target_idx].label = lbl
            return lbl

        # First pass: handle existing T-labels (from >> markers)
        for ii, instr in enumerate(instrs):
            if instr.label and instr.label.startswith('T') and instr.src_line:
                m = re.search(r'^\s*(?:\d+\s+)?>>\s+(\d+)\s+[A-Z]', instr.src_line)
                if m:
                    try:
                        off = int(m.group(1))
                        # Rename T-label to L-label for consistency
                        lbl = f'L{off}'
                        instr.label = lbl
                        offset_to_idx[off] = ii
                    except ValueError:
                        pass

        # Second pass: resolve "to N" in jump instructions
        for ii, instr in enumerate(instrs):
            if instr.opcode not in JUMP_OPS:
                continue
            raw = instr.raw_arg.strip()
            m = re.match(r'to (\d+)$', raw)
            if not m:
                continue
            target_off = int(m.group(1))

            # Find or create target label
            if target_off in offset_to_idx:
                target_idx = offset_to_idx[target_off]
                lbl = get_or_create_label(target_idx)
            else:
                # Target offset not found (might be in exception table or truncated)
                lbl = f'L{target_off}'

            instr.raw_arg = f'to {lbl}'

    def _gen_module_level(self) -> List[str]:

        module_key = '__module__@'
        if module_key not in self.blocks:
            return []
        _, module_lines = self.blocks[module_key]
        instrs = self._parse_instrs(module_lines)

        out = []

        imports = self._extract_imports(instrs)

        defs = self._extract_definitions(instrs)

        vars_code = self._extract_global_vars(instrs)

        main_code = self._extract_main_block(instrs)

        all_generated_code = '\n'.join(
            [self._gen_class(n, b, a)[0] for t, n, b, a, _ in defs if t == 'class'] +
            vars_code
        )
        missing_imports = self._detect_missing_imports(imports, all_generated_code, defs)

        base64_vars = self._detect_base64_resources(instrs)

        CTYPES_BASES = {'ctypes.Structure', 'ctypes.Union', 'Structure', 'Union',
                        'ctypes.LittleEndianStructure', 'ctypes.BigEndianStructure'}

        ctypes_defs = []
        other_defs = []

        for defn in defs:
            def_type, name, bases, addr, lineno = defn
            if def_type == 'class' and any(b in CTYPES_BASES for b in bases):
                ctypes_defs.append(defn)
            else:
                other_defs.append(defn)

        all_code_preview = '\n'.join(vars_code)
        imports = self._refine_imports(imports, all_code_preview)

        for imp in imports:
            out.append(imp)

        for imp in missing_imports:
            if imp not in imports:
                out.append(f'# [AUTO-DETECTED] {imp}')
        if imports or missing_imports:
            out.append('')

        if base64_vars:
            out.append('# ─── Ressources encodées Base64 ──────────────────────')
            for var_name, b64_val in base64_vars:
                b64_len = len(b64_val)
                out.append(f'# Resource: {var_name}  ({b64_len} chars de base64)')
                if b64_len > 120:
                    chunks = [b64_val[k:k+76] for k in range(0, b64_len, 76)]
                    lines_b64 = '\\\n    '.join(f'"{c}"' for c in chunks)
                    out.append(f'{var_name} = base64.b64decode(')
                    for ci, chunk in enumerate(chunks):
                        comma = '' if ci == len(chunks)-1 else ''
                        out.append(f'    b"{chunk}"')
                    out.append(')')
                else:
                    out.append(f'{var_name} = base64.b64decode(b"{b64_val}")')
            out.append('')

        if ctypes_defs:
            out.append('# ─── Structures ctypes ────────────────────────────────')
            for (def_type, name, bases, addr, lineno) in ctypes_defs:
                cls_code = self._gen_class(name, bases, addr)
                out.extend(cls_code)
                out.append('')
            out.append('')

        clean_vars = []
        for v in vars_code:

            m = re.match(r'^(\w[\w.]*)\s*=\s*(\w[\w.]*)$', v.strip())
            if m and m.group(1) == m.group(2):
                continue
            clean_vars.append(v)
        for v in clean_vars:
            out.append(v)
        if clean_vars:
            out.append('')

        for (def_type, name, bases, addr, lineno) in other_defs:
            if def_type == 'class':
                cls_code = self._gen_class(name, bases, addr)
                out.extend(cls_code)
                out.append('')
            elif def_type == 'function':
                func_code = self._gen_function(name, addr, indent=0)
                out.extend(func_code)
                out.append('')

        if main_code:
            out.append('')
            out.extend(main_code)

        return out

    def _detect_missing_imports(self, existing_imports: List[str],
                                 code_snippet: str,
                                 defs: List) -> List[str]:

        missing = []
        already_imported = set()

        for imp in existing_imports:

            m = re.match(r'^from\s+\S+\s+import\s+(.+)$', imp)
            if m:
                for name in m.group(1).split(','):
                    already_imported.add(name.strip().split(' as ')[-1].strip())

            m2 = re.match(r'^import\s+(\S+)', imp)
            if m2:
                already_imported.add(m2.group(1).split('.')[0])

        for def_type, name, bases, addr, lineno in defs:
            already_imported.add(name)

        for def_type, name, bases, addr, lineno in defs:
            if def_type == 'class':
                for base in bases:
                    base_clean = re.sub(r'\s*\+\s*NULL.*$', '', base).strip()
                    base_name = base_clean.split('.')[0]
                    if base_name and base_name not in already_imported and \
                       base_name in KNOWN_MODULES:
                        imp = KNOWN_MODULES[base_name]
                        if imp not in missing:
                            missing.append(imp)
                            already_imported.add(base_name)

        used_names = set(re.findall(r'\b([A-Z][a-zA-Z0-9_]*)\b', code_snippet))
        for name in used_names:
            if name not in already_imported and name in KNOWN_MODULES:
                imp = KNOWN_MODULES[name]
                if imp not in missing and imp not in existing_imports:
                    missing.append(imp)

        return missing

    def _detect_base64_resources(self, instrs: List['Instr']) -> List[Tuple[str, str]]:

        resources = []
        i = 0
        while i < len(instrs):
            instr = instrs[i]
            if instr.opcode == 'LOAD_CONST':
                val = instr.raw_arg.strip()
                if (val.startswith("'") or val.startswith('"') or
                        val.startswith("b'") or val.startswith('b"')) and \
                   len(val) >= BASE64_MIN_LEN + 2:
                    inner_raw = val
                    if inner_raw.startswith("b'") or inner_raw.startswith('b"'):
                        inner = inner_raw[2:-1]
                    else:
                        inner = inner_raw[1:-1]
                    inner_clean = inner.replace('\\n', '').replace('\\r', '').replace(' ', '')
                    if re.match(r'^[A-Za-z0-9+/=]+$', inner_clean) and len(inner_clean) > BASE64_MIN_LEN:
                        if i + 1 < len(instrs) and instrs[i+1].opcode in ('STORE_NAME', 'STORE_FAST', 'STORE_GLOBAL'):
                            m = re.search(r'\(([^)]+)\)', instrs[i+1].raw_arg)
                            var_name = m.group(1).strip() if m else f'_b64_resource_{instr.lineno or i}'
                            resources.append((var_name, inner_clean))
            i += 1
        return resources

    def _extract_imports(self, instrs: List[Instr]) -> List[str]:

        imports = []
        i = 0
        while i < len(instrs):
            instr = instrs[i]
            if instr.opcode == 'IMPORT_NAME':
                m = re.search(r'\((\S+)\)', instr.raw_arg)
                if not m:
                    m = re.search(r'^(\S+)$', instr.raw_arg.strip())
                module = m.group(1) if m else instr.raw_arg.strip()

                fromlist = None
                level_val = 0
                if i >= 1 and instrs[i-1].opcode == 'LOAD_CONST':
                    fromlist_raw = instrs[i-1].raw_arg.strip()
                    if fromlist_raw.startswith("('"):
                        from_names = re.findall(r"'(\w+)'", fromlist_raw)
                        fromlist = from_names

                j = i + 1
                from_names_seen = []
                stored_name = None
                while j < min(i + 50, len(instrs)):
                    ij = instrs[j]
                    if ij.opcode == 'IMPORT_FROM':
                        m2 = re.search(r'\(([^)]+)\)', ij.raw_arg)
                        name = m2.group(1).strip() if m2 else ij.raw_arg.strip()
                        from_names_seen.append(name)
                    elif ij.opcode in ('STORE_NAME', 'STORE_FAST') and not from_names_seen:
                        m2 = re.search(r'\(([^)]+)\)', ij.raw_arg)
                        stored_name = m2.group(1).strip() if m2 else None
                        break
                    elif ij.opcode in ('POP_TOP', 'IMPORT_NAME', 'LOAD_BUILD_CLASS'):
                        break
                    j += 1

                if from_names_seen:
                    imports.append(f'from {module} import {", ".join(from_names_seen)}')
                elif fromlist:
                    imports.append(f'from {module} import {", ".join(fromlist)}')
                else:
                    if stored_name and stored_name != module.split('.')[-1]:
                        imports.append(f'import {module} as {stored_name}')
                    else:
                        imports.append(f'import {module}')

            i += 1

        seen = set()
        result = []
        for imp in imports:
            if imp not in seen:
                seen.add(imp)
                result.append(imp)
        return result

    def _extract_global_vars(self, instrs: List[Instr]) -> List[str]:

        out = []

        from engine.translator import BytecodeTranslator
        translator = BytecodeTranslator(self.source)
        exc_table = translator._parse_exception_table_from_instrs(instrs)
        result = translator._smart_translate(instrs, 0, exc_table)

        skip_names = ('__module__', '__qualname__', '__firstlineno__',
                      '__classcell__', '__static_attributes__', '__doc__')
        for line in result:
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith('def ') or stripped.startswith('class ') or \
               stripped.startswith('import ') or stripped.startswith('from ') or \
               stripped.startswith('#') or stripped.startswith('try:') or \
               stripped.startswith('except') or stripped.startswith('if '):
                continue
            if '<code object' in stripped or '<func:' in stripped:
                continue

            if '=' in stripped:
                name = stripped.split('=')[0].strip()
                if name in skip_names:
                    continue
                out.append(stripped)
            elif '(' in stripped:
                out.append(stripped)

        return out

    def _extract_definitions(self, instrs: List[Instr]) -> List:

        defs = []
        i = 0
        while i < len(instrs):
            instr = instrs[i]

            if instr.opcode == 'LOAD_BUILD_CLASS':
                j = i + 1
                code_addr = None
                class_name = None
                bases = []
                lineno = instr.lineno
                pending_base = None
                while j < min(i + 25, len(instrs)):
                    ij = instrs[j]
                    if ij.opcode in ('LOAD_CONST', 'MAKE_FUNCTION'):
                        m = re.search(r'code object (\w+) at (0x[0-9a-fA-F]+)', ij.raw_arg)
                        if m:
                            code_addr = m.group(2).lower()
                            if not class_name:
                                class_name = m.group(1)
                            pending_base = None
                    if ij.opcode == 'LOAD_CONST':
                        m = re.search(r"^'(\w+)'$", ij.raw_arg.strip())
                        if m and class_name:
                            class_name = m.group(1)
                            pending_base = None
                    if ij.opcode in ('LOAD_NAME', 'LOAD_GLOBAL') and class_name:

                        raw = ij.raw_arg.strip()
                        m = re.search(r'\(([^)]+)\)', raw)
                        name = m.group(1).strip() if m else raw
                        name = re.sub(r'\s*\+\s*NULL.*$', '', name).strip()
                        if name and name not in ('__build_class__',):
                            pending_base = name
                    elif ij.opcode == 'LOAD_ATTR' and pending_base and class_name:

                        raw = ij.raw_arg.strip()
                        m = re.search(r'\(([^)]+)\)', raw)
                        attr = m.group(1).strip() if m else raw
                        attr = re.sub(r'\s*\+\s*NULL.*$', '', attr).strip()
                        pending_base = f'{pending_base}.{attr}'
                    elif pending_base and ij.opcode in ('CALL', 'STORE_NAME'):

                        if re.match(r'^[A-Za-z_][A-Za-z0-9_.]*$', pending_base):
                            bases.append(pending_base)
                        pending_base = None
                    elif ij.opcode not in ('LOAD_ATTR', 'LOAD_NAME', 'LOAD_GLOBAL',
                                           'PUSH_NULL', 'MAKE_FUNCTION', 'LOAD_CONST',
                                           'CALL', 'SET_FUNCTION_ATTRIBUTE'):

                        if pending_base and re.match(r'^[A-Za-z_][A-Za-z0-9_.]*$', pending_base):
                            bases.append(pending_base)
                        pending_base = None

                    if ij.opcode == 'STORE_NAME':
                        raw_store = ij.raw_arg.strip()
                        m = re.search(r'\(([^)]+)\)', raw_store)
                        stored = m.group(1).strip() if m else raw_store
                        if stored and stored != class_name:
                            class_name = stored
                        break
                    j += 1
                if class_name and code_addr:
                    defs.append(('class', class_name, bases, code_addr, lineno))
                    i = j

            elif instr.opcode in ('LOAD_CONST', 'MAKE_FUNCTION'):
                m = re.search(r'code object (\w+) at (0x[0-9a-fA-F]+)', instr.raw_arg)
                if m:
                    func_name = m.group(1)
                    func_addr = m.group(2).lower()
                    lineno = instr.lineno

                    j = i + 1
                    while j < min(i + 10, len(instrs)):
                        ij = instrs[j]
                        if ij.opcode == 'SET_FUNCTION_ATTRIBUTE':
                            j += 1
                            continue
                        if ij.opcode in ('STORE_NAME', 'STORE_FAST', 'STORE_GLOBAL'):
                            m2 = re.search(r'\(([^)]+)\)', ij.raw_arg)
                            if m2:
                                func_name = m2.group(1).strip()
                            defs.append(('function', func_name, [], func_addr, lineno))
                            i = j
                            break
                        elif ij.opcode in ('LOAD_BUILD_CLASS', 'IMPORT_NAME'):
                            break
                        j += 1

            i += 1

        return defs

    def _extract_main_block(self, instrs: List[Instr]) -> List[str]:

        for i, instr in enumerate(instrs):
            if instr.opcode in ('LOAD_NAME', 'LOAD_GLOBAL'):
                m = re.search(r'\(([^)]+)\)', instr.raw_arg)
                name = m.group(1).strip() if m else ''
                if name == '__name__':

                    for j in range(i+1, min(i+5, len(instrs))):
                        ij = instrs[j]
                        if ij.opcode == 'LOAD_CONST' and "'__main__'" in ij.raw_arg:
                            return [f"if __name__ == '__main__':"]
        return []

    def _gen_class(self, class_name: str, bases: List[str], addr: str) -> List[str]:

        cls_key = f'{class_name}@{addr}'
        if cls_key not in self.blocks:
            for key in self.blocks:
                if key.startswith(f'{class_name}@') or key.endswith(f'@{addr}'):
                    cls_key = key
                    break
            else:
                if bases:
                    return [f'class {class_name}({", ".join(bases)}):', '    pass']
                return [f'class {class_name}:', '    pass']

        _, cls_lines = self.blocks[cls_key]
        cls_instrs = self._parse_instrs(cls_lines)

        is_ctypes = any(b in ('Structure', 'Union', 'ctypes.Structure', 'ctypes.Union')
                        for b in bases)

        clean_bases = []
        for b in bases:
            b = re.sub(r'\s*\+\s*NULL.*$', '', b).strip()
            if b and b not in ('__build_class__',):
                clean_bases.append(b)
        base_str = f'({", ".join(clean_bases)})' if clean_bases else ''
        out = [f'class {class_name}{base_str}:']
        has_content = False

        docstring = self._extract_docstring_from_block(cls_instrs)
        if docstring:
            if '\n' in docstring or len(docstring) > 60:
                out.append('    """')
                for dl in docstring.splitlines():
                    out.append(f'    {dl}')
                out.append('    """')
            else:
                out.append(f'    """{docstring}"""')
            has_content = True
        else:

            for j, instr in enumerate(cls_instrs[:10]):
                if instr.opcode == 'LOAD_CONST' and \
                   j + 1 < len(cls_instrs) and cls_instrs[j+1].opcode == 'STORE_NAME':
                    m = re.search(r'\(([^)]+)\)', cls_instrs[j+1].raw_arg)
                    if m and m.group(1).strip() == '__doc__':
                        doc = instr.raw_arg.strip()
                        doc_inner = doc[1:-1] if len(doc) >= 2 and doc[0] in ('"', "'") else doc
                        out.append(f'    """{doc_inner}"""')
                        has_content = True
                        break

        cls_var_code = self._gen_class_vars_v4(cls_instrs, is_ctypes)
        for cv in cls_var_code:
            out.append('    ' + cv)
            has_content = True

        methods_found = []
        i = 0
        while i < len(cls_instrs):
            instr = cls_instrs[i]
            op = instr.opcode

            if op in SKIP_OPCODES + ('MAKE_CELL',):
                i += 1
                continue

            decorator = None
            if op in ('LOAD_GLOBAL', 'LOAD_NAME', 'LOAD_DEREF'):
                m = re.search(r'\(([^)]+)\)', instr.raw_arg)
                if m:
                    deco_name = re.sub(r'\s*\+\s*NULL.*$', '', m.group(1)).strip()

                    KNOWN_DECOS = {
                        'property', 'staticmethod', 'classmethod',
                        'pyqtSignal', 'abstractmethod', 'override',
                        'lru_cache', 'cache', 'cached_property',
                    }

                    has_func = False
                    for jj in range(i + 1, min(i + 20, len(cls_instrs))):
                        if cls_instrs[jj].opcode in ('MAKE_FUNCTION',):
                            has_func = True
                            break
                        if cls_instrs[jj].opcode in ('LOAD_BUILD_CLASS', 'IMPORT_NAME'):
                            break
                    if has_func and (deco_name in KNOWN_DECOS or
                                     deco_name.startswith('property') or
                                     '.' in deco_name):
                        decorator = deco_name

            if op in ('LOAD_CONST', 'MAKE_FUNCTION'):
                m = re.search(r'code object (\w+) at (0x[0-9a-fA-F]+)', instr.raw_arg)
                if m:
                    method_name = m.group(1)
                    method_addr = m.group(2).lower()

                    j = i + 1
                    stored_name = method_name
                    method_decorator = None
                    while j < min(i + 20, len(cls_instrs)):
                        ij = cls_instrs[j]
                        if ij.opcode == 'STORE_NAME':
                            m2 = re.search(r'\(([^)]+)\)', ij.raw_arg)
                            if m2:
                                stored_name = m2.group(1).strip()
                            break

                        if ij.opcode == 'CALL' and ij.arg == 1:

                            for k in range(i - 1, max(0, i - 10), -1):
                                ik = cls_instrs[k]
                                if ik.opcode in ('LOAD_GLOBAL', 'LOAD_NAME', 'LOAD_DEREF',
                                                 'LOAD_ATTR'):
                                    mk = re.search(r'\(([^)]+)\)', ik.raw_arg)
                                    if mk:
                                        dn = re.sub(r'\s*\+\s*NULL.*$', '', mk.group(1)).strip()
                                        KNOWN_DECOS = {
                                            'property', 'staticmethod', 'classmethod',
                                            'pyqtSignal', 'abstractmethod', 'override',
                                            'lru_cache', 'cache', 'cached_property',
                                        }
                                        if dn in KNOWN_DECOS or '.' in dn:
                                            method_decorator = dn
                                    break
                        j += 1

                    method_key = f'{method_name}@{method_addr}'
                    if method_key not in self.blocks:
                        for key in self.blocks:
                            if key.endswith(f'@{method_addr}'):
                                method_key = key
                                break

                    if method_key in self.blocks:
                        methods_found.append((stored_name, method_addr,
                                              method_key, method_decorator))

            i += 1

        init_methods = [(n, a, k, d) for n, a, k, d in methods_found if n == '__init__']
        other_methods = [(n, a, k, d) for n, a, k, d in methods_found if n != '__init__']

        special_methods = [(n, a, k, d) for n, a, k, d in other_methods
                           if n.startswith('__') and n.endswith('__')]
        regular_methods = [(n, a, k, d) for n, a, k, d in other_methods
                           if not (n.startswith('__') and n.endswith('__'))]
        ordered_methods = init_methods + special_methods + regular_methods

        for stored_name, method_addr, method_key, deco in ordered_methods:
            method_code = self._gen_function(stored_name, method_addr, indent=1,
                                              key=method_key, decorator=deco)
            if method_code:
                out.append('')
                out.extend(method_code)
                has_content = True

        if not has_content:
            out.append('    pass')

        return out

    def _gen_class_vars_v4(self, cls_instrs: List['Instr'], is_ctypes: bool) -> List[str]:

        out = []
        emu_stack = []

        def emu_push(v):
            emu_stack.append(v)

        def emu_pop():
            return emu_stack.pop() if emu_stack else '__MISSING__'

        def emu_peek():
            return emu_stack[-1] if emu_stack else '__MISSING__'

        SKIP = set(SKIP_OPCODES) | {'MAKE_CELL', 'MAKE_FUNCTION', 'SET_FUNCTION_ATTRIBUTE',
                                     'STORE_DEREF', 'COPY', 'LOAD_FAST_BORROW',
                                     'LOAD_DEREF', 'RETURN_VALUE', 'RETURN_CONST'}
        i = 0
        while i < len(cls_instrs):
            instr = cls_instrs[i]
            op = instr.opcode
            raw = instr.raw_arg
            arg = instr.arg

            if op in SKIP:
                i += 1
                continue

            if op in ('LOAD_CONST', 'LOAD_SMALL_INT', 'LOAD_ZERO'):
                if op == 'LOAD_ZERO':
                    emu_push('0')
                elif op == 'LOAD_SMALL_INT':
                    emu_push(str(arg))
                else:
                    emu_push(raw.strip())

            elif op in ('LOAD_NAME', 'LOAD_GLOBAL', 'LOAD_FAST',
                        'LOAD_FAST_BORROW', 'LOAD_CLASSDEREF'):
                m = re.search(r'\(([^)]+)\)', raw)
                name = m.group(1).strip() if m else raw.strip('()')
                name = re.sub(r'\s*\+\s*NULL.*$', '', name).strip()
                emu_push(name)

            elif op == 'LOAD_ATTR':
                m = re.search(r'\(([^)]+)\)', raw)
                attr = m.group(1).strip() if m else raw.strip('()')
                attr = re.sub(r'\s*\+\s*NULL.*$', '', attr).strip()
                obj = emu_pop()
                emu_push(f'{obj}.{attr}')

            elif op == 'BUILD_LIST':
                items = [emu_pop() for _ in range(arg or 0)]
                items.reverse()
                emu_push(f'[{", ".join(items)}]')

            elif op == 'BUILD_TUPLE':
                items = [emu_pop() for _ in range(arg or 0)]
                items.reverse()
                if arg == 0:
                    emu_push('()')
                elif arg == 1:
                    emu_push(f'({items[0]},)')
                else:
                    emu_push(f'({", ".join(items)})')

            elif op == 'BUILD_MAP':
                pairs = []
                for _ in range(arg or 0):
                    v = emu_pop()
                    k = emu_pop()
                    pairs.insert(0, f'{k}: {v}')
                emu_push('{' + ', '.join(pairs) + '}')

            elif op == 'CALL':
                nargs = arg or 0
                args_list = [emu_pop() for _ in range(nargs)]
                args_list.reverse()

                while emu_stack and emu_stack[-1] in ('__NULL__', 'None'):
                    emu_stack.pop()
                func = emu_pop()

                if is_ctypes or func in CTYPES_TYPE_MAP:
                    if func == 'POINTER' or func == 'ctypes.POINTER':
                        emu_push(f'ctypes.POINTER({", ".join(args_list)})')
                    elif func in CTYPES_TYPE_MAP:
                        emu_push(f'{CTYPES_TYPE_MAP[func]}({", ".join(args_list)})')
                    else:
                        emu_push(f'{func}({", ".join(args_list)})')
                else:
                    emu_push(f'{func}({", ".join(args_list)})')

            elif op == 'BINARY_OP':
                rhs = emu_pop()
                lhs = emu_pop()
                op_sym = BINARY_OPS.get(arg, '*')
                emu_push(f'{lhs} {op_sym} {rhs}')

            elif op == 'PUSH_NULL':
                emu_push('__NULL__')

            elif op == 'STORE_NAME':
                m = re.search(r'\(([^)]+)\)', raw)
                name = m.group(1).strip() if m else ''
                if name in ('__module__', '__qualname__', '__firstlineno__',
                             '__classcell__', '__classdictcell__', '__static_attributes__',
                             '__doc__', '__class__', '__dict__'):
                    if emu_stack:
                        emu_pop()
                    i += 1
                    continue

                val = emu_pop()
                if val and val not in ('__MISSING__', '__NULL__', '') \
                   and '<code object' not in val:

                    if val == name:
                        i += 1
                        continue

                    if name == '_fields_' and is_ctypes:
                        val = self._format_ctypes_fields(val)
                    out.append(f'{name} = {val}')

            i += 1

        return out

    def _format_ctypes_fields(self, val: str) -> str:

        for ctype, qualified in CTYPES_TYPE_MAP.items():
            if ctype in ('Structure', 'Union', 'POINTER', 'Array'):
                continue

            val = re.sub(r'(?<!\.)\b' + re.escape(ctype) + r'\b', qualified, val)
        return val

    def _extract_fields(self, instrs: List['Instr'], store_idx: int) -> str:

        j = store_idx - 1
        while j >= max(0, store_idx - 50):
            ij = instrs[j]
            if ij.opcode == 'BUILD_LIST':
                n = ij.arg or 0
                pairs = []
                k = j - 1
                count = 0
                while k >= 0 and count < n:
                    ik = instrs[k]
                    if ik.opcode == 'BUILD_TUPLE' and ik.arg == 2:
                        if k >= 2:
                            type_instr = instrs[k-1]
                            name_instr = instrs[k-2]
                            type_val = self._get_load_name(type_instr)
                            name_val = name_instr.raw_arg.strip() if name_instr.opcode == 'LOAD_CONST' else ''
                            pairs.insert(0, f'({name_val}, {type_val})')
                            count += 1
                    k -= 1
                return '[' + ', '.join(pairs) + ']' if pairs else '[]'
            j -= 1
        return '[]'

    def _get_load_name(self, instr: 'Instr') -> str:

        if instr.opcode in ('LOAD_NAME', 'LOAD_GLOBAL', 'LOAD_ATTR'):
            m = re.search(r'\(([^)]+)\)', instr.raw_arg)
            name = m.group(1).strip() if m else instr.raw_arg.strip()
            return re.sub(r'\s*\+\s*NULL.*$', '', name).strip()
        return instr.raw_arg.strip()

    def _gen_function(self, func_name: str, addr: str, indent: int = 0,
                      key: str = None, decorator: str = None) -> List[str]:

        if key is None:
            key = f'{func_name}@{addr}'
        if key not in self.blocks:
            for k in self.blocks:
                if k.endswith(f'@{addr}'):
                    key = k
                    func_name = k.split('@')[0]
                    break
            else:
                if addr:
                    try:
                        addr_int = int(addr, 16)
                        for k in self.blocks:
                            parts = k.split('@')
                            if len(parts) == 2 and parts[1].startswith('0x'):
                                try:
                                    if int(parts[1], 16) == addr_int:
                                        key = k
                                        func_name = parts[0]
                                        break
                                except (ValueError, TypeError):
                                    pass
                    except (ValueError, TypeError):
                        pass
                if key not in self.blocks:
                    return []

        _, func_lines = self.blocks[key]
        instrs = self._parse_instrs(func_lines)

        if not instrs:
            ind = '    ' * indent
            return [f'{ind}def {func_name}():', f'{ind}    pass']

        params = self._extract_params(instrs)

        annotations = self._extract_annotations(instrs)

        free_vars = self._extract_free_vars(instrs)

        ind = '    ' * indent

        if annotations:
            params_str = self._apply_annotations_to_signature(params, annotations)
        else:
            params_str = ', '.join(params)

        return_annotation = annotations.get('return', '')

        out = []

        all_decorators = []
        if decorator:
            all_decorators.append(decorator)

        for deco in all_decorators:
            if deco == 'property':
                out.append(f'{ind}@property')
            elif deco == 'staticmethod':
                out.append(f'{ind}@staticmethod')
            elif deco == 'classmethod':
                out.append(f'{ind}@classmethod')
            elif deco == 'pyqtSignal':
                out.append(f'{ind}@pyqtSignal')
            elif deco == 'abstractmethod':
                out.append(f'{ind}@abstractmethod')
            else:
                out.append(f'{ind}@{deco}')

        if return_annotation:
            out.append(f'{ind}def {func_name}({params_str}) -> {return_annotation}:')
        else:
            out.append(f'{ind}def {func_name}({params_str}):')

        docstring = self._extract_docstring_from_block(instrs)
        if docstring:
            if '\n' in docstring or len(docstring) > 60:
                out.append(f'{ind}    """')
                for doc_line in docstring.splitlines():
                    out.append(f'{ind}    {doc_line}')
                out.append(f'{ind}    """')
            else:
                out.append(f'{ind}    """{docstring}"""')

        func_addr_key = addr if addr else key.split('@')[-1] if key and '@' in key else ''
        nonlocal_vars = []
        if self._closure_tracker and func_addr_key:
            nonlocal_vars = self._closure_tracker.get_nonlocals(func_addr_key)
        if nonlocal_vars:
            out.append(f'{ind}    nonlocal {", ".join(nonlocal_vars)}')

        from engine.translator import BytecodeTranslator
        translator = BytecodeTranslator(self.source)
        exc_table = translator._parse_exception_table_from_instrs(instrs)
        body = translator._smart_translate(instrs, indent + 1, exc_table)

        body = self._inline_nested_functions(body, indent + 1)

        body = self._remove_redundant_assignments(body)

        if not body:
            out.append(f'{ind}    pass')
        else:
            out.extend(body)

        return out

    def _extract_free_vars(self, instrs: List['Instr']) -> List[str]:

        free_vars = []
        seen = set()
        for instr in instrs[:20]:
            if instr.opcode == 'COPY_FREE_VARS':
                continue
            if instr.opcode in ('LOAD_DEREF', 'LOAD_CLASSDEREF'):
                m = re.search(r'\(([^)]+)\)', instr.raw_arg)
                name = m.group(1).strip() if m else instr.raw_arg.strip('()')
                if name and name not in seen and not name.startswith('__'):
                    seen.add(name)
                    free_vars.append(name)
        return free_vars

    def _inline_nested_functions(self, body_lines: List[str], indent: int) -> List[str]:

        FUNC_REF_RE = re.compile(r'^(\s*)(\w+)\s*=\s*<func:(\w+):(0x[0-9a-fA-F]+)[^>]*>$')
        FUNC_REF_INLINE_RE = re.compile(r'<func:(\w+):(0x[0-9a-fA-F]+)[^>]*>')
        result = []

        for line in body_lines:
            m = FUNC_REF_RE.match(line)
            if m:
                line_ind, var_name, func_name, func_addr = m.groups()

                nested_code = self._gen_function(
                    func_name=var_name,
                    addr=func_addr,
                    indent=indent,
                )
                if nested_code:

                    scope_info = (self._closure_tracker.get_scope(func_addr)
                                  if self._closure_tracker else None)
                    if scope_info and scope_info.free_vars:

                        pass
                    result.extend(nested_code)
                    result.append('')
                else:

                    result.append(f'{line_ind}# TODO (closure): {line.strip()}')
                continue

            if FUNC_REF_INLINE_RE.search(line):
                def replace_func_ref(match):
                    fname = match.group(1)
                    faddr = match.group(2)

                    for k in self.blocks:
                        if k.endswith(f'@{faddr}') or k.endswith(f'@{faddr.lower()}'):
                            return fname
                    return fname
                new_line = FUNC_REF_INLINE_RE.sub(replace_func_ref, line)
                result.append(new_line)
                continue

            result.append(line)
        return result

    def _remove_redundant_assignments(self, lines: List[str]) -> List[str]:

        result = []
        for line in lines:
            stripped = line.strip()

            m = re.match(r'^(\w[\w.]*)\s*=\s*(\w[\w.]*)$', stripped)
            if m and m.group(1) == m.group(2):

                continue
            result.append(line)
        return result

    def _extract_params(self, instrs: List['Instr']) -> List[str]:

        var_by_index: Dict[int, str] = {}

        for instr in instrs:
            op = instr.opcode
            if op in ('LOAD_FAST', 'LOAD_FAST_BORROW', 'LOAD_FAST_CHECK', 'STORE_FAST'):

                raw = instr.raw_arg.strip()

                idx = instr.arg if instr.arg is not None else 9999
                m = re.search(r'\(([^)]+)\)', raw)
                name = m.group(1).strip() if m else raw.strip('()')
                name = name.split(',')[0].strip()
                if name and not name.startswith('__') and idx not in var_by_index:
                    var_by_index[idx] = name
            elif op == 'LOAD_FAST_BORROW_LOAD_FAST_BORROW':
                raw = instr.raw_arg.strip()
                m = re.search(r'\(([^)]+)\)', raw)
                if m:
                    parts = [p.strip() for p in m.group(1).split(',')]

                    arg = instr.arg or 0
                    idx1 = arg & 0xFF
                    idx2 = (arg >> 8) & 0xFF
                    indices = [idx1, idx2]
                    for k, name in enumerate(parts[:2]):
                        if name and not name.startswith('__'):
                            var_by_index[indices[k]] = name

        if not var_by_index:
            return []

        sorted_params = [name for _, name in sorted(var_by_index.items())]

        self_names = {'self', 'cls', 'mcs'}
        self_idx = None
        for i, p in enumerate(sorted_params):
            if p in self_names:
                self_idx = i
                break
        if self_idx is not None and self_idx > 0:
            sp = sorted_params.pop(self_idx)
            sorted_params.insert(0, sp)

        seen = set()
        result = []
        for p in sorted_params:
            if p not in seen:
                seen.add(p)
                result.append(p)
        return result

    def _extract_annotations(self, instrs: List['Instr']) -> Dict[str, str]:

        annotations: Dict[str, str] = {}
        i = 0
        while i < len(instrs):
            instr = instrs[i]

            if instr.opcode == 'SET_FUNCTION_ATTRIBUTE' and instr.arg == 4:

                j = i - 1
                while j >= max(0, i - 30):
                    ij = instrs[j]
                    if ij.opcode in ('BUILD_CONST_KEY_MAP',):

                        nkeys = ij.arg or 0

                        keys_instr = instrs[j - 1] if j > 0 else None
                        if keys_instr and keys_instr.opcode == 'LOAD_CONST':
                            keys_raw = keys_instr.raw_arg.strip()
                            keys = re.findall(r"'([^']+)'", keys_raw)

                            vals = []
                            for k in range(j - 1 - nkeys, j - 1):
                                if 0 <= k < len(instrs):
                                    vals.append(self._type_annotation_from_instr(instrs[k]))
                            for name, typ in zip(keys, vals):
                                if typ:
                                    annotations[name] = typ
                        break
                    elif ij.opcode == 'BUILD_MAP':
                        nkeys = ij.arg or 0

                        for k in range(j - nkeys * 2, j, 2):
                            if k >= 0 and k + 1 < len(instrs):
                                key_instr = instrs[k]
                                val_instr = instrs[k + 1]
                                key = re.search(r"'([^']+)'", key_instr.raw_arg or '')
                                if key:
                                    typ = self._type_annotation_from_instr(val_instr)
                                    if typ:
                                        annotations[key.group(1)] = typ
                        break
                    j -= 1
            i += 1
        return annotations

    def _type_annotation_from_instr(self, instr: 'Instr') -> Optional[str]:

        if instr is None:
            return None
        op = instr.opcode
        raw = instr.raw_arg.strip()
        if op in ('LOAD_GLOBAL', 'LOAD_NAME', 'LOAD_FAST', 'LOAD_DEREF'):
            m = re.search(r'\(([^)]+)\)', raw)
            name = m.group(1).strip() if m else raw.strip('()')
            name = re.sub(r'\s*\+\s*NULL.*$', '', name).strip()
            if name and re.match(r'^[A-Za-z_][\w.]*$', name):
                return name
        elif op == 'LOAD_CONST':

            if raw in ("'None'", 'None'):
                return 'None'
            m = re.search(r"'([A-Za-z_][\w.]*)'", raw)
            if m:
                return m.group(1)
        elif op == 'LOAD_ATTR':

            m = re.search(r'\(([^)]+)\)', raw)
            if m:
                attr = re.sub(r'\s*\+\s*NULL.*$', '', m.group(1)).strip()
                return attr
        return None

    def _apply_annotations_to_signature(self, params: List[str],
                                         annotations: Dict[str, str]) -> str:

        parts = []
        for p in params:

            base = p.split('=')[0].strip().lstrip('*')
            if base in annotations:
                typ = annotations[base]
                if '=' in p:
                    eq_idx = p.index('=')
                    parts.append(f'{p[:eq_idx].strip()}: {typ} = {p[eq_idx+1:].strip()}')
                else:
                    prefix = p[:len(p)-len(p.lstrip('*'))]
                    parts.append(f'{prefix}{base}: {typ}')
            else:
                parts.append(p)
        return ', '.join(parts)

    @staticmethod
    def _fold_fstring_concatenations(lines: List[str]) -> List[str]:

        STR_CALL_RE = re.compile(r'\bstr\(([^()]+)\)')
        CONCAT_RE = re.compile(
            r'''(?:"[^"]*"|'[^']*'|\bstr\([^()]+\))'''
            r'''(?:\s*\+\s*(?:"[^"]*"|'[^']*'|\bstr\([^()]+\)))+'''
        )

        result = []
        for line in lines:
            if '+ str(' not in line and 'str(' not in line:
                result.append(line)
                continue

            new_line = line
            for m in CONCAT_RE.finditer(line):
                seg = m.group(0)
                if 'str(' not in seg:
                    continue
                parts = re.split(r'\s*\+\s*', seg)
                fstr_parts = []
                for part in parts:
                    part = part.strip()
                    ms = STR_CALL_RE.match(part)
                    if ms:
                        fstr_parts.append('{' + ms.group(1).strip() + '}')
                    elif (part.startswith('"') and part.endswith('"')):
                        inner = part[1:-1]
                        fstr_parts.append(inner.replace('{', '{{').replace('}', '}}'))
                    elif (part.startswith("'") and part.endswith("'")):
                        inner = part[1:-1]
                        fstr_parts.append(inner.replace('{', '{{').replace('}', '}}'))
                    else:

                        fstr_parts = None
                        break
                if fstr_parts is not None:
                    folded = 'f"' + ''.join(fstr_parts) + '"'
                    new_line = new_line.replace(seg, folded, 1)
            result.append(new_line)
        return result

    def _refine_imports(self, imports: List[str], all_code: str) -> List[str]:

        result = []
        for imp in imports:
            m = re.match(r'^import\s+(\S+)$', imp.strip())
            if not m:
                result.append(imp)
                continue
            module = m.group(1)

            attr_uses = re.findall(rf'\b{re.escape(module)}\.(\w+)\b', all_code)

            direct_uses_re = re.compile(rf'(?<!\w\.)\b{re.escape(module)}\b(?!\s*\.)')
            direct_uses = direct_uses_re.findall(all_code)

            code_without_imports = '\n'.join(
                l for l in all_code.splitlines()
                if not l.strip().startswith('import ') and not l.strip().startswith('from ')
            )
            attr_uses_code = re.findall(rf'\b{re.escape(module)}\.(\w+)\b', code_without_imports)
            direct_uses_code = direct_uses_re.findall(code_without_imports)

            unique_attrs = list(dict.fromkeys(attr_uses_code))
            n_attrs = len(unique_attrs)
            n_direct = len(direct_uses_code)

            if n_attrs > 0 and n_direct == 0 and n_attrs <= 3:
                from_imp = f'from {module} import {", ".join(unique_attrs)}'
                result.append(from_imp)
            else:
                result.append(imp)
        return result

    def _detect_decorators_from_instrs(self, instrs: List['Instr'],
                                        func_start_idx: int) -> List[str]:

        decorators = []

        i = func_start_idx - 1

        decorator_candidates = []

        j = func_start_idx - 1
        while j >= max(0, func_start_idx - 30):
            ij = instrs[j]
            op = ij.opcode
            if op in ('LOAD_GLOBAL', 'LOAD_NAME', 'LOAD_DEREF', 'LOAD_ATTR'):
                m = re.search(r'\(([^)]+)\)', ij.raw_arg)
                if m:
                    name = re.sub(r'\s*\+\s*NULL.*$', '', m.group(1)).strip()
                    KNOWN_DECOS = {
                        'property', 'staticmethod', 'classmethod', 'abstractmethod',
                        'override', 'lru_cache', 'cache', 'cached_property',
                        'dataclass', 'total_ordering', 'wraps', 'functools.wraps',
                        'contextmanager', 'asynccontextmanager',
                    }

                    has_call = any(
                        instrs[k].opcode == 'CALL' and instrs[k].arg in (1, 2)
                        for k in range(func_start_idx, min(func_start_idx + 15, len(instrs)))
                    )
                    if has_call and (name in KNOWN_DECOS or op == 'LOAD_ATTR'):
                        decorator_candidates.insert(0, name)
                        break
                    elif name in KNOWN_DECOS:
                        decorator_candidates.insert(0, name)
                        break
            elif op in ('LOAD_BUILD_CLASS', 'IMPORT_NAME', 'STORE_NAME', 'STORE_FAST'):
                break
            j -= 1

        return decorator_candidates

    def _extract_docstring_from_block(self, instrs: List['Instr']) -> Optional[str]:

        for j, instr in enumerate(instrs[:10]):
            if instr.opcode != 'LOAD_CONST':
                if instr.opcode not in SKIP_OPCODES_SET and instr.opcode not in (
                    'COPY_FREE_VARS', 'MAKE_CELL', 'RESUME', 'RESUME_CHECK'
                ):
                    break
                continue
            val = instr.raw_arg.strip()

            if not ((val.startswith("'") and val.endswith("'")) or
                    (val.startswith('"') and val.endswith('"'))):
                break

            if j + 1 >= len(instrs):
                break
            next_instr = instrs[j + 1]
            if next_instr.opcode == 'POP_TOP':

                doc_inner = val[1:-1]
                return doc_inner
            elif next_instr.opcode == 'STORE_NAME':
                m = re.search(r'\(([^)]+)\)', next_instr.raw_arg)
                if m and m.group(1).strip() == '__doc__':
                    doc_inner = val[1:-1]
                    return doc_inner
        return None

