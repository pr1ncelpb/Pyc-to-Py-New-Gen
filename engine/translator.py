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

class BytecodeTranslator:

    def __init__(self, source: str, verbose: bool = False):
        self.source = source
        self.verbose = verbose

        self.code_objects: Dict[str, Tuple] = {}

        self.disassemblies: Dict[str, List[str]] = {}
        self._parse_code_objects()

    def _parse_code_objects(self):

        lines = self.source.splitlines()

        self._find_classes_from_module(lines)

    def _find_classes_from_module(self, lines):

        i = 0
        while i < len(lines):
            l = lines[i].strip()
            if 'LOAD_BUILD_CLASS' in l:

                j = i + 1
                func_addr = None
                class_name = None
                bases = []
                while j < min(i + 20, len(lines)):
                    lj = lines[j].strip()
                    m = re.search(r'LOAD_CONST\s+\d+\s+\(<code object (\w+) at (0x[0-9a-fA-F]+)', lj)
                    if m:
                        class_name = m.group(1)
                        func_addr = m.group(2).lower()
                    m2 = re.search(r'LOAD_CONST\s+\d+\s+\(\'(\w+)\'\)', lj)
                    if m2 and not class_name:
                        class_name = m2.group(1)
                    if 'LOAD_NAME' in lj or 'LOAD_GLOBAL' in lj:
                        m3 = re.search(r'\((\w+)\)', lj)
                        if m3:
                            name = m3.group(1)
                            if name not in ('__build_class__',) and class_name:
                                bases.append(name)
                    if 'STORE_NAME' in lj or 'STORE_FAST' in lj:
                        m4 = re.search(r'\((\w+)\)', lj)
                        if m4:
                            stored = m4.group(1)
                            if class_name and stored == class_name:
                                if func_addr:
                                    self.code_objects[func_addr] = (class_name, None, bases)
                        break
                    j += 1
            i += 1

    def _parse_instrs(self, lines: List[str]) -> List[Instr]:
        instrs = []

        RE = re.compile(
            r'^'
            r'\s*(?:(\d+|--)\s+)?'
            r'(?:\s*\d+\s+)?'
            r'(?:(L\w+|[A-Z]\d+):\s*)?'
            r'([A-Z][A-Z0-9_]+)'
            r'(?:\s+(-?\d+))?'
            r'(?:\s+\((.*)\))?'
            r'\s*$'
        )
        EXC_RE = re.compile(r'^\s*(L\w+)\s+to\s+(L\w+)\s+->\s+(L\w+)')
        in_exc_table = False
        for raw in lines:
            if not raw.strip():
                continue
            stripped = raw.strip()

            if stripped.startswith('ExceptionTable'):
                in_exc_table = True
                continue

            if in_exc_table:
                m_exc = EXC_RE.match(raw)
                if m_exc:

                    instrs.append(Instr(
                        lineno=None, label=None,
                        opcode='__EXCTABLE_ENTRY__',
                        arg=None,
                        raw_arg=f'{m_exc.group(1)},{m_exc.group(2)},{m_exc.group(3)}',
                        src_line=raw,
                    ))
                    continue
                elif stripped and not stripped.startswith('L'):
                    in_exc_table = False
                else:
                    continue

            if stripped.startswith('Disassembly of'):
                continue
            if stripped.startswith('--'):

                m = RE.match(raw)
                if m:
                    lineno, label, opcode, arg_s, comment = m.groups()
                    arg = int(arg_s) if arg_s is not None else None
                    instrs.append(Instr(
                        lineno=lineno,
                        label=label,
                        opcode=opcode,
                        arg=arg,
                        raw_arg=comment or '',
                        src_line=raw,
                    ))
                continue
            m = RE.match(raw)
            if not m:
                continue
            lineno_s, label, opcode, arg_s, comment = m.groups()
            lineno = None
            if lineno_s and lineno_s != '--':
                try:
                    lineno = int(lineno_s)
                except ValueError:
                    pass
            arg = int(arg_s) if arg_s is not None else None
            instrs.append(Instr(
                lineno=lineno,
                label=label,
                opcode=opcode,
                arg=arg,
                raw_arg=comment or '',
                src_line=raw,
            ))

        for instr in instrs:
            normalized = TIER2_OPCODE_NORMALIZE.get(instr.opcode)
            if normalized:
                instr.opcode = normalized
        return instrs

    class StackEmulator:
        def __init__(self, translator, instrs, context='function', indent=1):
            self.T = translator
            self.instrs = instrs
            self.stack: List[StackVal] = []
            self.context = context
            self.indent = indent
            self.lines: List[str] = []
            self.pending_assign: Optional[str] = None
            self._kw_names: Optional[List[str]] = None
            self._build_map_stack: List[dict] = []
            self._build_list_stack: List[list] = []
            self._build_set_stack: List[set] = []
            self._for_iters: List[str] = []
            self._exception_handlers: Dict[str, str] = {}
            self._labels_seen: set = set()
            self._jumped_labels: set = set()
            self._current_lineno: Optional[int] = None
            self._if_depth = 0
            self._loop_depth = 0
            self._last_test_expr: Optional[str] = None
            self._block_stack: List[str] = []

        def push(self, val: str, is_null=False, is_callable=False):
            self.stack.append(StackVal(val, is_null, is_callable))

        def pop(self) -> str:
            if self.stack:
                return self.stack.pop().expr
            return '__MISSING__'

        def peek(self) -> str:
            if self.stack:
                return self.stack[-1].expr
            return '__MISSING__'

        def pop_n(self, n: int) -> List[str]:

            if n == 0:
                return []
            items = []
            for _ in range(n):
                items.append(self.pop())
            items.reverse()
            return items

        def emit(self, line: str, indent_delta=0):
            ind = '    ' * (self.indent + indent_delta)
            self.lines.append(ind + line)

        def emit_raw(self, line: str):
            self.lines.append(line)

        def _clean_expr(self, expr: str) -> str:

            expr = re.sub(r'\s*\+\s*__NULL__', '', expr)
            expr = re.sub(r'__NULL__\s*\+\s*', '', expr)
            return expr.strip()

        def _format_call(self, func: str, args: List[str], kwargs: Optional[Dict] = None) -> str:

            func = re.sub(r'\s*\+\s*NULL\|self\s*$', '', func).strip()
            func = re.sub(r'\s*\+\s*NULL\s*$', '', func).strip()
            all_args = list(args)
            if kwargs:
                for k, v in kwargs.items():
                    all_args.append(f'{k}={v}')
            return f"{func}({', '.join(all_args)})"

        def run(self) -> List[str]:

            i = 0
            while i < len(self.instrs):
                instr = self.instrs[i]
                if instr.lineno:
                    self._current_lineno = instr.lineno
                i = self._exec(instr, i)
            return self.lines

        def _exec(self, instr: Instr, idx: int) -> int:

            op = instr.opcode
            arg = instr.arg
            raw = instr.raw_arg

            if op in SKIP_OPCODES:
                return idx + 1

            if op in ('LOAD_FAST', 'LOAD_FAST_BORROW'):
                name = raw.split(',')[0].strip().strip('()')

                name = re.sub(r'^\(', '', name).strip()
                name = name.strip(')')
                self.push(name)

            elif op == 'LOAD_FAST_BORROW_LOAD_FAST_BORROW':

                parts = raw.strip('()').split(',')
                var1 = parts[0].strip()
                var2 = parts[1].strip() if len(parts) > 1 else '__?__'

                self.push(var2)
                self.push(var1)

            elif op == 'STORE_FAST_STORE_FAST':

                parts = raw.strip('()').split(',')
                var1 = parts[0].strip()
                var2 = parts[1].strip() if len(parts) > 1 else '__?__'
                val2 = self.pop()
                val1 = self.pop()
                self.emit(f'{var1}, {var2} = {val1}, {val2}')

            elif op in ('LOAD_CONST', 'LOAD_SMALL_INT', 'LOAD_ZERO'):
                if op == 'LOAD_ZERO':
                    self.push('0')
                elif op == 'LOAD_SMALL_INT':
                    self.push(str(arg))
                else:
                    val = self._format_const(raw)
                    self.push(val)

            elif op == 'LOAD_COMMON_CONSTANT':

                const_map = {0: 'None', 1: 'True', 2: 'False', 3: 'Ellipsis', 4: '__debug__'}
                self.push(const_map.get(arg, f'__COMMON_{arg}__'))

            elif op in ('LOAD_NAME', 'LOAD_FAST_CHECK'):
                m = re.search(r'\((\w+)\)', raw)
                name = m.group(1) if m else raw.strip('()')
                self.push(name)

            elif op == 'LOAD_GLOBAL':

                raw_clean = raw.strip('()')
                is_callable = 'NULL' in raw_clean
                name = raw_clean
                name = re.sub(r'^NULL\s*\+\s*', '', name).strip()
                name = re.sub(r'\s*\+\s*NULL\s*$', '', name).strip()
                name = name.strip('()')
                self.push(name, is_callable=is_callable)

            elif op == 'LOAD_ATTR':

                raw_clean = raw.strip('()')
                is_method = 'NULL|self' in raw_clean or 'NULL + ' in raw_clean

                attr = raw_clean

                attr = re.sub(r'^NULL\|self\s*\+\s*', '', attr).strip()

                attr = re.sub(r'\s*\+\s*NULL\|self\s*$', '', attr).strip()

                attr = re.sub(r'^NULL\s*\+\s*', '', attr).strip()

                attr = re.sub(r'\s*\+\s*NULL\s*$', '', attr).strip()
                attr = attr.strip('()')
                obj = self.pop()
                expr = f'{obj}.{attr}'
                self.push(expr, is_callable=is_method)

            elif op == 'LOAD_DEREF':
                m = re.search(r'\((\w+)\)', raw)
                name = m.group(1) if m else raw.strip('()')
                self.push(name)

            elif op == 'LOAD_CLOSURE':

                m = re.search(r'\((\w+)\)', raw)
                name = m.group(1) if m else raw.strip('()')
                self.push(name)

            elif op == 'LOAD_CLASSDEREF':
                m = re.search(r'\((\w+)\)', raw)
                name = m.group(1) if m else raw.strip('()')
                self.push(name)

            elif op == 'LOAD_LOCALS':
                self.push('__locals__')

            elif op == 'LOAD_SUPER_ATTR':

                attr = re.sub(r'\s*\+\s*NULL\|self\s*$', '', raw.strip('()')).strip()
                attr = re.sub(r'\s*\+\s*NULL\s*$', '', attr).strip()

                self_obj = self.pop()
                super_type = self.pop()
                super_obj = self.pop()
                if super_type and super_type != 'super':
                    self.push(f'super({super_type}, {self_obj}).{attr}', is_callable=True)
                else:
                    self.push(f'super().{attr}', is_callable=True)

            elif op == 'LOAD_BUILD_CLASS':
                self.push('__build_class__')

            elif op == 'LOAD_SPECIAL':

                special_map = {0: '__enter__', 1: '__exit__'}
                attr = special_map.get(arg, f'__special_{arg}__')
                obj = self.pop()
                self.push(f'{obj}.{attr}', is_callable=True)

            elif op in ('STORE_NAME', 'STORE_FAST', 'STORE_DEREF', 'STORE_GLOBAL'):
                m = re.search(r'\((\w+)\)', raw)
                name = m.group(1) if m else raw.strip('()')
                val = self.pop()

                if name in ('__module__', '__qualname__', '__firstlineno__',
                            '__classcell__', '__classdictcell__', '__locals__',
                            '__static_attributes__', '__classdict__'):
                    pass
                elif val == '__locals__':
                    pass
                else:
                    val = self._clean_expr(val)
                    self.emit(f'{name} = {val}')

            elif op == 'STORE_ATTR':
                m = re.search(r'\((\w+)\)', raw)
                attr = m.group(1) if m else raw.strip('()')

                obj = self.pop()
                val = self.pop()
                val = self._clean_expr(val)
                self.emit(f'{obj}.{attr} = {val}')

            elif op == 'STORE_SUBSCR':
                key = self.pop()
                obj = self.pop()
                val = self.pop()
                val = self._clean_expr(val)
                self.emit(f'{obj}[{key}] = {val}')

            elif op == 'DELETE_FAST':
                m = re.search(r'\((\w+)\)', raw)
                name = m.group(1) if m else raw.strip('()')
                self.emit(f'del {name}')

            elif op == 'DELETE_ATTR':
                m = re.search(r'\((\w+)\)', raw)
                attr = m.group(1) if m else raw.strip('()')
                obj = self.pop()
                self.emit(f'del {obj}.{attr}')

            elif op == 'DELETE_SUBSCR':
                key = self.pop()
                obj = self.pop()
                self.emit(f'del {obj}[{key}]')

            elif op == 'PUSH_NULL':

                self.push('__NULL__', is_null=True)

            elif op == 'CALL':
                nargs = arg
                args = self.pop_n(nargs)

                while self.stack and self.stack[-1].is_null:
                    self.stack.pop()
                func = self.pop()

                while self.stack and self.stack[-1].is_null:
                    self.stack.pop()

                kwargs = {}
                if self._kw_names:
                    kw_count = len(self._kw_names)
                    kw_vals = args[-kw_count:]
                    args = args[:-kw_count]
                    kwargs = dict(zip(self._kw_names, kw_vals))
                    self._kw_names = None
                expr = self._format_call(func, args, kwargs if kwargs else None)
                self.push(expr)

            elif op == 'CALL_KW':

                kw_tuple = self.pop()
                nargs = arg
                all_args = self.pop_n(nargs)

                while self.stack and self.stack[-1].is_null:
                    self.stack.pop()
                func = self.pop()

                while self.stack and self.stack[-1].is_null:
                    self.stack.pop()

                kw_names = []
                m = re.findall(r"'(\w+)'", kw_tuple)
                if m:
                    kw_names = m
                kwargs = {}
                if kw_names:
                    kw_count = len(kw_names)
                    kw_vals = all_args[-kw_count:]
                    all_args = all_args[:-kw_count]
                    kwargs = dict(zip(kw_names, kw_vals))
                expr = self._format_call(func, all_args, kwargs if kwargs else None)
                self.push(expr)

            elif op == 'KW_NAMES':

                names = re.findall(r"'(\w+)'", raw)
                self._kw_names = names

            elif op in ('CALL_FUNCTION', 'CALL_FUNCTION_EX'):
                nargs = arg
                if op == 'CALL_FUNCTION_EX':
                    kwargs_dict = self.pop() if arg & 1 else None
                    args_tuple = self.pop()
                    func = self.pop()
                    if self.stack and self.stack[-1].is_null:
                        self.stack.pop()
                    if kwargs_dict and kwargs_dict != '__NULL__':
                        self.push(f'{func}(*{args_tuple}, **{kwargs_dict})')
                    else:
                        self.push(f'{func}(*{args_tuple})')
                else:
                    args = self.pop_n(nargs)
                    func = self.pop()
                    self.push(self._format_call(func, args))

            elif op == 'CALL_INTRINSIC_1':

                intrinsics = {
                    1: 'print', 2: 'iter', 3: 'print', 4: 'list',
                    5: 'reversed', 6: 'tuple', 7: 'set',
                }
                fname = intrinsics.get(arg, f'__intrinsic_{arg}__')
                val = self.pop()
                self.push(f'{fname}({val})')

            elif op == 'CALL_INTRINSIC_2':
                val2 = self.pop()
                val1 = self.pop()
                self.push(f'__intrinsic2_{arg}__({val1}, {val2})')

            elif op == 'POP_TOP':
                val = self.pop()
                val = self._clean_expr(val)

                if val and val not in ('None', '__NULL__', '__MISSING__', '__locals__'):
                    if '(' in val or '=' in val:
                        self.emit(val)

            elif op == 'POP_JUMP_IF_TRUE':
                cond = self.pop()

                self._last_test_expr = cond

                label = raw if raw else f'L{arg}'
                self.emit(f'if not {cond}:')
                self._if_depth += 1

            elif op == 'POP_JUMP_IF_FALSE':
                cond = self.pop()
                self._last_test_expr = cond
                label = raw if raw else f'L{arg}'
                self.emit(f'if {cond}:')
                self._if_depth += 1

            elif op == 'JUMP_IF_TRUE_OR_POP':
                cond = self.peek()
                self._last_test_expr = cond

            elif op == 'JUMP_IF_FALSE_OR_POP':
                cond = self.peek()
                self._last_test_expr = cond

            elif op in ('RETURN_VALUE',):
                val = self.pop()
                val = self._clean_expr(val)
                if val and val not in ('None',):
                    self.emit(f'return {val}')
                else:
                    self.emit('return')

            elif op == 'RETURN_CONST':
                val = self._format_const(raw)
                if val and val != 'None':
                    self.emit(f'return {val}')
                else:
                    self.emit('return')

            elif op == 'RETURN_GENERATOR':

                pass

            elif op == 'BINARY_OP':
                rhs = self.pop()
                lhs = self.pop()
                if arg in INPLACE_OPS:
                    op_str = INPLACE_MAP[arg]
                    self.emit(f'{lhs} {op_str} {rhs}')
                    self.push(lhs)
                else:
                    op_str = BINARY_OPS.get(arg, f'__op{arg}__')
                    self.push(f'{lhs} {op_str} {rhs}')

            elif op in ('BINARY_ADD', 'INPLACE_ADD'):
                rhs = self.pop()
                lhs = self.pop()
                if op.startswith('INPLACE'):
                    self.emit(f'{lhs} += {rhs}')
                    self.push(lhs)
                else:
                    self.push(f'{lhs} + {rhs}')

            elif op in ('BINARY_SUBTRACT', 'INPLACE_SUBTRACT'):
                rhs = self.pop()
                lhs = self.pop()
                if op.startswith('INPLACE'):
                    self.emit(f'{lhs} -= {rhs}')
                    self.push(lhs)
                else:
                    self.push(f'{lhs} - {rhs}')

            elif op in ('BINARY_MULTIPLY', 'INPLACE_MULTIPLY'):
                rhs = self.pop()
                lhs = self.pop()
                if op.startswith('INPLACE'):
                    self.emit(f'{lhs} *= {rhs}')
                    self.push(lhs)
                else:
                    self.push(f'{lhs} * {rhs}')

            elif op in ('BINARY_TRUE_DIVIDE', 'INPLACE_TRUE_DIVIDE'):
                rhs = self.pop()
                lhs = self.pop()
                if op.startswith('INPLACE'):
                    self.emit(f'{lhs} /= {rhs}')
                    self.push(lhs)
                else:
                    self.push(f'{lhs} / {rhs}')

            elif op in ('BINARY_FLOOR_DIVIDE', 'INPLACE_FLOOR_DIVIDE'):
                rhs = self.pop()
                lhs = self.pop()
                if op.startswith('INPLACE'):
                    self.emit(f'{lhs} //= {rhs}')
                    self.push(lhs)
                else:
                    self.push(f'{lhs} // {rhs}')

            elif op in ('BINARY_MODULO', 'INPLACE_MODULO'):
                rhs = self.pop()
                lhs = self.pop()
                if op.startswith('INPLACE'):
                    self.emit(f'{lhs} %= {rhs}')
                    self.push(lhs)
                else:
                    self.push(f'{lhs} % {rhs}')

            elif op in ('BINARY_POWER', 'INPLACE_POWER'):
                rhs = self.pop()
                lhs = self.pop()
                if op.startswith('INPLACE'):
                    self.emit(f'{lhs} **= {rhs}')
                    self.push(lhs)
                else:
                    self.push(f'{lhs} ** {rhs}')

            elif op in ('BINARY_OR', 'INPLACE_OR'):
                rhs = self.pop()
                lhs = self.pop()
                if op.startswith('INPLACE'):
                    self.emit(f'{lhs} |= {rhs}')
                    self.push(lhs)
                else:
                    self.push(f'{lhs} | {rhs}')

            elif op in ('BINARY_AND', 'INPLACE_AND'):
                rhs = self.pop()
                lhs = self.pop()
                if op.startswith('INPLACE'):
                    self.emit(f'{lhs} &= {rhs}')
                    self.push(lhs)
                else:
                    self.push(f'{lhs} & {rhs}')

            elif op in ('BINARY_XOR', 'INPLACE_XOR'):
                rhs = self.pop()
                lhs = self.pop()
                if op.startswith('INPLACE'):
                    self.emit(f'{lhs} ^= {rhs}')
                    self.push(lhs)
                else:
                    self.push(f'{lhs} ^ {rhs}')

            elif op in ('BINARY_LSHIFT', 'INPLACE_LSHIFT'):
                rhs = self.pop()
                lhs = self.pop()
                if op.startswith('INPLACE'):
                    self.emit(f'{lhs} <<= {rhs}')
                    self.push(lhs)
                else:
                    self.push(f'{lhs} << {rhs}')

            elif op in ('BINARY_RSHIFT', 'INPLACE_RSHIFT'):
                rhs = self.pop()
                lhs = self.pop()
                if op.startswith('INPLACE'):
                    self.emit(f'{lhs} >>= {rhs}')
                    self.push(lhs)
                else:
                    self.push(f'{lhs} >> {rhs}')

            elif op == 'BINARY_SUBSCR':
                key = self.pop()
                obj = self.pop()
                self.push(f'{obj}[{key}]')

            elif op == 'BINARY_SLICE':
                stop = self.pop()
                start = self.pop()
                container = self.pop()
                start_str = '' if start in ('None', '') else start
                stop_str = '' if stop in ('None', '') else stop
                self.push(f'{container}[{start_str}:{stop_str}]')

            elif op == 'COMPARE_OP':
                op_str = COMPARE_OPS.get(arg, '==')
                rhs = self.pop()
                lhs = self.pop()
                self.push(f'{lhs} {op_str} {rhs}')

            elif op == 'IS_OP':
                rhs = self.pop()
                lhs = self.pop()
                if arg == 1:
                    self.push(f'{lhs} is not {rhs}')
                else:
                    self.push(f'{lhs} is {rhs}')

            elif op == 'CONTAINS_OP':
                rhs = self.pop()
                lhs = self.pop()
                if arg == 1:
                    self.push(f'{lhs} not in {rhs}')
                else:
                    self.push(f'{lhs} in {rhs}')

            elif op == 'TO_BOOL':

                pass

            elif op == 'UNARY_NOT':
                val = self.pop()
                self.push(f'not {val}')

            elif op == 'UNARY_NEGATIVE':
                val = self.pop()
                self.push(f'-{val}')

            elif op == 'UNARY_POSITIVE':
                val = self.pop()
                self.push(f'+{val}')

            elif op == 'UNARY_INVERT':
                val = self.pop()
                self.push(f'~{val}')

            elif op == 'BUILD_TUPLE':
                items = self.pop_n(arg)
                if arg == 0:
                    self.push('()')
                elif arg == 1:
                    self.push(f'({items[0]},)')
                else:
                    self.push(f'({", ".join(items)})')

            elif op == 'BUILD_LIST':
                items = self.pop_n(arg)
                self.push(f'[{", ".join(items)}]')

            elif op == 'BUILD_SET':
                items = self.pop_n(arg)
                if arg == 0:
                    self.push('set()')
                else:
                    self.push('{' + ', '.join(items) + '}')

            elif op == 'BUILD_MAP':

                pairs = []
                for _ in range(arg):
                    v = self.pop()
                    k = self.pop()
                    pairs.insert(0, f'{k}: {v}')
                self.push('{' + ', '.join(pairs) + '}')

            elif op == 'BUILD_CONST_KEY_MAP':
                keys_tuple = self.pop()
                vals = self.pop_n(arg)
                keys = re.findall(r"'(\w+)'", keys_tuple)
                if len(keys) == len(vals):
                    pairs = [f"'{k}': {v}" for k, v in zip(keys, vals)]
                    self.push('{' + ', '.join(pairs) + '}')
                else:
                    self.push(f'dict(zip({keys_tuple}, [{", ".join(vals)}]))')

            elif op == 'MAP_ADD':
                val = self.pop()
                key = self.pop()

                idx2 = len(self.stack) - arg
                if 0 <= idx2 < len(self.stack):
                    existing = self.stack[idx2].expr
                    if existing == '{}':
                        self.stack[idx2].expr = '{' + f'{key}: {val}' + '}'
                    elif existing.startswith('{') and existing.endswith('}'):
                        inner = existing[1:-1]
                        self.stack[idx2].expr = '{' + inner + (', ' if inner else '') + f'{key}: {val}' + '}'
                    else:
                        self.stack[idx2].expr += f'  # [{key}] = {val}'

            elif op == 'DICT_UPDATE':
                update = self.pop()

                idx2 = len(self.stack) - arg
                if 0 <= idx2 < len(self.stack):
                    existing = self.stack[idx2].expr
                    if existing == '{}':
                        self.stack[idx2].expr = update
                    elif existing.startswith('{') and existing.endswith('}') and update.startswith('{') and update.endswith('}'):

                        inner1 = existing[1:-1].strip()
                        inner2 = update[1:-1].strip()
                        combined = (inner1 + ', ' + inner2).strip(', ')
                        self.stack[idx2].expr = '{' + combined + '}'
                    else:
                        self.stack[idx2].expr = f'{{**{existing}, **{update}}}'

            elif op == 'BUILD_STRING':
                parts = self.pop_n(arg)

                result = 'f"'
                for part in parts:
                    if part.startswith(("'", '"')):

                        inner = part[1:-1] if len(part) >= 2 else ''
                        result += inner
                    else:
                        result += '{' + part + '}'
                result += '"'
                self.push(result)

            elif op == 'FORMAT_SIMPLE':
                val = self.pop()
                self.push(f'{{{val}}}')

            elif op == 'FORMAT_WITH_SPEC':
                spec = self.pop()
                val = self.pop()

                spec = spec.strip("'\"")
                self.push(f'{{{val}:{spec}}}')

            elif op in ('LIST_APPEND', 'SET_ADD'):
                val = self.pop()
                idx2 = len(self.stack) - arg
                if 0 <= idx2 < len(self.stack):
                    existing = self.stack[idx2].expr
                    if existing.startswith('[') and existing.endswith(']'):
                        inner = existing[1:-1]
                        self.stack[idx2].expr = '[' + (inner + ', ' if inner else '') + val + ']'
                    elif existing.startswith('{') and existing.endswith('}'):
                        inner = existing[1:-1]
                        self.stack[idx2].expr = '{' + (inner + ', ' if inner else '') + val + '}'

            elif op == 'SET_UPDATE':
                update = self.pop()
                idx2 = len(self.stack) - arg
                if 0 <= idx2 < len(self.stack):
                    existing = self.stack[idx2].expr
                    if existing == 'set()':
                        self.stack[idx2].expr = f'set({update})'
                    else:
                        self.stack[idx2].expr = f'{existing} | {update}'

            elif op == 'LIST_EXTEND':
                update = self.pop()
                idx2 = len(self.stack) - arg
                if 0 <= idx2 < len(self.stack):
                    existing = self.stack[idx2].expr
                    if existing == '[]':
                        self.stack[idx2].expr = f'list({update})'
                    elif existing.startswith('[') and existing.endswith(']'):
                        inner = existing[1:-1]
                        if update.startswith('[') and update.endswith(']'):
                            inner2 = update[1:-1]
                            self.stack[idx2].expr = '[' + (inner + ', ' if inner else '') + inner2 + ']'
                        else:
                            self.stack[idx2].expr = f'[*{existing}, *{update}]'
                    else:
                        self.stack[idx2].expr = f'{existing} + {update}'

            elif op == 'GET_ITER':

                pass

            elif op == 'FOR_ITER':

                iterable = self.peek()

                self.push(f'__for_iter__({iterable})')

            elif op == 'STORE_FAST' if False else '':
                pass

            elif op in ('END_FOR', 'POP_ITER'):
                pass

            elif op == 'IMPORT_NAME':
                m = re.search(r'\((\S+)\)', raw)
                module = m.group(1) if m else raw.strip('()')
                fromlist = self.pop()
                level = self.pop()

                if fromlist == 'None' or fromlist == '()' or not fromlist:
                    self.push(f'__import__({module})')
                    self._pending_import = ('import', module, level)
                else:
                    names = re.findall(r"'(\w+)'", fromlist)
                    self._pending_import = ('from', module, names, level)
                    self.push(module)

            elif op == 'IMPORT_FROM':
                m = re.search(r'\((\w+)\)', raw)
                name = m.group(1) if m else raw.strip('()')

                module = self.peek()
                self.push(f'{module}.{name}')

            elif op == 'MAKE_FUNCTION':
                code_ref = self.pop()

                m = re.search(r'at (0x[0-9a-fA-F]+)', code_ref)
                addr = m.group(1).lower() if m else None
                m2 = re.search(r'code object (\w+)', code_ref)
                func_name = m2.group(1) if m2 else 'unknown'

                self.push(f'<func:{func_name}:{addr}>')

            elif op == 'SET_FUNCTION_ATTRIBUTE':

                val = self.pop()

                if self.stack:
                    func_expr = self.stack[-1].expr

                    if arg == 1:
                        self.stack[-1].expr = func_expr + f'[defaults={val}]'
                    elif arg == 8:
                        self.stack[-1].expr = func_expr.replace('[', f'[closure={val},')

            elif op == 'UNPACK_SEQUENCE':
                val = self.pop()

                for i_idx in range(arg - 1, -1, -1):
                    self.push(f'{val}[{i_idx}]')

            elif op == 'UNPACK_EX':
                val = self.pop()
                before = arg & 0xFF
                after = (arg >> 8) & 0xFF
                total = before + after + 1
                for i_idx in range(total - 1, -1, -1):
                    if i_idx == before:
                        self.push(f'*{val}[{before}:]')
                    else:
                        self.push(f'{val}[{i_idx}]')

            elif op == 'BEFORE_WITH':
                ctx = self.pop()
                self.emit(f'with {ctx} as __ctx__:')
                self.push('__ctx__')

            elif op in ('SETUP_WITH', 'WITH_EXCEPT_START'):
                pass

            elif op == 'PUSH_EXC_INFO':
                self.emit('except:')

            elif op == 'POP_EXCEPT':
                pass

            elif op == 'CHECK_EXC_MATCH':
                exc_type = self.pop()

                self.push(f'isinstance(__exc__, {exc_type})')

            elif op == 'RERAISE':
                self.emit('raise')

            elif op == 'RAISE_VARARGS':
                if arg == 0:
                    self.emit('raise')
                elif arg == 1:
                    exc = self.pop()
                    self.emit(f'raise {exc}')
                else:
                    cause = self.pop()
                    exc = self.pop()
                    self.emit(f'raise {exc} from {cause}')

            elif op == 'COPY':

                if arg == 1:
                    val = self.peek()
                    self.push(val)
                elif self.stack and len(self.stack) >= arg:
                    val = self.stack[-arg].expr
                    self.push(val)

            elif op == 'SWAP':
                if len(self.stack) >= arg:
                    self.stack[-1], self.stack[-arg] = self.stack[-arg], self.stack[-1]

            elif op == 'JUMP_FORWARD':
                pass

            elif op in ('JUMP_BACKWARD', 'JUMP_ABSOLUTE'):
                pass

            elif op == 'END_SEND':
                val = self.pop()
                self.push(val)

            elif op in ('YIELD_VALUE', 'YIELD_FROM'):
                val = self.pop()
                self.push(f'yield {val}')

            elif op == 'SEND':
                val = self.pop()
                gen = self.pop()
                self.push(f'{gen}.send({val})')

            elif op == 'GET_AWAITABLE':
                val = self.pop()
                self.push(f'await {val}')

            elif op == 'GET_AITER':
                val = self.pop()
                self.push(f'aiter({val})')

            elif op == 'GET_ANEXT':
                val = self.pop()
                self.push(f'anext({val})')

            elif op == 'MAKE_CELL':
                pass

            elif op == 'STORE_DEREF':
                m = re.search(r'\((\w+)\)', raw)
                name = m.group(1) if m else raw.strip('()')
                if name not in ('__classdictcell__', '__classdict__', '__classcell__'):
                    val = self.pop()
                    val = self._clean_expr(val)
                    self.emit(f'{name} = {val}')
                else:
                    self.pop()

            elif op == 'RESUME':
                pass

            else:

                if self.verbose:
                    self.emit(f'# UNKNOWN: {op} {arg} ({raw})')

            return idx + 1

        def _format_const(self, raw: str) -> str:

            raw = raw.strip()
            if not raw:
                return 'None'

            if '<code object' in raw:
                return raw

            if raw.startswith("('") or raw.startswith('(\''):
                return raw

            if raw in ('None', 'True', 'False', 'Ellipsis', '...'):
                return raw

            if (raw.startswith("'") and raw.endswith("'")) or \
               (raw.startswith('"') and raw.endswith('"')):
                return raw

            try:
                float(raw)
                return raw
            except ValueError:
                pass

            if raw.startswith('frozenset('):
                return raw

            if raw.startswith('(') and raw.endswith(')'):
                return raw
            return repr(raw) if raw else 'None'

    def translate(self) -> str:
        lines = self.source.splitlines()

        blocks = self._split_blocks(lines)
        if not blocks:
            return '# No disassembly found'

        out = []
        out.append('# ─────────────────────────────────────────────────────────')
        out.append('# Code décompilé par Ultra Bytecode Translator v3.0')
        out.append('# ─────────────────────────────────────────────────────────')
        out.append('')

        module_block = blocks.get('__module__', [])
        class_blocks = {k: v for k, v in blocks.items() if k != '__module__'}

        module_code = self._gen_module(module_block, class_blocks)
        out.extend(module_code)

        return '\n'.join(out)

    def _split_blocks(self, lines: List[str]) -> Dict[str, List[str]]:

        blocks = {}
        current_name = '__module__'
        current_lines = []
        in_disassembly = False

        for line in lines:
            stripped = line.strip()

            m = re.match(r'^Disassembly of <code object (\w+) at (0x[0-9a-fA-F]+)', stripped)
            if m:

                if current_lines:
                    blocks[current_name] = current_lines
                obj_name = m.group(1)
                obj_addr = m.group(2).lower()
                current_name = f'{obj_name}@{obj_addr}'
                current_lines = []
                in_disassembly = True
                continue

            if not in_disassembly:
                current_lines.append(line)
            else:
                current_lines.append(line)

        if current_lines:
            blocks[current_name] = current_lines

        return blocks

    def _gen_module(self, module_lines: List[str], class_blocks: Dict) -> List[str]:

        out = []
        instrs = self._parse_instrs(module_lines)

        imports_out = []
        class_defs = {}
        func_defs = {}
        consts = {}

        i = 0
        while i < len(instrs):
            instr = instrs[i]
            op = instr.opcode
            raw = instr.raw_arg

            if op in SKIP_OPCODES:
                i += 1
                continue

            if op == 'IMPORT_NAME':
                m = re.search(r'\((\S+)\)', raw)
                module = m.group(1) if m else raw.strip('()')

                j = i + 1
                from_names = []
                stored_as = None

                while j < len(instrs) and instrs[j].opcode not in ('IMPORT_NAME', 'LOAD_BUILD_CLASS'):
                    if instrs[j].opcode == 'IMPORT_FROM':
                        m2 = re.search(r'\((\w+)\)', instrs[j].raw_arg)
                        name = m2.group(1) if m2 else instrs[j].raw_arg.strip('()')
                        from_names.append(name)
                    elif instrs[j].opcode in ('STORE_NAME', 'STORE_FAST'):
                        m2 = re.search(r'\((\w+)\)', instrs[j].raw_arg)
                        if m2:
                            stored_as = m2.group(1)
                            if not from_names:
                                break
                    j += 1

                if from_names:
                    imports_out.append(f'from {module} import {", ".join(from_names)}')
                else:
                    alias = f' as {stored_as}' if stored_as and stored_as != module else ''
                    imports_out.append(f'import {module}{alias}')

            elif op == 'LOAD_BUILD_CLASS':

                j = i + 1
                code_addr = None
                class_name = None
                bases = []
                while j < min(i + 15, len(instrs)):
                    ij = instrs[j]
                    if ij.opcode in ('LOAD_CONST', 'MAKE_FUNCTION'):
                        m2 = re.search(r'code object (\w+) at (0x[0-9a-fA-F]+)', ij.raw_arg)
                        if m2:
                            code_addr = m2.group(2).lower()
                    if ij.opcode == 'LOAD_CONST':
                        m2 = re.search(r"^'(\w+)'$", ij.raw_arg.strip())
                        if m2:
                            class_name = m2.group(1)
                    if ij.opcode in ('LOAD_NAME', 'LOAD_GLOBAL') and class_name:
                        m2 = re.search(r'\((\w+)\)', ij.raw_arg)
                        if m2:
                            name = re.sub(r'\s*\+\s*NULL\s*$', '', m2.group(1)).strip()
                            if name not in ('__build_class__',):
                                bases.append(name)
                    if ij.opcode == 'STORE_NAME':
                        break
                    j += 1
                if class_name and code_addr:
                    class_defs[class_name] = (bases, code_addr)

            i += 1

        for imp in imports_out:
            out.append(imp)
        if imports_out:
            out.append('')

        generated_classes = set()
        generated_funcs = set()

        all_block_keys = list(class_blocks.keys())

        for cls_name, (bases, addr) in class_defs.items():
            if cls_name in generated_classes:
                continue
            cls_code = self._gen_class(cls_name, bases, addr, class_blocks)
            if cls_code:
                out.extend(cls_code)
                out.append('')
                generated_classes.add(cls_name)

        for key in all_block_keys:
            parts = key.split('@')
            if len(parts) == 2:
                func_name, addr = parts
                if func_name in generated_classes:
                    continue

                is_method = False
                for cls_n, (_, cls_addr) in class_defs.items():
                    cls_key = f'{cls_n}@{cls_addr}'
                    if cls_key in class_blocks:
                        cls_content = '\n'.join(class_blocks[cls_key])
                        if addr in cls_content:
                            is_method = True
                            break
                if not is_method and func_name not in generated_classes:
                    func_code = self._gen_function(func_name, addr, class_blocks, indent=0)
                    if func_code:
                        out.extend(func_code)
                        out.append('')
                        generated_funcs.add(func_name)

        module_var_code = self._gen_module_vars(instrs)
        if module_var_code:
            out.extend(module_var_code)
            out.append('')

        main_code = self._gen_main_block(instrs)
        if main_code:
            out.extend(main_code)

        return out

    def _gen_module_vars(self, instrs: List[Instr]) -> List[str]:

        out = []
        emu = self.StackEmulator(self, instrs, context='module', indent=0)

        i = 0
        skip_until = -1
        while i < len(instrs):
            instr = instrs[i]
            op = instr.opcode
            raw = instr.raw_arg

            if i <= skip_until:
                i += 1
                continue

            if op in SKIP_OPCODES:
                i += 1
                continue

            if op in ('IMPORT_NAME', 'LOAD_BUILD_CLASS'):

                j = i + 1
                while j < len(instrs) and instrs[j].opcode not in ('STORE_NAME',):
                    j += 1
                skip_until = j
                i += 1
                continue

            if op == 'LOAD_SMALL_INT':

                if i + 1 < len(instrs) and instrs[i + 1].opcode in ('STORE_NAME', 'STORE_FAST'):
                    val = str(instr.arg)
                    m = re.search(r'\((\w+)\)', instrs[i + 1].raw_arg)
                    name = m.group(1) if m else ''
                    if name and name not in ('__module__', '__qualname__'):
                        out.append(f'{name} = {val}')
                    i += 2
                    continue

            if op == 'LOAD_CONST':

                if i + 1 < len(instrs) and instrs[i + 1].opcode in ('STORE_NAME', 'STORE_FAST', 'STORE_GLOBAL'):
                    val = self._format_const_static(raw)
                    m = re.search(r'\((\w+)\)', instrs[i + 1].raw_arg)
                    name = m.group(1) if m else ''
                    if name and name not in ('__module__', '__qualname__', '__firstlineno__',
                                             '__classcell__', '__static_attributes__'):
                        if '<code object' not in val:
                            out.append(f'{name} = {val}')
                    i += 2
                    continue

            i += 1

        return out

    def _gen_main_block(self, instrs: List[Instr]) -> List[str]:

        for i, instr in enumerate(instrs):
            if instr.opcode in ('COMPARE_OP',) and instr.raw_arg and '__main__' in instr.raw_arg:

                return ["if __name__ == '__main__':"]
            if instr.opcode == 'LOAD_CONST' and "'__main__'" in instr.raw_arg:
                return ["if __name__ == '__main__':"]
        return []

    def _gen_class(self, class_name: str, bases: List[str], addr: str,
                   class_blocks: Dict) -> List[str]:

        cls_key = f'{class_name}@{addr}'
        if cls_key not in class_blocks:

            for key in class_blocks:
                if key.startswith(f'{class_name}@'):
                    cls_key = key
                    addr = key.split('@')[1]
                    break
            else:
                return []

        cls_lines = class_blocks[cls_key]
        instrs = self._parse_instrs(cls_lines)

        if bases:
            base_str = '(' + ', '.join(bases) + ')'
        else:
            base_str = ''

        out = [f'class {class_name}{base_str}:']

        has_content = False
        for instr in instrs:
            if instr.opcode == 'LOAD_CONST' and instr.raw_arg:
                val = instr.raw_arg.strip()
                if (val.startswith("'") or val.startswith('"')) and len(val) > 2:
                    content = val[1:-1]
                    if not content.startswith('(') and '\\n' not in content[:50]:

                        pass

        methods = []
        class_vars = []
        i = 0
        while i < len(instrs):
            instr = instrs[i]
            op = instr.opcode
            raw = instr.raw_arg

            if op in SKIP_OPCODES + ('MAKE_CELL',):
                i += 1
                continue

            if op == 'LOAD_CONST' and i + 1 < len(instrs) and instrs[i + 1].opcode == 'STORE_NAME':
                m = re.search(r'\((\w+)\)', instrs[i + 1].raw_arg)
                name = m.group(1) if m else ''
                if name == '__doc__':
                    val = raw.strip()
                    out.append(f'    """{val[1:-1]}"""')
                    has_content = True
                    i += 2
                    continue

            if op == 'STORE_NAME':
                m = re.search(r'\((\w+)\)', raw)
                name = m.group(1) if m else ''
                if name == '_fields_':

                    pass

            if op in ('LOAD_CONST', 'MAKE_FUNCTION'):
                m = re.search(r'code object (\w+) at (0x[0-9a-fA-F]+)', raw)
                if m:
                    method_name = m.group(1)
                    method_addr = m.group(2).lower()

                    j = i + 1
                    stored_name = method_name
                    defaults = []
                    closure = []
                    while j < min(i + 10, len(instrs)):
                        ij = instrs[j]
                        if ij.opcode == 'SET_FUNCTION_ATTRIBUTE':
                            if ij.arg == 1:
                                if defaults_instr := self._find_defaults(instrs, j):
                                    defaults = defaults_instr
                            elif ij.arg == 8:
                                pass
                        elif ij.opcode == 'STORE_NAME':
                            m2 = re.search(r'\((\w+)\)', ij.raw_arg)
                            if m2:
                                stored_name = m2.group(1)
                            break
                        j += 1

                    method_key = f'{method_name}@{method_addr}'
                    if method_key in class_blocks:
                        method_code = self._gen_function(
                            stored_name, method_addr, class_blocks, indent=1, defaults=defaults
                        )
                        if method_code:
                            methods.append(method_code)
                            has_content = True

            elif op == 'STORE_NAME':
                m = re.search(r'\((\w+)\)', raw)
                name = m.group(1) if m else ''
                if name not in ('__module__', '__qualname__', '__firstlineno__',
                                '__classcell__', '__classdictcell__', '__static_attributes__',
                                '__doc__'):
                    pass

            i += 1

        cls_vars_code = self._gen_class_vars(instrs)
        for cv in cls_vars_code:
            out.append('    ' + cv)
            has_content = True

        for method_lines in methods:
            out.append('')
            out.extend(method_lines)

        if not has_content:
            out.append('    pass')

        return out

    def _gen_class_vars(self, instrs: List[Instr]) -> List[str]:

        out = []
        emu = self.StackEmulator(self, instrs, context='class', indent=0)

        i = 0
        while i < len(instrs):
            instr = instrs[i]
            op = instr.opcode

            if op in SKIP_OPCODES + ('MAKE_CELL', 'MAKE_FUNCTION', 'SET_FUNCTION_ATTRIBUTE',
                                      'STORE_DEREF', 'COPY', 'LOAD_FAST_BORROW',
                                      'LOAD_DEREF', 'RETURN_VALUE'):
                i += 1
                continue

            if op == 'STORE_NAME':
                m = re.search(r'\((\w+)\)', instr.raw_arg)
                name = m.group(1) if m else ''
                if name in ('__module__', '__qualname__', '__firstlineno__',
                             '__classcell__', '__classdictcell__', '__static_attributes__',
                             '__doc__', '__class__'):
                    emu.pop() if emu.stack else None
                    i += 1
                    continue
                if name == '_fields_':
                    val = emu.pop() if emu.stack else '__MISSING__'
                    out.append(f'_fields_ = {val}')
                else:
                    val = emu.pop() if emu.stack else '__MISSING__'
                    if val and val != '__MISSING__' and '<code object' not in val:
                        out.append(f'{name} = {val}')
                i += 1
                continue

            emu._exec(instr, i)
            i += 1

        return out

    def _find_defaults(self, instrs: List[Instr], start: int) -> List[str]:

        defaults = []
        j = start - 1
        while j >= max(0, start - 20):
            ij = instrs[j]
            if ij.opcode in ('LOAD_CONST', 'LOAD_SMALL_INT'):
                val = self._format_const_static(ij.raw_arg) if ij.opcode == 'LOAD_CONST' else str(ij.arg)
                defaults.insert(0, val)
            elif ij.opcode == 'BUILD_TUPLE':
                break
            j -= 1
        return defaults

    def _gen_function(self, func_name: str, addr: str, class_blocks: Dict,
                      indent: int = 0, defaults: List[str] = None) -> List[str]:

        key = f'{func_name}@{addr}'
        if key not in class_blocks:

            for k in class_blocks:
                if k.endswith(f'@{addr}'):
                    key = k
                    func_name = k.split('@')[0]
                    break
            else:
                return []

        func_lines = class_blocks[key]
        instrs = self._parse_instrs(func_lines)

        if not instrs:
            return []

        params = self._extract_params(instrs)

        if defaults and params:

            n = len(defaults)
            if n <= len(params):
                for i in range(n):
                    params[-(n - i)] = f'{params[-(n - i)]}={defaults[i]}'

        ind = '    ' * indent
        params_str = ', '.join(params)
        func_def = f'{ind}def {func_name}({params_str}):'

        body_lines = self._gen_function_body(instrs, indent + 1)

        nonlocal_candidates = []
        for instr in instrs:
            if instr.opcode == 'STORE_DEREF':
                name = re.search(r'\(([^)]+)\)', instr.raw_arg)
                vname = name.group(1).strip() if name else instr.raw_arg.strip('()')
                if (vname and not vname.startswith('__')
                        and vname not in params
                        and vname not in nonlocal_candidates):
                    nonlocal_candidates.append(vname)
        if nonlocal_candidates:
            nonlocal_line = f'{ind}    nonlocal {", ".join(nonlocal_candidates)}'
            body_lines = [nonlocal_line] + (body_lines or [])

        if not body_lines:
            body_lines = [f'{ind}    pass']

        return [func_def] + body_lines

    def _extract_params(self, instrs: List[Instr]) -> List[str]:

        params = []
        seen = set()

        for instr in instrs[:50]:
            if instr.opcode in ('LOAD_FAST', 'LOAD_FAST_BORROW', 'LOAD_FAST_CHECK'):
                raw = instr.raw_arg
                parts = raw.strip('()').split(',')
                for p in parts:
                    name = p.strip()
                    if name and name not in seen and not name.startswith('__'):
                        seen.add(name)
                        params.append(name)
            elif instr.opcode == 'LOAD_FAST_BORROW_LOAD_FAST_BORROW':
                raw = instr.raw_arg
                parts = raw.strip('()').split(',')
                for p in parts:
                    name = p.strip()
                    if name and name not in seen and not name.startswith('__'):
                        seen.add(name)
                        params.append(name)
            elif instr.opcode in ('RESUME', 'COPY_FREE_VARS'):
                continue
            elif instr.opcode in ('STORE_FAST', 'STORE_DEREF'):
                break
            elif instr.opcode not in SKIP_OPCODES and instr.opcode not in (
                'LOAD_GLOBAL', 'LOAD_ATTR', 'LOAD_CONST', 'LOAD_SMALL_INT',
                'PUSH_NULL', 'LOAD_DEREF', 'COPY', 'LOAD_NAME', 'BUILD_TUPLE',
                'LOAD_SUPER_ATTR', 'LOAD_CLASSDEREF', 'GET_ITER', 'FOR_ITER',
                'SET_FUNCTION_ATTRIBUTE', 'MAKE_FUNCTION', 'LOAD_CONST',
            ):
                break

        return params

    def _gen_function_body(self, instrs: List[Instr], indent: int) -> List[str]:

        ind = '    ' * indent
        out = []

        exc_table = self._parse_exception_table_from_instrs(instrs)

        emu = self.StackEmulator(self, instrs, context='function', indent=indent)
        raw_lines = self._smart_translate(instrs, indent, exc_table)

        return raw_lines

    def _parse_exception_table_from_instrs(self, instrs: List[Instr]) -> Dict:

        raw_table = {}
        for instr in instrs:
            if instr.opcode == '__EXCTABLE_ENTRY__':
                parts = instr.raw_arg.split(',')
                if len(parts) == 3:
                    start_lbl, end_lbl, handler_lbl = parts
                    if handler_lbl not in raw_table:
                        raw_table[handler_lbl] = []
                    raw_table[handler_lbl].append((start_lbl, end_lbl))

        all_handler_labels = set(raw_table.keys())
        table = {}
        for handler_lbl, ranges in raw_table.items():
            real_ranges = [(s, e) for s, e in ranges if s not in all_handler_labels]
            if real_ranges:
                table[handler_lbl] = real_ranges
        return table

    def _parse_exception_table_from_lines(self, lines: List[str]) -> Dict:

        table = {}
        exc_re = re.compile(r'^\s*(L\w+)\s+to\s+(L\w+)\s+->\s+(L\w+)')
        in_exc_table = False
        for line in lines:
            if 'ExceptionTable' in line:
                in_exc_table = True
                continue
            if in_exc_table:
                m = exc_re.match(line)
                if m:
                    start_lbl, end_lbl, handler_lbl = m.group(1), m.group(2), m.group(3)
                    if handler_lbl not in table:
                        table[handler_lbl] = []
                    table[handler_lbl].append((start_lbl, end_lbl))
                elif line.strip() and not line.strip().startswith('L'):
                    in_exc_table = False
        return table

    def _smart_translate(self, instrs: List[Instr], indent: int,
                         exc_table: Dict) -> List[str]:

        out = []
        ind = '    ' * indent
        stack = []
        kw_names = None
        pending_for = None
        i = 0
        if_stack = []
        label_map = {}

        def push(v, null=False, callable_=False):
            stack.append(StackVal(v, null, callable_))

        def pop():
            return stack.pop().expr if stack else '__MISSING__'

        def peek():
            return stack[-1].expr if stack else '__MISSING__'

        def pop_n(n):
            if n == 0:
                return []
            items = [pop() for _ in range(n)]
            items.reverse()
            return items

        def clean(s):
            s = re.sub(r'\s*\+\s*__NULL__', '', s)
            s = re.sub(r'__NULL__\s*\+\s*', '', s)
            return s.strip()

        def fmt_call(f, args, kw=None):
            f = re.sub(r'\s*\+\s*NULL\|self\s*$', '', f).strip()
            f = re.sub(r'\s*\+\s*NULL\s*$', '', f).strip()
            all_a = list(args)
            if kw:
                for k, v in kw.items():
                    all_a.append(f'{k}={v}')
            return f'{f}({", ".join(all_a)})'

        def fmt_const(raw):
            raw = raw.strip()
            if not raw:
                return 'None'
            if '<code object' in raw:
                return raw
            if raw in ('None', 'True', 'False', 'Ellipsis', '...'):
                return raw
            try:
                float(raw)
                return raw
            except:
                pass
            return raw

        label_to_idx = {}
        idx_to_label = {}
        for ii, instr in enumerate(instrs):
            if instr.label:
                label_to_idx[instr.label] = ii
                idx_to_label[ii] = instr.label

        try_start_to_handler = {}
        handler_labels = set()
        try_end_labels = {}

        handler_first_start = {}
        if exc_table:
            for handler_lbl, ranges in exc_table.items():
                handler_labels.add(handler_lbl)
                for (start_lbl, end_lbl) in ranges:
                    if start_lbl not in try_start_to_handler:
                        try_start_to_handler[start_lbl] = handler_lbl
                    try_end_labels[end_lbl] = handler_lbl

            for handler_lbl, ranges in exc_table.items():

                starts = [s for s, e in ranges]

                first = min(starts, key=lambda l: label_to_idx.get(l, 9999))
                handler_first_start[handler_lbl] = first

        try_block_stack = []

        handler_try_emitted = set()

        try_emitted = set()

        jump_targets = {}
        for instr in instrs:
            if instr.opcode.startswith('POP_JUMP_IF_'):
                m = re.search(r'to (L\w+)', instr.raw_arg)
                if m:
                    lbl = m.group(1)
                    if lbl not in jump_targets:
                        jump_targets[lbl] = 'else'

        loop_headers: Set[str] = set()
        back_jump_at: Dict[int, str] = {}

        for _ii, _instr in enumerate(instrs):
            if _instr.opcode in ('JUMP_BACKWARD', 'JUMP_ABSOLUTE',
                                  'JUMP_BACKWARD_NO_INTERRUPT'):
                _m = re.search(r'to (L\w+)', _instr.raw_arg)
                if _m:
                    _tgt = _m.group(1)
                    _tgt_idx = label_to_idx.get(_tgt, 9999)
                    if _tgt_idx <= _ii:
                        loop_headers.add(_tgt)
                        back_jump_at[_ii] = _tgt

        loop_end_idx: Dict[str, int] = {}
        for _jj, _tgt in back_jump_at.items():
            if _tgt in loop_headers:
                if _tgt not in loop_end_idx or _jj > loop_end_idx[_tgt]:
                    loop_end_idx[_tgt] = _jj

        while_stack: List[Tuple[str, int]] = []
        while_emitted: Set[str] = set()

        ctrl_stack = []
        in_except = False
        pending_import_module = None
        from_names = []
        import_as = None

        while i < len(instrs):
            instr = instrs[i]
            op = instr.opcode
            raw = instr.raw_arg
            arg = instr.arg

            if instr.label:
                lbl = instr.label

                if lbl in loop_headers and lbl not in while_emitted:
                    out.append(f'{ind}while True:')
                    while_emitted.add(lbl)
                    while_stack.append((lbl, indent))
                    indent += 1
                    ind = '    ' * indent

                while if_stack and if_stack[-1][2] == lbl:
                    _, if_ind, _, _ = if_stack.pop()
                    indent = if_ind
                    ind = '    ' * indent

                if lbl in try_start_to_handler and lbl not in try_emitted:
                    handler_lbl = try_start_to_handler[lbl]

                    if handler_lbl not in handler_try_emitted:
                        out.append(f'{ind}try:')
                        handler_try_emitted.add(handler_lbl)
                        try_block_stack.append((handler_lbl, indent))
                        indent += 1
                        ind = '    ' * indent
                    try_emitted.add(lbl)

                elif lbl in handler_labels and op == 'PUSH_EXC_INFO':

                    if try_block_stack and try_block_stack[-1][0] == lbl:
                        _, try_indent = try_block_stack[-1]
                        indent = try_indent
                        ind = '    ' * indent
                    elif try_block_stack:
                        _, try_indent = try_block_stack[-1]
                        indent = try_indent
                        ind = '    ' * indent
                    out.append(f'{ind}except:')
                    in_except = True
                    indent += 1
                    ind = '    ' * indent
                    i += 1
                    continue

            if op in SKIP_OPCODES:
                i += 1
                continue

            if op in ('LOAD_FAST', 'LOAD_FAST_BORROW', 'LOAD_FAST_CHECK'):
                m = re.search(r'\(([^)]+)\)', raw)
                name = m.group(1).split(',')[0].strip() if m else raw.strip('()')
                push(name)

            elif op == 'LOAD_FAST_BORROW_LOAD_FAST_BORROW':
                parts = re.findall(r'\(([^)]+)\)', raw)
                if parts:
                    all_parts = [p.strip() for p in parts[0].split(',')]
                    v1 = all_parts[0] if len(all_parts) > 0 else '__?__'
                    v2 = all_parts[1] if len(all_parts) > 1 else '__?__'
                    push(v2)
                    push(v1)
                else:
                    push('__a__')
                    push('__b__')

            elif op == 'STORE_FAST_STORE_FAST':
                parts = re.findall(r'\(([^)]+)\)', raw)
                if parts:
                    all_parts = [p.strip() for p in parts[0].split(',')]
                    v1 = all_parts[0] if len(all_parts) > 0 else '__a__'
                    v2 = all_parts[1] if len(all_parts) > 1 else '__b__'
                else:
                    v1, v2 = '__a__', '__b__'
                val1 = pop()
                val2 = pop()
                out.append(f'{ind}{v1}, {v2} = {clean(val1)}, {clean(val2)}')

            elif op == 'LOAD_SMALL_INT' or op == 'LOAD_ZERO':
                push('0' if op == 'LOAD_ZERO' else str(arg))

            elif op == 'LOAD_CONST':
                push(fmt_const(raw))

            elif op == 'LOAD_COMMON_CONSTANT':
                cm = {0: 'None', 1: 'True', 2: 'False', 3: 'Ellipsis'}
                push(cm.get(arg, 'None'))

            elif op in ('LOAD_NAME', 'LOAD_GLOBAL'):
                name = re.sub(r'\s*\+\s*NULL\s*$', '', raw.strip('()')).strip()
                m = re.search(r'\(([^)]+)\)', raw)
                if m:
                    name = re.sub(r'\s*\+\s*NULL\s*$', '', m.group(1)).strip()
                push(name, callable_=('NULL' in raw))

            elif op == 'LOAD_ATTR':
                attr = re.sub(r'\s*\+\s*NULL\|self\s*$', '', raw.strip('()')).strip()
                attr = re.sub(r'\s*\+\s*NULL\s*$', '', attr).strip()
                m = re.search(r'\(([^)]+)\)', raw)
                if m:
                    attr = re.sub(r'\s*\+\s*NULL\|self\s*$', '', m.group(1)).strip()
                    attr = re.sub(r'\s*\+\s*NULL\s*$', '', attr).strip()
                obj = pop()
                push(f'{obj}.{attr}', callable_=('+' in raw))

            elif op in ('LOAD_DEREF', 'LOAD_CLASSDEREF', 'LOAD_FAST_CHECK'):
                m = re.search(r'\(([^)]+)\)', raw)
                name = m.group(1).strip() if m else raw.strip('()')
                push(name)

            elif op == 'LOAD_CLOSURE':

                m = re.search(r'\(([^)]+)\)', raw)
                name = m.group(1).strip() if m else raw.strip('()')
                push(name)

            elif op == 'LOAD_LOCALS':
                push('vars()')

            elif op == 'LOAD_SUPER_ATTR':
                attr = re.sub(r'\s*\+\s*NULL\|self\s*$', '', raw.strip('()')).strip()
                m = re.search(r'\(([^)]+)\)', raw)
                if m:
                    attr = re.sub(r'\s*\+\s*NULL\|self\s*$', '', m.group(1)).strip()
                self_obj = pop()
                super_type = pop()
                super_func = pop()
                if super_type and not super_type.startswith('__'):
                    push(f'super({super_type}, {self_obj}).{attr}', callable_=True)
                else:
                    push(f'super().{attr}', callable_=True)

            elif op == 'LOAD_BUILD_CLASS':
                push('__build_class__', null=True)

            elif op == 'PUSH_NULL':
                push('__NULL__', null=True)

            elif op in ('STORE_NAME', 'STORE_FAST', 'STORE_GLOBAL', 'STORE_DEREF'):
                m = re.search(r'\(([^)]+)\)', raw)
                name = m.group(1).strip() if m else raw.strip('()')
                val = pop()
                if name in ('__module__', '__qualname__', '__firstlineno__',
                             '__classcell__', '__classdictcell__', '__static_attributes__',
                             '__doc__', '__class__'):
                    pass
                elif val in ('vars()', '__locals__'):
                    pass
                else:

                    if val.startswith('__for_iter__'):
                        m2 = re.search(r'__for_iter__\((.+)\)', val)
                        iterable = m2.group(1) if m2 else val
                        out.append(f'{ind}for {name} in {iterable}:')
                        pending_for = name
                    else:
                        val = clean(val)
                        if val and '<code object' not in val and val not in ('None', '__NULL__', '__MISSING__'):
                            out.append(f'{ind}{name} = {val}')
                        elif val == 'None' and name not in ('_',):
                            pass

            elif op == 'STORE_ATTR':
                m = re.search(r'\(([^)]+)\)', raw)
                attr = m.group(1).strip() if m else raw.strip('()')

                obj = pop()
                val = pop()
                val = clean(val)
                if val not in ('__NULL__', '__MISSING__', ''):
                    out.append(f'{ind}{obj}.{attr} = {val}')

            elif op == 'STORE_SUBSCR':
                key = pop()
                obj = pop()
                val = pop()
                val = clean(val)
                out.append(f'{ind}{obj}[{key}] = {val}')

            elif op in ('DELETE_FAST', 'DELETE_NAME', 'DELETE_GLOBAL'):
                m = re.search(r'\(([^)]+)\)', raw)
                name = m.group(1).strip() if m else raw.strip('()')
                out.append(f'{ind}del {name}')

            elif op == 'DELETE_ATTR':
                m = re.search(r'\(([^)]+)\)', raw)
                attr = m.group(1).strip() if m else raw.strip('()')
                obj = pop()
                out.append(f'{ind}del {obj}.{attr}')

            elif op == 'DELETE_SUBSCR':
                key = pop()
                obj = pop()
                out.append(f'{ind}del {obj}[{key}]')

            elif op == 'CALL':
                nargs = arg
                args = pop_n(nargs)

                while stack and stack[-1].is_null:
                    stack.pop()
                func = pop()

                while stack and stack[-1].is_null:
                    stack.pop()
                kw = {}
                if kw_names:
                    kn = len(kw_names)
                    kw_vals = args[-kn:]
                    args = args[:-kn]
                    kw = dict(zip(kw_names, kw_vals))
                    kw_names = None
                push(fmt_call(func, args, kw if kw else None))

            elif op == 'CALL_KW':
                kw_tuple = pop()
                nargs = arg
                all_args = pop_n(nargs)

                while stack and stack[-1].is_null:
                    stack.pop()
                func = pop()

                while stack and stack[-1].is_null:
                    stack.pop()
                kw_names_list = re.findall(r"'(\w+)'", kw_tuple)
                kw = {}
                if kw_names_list:
                    kn = len(kw_names_list)
                    kw_vals = all_args[-kn:]
                    all_args = all_args[:-kn]
                    kw = dict(zip(kw_names_list, kw_vals))
                push(fmt_call(func, all_args, kw if kw else None))

            elif op == 'KW_NAMES':
                kw_names = re.findall(r"'(\w+)'", raw)

            elif op == 'CALL_FUNCTION':
                nargs = arg
                args = pop_n(nargs)
                func = pop()
                push(fmt_call(func, args))

            elif op == 'CALL_FUNCTION_KW':
                keys = pop()
                nargs = arg
                vals = pop_n(nargs)
                func = pop()
                key_names = re.findall(r"'(\w+)'", keys)
                kw = dict(zip(key_names, vals[-len(key_names):]))
                pos_args = vals[:-len(key_names)]
                push(fmt_call(func, pos_args, kw))

            elif op == 'CALL_FUNCTION_EX':
                kwargs_dict = pop() if (arg or 0) & 1 else None
                args_tuple = pop()
                func = pop()
                while stack and stack[-1].is_null:
                    stack.pop()
                if kwargs_dict and kwargs_dict not in ('None', '{}'):
                    push(f'{func}(*{args_tuple}, **{kwargs_dict})')
                else:
                    push(f'{func}(*{args_tuple})')

            elif op == 'CALL_INTRINSIC_1':
                val = pop()
                intrinsics = {1: 'print', 2: 'iter', 5: 'reversed', 6: 'tuple', 7: 'set'}
                fname = intrinsics.get(arg, f'__intrinsic_{arg}__')
                push(f'{fname}({val})')

            elif op == 'POP_TOP':
                val = pop()
                val = clean(val)
                if val and val not in ('None', '__NULL__', '__MISSING__', '', 'vars()'):
                    if any(c in val for c in ('(', '=')):
                        if not (val.startswith('if ') or val.endswith(': pass')):
                            out.append(f'{ind}{val}')

            elif op in ('RETURN_VALUE',):
                val = pop()
                val = clean(val)
                if val and val not in ('None',):
                    out.append(f'{ind}return {val}')
                else:

                    pass

            elif op == 'RETURN_CONST':
                val = fmt_const(raw)
                if val and val != 'None':
                    out.append(f'{ind}return {val}')

            elif op == 'BINARY_OP':
                rhs = pop()
                lhs = pop()

                if raw == '[]' or raw.strip('()') == '[]':
                    push(f'{lhs}[{rhs}]')
                elif arg in INPLACE_OPS:
                    op_str = INPLACE_MAP[arg]
                    out.append(f'{ind}{lhs} {op_str} {rhs}')
                    push(lhs)
                else:
                    op_str = BINARY_OPS.get(arg, f'OP{arg}')
                    push(f'({lhs} {op_str} {rhs})')

            elif op == 'BINARY_SUBSCR':
                key = pop()
                obj = pop()
                push(f'{obj}[{key}]')

            elif op == 'BINARY_SLICE':

                stop = pop()
                start = pop()
                container = pop()

                start_str = '' if start in ('None', '') else start
                stop_str = '' if stop in ('None', '') else stop
                push(f'{container}[{start_str}:{stop_str}]')

            elif op == 'STORE_SLICE':

                stop = pop()
                start = pop()
                container = pop()
                value = pop()
                start_str = '' if start in ('None', '') else start
                stop_str = '' if stop in ('None', '') else stop
                out.append(f'{ind}{container}[{start_str}:{stop_str}] = {value}')

            elif op == 'COMPARE_OP':
                op_str = COMPARE_OPS.get(arg, '==')
                rhs = pop()
                lhs = pop()
                push(f'{lhs} {op_str} {rhs}')

            elif op == 'IS_OP':
                rhs = pop()
                lhs = pop()
                push(f'{lhs} is not {rhs}' if arg else f'{lhs} is {rhs}')

            elif op == 'CONTAINS_OP':
                rhs = pop()
                lhs = pop()
                push(f'{lhs} not in {rhs}' if arg else f'{lhs} in {rhs}')

            elif op == 'TO_BOOL':
                pass

            elif op == 'UNARY_NOT':
                push(f'not {pop()}')
            elif op == 'UNARY_NEGATIVE':
                push(f'-{pop()}')
            elif op == 'UNARY_POSITIVE':
                push(f'+{pop()}')
            elif op == 'UNARY_INVERT':
                push(f'~{pop()}')

            elif op == 'BUILD_TUPLE':
                items = pop_n(arg)
                push('()' if arg == 0 else f'({", ".join(items)},)' if arg == 1 else f'({", ".join(items)})')

            elif op == 'BUILD_LIST':
                items = pop_n(arg)
                push(f'[{", ".join(items)}]')

            elif op == 'BUILD_SET':
                items = pop_n(arg)
                push('set()' if arg == 0 else '{' + ', '.join(items) + '}')

            elif op == 'BUILD_MAP':
                pairs = []
                for _ in range(arg):
                    v = pop()
                    k = pop()
                    pairs.insert(0, f'{k}: {v}')
                push('{' + ', '.join(pairs) + '}')

            elif op == 'BUILD_CONST_KEY_MAP':
                keys = pop()
                vals = pop_n(arg)
                key_names = re.findall(r"'([^']+)'", keys)
                if len(key_names) == len(vals):
                    pairs = [f"'{k}': {v}" for k, v in zip(key_names, vals)]
                    push('{' + ', '.join(pairs) + '}')
                else:
                    push(f'dict(zip({keys}, [{", ".join(vals)}]))')

            elif op == 'BUILD_STRING':
                parts = pop_n(arg)
                result = 'f"'
                for part in parts:
                    if (part.startswith("'") and part.endswith("'")) or \
                       (part.startswith('"') and part.endswith('"')):

                        inner = part[1:-1]
                        inner = inner.replace('{', '{{').replace('}', '}}')
                        result += inner
                    elif part.startswith('{') and part.endswith('}'):

                        result += part
                    else:
                        result += '{' + part + '}'
                result += '"'
                push(result)

            elif op == 'FORMAT_SIMPLE':
                val = pop()
                push(f'{{{val}}}')

            elif op == 'FORMAT_WITH_SPEC':
                spec = pop().strip("'\"")
                val = pop()
                push(f'{{{val}:{spec}}}')

            elif op == 'MAP_ADD':
                val = pop()
                key = pop()
                idx2 = len(stack) - arg
                if 0 <= idx2 < len(stack):
                    ex = stack[idx2].expr
                    if ex == '{}':
                        stack[idx2].expr = '{' + f'{key}: {val}' + '}'
                    elif ex.startswith('{') and ex.endswith('}'):
                        inner = ex[1:-1]
                        stack[idx2].expr = '{' + (inner + ', ' if inner else '') + f'{key}: {val}' + '}'

            elif op == 'DICT_UPDATE':
                update = pop()
                idx2 = len(stack) - arg
                if 0 <= idx2 < len(stack):
                    ex = stack[idx2].expr
                    if ex == '{}':
                        stack[idx2].expr = update
                    elif ex.startswith('{') and ex.endswith('}') and \
                         update.startswith('{') and update.endswith('}'):
                        i1 = ex[1:-1].strip()
                        i2 = update[1:-1].strip()
                        combined = (i1 + ', ' + i2).strip(', ')
                        stack[idx2].expr = '{' + combined + '}'
                    else:
                        stack[idx2].expr = f'{{**{ex}, **{update}}}'

            elif op in ('LIST_APPEND', 'SET_ADD'):
                val = pop()
                idx2 = len(stack) - arg
                if 0 <= idx2 < len(stack):
                    ex = stack[idx2].expr
                    if ex.startswith('[') and ex.endswith(']'):
                        inner = ex[1:-1]
                        stack[idx2].expr = '[' + (inner + ', ' if inner else '') + val + ']'
                    elif ex.startswith('{') and ex.endswith('}') and op == 'SET_ADD':
                        inner = ex[1:-1]
                        stack[idx2].expr = '{' + (inner + ', ' if inner else '') + val + '}'

            elif op == 'LIST_EXTEND':
                update = pop()
                idx2 = len(stack) - arg
                if 0 <= idx2 < len(stack):
                    ex = stack[idx2].expr
                    if ex == '[]':
                        stack[idx2].expr = f'list({update})' if not update.startswith('[') else update
                    elif ex.startswith('[') and update.startswith('['):
                        i1 = ex[1:-1]
                        i2 = update[1:-1]
                        stack[idx2].expr = '[' + (i1 + ', ' if i1 else '') + i2 + ']'
                    else:
                        stack[idx2].expr = f'{ex} + {update}'

            elif op == 'SET_UPDATE':
                update = pop()
                idx2 = len(stack) - arg
                if 0 <= idx2 < len(stack):
                    ex = stack[idx2].expr
                    if ex == 'set()':
                        stack[idx2].expr = f'set({update})'
                    else:
                        stack[idx2].expr = f'{ex} | {update}'

            elif op == 'IMPORT_NAME':
                m = re.search(r'\((\S+)\)', raw)
                module = m.group(1) if m else raw.strip('()')
                fromlist = pop()
                level = pop()

                if fromlist in ('None', '()', '', 'None'):
                    pending_import_module = ('import', module)
                else:
                    names = re.findall(r"'(\w+)'", fromlist)
                    pending_import_module = ('from', module, names)
                push(module)

            elif op == 'IMPORT_FROM':
                m = re.search(r'\(([^)]+)\)', raw)
                name = m.group(1).strip() if m else raw.strip('()')
                module = peek()
                push(name)

            elif op == 'IMPORT_STAR':
                module = pop()
                out.append(f'{ind}from {module} import *')

            elif op == 'GET_ITER':
                pass

            elif op == 'FOR_ITER':

                iterable = peek()

                if stack and not stack[-1].expr.startswith('__for_iter__'):
                    stack[-1].expr = f'__for_iter__({iterable})'
                else:
                    push(f'__for_iter__({iterable})')

            elif op in ('END_FOR', 'POP_ITER'):
                pass

            elif op == 'POP_JUMP_IF_FALSE':
                cond = pop()
                m = re.search(r'to (L\w+)', raw)
                lbl = m.group(1) if m else ''
                tgt_idx = label_to_idx.get(lbl, 9999)
                _is_loop_exit = (while_stack and lbl and
                    tgt_idx > loop_end_idx.get(while_stack[-1][0], 9999))
                _is_back_jump = lbl and tgt_idx <= i
                if _is_loop_exit:
                    out.append(f'{ind}if not {cond}:')
                    out.append(f'{ind}    break')
                elif _is_back_jump:
                    out.append(f'{ind}if not {cond}:')
                    out.append(f'{ind}    continue')
                else:
                    out.append(f'{ind}if {cond}:')
                    if_stack.append((cond, indent, lbl, 'if'))
                    indent += 1
                    ind = '    ' * indent

            elif op == 'POP_JUMP_IF_TRUE':
                cond = pop()
                m = re.search(r'to (L\w+)', raw)
                lbl = m.group(1) if m else ''
                tgt_idx = label_to_idx.get(lbl, 9999)
                _is_loop_exit = (while_stack and lbl and
                    tgt_idx > loop_end_idx.get(while_stack[-1][0], 9999))
                _is_back_jump = lbl and tgt_idx <= i
                if _is_loop_exit:
                    out.append(f'{ind}if {cond}:')
                    out.append(f'{ind}    break')
                elif _is_back_jump:
                    out.append(f'{ind}if {cond}:')
                    out.append(f'{ind}    continue')
                else:
                    out.append(f'{ind}if not {cond}:')
                    if_stack.append((cond, indent, lbl, 'if_not'))
                    indent += 1
                    ind = '    ' * indent

            elif op in ('JUMP_FORWARD', 'JUMP_BACKWARD', 'JUMP_ABSOLUTE',
                        'JUMP_BACKWARD_NO_INTERRUPT'):
                m = re.search(r'to (L\w+)', raw)
                if m:
                    lbl = m.group(1)
                    tgt_idx = label_to_idx.get(lbl, 9999)

                    if op in ('JUMP_BACKWARD', 'JUMP_BACKWARD_NO_INTERRUPT') or (
                            op == 'JUMP_ABSOLUTE' and tgt_idx <= i):
                        if while_stack:
                            header_lbl, while_ind = while_stack[-1]
                            if lbl == header_lbl:
                                indent = while_ind + 1
                                ind = '    ' * indent
                            elif lbl in loop_headers:
                                out.append(f'{ind}continue')
                        elif lbl in loop_headers:
                            out.append(f'{ind}continue')
                    elif if_stack and lbl:
                        pass

            elif op == 'BEFORE_WITH':
                ctx = pop()
                out.append(f'{ind}with {ctx}:')

            elif op in ('SETUP_WITH', 'SETUP_FINALLY', 'SETUP_EXCEPT'):
                pass

            elif op == 'PUSH_EXC_INFO':

                if not in_except:
                    if try_block_stack:
                        _, try_indent = try_block_stack[-1]
                        indent = try_indent
                        ind = '    ' * indent
                    out.append(f'{ind}except:')
                    in_except = True
                    indent += 1
                    ind = '    ' * indent

            elif op == 'CHECK_EXC_MATCH':
                exc_type = pop()

                for j in range(len(out) - 1, -1, -1):
                    if out[j].strip() == 'except:':
                        out[j] = out[j].replace('except:', f'except {exc_type}:')
                        break
                in_except = True

            elif op == 'POP_EXCEPT':
                in_except = False

                if try_block_stack:
                    _, try_indent = try_block_stack.pop()
                    indent = try_indent
                    ind = '    ' * indent

            elif op == 'RERAISE':

                if arg == 0:
                    out.append(f'{ind}raise')

            elif op == 'RAISE_VARARGS':
                if arg == 0:
                    out.append(f'{ind}raise')
                elif arg == 1:
                    out.append(f'{ind}raise {pop()}')
                else:
                    cause = pop()
                    exc = pop()
                    out.append(f'{ind}raise {exc} from {cause}')

            elif op in ('YIELD_VALUE',):
                val = pop()
                push(f'yield {val}')

            elif op == 'YIELD_FROM':
                val = pop()
                push(f'yield from {val}')

            elif op == 'SEND':
                val = pop()
                gen = pop()
                push(f'{gen}.send({val})')

            elif op == 'GET_AWAITABLE':
                push(f'await {pop()}')

            elif op == 'COPY':
                if arg == 1:
                    push(peek())
                elif len(stack) >= arg:
                    push(stack[-arg].expr)

            elif op == 'SWAP':
                if len(stack) >= arg:
                    stack[-1], stack[-arg] = stack[-arg], stack[-1]

            elif op == 'MAKE_FUNCTION':
                code_ref = pop()
                m = re.search(r'code object (\w+) at (0x[0-9a-fA-F]+)', code_ref)
                if m:
                    push(f'<func:{m.group(1)}:{m.group(2).lower()}>')
                else:
                    push(f'<func:unknown>')

            elif op == 'SET_FUNCTION_ATTRIBUTE':
                val = pop()
                if stack:
                    fx = stack[-1].expr
                    if arg == 1:
                        stack[-1].expr = re.sub(r'<func:(\w+):([^>]+)>', rf'<func:\1:\2,defaults={val}>', fx)
                    elif arg == 8:
                        stack[-1].expr = re.sub(r'<func:(\w+):([^>]+)>', rf'<func:\1:\2,closure={val}>', fx)

            elif op == 'UNPACK_SEQUENCE':
                val = pop()
                for i2 in range(arg - 1, -1, -1):
                    push(f'{val}[{i2}]')

            elif op == 'MAKE_CELL':
                pass

            elif op == 'END_SEND':
                pass

            elif op == 'GET_LEN':
                obj = peek()
                push(f'len({obj})')

            elif op == 'MATCH_MAPPING':
                push(f'isinstance({peek()}, dict)')

            elif op == 'MATCH_SEQUENCE':
                push(f'isinstance({peek()}, (list, tuple))')

            elif op == 'MATCH_KEYS':
                keys = pop()
                obj = pop()
                push(f'{obj}.get_items({keys})')

            elif op == 'COPY_DICT_WITHOUT_KEYS':
                keys = pop()
                obj = pop()
                push(f'{{k: v for k, v in {obj}.items() if k not in {keys}}}')

            else:
                pass

            i += 1

        return out

    def _format_const_static(self, raw: str) -> str:

        raw = raw.strip()
        if not raw:
            return 'None'
        if '<code object' in raw:
            return raw
        if raw in ('None', 'True', 'False', 'Ellipsis', '...'):
            return raw
        try:
            float(raw)
            return raw
        except:
            pass
        return raw

