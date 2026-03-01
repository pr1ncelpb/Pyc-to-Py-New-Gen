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

@dataclass
class Instr:
    lineno: Optional[int]
    label: Optional[str]
    opcode: str
    arg: Any
    raw_arg: str
    src_line: str = ''

@dataclass
class StackVal:
    expr: str
    is_null: bool = False
    is_callable: bool = False

@dataclass
class ScopeInfo:

    name: str
    addr: str

    local_vars: Set[str] = field(default_factory=set)

    free_vars: Set[str] = field(default_factory=set)

    cell_vars: Set[str] = field(default_factory=set)

    params: List[str] = field(default_factory=list)

    parent_addr: Optional[str] = None

    children: List[str] = field(default_factory=list)

class ClosureScopeTracker:

    def __init__(self, blocks: Dict[str, Tuple[str, List[str]]],
                 parse_instrs_fn):

        self._blocks = blocks
        self._parse = parse_instrs_fn
        self._scopes: Dict[str, ScopeInfo] = {}
        self._key_to_addr: Dict[str, str] = {}

    def build(self):

        for key, (name, lines) in self._blocks.items():
            addr = key.split('@')[-1] if '@' in key else key
            scope = ScopeInfo(name=name, addr=addr)
            self._scopes[addr] = scope
            self._key_to_addr[key] = addr
            instrs = self._parse(lines)
            self._analyze_scope(scope, instrs)

        for key, (name, lines) in self._blocks.items():
            addr = self._key_to_addr[key]
            instrs = self._parse(lines)
            self._find_children(addr, instrs)

    def _analyze_scope(self, scope: ScopeInfo, instrs: List[Instr]):

        for instr in instrs:
            op = instr.opcode
            raw = instr.raw_arg

            if op == 'MAKE_CELL':

                name = self._extract_name(raw)
                if name:
                    scope.cell_vars.add(name)

            elif op in ('LOAD_DEREF', 'STORE_DEREF', 'DELETE_DEREF', 'LOAD_CLASSDEREF'):
                name = self._extract_name(raw)
                if name and not name.startswith('__'):
                    scope.free_vars.add(name)

            elif op in ('LOAD_FAST', 'LOAD_FAST_BORROW', 'STORE_FAST',
                        'LOAD_FAST_CHECK', 'LOAD_FAST_AND_CLEAR'):
                name = self._extract_name(raw)
                if name:
                    scope.local_vars.add(name)

            elif op in ('LOAD_FAST_BORROW_LOAD_FAST_BORROW', 'STORE_FAST_STORE_FAST'):

                for n in self._extract_names_dual(raw):
                    scope.local_vars.add(n)

    def _find_children(self, parent_addr: str, instrs: List[Instr]):

        for i, instr in enumerate(instrs):
            if instr.opcode == 'MAKE_FUNCTION':

                if i > 0:
                    prev = instrs[i - 1]
                    m = re.search(r'code object (\w+) at (0x[0-9a-fA-F]+)',
                                  prev.raw_arg)
                    if m:
                        child_addr = m.group(2).lower()
                        if child_addr in self._scopes:
                            child_scope = self._scopes[child_addr]
                            child_scope.parent_addr = parent_addr
                            parent_scope = self._scopes.get(parent_addr)
                            if parent_scope and child_addr not in parent_scope.children:
                                parent_scope.children.append(child_addr)

    def get_nonlocals(self, func_addr: str) -> List[str]:

        scope = self._scopes.get(func_addr)
        if not scope or not scope.free_vars:
            return []

        nonlocals = []
        for var in sorted(scope.free_vars):
            if self._is_nonlocal(var, scope):
                nonlocals.append(var)
        return nonlocals

    def _is_nonlocal(self, var: str, scope: ScopeInfo) -> bool:

        parent_addr = scope.parent_addr
        while parent_addr:
            parent = self._scopes.get(parent_addr)
            if parent is None:
                break
            if var in parent.cell_vars:
                return True

            if var in parent.local_vars and var not in parent.free_vars:
                return False
            parent_addr = parent.parent_addr
        return False

    def get_cell_vars_for_children(self, func_addr: str) -> Set[str]:

        scope = self._scopes.get(func_addr)
        return scope.cell_vars if scope else set()

    def get_scope(self, func_addr: str) -> Optional[ScopeInfo]:
        return self._scopes.get(func_addr)

    @staticmethod
    def _extract_name(raw: str) -> Optional[str]:
        m = re.search(r'\(([^)]+)\)', raw)
        if m:
            return m.group(1).strip().split(',')[0].strip()
        return raw.strip('()').strip() or None

    @staticmethod
    def _extract_names_dual(raw: str) -> List[str]:
        m = re.search(r'\(([^)]+)\)', raw)
        if m:
            return [p.strip() for p in m.group(1).split(',') if p.strip()]
        return []

