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

BINARY_OPS = {
    0: '+', 1: '&', 2: '//', 3: '@', 4: '<<', 5: '%', 6: '*',
    7: '|', 8: '**', 9: '>>', 10: '-', 11: '/', 12: '^',
    13: '+=', 14: '&=', 15: '//=', 16: '@=',
    17: '<<=', 18: '%=', 19: '*=', 20: '|=',
    21: '**=', 22: '>>=', 23: '-=', 24: '/=', 25: '^=',
}
INPLACE_OPS = {13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25}
INPLACE_MAP = {
    13: '+=', 14: '&=', 15: '//=', 16: '@=', 17: '<<=', 18: '%=',
    19: '*=', 20: '|=', 21: '**=', 22: '>>=', 23: '-=', 24: '/=', 25: '^=',
}

COMPARE_OPS = {
    0: '<', 1: '<=', 2: '==', 3: '!=', 4: '>', 5: '>=',
    18: '<', 58: '<=', 88: '==', 104: '!=', 148: '>', 196: '>=',
}

SKIP_OPCODES = (
    'RESUME', 'NOP', 'CACHE', 'NOT_TAKEN', 'COPY_FREE_VARS',
    'MAKE_CELL', 'EXTENDED_ARG', 'PRECALL', 'ADAPTIVE',
    'JUMP_BACKWARD_NO_INTERRUPT', '__EXCTABLE_ENTRY__',
    'RESUME_CHECK',
    'CHECK_STACK_SPACE',
)
SKIP_OPCODES_SET = set(SKIP_OPCODES)

TIER2_OPCODE_NORMALIZE: Dict[str, str] = {
    'BINARY_OP_ADD_FLOAT':             'BINARY_OP',
    'BINARY_OP_ADD_INT':               'BINARY_OP',
    'BINARY_OP_ADD_UNICODE':           'BINARY_OP',
    'BINARY_OP_INPLACE_ADD_UNICODE':   'BINARY_OP',
    'BINARY_OP_MULTIPLY_FLOAT':        'BINARY_OP',
    'BINARY_OP_MULTIPLY_INT':          'BINARY_OP',
    'BINARY_OP_SUBTRACT_FLOAT':        'BINARY_OP',
    'BINARY_OP_SUBTRACT_INT':          'BINARY_OP',
    'BINARY_SUBSCR_DICT':              'BINARY_SUBSCR',
    'BINARY_SUBSCR_GETITEM':           'BINARY_SUBSCR',
    'BINARY_SUBSCR_LIST_INT':          'BINARY_SUBSCR',
    'BINARY_SUBSCR_STR_INT':           'BINARY_SUBSCR',
    'BINARY_SUBSCR_TUPLE_INT':         'BINARY_SUBSCR',
    'STORE_SUBSCR_DICT':               'STORE_SUBSCR',
    'STORE_SUBSCR_LIST_INT':           'STORE_SUBSCR',
    'LOAD_ATTR_CLASS':                 'LOAD_ATTR',
    'LOAD_ATTR_CLASS_WITH_METACLASS_CHECK': 'LOAD_ATTR',
    'LOAD_ATTR_GETATTRIBUTE_OVERRIDDEN': 'LOAD_ATTR',
    'LOAD_ATTR_INSTANCE_VALUE':        'LOAD_ATTR',
    'LOAD_ATTR_METHOD_LAZY_DICT':      'LOAD_ATTR',
    'LOAD_ATTR_METHOD_NO_DICT':        'LOAD_ATTR',
    'LOAD_ATTR_METHOD_WITH_VALUES':    'LOAD_ATTR',
    'LOAD_ATTR_MODULE':                'LOAD_ATTR',
    'LOAD_ATTR_NONDESCRIPTOR_NO_DICT': 'LOAD_ATTR',
    'LOAD_ATTR_NONDESCRIPTOR_WITH_VALUES': 'LOAD_ATTR',
    'LOAD_ATTR_PROPERTY':              'LOAD_ATTR',
    'LOAD_ATTR_SLOT':                  'LOAD_ATTR',
    'LOAD_ATTR_WITH_HINT':             'LOAD_ATTR',
    'STORE_ATTR_INSTANCE_VALUE':       'STORE_ATTR',
    'STORE_ATTR_SLOT':                 'STORE_ATTR',
    'STORE_ATTR_WITH_HINT':            'STORE_ATTR',
    'LOAD_GLOBAL_BUILTIN':             'LOAD_GLOBAL',
    'LOAD_GLOBAL_MODULE':              'LOAD_GLOBAL',
    'LOAD_SUPER_ATTR_ATTR':            'LOAD_SUPER_ATTR',
    'LOAD_SUPER_ATTR_METHOD':          'LOAD_SUPER_ATTR',
    'CALL_ALLOC_AND_ENTER_INIT':       'CALL',
    'CALL_BOUND_METHOD_EXACT_ARGS':    'CALL',
    'CALL_BOUND_METHOD_GENERAL':       'CALL',
    'CALL_BUILTIN_CLASS':              'CALL',
    'CALL_BUILTIN_FAST':               'CALL',
    'CALL_BUILTIN_FAST_WITH_KEYWORDS': 'CALL',
    'CALL_BUILTIN_O':                  'CALL',
    'CALL_ISINSTANCE':                 'CALL',
    'CALL_LEN':                        'CALL',
    'CALL_LIST_APPEND':                'CALL',
    'CALL_METHOD_DESCRIPTOR_FAST':     'CALL',
    'CALL_METHOD_DESCRIPTOR_FAST_WITH_KEYWORDS': 'CALL',
    'CALL_METHOD_DESCRIPTOR_NOARGS':   'CALL',
    'CALL_METHOD_DESCRIPTOR_O':        'CALL',
    'CALL_NON_PY_GENERAL':             'CALL',
    'CALL_PY_EXACT_ARGS':              'CALL',
    'CALL_PY_GENERAL':                 'CALL',
    'CALL_STR_1':                      'CALL',
    'CALL_TUPLE_1':                    'CALL',
    'CALL_TYPE_1':                     'CALL',
    'FOR_ITER_GEN':                    'FOR_ITER',
    'FOR_ITER_LIST':                   'FOR_ITER',
    'FOR_ITER_RANGE':                  'FOR_ITER',
    'FOR_ITER_TUPLE':                  'FOR_ITER',
    'COMPARE_OP_FLOAT':                'COMPARE_OP',
    'COMPARE_OP_INT':                  'COMPARE_OP',
    'COMPARE_OP_STR':                  'COMPARE_OP',
    'CONTAINS_OP_DICT':                'CONTAINS_OP',
    'CONTAINS_OP_SET':                 'CONTAINS_OP',
    'SEND_GEN':                        'SEND',
    'LOAD_FAST_BORROW_LOAD_FAST_BORROW': 'LOAD_FAST_BORROW_LOAD_FAST_BORROW',
    'UNPACK_SEQUENCE_LIST':            'UNPACK_SEQUENCE',
    'UNPACK_SEQUENCE_TUPLE':           'UNPACK_SEQUENCE',
    'UNPACK_SEQUENCE_TWO_TUPLE':       'UNPACK_SEQUENCE',
    'TO_BOOL_ALWAYS_TRUE':             'TO_BOOL',
    'TO_BOOL_BOOL':                    'TO_BOOL',
    'TO_BOOL_INT':                     'TO_BOOL',
    'TO_BOOL_LIST':                    'TO_BOOL',
    'TO_BOOL_NONE':                    'TO_BOOL',
    'TO_BOOL_STR':                     'TO_BOOL',
    '_DO_CALL':                        'CALL',
    '_CALL_BUILTIN_FAST':              'CALL',
    '_GUARD_TYPE_VERSION':             'NOP',
    '_CHECK_VALIDITY':                 'NOP',
    '_DEOPT':                          'NOP',
    '_EXIT_TRACE':                     'NOP',
    '_GUARD_GLOBALS_VERSION':          'NOP',
    '_GUARD_BUILTINS_VERSION':         'NOP',
    '_GUARD_NOT_EXHAUSTED_LIST':       'NOP',
    '_GUARD_NOT_EXHAUSTED_RANGE':      'NOP',
    '_GUARD_NOT_EXHAUSTED_TUPLE':      'NOP',
    '_ITER_JUMP_LIST':                 'FOR_ITER',
    '_ITER_JUMP_RANGE':                'FOR_ITER',
    '_ITER_JUMP_TUPLE':                'FOR_ITER',
    '_ITER_NEXT_LIST':                 'FOR_ITER',
    '_ITER_NEXT_RANGE':                'FOR_ITER',
    '_ITER_NEXT_TUPLE':                'FOR_ITER',
}

