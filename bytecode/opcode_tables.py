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

def _build_opcode_table_310() -> Dict[int, str]:

    t = {}
    _ops = [
        (1,'POP_TOP'),(2,'ROT_TWO'),(3,'ROT_THREE'),(4,'DUP_TOP'),
        (5,'DUP_TOP_TWO'),(6,'ROT_FOUR'),(9,'NOP'),(10,'UNARY_POSITIVE'),
        (11,'UNARY_NEGATIVE'),(12,'UNARY_NOT'),(15,'UNARY_INVERT'),
        (16,'BINARY_MATRIX_MULTIPLY'),(17,'INPLACE_MATRIX_MULTIPLY'),
        (19,'BINARY_POWER'),(20,'BINARY_MULTIPLY'),(22,'BINARY_MODULO'),
        (23,'BINARY_ADD'),(24,'BINARY_SUBTRACT'),(25,'BINARY_SUBSCR'),
        (26,'BINARY_FLOOR_DIVIDE'),(27,'BINARY_TRUE_DIVIDE'),
        (28,'INPLACE_FLOOR_DIVIDE'),(29,'INPLACE_TRUE_DIVIDE'),
        (49,'GET_AITER'),(50,'GET_ANEXT'),(51,'BEFORE_ASYNC_WITH'),
        (53,'END_ASYNC_FOR'),(54,'INPLACE_ADD'),(55,'INPLACE_SUBTRACT'),
        (56,'INPLACE_MULTIPLY'),(57,'INPLACE_MODULO'),
        (59,'BINARY_LSHIFT'),(60,'BINARY_RSHIFT'),(61,'BINARY_AND'),
        (62,'BINARY_XOR'),(63,'BINARY_OR'),(64,'INPLACE_POWER'),
        (65,'GET_ITER'),(66,'GET_YIELD_FROM_ITER'),(67,'PRINT_EXPR'),
        (68,'LOAD_BUILD_CLASS'),(69,'YIELD_FROM'),(70,'GET_AWAITABLE'),
        (71,'LOAD_ASSERTION_ERROR'),(72,'INPLACE_LSHIFT'),
        (73,'INPLACE_RSHIFT'),(74,'INPLACE_AND'),(75,'INPLACE_XOR'),
        (76,'INPLACE_OR'),(77,'WITH_EXCEPT_START'),(78,'LIST_TO_TUPLE'),
        (79,'RETURN_VALUE'),(80,'IMPORT_STAR'),(81,'SETUP_ANNOTATIONS'),
        (82,'YIELD_VALUE'),(83,'POP_BLOCK'),(85,'POP_EXCEPT'),
        (90,'STORE_NAME'),(91,'DELETE_NAME'),(92,'UNPACK_SEQUENCE'),
        (93,'FOR_ITER'),(94,'UNPACK_EX'),(95,'STORE_ATTR'),
        (96,'DELETE_ATTR'),(97,'STORE_GLOBAL'),(98,'DELETE_GLOBAL'),
        (100,'LOAD_CONST'),(101,'LOAD_NAME'),(102,'BUILD_TUPLE'),
        (103,'BUILD_LIST'),(104,'BUILD_SET'),(105,'BUILD_MAP'),
        (106,'LOAD_ATTR'),(107,'COMPARE_OP'),(108,'IMPORT_NAME'),
        (109,'IMPORT_FROM'),(110,'JUMP_FORWARD'),
        (111,'JUMP_IF_FALSE_OR_POP'),(112,'JUMP_IF_TRUE_OR_POP'),
        (113,'JUMP_ABSOLUTE'),(114,'POP_JUMP_IF_FALSE'),
        (115,'POP_JUMP_IF_TRUE'),(116,'LOAD_GLOBAL'),(117,'IS_OP'),
        (118,'CONTAINS_OP'),(119,'RERAISE'),(121,'JUMP_IF_NOT_EXC_MATCH'),
        (122,'SETUP_FINALLY'),(124,'LOAD_FAST'),(125,'STORE_FAST'),
        (126,'DELETE_FAST'),(129,'RAISE_VARARGS'),(130,'CALL_FUNCTION'),
        (131,'MAKE_FUNCTION'),(132,'BUILD_SLICE'),(133,'LOAD_CLOSURE'),
        (134,'LOAD_DEREF'),(135,'STORE_DEREF'),(136,'DELETE_DEREF'),
        (141,'CALL_FUNCTION_KW'),(142,'CALL_FUNCTION_EX'),
        (143,'SETUP_WITH'),(144,'EXTENDED_ARG'),
        (145,'LIST_APPEND'),(146,'SET_ADD'),(147,'MAP_ADD'),
        (148,'LOAD_CLASSDEREF'),(149,'MATCH_CLASS'),
        (152,'SETUP_ASYNC_WITH'),(153,'FORMAT_VALUE'),
        (154,'BUILD_STRING'),(155,'LOAD_METHOD'),(156,'CALL_METHOD'),
        (158,'MATCH_MAPPING'),(159,'MATCH_SEQUENCE'),
        (160,'MATCH_KEYS'),(161,'COPY_DICT_WITHOUT_KEYS'),
        (162,'ROT_N'),(163,'MAKE_CELL'),(164,'LOAD_FAST_CHECK'),
        (165,'COPY_FREE_VARS'),
    ]
    for op, name in _ops:
        t[op] = name
    return t

def _build_opcode_table_311() -> Dict[int, str]:

    t = {}
    _ops = [
        (0,'CACHE'),(1,'POP_TOP'),(2,'PUSH_NULL'),(3,'INTERPRETER_EXIT'),
        (4,'END_FOR'),(5,'END_SEND'),(9,'NOP'),
        (11,'UNARY_NEGATIVE'),(12,'UNARY_NOT'),(15,'UNARY_INVERT'),
        (16,'BINARY_SUBSCR'),(17,'BINARY_SLICE'),(18,'STORE_SLICE'),
        (19,'GET_LEN'),(20,'MATCH_MAPPING'),(21,'MATCH_SEQUENCE'),
        (22,'MATCH_KEYS'),(25,'PUSH_EXC_INFO'),(26,'CHECK_EXC_MATCH'),
        (27,'CHECK_EG_MATCH'),(35,'WITH_EXCEPT_START'),(36,'GET_AITER'),
        (37,'GET_ANEXT'),(38,'BEFORE_ASYNC_WITH'),(39,'BEFORE_WITH'),
        (40,'END_ASYNC_FOR'),(49,'STORE_SUBSCR'),(50,'DELETE_SUBSCR'),
        (52,'GET_ITER'),(53,'GET_YIELD_FROM_ITER'),(54,'LOAD_BUILD_CLASS'),
        (58,'LOAD_ASSERTION_ERROR'),(59,'RETURN_GENERATOR'),
        (60,'LIST_TO_TUPLE'),(61,'RETURN_VALUE'),(62,'IMPORT_STAR'),
        (63,'SETUP_ANNOTATIONS'),(64,'YIELD_VALUE'),(65,'ASYNC_GEN_WRAP'),
        (66,'PREP_RERAISE_STAR'),(67,'POP_EXCEPT'),(68,'STORE_NAME'),
        (69,'DELETE_NAME'),(70,'UNPACK_SEQUENCE'),(71,'FOR_ITER'),
        (72,'UNPACK_EX'),(73,'STORE_ATTR'),(74,'DELETE_ATTR'),
        (75,'STORE_GLOBAL'),(76,'DELETE_GLOBAL'),(77,'SWAP'),
        (78,'LOAD_CONST'),(79,'LOAD_NAME'),(80,'BUILD_TUPLE'),
        (81,'BUILD_LIST'),(82,'BUILD_SET'),(83,'BUILD_MAP'),
        (84,'LOAD_ATTR'),(85,'COMPARE_OP'),(86,'IMPORT_NAME'),
        (87,'IMPORT_FROM'),(88,'JUMP_FORWARD'),(89,'JUMP_BACKWARD_NO_INTERRUPT'),
        (90,'POP_JUMP_FORWARD_IF_NONE'),(91,'POP_JUMP_FORWARD_IF_NOT_NONE'),
        (92,'POP_JUMP_BACKWARD_IF_NOT_NONE'),(93,'POP_JUMP_BACKWARD_IF_NONE'),
        (94,'POP_JUMP_BACKWARD_IF_FALSE'),(95,'POP_JUMP_BACKWARD_IF_TRUE'),
        (96,'LOAD_GLOBAL'),(97,'IS_OP'),(98,'CONTAINS_OP'),(99,'RERAISE'),
        (100,'COPY'),(101,'BINARY_OP'),(102,'SEND'),(103,'LOAD_FAST'),
        (104,'STORE_FAST'),(105,'DELETE_FAST'),(106,'LOAD_FAST_CHECK'),
        (107,'POP_JUMP_FORWARD_IF_FALSE'),(108,'POP_JUMP_FORWARD_IF_TRUE'),
        (109,'LOAD_CLOSURE'),(110,'LOAD_DEREF'),(111,'STORE_DEREF'),
        (112,'DELETE_DEREF'),(113,'JUMP_BACKWARD'),
        (114,'LOAD_SUPER_ATTR'),(115,'CALL_INTRINSIC_1'),
        (116,'CALL_INTRINSIC_2'),(117,'LOAD_CLASSDEREF'),
        (118,'COPY_FREE_VARS'),(119,'YIELD_VALUE'),(120,'RESUME'),
        (121,'MATCH_CLASS'),(122,'FORMAT_VALUE'),(123,'BUILD_STRING'),
        (124,'LOAD_METHOD'),(136,'CALL'),(137,'KW_NAMES'),
        (138,'CALL_FUNCTION_EX'),(140,'EXTENDED_ARG'),
        (141,'LIST_APPEND'),(142,'SET_ADD'),(143,'MAP_ADD'),
        (146,'MAKE_FUNCTION'),(147,'BUILD_SLICE'),(149,'MAKE_CELL'),
        (150,'RAISE_VARARGS'),(151,'JUMP_BACKWARD_NO_INTERRUPT'),
        (152,'DICT_MERGE'),(153,'DICT_UPDATE'),(154,'LIST_EXTEND'),
        (155,'SET_UPDATE'),(156,'LOAD_CLASSDEREF'),
        (162,'BEFORE_WITH'),
    ]
    for op, name in _ops:
        t[op] = name
    return t

def _build_opcode_table_312() -> Dict[int, str]:

    t = {}
    _ops = [

        (0,'CACHE'),(1,'POP_TOP'),(2,'PUSH_NULL'),(3,'INTERPRETER_EXIT'),
        (4,'END_FOR'),(5,'END_SEND'),(9,'NOP'),
        (11,'UNARY_NEGATIVE'),(12,'UNARY_NOT'),(15,'UNARY_INVERT'),
        (17,'RESERVED'),
        (25,'BINARY_SUBSCR'),(26,'BINARY_SLICE'),(27,'STORE_SLICE'),
        (30,'GET_LEN'),(31,'MATCH_MAPPING'),(32,'MATCH_SEQUENCE'),
        (33,'MATCH_KEYS'),(35,'PUSH_EXC_INFO'),(36,'CHECK_EXC_MATCH'),
        (37,'CHECK_EG_MATCH'),
        (49,'WITH_EXCEPT_START'),(50,'GET_AITER'),(51,'GET_ANEXT'),
        (52,'BEFORE_ASYNC_WITH'),(53,'BEFORE_WITH'),(54,'END_ASYNC_FOR'),
        (55,'CLEANUP_THROW'),
        (60,'STORE_SUBSCR'),(61,'DELETE_SUBSCR'),
        (68,'GET_ITER'),(69,'GET_YIELD_FROM_ITER'),
        (71,'LOAD_BUILD_CLASS'),(74,'LOAD_ASSERTION_ERROR'),
        (75,'RETURN_GENERATOR'),
        (83,'RETURN_VALUE'),(85,'SETUP_ANNOTATIONS'),(87,'LOAD_LOCALS'),
        (89,'POP_EXCEPT'),

        (90,'STORE_NAME'),(91,'DELETE_NAME'),(92,'UNPACK_SEQUENCE'),
        (93,'FOR_ITER'),(94,'UNPACK_EX'),(95,'STORE_ATTR'),
        (96,'DELETE_ATTR'),(97,'STORE_GLOBAL'),(98,'DELETE_GLOBAL'),
        (99,'SWAP'),(100,'LOAD_CONST'),(101,'LOAD_NAME'),
        (102,'BUILD_TUPLE'),(103,'BUILD_LIST'),(104,'BUILD_SET'),
        (105,'BUILD_MAP'),(106,'LOAD_ATTR'),(107,'COMPARE_OP'),
        (108,'IMPORT_NAME'),(109,'IMPORT_FROM'),(110,'JUMP_FORWARD'),
        (114,'POP_JUMP_IF_FALSE'),(115,'POP_JUMP_IF_TRUE'),
        (116,'LOAD_GLOBAL'),(117,'IS_OP'),(118,'CONTAINS_OP'),
        (119,'RERAISE'),(120,'COPY'),(121,'RETURN_CONST'),
        (122,'BINARY_OP'),(123,'SEND'),
        (124,'LOAD_FAST'),(125,'STORE_FAST'),(126,'DELETE_FAST'),
        (127,'LOAD_FAST_CHECK'),(128,'POP_JUMP_IF_NOT_NONE'),
        (129,'POP_JUMP_IF_NONE'),(130,'RAISE_VARARGS'),
        (131,'GET_AWAITABLE'),(132,'MAKE_FUNCTION'),(133,'BUILD_SLICE'),
        (134,'JUMP_BACKWARD_NO_INTERRUPT'),(135,'MAKE_CELL'),
        (136,'LOAD_CLOSURE'),(137,'LOAD_DEREF'),(138,'STORE_DEREF'),
        (139,'DELETE_DEREF'),(140,'JUMP_BACKWARD'),(141,'LOAD_SUPER_ATTR'),
        (142,'CALL_FUNCTION_EX'),(143,'LOAD_FAST_AND_CLEAR'),
        (144,'EXTENDED_ARG'),(145,'LIST_APPEND'),(146,'SET_ADD'),
        (147,'MAP_ADD'),(149,'COPY_FREE_VARS'),(150,'YIELD_VALUE'),
        (151,'RESUME'),(152,'MATCH_CLASS'),(155,'FORMAT_VALUE'),
        (156,'BUILD_CONST_KEY_MAP'),(157,'BUILD_STRING'),
        (162,'LIST_EXTEND'),(163,'SET_UPDATE'),(164,'DICT_MERGE'),
        (165,'DICT_UPDATE'),
        (171,'CALL'),(172,'KW_NAMES'),(173,'CALL_INTRINSIC_1'),
        (174,'CALL_INTRINSIC_2'),(175,'LOAD_FROM_DICT_OR_GLOBALS'),
        (176,'LOAD_FROM_DICT_OR_DEREF'),
    ]
    for op, name in _ops:
        t[op] = name
    return t

def _build_opcode_table_313() -> Dict[int, str]:

    t = _build_opcode_table_312()

    updates = [

        (87,'LOAD_LOCALS'),

        (128,'POP_JUMP_IF_NOT_NONE'),(129,'POP_JUMP_IF_NONE'),
    ]
    for op, name in updates:
        t[op] = name
    return t

def _build_opcode_table_314() -> Dict[int, str]:

    t = _build_opcode_table_313()

    updates_314 = [

        (74,'LOAD_FAST_BORROW'),
        (75,'LOAD_FAST_BORROW_LOAD_FAST_BORROW'),
        (77,'STORE_FAST_STORE_FAST'),
        (116,'CALL_KW'),
        (117,'LOAD_SPECIAL'),
    ]
    for op, name in updates_314:
        t[op] = name
    return t

_OPCODE_TABLE_BUILDERS = {
    (3, 10): _build_opcode_table_310,
    (3, 11): _build_opcode_table_311,
    (3, 12): _build_opcode_table_312,
    (3, 13): _build_opcode_table_313,
    (3, 14): _build_opcode_table_314,
}

def _get_opcode_table(py_ver: Tuple[int, int]) -> Dict[int, str]:

    cur = sys.version_info[:2]
    if py_ver == cur:

        import opcode as _opcode_mod
        return {v: k for k, v in _opcode_mod.opmap.items()}
    builder = _OPCODE_TABLE_BUILDERS.get(py_ver)
    if builder:
        return builder()

    versions = sorted(_OPCODE_TABLE_BUILDERS.keys())
    best = versions[0]
    for v in versions:
        if v <= py_ver:
            best = v
    return _OPCODE_TABLE_BUILDERS[best]()

_MAGIC_TO_VERSION: Dict[int, Tuple[int, int]] = {

    3430: (3, 10), 3431: (3, 10), 3432: (3, 10), 3433: (3, 10),
    3434: (3, 10), 3435: (3, 10),

    3495: (3, 11), 3496: (3, 11), 3497: (3, 11), 3498: (3, 11),
    3499: (3, 11), 3500: (3, 11), 3501: (3, 11), 3502: (3, 11),
    3503: (3, 11), 3504: (3, 11), 3505: (3, 11), 3506: (3, 11),
    3507: (3, 11), 3508: (3, 11), 3509: (3, 11), 3510: (3, 11),
    3511: (3, 11),

    3531: (3, 12), 3532: (3, 12), 3533: (3, 12), 3534: (3, 12),
    3535: (3, 12), 3536: (3, 12), 3537: (3, 12), 3538: (3, 12),
    3539: (3, 12),

    3570: (3, 13), 3571: (3, 13), 3572: (3, 13), 3573: (3, 13),
    3574: (3, 13), 3575: (3, 13), 3576: (3, 13),

    3600: (3, 14), 3601: (3, 14), 3602: (3, 14), 3603: (3, 14),
    3604: (3, 14), 3605: (3, 14),
}

_HAVE_ARGUMENT: Dict[Tuple[int,int], int] = {
    (3, 10): 90,
    (3, 11): 90,
    (3, 12): 90,
    (3, 13): 90,
    (3, 14): 90,
}

_CACHE_COUNTS: Dict[Tuple[int,int], Dict[str, int]] = {
    (3, 11): {
        'BINARY_SUBSCR': 4, 'STORE_SUBSCR': 1, 'UNPACK_SEQUENCE': 1,
        'FOR_ITER': 1, 'LOAD_GLOBAL': 4, 'LOAD_ATTR': 4,
        'COMPARE_OP': 1, 'LOAD_METHOD': 10, 'CALL': 4, 'BINARY_OP': 1,
        'PRECALL': 1,
    },
    (3, 12): {
        'BINARY_SUBSCR': 1, 'STORE_SUBSCR': 1, 'UNPACK_SEQUENCE': 1,
        'FOR_ITER': 1, 'LOAD_GLOBAL': 4, 'LOAD_ATTR': 4,
        'COMPARE_OP': 1, 'CALL': 4, 'BINARY_OP': 1, 'STORE_ATTR': 4,
        'LOAD_SUPER_ATTR': 1, 'LOAD_METHOD': 10,
    },
    (3, 13): {
        'BINARY_SUBSCR': 1, 'STORE_SUBSCR': 1, 'UNPACK_SEQUENCE': 1,
        'FOR_ITER': 1, 'LOAD_GLOBAL': 4, 'LOAD_ATTR': 4,
        'COMPARE_OP': 1, 'CALL': 4, 'BINARY_OP': 1, 'STORE_ATTR': 4,
        'LOAD_SUPER_ATTR': 1,
    },
    (3, 14): {
        'BINARY_SUBSCR': 1, 'STORE_SUBSCR': 1, 'UNPACK_SEQUENCE': 1,
        'FOR_ITER': 1, 'LOAD_GLOBAL': 4, 'LOAD_ATTR': 4,
        'COMPARE_OP': 2, 'CALL': 4, 'BINARY_OP': 1, 'STORE_ATTR': 4,
        'LOAD_SUPER_ATTR': 1, 'CALL_KW': 4,
        'LOAD_FAST_BORROW_LOAD_FAST_BORROW': 1, 'STORE_FAST_STORE_FAST': 1,
    },
}

_BINARY_OP_NAMES = {
    0: '+', 1: '&', 2: '//', 3: '@', 4: '<<', 5: '%', 6: '*',
    7: '|', 8: '**', 9: '>>', 10: '-', 11: '/', 12: '^',
    13: '+=', 14: '&=', 15: '//=', 16: '@=', 17: '<<=', 18: '%=',
    19: '*=', 20: '|=', 21: '**=', 22: '>>=', 23: '-=', 24: '/=', 25: '^=',
}

_CMP_OPS_310 = ['<', '<=', '==', '!=', '>', '>=', 'in', 'not in', 'is', 'is not', 'exception match', 'BAD']
_CMP_OPS_312 = ['<', '<=', '==', '!=', '>', '>=']

def _cmp_op_name(arg: int, py_ver: Tuple[int,int]) -> str:
    if py_ver <= (3, 11):
        idx = arg
        ops = _CMP_OPS_310
        if 0 <= idx < len(ops):
            return ops[idx]
    else:

        real_idx = arg >> 4 if py_ver >= (3, 12) else arg
        ops = _CMP_OPS_312
        if 0 <= real_idx < len(ops):
            return ops[real_idx]

        ops2 = _CMP_OPS_310
        if 0 <= arg < len(ops2):
            return ops2[arg]
    return '=='

