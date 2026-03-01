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

class CtypesStructureGenerator:

    STRUCT_TEMPLATES: Dict[str, List[Tuple[str, str]]] = {
        'MOUSEINPUT': [
            ('dx',          'c_long'),
            ('dy',          'c_long'),
            ('mouseData',   'c_ulong'),
            ('dwFlags',     'c_ulong'),
            ('time',        'c_ulong'),
            ('dwExtraInfo', 'ULONG_PTR'),
        ],
        'KEYBDINPUT': [
            ('wVk',         'c_ushort'),
            ('wScan',       'c_ushort'),
            ('dwFlags',     'c_ulong'),
            ('time',        'c_ulong'),
            ('dwExtraInfo', 'ULONG_PTR'),
        ],
        'HARDWAREINPUT': [
            ('uMsg',    'c_ulong'),
            ('wParamL', 'c_ushort'),
            ('wParamH', 'c_ushort'),
        ],
        'POINT': [
            ('x', 'c_long'),
            ('y', 'c_long'),
        ],
        'RECT': [
            ('left',   'c_long'),
            ('top',    'c_long'),
            ('right',  'c_long'),
            ('bottom', 'c_long'),
        ],
        'SIZE': [
            ('cx', 'c_long'),
            ('cy', 'c_long'),
        ],
        'COORD': [
            ('X', 'c_short'),
            ('Y', 'c_short'),
        ],
        'SMALL_RECT': [
            ('Left',   'c_short'),
            ('Top',    'c_short'),
            ('Right',  'c_short'),
            ('Bottom', 'c_short'),
        ],
        'CONSOLE_SCREEN_BUFFER_INFO': [
            ('dwSize',               'COORD'),
            ('dwCursorPosition',     'COORD'),
            ('wAttributes',          'c_ushort'),
            ('srWindow',             'SMALL_RECT'),
            ('dwMaximumWindowSize',  'COORD'),
        ],
        'FILETIME': [
            ('dwLowDateTime',  'c_ulong'),
            ('dwHighDateTime', 'c_ulong'),
        ],
        'SYSTEMTIME': [
            ('wYear',         'c_ushort'),
            ('wMonth',        'c_ushort'),
            ('wDayOfWeek',    'c_ushort'),
            ('wDay',          'c_ushort'),
            ('wHour',         'c_ushort'),
            ('wMinute',       'c_ushort'),
            ('wSecond',       'c_ushort'),
            ('wMilliseconds', 'c_ushort'),
        ],
        'GUID': [
            ('Data1', 'c_ulong'),
            ('Data2', 'c_ushort'),
            ('Data3', 'c_ushort'),
            ('Data4', 'c_ubyte * 8'),
        ],
        'SECURITY_ATTRIBUTES': [
            ('nLength',              'c_ulong'),
            ('lpSecurityDescriptor', 'c_void_p'),
            ('bInheritHandle',       'c_bool'),
        ],
        'PROCESS_INFORMATION': [
            ('hProcess',    'HANDLE'),
            ('hThread',     'HANDLE'),
            ('dwProcessId', 'c_ulong'),
            ('dwThreadId',  'c_ulong'),
        ],
        'OVERLAPPED_OFFSET': [
            ('Offset',     'c_ulong'),
            ('OffsetHigh', 'c_ulong'),
        ],
        'OVERLAPPED': [
            ('Internal',     'ULONG_PTR'),
            ('InternalHigh', 'ULONG_PTR'),
            ('Offset',       'c_ulong'),
            ('OffsetHigh',   'c_ulong'),
            ('hEvent',       'HANDLE'),
        ],
        'MEMORY_BASIC_INFORMATION': [
            ('BaseAddress',       'c_void_p'),
            ('AllocationBase',    'c_void_p'),
            ('AllocationProtect', 'c_ulong'),
            ('RegionSize',        'c_size_t'),
            ('State',             'c_ulong'),
            ('Protect',           'c_ulong'),
            ('Type',              'c_ulong'),
        ],
        'MODULEINFO': [
            ('lpBaseOfDll', 'c_void_p'),
            ('SizeOfImage', 'c_ulong'),
            ('EntryPoint',  'c_void_p'),
        ],
        'THREADENTRY32': [
            ('dwSize',             'c_ulong'),
            ('cntUsage',           'c_ulong'),
            ('th32ThreadID',       'c_ulong'),
            ('th32OwnerProcessID', 'c_ulong'),
            ('tpBasePri',          'c_long'),
            ('tpDeltaPri',         'c_long'),
            ('dwFlags',            'c_ulong'),
        ],
        'PROCESSENTRY32': [
            ('dwSize',              'c_ulong'),
            ('cntUsage',            'c_ulong'),
            ('th32ProcessID',       'c_ulong'),
            ('th32DefaultHeapID',   'ULONG_PTR'),
            ('th32ModuleID',        'c_ulong'),
            ('cntThreads',          'c_ulong'),
            ('th32ParentProcessID', 'c_ulong'),
            ('pcPriClassBase',      'c_long'),
            ('dwFlags',             'c_ulong'),
            ('szExeFile',           'c_char * 260'),
        ],
        'MODULEENTRY32': [
            ('dwSize',        'c_ulong'),
            ('th32ModuleID',  'c_ulong'),
            ('th32ProcessID', 'c_ulong'),
            ('GlblcntUsage',  'c_ulong'),
            ('ProccntUsage',  'c_ulong'),
            ('modBaseAddr',   'c_char_p'),
            ('modBaseSize',   'c_ulong'),
            ('hModule',       'HANDLE'),
            ('szModule',      'c_char * 256'),
            ('szExePath',     'c_char * 260'),
        ],
        'WIN32_FIND_DATA': [
            ('dwFileAttributes',   'c_ulong'),
            ('ftCreationTime',     'FILETIME'),
            ('ftLastAccessTime',   'FILETIME'),
            ('ftLastWriteTime',    'FILETIME'),
            ('nFileSizeHigh',      'c_ulong'),
            ('nFileSizeLow',       'c_ulong'),
            ('dwReserved0',        'c_ulong'),
            ('dwReserved1',        'c_ulong'),
            ('cFileName',          'c_wchar * 260'),
            ('cAlternateFileName', 'c_wchar * 14'),
        ],
        'STARTUPINFO': [
            ('cb',              'c_ulong'),
            ('lpReserved',      'c_wchar_p'),
            ('lpDesktop',       'c_wchar_p'),
            ('lpTitle',         'c_wchar_p'),
            ('dwX',             'c_ulong'),
            ('dwY',             'c_ulong'),
            ('dwXSize',         'c_ulong'),
            ('dwYSize',         'c_ulong'),
            ('dwXCountChars',   'c_ulong'),
            ('dwYCountChars',   'c_ulong'),
            ('dwFillAttribute', 'c_ulong'),
            ('dwFlags',         'c_ulong'),
            ('wShowWindow',     'c_ushort'),
            ('cbReserved2',     'c_ushort'),
            ('lpReserved2',     'c_char_p'),
            ('hStdInput',       'HANDLE'),
            ('hStdOutput',      'HANDLE'),
            ('hStdError',       'HANDLE'),
        ],
    }

    UNION_TEMPLATES: Dict[str, List[Tuple[str, str]]] = {
        '_INPUT_UNION': [
            ('mi', 'MOUSEINPUT'),
            ('ki', 'KEYBDINPUT'),
            ('hi', 'HARDWAREINPUT'),
        ],
        'LARGE_INTEGER_UNION': [
            ('LowPart',  'c_ulong'),
            ('HighPart', 'c_long'),
        ],
        'ULARGE_INTEGER_UNION': [
            ('LowPart',  'c_ulong'),
            ('HighPart', 'c_ulong'),
        ],
    }

    STANDALONE_DEFINITIONS: Dict[str, str] = {
        'INPUT_MOUSE':           '0',
        'INPUT_KEYBOARD':        '1',
        'INPUT_HARDWARE':        '2',
        'MOUSEEVENTF_MOVE':      '0x0001',
        'MOUSEEVENTF_LEFTDOWN':  '0x0002',
        'MOUSEEVENTF_LEFTUP':    '0x0004',
        'MOUSEEVENTF_RIGHTDOWN': '0x0008',
        'MOUSEEVENTF_RIGHTUP':   '0x0010',
        'MOUSEEVENTF_MIDDLEDOWN':'0x0020',
        'MOUSEEVENTF_MIDDLEUP':  '0x0040',
        'MOUSEEVENTF_WHEEL':     '0x0800',
        'MOUSEEVENTF_HWHEEL':    '0x1000',
        'MOUSEEVENTF_ABSOLUTE':  '0x8000',
        'KEYEVENTF_EXTENDEDKEY': '0x0001',
        'KEYEVENTF_KEYUP':       '0x0002',
        'KEYEVENTF_UNICODE':     '0x0004',
        'KEYEVENTF_SCANCODE':    '0x0008',
        'VK_LBUTTON':    '0x01',
        'VK_RBUTTON':    '0x02',
        'VK_CANCEL':     '0x03',
        'VK_MBUTTON':    '0x04',
        'VK_BACK':       '0x08',
        'VK_TAB':        '0x09',
        'VK_RETURN':     '0x0D',
        'VK_SHIFT':      '0x10',
        'VK_CONTROL':    '0x11',
        'VK_MENU':       '0x12',
        'VK_PAUSE':      '0x13',
        'VK_CAPITAL':    '0x14',
        'VK_ESCAPE':     '0x1B',
        'VK_SPACE':      '0x20',
        'VK_END':        '0x23',
        'VK_HOME':       '0x24',
        'VK_LEFT':       '0x25',
        'VK_UP':         '0x26',
        'VK_RIGHT':      '0x27',
        'VK_DOWN':       '0x28',
        'VK_DELETE':     '0x2E',
        'VK_F1':         '0x70',
        'VK_F2':         '0x71',
        'VK_F3':         '0x72',
        'VK_F4':         '0x73',
        'VK_F5':         '0x74',
        'VK_F6':         '0x75',
        'VK_F7':         '0x76',
        'VK_F8':         '0x77',
        'VK_F9':         '0x78',
        'VK_F10':        '0x79',
        'VK_F11':        '0x7A',
        'VK_F12':        '0x7B',
        'VK_LWIN':       '0x5B',
        'VK_RWIN':       '0x5C',
        'VK_NUMPAD0':    '0x60',
        'VK_NUMPAD1':    '0x61',
        'VK_NUMPAD2':    '0x62',
        'VK_NUMPAD3':    '0x63',
        'VK_NUMPAD4':    '0x64',
        'VK_NUMPAD5':    '0x65',
        'VK_NUMPAD6':    '0x66',
        'VK_NUMPAD7':    '0x67',
        'VK_NUMPAD8':    '0x68',
        'VK_NUMPAD9':    '0x69',
    }

    @classmethod
    def generate_structure(cls, name: str, indent: int = 0) -> List[str]:
        ind = '    ' * indent
        fields = cls.STRUCT_TEMPLATES.get(name)
        if fields is None:
            return []
        lines = [f'{ind}class {name}(ctypes.Structure):']
        lines.append(f'{ind}    _fields_ = [')
        for fname, ftype in fields:
            qualified = get_ctypes_qualified(ftype) or f'ctypes.{ftype}'
            lines.append(f"{ind}        ('{fname}', {qualified}),")
        lines.append(f'{ind}    ]')
        return lines

    @classmethod
    def generate_union(cls, name: str, indent: int = 0) -> List[str]:
        ind = '    ' * indent
        fields = cls.UNION_TEMPLATES.get(name)
        if fields is None:
            return []
        lines = [f'{ind}class {name}(ctypes.Union):']
        lines.append(f'{ind}    _fields_ = [')
        for fname, ftype in fields:
            qualified = get_ctypes_qualified(ftype) or f'ctypes.{ftype}'
            lines.append(f"{ind}        ('{fname}', {qualified}),")
        lines.append(f'{ind}    ]')
        return lines

    @classmethod
    def generate_all_missing(cls, code_str: str) -> str:
        additions = []
        for struct_name, fields in cls.STRUCT_TEMPLATES.items():
            if struct_name in code_str and f'class {struct_name}' not in code_str:
                additions.extend(cls.generate_structure(struct_name))
                additions.append('')
        for union_name, fields in cls.UNION_TEMPLATES.items():
            if union_name in code_str and f'class {union_name}' not in code_str:
                additions.extend(cls.generate_union(union_name))
                additions.append('')
        for const_name, const_val in cls.STANDALONE_DEFINITIONS.items():
            if const_name in code_str and f'{const_name} =' not in code_str:
                additions.append(f'{const_name} = {const_val}')
        if not additions:
            return code_str
        insert_pos = 0
        lines = code_str.splitlines()
        for idx, line in enumerate(lines):
            stripped = line.strip()
            if stripped and not re.match(r'^(import |from |\s*#)', stripped):
                insert_pos = idx
                break
        new_lines = lines[:insert_pos] + additions + lines[insert_pos:]
        return '\n'.join(new_lines)

    @classmethod
    def list_available_structures(cls) -> List[str]:
        return sorted(list(cls.STRUCT_TEMPLATES.keys()) + list(cls.UNION_TEMPLATES.keys()))

    @classmethod
    def is_known_structure(cls, name: str) -> bool:
        return name in cls.STRUCT_TEMPLATES or name in cls.UNION_TEMPLATES

    @classmethod
    def get_field_types_for_structure(cls, name: str) -> List[str]:
        fields = cls.STRUCT_TEMPLATES.get(name) or cls.UNION_TEMPLATES.get(name) or []
        return [ftype for _, ftype in fields]


