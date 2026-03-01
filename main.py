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

CTYPES_TYPE_MAP = {
    'c_bool': 'ctypes.c_bool',
    'c_byte': 'ctypes.c_byte',
    'c_ubyte': 'ctypes.c_ubyte',
    'c_char': 'ctypes.c_char',
    'c_wchar': 'ctypes.c_wchar',
    'c_short': 'ctypes.c_short',
    'c_ushort': 'ctypes.c_ushort',
    'c_int': 'ctypes.c_int',
    'c_uint': 'ctypes.c_uint',
    'c_long': 'ctypes.c_long',
    'c_ulong': 'ctypes.c_ulong',
    'c_longlong': 'ctypes.c_longlong',
    'c_ulonglong': 'ctypes.c_ulonglong',
    'c_float': 'ctypes.c_float',
    'c_double': 'ctypes.c_double',
    'c_longdouble': 'ctypes.c_longdouble',
    'c_char_p': 'ctypes.c_char_p',
    'c_wchar_p': 'ctypes.c_wchar_p',
    'c_void_p': 'ctypes.c_void_p',
    'c_voidp': 'ctypes.c_voidp',
    'c_int8': 'ctypes.c_int8',
    'c_int16': 'ctypes.c_int16',
    'c_int32': 'ctypes.c_int32',
    'c_int64': 'ctypes.c_int64',
    'c_uint8': 'ctypes.c_uint8',
    'c_uint16': 'ctypes.c_uint16',
    'c_uint32': 'ctypes.c_uint32',
    'c_uint64': 'ctypes.c_uint64',
    'c_size_t': 'ctypes.c_size_t',
    'c_ssize_t': 'ctypes.c_ssize_t',
    'c_time_t': 'ctypes.c_time_t',
    'c_buffer': 'ctypes.c_buffer',
    'py_object': 'ctypes.py_object',
    'Structure': 'ctypes.Structure',
    'Union': 'ctypes.Union',
    'BigEndianStructure': 'ctypes.BigEndianStructure',
    'LittleEndianStructure': 'ctypes.LittleEndianStructure',
    'BigEndianUnion': 'ctypes.BigEndianUnion',
    'LittleEndianUnion': 'ctypes.LittleEndianUnion',
    'POINTER': 'ctypes.POINTER',
    'Array': 'ctypes.Array',
    'ARRAY': 'ctypes.ARRAY',
    'CFUNCTYPE': 'ctypes.CFUNCTYPE',
    'WINFUNCTYPE': 'ctypes.WINFUNCTYPE',
    'PYFUNCTYPE': 'ctypes.PYFUNCTYPE',
    'CDLL': 'ctypes.CDLL',
    'PyDLL': 'ctypes.PyDLL',
    'LibraryLoader': 'ctypes.LibraryLoader',
    'HRESULT': 'ctypes.HRESULT',
    'ArgumentError': 'ctypes.ArgumentError',
    'DEFAULT_MODE': 'ctypes.DEFAULT_MODE',
    'RTLD_GLOBAL': 'ctypes.RTLD_GLOBAL',
    'RTLD_LOCAL': 'ctypes.RTLD_LOCAL',
    'SIZEOF_TIME_T': 'ctypes.SIZEOF_TIME_T',
    'SetPointerType': 'ctypes.SetPointerType',
    'addressof': 'ctypes.addressof',
    'alignment': 'ctypes.alignment',
    'byref': 'ctypes.byref',
    'cast': 'ctypes.cast',
    'cdll': 'ctypes.cdll',
    'create_string_buffer': 'ctypes.create_string_buffer',
    'create_unicode_buffer': 'ctypes.create_unicode_buffer',
    'get_errno': 'ctypes.get_errno',
    'memmove': 'ctypes.memmove',
    'memset': 'ctypes.memset',
    'pointer': 'ctypes.pointer',
    'pydll': 'ctypes.pydll',
    'pythonapi': 'ctypes.pythonapi',
    'resize': 'ctypes.resize',
    'set_errno': 'ctypes.set_errno',
    'sizeof': 'ctypes.sizeof',
    'string_at': 'ctypes.string_at',
    'wstring_at': 'ctypes.wstring_at',
    'windll': 'ctypes.windll',
    'oledll': 'ctypes.oledll',
    'WinDLL': 'ctypes.WinDLL',
    'OleDLL': 'ctypes.OleDLL',
    'HANDLE': 'ctypes.wintypes.HANDLE',
    'HWND': 'ctypes.wintypes.HWND',
    'DWORD': 'ctypes.wintypes.DWORD',
    'WORD': 'ctypes.wintypes.WORD',
    'BOOL': 'ctypes.wintypes.BOOL',
    'BYTE': 'ctypes.wintypes.BYTE',
    'LONG': 'ctypes.wintypes.LONG',
    'ULONG': 'ctypes.wintypes.ULONG',
    'WCHAR': 'ctypes.wintypes.WCHAR',
    'LPVOID': 'ctypes.c_void_p',
    'LPCVOID': 'ctypes.c_void_p',
    'LPSTR': 'ctypes.c_char_p',
    'LPCSTR': 'ctypes.c_char_p',
    'LPWSTR': 'ctypes.c_wchar_p',
    'LPCWSTR': 'ctypes.c_wchar_p',
    'LPBYTE': 'ctypes.POINTER(ctypes.c_byte)',
    'LPWORD': 'ctypes.POINTER(ctypes.wintypes.WORD)',
    'LPDWORD': 'ctypes.POINTER(ctypes.wintypes.DWORD)',
    'LPLONG': 'ctypes.POINTER(ctypes.wintypes.LONG)',
    'LPBOOL': 'ctypes.POINTER(ctypes.wintypes.BOOL)',
    'LPHANDLE': 'ctypes.POINTER(ctypes.wintypes.HANDLE)',
    'UINT': 'ctypes.c_uint',
    'INT': 'ctypes.c_int',
    'USHORT': 'ctypes.c_ushort',
    'SHORT': 'ctypes.c_short',
    'ULONGLONG': 'ctypes.c_ulonglong',
    'LONGLONG': 'ctypes.c_longlong',
    'SIZE_T': 'ctypes.c_size_t',
    'SSIZE_T': 'ctypes.c_ssize_t',
    'ULONG_PTR': 'ctypes.POINTER(ctypes.c_ulong)',
    'LONG_PTR': 'ctypes.POINTER(ctypes.c_long)',
    'UINT_PTR': 'ctypes.POINTER(ctypes.c_uint)',
    'DWORD_PTR': 'ctypes.POINTER(ctypes.wintypes.DWORD)',
    'WPARAM': 'ctypes.c_size_t',
    'LPARAM': 'ctypes.c_ssize_t',
    'LRESULT': 'ctypes.c_ssize_t',
    'ATOM': 'ctypes.c_uint16',
    'COLORREF': 'ctypes.wintypes.COLORREF',
    'HMODULE': 'ctypes.wintypes.HMODULE',
    'HINSTANCE': 'ctypes.wintypes.HINSTANCE',
    'HDC': 'ctypes.wintypes.HDC',
    'HGDIOBJ': 'ctypes.wintypes.HGDIOBJ',
    'HBITMAP': 'ctypes.wintypes.HBITMAP',
    'HBRUSH': 'ctypes.wintypes.HBRUSH',
    'HPEN': 'ctypes.wintypes.HPEN',
    'HFONT': 'ctypes.wintypes.HFONT',
    'HMENU': 'ctypes.wintypes.HMENU',
    'HICON': 'ctypes.wintypes.HICON',
    'HCURSOR': 'ctypes.wintypes.HCURSOR',
    'HKEY': 'ctypes.wintypes.HKEY',
    'HACCEL': 'ctypes.wintypes.HACCEL',
    'HFILE': 'ctypes.wintypes.HFILE',
    'HGLOBAL': 'ctypes.wintypes.HGLOBAL',
    'HLOCAL': 'ctypes.wintypes.HLOCAL',
    'HPALETTE': 'ctypes.wintypes.HPALETTE',
    'HRGN': 'ctypes.wintypes.HRGN',
    'HRSRC': 'ctypes.wintypes.HRSRC',
    'HWINSTA': 'ctypes.wintypes.HWINSTA',
    'HDESK': 'ctypes.wintypes.HDESK',
    'HTASK': 'ctypes.wintypes.HTASK',
    'HMETAFILE': 'ctypes.wintypes.HMETAFILE',
    'HENHMETAFILE': 'ctypes.wintypes.HENHMETAFILE',
    'LPPOINT': 'ctypes.POINTER(ctypes.wintypes.POINT)',
    'LPRECT': 'ctypes.POINTER(ctypes.wintypes.RECT)',
    'LPSIZE': 'ctypes.POINTER(ctypes.wintypes.SIZE)',
    'LPMSG': 'ctypes.POINTER(ctypes.wintypes.MSG)',
    'POINT': 'ctypes.wintypes.POINT',
    'RECT': 'ctypes.wintypes.RECT',
    'SIZE': 'ctypes.wintypes.SIZE',
    'MSG': 'ctypes.wintypes.MSG',
    'FILETIME': 'ctypes.wintypes.FILETIME',
    'SYSTEMTIME': 'ctypes.wintypes.SYSTEMTIME',
    'SECURITY_ATTRIBUTES': 'ctypes.wintypes.SECURITY_ATTRIBUTES',
    'OVERLAPPED': 'ctypes.wintypes.OVERLAPPED',
    'PROCESS_INFORMATION': 'ctypes.wintypes.PROCESS_INFORMATION',
    'STARTUPINFO': 'ctypes.wintypes.STARTUPINFO',
    'STARTUPINFOEX': 'ctypes.wintypes.STARTUPINFOEX',
    'LOGFONT': 'ctypes.wintypes.LOGFONT',
    'LOGFONTA': 'ctypes.wintypes.LOGFONTA',
    'LOGFONTW': 'ctypes.wintypes.LOGFONTW',
    'TEXTMETRIC': 'ctypes.wintypes.TEXTMETRIC',
    'MEMORYSTATUS': 'ctypes.wintypes.MEMORYSTATUS',
    'MEMORYSTATUSEX': 'ctypes.wintypes.MEMORYSTATUSEX',
    'BY_HANDLE_FILE_INFORMATION': 'ctypes.wintypes.BY_HANDLE_FILE_INFORMATION',
    'WIN32_FIND_DATA': 'ctypes.wintypes.WIN32_FIND_DATA',
    'CREATESTRUCT': 'ctypes.wintypes.CREATESTRUCT',
    'PAINTSTRUCT': 'ctypes.wintypes.PAINTSTRUCT',
    'WINDOWPOS': 'ctypes.wintypes.WINDOWPOS',
    'SCROLLINFO': 'ctypes.wintypes.SCROLLINFO',
    'MOUSEINPUT': 'ctypes.wintypes.MOUSEINPUT',
    'KEYBDINPUT': 'ctypes.wintypes.KEYBDINPUT',
    'HARDWAREINPUT': 'ctypes.wintypes.HARDWAREINPUT',
    'INPUT': 'ctypes.wintypes.INPUT',
    'MINMAXINFO': 'ctypes.wintypes.MINMAXINFO',
    'NCCALCSIZE_PARAMS': 'ctypes.wintypes.NCCALCSIZE_PARAMS',
    'TRACKMOUSEEVENT': 'ctypes.wintypes.TRACKMOUSEEVENT',
    'FLASHWINFO': 'ctypes.wintypes.FLASHWINFO',
    'WNDCLASSEX': 'ctypes.wintypes.WNDCLASSEX',
    'WNDCLASS': 'ctypes.wintypes.WNDCLASS',
    'OSVERSIONINFO': 'ctypes.wintypes.OSVERSIONINFO',
    'SYSTEM_INFO': 'ctypes.wintypes.SYSTEM_INFO',
    'CRITICAL_SECTION': 'ctypes.wintypes.CRITICAL_SECTION',
    'GUID': 'ctypes.wintypes.GUID',
    'IID': 'ctypes.wintypes.IID',
    'CLSID': 'ctypes.wintypes.CLSID',
    'VARIANT_BOOL': 'ctypes.c_short',
    'BSTR': 'ctypes.c_wchar_p',
    'VARIANT': 'ctypes.c_void_p',
    'SAFEARRAY': 'ctypes.c_void_p',
    'DISPID': 'ctypes.c_long',
    'MEMBERID': 'ctypes.c_long',
    'SCODE': 'ctypes.c_long',
    'LCID': 'ctypes.c_ulong',
    'LANGID': 'ctypes.c_ushort',
    'MAKELANGID': 'ctypes.c_ushort',
    'SUBLANGID': 'ctypes.c_ushort',
    'PRIMARYLANGID': 'ctypes.c_ushort',
    'ACCESS_MASK': 'ctypes.c_ulong',
    'REGSAM': 'ctypes.c_ulong',
    'LPSECURITY_ATTRIBUTES': 'ctypes.POINTER(ctypes.wintypes.SECURITY_ATTRIBUTES)',
    'PSECURITY_ATTRIBUTES': 'ctypes.POINTER(ctypes.wintypes.SECURITY_ATTRIBUTES)',
    'PSID': 'ctypes.c_void_p',
    'PACL': 'ctypes.c_void_p',
    'PSECURITY_DESCRIPTOR': 'ctypes.c_void_p',
    'PTOKEN_PRIVILEGES': 'ctypes.c_void_p',
    'POBJECT_ATTRIBUTES': 'ctypes.c_void_p',
    'IO_STATUS_BLOCK': 'ctypes.c_void_p',
    'UNICODE_STRING': 'ctypes.c_void_p',
    'NTSTATUS': 'ctypes.c_long',
    'PVOID': 'ctypes.c_void_p',
    'UCHAR': 'ctypes.c_ubyte',
    'PUCHAR': 'ctypes.POINTER(ctypes.c_ubyte)',
    'PULONG': 'ctypes.POINTER(ctypes.wintypes.ULONG)',
    'PULONG_PTR': 'ctypes.POINTER(ctypes.c_ulong)',
    'PULONGLONG': 'ctypes.POINTER(ctypes.c_ulonglong)',
    'PLARGE_INTEGER': 'ctypes.POINTER(ctypes.c_int64)',
    'LARGE_INTEGER': 'ctypes.c_int64',
    'ULARGE_INTEGER': 'ctypes.c_uint64',
    'PULARGE_INTEGER': 'ctypes.POINTER(ctypes.c_uint64)',
    'BOOLEAN': 'ctypes.c_ubyte',
    'PBOOLEAN': 'ctypes.POINTER(ctypes.c_ubyte)',
    'PBOOL': 'ctypes.POINTER(ctypes.wintypes.BOOL)',
    'PINT': 'ctypes.POINTER(ctypes.c_int)',
    'PUINT': 'ctypes.POINTER(ctypes.c_uint)',
    'PSHORT': 'ctypes.POINTER(ctypes.c_short)',
    'PUSHORT': 'ctypes.POINTER(ctypes.c_ushort)',
    'PBYTE': 'ctypes.POINTER(ctypes.wintypes.BYTE)',
    'PWORD': 'ctypes.POINTER(ctypes.wintypes.WORD)',
    'PDWORD': 'ctypes.POINTER(ctypes.wintypes.DWORD)',
    'PLONG': 'ctypes.POINTER(ctypes.wintypes.LONG)',
    'PHANDLE': 'ctypes.POINTER(ctypes.wintypes.HANDLE)',
    'PHKEY': 'ctypes.POINTER(ctypes.wintypes.HKEY)',
    'PCHAR': 'ctypes.c_char_p',
    'PWCHAR': 'ctypes.c_wchar_p',
    'PSTR': 'ctypes.c_char_p',
    'PWSTR': 'ctypes.c_wchar_p',
    'PCSTR': 'ctypes.c_char_p',
    'PCWSTR': 'ctypes.c_wchar_p',
    'LPCTSTR': 'ctypes.c_wchar_p',
    'LPTSTR': 'ctypes.c_wchar_p',
    'TCHAR': 'ctypes.c_wchar',
    'SC_HANDLE': 'ctypes.wintypes.HANDLE',
    'SERVICE_STATUS_HANDLE': 'ctypes.wintypes.HANDLE',
    'HWINEVENTHOOK': 'ctypes.wintypes.HANDLE',
    'HDEVNOTIFY': 'ctypes.wintypes.HANDLE',
    'HPOWERNOTIFY': 'ctypes.wintypes.HANDLE',
    'HRAWINPUT': 'ctypes.wintypes.HANDLE',
    'HTOUCHINPUT': 'ctypes.wintypes.HANDLE',
    'HGESTUREINFO': 'ctypes.wintypes.HANDLE',
    'HMONITOR': 'ctypes.wintypes.HANDLE',
    'HINTERNET': 'ctypes.c_void_p',
    'HCERTSTORE': 'ctypes.c_void_p',
    'PCCERT_CONTEXT': 'ctypes.c_void_p',
    'HCRYPTPROV': 'ctypes.c_void_p',
    'HCRYPTKEY': 'ctypes.c_void_p',
    'HCRYPTHASH': 'ctypes.c_void_p',
    'HCRYPTMSG': 'ctypes.c_void_p',
    'HCRYPTOIDFUNCADDR': 'ctypes.c_void_p',
    'SOCKET': 'ctypes.c_uint',
    'SOCKADDR': 'ctypes.c_void_p',
    'WSADATA': 'ctypes.c_void_p',
    'ADDRINFO': 'ctypes.c_void_p',
    'ADDRINFOEX': 'ctypes.c_void_p',
    'PADDRINFO': 'ctypes.c_void_p',
    'in_addr': 'ctypes.c_uint32',
    'in6_addr': 'ctypes.c_byte * 16',
    'SOCKADDR_IN': 'ctypes.c_void_p',
    'SOCKADDR_IN6': 'ctypes.c_void_p',
    'DEVICEDRIVERINFODATA': 'ctypes.c_void_p',
    'PIXELFORMATDESCRIPTOR': 'ctypes.c_void_p',
    'HGLRC': 'ctypes.wintypes.HANDLE',
    'HPBUFFERARB': 'ctypes.c_void_p',
    'GLuint': 'ctypes.c_uint',
    'GLint': 'ctypes.c_int',
    'GLfloat': 'ctypes.c_float',
    'GLdouble': 'ctypes.c_double',
    'GLenum': 'ctypes.c_uint',
    'GLsizei': 'ctypes.c_int',
    'GLboolean': 'ctypes.c_ubyte',
    'GLbitfield': 'ctypes.c_uint',
    'GLbyte': 'ctypes.c_byte',
    'GLshort': 'ctypes.c_short',
    'GLubyte': 'ctypes.c_ubyte',
    'GLushort': 'ctypes.c_ushort',
    'GLulong': 'ctypes.c_ulong',
    'GLvoid': 'ctypes.c_void_p',
    'GLchar': 'ctypes.c_char',
    'GLsizeiptr': 'ctypes.c_ssize_t',
    'GLintptr': 'ctypes.c_ssize_t',
    'GLint64': 'ctypes.c_int64',
    'GLuint64': 'ctypes.c_uint64',
    'GLsync': 'ctypes.c_void_p',
    'VkResult': 'ctypes.c_int',
    'VkBool32': 'ctypes.c_uint',
    'VkFlags': 'ctypes.c_uint',
    'VkDeviceSize': 'ctypes.c_uint64',
    'VkSampleMask': 'ctypes.c_uint',
    'VkInstance': 'ctypes.c_void_p',
    'VkPhysicalDevice': 'ctypes.c_void_p',
    'VkDevice': 'ctypes.c_void_p',
    'VkQueue': 'ctypes.c_void_p',
    'VkCommandBuffer': 'ctypes.c_void_p',
    'time_t': 'ctypes.c_time_t',
    'clock_t': 'ctypes.c_ulong',
    'dev_t': 'ctypes.c_uint',
    'ino_t': 'ctypes.c_ulong',
    'mode_t': 'ctypes.c_uint',
    'off_t': 'ctypes.c_long',
    'pid_t': 'ctypes.c_int',
    'uid_t': 'ctypes.c_uint',
    'gid_t': 'ctypes.c_uint',
    'nlink_t': 'ctypes.c_ulong',
    'blksize_t': 'ctypes.c_long',
    'blkcnt_t': 'ctypes.c_long',
    'int8_t': 'ctypes.c_int8',
    'int16_t': 'ctypes.c_int16',
    'int32_t': 'ctypes.c_int32',
    'int64_t': 'ctypes.c_int64',
    'uint8_t': 'ctypes.c_uint8',
    'uint16_t': 'ctypes.c_uint16',
    'uint32_t': 'ctypes.c_uint32',
    'uint64_t': 'ctypes.c_uint64',
    'intptr_t': 'ctypes.c_ssize_t',
    'uintptr_t': 'ctypes.c_size_t',
    'ptrdiff_t': 'ctypes.c_ssize_t',
    'intmax_t': 'ctypes.c_int64',
    'uintmax_t': 'ctypes.c_uint64',
    'wchar_t': 'ctypes.c_wchar',
    'char16_t': 'ctypes.c_uint16',
    'char32_t': 'ctypes.c_uint32',
}

CTYPES_LIBRARY: Dict[str, Dict] = {
    'primitifs_entiers': {
        'c_bool':      {'ctypes': 'ctypes.c_bool',      'bits': 8,  'signe': True,  'desc': 'Booleen C (_Bool)'},
        'c_byte':      {'ctypes': 'ctypes.c_byte',      'bits': 8,  'signe': True,  'desc': 'Octet signe (signed char)'},
        'c_ubyte':     {'ctypes': 'ctypes.c_ubyte',     'bits': 8,  'signe': False, 'desc': 'Octet non signe (unsigned char)'},
        'c_short':     {'ctypes': 'ctypes.c_short',     'bits': 16, 'signe': True,  'desc': 'Entier court signe (short)'},
        'c_ushort':    {'ctypes': 'ctypes.c_ushort',    'bits': 16, 'signe': False, 'desc': 'Entier court non signe (unsigned short)'},
        'c_int':       {'ctypes': 'ctypes.c_int',       'bits': 32, 'signe': True,  'desc': 'Entier signe (int)'},
        'c_uint':      {'ctypes': 'ctypes.c_uint',      'bits': 32, 'signe': False, 'desc': 'Entier non signe (unsigned int)'},
        'c_long':      {'ctypes': 'ctypes.c_long',      'bits': 32, 'signe': True,  'desc': 'Entier long signe (long)'},
        'c_ulong':     {'ctypes': 'ctypes.c_ulong',     'bits': 32, 'signe': False, 'desc': 'Entier long non signe (unsigned long)'},
        'c_longlong':  {'ctypes': 'ctypes.c_longlong',  'bits': 64, 'signe': True,  'desc': 'Entier 64 bits signe (long long)'},
        'c_ulonglong': {'ctypes': 'ctypes.c_ulonglong', 'bits': 64, 'signe': False, 'desc': 'Entier 64 bits non signe (unsigned long long)'},
        'c_int8':      {'ctypes': 'ctypes.c_int8',      'bits': 8,  'signe': True,  'desc': 'Entier 8 bits signe exact'},
        'c_int16':     {'ctypes': 'ctypes.c_int16',     'bits': 16, 'signe': True,  'desc': 'Entier 16 bits signe exact'},
        'c_int32':     {'ctypes': 'ctypes.c_int32',     'bits': 32, 'signe': True,  'desc': 'Entier 32 bits signe exact'},
        'c_int64':     {'ctypes': 'ctypes.c_int64',     'bits': 64, 'signe': True,  'desc': 'Entier 64 bits signe exact'},
        'c_uint8':     {'ctypes': 'ctypes.c_uint8',     'bits': 8,  'signe': False, 'desc': 'Entier 8 bits non signe exact'},
        'c_uint16':    {'ctypes': 'ctypes.c_uint16',    'bits': 16, 'signe': False, 'desc': 'Entier 16 bits non signe exact'},
        'c_uint32':    {'ctypes': 'ctypes.c_uint32',    'bits': 32, 'signe': False, 'desc': 'Entier 32 bits non signe exact'},
        'c_uint64':    {'ctypes': 'ctypes.c_uint64',    'bits': 64, 'signe': False, 'desc': 'Entier 64 bits non signe exact'},
        'c_size_t':    {'ctypes': 'ctypes.c_size_t',    'bits': 64, 'signe': False, 'desc': 'Taille memoire (size_t)'},
        'c_ssize_t':   {'ctypes': 'ctypes.c_ssize_t',   'bits': 64, 'signe': True,  'desc': 'Taille memoire signee (ssize_t)'},
        'c_time_t':    {'ctypes': 'ctypes.c_time_t',    'bits': 64, 'signe': True,  'desc': 'Temps Unix (time_t)'},
    },
    'primitifs_flottants': {
        'c_float':      {'ctypes': 'ctypes.c_float',      'bits': 32, 'desc': 'Virgule flottante simple precision (float)'},
        'c_double':     {'ctypes': 'ctypes.c_double',     'bits': 64, 'desc': 'Virgule flottante double precision (double)'},
        'c_longdouble': {'ctypes': 'ctypes.c_longdouble', 'bits': 80, 'desc': 'Virgule flottante longue (long double)'},
    },
    'primitifs_chaines': {
        'c_char':    {'ctypes': 'ctypes.c_char',   'desc': 'Caractere C unique (char)'},
        'c_wchar':   {'ctypes': 'ctypes.c_wchar',  'desc': 'Caractere large C (wchar_t)'},
        'c_char_p':  {'ctypes': 'ctypes.c_char_p', 'desc': 'Pointeur vers chaine d octets (char*)'},
        'c_wchar_p': {'ctypes': 'ctypes.c_wchar_p','desc': 'Pointeur vers chaine unicode (wchar_t*)'},
        'c_void_p':  {'ctypes': 'ctypes.c_void_p', 'desc': 'Pointeur generique (void*)'},
        'c_voidp':   {'ctypes': 'ctypes.c_voidp',  'desc': 'Alias de c_void_p'},
    },
    'types_python': {
        'py_object': {'ctypes': 'ctypes.py_object', 'desc': 'Objet Python arbitraire'},
        'c_buffer':  {'ctypes': 'ctypes.c_buffer',  'desc': 'Tampon d octets mutable'},
    },
    'structures_base': {
        'Structure':            {'ctypes': 'ctypes.Structure',            'desc': 'Classe de base structure C (sequentielle)'},
        'Union':                {'ctypes': 'ctypes.Union',                'desc': 'Classe de base union C'},
        'BigEndianStructure':   {'ctypes': 'ctypes.BigEndianStructure',   'desc': 'Structure big-endian'},
        'LittleEndianStructure':{'ctypes': 'ctypes.LittleEndianStructure','desc': 'Structure little-endian'},
        'BigEndianUnion':       {'ctypes': 'ctypes.BigEndianUnion',       'desc': 'Union big-endian'},
        'LittleEndianUnion':    {'ctypes': 'ctypes.LittleEndianUnion',    'desc': 'Union little-endian'},
        'Array':                {'ctypes': 'ctypes.Array',                'desc': 'Type de tableau C'},
        'ARRAY':                {'ctypes': 'ctypes.ARRAY',                'desc': 'Constructeur de tableau C (deprecated)'},
    },
    'pointeurs_et_fonctions': {
        'POINTER':    {'ctypes': 'ctypes.POINTER',    'desc': 'Cree un type pointeur vers un type C'},
        'pointer':    {'ctypes': 'ctypes.pointer',    'desc': 'Cree une instance de pointeur'},
        'byref':      {'ctypes': 'ctypes.byref',      'desc': 'Reference a un objet ctypes (passage par ref)'},
        'addressof':  {'ctypes': 'ctypes.addressof',  'desc': 'Retourne l adresse memoire d un objet ctypes'},
        'cast':       {'ctypes': 'ctypes.cast',       'desc': 'Convertit un pointeur vers un autre type'},
        'CFUNCTYPE':  {'ctypes': 'ctypes.CFUNCTYPE',  'desc': 'Prototype de fonction C (cdecl)'},
        'WINFUNCTYPE':{'ctypes': 'ctypes.WINFUNCTYPE','desc': 'Prototype de fonction Windows (stdcall)'},
        'PYFUNCTYPE': {'ctypes': 'ctypes.PYFUNCTYPE', 'desc': 'Prototype de fonction Python'},
        'SetPointerType': {'ctypes': 'ctypes.SetPointerType', 'desc': 'Definit le type cible d un pointeur'},
    },
    'utilitaires': {
        'sizeof':                {'ctypes': 'ctypes.sizeof',                'desc': 'Taille en octets d un type ou d un objet ctypes'},
        'alignment':             {'ctypes': 'ctypes.alignment',             'desc': 'Alignement requis d un type ctypes'},
        'memmove':               {'ctypes': 'ctypes.memmove',               'desc': 'Deplace un bloc memoire (comme C memmove)'},
        'memset':                {'ctypes': 'ctypes.memset',                'desc': 'Remplit un bloc memoire (comme C memset)'},
        'string_at':             {'ctypes': 'ctypes.string_at',             'desc': 'Lit une chaine d octets a une adresse memoire'},
        'wstring_at':            {'ctypes': 'ctypes.wstring_at',            'desc': 'Lit une chaine unicode a une adresse memoire'},
        'create_string_buffer':  {'ctypes': 'ctypes.create_string_buffer',  'desc': 'Cree un tampon d octets mutable'},
        'create_unicode_buffer': {'ctypes': 'ctypes.create_unicode_buffer', 'desc': 'Cree un tampon unicode mutable'},
        'get_errno':             {'ctypes': 'ctypes.get_errno',             'desc': 'Lit la variable errno du thread courant'},
        'set_errno':             {'ctypes': 'ctypes.set_errno',             'desc': 'Definit la variable errno du thread courant'},
        'resize':                {'ctypes': 'ctypes.resize',                'desc': 'Redimensionne un objet ctypes interne'},
    },
    'chargement_dll': {
        'cdll':       {'ctypes': 'ctypes.cdll',       'desc': 'Chargeur de DLL via convention cdecl'},
        'windll':     {'ctypes': 'ctypes.windll',     'desc': 'Chargeur de DLL via convention stdcall (Windows)'},
        'oledll':     {'ctypes': 'ctypes.oledll',     'desc': 'Chargeur de DLL OLE (Windows)'},
        'pydll':      {'ctypes': 'ctypes.pydll',      'desc': 'Chargeur de DLL Python sans GIL'},
        'pythonapi':  {'ctypes': 'ctypes.pythonapi',  'desc': 'Acces direct a l API CPython'},
        'CDLL':       {'ctypes': 'ctypes.CDLL',       'desc': 'Classe de chargement DLL cdecl'},
        'WinDLL':     {'ctypes': 'ctypes.WinDLL',     'desc': 'Classe de chargement DLL stdcall'},
        'OleDLL':     {'ctypes': 'ctypes.OleDLL',     'desc': 'Classe de chargement DLL OLE'},
        'PyDLL':      {'ctypes': 'ctypes.PyDLL',      'desc': 'Classe de chargement DLL sans GIL'},
        'LibraryLoader': {'ctypes': 'ctypes.LibraryLoader', 'desc': 'Chargeur de bibliotheque generique'},
    },
    'constantes': {
        'DEFAULT_MODE': {'ctypes': 'ctypes.DEFAULT_MODE', 'desc': 'Mode de chargement par defaut (RTLD_LOCAL)'},
        'RTLD_GLOBAL':  {'ctypes': 'ctypes.RTLD_GLOBAL',  'desc': 'Symboles exportes globalement (POSIX)'},
        'RTLD_LOCAL':   {'ctypes': 'ctypes.RTLD_LOCAL',   'desc': 'Symboles locaux a la DLL (POSIX)'},
        'SIZEOF_TIME_T':{'ctypes': 'ctypes.SIZEOF_TIME_T','desc': 'Taille de time_t en octets'},
    },
    'exceptions': {
        'ArgumentError': {'ctypes': 'ctypes.ArgumentError', 'desc': 'Erreur de conversion d argument ctypes'},
        'HRESULT':       {'ctypes': 'ctypes.HRESULT',       'desc': 'Type HRESULT Windows (code retour COM)'},
    },
    'wintypes_poignees': {
        'HANDLE':   {'ctypes': 'ctypes.wintypes.HANDLE',   'win': True, 'desc': 'Poignee generique Windows'},
        'HWND':     {'ctypes': 'ctypes.wintypes.HWND',     'win': True, 'desc': 'Poignee fenetre Windows'},
        'HMODULE':  {'ctypes': 'ctypes.wintypes.HMODULE',  'win': True, 'desc': 'Poignee module charge'},
        'HINSTANCE':{'ctypes': 'ctypes.wintypes.HINSTANCE','win': True, 'desc': 'Poignee instance application'},
        'HDC':      {'ctypes': 'ctypes.wintypes.HDC',      'win': True, 'desc': 'Contexte de peripherique GDI'},
        'HGDIOBJ':  {'ctypes': 'ctypes.wintypes.HGDIOBJ',  'win': True, 'desc': 'Objet GDI generique'},
        'HBITMAP':  {'ctypes': 'ctypes.wintypes.HBITMAP',  'win': True, 'desc': 'Poignee bitmap GDI'},
        'HBRUSH':   {'ctypes': 'ctypes.wintypes.HBRUSH',   'win': True, 'desc': 'Pinceau GDI'},
        'HPEN':     {'ctypes': 'ctypes.wintypes.HPEN',     'win': True, 'desc': 'Plume GDI'},
        'HFONT':    {'ctypes': 'ctypes.wintypes.HFONT',    'win': True, 'desc': 'Police GDI'},
        'HMENU':    {'ctypes': 'ctypes.wintypes.HMENU',    'win': True, 'desc': 'Poignee menu'},
        'HICON':    {'ctypes': 'ctypes.wintypes.HICON',    'win': True, 'desc': 'Icone Windows'},
        'HCURSOR':  {'ctypes': 'ctypes.wintypes.HCURSOR',  'win': True, 'desc': 'Curseur souris'},
        'HKEY':     {'ctypes': 'ctypes.wintypes.HKEY',     'win': True, 'desc': 'Cle de registre Windows'},
        'HACCEL':   {'ctypes': 'ctypes.wintypes.HACCEL',   'win': True, 'desc': 'Table d accelerateurs clavier'},
        'HFILE':    {'ctypes': 'ctypes.wintypes.HFILE',    'win': True, 'desc': 'Poignee de fichier Windows'},
        'HGLOBAL':  {'ctypes': 'ctypes.wintypes.HGLOBAL',  'win': True, 'desc': 'Memoire globale Windows'},
        'HLOCAL':   {'ctypes': 'ctypes.wintypes.HLOCAL',   'win': True, 'desc': 'Memoire locale Windows'},
        'HPALETTE': {'ctypes': 'ctypes.wintypes.HPALETTE', 'win': True, 'desc': 'Palette de couleurs GDI'},
        'HRGN':     {'ctypes': 'ctypes.wintypes.HRGN',     'win': True, 'desc': 'Region GDI'},
    },
    'wintypes_entiers': {
        'BOOL':      {'ctypes': 'ctypes.wintypes.BOOL',     'bits': 32, 'desc': 'Booleen Windows (int 32 bits)'},
        'BYTE':      {'ctypes': 'ctypes.wintypes.BYTE',     'bits': 8,  'desc': 'Octet Windows (unsigned char)'},
        'WORD':      {'ctypes': 'ctypes.wintypes.WORD',     'bits': 16, 'desc': 'Mot Windows (unsigned short)'},
        'DWORD':     {'ctypes': 'ctypes.wintypes.DWORD',    'bits': 32, 'desc': 'Double mot Windows (unsigned long)'},
        'LONG':      {'ctypes': 'ctypes.wintypes.LONG',     'bits': 32, 'desc': 'Entier long signe Windows (long)'},
        'ULONG':     {'ctypes': 'ctypes.wintypes.ULONG',    'bits': 32, 'desc': 'Entier long non signe Windows (unsigned long)'},
        'WCHAR':     {'ctypes': 'ctypes.wintypes.WCHAR',    'bits': 16, 'desc': 'Caractere Unicode Windows (wchar_t)'},
        'COLORREF':  {'ctypes': 'ctypes.wintypes.COLORREF', 'bits': 32, 'desc': 'Couleur RGB Windows (DWORD)'},
        'UINT':      {'ctypes': 'ctypes.c_uint',             'bits': 32, 'desc': 'Alias UINT (unsigned int)'},
        'INT':       {'ctypes': 'ctypes.c_int',              'bits': 32, 'desc': 'Alias INT (int)'},
        'SHORT':     {'ctypes': 'ctypes.c_short',            'bits': 16, 'desc': 'Alias SHORT (short)'},
        'USHORT':    {'ctypes': 'ctypes.c_ushort',           'bits': 16, 'desc': 'Alias USHORT (unsigned short)'},
        'LONGLONG':  {'ctypes': 'ctypes.c_longlong',         'bits': 64, 'desc': 'Entier 64 bits signe (long long)'},
        'ULONGLONG': {'ctypes': 'ctypes.c_ulonglong',        'bits': 64, 'desc': 'Entier 64 bits non signe'},
        'SIZE_T':    {'ctypes': 'ctypes.c_size_t',           'bits': 64, 'desc': 'Taille memoire (size_t)'},
        'SSIZE_T':   {'ctypes': 'ctypes.c_ssize_t',          'bits': 64, 'desc': 'Taille memoire signee'},
        'WPARAM':    {'ctypes': 'ctypes.c_size_t',           'bits': 64, 'desc': 'Parametre de message W'},
        'LPARAM':    {'ctypes': 'ctypes.c_ssize_t',          'bits': 64, 'desc': 'Parametre de message L'},
        'LRESULT':   {'ctypes': 'ctypes.c_ssize_t',          'bits': 64, 'desc': 'Resultat de procedure fenetre'},
        'ATOM':      {'ctypes': 'ctypes.c_uint16',           'bits': 16, 'desc': 'Atome Windows (index dans table)'},
    },
    'wintypes_pointeurs': {
        'LPVOID':   {'ctypes': 'ctypes.c_void_p',   'desc': 'Pointeur generique (void*)'},
        'LPCVOID':  {'ctypes': 'ctypes.c_void_p',   'desc': 'Pointeur const generique'},
        'LPSTR':    {'ctypes': 'ctypes.c_char_p',   'desc': 'Pointeur chaine ANSI (char*)'},
        'LPCSTR':   {'ctypes': 'ctypes.c_char_p',   'desc': 'Pointeur chaine ANSI constante'},
        'LPWSTR':   {'ctypes': 'ctypes.c_wchar_p',  'desc': 'Pointeur chaine Unicode (wchar_t*)'},
        'LPCWSTR':  {'ctypes': 'ctypes.c_wchar_p',  'desc': 'Pointeur chaine Unicode constante'},
        'LPBOOL':   {'ctypes': 'ctypes.POINTER(ctypes.wintypes.BOOL)',  'desc': 'Pointeur vers BOOL'},
        'LPBYTE':   {'ctypes': 'ctypes.POINTER(ctypes.c_byte)',         'desc': 'Pointeur vers BYTE'},
        'LPWORD':   {'ctypes': 'ctypes.POINTER(ctypes.wintypes.WORD)',  'desc': 'Pointeur vers WORD'},
        'LPDWORD':  {'ctypes': 'ctypes.POINTER(ctypes.wintypes.DWORD)', 'desc': 'Pointeur vers DWORD'},
        'LPLONG':   {'ctypes': 'ctypes.POINTER(ctypes.wintypes.LONG)',  'desc': 'Pointeur vers LONG'},
        'LPHANDLE': {'ctypes': 'ctypes.POINTER(ctypes.wintypes.HANDLE)','desc': 'Pointeur vers HANDLE'},
        'LPPOINT':  {'ctypes': 'ctypes.POINTER(ctypes.wintypes.POINT)', 'desc': 'Pointeur vers POINT'},
        'LPRECT':   {'ctypes': 'ctypes.POINTER(ctypes.wintypes.RECT)',  'desc': 'Pointeur vers RECT'},
        'LPSIZE':   {'ctypes': 'ctypes.POINTER(ctypes.wintypes.SIZE)',  'desc': 'Pointeur vers SIZE'},
        'LPMSG':    {'ctypes': 'ctypes.POINTER(ctypes.wintypes.MSG)',   'desc': 'Pointeur vers MSG'},
        'ULONG_PTR':{'ctypes': 'ctypes.POINTER(ctypes.c_ulong)',        'desc': 'Pointeur sans signe (ULONG_PTR)'},
        'LONG_PTR': {'ctypes': 'ctypes.POINTER(ctypes.c_long)',         'desc': 'Pointeur signe (LONG_PTR)'},
        'DWORD_PTR':{'ctypes': 'ctypes.POINTER(ctypes.wintypes.DWORD)', 'desc': 'Pointeur DWORD (DWORD_PTR)'},
        'UINT_PTR': {'ctypes': 'ctypes.POINTER(ctypes.c_uint)',         'desc': 'Pointeur UINT (UINT_PTR)'},
    },
    'wintypes_structures': {
        'POINT':               {'ctypes': 'ctypes.wintypes.POINT',               'desc': 'Coordonnees 2D (x, y)'},
        'RECT':                {'ctypes': 'ctypes.wintypes.RECT',                'desc': 'Rectangle (left, top, right, bottom)'},
        'SIZE':                {'ctypes': 'ctypes.wintypes.SIZE',                'desc': 'Dimensions (cx, cy)'},
        'MSG':                 {'ctypes': 'ctypes.wintypes.MSG',                 'desc': 'Message Windows'},
        'FILETIME':            {'ctypes': 'ctypes.wintypes.FILETIME',            'desc': 'Temps fichier (100 ns depuis 1601)'},
        'SYSTEMTIME':          {'ctypes': 'ctypes.wintypes.SYSTEMTIME',          'desc': 'Date et heure systeme'},
        'SECURITY_ATTRIBUTES': {'ctypes': 'ctypes.wintypes.SECURITY_ATTRIBUTES', 'desc': 'Attributs de securite'},
        'OVERLAPPED':          {'ctypes': 'ctypes.wintypes.OVERLAPPED',          'desc': 'Structure d entree-sortie asynchrone'},
        'PROCESS_INFORMATION': {'ctypes': 'ctypes.wintypes.PROCESS_INFORMATION', 'desc': 'Info processus cree'},
        'STARTUPINFO':         {'ctypes': 'ctypes.wintypes.STARTUPINFO',         'desc': 'Parametres demarrage processus'},
        'LOGFONT':             {'ctypes': 'ctypes.wintypes.LOGFONT',             'desc': 'Description police logique'},
        'MEMORYSTATUS':        {'ctypes': 'ctypes.wintypes.MEMORYSTATUS',        'desc': 'Statut memoire globale'},
        'WIN32_FIND_DATA':     {'ctypes': 'ctypes.wintypes.WIN32_FIND_DATA',     'desc': 'Donnees de recherche de fichier'},
        'CREATESTRUCT':        {'ctypes': 'ctypes.wintypes.CREATESTRUCT',        'desc': 'Parametres creation fenetre'},
        'PAINTSTRUCT':         {'ctypes': 'ctypes.wintypes.PAINTSTRUCT',         'desc': 'Info peinture fenetre'},
        'WNDCLASSEX':          {'ctypes': 'ctypes.wintypes.WNDCLASSEX',          'desc': 'Classe fenetre etendue'},
        'MINMAXINFO':          {'ctypes': 'ctypes.wintypes.MINMAXINFO',          'desc': 'Info tailles min/max fenetre'},
        'OSVERSIONINFO':       {'ctypes': 'ctypes.wintypes.OSVERSIONINFO',       'desc': 'Info version systeme'},
        'SYSTEM_INFO':         {'ctypes': 'ctypes.wintypes.SYSTEM_INFO',         'desc': 'Info systeme (CPU etc.)'},
        'CRITICAL_SECTION':    {'ctypes': 'ctypes.wintypes.CRITICAL_SECTION',    'desc': 'Section critique synchronisation'},
        'GUID':                {'ctypes': 'ctypes.wintypes.GUID',                'desc': 'Identifiant global unique (128 bits)'},
    },
    'types_com': {
        'VARIANT_BOOL': {'ctypes': 'ctypes.c_short',    'desc': 'Booleen COM/OLE (VARIANT_BOOL, -1 ou 0)'},
        'BSTR':         {'ctypes': 'ctypes.c_wchar_p',  'desc': 'Chaine COM (Basic String)'},
        'VARIANT':      {'ctypes': 'ctypes.c_void_p',   'desc': 'Type variante COM'},
        'SAFEARRAY':    {'ctypes': 'ctypes.c_void_p',   'desc': 'Tableau securise COM'},
        'DISPID':       {'ctypes': 'ctypes.c_long',     'desc': 'Identifiant dispatch COM'},
        'MEMBERID':     {'ctypes': 'ctypes.c_long',     'desc': 'Identifiant membre type'},
        'SCODE':        {'ctypes': 'ctypes.c_long',     'desc': 'Code statut OLE'},
        'LCID':         {'ctypes': 'ctypes.c_ulong',    'desc': 'Identifiant de locale'},
        'LANGID':       {'ctypes': 'ctypes.c_ushort',   'desc': 'Identifiant de langue'},
    },
    'types_securite': {
        'ACCESS_MASK':           {'ctypes': 'ctypes.c_ulong',  'desc': 'Masque d acces Windows'},
        'REGSAM':                {'ctypes': 'ctypes.c_ulong',  'desc': 'Masque securite registre'},
        'PSID':                  {'ctypes': 'ctypes.c_void_p', 'desc': 'Identifiant de securite (SID)'},
        'PACL':                  {'ctypes': 'ctypes.c_void_p', 'desc': 'Liste de controle d acces (ACL)'},
        'PSECURITY_DESCRIPTOR':  {'ctypes': 'ctypes.c_void_p', 'desc': 'Descripteur de securite'},
        'PTOKEN_PRIVILEGES':     {'ctypes': 'ctypes.c_void_p', 'desc': 'Privileges de jeton'},
        'LPSECURITY_ATTRIBUTES': {'ctypes': 'ctypes.POINTER(ctypes.wintypes.SECURITY_ATTRIBUTES)', 'desc': 'Pointeur SECURITY_ATTRIBUTES'},
    },
    'types_reseau': {
        'SOCKET':      {'ctypes': 'ctypes.c_uint',   'desc': 'Descripteur socket Windows'},
        'SOCKADDR':    {'ctypes': 'ctypes.c_void_p', 'desc': 'Structure adresse socket generique'},
        'WSADATA':     {'ctypes': 'ctypes.c_void_p', 'desc': 'Donnees initialisation Winsock'},
        'ADDRINFO':    {'ctypes': 'ctypes.c_void_p', 'desc': 'Info adresse reseau'},
        'in_addr':     {'ctypes': 'ctypes.c_uint32', 'desc': 'Adresse IPv4 (4 octets)'},
        'in6_addr':    {'ctypes': 'ctypes.c_byte * 16', 'desc': 'Adresse IPv6 (16 octets)'},
        'SOCKADDR_IN': {'ctypes': 'ctypes.c_void_p', 'desc': 'Adresse IPv4 socket'},
        'SOCKADDR_IN6':{'ctypes': 'ctypes.c_void_p', 'desc': 'Adresse IPv6 socket'},
    },
    'types_opengl': {
        'GLuint':    {'ctypes': 'ctypes.c_uint',   'desc': 'Entier non signe OpenGL'},
        'GLint':     {'ctypes': 'ctypes.c_int',    'desc': 'Entier signe OpenGL'},
        'GLfloat':   {'ctypes': 'ctypes.c_float',  'desc': 'Flottant simple OpenGL'},
        'GLdouble':  {'ctypes': 'ctypes.c_double', 'desc': 'Flottant double OpenGL'},
        'GLenum':    {'ctypes': 'ctypes.c_uint',   'desc': 'Enumeration OpenGL'},
        'GLsizei':   {'ctypes': 'ctypes.c_int',    'desc': 'Taille OpenGL'},
        'GLboolean': {'ctypes': 'ctypes.c_ubyte',  'desc': 'Booleen OpenGL'},
        'GLbitfield':{'ctypes': 'ctypes.c_uint',   'desc': 'Champ de bits OpenGL'},
        'GLbyte':    {'ctypes': 'ctypes.c_byte',   'desc': 'Octet signe OpenGL'},
        'GLshort':   {'ctypes': 'ctypes.c_short',  'desc': 'Entier court OpenGL'},
        'GLubyte':   {'ctypes': 'ctypes.c_ubyte',  'desc': 'Octet non signe OpenGL'},
        'GLushort':  {'ctypes': 'ctypes.c_ushort', 'desc': 'Entier court non signe OpenGL'},
        'GLulong':   {'ctypes': 'ctypes.c_ulong',  'desc': 'Entier long non signe OpenGL'},
        'GLvoid':    {'ctypes': 'ctypes.c_void_p', 'desc': 'Void pointer OpenGL'},
        'GLchar':    {'ctypes': 'ctypes.c_char',   'desc': 'Caractere OpenGL'},
        'GLsizeiptr':{'ctypes': 'ctypes.c_ssize_t','desc': 'Taille pointeur OpenGL'},
        'GLintptr':  {'ctypes': 'ctypes.c_ssize_t','desc': 'Entier pointeur OpenGL'},
        'GLint64':   {'ctypes': 'ctypes.c_int64',  'desc': 'Entier 64 bits OpenGL'},
        'GLuint64':  {'ctypes': 'ctypes.c_uint64', 'desc': 'Entier 64 bits non signe OpenGL'},
        'GLsync':    {'ctypes': 'ctypes.c_void_p', 'desc': 'Objet synchronisation OpenGL'},
        'HGLRC':     {'ctypes': 'ctypes.wintypes.HANDLE', 'desc': 'Contexte de rendu OpenGL Windows'},
    },
    'types_posix': {
        'time_t':    {'ctypes': 'ctypes.c_time_t', 'desc': 'Temps Unix'},
        'clock_t':   {'ctypes': 'ctypes.c_ulong',  'desc': 'Tics horloge processeur'},
        'dev_t':     {'ctypes': 'ctypes.c_uint',   'desc': 'Numero de peripherique'},
        'ino_t':     {'ctypes': 'ctypes.c_ulong',  'desc': 'Numero d inode'},
        'mode_t':    {'ctypes': 'ctypes.c_uint',   'desc': 'Mode de fichier'},
        'off_t':     {'ctypes': 'ctypes.c_long',   'desc': 'Decalage dans fichier'},
        'pid_t':     {'ctypes': 'ctypes.c_int',    'desc': 'Identifiant processus'},
        'uid_t':     {'ctypes': 'ctypes.c_uint',   'desc': 'Identifiant utilisateur'},
        'gid_t':     {'ctypes': 'ctypes.c_uint',   'desc': 'Identifiant groupe'},
        'nlink_t':   {'ctypes': 'ctypes.c_ulong',  'desc': 'Nombre de liens physiques'},
        'blksize_t': {'ctypes': 'ctypes.c_long',   'desc': 'Taille de bloc E/S'},
        'blkcnt_t':  {'ctypes': 'ctypes.c_long',   'desc': 'Nombre de blocs alloues'},
    },
    'types_portable_exact': {
        'int8_t':   {'ctypes': 'ctypes.c_int8',    'bits': 8,  'signe': True,  'desc': 'Entier 8 bits signe exact (C99)'},
        'int16_t':  {'ctypes': 'ctypes.c_int16',   'bits': 16, 'signe': True,  'desc': 'Entier 16 bits signe exact (C99)'},
        'int32_t':  {'ctypes': 'ctypes.c_int32',   'bits': 32, 'signe': True,  'desc': 'Entier 32 bits signe exact (C99)'},
        'int64_t':  {'ctypes': 'ctypes.c_int64',   'bits': 64, 'signe': True,  'desc': 'Entier 64 bits signe exact (C99)'},
        'uint8_t':  {'ctypes': 'ctypes.c_uint8',   'bits': 8,  'signe': False, 'desc': 'Entier 8 bits non signe exact (C99)'},
        'uint16_t': {'ctypes': 'ctypes.c_uint16',  'bits': 16, 'signe': False, 'desc': 'Entier 16 bits non signe exact (C99)'},
        'uint32_t': {'ctypes': 'ctypes.c_uint32',  'bits': 32, 'signe': False, 'desc': 'Entier 32 bits non signe exact (C99)'},
        'uint64_t': {'ctypes': 'ctypes.c_uint64',  'bits': 64, 'signe': False, 'desc': 'Entier 64 bits non signe exact (C99)'},
        'intptr_t': {'ctypes': 'ctypes.c_ssize_t', 'desc': 'Entier capable de contenir un pointeur (signe)'},
        'uintptr_t':{'ctypes': 'ctypes.c_size_t',  'desc': 'Entier capable de contenir un pointeur (non signe)'},
        'ptrdiff_t':{'ctypes': 'ctypes.c_ssize_t', 'desc': 'Difference entre deux pointeurs'},
        'intmax_t': {'ctypes': 'ctypes.c_int64',   'bits': 64, 'signe': True,  'desc': 'Plus grand type entier signe'},
        'uintmax_t':{'ctypes': 'ctypes.c_uint64',  'bits': 64, 'signe': False, 'desc': 'Plus grand type entier non signe'},
    },
    'types_caracteres': {
        'wchar_t':   {'ctypes': 'ctypes.c_wchar',   'desc': 'Caractere large (wchar_t)'},
        'char16_t':  {'ctypes': 'ctypes.c_uint16',  'desc': 'Caractere UTF-16 (C++11)'},
        'char32_t':  {'ctypes': 'ctypes.c_uint32',  'desc': 'Caractere UTF-32 (C++11)'},
    },
    'ntstatus': {
        'NTSTATUS':  {'ctypes': 'ctypes.c_long',   'desc': 'Code de statut NT (NTSTATUS)'},
        'PVOID':     {'ctypes': 'ctypes.c_void_p', 'desc': 'Pointeur generique NT'},
        'UCHAR':     {'ctypes': 'ctypes.c_ubyte',  'desc': 'Octet non signe NT'},
    },
}

ALL_CTYPES_FLAT: Dict[str, str] = {}
for _cat, _entries in CTYPES_LIBRARY.items():
    for _name, _info in _entries.items():
        if _name not in ALL_CTYPES_FLAT:
            ALL_CTYPES_FLAT[_name] = _info['ctypes']
ALL_CTYPES_FLAT.update(CTYPES_TYPE_MAP)


def get_ctypes_qualified(name: str) -> Optional[str]:
    result = CTYPES_TYPE_MAP.get(name)
    if result:
        return result
    result = ALL_CTYPES_FLAT.get(name)
    if result:
        return result
    for cat_entries in CTYPES_LIBRARY.values():
        if name in cat_entries:
            return cat_entries[name]['ctypes']
    return None


def is_ctypes_type(name: str) -> bool:
    return (
        name in CTYPES_TYPE_MAP
        or name in ALL_CTYPES_FLAT
        or any(name in cat for cat in CTYPES_LIBRARY.values())
    )


def list_ctypes_by_bits(bits: int, signed: Optional[bool] = None) -> List[str]:
    result = []
    for cat_entries in CTYPES_LIBRARY.values():
        for name, info in cat_entries.items():
            if info.get('bits') == bits:
                if signed is None or info.get('signe') == signed:
                    result.append(name)
    return sorted(set(result))


def get_ctypes_category(name: str) -> Optional[str]:
    for cat_name, cat_entries in CTYPES_LIBRARY.items():
        if name in cat_entries:
            return cat_name
    return None


def get_ctypes_description(name: str) -> Optional[str]:
    for cat_entries in CTYPES_LIBRARY.values():
        if name in cat_entries:
            return cat_entries[name].get('desc')
    return None


def is_windows_only_ctypes(name: str) -> bool:
    for cat_entries in CTYPES_LIBRARY.values():
        if name in cat_entries:
            return cat_entries[name].get('win', False)
    return False


def resolve_ctypes_pointer_target(ptr_type_str: str) -> Optional[str]:
    m = re.match(r'ctypes\.POINTER\((.+)\)', ptr_type_str)
    if m:
        return m.group(1).strip()
    return None


def build_ctypes_fields_str(fields_spec: List[Tuple[str, str]]) -> str:
    parts = []
    for field_name, type_name in fields_spec:
        qualified = get_ctypes_qualified(type_name) or type_name
        parts.append(f"    ('{field_name}', {qualified}),")
    return '[\n' + '\n'.join(parts) + '\n]'


def normalize_ctypes_name(name: str) -> str:
    direct = get_ctypes_qualified(name)
    if direct:
        return direct
    lower = name.lower()
    for cname in CTYPES_TYPE_MAP:
        if cname.lower() == lower:
            return CTYPES_TYPE_MAP[cname]
    return name


KNOWN_MODULES: Dict[str, str] = {
    'QApplication': 'from PyQt5.QtWidgets import QApplication',
    'QMainWindow': 'from PyQt5.QtWidgets import QMainWindow',
    'QWidget': 'from PyQt5.QtWidgets import QWidget',
    'QDialog': 'from PyQt5.QtWidgets import QDialog',
    'QThread': 'from PyQt5.QtCore import QThread',
    'pyqtSignal': 'from PyQt5.QtCore import pyqtSignal',
    'QTimer': 'from PyQt5.QtCore import QTimer',
    'QMutex': 'from PyQt5.QtCore import QMutex',
    'Structure': 'import ctypes',
    'Union': 'import ctypes',
    'POINTER': 'import ctypes',
    'windll': 'import ctypes',
    'c_int': 'import ctypes',
    'c_long': 'import ctypes',
    'c_ulong': 'import ctypes',
    'CFUNCTYPE': 'import ctypes',
    'keyboard': 'import keyboard',
    'threading': 'import threading',
    'time': 'import time',
    'os': 'import os',
    'sys': 'import sys',
    'json': 'import json',
    're': 'import re',
    'base64': 'import base64',
    'io': 'import io',
    'functools': 'import functools',
    'collections': 'import collections',
    'datetime': 'from datetime import datetime',
    'Path': 'from pathlib import Path',
    'ABC': 'from abc import ABC',
    'abstractmethod': 'from abc import abstractmethod',
    'dataclass': 'from dataclasses import dataclass',
    'Enum': 'from enum import Enum',
    'Optional': 'from typing import Optional',
    'List': 'from typing import List',
    'Dict': 'from typing import Dict',
    'Tuple': 'from typing import Tuple',
}

BASE64_MIN_LEN = 100

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

        # ── Pré-analyse des boucles while ────────────────────────────────────
        # Identifie les labels qui sont des en-têtes de boucle (cibles de
        # JUMP_BACKWARD) et les indices des back-jumps correspondants.
        # Cela permet de reconstruire while/break/continue correctement.
        loop_headers: Set[str] = set()   # labels qui démarrent une boucle
        back_jump_at: Dict[int, str] = {}  # idx → label cible du back-jump

        for _ii, _instr in enumerate(instrs):
            if _instr.opcode in ('JUMP_BACKWARD', 'JUMP_ABSOLUTE',
                                  'JUMP_BACKWARD_NO_INTERRUPT'):
                _m = re.search(r'to (L\w+)', _instr.raw_arg)
                if _m:
                    _tgt = _m.group(1)
                    _tgt_idx = label_to_idx.get(_tgt, 9999)
                    if _tgt_idx <= _ii:   # saut en arrière = fermeture de boucle
                        loop_headers.add(_tgt)
                        back_jump_at[_ii] = _tgt

        # Pour chaque en-tête de boucle, trouver l'index du back-jump le plus loin
        loop_end_idx: Dict[str, int] = {}  # header_label → index du dernier back-jump
        for _jj, _tgt in back_jump_at.items():
            if _tgt in loop_headers:
                if _tgt not in loop_end_idx or _jj > loop_end_idx[_tgt]:
                    loop_end_idx[_tgt] = _jj

        # Pile des boucles actives: (header_label, indent_before_while)
        while_stack: List[Tuple[str, int]] = []
        # Labels déjà émis comme en-têtes de boucle
        while_emitted: Set[str] = set()
        # ─────────────────────────────────────────────────────────────────────

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

                # ── Fermeture de boucle while: on revient à l'en-tête ────────
                # Si on arrive à un label qui est en-tête de boucle ET qu'on
                # n'a pas encore émis le while pour ce label, on l'émet.
                if lbl in loop_headers and lbl not in while_emitted:
                    # La condition du while est soit True (while True), soit
                    # déterminée par le prochain POP_JUMP_IF_* avant le corps.
                    # Pour l'instant on émet while True: et on laisse les if+break
                    # gérer les sorties.
                    out.append(f'{ind}while True:')
                    while_emitted.add(lbl)
                    while_stack.append((lbl, indent))
                    indent += 1
                    ind = '    ' * indent

                # ── Fermeture des blocs if/elif ──────────────────────────────
                # Quand on atteint le label cible d'un if_stack, on ferme
                # les blocs if dont la cible est ce label (en dédentant)
                while if_stack and if_stack[-1][2] == lbl:
                    _, if_ind, _, _ = if_stack.pop()
                    indent = if_ind
                    ind = '    ' * indent
                # ─────────────────────────────────────────────────────────────

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
                # Détecter si ce saut va au-delà de la boucle courante (= sortie)
                _is_loop_exit = (while_stack and lbl and
                    tgt_idx > loop_end_idx.get(while_stack[-1][0], 9999))
                _is_back_jump = lbl and tgt_idx <= i
                if _is_loop_exit:
                    # if not cond: break
                    out.append(f'{ind}if not {cond}:')
                    out.append(f'{ind}    break')
                elif _is_back_jump:
                    # if not cond: continue
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
                        # Saut en arrière = fin du corps de la boucle while
                        # Dédenter pour revenir au niveau du while
                        if while_stack:
                            header_lbl, while_ind = while_stack[-1]
                            if lbl == header_lbl:
                                # C'est la fermeture normale du corps → pas de
                                # break/continue, juste fermeture d'indentation
                                indent = while_ind + 1  # reste indenté dans le while
                                ind = '    ' * indent
                            elif lbl in loop_headers:
                                # continue vers une autre boucle ou sous-boucle
                                out.append(f'{ind}continue')
                        elif lbl in loop_headers:
                            out.append(f'{ind}continue')
                    elif if_stack and lbl:
                        pass  # JUMP_FORWARD normal après corps de if

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

def validate_syntax(code: str) -> Tuple[bool, str]:

    import warnings as _wmod
    with _wmod.catch_warnings(record=True) as _caught:
        _wmod.simplefilter('always')
        try:
            ast.parse(code)
        except SyntaxError as e:
            return False, f'SyntaxError at line {e.lineno}: {e.msg}'
    for w in _caught:
        if issubclass(w.category, SyntaxWarning):
            return True, f'SyntaxWarning at line {w.lineno or 0}: {w.message}'
    return True, ''

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

class CrossVersionDisassembler:

    def __init__(self, py_ver: Tuple[int,int], verbose: bool = False):
        self.py_ver = py_ver
        self.verbose = verbose
        self.opcode_table = _get_opcode_table(py_ver)
        self.have_argument = _HAVE_ARGUMENT.get(py_ver, 90)
        self.cache_counts = _CACHE_COUNTS.get(py_ver, {})
        self._output_lines: List[str] = []

    def disassemble_all(self, co) -> str:

        self._output_lines = []
        self._disassemble_recursive(co, depth=0)
        return '\n'.join(self._output_lines)

    def _disassemble_recursive(self, co, depth: int = 0):

        if not isinstance(co, PycCodeObject):
            pco = _wrap_code_object(co, self.py_ver)
        else:
            pco = co

        if depth > 0:
            self._output_lines.append('')
            self._output_lines.append(
                f'Disassembly of <code object {pco.co_name} at {hex(id(co))}>:'
            )

        self._disassemble_one(pco)

        for const in pco.co_consts:
            if hasattr(const, 'co_name'):
                self._disassemble_recursive(const, depth + 1)

    def _disassemble_one(self, co: PycCodeObject):

        code = co.co_code
        if not code:
            return

        lineno_map = _get_lineno_map(co)
        n = len(code)
        i = 0
        extended_arg = 0
        last_lineno_emitted = None

        while i < n:
            offset = i
            op = code[i]
            i += 1

            if i < n:
                arg_byte = code[i]
                i += 1
            else:
                arg_byte = 0

            arg = arg_byte | extended_arg

            op_name = self.opcode_table.get(op, f'OP_{op}')

            if op_name == 'EXTENDED_ARG':
                extended_arg = arg << 8

                continue
            else:
                extended_arg = 0

            lineno = lineno_map.get(offset)
            if lineno is None:

                for back_off in range(offset, -1, -2):
                    if back_off in lineno_map:
                        lineno = lineno_map[back_off]
                        break

            lineno_str = ''
            if lineno is not None and lineno != last_lineno_emitted:
                lineno_str = str(lineno)
                last_lineno_emitted = lineno

            comment = self._resolve_arg(op_name, arg, co)

            if comment:
                line = f'{lineno_str:>6}  {offset:>6}  {op_name:<30} {arg:<5} ({comment})'
            else:
                line = f'{lineno_str:>6}  {offset:>6}  {op_name:<30} {arg}'

            self._output_lines.append(line)

            n_cache = self.cache_counts.get(op_name, 0)
            for _ in range(n_cache):
                if i + 1 < n:
                    cache_op = code[i]
                    cache_name = self.opcode_table.get(cache_op, f'OP_{cache_op}')
                    if cache_name == 'CACHE':
                        i += 2
                    else:
                        break
                else:
                    break

    def _resolve_arg(self, op_name: str, arg: int, co: PycCodeObject) -> str:

        py = self.py_ver

        try:

            if op_name in ('LOAD_CONST', 'RETURN_CONST', 'LOAD_SMALL_INT', 'LOAD_ZERO'):
                if op_name == 'LOAD_SMALL_INT':
                    return str(arg)
                if op_name == 'LOAD_ZERO':
                    return '0'
                if co.co_consts and 0 <= arg < len(co.co_consts):
                    val = co.co_consts[arg]
                    return _repr_const(val)
                return str(arg)

            elif op_name in ('LOAD_NAME', 'STORE_NAME', 'DELETE_NAME',
                             'IMPORT_NAME', 'IMPORT_FROM', 'LOAD_FROM_DICT_OR_GLOBALS'):
                if co.co_names and 0 <= arg < len(co.co_names):
                    return co.co_names[arg]
                return str(arg)

            elif op_name in ('LOAD_FAST', 'STORE_FAST', 'DELETE_FAST',
                             'LOAD_FAST_CHECK', 'LOAD_FAST_AND_CLEAR',
                             'STORE_FAST_MAYBE_NULL', 'LOAD_FAST_BORROW'):
                if co.co_varnames and 0 <= arg < len(co.co_varnames):
                    return co.co_varnames[arg]
                return str(arg)

            elif op_name == 'LOAD_FAST_BORROW_LOAD_FAST_BORROW':

                idx1 = arg & 0xFF
                idx2 = (arg >> 8) & 0xFF
                v1 = co.co_varnames[idx1] if co.co_varnames and idx1 < len(co.co_varnames) else str(idx1)
                v2 = co.co_varnames[idx2] if co.co_varnames and idx2 < len(co.co_varnames) else str(idx2)
                return f'{v1}, {v2}'

            elif op_name == 'STORE_FAST_STORE_FAST':
                idx1 = arg & 0xFF
                idx2 = (arg >> 8) & 0xFF
                v1 = co.co_varnames[idx1] if co.co_varnames and idx1 < len(co.co_varnames) else str(idx1)
                v2 = co.co_varnames[idx2] if co.co_varnames and idx2 < len(co.co_varnames) else str(idx2)
                return f'{v1}, {v2}'

            elif op_name == 'LOAD_GLOBAL':
                if py >= (3, 11):

                    name_idx = arg >> 1
                    push_null = arg & 1
                    if co.co_names and 0 <= name_idx < len(co.co_names):
                        name = co.co_names[name_idx]
                        if push_null:
                            return f'NULL + {name}'
                        return name
                else:
                    if co.co_names and 0 <= arg < len(co.co_names):
                        return co.co_names[arg]
                return str(arg)

            elif op_name in ('STORE_GLOBAL', 'DELETE_GLOBAL'):
                if co.co_names and 0 <= arg < len(co.co_names):
                    return co.co_names[arg]
                return str(arg)

            elif op_name in ('LOAD_ATTR', 'STORE_ATTR', 'DELETE_ATTR'):
                if py >= (3, 12):

                    name_idx = arg >> 1
                    is_method = arg & 1
                    if co.co_names and 0 <= name_idx < len(co.co_names):
                        name = co.co_names[name_idx]
                        if is_method and op_name == 'LOAD_ATTR':
                            return f'NULL|self + {name}'
                        return name
                else:
                    if co.co_names and 0 <= arg < len(co.co_names):
                        return co.co_names[arg]
                return str(arg)

            elif op_name == 'LOAD_METHOD':
                if co.co_names and 0 <= arg < len(co.co_names):
                    return co.co_names[arg]
                return str(arg)

            elif op_name in ('LOAD_CLOSURE', 'LOAD_DEREF', 'STORE_DEREF',
                             'DELETE_DEREF', 'LOAD_CLASSDEREF', 'MAKE_CELL'):

                all_vars = list(co.co_cellvars or ()) + list(co.co_freevars or ())
                if 0 <= arg < len(all_vars):
                    return all_vars[arg]
                return str(arg)

            elif op_name == 'LOAD_SUPER_ATTR':
                name_idx = arg >> 2 if py >= (3, 12) else arg >> 1
                if co.co_names and 0 <= name_idx < len(co.co_names):
                    return co.co_names[name_idx]
                return str(arg)

            elif op_name == 'BINARY_OP':
                return _BINARY_OP_NAMES.get(arg, str(arg))

            elif op_name == 'COMPARE_OP':
                return _cmp_op_name(arg, py)

            elif op_name == 'IS_OP':
                return 'is not' if arg else 'is'
            elif op_name == 'CONTAINS_OP':
                return 'not in' if arg else 'in'

            elif op_name == 'MAKE_FUNCTION':
                flags = []
                if arg & 0x01: flags.append('defaults')
                if arg & 0x02: flags.append('kwdefaults')
                if arg & 0x04: flags.append('annotations')
                if arg & 0x08: flags.append('closure')
                return ', '.join(flags) if flags else ''

            elif op_name == 'SET_FUNCTION_ATTRIBUTE':
                attrs = {1: 'defaults', 2: 'kwdefaults', 4: 'annotations', 8: 'closure'}
                return attrs.get(arg, str(arg))

            elif op_name == 'FORMAT_VALUE':
                conv = arg & 0x03
                have_spec = bool(arg & 0x04)
                conv_str = {0: '', 1: '!s', 2: '!r', 3: '!a'}.get(conv, '')
                return f'{conv_str}' + (' with spec' if have_spec else '')

            elif op_name == 'UNPACK_SEQUENCE':
                return str(arg)

            elif op_name == 'RAISE_VARARGS':
                return str(arg)

            elif op_name in ('CALL', 'PRECALL', 'CALL_FUNCTION',
                             'CALL_FUNCTION_KW', 'CALL_KW',
                             'CALL_FUNCTION_EX', 'CALL_METHOD'):
                return str(arg)

            elif op_name in ('JUMP_FORWARD', 'JUMP_BACKWARD', 'JUMP_ABSOLUTE',
                             'POP_JUMP_IF_FALSE', 'POP_JUMP_IF_TRUE',
                             'POP_JUMP_IF_NONE', 'POP_JUMP_IF_NOT_NONE',
                             'POP_JUMP_FORWARD_IF_FALSE', 'POP_JUMP_FORWARD_IF_TRUE',
                             'POP_JUMP_BACKWARD_IF_FALSE', 'POP_JUMP_BACKWARD_IF_TRUE',
                             'POP_JUMP_FORWARD_IF_NONE', 'POP_JUMP_FORWARD_IF_NOT_NONE',
                             'POP_JUMP_BACKWARD_IF_NONE', 'POP_JUMP_BACKWARD_IF_NOT_NONE',
                             'JUMP_IF_FALSE_OR_POP', 'JUMP_IF_TRUE_OR_POP',
                             'JUMP_NO_INTERRUPT', 'JUMP_BACKWARD_NO_INTERRUPT',
                             'FOR_ITER', 'SEND', 'SETUP_FINALLY', 'SETUP_WITH',
                             'SETUP_ASYNC_WITH'):
                return f'to {arg}'

            elif op_name == 'KW_NAMES':
                if co.co_consts and 0 <= arg < len(co.co_consts):
                    val = co.co_consts[arg]
                    return _repr_const(val)
                return str(arg)

            elif op_name in ('BUILD_TUPLE', 'BUILD_LIST', 'BUILD_SET',
                             'BUILD_MAP', 'BUILD_STRING', 'BUILD_SLICE',
                             'BUILD_CONST_KEY_MAP'):
                return str(arg)

            elif op_name in ('SWAP', 'COPY', 'ROT_N'):
                return str(arg)

            elif op_name in ('LIST_APPEND', 'SET_ADD', 'MAP_ADD'):
                return str(arg)

            elif op_name == 'MATCH_CLASS':
                return str(arg)

            elif op_name == 'GET_AWAITABLE':
                return {0: '', 1: 'send', 2: 'yield from'}.get(arg, str(arg))

            elif op_name in ('CALL_INTRINSIC_1', 'CALL_INTRINSIC_2'):
                return str(arg)

            elif op_name == 'LOAD_SPECIAL':
                return {0: '__enter__', 1: '__exit__'}.get(arg, str(arg))

            elif op_name == 'RESUME':
                return str(arg)

            return ''

        except (IndexError, TypeError):
            return str(arg)

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

def _custom_marshal_load(data: bytes, py_ver: Tuple[int, int],
                          verbose: bool = False) -> 'PycCodeObject':

    try:
        obj = marshal.loads(data)
        return _wrap_code_object(obj, py_ver)
    except Exception as e1:
        if verbose:
            print(f'[INFO] marshal.loads() natif échoué ({e1}), '
                  f'utilisation du lecteur custom...', file=sys.stderr)

    try:
        reader = MarshalReader(data, py_ver, verbose=verbose)
        obj = reader.load()
        if not isinstance(obj, PycCodeObject):

            obj = _wrap_code_object(obj, py_ver)
        return obj
    except Exception as e2:
        raise ValueError(
            f'Impossible de lire le bytecode marshal.\n'
            f'  Erreur native:  {e1}\n'
            f'  Erreur custom:  {e2}\n'
            f'\n'
            f'  Ce .pyc est compilé pour Python {py_ver[0]}.{py_ver[1]}.\n'
            f'  Installez Python {py_ver[0]}.{py_ver[1]} pour une décompilation parfaite:\n'
            f'  https://www.python.org/downloads/release/python-{py_ver[0]}{py_ver[1]}0/'
        )

def _read_pyc_file(path: str, verbose: bool = False) -> Tuple[Any, Tuple[int, int]]:

    with open(path, 'rb') as f:
        raw = f.read()

    if len(raw) < 16:
        raise ValueError(f'Fichier .pyc trop court ({len(raw)} bytes)')

    magic_word = struct.unpack_from('<H', raw, 0)[0]

    py_ver = _MAGIC_TO_VERSION.get(magic_word)
    if py_ver is None:
        closest = min(_MAGIC_TO_VERSION.keys(), key=lambda k: abs(k - magic_word))
        py_ver = _MAGIC_TO_VERSION[closest]
        if verbose:
            print(f'[WARN] Magic 0x{magic_word:04x} inconnu → '
                  f'Python {py_ver[0]}.{py_ver[1]} (le plus proche)',
                  file=sys.stderr)

    if verbose:
        print(f'[INFO] Magic number: 0x{magic_word:04x} → Python {py_ver[0]}.{py_ver[1]}',
              file=sys.stderr)

    flags = struct.unpack_from('<I', raw, 4)[0]
    header_size = 16

    code_bytes = raw[header_size:]

    cur_ver = sys.version_info[:2]

    if cur_ver == py_ver:

        try:
            code_obj = marshal.loads(code_bytes)
            if verbose:
                print(f'[INFO] Désassemblage natif (Python {cur_ver[0]}.{cur_ver[1]})',
                      file=sys.stderr)
            return code_obj, py_ver
        except Exception as e:
            if verbose:
                print(f'[WARN] marshal.loads natif échoué: {e}', file=sys.stderr)

    if verbose:
        print(f'[INFO] Lecture cross-version: .pyc={py_ver[0]}.{py_ver[1]}, '
              f'Python courant={cur_ver[0]}.{cur_ver[1]}', file=sys.stderr)

    code_obj = _custom_marshal_load(code_bytes, py_ver, verbose=verbose)
    return code_obj, py_ver

def _pyc_to_dis_string(path: str, verbose: bool = False) -> str:

    code_obj, py_ver = _read_pyc_file(path, verbose)

    if verbose:
        print(f'[INFO] Code object: {getattr(code_obj, "co_name", "<module>")}', file=sys.stderr)

    cur_ver = sys.version_info[:2]
    if cur_ver == py_ver:

        try:
            buf = _io.StringIO()
            import dis as _dis
            _dis.dis(code_obj, file=buf)
            if verbose:
                print(f'[INFO] Désassemblage avec dis.dis() natif (version identique)', file=sys.stderr)
            return buf.getvalue()
        except Exception as e:
            if verbose:
                print(f'[WARN] dis.dis() natif a échoué ({e}), utilisation du désassembleur custom',
                      file=sys.stderr)

    if verbose:
        print(f'[INFO] Désassemblage cross-version {py_ver[0]}.{py_ver[1]} '
              f'(Python installé: {cur_ver[0]}.{cur_ver[1]})', file=sys.stderr)

    disasm = CrossVersionDisassembler(py_ver, verbose=verbose)
    return disasm.disassemble_all(code_obj)

def _get_pyc_python_version(path: str) -> Optional[Tuple[int, int]]:

    try:
        with open(path, 'rb') as f:
            raw = f.read(4)
        if len(raw) < 4:
            return None
        magic_word = struct.unpack_from('<H', raw, 0)[0]

        ver = _MAGIC_TO_VERSION.get(magic_word)
        if ver:
            return ver

        closest = min(_MAGIC_TO_VERSION.keys(), key=lambda k: abs(k - magic_word))
        return _MAGIC_TO_VERSION[closest]
    except Exception:
        return None

def _probe_python_exe(path: str, target_ver: Tuple[int, int]) -> bool:

    import subprocess
    try:
        r = subprocess.run(
            [path, '-c', 'import sys; print(sys.version_info[:2])'],
            capture_output=True, text=True, timeout=8
        )
        out = (r.stdout + r.stderr).strip()

        m = re.search(r'\((\d+),\s*(\d+)\)', out)
        if m and (int(m.group(1)), int(m.group(2))) == target_ver:
            return True
        m2 = re.search(r'Python (\d+)\.(\d+)', out)
        if m2 and (int(m2.group(1)), int(m2.group(2))) == target_ver:
            return True
    except Exception:
        pass
    return False

def _find_python_exe(ver: Tuple[int, int], verbose: bool = False) -> Optional[str]:

    import shutil
    import subprocess
    import os
    maj, mn = ver

    def probe(path: str) -> bool:
        return _probe_python_exe(path, ver)

    found: Optional[str] = None

    if sys.platform == 'win32':
        py_launcher = shutil.which('py')
        if py_launcher:
            try:
                r = subprocess.run(
                    [py_launcher, f'-{maj}.{mn}', '-c',
                     'import sys; print(sys.version_info[:2])'],
                    capture_output=True, text=True, timeout=8
                )
                out = r.stdout + r.stderr
                m = re.search(r'\((\d+),\s*(\d+)\)', out)
                if m and (int(m.group(1)), int(m.group(2))) == ver:
                    if verbose:
                        print(f'[FIND] py launcher: py -{maj}.{mn}', file=sys.stderr)

                    r2 = subprocess.run(
                        [py_launcher, f'-{maj}.{mn}', '-c',
                         'import sys; print(sys.executable)'],
                        capture_output=True, text=True, timeout=8
                    )
                    real_exe = r2.stdout.strip()
                    if real_exe and os.path.isfile(real_exe):
                        return real_exe
            except Exception:
                pass

    path_candidates = [
        f'python{maj}.{mn}',
        f'python{maj}',
        'python3',
        'python',
    ]
    for name in path_candidates:
        exe = shutil.which(name)
        if exe and probe(exe):
            if verbose:
                print(f'[FIND] PATH: {exe}', file=sys.stderr)
            return exe

    if sys.platform == 'win32':
        home = os.path.expanduser('~')
        win_paths = []

        for suffix in (f'Python{maj}{mn}', f'Python{maj}.{mn}'):
            win_paths.extend([
                os.path.join(home, 'AppData', 'Local', 'Programs',
                             'Python', suffix, 'python.exe'),
                os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Programs',
                             'Python', suffix, 'python.exe'),
            ])

        for root in ('C:\\', 'D:\\'):
            win_paths.extend([
                os.path.join(root, f'Python{maj}{mn}', 'python.exe'),
                os.path.join(root, f'Python{maj}.{mn}', 'python.exe'),
                os.path.join(root, 'Python', f'{maj}.{mn}', 'python.exe'),
            ])

        for pf in (os.environ.get('ProgramFiles', 'C:\\Program Files'),
                   os.environ.get('ProgramFiles(x86)', 'C:\\Program Files (x86)')):
            win_paths.extend([
                os.path.join(pf, 'Python', f'{maj}.{mn}', 'python.exe'),
                os.path.join(pf, f'Python{maj}{mn}', 'python.exe'),
            ])

        local_app = os.environ.get('LOCALAPPDATA', '')
        win_apps = os.path.join(local_app, 'Microsoft', 'WindowsApps')
        if os.path.isdir(win_apps):
            win_paths.append(
                os.path.join(win_apps, f'python{maj}.{mn}.exe')
            )

        for path in win_paths:
            if path and os.path.isfile(path) and probe(path):
                if verbose:
                    print(f'[FIND] Windows path: {path}', file=sys.stderr)
                return path

        try:
            import winreg
            ver_str = f'{maj}.{mn}'
            reg_paths = [
                (winreg.HKEY_LOCAL_MACHINE,
                 f'SOFTWARE\\Python\\PythonCore\\{ver_str}\\InstallPath'),
                (winreg.HKEY_CURRENT_USER,
                 f'SOFTWARE\\Python\\PythonCore\\{ver_str}\\InstallPath'),
                (winreg.HKEY_LOCAL_MACHINE,
                 f'SOFTWARE\\WOW6432Node\\Python\\PythonCore\\{ver_str}\\InstallPath'),
            ]
            for hive, subkey in reg_paths:
                try:
                    with winreg.OpenKey(hive, subkey) as k:
                        install_dir, _ = winreg.QueryValueEx(k, 'ExecutablePath')
                        if os.path.isfile(install_dir) and probe(install_dir):
                            if verbose:
                                print(f'[FIND] Registre: {install_dir}', file=sys.stderr)
                            return install_dir

                        exe_path = os.path.join(install_dir, 'python.exe')
                        if os.path.isfile(exe_path) and probe(exe_path):
                            if verbose:
                                print(f'[FIND] Registre dir: {exe_path}', file=sys.stderr)
                            return exe_path
                except Exception:
                    pass
        except ImportError:
            pass

    else:
        unix_paths = [
            f'/usr/bin/python{maj}.{mn}',
            f'/usr/local/bin/python{maj}.{mn}',
            f'/usr/bin/python{maj}',
            f'/usr/local/bin/python{maj}',

            f'/opt/homebrew/bin/python{maj}.{mn}',
            f'/opt/homebrew/opt/python@{maj}.{mn}/bin/python{maj}.{mn}',

            f'/usr/local/opt/python@{maj}.{mn}/bin/python{maj}.{mn}',

            f'/opt/local/bin/python{maj}.{mn}',

            f'/nix/var/nix/profiles/default/bin/python{maj}.{mn}',
        ]

        pyenv_root = os.path.expanduser('~/.pyenv/versions')
        if os.path.isdir(pyenv_root):
            try:
                for entry in sorted(os.listdir(pyenv_root), reverse=True):
                    if entry.startswith(f'{maj}.{mn}.'):
                        p = os.path.join(pyenv_root, entry, 'bin', 'python')
                        unix_paths.insert(0, p)
            except Exception:
                pass

        asdf_root = os.path.expanduser('~/.asdf/installs/python')
        if os.path.isdir(asdf_root):
            try:
                for entry in sorted(os.listdir(asdf_root), reverse=True):
                    if entry.startswith(f'{maj}.{mn}.'):
                        p = os.path.join(asdf_root, entry, 'bin', 'python')
                        unix_paths.insert(0, p)
            except Exception:
                pass

        for conda_root in ('~/miniconda3', '~/anaconda3', '~/conda',
                           '/opt/conda', '/opt/miniconda3', '/opt/anaconda3'):
            expanded = os.path.expanduser(conda_root)
            for sub in ('bin', os.path.join('envs', f'py{maj}{mn}', 'bin')):
                p = os.path.join(expanded, sub, f'python{maj}.{mn}')
                unix_paths.append(p)

        for path in unix_paths:
            if path and os.path.isfile(path) and probe(path):
                if verbose:
                    print(f'[FIND] Unix path: {path}', file=sys.stderr)
                return path

    return None

def _open_python_download(ver: Tuple[int, int]):

    import webbrowser
    maj, mn = ver
    url = f'https://www.python.org/downloads/release/python-{maj}{mn}0/'
    print(f'  → Ouverture: {url}')
    webbrowser.open(url)

def _relaunch_with_python(ver: Tuple[int, int], exe: str):

    import subprocess
    maj, mn = ver
    print(f'[AUTO] Python {maj}.{mn} détecté → {exe}')
    print(f'[AUTO] Relancement pour décompilation optimale...\n')
    result = subprocess.run([exe] + sys.argv)
    sys.exit(result.returncode)

def _check_version_and_maybe_relaunch(input_path: str,
                                       force: bool = False,
                                       verbose: bool = False):

    if force or not input_path.lower().endswith('.pyc'):
        return

    target = _get_pyc_python_version(input_path)
    if target is None:
        return

    cur = sys.version_info[:2]
    if cur == target:
        return

    maj, mn = target
    sep = '═' * 62

    print(f'\n{sep}')
    print(f'  Ce .pyc est compilé avec Python {maj}.{mn}')
    print(f'  Version Python courante: {cur[0]}.{cur[1]}')
    print(f'  Recherche de Python {maj}.{mn} sur ce PC...')
    print(f'{sep}')

    exe = _find_python_exe(target, verbose=verbose)

    if exe:

        print(f'  ✅ Python {maj}.{mn} trouvé → {exe}')
        print(f'  Relancement automatique...\n')
        _relaunch_with_python(target, exe)

    print(f'  ❌ Python {maj}.{mn} non trouvé sur ce PC.')
    print(f'{sep}')
    print(f'  Pour une décompilation PARFAITE, installez Python {maj}.{mn}.')
    print(f'  Le script se relancera automatiquement à la prochaine utilisation.')
    print(f'{sep}')
    print()

    try:
        if sys.stdin.isatty():
            ans = input(f'  Ouvrir python.org pour installer Python {maj}.{mn} ? [o/N] ').strip().lower()
            if ans in ('o', 'oui', 'y', 'yes'):
                _open_python_download(target)
                print()
                print('  Après installation, relancez ce script.')
                print('  Il se relancera automatiquement avec Python {maj}.{mn}.')
                sys.exit(0)
    except (EOFError, KeyboardInterrupt):
        pass

    print(f'  ℹ  Continuation en mode cross-version (lecteur marshal custom)...\n')

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

def reorder_definitions(code: str) -> str:
    """
    Réordonne le code pour que les classes et fonctions soient définies
    avant le code module-level qui les utilise.
    Résout les NameError du type "name 'Foo' is not defined".
    """
    lines = code.splitlines(keepends=True)
    
    imports = []
    definitions = []   # class / def blocks (top-level)
    module_level = []  # tout le reste (code exécuté au niveau module)
    
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.rstrip('\n').rstrip()
        
        # Lignes vides ou commentaires → on les garde avec le bloc précédent
        if not stripped or stripped.startswith('#'):
            if definitions:
                definitions.append(line)
            elif imports:
                imports.append(line)
            else:
                module_level.append(line)
            i += 1
            continue
        
        # Imports
        if re.match(r'^(import |from )', stripped):
            imports.append(line)
            i += 1
            continue
        
        # Début d'une classe ou fonction top-level (non indentée)
        if re.match(r'^(class |def |async def )', stripped):
            block = [line]
            i += 1
            # Collecter toutes les lignes indentées qui suivent (corps du bloc)
            while i < len(lines):
                next_line = lines[i]
                next_stripped = next_line.rstrip('\n').rstrip()
                # Une ligne vide ou commentaire à l'intérieur du bloc
                if not next_stripped:
                    block.append(next_line)
                    i += 1
                    continue
                # Si la ligne est indentée → partie du bloc
                if next_line[0:1] in (' ', '\t'):
                    block.append(next_line)
                    i += 1
                # Sinon fin du bloc
                else:
                    break
            definitions.append(''.join(block))
            continue
        
        # Code module-level
        module_level.append(line)
        i += 1
    
    # Reconstituer dans l'ordre : imports, définitions, code module-level
    result = ''.join(imports)
    if result and not result.endswith('\n\n'):
        result += '\n'
    result += '\n'.join(definitions)
    if module_level:
        result += '\n'
        result += ''.join(module_level)
    
    return result


class SemanticFixer:
    """
    Correcteur sémantique post-décompilation — version complète.

    Phases:
      1. Nettoyage des `global X` invalides (X est aussi un paramètre → SyntaxError)
      2. Suppression des paramètres fantômes (toutes fonctions)
      3. Re-nettoyage des globaux après modification des params
      4. Correction signatures callbacks (pynput, tkinter, etc.)
      5. Correction artefacts structurels (double calls, None, try:raise, unreachable)
      6. Injection des `global` manquants pour vraies variables globales
      7. Fusion import aliases (XYZ = Lib → from X import Y as XYZ)
      8. Ajout if __name__ == '__main__' si absent
      9. Injection structures ctypes manquantes
    """

    def __init__(self, code: str):
        self.code = code

    def fix(self) -> str:
        lines = self.code.splitlines()
        lines = self._fix_tuple_index_calls(lines)  # var1,var2=f()[0],f()[1] → var1,var2=f()
        lines = self._clean_invalid_globals(lines)
        lines = self._fix_all_phantom_params(lines)
        lines = self._fix_missing_params_from_callsites(lines)  # f(a,b) mais def f(a) → add b
        lines = self._clean_invalid_globals(lines)
        lines = self._fix_callback_signatures(lines)
        lines = self._fix_double_calls(lines)
        lines = self._fix_none_calls(lines)
        lines = self._fix_type_modulo(lines)
        lines = self._fix_bare_none_statements(lines)
        lines = self._fix_try_raise_artifact(lines)
        lines = self._fix_unreachable_after_return(lines)
        lines = self._fix_import_aliases(lines)
        lines = self._resolve_anon_vars(lines)      # résout _anonN → vrais noms
        lines = self._wrap_main_guard(lines)       # AVANT inject_missing_globals
        lines = self._inject_missing_globals(lines) # vars __main__ non visibles
        lines = self._clean_invalid_globals(lines)  # nettoyage final
        lines = self._add_missing_ctypes_structures(lines)
        return '\n'.join(lines)

    # ═══════════════════════════════════════════════════════════════════
    # PHASE _resolve_anon_vars — Résolution des variables _anonN
    #
    # Problème: le décompilateur génère parfois:
    #   _anon0, _anon1 = some_func()[0], some_func()[1]
    # alors que le code original était:
    #   real_name, _ = some_func()
    # Résultat: `real_name` est utilisé plus loin mais jamais défini → NameError.
    #
    # Algorithme:
    #   Pour chaque scope (module + corps de fonctions):
    #     1. Collecter les variables _anonN assignées
    #     2. Collecter les noms utilisés mais jamais définis dans ce scope
    #     3. Pour chaque nom indéfini, chercher si un _anonN lui correspond
    #        (même position dans un tuple-unpack, ou heuristique d'usage)
    #     4. Renommer _anonN → nom_réel dans tout le scope
    # ═══════════════════════════════════════════════════════════════════

    def _resolve_anon_vars(self, lines: List[str]) -> List[str]:
        """
        Renomme les variables _anonN en noms réels si ceux-ci sont utilisés
        mais jamais définis dans le même scope.
        """
        # Collecter les noms définis au niveau module (fonctions, classes, variables)
        module_defined: Set[str] = set()
        IDENT_RE2 = re.compile(r'\b([a-zA-Z_]\w*)\b')
        for line in lines:
            # Fonctions et classes top-level
            m_def = re.match(r'^(?:def|class|async\s+def)\s+(\w+)', line.strip())
            if m_def:
                module_defined.add(m_def.group(1))
            # Assignments top-level (non indentés)
            if not line[:1].isspace():
                assign_m = re.match(r'^([a-zA-Z_]\w*(?:\s*,\s*[a-zA-Z_]\w*)*)\s*=(?!=)', line.strip())
                if assign_m:
                    for name in re.split(r'\s*,\s*', assign_m.group(1)):
                        module_defined.add(name.strip())
            # Imports
            imp_m = re.match(r'^(?:import|from)\s+(\w+)', line.strip())
            if imp_m:
                module_defined.add(imp_m.group(1))
            for m in re.finditer(r'import\s+(\w+)(?:\s+as\s+(\w+))?', line):
                module_defined.add(m.group(2) or m.group(1))

        # Identifie les scopes : module-level + chaque corps de fonction
        scopes = self._extract_scopes(lines)

        # Construire un mapping de remplacement global {_anonN: real_name}
        replacements: Dict[str, str] = {}

        for scope_lines, scope_start in scopes:
            scope_replacements = self._compute_anon_replacements(
                scope_lines, extra_known=module_defined
            )
            replacements.update(scope_replacements)

        if not replacements:
            return lines

        # Appliquer les remplacements sur tout le fichier
        return self._apply_anon_replacements(lines, replacements)

    def _extract_scopes(self, lines: List[str]) -> List[Tuple[List[str], int]]:
        """
        Retourne une liste de (lignes_du_scope, index_debut).
        Un scope = corps d'une fonction/méthode, ou le module entier.
        """
        scopes = []
        i = 0
        while i < len(lines):
            line = lines[i]
            m = re.match(r'^(\s*)(?:async\s+)?def\s+\w+\s*\(', line)
            if m:
                block_idx = self._get_block(lines, i)
                body = [lines[j] for j in block_idx[1:]]
                scopes.append((body, block_idx[1] if len(block_idx) > 1 else i + 1))
                i = block_idx[-1] + 1
            else:
                i += 1
        # Module-level scope
        scopes.append((lines, 0))
        return scopes

    @staticmethod
    def _strip_string_literals(s: str) -> str:
        """
        Remplace le contenu des chaînes littérales par des espaces,
        pour éviter de confondre des mots dans une chaîne avec des identifiants.
        Gère f-strings, triple-quotes, guillemets simples/doubles.
        """
        result = []
        i = 0
        while i < len(s):
            # Triple guillemets
            if s[i:i+3] in ('"""', "'''"):
                q = s[i:i+3]
                end = s.find(q, i + 3)
                if end == -1:
                    result.append(' ' * (len(s) - i))
                    break
                content = s[i:end + 3]
                result.append(' ' * len(content))
                i = end + 3
            # Guillemets simples ou doubles
            elif s[i] in ('"', "'"):
                q = s[i]
                j = i + 1
                while j < len(s) and s[j] != q:
                    if s[j] == '\\':
                        j += 2
                    else:
                        j += 1
                end = j
                result.append(' ' * (end - i + 1))
                i = end + 1
            else:
                result.append(s[i])
                i += 1
        return ''.join(result)

    def _compute_anon_replacements(self, scope_lines: List[str], extra_known: Optional[Set[str]] = None) -> Dict[str, str]:
        """
        Dans un scope donné, trouve les _anonN non utilisés et les variables
        utilisées mais non définies, et propose un mapping de renommage.

        Amélioration v2: ignore les identifiants dans les chaînes littérales
        pour ne pas confondre du texte avec des noms de variables.
        Association par ordre d'apparition après l'assignation du _anonN.
        """
        ANON_RE = re.compile(r'\b(_anon\d+)\b')
        IDENT_RE = re.compile(r'\b([a-zA-Z_]\w*)\b')

        KEYWORDS = {
            'None', 'True', 'False', 'and', 'as', 'assert', 'async', 'await',
            'break', 'class', 'continue', 'def', 'del', 'elif', 'else',
            'except', 'finally', 'for', 'from', 'global', 'if', 'import',
            'in', 'is', 'lambda', 'nonlocal', 'not', 'or', 'pass', 'raise',
            'return', 'try', 'while', 'with', 'yield',
            'print', 'len', 'range', 'int', 'str', 'float', 'list', 'dict',
            'set', 'tuple', 'bool', 'type', 'object', 'super', 'self', 'cls',
            'input', 'open', 'enumerate', 'zip', 'map', 'filter', 'sorted',
            'reversed', 'isinstance', 'issubclass', 'hasattr', 'getattr',
            'setattr', 'delattr', 'vars', 'dir', 'id', 'hash', 'repr',
            'abs', 'min', 'max', 'sum', 'any', 'all', 'next', 'iter',
            'Exception', 'ValueError', 'TypeError', 'KeyError', 'IndexError',
            'AttributeError', 'RuntimeError', 'StopIteration', 'OSError',
            'IOError', 'FileNotFoundError', 'NameError', 'NotImplementedError',
        }

        assigned: Set[str] = set()
        anon_used: Set[str] = set()
        used: Set[str] = set()

        for line in scope_lines:
            s = line.strip()
            if not s or s.startswith('#'):
                continue

            # Détecter les noms assignés (lhs)
            assign_m = re.match(r'^([a-zA-Z_]\w*(?:\s*,\s*[a-zA-Z_]\w*)*)\s*=(?!=)', s)
            if assign_m:
                for name in re.split(r'\s*,\s*', assign_m.group(1)):
                    name = name.strip()
                    if name:
                        assigned.add(name)

            # Détecter _anonN dans lhs
            anon_assign_m = re.match(
                r'^((?:_anon\d+|[a-zA-Z_]\w*)(?:\s*,\s*(?:_anon\d+|[a-zA-Z_]\w*))*)\s*=(?!=)', s
            )
            if anon_assign_m:
                for name in re.split(r'\s*,\s*', anon_assign_m.group(1)):
                    name = name.strip()
                    if ANON_RE.match(name):
                        assigned.add(name)

            # _anonN utilisés dans expressions (rhs)
            rhs_start = assign_m.end() if assign_m else 0
            rhs_part = s[rhs_start:]
            for m in ANON_RE.finditer(rhs_part):
                anon_used.add(m.group(1))

            # Identifiants utilisés hors chaînes littérales (rhs uniquement)
            s_no_str = self._strip_string_literals(s)
            rhs_no_str = s_no_str[rhs_start:]
            for m in IDENT_RE.finditer(rhs_no_str):
                name = m.group(1)
                if name not in KEYWORDS and not ANON_RE.match(name):
                    used.add(name)

        anon_assigned = {n for n in assigned if ANON_RE.match(n)}
        anon_unused_as_value = anon_assigned - anon_used
        _all_known = KEYWORDS | (extra_known or set())
        undefined_used = used - assigned - _all_known

        if not anon_unused_as_value or not undefined_used:
            return {}

        mapping: Dict[str, str] = {}
        used_anons: Set[str] = set()
        used_undefs: Set[str] = set()

        for line_idx, line in enumerate(scope_lines):
            s = line.strip()
            if not s or s.startswith('#'):
                continue

            anon_assign_lhs = re.match(
                r'^((?:_anon\d+)(?:\s*,\s*(?:_anon\d+|[a-zA-Z_]\w*))*)\s*=(?!=)', s
            )
            if not anon_assign_lhs:
                continue

            lhs_names = [n.strip() for n in re.split(r'\s*,\s*', anon_assign_lhs.group(1))]
            anons_to_map = [
                n for n in lhs_names
                if ANON_RE.match(n) and n in anon_unused_as_value and n not in used_anons
            ]
            if not anons_to_map:
                continue

            # Trouver les premiers usages des noms indéfinis APRÈS cette ligne
            first_uses: Dict[str, int] = {}
            for future_idx in range(line_idx + 1, len(scope_lines)):
                fs = scope_lines[future_idx].strip()
                if not fs or fs.startswith('#'):
                    continue
                fs_no_str = self._strip_string_literals(fs)
                # Cherche dans rhs seulement (pas dans lhs d'un assignment)
                assign_m2 = re.match(r'^[a-zA-Z_]\w*(?:\s*,\s*[a-zA-Z_]\w*)*\s*=(?!=)', fs_no_str)
                rhs_start2 = assign_m2.end() if assign_m2 else 0
                search_zone = fs_no_str[rhs_start2:]
                for m in IDENT_RE.finditer(search_zone):
                    name = m.group(1)
                    if (name in undefined_used and name not in used_undefs
                            and name not in first_uses):
                        first_uses[name] = future_idx

            sorted_undefs = sorted(first_uses.items(), key=lambda x: x[1])
            anons_sorted = sorted(anons_to_map, key=lambda x: int(re.search(r'\d+', x).group()))

            for i, anon in enumerate(anons_sorted):
                if i < len(sorted_undefs):
                    target = sorted_undefs[i][0]
                    if target not in used_undefs:
                        mapping[anon] = target
                        used_anons.add(anon)
                        used_undefs.add(target)

        return mapping

    def _apply_anon_replacements(self, lines: List[str], mapping: Dict[str, str]) -> List[str]:
        """
        Applique le mapping {_anonN: real_name} sur toutes les lignes.
        """
        if not mapping:
            return lines

        # Construire un pattern de remplacement
        # Trier par longueur décroissante pour éviter les remplacements partiels
        sorted_keys = sorted(mapping.keys(), key=len, reverse=True)

        result = []
        for line in lines:
            for old, new in mapping.items():
                # Remplacement word-boundary pour éviter les faux positifs
                line = re.sub(rf'\b{re.escape(old)}\b', new, line)
            result.append(line)
        return result

    # ═══════════════════════════════════════════════════════════════════
    # HELPERS
    # ═══════════════════════════════════════════════════════════════════

    @staticmethod
    def _indent(line: str) -> str:
        return line[: len(line) - len(line.lstrip())]

    @staticmethod
    def _get_block(lines: List[str], start: int) -> List[int]:
        base_indent = SemanticFixer._indent(lines[start])
        result = [start]
        for i in range(start + 1, len(lines)):
            l = lines[i]
            stripped = l.strip()
            if not stripped:
                result.append(i)
                continue
            ind = SemanticFixer._indent(l)
            if len(ind) > len(base_indent):
                result.append(i)
            else:
                break
        return result

    @staticmethod
    def _get_func_params(line: str) -> List[str]:
        m = re.match(r'^\s*(?:async\s+)?def\s+\w+\s*\(([^)]*)\)', line)
        if not m:
            return []
        params = []
        for p in m.group(1).split(','):
            p = p.strip().lstrip('*')
            p = p.split(':')[0].split('=')[0].strip()
            if p and p not in ('self', 'cls'):
                params.append(p)
        return params

    # ═══════════════════════════════════════════════════════════════════
    # PHASE 1 & 3 — Supprimer `global X` invalide quand X est param
    # ═══════════════════════════════════════════════════════════════════

    def _clean_invalid_globals(self, lines: List[str]) -> List[str]:
        """
        Python interdit: def f(x): global x → SyntaxError.

        Supprime ou nettoie toute déclaration `global` dont une ou plusieurs
        variables sont aussi des paramètres de la même fonction.

        - `global kl, ml` quand kl et ml sont params → supprimer la ligne entière
        - `global kl, ml, real_global` → garder `global real_global`
        """
        result = list(lines)
        i = 0
        while i < len(result):
            line = result[i]
            m = re.match(r'^(\s*)(?:async\s+)?def\s+\w+\s*\(([^)]*)\)\s*(?:->.*?)?\s*:', line)
            if not m:
                i += 1
                continue

            param_names = set(self._get_func_params(line))
            if not param_names:
                i += 1
                continue

            block_indices = self._get_block(result, i)

            for j in block_indices[1:]:
                bl = result[j]
                gm = re.match(r'^(\s*)global\s+(.+)', bl)
                if not gm:
                    continue
                gind = gm.group(1)
                gvars = [v.strip() for v in gm.group(2).split(',') if v.strip()]
                clean_vars = [v for v in gvars if v not in param_names]

                if len(clean_vars) == len(gvars):
                    continue
                elif not clean_vars:
                    result[j] = ''
                else:
                    result[j] = f"{gind}global {', '.join(clean_vars)}"

            i += 1

        # Collapse consecutive blank lines introduced by deletions
        out = []
        prev_blank = False
        for line in result:
            if line == '':
                if not prev_blank:
                    out.append(line)
                prev_blank = True
            else:
                out.append(line)
                prev_blank = False
        return out

    # ═══════════════════════════════════════════════════════════════════
    # PHASE 2 — Paramètres fantômes (universel)
    # ═══════════════════════════════════════════════════════════════════

    def _fix_all_phantom_params(self, lines: List[str]) -> List[str]:
        """
        Fixer universel: méthodes (__init__, méthodes), fonctions standalone,
        fonctions imbriquées.

        Un paramètre P est fantôme si:
          A) P est assigné dans le corps (sans self-ref dans RHS) AVANT tout usage
          B) P n'est jamais assigné mais le corps a un tuple-unpack _anonX au début
          C) P n'est jamais utilisé ni assigné du tout
          D) Tous les call-sites passent moins d'args que la signature en déclare

        Ctypes injectés (INPUT, MOUSEINPUT...) → toujours fantômes.
        """
        INJECTED_CTYPES = {
            'INPUT', 'MOUSEINPUT', '_INPUT_UNION',
            'INPUT_MOUSE', 'MOUSEEVENTF_LEFTDOWN', 'MOUSEEVENTF_LEFTUP',
            'MOUSEEVENTF_MOVE', 'MOUSEEVENTF_ABSOLUTE',
        }

        result = list(lines)
        i = 0
        while i < len(result):
            line = result[i]
            m = re.match(r'^(\s*)(?:async\s+)?def\s+(\w+)\s*\(([^)]*)\)\s*(?:->.*?)?\s*:', line)
            if not m:
                i += 1
                continue

            ind, func_name, raw_sig = m.group(1), m.group(2), m.group(3)
            raw_params = [p.strip() for p in raw_sig.split(',') if p.strip()]

            has_self = raw_params and raw_params[0] in ('self', 'cls')
            self_param = [raw_params[0]] if has_self else []
            work_params = raw_params[1:] if has_self else raw_params[:]

            if not work_params:
                i += 1
                continue

            block_indices = self._get_block(result, i)
            body_lines = [result[j] for j in block_indices[1:]]

            body_phantom: Set[str] = set()
            for param in work_params:
                pname = param.split(':')[0].split('=')[0].strip().lstrip('*')
                if not pname or param.startswith('**'):
                    continue
                if pname in INJECTED_CTYPES:
                    body_phantom.add(pname)
                    continue
                if self._is_phantom_by_body(pname, body_lines):
                    body_phantom.add(pname)

            callsite_phantom = self._phantom_by_callsites(result, func_name, work_params)
            phantom = body_phantom | callsite_phantom

            if phantom:
                kept = [
                    p for p in raw_params
                    if p.split(':')[0].split('=')[0].strip().lstrip('*') not in phantom
                ]
                params_str = ', '.join(kept)
                ret_ann = re.search(r'\)\s*(->.+?)\s*:', line)
                ret_part = (' ' + ret_ann.group(1).strip()) if ret_ann else ''
                result[i] = f"{ind}def {func_name}({params_str}){ret_part}:"

            i += 1
        return result

    @staticmethod
    def _is_phantom_by_body(pname: str, body_lines: List[str]) -> bool:
        pesc = re.escape(pname)
        first_assign_idx: Optional[int] = None
        first_use_idx: Optional[int] = None
        ever_assigned = False
        ever_used = False

        ANON_TUPLE_RE = re.compile(
            r'^(?:_anon\d+|_var_\d+|[a-z_]\w*)'
            r'(?:\s*,\s*(?:_anon\d+|_var_\d+|[a-z_]\w*))*\s*='
        )
        ANON_NAME_RE = re.compile(r'^_anon\d+|^_var_\d+')

        has_anon_unpack_early = any(
            ANON_TUPLE_RE.match(bl.strip()) and ANON_NAME_RE.match(bl.strip())
            for bl in body_lines[:6] if bl.strip()
        )

        for li, bl in enumerate(body_lines):
            bs = bl.strip()
            if not bs or bs.startswith('#'):
                continue

            # Direct assignment (not augmented)
            am = re.match(rf'^{pesc}\s*=(?!=)\s*(.+)', bs)
            if am and first_assign_idx is None:
                rhs = am.group(1).strip()
                ever_assigned = True
                if not re.search(rf'\b{pesc}\b', rhs):
                    first_assign_idx = li
                continue

            # Tuple unpack
            tm = re.match(
                rf'^(?:[\w_]+\s*,\s*)*{pesc}(?:\s*,\s*[\w_]+)*\s*=(?!=)\s*(.+)', bs
            )
            if tm and first_assign_idx is None:
                rhs = tm.group(1).strip()
                ever_assigned = True
                if not re.search(rf'\b{pesc}\b', rhs):
                    first_assign_idx = li
                continue

            # Augmented assign → use
            if re.match(rf'^{pesc}\s*[+\-*/%|&^]=', bs):
                ever_used = True
                if first_use_idx is None:
                    first_use_idx = li
                continue

            # Use as value
            if re.search(rf'\b{pesc}\b', bs) and not re.match(rf'^{pesc}\s*=', bs):
                ever_used = True
                if first_use_idx is None:
                    first_use_idx = li

        # Rule A: assigned before first use
        if first_assign_idx is not None:
            if first_use_idx is None or first_assign_idx < first_use_idx:
                return True
        # Rule B: never assigned, early anon tuple-unpack present
        if not ever_assigned and has_anon_unpack_early:
            return True
        # Rule C: never used or assigned
        if not ever_used and not ever_assigned:
            return True

        return False

    @staticmethod
    def _collect_call_sites(all_lines: List[str], func_name: str) -> List[int]:
        pat = re.compile(rf'(?<!\bdef\s)\b{re.escape(func_name)}\s*\(([^)]*)\)')
        results = []
        for line in all_lines:
            if re.match(r'^\s*(?:async\s+)?def\s+', line):
                continue
            if line.strip().startswith('#'):
                continue
            for m in pat.finditer(line):
                args_str = m.group(1).strip()
                if not args_str:
                    results.append(0)
                else:
                    parts = [a.strip() for a in args_str.split(',') if a.strip()]
                    pos = sum(1 for p in parts if '=' not in p and not p.startswith('**'))
                    results.append(pos)
        return results

    def _phantom_by_callsites(
        self,
        all_lines: List[str],
        func_name: str,
        work_params: List[str],
    ) -> Set[str]:
        call_counts = self._collect_call_sites(all_lines, func_name)
        if not call_counts:
            return set()
        min_args = min(call_counts)
        max_args = max(call_counts)
        if min_args != max_args:
            return set()
        positional = [p for p in work_params if not p.startswith('*') and '=' not in p]
        n_pos = len(positional)
        if n_pos <= min_args:
            return set()
        excess = n_pos - min_args
        phantom_names: Set[str] = set()
        for p in positional[-excess:]:
            pname = p.split(':')[0].split('=')[0].strip().lstrip('*')
            phantom_names.add(pname)
        return phantom_names

    # ═══════════════════════════════════════════════════════════════════
    # PHASE 4 — Signatures callbacks frameworks
    # ═══════════════════════════════════════════════════════════════════

    def _fix_callback_signatures(self, lines: List[str]) -> List[str]:
        """
        Restaure les signatures attendues par les frameworks (pynput, tkinter).
        Remplace COMPLÈTEMENT les params positionnels pour éviter les doublons.
        """
        CALLBACK_SIGS: Dict[str, List[str]] = {
            'on_press':   ['key'],
            'on_release': ['key'],
            'on_click':   ['x', 'y', 'button', 'pressed'],
            'on_move':    ['x', 'y'],
            'on_scroll':  ['x', 'y', 'dx', 'dy'],
        }
        code_str = '\n'.join(lines)
        func_to_expected: Dict[str, List[str]] = {}
        for cb_kw, expected in CALLBACK_SIGS.items():
            for m in re.finditer(rf'\b{cb_kw}\s*=\s*([A-Za-z_]\w*)', code_str):
                fname = m.group(1)
                if fname not in func_to_expected or len(expected) > len(func_to_expected[fname]):
                    func_to_expected[fname] = expected

        if not func_to_expected:
            return lines

        result = list(lines)
        for i, line in enumerate(result):
            m = re.match(r'^(\s*)def\s+(\w+)\s*\(([^)]*)\)\s*:', line)
            if not m:
                continue
            ind, fname, raw = m.group(1), m.group(2), m.group(3)
            if fname not in func_to_expected:
                continue
            expected = func_to_expected[fname]
            current = [p.strip() for p in raw.split(',') if p.strip()]
            has_self = current and current[0] in ('self', 'cls')
            self_p = [current[0]] if has_self else []
            work = current[1:] if has_self else current[:]
            current_pos = [p for p in work if not p.startswith('*') and '=' not in p]
            if len(current_pos) >= len(expected):
                continue
            result[i] = f"{ind}def {fname}({', '.join(self_p + list(expected))}):"

        return result

    # ═══════════════════════════════════════════════════════════════════
    # PHASE 5 — Artefacts structurels
    # ═══════════════════════════════════════════════════════════════════

    def _fix_double_calls(self, lines: List[str]) -> List[str]:
        """Supprime les appels doubles artefacts: func()() → func()"""
        result = []
        for line in lines:
            result.append(re.sub(r'(\w[\w.]*\([^)]*\))\(\)', r'\1', line))
        return result

    def _fix_tuple_index_calls(self, lines: List[str]) -> List[str]:
        """
        Transforme deux patterns d'artefacts de décompilation en tuple-unpack propre.

        Pattern A (sur une ligne):
            var1, var2 = func(args)[0], func(args)[1]
            → var1, var2 = func(args)

        Pattern B (sur plusieurs lignes consécutives):
            var1 = func(args)[0]
            var2 = func(args)[1]
            → var1, var2 = func(args)

        Conditions requises pour Pattern A/B:
        - Même fonction, mêmes arguments exacts
        - Index consécutifs depuis 0
        - Même indentation (pour B)
        """
        # ── Pattern A: var1, var2 = func(args)[0], func(args)[1], ... ──
        result = []
        for line in lines:
            result.append(self._collapse_multiindex_line(line))
        lines = result

        # ── Pattern B: merge consecutive single-index assignments ──
        return self._merge_sequential_index_assigns(lines)

    @staticmethod
    def _collapse_multiindex_line(line: str) -> str:
        """
        var1, var2, ..., varN = func(args)[0], func(args)[1], ..., func(args)[N-1]
        → var1, var2, ..., varN = func(args)
        """
        s = line.strip()
        ind = line[:len(line) - len(s)]

        # LHS vars = first_call[0], rest...
        m = re.match(
            r'^([\w\s,]+?)\s*=\s*(.+?)\[0\]((?:\s*,\s*.+?\[\d+\])*)\s*$', s
        )
        if not m:
            return line

        lhs_raw, func_call, rest_raw = m.group(1).strip(), m.group(2).strip(), m.group(3).strip()

        # Parse rest: , func_call[1], func_call[2], ...
        if not rest_raw:
            # Single [0] without subsequent parts — could still simplify if var = func()[0]
            # Only simplify if it's a proper tuple unpack with [0]
            return line

        expected_idx = 1
        temp = rest_raw
        while temp:
            chunk = re.match(
                r'^,\s*' + re.escape(func_call) + r'\[(\d+)\](.*)', temp
            )
            if not chunk:
                return line  # different func or non-sequential
            if int(chunk.group(1)) != expected_idx:
                return line
            expected_idx += 1
            temp = chunk.group(2).strip()

        lhs_vars = [v.strip() for v in lhs_raw.split(',')]
        if len(lhs_vars) != expected_idx:
            return line

        return f'{ind}{lhs_raw} = {func_call}'

    @staticmethod
    def _merge_sequential_index_assigns(lines: List[str]) -> List[str]:
        """
        Fusionne des lignes consécutives:
            var0 = func(args)[0]
            var1 = func(args)[1]
            ...
        En:
            var0, var1, ... = func(args)
        """
        # Pattern: indent + simple_var = anything[digit]
        SINGLE_IDX = re.compile(r'^(\s*)([\w.]+)\s*=\s*(.+?)\[(\d+)\]\s*$')
        result = []
        i = 0
        while i < len(lines):
            m0 = SINGLE_IDX.match(lines[i])
            if m0 and int(m0.group(4)) == 0:
                ind, var0, func_call = m0.group(1), m0.group(2), m0.group(3)
                collected = [var0]
                j = i + 1
                while j < len(lines):
                    mj = SINGLE_IDX.match(lines[j])
                    if (mj
                            and mj.group(1) == ind
                            and mj.group(3).strip() == func_call.strip()
                            and int(mj.group(4)) == len(collected)):
                        collected.append(mj.group(2))
                        j += 1
                    else:
                        break
                if len(collected) >= 2:
                    lhs = ', '.join(collected)
                    result.append(f'{ind}{lhs} = {func_call}')
                    i = j
                    continue
            result.append(lines[i])
            i += 1
        return result

    def _fix_missing_params_from_callsites(self, lines: List[str]) -> List[str]:
        """
        Détecte les fonctions dont la définition a moins de paramètres
        que ce que les callsites leur passent, et ajoute les paramètres manquants.

        Exemple:
            def fmt_trigger(key):       ← défini avec 1 param
                ...
            fmt_trigger(key, ttype)     ← appelé avec 2 args

        → devient:
            def fmt_trigger(key, ttype):
                ...

        Les noms des paramètres manquants sont inférés depuis les callsites
        (dernier segment du nom passé en argument, ou _pN en fallback).
        """
        result = list(lines)
        i = 0
        while i < len(result):
            line = result[i]
            m = re.match(
                r'^(\s*)(?:async\s+)?def\s+(\w+)\s*\(([^)]*)\)\s*(?:->.*?)?\s*:', line
            )
            if not m:
                i += 1
                continue

            ind, func_name, raw_sig = m.group(1), m.group(2), m.group(3)

            # Parse current params
            raw_params = [p.strip() for p in raw_sig.split(',') if p.strip()]
            has_self = raw_params and raw_params[0] in ('self', 'cls')
            non_self_params = raw_params[1:] if has_self else raw_params[:]
            # Don't touch *args/**kwargs signatures
            if any(p.startswith('*') for p in non_self_params):
                i += 1
                continue

            n_defined = len(non_self_params)

            # Collect all callsite argument counts and names
            call_sites_args = self._collect_call_sites_with_args(result, func_name)
            if not call_sites_args:
                i += 1
                continue

            max_args = max(len(a) for a in call_sites_args)
            if max_args <= n_defined:
                i += 1
                continue  # no missing params

            # Build the list of existing param names (for dedup)
            existing_names = {
                p.split(':')[0].split('=')[0].strip().lstrip('*')
                for p in raw_params
            }

            # Infer names for the missing positions
            new_params = list(raw_params)
            for pos in range(n_defined, max_args):
                # pos is relative to non-self params
                abs_pos = pos + (1 if has_self else 0)  # position in full param list
                name = self._infer_param_name(pos, call_sites_args, existing_names)
                existing_names.add(name)
                new_params.append(name)

            # Rebuild the def line
            ret_ann = re.search(r'\)\s*(->.+?)\s*:', line)
            ret_part = (' ' + ret_ann.group(1).strip()) if ret_ann else ''
            result[i] = f'{ind}def {func_name}({", ".join(new_params)}){ret_part}:'

            i += 1
        return result

    @staticmethod
    def _collect_call_sites_with_args(
        all_lines: List[str], func_name: str
    ) -> List[List[str]]:
        """
        Retourne la liste des listes d'arguments passés à chaque callsite.
        Ignore les lignes de définition.
        """
        pat = re.compile(
            rf'(?<!\bdef\s)\b{re.escape(func_name)}\s*\(([^)]*)\)'
        )
        results = []
        for line in all_lines:
            if re.match(r'^\s*(?:async\s+)?def\s+', line):
                continue
            if line.strip().startswith('#'):
                continue
            for m in pat.finditer(line):
                args_str = m.group(1).strip()
                if not args_str:
                    results.append([])
                else:
                    parts = [a.strip() for a in args_str.split(',') if a.strip()]
                    # Only count positional (non-keyword) args
                    pos_args = [p for p in parts if '=' not in p and not p.startswith('**')]
                    results.append(pos_args)
        return results

    @staticmethod
    def _infer_param_name(
        pos: int,
        call_sites_args: List[List[str]],
        existing_names: Set[str],
    ) -> str:
        """
        Infère un nom de paramètre raisonnable pour la position `pos`
        en regardant les noms passés aux callsites.

        Stratégie:
        1. Collecter tous les noms d'arguments à cette position
        2. Prendre le dernier segment (après _ ou .) de chaque
        3. Si tous les segments sont identiques et pas déjà utilisés → utiliser ce nom
        4. Sinon fallback sur _pN
        """
        candidates = []
        for args in call_sites_args:
            if pos < len(args):
                arg = args[pos]
                # Dernier segment: 'trigger_type' → 'type', 't_type' → 'type'
                seg = re.split(r'[_.]', arg)[-1]
                if seg and re.match(r'^[a-zA-Z_]\w*$', seg):
                    candidates.append(seg)

        if not candidates:
            return f'_p{pos}'

        # Most common segment
        from collections import Counter
        common = Counter(candidates).most_common(1)[0][0]
        if common and common not in existing_names:
            return common

        # Try full arg name if unique
        full_candidates = []
        for args in call_sites_args:
            if pos < len(args):
                full_candidates.append(args[pos])
        if len(set(full_candidates)) == 1 and full_candidates[0] not in existing_names:
            return full_candidates[0]

        return f'_p{pos}'

    def _fix_none_calls(self, lines: List[str]) -> List[str]:
        result = []
        for line in lines:
            stripped = line.strip()
            ind = self._indent(line)
            if (re.match(r'^None\s*[\(\[]', stripped) or
                    re.match(r'^(\w[\w.]*)\s*=\s*None\s*\(', stripped)):
                result.append(f'{ind}# TODO (decompile): {stripped}')
            else:
                result.append(line)
        return result

    def _fix_type_modulo(self, lines: List[str]) -> List[str]:
        result = []
        for line in lines:
            result.append(re.sub(r'\((\w+)\s*%\s*(\d+)\)', r'(\1 * \2)', line))
        return result

    def _fix_bare_none_statements(self, lines: List[str]) -> List[str]:
        return [l for l in lines if l.strip() != 'None']

    def _fix_try_raise_artifact(self, lines: List[str]) -> List[str]:
        """Supprime try: raise/pass  except: pass — artefacts de décompilation."""
        result = list(lines)
        to_remove: Set[int] = set()
        i = 0
        while i < len(result):
            if result[i].strip() != 'try:':
                i += 1
                continue
            ind = self._indent(result[i])
            body_ind = ind + '    '

            j = i + 1
            try_body = []
            while j < len(result):
                s = result[j].strip()
                li = self._indent(result[j])
                if not s:
                    j += 1
                    continue
                if li == body_ind:
                    try_body.append((j, s))
                    j += 1
                elif len(li) < len(body_ind):
                    break
                else:
                    j += 1

            if any(s not in ('raise', 'pass') for _, s in try_body):
                i += 1
                continue

            except_start = j
            if except_start >= len(result) or not re.match(r'^\s*except\b', result[except_start]):
                i += 1
                continue

            k = except_start + 1
            except_body = []
            while k < len(result):
                s = result[k].strip()
                li = self._indent(result[k])
                if not s:
                    k += 1
                    continue
                if len(li) > len(ind):
                    except_body.append((k, s))
                    k += 1
                else:
                    break

            if any(s != 'pass' for _, s in except_body):
                i += 1
                continue

            to_remove.add(i)
            for idx, _ in try_body:
                to_remove.add(idx)
            to_remove.add(except_start)
            for idx, _ in except_body:
                to_remove.add(idx)
            i = k

        return [l for idx, l in enumerate(result) if idx not in to_remove]

    def _fix_unreachable_after_return(self, lines: List[str]) -> List[str]:
        """Supprime le code mort après return/raise dans le même bloc."""
        result = list(lines)
        to_remove: Set[int] = set()
        i = 0
        while i < len(result):
            stripped = result[i].strip()
            if not stripped or stripped.startswith('#'):
                i += 1
                continue
            ind = self._indent(result[i])
            if re.match(r'^(return|raise)\b', stripped):
                j = i + 1
                while j < len(result):
                    ns = result[j].strip()
                    if not ns:
                        j += 1
                        continue
                    ni = self._indent(result[j])
                    if len(ni) < len(ind):
                        break
                    to_remove.add(j)
                    j += 1
                i = j
                continue
            i += 1
        return [l for idx, l in enumerate(result) if idx not in to_remove]

    # ═══════════════════════════════════════════════════════════════════
    # PHASE 6 — Inject missing `global` declarations
    # ═══════════════════════════════════════════════════════════════════

    # ═══════════════════════════════════════════════════════════════════
    # Cross-function global detection
    # ═══════════════════════════════════════════════════════════════════

    def _analyze_cross_function_globals(self, lines: List[str]) -> Tuple[Set[str], Dict[str, Set[str]]]:
        """
        Algorithme principal de détection des variables globales implicites.

        Une variable V est "cross-function global" si:
          - Elle est ASSIGNÉE (sans global) dans au moins une fonction A
          - Elle est LUE dans au moins une AUTRE fonction B
            (où elle n'est ni param de B, ni assignée localement dans B avant usage)

        Retourne:
          - undeclared_module_vars: vars qui doivent être ajoutées au module-level
          - needs_global_in: {var → set de fonctions qui doivent déclarer global var}
        """
        SKIP = frozenset({'self', 'cls', 'True', 'False', 'None', 'print', 'len',
                          'range', 'int', 'str', 'list', 'dict', 'set', 'tuple',
                          'type', 'isinstance', 'hasattr', 'getattr', 'setattr',
                          'open', 'super', 'property', 'staticmethod', 'classmethod'})

        # ── Collect module-level vars (excluding __main__ block) ──────────
        module_vars: Set[str] = set()
        in_func_or_class = False
        in_main = False
        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                continue
            ind = self._indent(line)
            if re.match(r'^if\s+__name__\s*==\s*[\'"]__main__[\'"]\s*:', stripped) and ind == '':
                in_main = True
                continue
            if in_main:
                if ind == '' and stripped:
                    in_main = False
                else:
                    continue
            if re.match(r'^(?:async\s+)?def\s+|^class\s+', stripped) and ind == '':
                in_func_or_class = True
                continue
            if in_func_or_class:
                if ind == '' and stripped:
                    in_func_or_class = False
                else:
                    continue
            m = re.match(r'^([A-Za-z_]\w*)\s*(?:[+\-*/%|&^]=|=(?!=))', stripped)
            if m and m.group(1) not in SKIP:
                module_vars.add(m.group(1))

        # ── Parse all top-level and class-method functions ─────────────────
        # For each function, collect:
        #   assigned_no_global: vars assigned without global declaration
        #   reads_without_local: vars read before any local assignment

        func_info: Dict[str, Dict] = {}

        i = 0
        while i < len(lines):
            line = lines[i]
            m = re.match(r'^(\s*)(?:async\s+)?def\s+(\w+)\s*\(([^)]*)\)\s*:', line)
            if not m or len(m.group(1)) > 4:
                i += 1
                continue

            fname = m.group(2)
            params: Set[str] = set()
            for p in m.group(3).split(','):
                p = p.strip().lstrip('*').split(':')[0].split('=')[0].strip()
                if p and p not in ('self', 'cls'):
                    params.add(p)

            block_indices = self._get_block(lines, i)
            body_lines = [lines[j] for j in block_indices[1:]]
            body_ind = m.group(1) + '    '
            for bl in body_lines:
                if bl.strip() and not bl.strip().startswith('#'):
                    body_ind = self._indent(bl)
                    break

            # Collect declared globals in this function
            declared_globals: Set[str] = set()
            for bl in body_lines:
                gm = re.match(r'^\s*global\s+(.+)', bl.strip())
                if gm:
                    for v in gm.group(1).split(','):
                        declared_globals.add(v.strip())

            # Collect assigns without global (at direct body level only)
            assigned_no_global: Set[str] = set()
            for bl in body_lines:
                bs = bl.strip()
                if not bs or bs.startswith('#'):
                    continue
                if self._indent(bl) != body_ind:
                    continue
                am = re.match(r'^([A-Za-z_]\w*)\s*(?:[+\-*/%|&^]=|=(?!=))', bs)
                if am:
                    vn = am.group(1)
                    if vn not in declared_globals and vn not in params and vn not in SKIP:
                        assigned_no_global.add(vn)
                # Tuple unpack
                tup = re.match(r'^((?:[A-Za-z_]\w*\s*,\s*)+[A-Za-z_]\w*)\s*=(?!=)', bs)
                if tup:
                    for vn in re.findall(r'[A-Za-z_]\w*', tup.group(1)):
                        if vn not in declared_globals and vn not in params and vn not in SKIP:
                            assigned_no_global.add(vn)

            # Collect reads: all identifiers referenced in expressions,
            # excluding vars assigned before the read AND params AND declared globals
            # IMPORTANT: exclude keyword arguments (name=value in function calls)
            locally_assigned: Set[str] = set()
            reads_without_local: Set[str] = set()

            def _extract_reads(text: str) -> Set[str]:
                """
                Extract identifiers that are READ values (not keyword arg names).
                Excludes: kwarg names like `end=` `flush=` `key=` etc.
                """
                found = set()
                # Remove keyword arguments: word= (not ==)
                cleaned = re.sub(r'\b([A-Za-z_]\w*)\s*=(?!=)', '', text)
                for vr in re.findall(r'\b([A-Za-z_]\w*)\b', cleaned):
                    found.add(vr)
                return found

            for bl in body_lines:
                bs = bl.strip()
                if not bs or bs.startswith('#'):
                    continue
                # Track assignment
                am = re.match(r'^([A-Za-z_]\w*)\s*=(?!=)\s*(.+)', bs)
                if am:
                    vn = am.group(1)
                    rhs = am.group(2)
                    for vr in _extract_reads(rhs):
                        if (vr not in locally_assigned and vr not in params
                                and vr not in declared_globals and vr not in SKIP):
                            reads_without_local.add(vr)
                    locally_assigned.add(vn)
                    continue
                # All identifiers in the line are potential reads
                for vr in _extract_reads(bs):
                    if (vr not in locally_assigned and vr not in params
                            and vr not in declared_globals and vr not in SKIP):
                        reads_without_local.add(vr)

            func_info[fname] = {
                'params': params,
                'declared_globals': declared_globals,
                'assigned_no_global': assigned_no_global,
                'reads_without_local': reads_without_local,
            }
            i = block_indices[-1] + 1

        # ── Cross-function analysis ────────────────────────────────────────
        # For each var: which funcs assign it (without global)?
        var_assigned_in: Dict[str, Set[str]] = {}
        for fname, info in func_info.items():
            for vn in info['assigned_no_global']:
                var_assigned_in.setdefault(vn, set()).add(fname)

        # For each var: which funcs read it without it being local?
        var_read_in: Dict[str, Set[str]] = {}
        for fname, info in func_info.items():
            for vn in info['reads_without_local']:
                var_read_in.setdefault(vn, set()).add(fname)

        # Determine which vars are cross-function globals
        needs_global_in: Dict[str, Set[str]] = {}  # var → funcs needing global decl
        undeclared_module_vars: Set[str] = set()   # vars not in module-level yet

        for vn, assigning_funcs in var_assigned_in.items():
            reading_funcs = var_read_in.get(vn, set())
            # Cross-function: read in a different function than where it's assigned
            cross_readers = reading_funcs - assigning_funcs
            # Also: if it exists in module_vars already, all assigning funcs need global
            in_module = vn in module_vars

            if cross_readers or in_module:
                needs_global_in[vn] = assigning_funcs
                if not in_module:
                    undeclared_module_vars.add(vn)

        return undeclared_module_vars, needs_global_in

    def _inject_missing_globals(self, lines: List[str]) -> List[str]:
        """
        Deux actions complémentaires:

        A) Pour les variables cross-function (assignées dans f1, lues dans f2):
           - Ajouter `global V` dans chaque fonction qui assigne V
           - Si V absent du module-level → ajouter `V = None` avant les defs

        B) Pour les variables déjà au module-level:
           - S'assurer que chaque fonction qui les assigne a `global V`
        """
        undeclared, needs_global = self._analyze_cross_function_globals(lines)

        if not needs_global and not undeclared:
            return lines

        result = list(lines)

        # ── A) Inject missing module-level declarations ────────────────────
        if undeclared:
            # Find insertion point: just before first def/class (after imports + comments)
            insert_at = 0
            for idx, line in enumerate(result):
                stripped = line.strip()
                if re.match(r'^(?:async\s+)?def\s+|^class\s+', stripped) and not line[:1] in (' ', '\t'):
                    insert_at = idx
                    break

            injections = []
            for vn in sorted(undeclared):
                injections.append(f'{vn} = None')
            # Insert as a block with blank line separator
            result = result[:insert_at] + injections + [''] + result[insert_at:]

        # ── B) Inject `global V` inside functions that assign cross-func vars ─
        i = 0
        while i < len(result):
            line = result[i]
            m = re.match(r'^(\s*)(?:async\s+)?def\s+(\w+)\s*\(([^)]*)\)\s*:', line)
            if not m or len(m.group(1)) > 4:
                i += 1
                continue

            func_ind = m.group(1)
            fname = m.group(2)
            param_names = set(self._get_func_params(line))

            block_indices = self._get_block(result, i)
            body_indices = block_indices[1:]

            # Find body indent + first real line
            first_body_idx = None
            body_ind = func_ind + '    '
            for j in body_indices:
                s = result[j].strip()
                if s and not s.startswith('#'):
                    first_body_idx = j
                    body_ind = self._indent(result[j])
                    break

            if first_body_idx is None:
                i += 1
                continue

            # Existing global declarations
            existing_globals: Set[str] = set()
            for j in body_indices:
                gm = re.match(r'^\s*global\s+(.+)', result[j].strip())
                if gm:
                    for v in gm.group(1).split(','):
                        existing_globals.add(v.strip())

            # Vars this function needs to globalise
            new_globals: Set[str] = set()
            for vn, funcs_needing in needs_global.items():
                if fname in funcs_needing and vn not in existing_globals and vn not in param_names:
                    new_globals.add(vn)

            if new_globals:
                # Insert after existing global lines (or at first body line)
                insert_after = first_body_idx
                for j in body_indices:
                    s = result[j].strip()
                    if re.match(r'^global\s+', s):
                        insert_after = j + 1  # append to existing global block
                        break
                    if s and not s.startswith('#'):
                        break  # no global block → insert before first real line

                global_line = f'{body_ind}global {", ".join(sorted(new_globals))}'
                result.insert(insert_after, global_line)
                i += 1  # account for inserted line

            i += 1

        return result

    # ═══════════════════════════════════════════════════════════════════
    # PHASE 7 — Import aliases
    # ═══════════════════════════════════════════════════════════════════

    def _fix_import_aliases(self, lines: List[str]) -> List[str]:
        """
        KeyboardListener = Listener → from pynput.keyboard import Listener as KeyboardListener
        Gère les ambiguïtés (même nom importé de plusieurs modules) par heuristique.
        """
        all_imports: List[Tuple[int, str, str]] = []
        for i, line in enumerate(lines):
            m = re.match(r'^from\s+([\w.]+)\s+import\s+(.+)', line.strip())
            if m:
                module = m.group(1)
                for part in m.group(2).split(','):
                    part = part.strip()
                    if ' as ' not in part and part:
                        all_imports.append((i, module, part))

        if not all_imports:
            return lines

        alias_assignments: List[Tuple[int, str, str]] = []
        for i, line in enumerate(lines):
            if line and line[0] in (' ', '\t'):
                continue
            m = re.match(r'^([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)\s*$', line.strip())
            if m:
                alias, imported = m.group(1), m.group(2)
                if alias != imported and any(nm == imported for _, _, nm in all_imports):
                    alias_assignments.append((i, alias, imported))

        if not alias_assignments:
            return lines

        result = list(lines)
        lines_to_remove: Set[int] = set()

        for assign_idx, alias, imported_name in alias_assignments:
            candidates = [(idx, mod) for (idx, mod, nm) in all_imports if nm == imported_name]
            if len(candidates) == 1:
                target_idx = candidates[0][0]
            else:
                alias_lower = alias.lower()
                scored = sorted(
                    [(sum(1 for p in mod.lower().split('.') if p in alias_lower), idx)
                     for (idx, mod) in candidates],
                    reverse=True
                )
                target_idx = scored[0][1]

            m = re.match(r'^from\s+([\w.]+)\s+import\s+(.+)', result[target_idx].strip())
            if not m:
                continue
            mod = m.group(1)
            names = [n.strip() for n in m.group(2).split(',')]
            new_names = [f'{n} as {alias}' if n == imported_name else n for n in names]
            result[target_idx] = f'from {mod} import {", ".join(new_names)}'
            lines_to_remove.add(assign_idx)

        return [l for i, l in enumerate(result) if i not in lines_to_remove]

    # ═══════════════════════════════════════════════════════════════════
    # PHASE 8 — if __name__ == '__main__' wrapper
    # ═══════════════════════════════════════════════════════════════════

    def _wrap_main_guard(self, lines: List[str]) -> List[str]:
        """
        Détecte le code d'exécution module-level final et le place dans
        if __name__ == '__main__':
        en séparant les déclarations (module-level) de l'exécution.
        """
        code_str = '\n'.join(lines)
        if '__name__' in code_str:
            return lines

        last_def_end = -1
        for i, line in enumerate(lines):
            stripped = line.strip()
            if (re.match(r'^(?:async\s+)?def\s+|^class\s+', stripped)
                    and not line[:1] in (' ', '\t')):
                last_def_end = max(self._get_block(lines, i))

        if last_def_end == -1:
            return lines

        def is_exec(s: str) -> bool:
            if not s or s.startswith('#') or re.match(r'^(import |from )', s):
                return False
            m = re.match(r'^([A-Za-z_]\w*)\s*=\s*(.+)', s)
            if m:
                rhs = m.group(2).strip()
                if re.match(r'^(-?\d[\d._xX]*|True|False|None|\'[^\']*\'|"[^"]*")$', rhs):
                    return False
                if re.match(r'^[\[{(]', rhs) and not re.search(r'\b\w+\s*\(', rhs):
                    return False
                if re.search(r'threading\.Thread\s*\(', rhs):
                    return True
                CTORS = [r'^ctypes\.', r'threading\.Event\s*\(', r'threading\.Lock\s*\(',
                         r'\.WinDLL\s*\(', r'\.CDLL\s*\(']
                if any(re.search(p, rhs) for p in CTORS):
                    return False
                if re.search(r'\b\w+\s*\(', rhs):
                    return True
                return False
            return True

        exec_start = -1
        for i in range(last_def_end + 1, len(lines)):
            s = lines[i].strip()
            if lines[i][:1] in (' ', '\t'):
                continue
            if is_exec(s):
                exec_start = i
                break

        if exec_start == -1:
            return lines

        exec_str = '\n'.join(lines[exec_start:])
        MARKERS = [r'\bsetup\s*\(', r'\bmain\s*\(', r'threading\.Thread\b',
                   r'\.start\s*\(\s*\)', r'\.join\s*\(\s*\)', r'\.mainloop\s*\(']
        if sum(1 for p in MARKERS if re.search(p, exec_str)) < 2:
            return lines

        result = list(lines[:exec_start])
        result.append('')
        result.append("if __name__ == '__main__':")
        for line in lines[exec_start:]:
            result.append('    ' + line if line.strip() else '')
        return result

    # ═══════════════════════════════════════════════════════════════════
    # PHASE 9 — Structures ctypes manquantes
    # ═══════════════════════════════════════════════════════════════════

    def _add_missing_ctypes_structures(self, lines: List[str]) -> List[str]:
        code_str = '\n'.join(lines)
        additions = []

        if 'MOUSEINPUT' in code_str and 'class MOUSEINPUT' not in code_str:
            additions.append(
                "\nclass MOUSEINPUT(ctypes.Structure):\n"
                "    _fields_ = [\n"
                "        ('dx',          ctypes.c_long),\n"
                "        ('dy',          ctypes.c_long),\n"
                "        ('mouseData',   ctypes.c_ulong),\n"
                "        ('dwFlags',     ctypes.c_ulong),\n"
                "        ('time',        ctypes.c_ulong),\n"
                "        ('dwExtraInfo', ctypes.POINTER(ctypes.c_ulong)),\n"
                "    ]\n"
            )

        if 'class INPUT' not in code_str and (
            re.search(r'\bINPUT\s*\(', code_str) or re.search(r'\bself\.INPUT\b', code_str)
        ):
            additions.append(
                "\nclass _INPUT_UNION(ctypes.Union):\n"
                "    _fields_ = [('mi', MOUSEINPUT)]\n"
                "\nclass INPUT(ctypes.Structure):\n"
                "    _fields_ = [\n"
                "        ('type',   ctypes.c_ulong),\n"
                "        ('_input', _INPUT_UNION),\n"
                "    ]\n"
                "\nINPUT_MOUSE          = 0\n"
                "MOUSEEVENTF_LEFTDOWN = 0x0002\n"
                "MOUSEEVENTF_LEFTUP   = 0x0004\n"
            )

        if not additions:
            return lines

        insert_at = 0
        for idx, line in enumerate(lines):
            stripped = line.strip()
            if stripped and not stripped.startswith('#') and not re.match(r'^(import |from )', stripped):
                insert_at = idx
                break

        return lines[:insert_at] + ''.join(additions).splitlines() + lines[insert_at:]

    # ═══════════════════════════════════════════════════════════════════
    # LEGACY compatibility stubs
    # ═══════════════════════════════════════════════════════════════════

    def _fix_init_phantom_params(self, lines: List[str]) -> List[str]:
        return self._fix_all_phantom_params(lines)

    def _fix_method_phantom_params(self, lines: List[str]) -> List[str]:
        return lines

    def _remove_injected_ctypes_params(self, lines: List[str]) -> List[str]:
        return lines

def _is_python_source(source: str) -> bool:
    """
    Retourne True si `source` est déjà du code Python valide (ou presque),
    plutôt qu'un dump de bytecode `dis`.
    Critères :
      - Contient des instructions dis typiques (LOAD_FAST, STORE_NAME, etc.) → False
      - Parseable par ast.parse → True
      - Sinon, heuristique sur la présence de constructions Python de haut-niveau
    """
    # Un dump dis contient obligatoirement ces marqueurs
    dis_markers = ('LOAD_FAST', 'LOAD_CONST', 'STORE_NAME', 'STORE_FAST',
                   'CALL_FUNCTION', 'RETURN_VALUE', 'Disassembly of')
    first_5k = source[:5000]
    dis_hits = sum(1 for m in dis_markers if m in first_5k)
    if dis_hits >= 3:
        return False  # c'est un dump dis

    # Essayer de parser comme Python
    try:
        import ast as _ast
        _ast.parse(source)
        return True
    except SyntaxError:
        pass

    # Heuristique : si le fichier contient des def/class/import → probablement Python
    python_hits = sum(1 for pat in (r'^\s*def ', r'^\s*class ', r'^import ', r'^from ')
                      if re.search(pat, source, re.MULTILINE))
    return python_hits >= 2


def translate_file(input_path: str, output_path: str, verbose: bool = False) -> str:

    if input_path.lower().endswith('.pyc'):
        if verbose:
            print(f'[INFO] Lecture: {input_path}', file=sys.stderr)
        try:
            source = _pyc_to_dis_string(input_path, verbose)
        except Exception as e:
            print(f'[ERROR] Impossible de lire le .pyc: {e}', file=sys.stderr)
            sys.exit(1)

        if verbose:
            dump_path = output_path + '.dis_dump.txt'
            try:
                with open(dump_path, 'w', encoding='utf-8') as f:
                    f.write(source)
                print(f'[INFO] Dump dis → {dump_path}', file=sys.stderr)
            except Exception:
                pass
    else:
        with open(input_path, 'r', encoding='utf-8', errors='replace') as f:
            source = f.read()

    # ── Détection: est-ce déjà du code source Python (pas un dump dis) ? ──
    is_python_source = _is_python_source(source)
    if is_python_source:
        if verbose:
            print(f'[INFO] Fichier reconnu comme code source Python — passage direct au SemanticFixer', file=sys.stderr)
        code = source
    else:
        reconstructor = HighLevelReconstructor(source, verbose=verbose)
        code = reconstructor.reconstruct()

        pp = PostProcessorV5(code)
        code = pp.process()

        ok, err = validate_syntax(code)
        if not ok:
            if verbose:
                print(f'[WARN] Syntaxe 1ère passe: {err}', file=sys.stderr)
            pp2 = PostProcessorV5(code)
            lines = pp2._iterative_syntax_fix(code.splitlines())
            code = '\n'.join(lines)
            ok2, err2 = validate_syntax(code)
            if verbose:
                status = '✓ corrigée' if ok2 else f'résiduelle: {err2}'
                print(f'[INFO] Syntaxe 2ème passe: {status}', file=sys.stderr)

    # ── Correcteur sémantique ──────────────────────────────────────
    sf = SemanticFixer(code)
    code = sf.fix()

    # Re-validate after semantic fix
    ok3, err3 = validate_syntax(code)
    if not ok3 and verbose:
        print(f'[INFO] Syntaxe après SemanticFixer: {err3}', file=sys.stderr)

    # Réordonner : classes/fonctions avant le code module-level
    # pour éviter les NameError du type "name 'X' is not defined"
    # Ne s'applique qu'aux fichiers reconstruits depuis bytecode,
    # pas aux sources Python déjà correctement ordonnés.
    if not is_python_source:
        code = reorder_definitions(code)

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(code)

    return code


class BytecodeQualityAnalyzer:

    QUALITY_THRESHOLDS: Dict[str, float] = {
        'excellent': 0.95,
        'bon':       0.85,
        'acceptable':0.70,
        'partiel':   0.50,
        'mauvais':   0.0,
    }

    PATTERN_TODO        = re.compile(r'#\s*TODO\s*\(decompile\):')
    PATTERN_MISSING     = re.compile(r'\b__MISSING__\b')
    PATTERN_UNKNOWN_OP  = re.compile(r'\bOP\d+\b')
    PATTERN_INTRINSIC   = re.compile(r'\b__intrinsic\d*_\d+__\b')
    PATTERN_FUNC_REF    = re.compile(r'<func:[^>]+>')
    PATTERN_CODE_OBJ    = re.compile(r'<code object')
    PATTERN_NULL_LEAK   = re.compile(r'\b__NULL__\b')
    PATTERN_FOR_ITER    = re.compile(r'\b__for_iter__\b')
    PATTERN_COMMON_N    = re.compile(r'\b__COMMON_\d+__\b')

    def __init__(self, source_code: str):
        self.code   = source_code
        self.lines  = source_code.splitlines()
        self._stats: Dict[str, Any] = {}

    def analyze(self) -> Dict[str, Any]:
        self._stats = {
            'total_lines':        len(self.lines),
            'non_empty_lines':    self._count_non_empty(),
            'todo_count':         self._count_pattern(self.PATTERN_TODO),
            'missing_count':      self._count_pattern(self.PATTERN_MISSING),
            'unknown_op_count':   self._count_pattern(self.PATTERN_UNKNOWN_OP),
            'intrinsic_count':    self._count_pattern(self.PATTERN_INTRINSIC),
            'func_ref_count':     self._count_pattern(self.PATTERN_FUNC_REF),
            'code_obj_count':     self._count_pattern(self.PATTERN_CODE_OBJ),
            'null_leak_count':    self._count_pattern(self.PATTERN_NULL_LEAK),
            'for_iter_count':     self._count_pattern(self.PATTERN_FOR_ITER),
            'common_n_count':     self._count_pattern(self.PATTERN_COMMON_N),
            'syntax_valid':       False,
            'syntax_error':       '',
            'def_count':          self._count_keyword('def '),
            'class_count':        self._count_keyword('class '),
            'import_count':       self._count_keyword('import '),
            'ctypes_count':       self._count_ctypes_usage(),
            'quality_score':      0.0,
            'quality_label':      'mauvais',
            'artifact_lines':     [],
        }
        ok, err = validate_syntax(self.code)
        self._stats['syntax_valid'] = ok
        self._stats['syntax_error'] = err
        self._stats['quality_score'] = self._compute_score()
        self._stats['quality_label'] = self._compute_label()
        self._stats['artifact_lines'] = self._find_artifact_lines()
        return self._stats

    def _count_non_empty(self) -> int:
        return sum(1 for ln in self.lines if ln.strip())

    def _count_pattern(self, pat: re.Pattern) -> int:
        return sum(1 for ln in self.lines if pat.search(ln))

    def _count_keyword(self, kw: str) -> int:
        return sum(1 for ln in self.lines if kw in ln)

    def _count_ctypes_usage(self) -> int:
        return sum(1 for ln in self.lines if 'ctypes' in ln or any(
            ct in ln for ct in ('Structure', 'Union', 'POINTER', 'c_int', 'c_long', 'CFUNCTYPE')
        ))

    def _compute_score(self) -> float:
        total = max(self._stats['non_empty_lines'], 1)
        bad_lines = (
            self._stats['todo_count']
            + self._stats['missing_count']
            + self._stats['unknown_op_count']
            + self._stats['intrinsic_count']
            + self._stats['func_ref_count']
            + self._stats['code_obj_count']
            + self._stats['null_leak_count']
            + self._stats['for_iter_count']
            + self._stats['common_n_count']
        )
        penalty = min(bad_lines / total, 1.0)
        score   = 1.0 - penalty
        if not self._stats['syntax_valid']:
            score *= 0.8
        return round(max(score, 0.0), 4)

    def _compute_label(self) -> str:
        score = self._stats['quality_score']
        for label, threshold in self.QUALITY_THRESHOLDS.items():
            if score >= threshold:
                return label
        return 'mauvais'

    def _find_artifact_lines(self) -> List[Tuple[int, str, str]]:
        artifacts = []
        patterns = [
            (self.PATTERN_TODO,       'TODO non décompilé'),
            (self.PATTERN_MISSING,    'valeur __MISSING__'),
            (self.PATTERN_UNKNOWN_OP, 'opcode inconnu OP#'),
            (self.PATTERN_INTRINSIC,  'intrinsèque non résolu'),
            (self.PATTERN_FUNC_REF,   'référence de fonction brute'),
            (self.PATTERN_CODE_OBJ,   'objet code non expansé'),
            (self.PATTERN_NULL_LEAK,  'NULL sur la pile'),
            (self.PATTERN_FOR_ITER,   '__for_iter__ non résolu'),
        ]
        for lineno, ln in enumerate(self.lines, start=1):
            for pat, reason in patterns:
                if pat.search(ln):
                    artifacts.append((lineno, reason, ln.strip()))
                    break
        return artifacts

    def report(self, verbose: bool = False) -> str:
        if not self._stats:
            self.analyze()
        s = self._stats
        lines_out = [
            f'Qualité de décompilation: {s["quality_label"].upper()} '
            f'({s["quality_score"]*100:.1f}%)',
            f'  Lignes totales        : {s["total_lines"]}',
            f'  Lignes non vides      : {s["non_empty_lines"]}',
            f'  Syntaxe valide        : {"Oui" if s["syntax_valid"] else "Non — " + s["syntax_error"]}',
            f'  Définitions (def)     : {s["def_count"]}',
            f'  Classes               : {s["class_count"]}',
            f'  Imports               : {s["import_count"]}',
            f'  Usages ctypes         : {s["ctypes_count"]}',
            f'  Artefacts résiduels   : {len(s["artifact_lines"])}',
        ]
        if verbose and s['artifact_lines']:
            lines_out.append('  Détail des artefacts:')
            for lineno, reason, text in s['artifact_lines'][:30]:
                lines_out.append(f'    L{lineno:5d} [{reason}]: {text[:80]}')
        return '\n'.join(lines_out)

    def suggest_fixes(self) -> List[str]:
        if not self._stats:
            self.analyze()
        suggestions = []
        s = self._stats
        if s['todo_count'] > 0:
            suggestions.append(
                f'{s["todo_count"]} ligne(s) non décompilées — vérifiez la version Python du .pyc '
                f'et relancez avec la version correcte.'
            )
        if s['unknown_op_count'] > 0:
            suggestions.append(
                f'{s["unknown_op_count"]} opcode(s) inconnus (OP#) — '
                f'mettez à jour la table des opcodes pour la version Python cible.'
            )
        if s['null_leak_count'] > 0:
            suggestions.append(
                f'{s["null_leak_count"]} fuite(s) __NULL__ — '
                f'le nettoyage de pile est incomplet dans le traducteur.'
            )
        if s['for_iter_count'] > 0:
            suggestions.append(
                f'{s["for_iter_count"]} boucle(s) for non reconstituées — '
                f'__for_iter__ n\'a pas été résolu en variable de boucle.'
            )
        if s['func_ref_count'] > 0:
            suggestions.append(
                f'{s["func_ref_count"]} référence(s) de fonctions brutes (<func:...>) — '
                f'des blocs de bytecode ne sont pas liés à leurs parents.'
            )
        if not s['syntax_valid']:
            suggestions.append(
                f'Erreur de syntaxe résiduelle: {s["syntax_error"]}. '
                f'Activez --verbose pour localiser le problème.'
            )
        if not suggestions:
            suggestions.append('Aucun problème majeur détecté. Le code reconstitué semble propre.')
        return suggestions


class PythonVersionCompatibilityMatrix:

    SUPPORTED_VERSIONS: List[Tuple[int, int]] = [
        (3, 10), (3, 11), (3, 12), (3, 13), (3, 14),
    ]

    VERSION_FEATURES: Dict[Tuple[int, int], Dict[str, Any]] = {
        (3, 10): {
            'match_statement':      True,
            'parenthesized_with':   False,
            'exception_groups':     False,
            'variadic_generics':    False,
            'type_aliases':         False,
            'free_threaded':        False,
            'f_string_nesting':     False,
            'pattern_matching':     True,
            'walrus_operator':      True,
            'positional_only_args': True,
            'opcode_PUSH_NULL':     False,
            'opcode_RESUME':        False,
            'opcode_BINARY_OP':     False,
            'opcode_COPY':          False,
            'opcode_CALL':          False,
            'opcode_LOAD_FAST_BORROW': False,
            'cache_entries':        False,
            'exception_table':      False,
            'co_qualname':          False,
            'co_linetable':         False,
            'magic_range':          list(range(3430, 3436)),
        },
        (3, 11): {
            'match_statement':      True,
            'parenthesized_with':   True,
            'exception_groups':     False,
            'variadic_generics':    False,
            'type_aliases':         False,
            'free_threaded':        False,
            'f_string_nesting':     False,
            'pattern_matching':     True,
            'walrus_operator':      True,
            'positional_only_args': True,
            'opcode_PUSH_NULL':     True,
            'opcode_RESUME':        True,
            'opcode_BINARY_OP':     True,
            'opcode_COPY':          True,
            'opcode_CALL':          True,
            'opcode_LOAD_FAST_BORROW': False,
            'cache_entries':        True,
            'exception_table':      True,
            'co_qualname':          True,
            'co_linetable':         True,
            'magic_range':          list(range(3495, 3512)),
        },
        (3, 12): {
            'match_statement':      True,
            'parenthesized_with':   True,
            'exception_groups':     True,
            'variadic_generics':    True,
            'type_aliases':         True,
            'free_threaded':        False,
            'f_string_nesting':     True,
            'pattern_matching':     True,
            'walrus_operator':      True,
            'positional_only_args': True,
            'opcode_PUSH_NULL':     True,
            'opcode_RESUME':        True,
            'opcode_BINARY_OP':     True,
            'opcode_COPY':          True,
            'opcode_CALL':          True,
            'opcode_LOAD_FAST_BORROW': False,
            'cache_entries':        True,
            'exception_table':      True,
            'co_qualname':          True,
            'co_linetable':         True,
            'magic_range':          list(range(3531, 3540)),
        },
        (3, 13): {
            'match_statement':      True,
            'parenthesized_with':   True,
            'exception_groups':     True,
            'variadic_generics':    True,
            'type_aliases':         True,
            'free_threaded':        True,
            'f_string_nesting':     True,
            'pattern_matching':     True,
            'walrus_operator':      True,
            'positional_only_args': True,
            'opcode_PUSH_NULL':     True,
            'opcode_RESUME':        True,
            'opcode_BINARY_OP':     True,
            'opcode_COPY':          True,
            'opcode_CALL':          True,
            'opcode_LOAD_FAST_BORROW': False,
            'cache_entries':        True,
            'exception_table':      True,
            'co_qualname':          True,
            'co_linetable':         True,
            'magic_range':          list(range(3570, 3577)),
        },
        (3, 14): {
            'match_statement':      True,
            'parenthesized_with':   True,
            'exception_groups':     True,
            'variadic_generics':    True,
            'type_aliases':         True,
            'free_threaded':        True,
            'f_string_nesting':     True,
            'pattern_matching':     True,
            'walrus_operator':      True,
            'positional_only_args': True,
            'opcode_PUSH_NULL':     True,
            'opcode_RESUME':        True,
            'opcode_BINARY_OP':     True,
            'opcode_COPY':          True,
            'opcode_CALL':          True,
            'opcode_LOAD_FAST_BORROW': True,
            'cache_entries':        True,
            'exception_table':      True,
            'co_qualname':          True,
            'co_linetable':         True,
            'magic_range':          list(range(3600, 3606)),
        },
    }

    @classmethod
    def get_features(cls, version: Tuple[int, int]) -> Dict[str, Any]:
        return cls.VERSION_FEATURES.get(version, {})

    @classmethod
    def supports_feature(cls, version: Tuple[int, int], feature: str) -> bool:
        features = cls.get_features(version)
        return bool(features.get(feature, False))

    @classmethod
    def minimum_version_for_feature(cls, feature: str) -> Optional[Tuple[int, int]]:
        for ver in cls.SUPPORTED_VERSIONS:
            if cls.supports_feature(ver, feature):
                return ver
        return None

    @classmethod
    def features_diff(cls, v1: Tuple[int, int], v2: Tuple[int, int]) -> Dict[str, Tuple[bool, bool]]:
        f1 = cls.get_features(v1)
        f2 = cls.get_features(v2)
        all_keys = set(f1) | set(f2)
        diff = {}
        for k in sorted(all_keys):
            val1 = bool(f1.get(k, False))
            val2 = bool(f2.get(k, False))
            if val1 != val2:
                diff[k] = (val1, val2)
        return diff

    @classmethod
    def get_magic_versions_table(cls) -> Dict[int, Tuple[int, int]]:
        table = {}
        for ver, features in cls.VERSION_FEATURES.items():
            for magic in features.get('magic_range', []):
                table[magic] = ver
        return table

    @classmethod
    def detect_version_from_bytecode_hints(cls, bytecode_text: str) -> Optional[Tuple[int, int]]:
        hints: Dict[Tuple[int, int], int] = {}
        for ver in cls.SUPPORTED_VERSIONS:
            hints[ver] = 0
        feature_hints = [
            ('LOAD_FAST_BORROW', (3, 14), 5),
            ('CALL_KW',          (3, 14), 3),
            ('LOAD_SPECIAL',     (3, 14), 3),
            ('STORE_FAST_STORE_FAST', (3, 14), 3),
            ('LOAD_LOCALS',      (3, 13), 2),
            ('LOAD_ZERO',        (3, 12), 2),
            ('LOAD_SMALL_INT',   (3, 12), 2),
            ('COPY_FREE_VARS',   (3, 11), 2),
            ('PUSH_EXC_INFO',    (3, 11), 2),
            ('CHECK_EXC_MATCH',  (3, 11), 2),
            ('RESUME',           (3, 11), 1),
            ('PUSH_NULL',        (3, 11), 1),
        ]
        for opcode, min_ver, weight in feature_hints:
            if opcode in bytecode_text:
                for ver in cls.SUPPORTED_VERSIONS:
                    if ver >= min_ver:
                        hints[ver] += weight
        if not any(hints.values()):
            return None
        return max(hints, key=lambda v: hints[v])

    @classmethod
    def compatibility_report(cls, version: Tuple[int, int]) -> str:
        features = cls.get_features(version)
        if not features:
            return f'Version {version[0]}.{version[1]} non reconnue.'
        lines = [f'Compatibilité Python {version[0]}.{version[1]}:']
        for feature, value in sorted(features.items()):
            if feature == 'magic_range':
                continue
            icon = 'OUI' if value else 'NON'
            lines.append(f'  {feature:<35}: {icon}')
        return '\n'.join(lines)


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


class ImportInferenceEngine:

    CTYPES_USAGE_PATTERNS: List[Tuple[re.Pattern, str]] = [
        (re.compile(r'\bctypes\b'),                    'import ctypes'),
        (re.compile(r'\bctypes\.wintypes\b'),          'import ctypes.wintypes'),
        (re.compile(r'\bwindll\b'),                    'import ctypes'),
        (re.compile(r'\bCFUNCTYPE\b'),                 'import ctypes'),
        (re.compile(r'\bWINFUNCTYPE\b'),               'import ctypes'),
        (re.compile(r'\bPOINTER\b'),                   'import ctypes'),
        (re.compile(r'\bStructure\b'),                 'import ctypes'),
        (re.compile(r'\bUnion\b'),                     'import ctypes'),
    ]

    MODULE_SYMBOL_MAP: Dict[str, str] = {
        'threading':      'import threading',
        'Thread':         'import threading',
        'Lock':           'import threading',
        'Event':          'import threading',
        'Semaphore':      'import threading',
        'RLock':          'import threading',
        'Condition':      'import threading',
        'Timer':          'import threading',
        'time':           'import time',
        'sleep':          'import time',
        'monotonic':      'import time',
        'perf_counter':   'import time',
        'struct_time':    'import time',
        'os':             'import os',
        'path':           'import os',
        'environ':        'import os',
        'getenv':         'import os',
        'getcwd':         'import os',
        'listdir':        'import os',
        'sys':            'import sys',
        'argv':           'import sys',
        'exit':           'import sys',
        'platform':       'import sys',
        'version_info':   'import sys',
        'json':           'import json',
        'loads':          'import json',
        'dumps':          'import json',
        're':             'import re',
        'compile':        'import re',
        'match':          'import re',
        'search':         'import re',
        'sub':            'import re',
        'findall':        'import re',
        'io':             'import io',
        'BytesIO':        'from io import BytesIO',
        'StringIO':       'from io import StringIO',
        'base64':         'import base64',
        'b64encode':      'from base64 import b64encode',
        'b64decode':      'from base64 import b64decode',
        'struct':         'import struct',
        'pack':           'import struct',
        'unpack':         'import struct',
        'hashlib':        'import hashlib',
        'md5':            'import hashlib',
        'sha256':         'import hashlib',
        'sha1':           'import hashlib',
        'socket':         'import socket',
        'gethostname':    'import socket',
        'gethostbyname':  'import socket',
        'subprocess':     'import subprocess',
        'Popen':          'import subprocess',
        'run':            'import subprocess',
        'check_output':   'import subprocess',
        'pathlib':        'from pathlib import Path',
        'Path':           'from pathlib import Path',
        'functools':      'import functools',
        'lru_cache':      'from functools import lru_cache',
        'partial':        'from functools import partial',
        'wraps':          'from functools import wraps',
        'itertools':      'import itertools',
        'chain':          'from itertools import chain',
        'islice':         'from itertools import islice',
        'product':        'from itertools import product',
        'collections':    'import collections',
        'defaultdict':    'from collections import defaultdict',
        'OrderedDict':    'from collections import OrderedDict',
        'Counter':        'from collections import Counter',
        'deque':          'from collections import deque',
        'namedtuple':     'from collections import namedtuple',
        'dataclass':      'from dataclasses import dataclass',
        'field':          'from dataclasses import field',
        'asdict':         'from dataclasses import asdict',
        'Enum':           'from enum import Enum',
        'IntEnum':        'from enum import IntEnum',
        'auto':           'from enum import auto',
        'ABC':            'from abc import ABC',
        'abstractmethod': 'from abc import abstractmethod',
        'Optional':       'from typing import Optional',
        'List':           'from typing import List',
        'Dict':           'from typing import Dict',
        'Tuple':          'from typing import Tuple',
        'Set':            'from typing import Set',
        'Any':            'from typing import Any',
        'Union':          'from typing import Union',
        'Callable':       'from typing import Callable',
        'Generator':      'from typing import Generator',
        'Iterator':       'from typing import Iterator',
        'ClassVar':       'from typing import ClassVar',
        'TypeVar':        'from typing import TypeVar',
        'Generic':        'from typing import Generic',
        'overload':       'from typing import overload',
        'cast':           'from typing import cast',
        'TYPE_CHECKING':  'from typing import TYPE_CHECKING',
        'contextmanager': 'from contextlib import contextmanager',
        'suppress':       'from contextlib import suppress',
        'datetime':       'from datetime import datetime',
        'timedelta':      'from datetime import timedelta',
        'date':           'from datetime import date',
        'QApplication':   'from PyQt5.QtWidgets import QApplication',
        'QMainWindow':    'from PyQt5.QtWidgets import QMainWindow',
        'QWidget':        'from PyQt5.QtWidgets import QWidget',
        'QDialog':        'from PyQt5.QtWidgets import QDialog',
        'QThread':        'from PyQt5.QtCore import QThread',
        'pyqtSignal':     'from PyQt5.QtCore import pyqtSignal',
        'QTimer':         'from PyQt5.QtCore import QTimer',
        'keyboard':       'import keyboard',
        'pynput':         'from pynput import keyboard as pynput_keyboard',
        'win32api':       'import win32api',
        'win32con':       'import win32con',
        'win32gui':       'import win32gui',
        'win32process':   'import win32process',
        'winerror':       'import winerror',
        'winreg':         'import winreg',
        'msvcrt':         'import msvcrt',
        'warnings':       'import warnings',
        'logging':        'import logging',
        'getLogger':      'import logging',
        'traceback':      'import traceback',
        'gc':             'import gc',
        'weakref':        'import weakref',
        'copy':           'import copy',
        'deepcopy':       'from copy import deepcopy',
        'math':           'import math',
        'sqrt':           'from math import sqrt',
        'ceil':           'from math import ceil',
        'floor':          'from math import floor',
        'pi':             'from math import pi',
        'inf':            'from math import inf',
        'random':         'import random',
        'randint':        'from random import randint',
        'choice':         'from random import choice',
        'shuffle':        'from random import shuffle',
        'uniform':        'from random import uniform',
        'pprint':         'import pprint',
        'pickle':         'import pickle',
        'shelve':         'import shelve',
        'sqlite3':        'import sqlite3',
        'csv':            'import csv',
        'xml':            'import xml.etree.ElementTree as ET',
        'configparser':   'import configparser',
        'argparse':       'import argparse',
        'shutil':         'import shutil',
        'glob':           'import glob',
        'fnmatch':        'import fnmatch',
        'tempfile':       'import tempfile',
        'zipfile':        'import zipfile',
        'tarfile':        'import tarfile',
        'gzip':           'import gzip',
        'bz2':            'import bz2',
        'lzma':           'import lzma',
        'zlib':           'import zlib',
        'hmac':           'import hmac',
        'secrets':        'import secrets',
        'uuid':           'import uuid',
        'urllib':         'import urllib.request',
        'http':           'import http.client',
        'email':          'import email',
        'smtplib':        'import smtplib',
        'ftplib':         'import ftplib',
        'telnetlib':      'import telnetlib',
        'xmlrpc':         'import xmlrpc.client',
        'queue':          'import queue',
        'asyncio':        'import asyncio',
        'concurrent':     'import concurrent.futures',
        'multiprocessing':'import multiprocessing',
        'signal':         'import signal',
        'ctypes':         'import ctypes',
        'atexit':         'import atexit',
        'platform':       'import platform',
        'sysconfig':      'import sysconfig',
        'site':           'import site',
        'importlib':      'import importlib',
        'pkgutil':        'import pkgutil',
        'inspect':        'import inspect',
        'dis':            'import dis',
        'ast':            'import ast',
        'token':          'import token',
        'tokenize':       'import tokenize',
        'py_compile':     'import py_compile',
        'compileall':     'import compileall',
        'marshal':        'import marshal',
        'builtins':       'import builtins',
        'keyword':        'import keyword',
        'textwrap':       'import textwrap',
        'string':         'import string',
        'unicodedata':    'import unicodedata',
        'codecs':         'import codecs',
        'locale':         'import locale',
        'gettext':        'import gettext',
        'difflib':        'import difflib',
        'fileinput':      'import fileinput',
        'linecache':      'import linecache',
        'rlcompleter':    'import rlcompleter',
    }

    def __init__(self, code: str):
        self.code  = code
        self.lines = code.splitlines()

    def infer_missing_imports(self) -> List[str]:
        existing = self._extract_existing_imports()
        needed   = self._detect_needed_imports()
        missing  = []
        for imp in needed:
            if not self._is_import_present(imp, existing):
                missing.append(imp)
        return sorted(set(missing))

    def _extract_existing_imports(self) -> Set[str]:
        imports = set()
        for ln in self.lines:
            stripped = ln.strip()
            if stripped.startswith('import ') or stripped.startswith('from '):
                imports.add(stripped)
        return imports

    def _detect_needed_imports(self) -> Set[str]:
        needed = set()
        code_no_imports = '\n'.join(
            ln for ln in self.lines
            if not ln.strip().startswith('import ')
            and not ln.strip().startswith('from ')
        )
        for sym, imp_stmt in self.MODULE_SYMBOL_MAP.items():
            pattern = re.compile(r'(?<![.\w])' + re.escape(sym) + r'(?![.\w])')
            if pattern.search(code_no_imports):
                needed.add(imp_stmt)
        for pat, imp_stmt in self.CTYPES_USAGE_PATTERNS:
            if pat.search(code_no_imports):
                needed.add(imp_stmt)
        return needed

    def _is_import_present(self, imp_stmt: str, existing: Set[str]) -> bool:
        if imp_stmt in existing:
            return True
        if imp_stmt.startswith('import '):
            module = imp_stmt[7:].strip()
            for ex in existing:
                if ex.startswith('import ') and module in ex:
                    return True
        elif imp_stmt.startswith('from '):
            m = re.match(r'^from (\S+) import (.+)$', imp_stmt)
            if m:
                mod, sym = m.group(1), m.group(2).strip()
                for ex in existing:
                    em = re.match(r'^from (\S+) import (.+)$', ex)
                    if em and em.group(1) == mod and sym in [
                        s.strip() for s in em.group(2).split(',')
                    ]:
                        return True
        return False

    def augment_code_with_missing_imports(self) -> str:
        missing = self.infer_missing_imports()
        if not missing:
            return self.code
        lines = self.code.splitlines()
        last_import_idx = 0
        for idx, ln in enumerate(lines):
            if ln.strip().startswith('import ') or ln.strip().startswith('from '):
                last_import_idx = idx
        insert_at = last_import_idx + 1
        new_lines = lines[:insert_at] + missing + lines[insert_at:]
        return '\n'.join(new_lines)


class SourceFidelityChecker:

    KNOWN_OBFUSCATION_PATTERNS: List[re.Pattern] = [
        re.compile(r'exec\s*\(\s*__import__\s*\('),
        re.compile(r'exec\s*\(\s*compile\s*\('),
        re.compile(r'exec\s*\(\s*base64\.b64decode\s*\('),
        re.compile(r'eval\s*\(\s*compile\s*\('),
        re.compile(r'__import__\s*\(\s*[\'"]marshal[\'"]\s*\)'),
        re.compile(r'zlib\.decompress\s*\(\s*base64'),
        re.compile(r'gzip\.decompress'),
        re.compile(r'[A-Za-z_][A-Za-z0-9_]*\s*=\s*[A-Za-z_][A-Za-z0-9_]*\s*=\s*[A-Za-z_][A-Za-z0-9_]*\s*=\s*\d+\s*$'),
    ]

    SYNTAX_QUALITY_PATTERNS: List[Tuple[re.Pattern, str, int]] = [
        (re.compile(r'def \w+\(\):?\s*\n\s*pass'), 'fonction vide', -5),
        (re.compile(r'class \w+[^:]*:\s*\n\s*pass'), 'classe vide', -3),
        (re.compile(r'try:\s*\n\s*pass'), 'bloc try vide', -8),
        (re.compile(r'except:\s*\n\s*pass'), 'except générique+pass', -5),
        (re.compile(r'\bif True:\s*\n'), 'condition triviale', -2),
        (re.compile(r'\bif False:\s*\n'), 'code mort détecté', -10),
        (re.compile(r'return\s+return'), 'double return', -15),
        (re.compile(r'print\s*\(\s*\)'), 'print vide', -1),
    ]

    def __init__(self, original_dis: str, reconstructed: str):
        self.original_dis   = original_dis
        self.reconstructed  = reconstructed
        self._scores: Dict[str, float] = {}

    def compute_fidelity_score(self) -> float:
        scores = []
        scores.append(self._score_def_count())
        scores.append(self._score_class_count())
        scores.append(self._score_import_coherence())
        scores.append(self._score_no_leaks())
        scores.append(self._score_syntax())
        scores.append(self._score_no_obfuscation())
        overall = sum(scores) / max(len(scores), 1)
        self._scores['overall'] = overall
        return round(overall, 4)

    def _score_def_count(self) -> float:
        expected = len(re.findall(r'Disassembly of <code object', self.original_dis))
        found    = len(re.findall(r'^\s*def ', self.reconstructed, re.MULTILINE))
        if expected == 0:
            return 1.0
        ratio = found / expected
        return min(ratio, 1.0)

    def _score_class_count(self) -> float:
        expected = len(re.findall(r'LOAD_BUILD_CLASS', self.original_dis))
        found    = len(re.findall(r'^\s*class ', self.reconstructed, re.MULTILINE))
        if expected == 0:
            return 1.0
        ratio = found / expected
        return min(ratio, 1.0)

    def _score_import_coherence(self) -> float:
        imports_in_code = re.findall(r'^\s*(?:import|from)\s+\S+', self.reconstructed, re.MULTILINE)
        if not imports_in_code:
            has_import_name = 'IMPORT_NAME' in self.original_dis
            return 0.5 if has_import_name else 1.0
        return 1.0

    def _score_no_leaks(self) -> float:
        leaks = [
            '__NULL__', '__MISSING__', '__for_iter__',
            '<func:', 'OP0 ', 'OP1 ', 'OP2 ', '__intrinsic',
        ]
        leak_count = sum(
            self.reconstructed.count(leak)
            for leak in leaks
        )
        non_empty = max(len(self.reconstructed.splitlines()), 1)
        penalty = min(leak_count / non_empty, 1.0)
        return 1.0 - penalty

    def _score_syntax(self) -> float:
        ok, _ = validate_syntax(self.reconstructed)
        return 1.0 if ok else 0.6

    def _score_no_obfuscation(self) -> float:
        for pat in self.KNOWN_OBFUSCATION_PATTERNS:
            if pat.search(self.reconstructed):
                return 0.7
        return 1.0

    def get_detailed_report(self) -> str:
        score = self.compute_fidelity_score()
        lines = [
            f'Score de fidélité: {score*100:.1f}%',
            f'  def trouvés     : {len(re.findall(chr(100)+"ef ", self.reconstructed))}',
            f'  class trouvés   : {len(re.findall("class ", self.reconstructed))}',
            f'  imports trouvés : {len(re.findall(chr(105)+"mport ", self.reconstructed))}',
            f'  leaks résiduels : {self.reconstructed.count("__MISSING__") + self.reconstructed.count("__NULL__")}',
        ]
        return '\n'.join(lines)


def run_quality_analysis(input_path: str, output_path: str,
                         verbose: bool = False) -> Dict[str, Any]:
    try:
        with open(output_path, 'r', encoding='utf-8', errors='replace') as f:
            code = f.read()
    except OSError:
        return {'error': f'Impossible de lire {output_path}'}

    analyzer = BytecodeQualityAnalyzer(code)
    stats    = analyzer.analyze()

    if verbose:
        print(analyzer.report(verbose=True), file=sys.stderr)
        suggestions = analyzer.suggest_fixes()
        if suggestions:
            print('[SUGGESTIONS]', file=sys.stderr)
            for sug in suggestions:
                print(f'  - {sug}', file=sys.stderr)

    original_source = ''
    if input_path.lower().endswith('.txt') or not input_path.lower().endswith('.pyc'):
        try:
            with open(input_path, 'r', encoding='utf-8', errors='replace') as f:
                original_source = f.read()
        except OSError:
            pass

    if original_source:
        checker = SourceFidelityChecker(original_source, code)
        stats['fidelity_score']  = checker.compute_fidelity_score()
        stats['fidelity_report'] = checker.get_detailed_report()

    compat = PythonVersionCompatibilityMatrix.detect_version_from_bytecode_hints(
        original_source or code
    )
    if compat:
        stats['detected_version'] = f'{compat[0]}.{compat[1]}'

    return stats


def apply_ctypes_enrichment(code: str) -> str:
    code = CtypesStructureGenerator.generate_all_missing(code)
    engine = ImportInferenceEngine(code)
    code   = engine.augment_code_with_missing_imports()
    for old_name, qualified in CTYPES_TYPE_MAP.items():
        if old_name in ('Structure', 'Union', 'Array', 'POINTER', 'cast',
                        'pointer', 'byref', 'sizeof', 'alignment', 'memmove',
                        'memset', 'addressof'):
            continue
        if old_name not in code:
            continue
        safe_old = re.escape(old_name)
        code = re.sub(
            r'(?<![.\w])' + safe_old + r'(?![.\w(])',
            qualified,
            code,
        )
    return code


def _format_analysis_table(stats: Dict[str, Any]) -> str:
    rows = [
        ('Lignes totales',    str(stats.get('total_lines', '?'))),
        ('Lignes non vides',  str(stats.get('non_empty_lines', '?'))),
        ('Score qualité',     f'{stats.get("quality_score", 0)*100:.1f}%'),
        ('Label qualité',     stats.get('quality_label', '?')),
        ('Syntaxe valide',    'Oui' if stats.get('syntax_valid') else 'Non'),
        ('Artefacts restants',str(len(stats.get('artifact_lines', [])))),
        ('def trouvés',       str(stats.get('def_count', '?'))),
        ('class trouvés',     str(stats.get('class_count', '?'))),
        ('imports détectés',  str(stats.get('import_count', '?'))),
        ('usages ctypes',     str(stats.get('ctypes_count', '?'))),
    ]
    if 'fidelity_score' in stats:
        rows.append(('Fidélité source', f'{stats["fidelity_score"]*100:.1f}%'))
    if 'detected_version' in stats:
        rows.append(('Version Python détectée', stats['detected_version']))
    col1 = max(len(r[0]) for r in rows) + 2
    lines = []
    sep = '+' + '-' * (col1 + 2) + '+' + '-' * 20 + '+'
    lines.append(sep)
    for label, value in rows:
        lines.append(f'| {label:<{col1}} | {value:<18} |')
    lines.append(sep)
    return '\n'.join(lines)


def _print_banner():
    banner_lines = [
        'Ultra Bytecode Translator v8.0',
        'Supporte Python 3.10, 3.11, 3.12, 3.13, 3.14',
        f'Version Python courante: {sys.version_info.major}.{sys.version_info.minor}',
        f'Types ctypes disponibles: {len(CTYPES_TYPE_MAP)} natifs + {len(ALL_CTYPES_FLAT)} étendu',
        f'Structures ctypes auto-injectables: {len(CtypesStructureGenerator.list_available_structures())}',
    ]
    width = max(len(ln) for ln in banner_lines) + 4
    border = '=' * width
    print(border)
    for ln in banner_lines:
        print(f'  {ln}')
    print(border)


def _print_usage():
    _print_banner()
    print()
    print('Utilisation:')
    print('  python main.py <fichier.pyc>  <sortie.py>  [options]')
    print('  python main.py <dump.txt>     <sortie.py>  [options]')
    print('  python main.py <source.py>    <sortie.py>  [options]')
    print()
    print('Options:')
    print('  --verbose  / -v      Affiche les détails + sauvegarde le dump dis')
    print('  --force              Ignore la vérification de version Python')
    print('  --analyze            Lance une analyse qualité après la décompilation')
    print('  --enrich-ctypes      Injecte automatiquement les structures ctypes manquantes')
    print('  --suggest-imports    Suggère les imports manquants dans le code reconstruit')
    print('  --compat-report      Affiche la matrice de compatibilité versions Python')
    print('  --quality-only       Lance seulement l\'analyse qualité sur le fichier de sortie')
    print()
    print('Exemples:')
    print('  python main.py script.pyc output.py --verbose --analyze')
    print('  python main.py dump.txt output.py --enrich-ctypes --suggest-imports')
    print('  python main.py script.pyc output.py --force --verbose')
    print()


def _handle_compat_report():
    print('Matrice de compatibilité Python — fonctionnalités du bytecode:')
    print()
    for ver in PythonVersionCompatibilityMatrix.SUPPORTED_VERSIONS:
        print(PythonVersionCompatibilityMatrix.compatibility_report(ver))
        print()


def _handle_quality_only(output_path: str, input_path: str, verbose: bool):
    print(f'Analyse de qualité: {output_path}')
    stats = run_quality_analysis(input_path, output_path, verbose=verbose)
    if 'error' in stats:
        print(f'[ERREUR] {stats["error"]}', file=sys.stderr)
        sys.exit(1)
    print(_format_analysis_table(stats))
    analyzer = BytecodeQualityAnalyzer('')
    analyzer._stats = stats
    suggestions = BytecodeQualityAnalyzer(
        open(output_path, encoding='utf-8', errors='replace').read()
    ).suggest_fixes()
    if suggestions:
        print()
        print('Suggestions:')
        for sug in suggestions:
            print(f'  - {sug}')


def main():
    argv = sys.argv[1:]

    if len(argv) < 2 or '--help' in argv or '-h' in argv:
        _print_usage()
        sys.exit(0 if '--help' in argv or '-h' in argv else 1)

    input_path  = argv[0]
    output_path = argv[1]

    verbose       = '--verbose' in argv or '-v' in argv
    force         = '--force' in argv
    do_analyze    = '--analyze' in argv
    enrich_ctypes = '--enrich-ctypes' in argv
    suggest_imp   = '--suggest-imports' in argv
    compat_report = '--compat-report' in argv
    quality_only  = '--quality-only' in argv

    if compat_report:
        _handle_compat_report()
        sys.exit(0)

    if quality_only:
        _handle_quality_only(output_path, input_path, verbose)
        sys.exit(0)

    _check_version_and_maybe_relaunch(input_path, force=force, verbose=verbose)

    code = translate_file(input_path, output_path, verbose)

    if enrich_ctypes:
        if verbose:
            print('[INFO] Enrichissement ctypes...', file=sys.stderr)
        code = apply_ctypes_enrichment(code)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(code)

    if suggest_imp:
        if verbose:
            print('[INFO] Inférence des imports manquants...', file=sys.stderr)
        engine = ImportInferenceEngine(code)
        missing_imps = engine.infer_missing_imports()
        if missing_imps:
            print('[IMPORTS SUGGÉRÉS]')
            for imp in missing_imps:
                print(f'  {imp}')

    ok, err = validate_syntax(code)
    if ok:
        print(f'[OK] Code source reconstruit → {output_path}')
    else:
        n_todo = code.count('TODO (decompile):')
        print(f'[OK] Code source reconstruit → {output_path}')
        print(f'[WARN] Syntaxe résiduelle ({n_todo} artefact(s)): {err}')
        print()
        print('  Les lignes non décompilées sont marquées: TODO (decompile):')
        if not force:
            target = _get_pyc_python_version(input_path)
            if target and target != sys.version_info[:2]:
                maj, mn = target
                print(f'  → Meilleur résultat avec Python {maj}.{mn}:')
                print(f'     https://www.python.org/downloads/release/python-{maj}{mn}0/')

    if do_analyze:
        print()
        stats = run_quality_analysis(input_path, output_path, verbose=verbose)
        if 'error' not in stats:
            print(_format_analysis_table(stats))
            suggestions = BytecodeQualityAnalyzer(code).suggest_fixes()
            if suggestions:
                print()
                print('Suggestions d\'amélioration:')
                for sug in suggestions:
                    print(f'  - {sug}')

def _get_version_string() -> str:
    maj, mn, mic = sys.version_info[:3]
    return f'{maj}.{mn}.{mic}'


def _check_min_python_version(major: int, minor: int) -> bool:
    return sys.version_info >= (major, minor)


def _count_total_ctypes_entries() -> int:
    return sum(len(entries) for entries in CTYPES_LIBRARY.values())


def _list_all_ctypes_names() -> List[str]:
    names = list(CTYPES_TYPE_MAP.keys())
    for entries in CTYPES_LIBRARY.values():
        for name in entries:
            if name not in names:
                names.append(name)
    return sorted(names)


def _print_ctypes_stats():
    print(f'Types ctypes dans CTYPES_TYPE_MAP    : {len(CTYPES_TYPE_MAP)}')
    print(f'Types ctypes dans CTYPES_LIBRARY     : {_count_total_ctypes_entries()}')
    print(f'Types ctypes uniques (ALL_CTYPES_FLAT): {len(ALL_CTYPES_FLAT)}')
    print(f'Catégories CTYPES_LIBRARY             : {len(CTYPES_LIBRARY)}')
    print(f'Structures injectables               : {len(CtypesStructureGenerator.STRUCT_TEMPLATES)}')
    print(f'Unions injectables                   : {len(CtypesStructureGenerator.UNION_TEMPLATES)}')
    print(f'Constantes Windows (VK_, events...)  : {len(CtypesStructureGenerator.STANDALONE_DEFINITIONS)}')
    print(f'Symboles dans ImportInferenceEngine  : {len(ImportInferenceEngine.MODULE_SYMBOL_MAP)}')
    print(f'Versions Python supportées           : {len(PythonVersionCompatibilityMatrix.SUPPORTED_VERSIONS)}')


def _self_validate() -> bool:
    try:
        import ast as _ast
        with open(__file__, 'r', encoding='utf-8') as f:
            src = f.read()
        _ast.parse(src)
        return True
    except SyntaxError as e:
        print(f'[SELF-CHECK] Erreur de syntaxe dans ce fichier: {e}', file=sys.stderr)
        return False
    except OSError:
        return True


if __name__ == '__main__':
    main()