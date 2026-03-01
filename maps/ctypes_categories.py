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
from .ctypes_types import CTYPES_TYPE_MAP

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


