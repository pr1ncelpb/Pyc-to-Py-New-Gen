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


