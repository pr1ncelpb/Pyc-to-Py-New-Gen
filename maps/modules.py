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
