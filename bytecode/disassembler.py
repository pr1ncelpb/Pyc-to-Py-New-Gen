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
from .opcode_tables import (
    _get_opcode_table, _MAGIC_TO_VERSION, _HAVE_ARGUMENT, _CACHE_COUNTS,
    _BINARY_OP_NAMES, _cmp_op_name,
)
from .pyc_reader import (
    PycCodeObject, _unmarshal_code, _wrap_code_object,
    _decode_linetable_310, _decode_linetable_311, _get_lineno_map, _repr_const,
)
from .marshal_reader import MarshalReader

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

