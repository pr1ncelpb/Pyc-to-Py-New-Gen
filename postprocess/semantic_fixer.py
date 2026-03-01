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

