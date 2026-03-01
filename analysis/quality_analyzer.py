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


