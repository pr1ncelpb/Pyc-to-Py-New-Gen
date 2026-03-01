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

from analysis.quality_analyzer import BytecodeQualityAnalyzer
from analysis.version_matrix import PythonVersionCompatibilityMatrix

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


