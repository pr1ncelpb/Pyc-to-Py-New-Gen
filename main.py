import sys
import ast
import warnings
from typing import List, Dict, Any

warnings.filterwarnings('ignore', category=SyntaxWarning)

from maps import CTYPES_TYPE_MAP, CTYPES_LIBRARY, ALL_CTYPES_FLAT
from bytecode import validate_syntax, _get_pyc_python_version, _check_version_and_maybe_relaunch
from analysis import BytecodeQualityAnalyzer, PythonVersionCompatibilityMatrix, run_quality_analysis
from ctypes_tools import CtypesStructureGenerator, ImportInferenceEngine, apply_ctypes_enrichment
from pipeline import translate_file

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
