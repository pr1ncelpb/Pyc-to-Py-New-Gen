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


