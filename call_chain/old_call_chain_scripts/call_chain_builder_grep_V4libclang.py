# --- aggiungi queste importazioni in cima ---
import os
import json
import subprocess
import re

from clang import cindex
import os, sys

# --- configura libclang (adatta il percorso se necessario) ---
# prova a usare env var CLANG_LIB if set, altrimenti prova percorso comune
clang_lib = "/usr/lib/llvm-14/lib/libclang.so"
try:
    cindex.Config.set_library_file(clang_lib)
except Exception as e:
    print(f"[WARN] Could not set libclang from {clang_lib}: {e}", file=sys.stderr)
    # lascialo provare comunque

# ---------------- helpers clang ----------------
def clang_get_qualified_name(cursor):
    """Ricostruisce qualified name per un cursor clang."""
    parts = []
    cur = cursor
    # se il cursor è una declaration (es. method) includi spelling e risali semantic_parent
    while cur and cur.kind != cindex.CursorKind.TRANSLATION_UNIT:
        if cur.spelling:
            parts.append(cur.spelling)
        cur = cur.semantic_parent
    return "::".join(reversed(parts))

def find_project_include_dirs(main_file, max_up=6):
    """Trova automaticamente directory include (src, include, c++/src) risalendo."""
    include_dirs = set()
    current = os.path.dirname(os.path.abspath(main_file))
    include_dirs.add(os.path.dirname(os.path.abspath(main_file)))
    for _ in range(max_up):
        for d in ["src", "include", "c++/src"]:
            cand = os.path.join(current, d)
            if os.path.isdir(cand):
                include_dirs.add(cand)
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
    return list(include_dirs)

def build_clang_tu(main_file, extra_includes=None, compile_args=None):
    """
    Costruisce e ritorna un TranslationUnit per main_file, con include dirs automatici.
    extra_includes: list di header paths da includere nelle -I.
    compile_args: lista addizionale di args clang.
    """
    index = cindex.Index.create()
    project_includes = find_project_include_dirs(main_file)
    args = ["-std=c++17", "-x", "c++"] + (compile_args or [])
    # aggiungi include dirs
    for inc in project_includes:
        args.append(f"-I{inc}")
    # aggiungi eventuali extra_includes directory
    if extra_includes:
        for header in extra_includes:
            d = os.path.dirname(os.path.abspath(header))
            args.append(f"-I{d}")
    # riduci rumore
    args.extend(["-Wno-everything", "-ferror-limit=100"])
    try:
        tu = index.parse(main_file, args=args,
                         options=cindex.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD | cindex.TranslationUnit.PARSE_INCOMPLETE)
    except Exception as e:
        print(f"[clang] parse failed for {main_file}: {e}", file=sys.stderr)
        return None
    return tu

def find_clang_call_at_location(tu, target_file, target_line):
    """
    Cerca CALL_EXPR / MEMBER_REF_EXPR / DECL_REF_EXPR che si trovano su target_line
    ritorna lista di cursors (referenced cursors) o [].
    target_line: 1-based
    """
    results = []

    def walk(node):
        # node.location may be None for implicit nodes
        if node.location and node.location.file and node.location.file.name == target_file:
            ln = node.location.line
            if ln == target_line:
                if node.kind == cindex.CursorKind.CALL_EXPR:
                    ref = node.referenced
                    if ref:
                        results.append(ref)
                    else:
                        # fallback: guarda figli per MEMBER_REF_EXPR / DECL_REF_EXPR
                        for c in node.get_children():
                            if c.kind in (cindex.CursorKind.MEMBER_REF_EXPR, cindex.CursorKind.DECL_REF_EXPR):
                                ref2 = c.referenced
                                if ref2:
                                    results.append(ref2)
                elif node.kind in (cindex.CursorKind.MEMBER_REF_EXPR, cindex.CursorKind.DECL_REF_EXPR):
                    ref = node.referenced
                    if ref:
                        results.append(ref)
        for c in node.get_children():
            walk(c)

    walk(tu.cursor)
    return results

def verify_call_with_clang(main_file, imports, file_path, line, target_qualified_name):
    """
    Verifica semanticamente che in file_path:line ci sia una chiamata che risolve
    alla funzione target_qualified_name (esatto match).
    main_file: file che useremo per costruire TU (può essere file_path stesso).
    imports: lista di header paths (opzionale) per -I.
    Ritorna (True, resolved_name) se verified; (False, reason) altrimenti.
    """
    tu = build_clang_tu(main_file, extra_includes=imports)
    if not tu:
        return False, "tu_failed"

    # Trova cursors referenziati sul target line
    refs = find_clang_call_at_location(tu, file_path, line)
    if not refs:
        return False, "no_refs_found"

    # compara ciascun ref con target
    for ref in refs:
        try:
            qn = clang_get_qualified_name(ref)
            if not qn:
                continue
            # confronti: esatto o suffix (consente namespace diversi)
            if qn == target_qualified_name or qn.endswith("::" + target_qualified_name.split("::")[-1]):
                return True, qn
        except Exception:
            continue
    # se nessuno matcha esatto, restituisci primo ref per info
    first_qn = clang_get_qualified_name(refs[0]) if refs else None
    return False, first_qn or "unresolved"



#!/usr/bin/env python3

import os
import json
import subprocess
import re

# Fix per tree-sitter: usa tree_sitter_languages con API nuova
try:
    import tree_sitter_cpp as tscpp
    from tree_sitter import Language, Parser
    CPP_LANGUAGE = Language(tscpp.language())
    print("[INFO] Using tree-sitter-cpp")
except ImportError:
    print("[ERROR] Could not import tree-sitter-cpp")
    print("[INFO] Install with: pip install tree-sitter tree-sitter-cpp")
    raise

def make_parser():
    parser = Parser(CPP_LANGUAGE)
    return parser

# ------------------------------------------------------------
# Step 1: GREP candidati (più preciso)
# ------------------------------------------------------------
def grep_candidates(target, repo_path):
    """
    Cerca file che contengono il target usando ripgrep.
    Usa word boundaries per evitare match parziali come findLineStatic quando cerchi findLine.
    """
    print(f"[GREP] Searching for '{target}' in {repo_path} ...")
    
    # Estrai solo il nome della funzione (ultima parte dopo ::)
    function_name = target.split("::")[-1]
    
    # Pattern con word boundary: deve essere seguito da ( o . o -> o ::
    # per evitare match parziali come findLineStatic
    pattern = f"\\b{re.escape(function_name)}\\s*\\(|[.>:]{re.escape(function_name)}\\s*\\("
    
    cmd = ["rg", pattern, "--type", "cpp", "--no-heading", "-n", repo_path]
    result = subprocess.run(cmd, capture_output=True, text=True)
    matches = []
    for line in result.stdout.splitlines():
        try:
            file, lineno, *_ = line.split(":", 2)
            matches.append((file, int(lineno)))
        except ValueError:
            continue
    print(f"[GREP] Found {len(matches)} candidates")
    return matches

# ------------------------------------------------------------
# Step 2: Tree-sitter verifica chiamata e posizione
# ------------------------------------------------------------
# Cache globale per i file già parsati
parsed_files = {}
MAX_CACHE = 1000

def extract_function_name(node, code):
    """
    Estrae il nome della funzione da un nodo function_declarator.
    Gestisce casi come:
    - simple: foo()
    - qualified: Class::foo()
    - templates: foo<T>()
    - operators: operator=()
    """
    if node.type == "function_declarator":
        # Cerca il primo identifier o qualified_identifier
        for child in node.children:
            if child.type == "qualified_identifier":
                # Es: Class::method
                return code[child.start_byte:child.end_byte].strip()
            elif child.type == "identifier":
                # Es: foo
                return code[child.start_byte:child.end_byte].strip()
            elif child.type == "field_identifier":
                # Es: member method
                return code[child.start_byte:child.end_byte].strip()
            elif child.type == "destructor_name":
                # Es: ~ClassName
                return code[child.start_byte:child.end_byte].strip()
            elif child.type == "operator_name":
                # Es: operator=
                return code[child.start_byte:child.end_byte].strip()
    
    # Fallback: cerca ricorsivamente
    for child in node.children:
        if child.type in ("identifier", "qualified_identifier", "field_identifier"):
            name = code[child.start_byte:child.end_byte].strip()
            # Ignora nomi che sono chiaramente tipi di ritorno
            if name and not name.startswith("_::") and "::" not in name[:3]:
                return name
    
    return None

def find_call_expressions(file_path, target):
    """
    Restituisce una lista di tuple (line, snippet, caller_name)
    se nel file sono trovate call_expression o member_expression
    che contengono il target.
    """
    if len(parsed_files) > MAX_CACHE:
        parsed_files.clear()
    calls = []
    try:
        # --- se già parsato, riusa il risultato ---
        if file_path in parsed_files:
            tree, code = parsed_files[file_path]
        else:
            with open(file_path, "rb") as f:
                code_bytes = f.read()
            code = code_bytes.decode("utf-8", errors="ignore")
            parser = make_parser()
            tree = parser.parse(code_bytes)
            parsed_files[file_path] = (tree, code)

        root = tree.root_node

        # --- funzione helper per trovare la funzione chiamante ---
        def find_containing_function(node, target_line, current_class=None):
            """Trova la funzione che contiene la linea target."""
            if node.type == "function_definition":
                start_line = node.start_point[0]
                end_line = node.end_point[0]
                if start_line <= target_line <= end_line:
                    # Cerca il function_declarator
                    for child in node.children:
                        if child.type == "function_declarator":
                            func_name = extract_function_name(child, code)
                            if func_name:
                                if current_class and "::" not in func_name:
                                    return f"{current_class}::{func_name}"
                                return func_name
                    # Fallback
                    return "unknown_function"

            # Gestione classi/struct
            if node.type in ("class_specifier", "struct_specifier"):
                class_name = None
                for c in node.children:
                    if c.type in ("type_identifier", "identifier"):
                        class_name = code[c.start_byte:c.end_byte]
                        break
                # Ricorsione dentro la classe
                for child in node.children:
                    result = find_containing_function(child, target_line, class_name)
                    if result:
                        return result
                return None

            # Ricorsione generica
            for child in node.children:
                result = find_containing_function(child, target_line, current_class)
                if result:
                    return result
            return None

        # --- scan delle chiamate ---
        target_func = target.split("::")[-1]
        
        def walk(node):
            if node.type == "call_expression":
                snippet = code[node.start_byte:node.end_byte]
                # Match preciso: cerca il nome della funzione seguito da (
                if re.search(rf'\b{re.escape(target_func)}\s*\(', snippet):
                    line = node.start_point[0] + 1
                    context = get_code_snippet(code, line)
                    caller = find_containing_function(root, node.start_point[0])
                    if not caller:
                        caller = f"unknown_{os.path.basename(file_path)}_L{line}"
                    calls.append((line, context, caller))

            for c in node.children:
                walk(c)

        walk(root)

    except Exception as e:
        print(f"[TREE-SITTER] Error parsing {file_path}: {e}")

    return calls

def get_code_snippet(code, line, context=5):
    """Ritorna qualche riga attorno a `line` per dare contesto al codice."""
    lines = code.splitlines()
    if not lines:
        return ""
    start = max(0, line - context - 1)
    end = min(len(lines), line + context)
    snippet = "\n".join(lines[start:end]).strip()
    return snippet or f"[code context unavailable at line {line}]"


# ---------------- integrazione con analyze_callers ----------------
# modifica analyze_callers per usare verify_call_with_clang:
def analyze_callers(repo_path, target_function, depth=0, visited_functions=None, max_depth=10, clang_main_hint=None, extra_imports=None):
    """
    Ora verifica con clang i candidate trovati via tree-sitter.
    clang_main_hint: file da passare come TU 'main' (se None useremo first candidate file)
    extra_imports: lista di header paths (opzionale) da passare a clang
    """
    if visited_functions is None:
        visited_functions = set()
    if target_function in visited_functions:
        return [[]]
    if depth > max_depth:
        return [[]]
    visited_functions.add(target_function)

    print(f"{' ' * depth*2}[DEPTH {depth}] Analyzing callers of '{target_function}'")

    candidates = grep_candidates(target_function, repo_path)
    callers_dict = {}

    for file_path, grep_line in candidates:
        # usa tree-sitter per ottenere call expressions e caller names
        calls = find_call_expressions(file_path, target_function)
        if not calls:
            continue
        for line, snippet, caller in calls:
            # tentativo di verifica clang:
            main_hint = clang_main_hint or file_path  # se non specificato usa il file corrente come main
            verified, info = verify_call_with_clang(main_hint, extra_imports or [], file_path, line, target_function)
            if verified:
                key = caller
                if key not in callers_dict:
                    callers_dict[key] = {"function": caller, "file": file_path, "line": line, "code": snippet, "verified": True, "resolved": info}
                    print(f"{' ' * depth*2}  ✓ Verified caller: {caller} -> {info} @ {file_path}:{line}")
            else:
                # opzionalmente tieni anche non verificati (ma marcati)
                key = f"{caller} (unverified)"
                if key not in callers_dict:
                    callers_dict[key] = {"function": caller, "file": file_path, "line": line, "code": snippet, "verified": False, "resolved": info}
                    print(f"{' ' * depth*2}  - Unverified caller: {caller} (clang -> {info}) @ {file_path}:{line}")

    valid_callers = list(callers_dict.values())
    if not valid_callers:
        return [[]]

    all_chains = []
    for vc in valid_callers:
        subchains = analyze_callers(repo_path, vc["function"], depth + 1, visited_functions.copy(), max_depth, clang_main_hint=clang_main_hint, extra_imports=extra_imports)
        for chain in subchains:
            new_chain = [vc] + chain
            all_chains.append(new_chain)
    return all_chains



# ------------------------------------------------------------
# MAIN
# ------------------------------------------------------------
if __name__ == "__main__":
    # Configurazione
    repo = "/home/michele/Desktop/ricerca/output_repos_cpp/CVE-2015-2313/repo/c++"
    input_json = "/home/michele/Desktop/ricerca/agents/local_agent/7thTest.context.json"
    output = "/home/michele/Desktop/ricerca/agents/call_chain/call_chains_tree_sitter_libclang_TESTv4.json"
    
    # Carica il JSON con tutte le funzioni
    print(f"[INFO] Loading functions from {input_json}")
    with open(input_json, "r") as f:
        functions_data = json.load(f)
    
    print(f"[INFO] Found {len(functions_data)} functions to analyze\n")
    
    # Analizza tutte le funzioni
    all_results = []
    
    for idx, func_record in enumerate(functions_data[:30], 1):  # Test con 10
        func_id = func_record["id"]
        qualified_name = func_record["qualified_name"]
        
        print(f"\n{'='*70}")
        print(f"[{idx}/{len(functions_data[:10])}] Analyzing: {qualified_name}")
        print(f"  ID: {func_id}")
        print(f"{'='*70}")
        
        # Analizza le call chains per questa funzione
        chains = analyze_callers(repo, qualified_name, max_depth=2)
        
        # Filtra catene vuote
        chains = [ch for ch in chains if ch]
        
        # Aggiungi la funzione target alla fine di ogni catena
        for chain in chains:
            chain.append({
                "function": qualified_name,
                "file": None,
                "line": None,
                "code": "",
                "note": "target_function"
            })
        
        # Se non ci sono chain, crea una singola entry con solo la funzione target
        if not chains:
            chains = [[{
                "function": qualified_name,
                "file": None,
                "line": None,
                "code": "",
                "note": "no_callers_found"
            }]]
        
        # Salva il risultato con id e qualified_name
        result = {
            "id": func_id,
            "qualified_name": qualified_name,
            "num_chains": len(chains),
            "call_chains": chains
        }
        
        all_results.append(result)
        
        print(f"\n[RESULT] Found {len(chains)} call chain(s) for {qualified_name}")
        for i, ch in enumerate(chains[:3], 1):  # Mostra solo le prime 3
            chain_str = " → ".join([f['function'] for f in ch])
            print(f"  Chain {i}: {chain_str}")
        if len(chains) > 3:
            print(f"  ... and {len(chains) - 3} more chains")
    
    # Salva tutti i risultati in un unico JSON
    print(f"\n{'='*70}")
    print(f"[SAVE] Writing results to {output}")
    
    # Crea la directory se non esiste
    os.makedirs(os.path.dirname(output), exist_ok=True)
    
    with open(output, "w") as f:
        json.dump(all_results, f, indent=2)
    
    # Statistiche finali
    total_chains = sum(r["num_chains"] for r in all_results)
    avg_chains = total_chains / len(all_results) if all_results else 0
    print(f"\n{'='*70}")
    print(f"[DONE] Analysis complete!")
    print(f"  Functions analyzed: {len(all_results)}")
    print(f"  Total call chains: {total_chains}")
    print(f"  Average chains per function: {avg_chains:.1f}")
    print(f"  Results saved to: {output}")
    print(f"{'='*70}")
