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

# ------------------------------------------------------------
# Step 3: Ricorsione per call-chain
# ------------------------------------------------------------
def analyze_callers(repo_path, target_function, depth=0, visited_functions=None, max_depth=10):
    """
    Analizza ricorsivamente i chiamanti di una funzione.
    Restituisce chain INVERTITE: dal chiamante più alto alla funzione target.
    """
    if visited_functions is None:
        visited_functions = set()
    
    # Evita loop infiniti: se abbiamo già analizzato questa funzione, stop
    if target_function in visited_functions:
        print(f"{' ' * depth*2}[CYCLE] Already visited {target_function}, stopping")
        return [[]]
    
    if depth > max_depth:
        print(f"{' ' * depth*2}[WARNING] Max depth {max_depth} reached, stopping recursion")
        return [[]]

    target_name = target_function.split("::")[-1]
    print(f"\n{' ' * depth*2}[DEPTH {depth}] Analyzing callers of '{target_function}'")
    
    # Marca questa funzione come visitata
    visited_functions.add(target_function)
    
    matches = grep_candidates(target_function, repo_path)

    # Usa un dict per deduplicare per nome funzione
    callers_dict = {}
    
    for file_path, grep_line in matches:
        calls = find_call_expressions(file_path, target_name)
        if not calls:
            continue

        for line, snippet, caller in calls:
            # Filtra nomi di funzione invalidi
            if caller.startswith("_::") or caller == "unknown_function":
                continue
            
            # Deduplica: se abbiamo già questa funzione chiamante, skippa
            if caller not in callers_dict:
                print(f"{' ' * depth*2}  → Found: {caller} in {file_path}:{line}")
                callers_dict[caller] = {
                    "function": caller,
                    "file": file_path,
                    "line": line,
                    "code": snippet.strip()
                }
            else:
                print(f"{' ' * depth*2}  → Skip duplicate: {caller} (already found)")

    valid_callers = list(callers_dict.values())
    
    # Costruisci le catene
    all_chains = []
    
    if not valid_callers:
        # Nessun chiamante trovato - questa è la root
        return [[]]

    for vc in valid_callers:
        # Ricorsione sul chiamante (passa il set di funzioni visitate)
        subchains = analyze_callers(
            repo_path, 
            vc["function"], 
            depth + 1, 
            visited_functions.copy(),  # ← Copia per ogni branch
            max_depth
        )
        
        for chain in subchains:
            # Prepend questo chiamante alla catena (ordine: root -> ... -> target)
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
    output = "/home/michele/Desktop/ricerca/agents/call_chain/call_chains_tree_sitter_TESTv3.json"
    
    # Carica il JSON con tutte le funzioni
    print(f"[INFO] Loading functions from {input_json}")
    with open(input_json, "r") as f:
        functions_data = json.load(f)
    
    print(f"[INFO] Found {len(functions_data)} functions to analyze\n")
    
    # Analizza tutte le funzioni
    all_results = []
    
    for idx, func_record in enumerate(functions_data[:50], 1):  # Test con 10
        func_id = func_record["id"]
        qualified_name = func_record["qualified_name"]
        
        print(f"\n{'='*70}")
        print(f"[{idx}/{len(functions_data[:10])}] Analyzing: {qualified_name}")
        print(f"  ID: {func_id}")
        print(f"{'='*70}")
        
        # Analizza le call chains per questa funzione
        chains = analyze_callers(repo, qualified_name, max_depth=5)
        
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