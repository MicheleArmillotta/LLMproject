#!/usr/bin/env python3

import os
import json
import subprocess

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
# Step 1: GREP candidati
# ------------------------------------------------------------
def grep_candidates(target, repo_path):
    """Cerca file che contengono il target usando ripgrep."""
    print(f"[GREP] Searching for '{target}' in {repo_path} ...")
    cmd = ["rg", target, "--type", "cpp", "--no-heading", "-n", repo_path]
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
            if node.type in ("function_definition", "method_declaration",
                             "declaration", "template_declaration"):
                start_line = node.start_point[0]
                end_line = node.end_point[0]
                if start_line <= target_line <= end_line:
                    func_name = None
                    for child in node.children:
                        if child.type in (
                            "function_declarator", "identifier",
                            "field_identifier", "qualified_identifier"
                        ):
                            func_name = code[child.start_byte:child.end_byte].strip()
                            break
                    if func_name:
                        if current_class:
                            return f"{current_class}::{func_name}"
                        return func_name

            if node.type in ("class_specifier", "struct_specifier"):
                class_name = None
                for c in node.children:
                    if c.type in ("type_identifier", "identifier"):
                        class_name = code[c.start_byte:c.end_byte]
                        break
                for child in node.children:
                    result = find_containing_function(child, target_line, class_name)
                    if result:
                        return result
                return None

            for child in node.children:
                result = find_containing_function(child, target_line, current_class)
                if result:
                    return result
            return None

        # --- scan delle chiamate ---
        def walk(node):
            if node.type == "call_expression":
                snippet = code[node.start_byte:node.end_byte]
                if target.split("::")[-1] in snippet:
                    line = node.start_point[0] + 1
                    context = get_code_snippet(code, line)
                    caller = find_containing_function(root, node.start_point[0])
                    if not caller:
                        caller = f"unknown_{os.path.basename(file_path)}_L{line}"
                    calls.append((line, context, caller))

            elif node.type == "member_expression":
                snippet = code[node.start_byte:node.end_byte]
                if target.split("::")[-1] in snippet and "(" in snippet and ")" in snippet:
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
def analyze_callers(repo_path, target_function, depth=0, visited=None, max_depth=10):
    """Analizza ricorsivamente i chiamanti di una funzione."""
    if visited is None:
        visited = set()
    
    if depth > max_depth:
        print(f"{' ' * depth*2}[WARNING] Max depth {max_depth} reached, stopping recursion")
        return [[{"function": target_function, "file": None, "line": None, "code": "", "note": "max_depth_reached"}]]

    target_name = target_function.split("::")[-1]
    print(f"\n{' ' * depth*2}[DEPTH {depth}] Analyzing callers of '{target_function}'")
    
    matches = grep_candidates(target_name, repo_path)

    valid_callers = []
    for file_path, grep_line in matches:
        if file_path in visited:
            continue

        calls = find_call_expressions(file_path, target_name)
        if not calls:
            continue

        for line, snippet, caller in calls:
            print(f"{' ' * depth*2}  → Found: {caller} in {file_path}:{line}")
            
            valid_callers.append({
                "caller": caller,
                "file": file_path,
                "line": line,
                "code": snippet.strip()
            })
        
        visited.add(file_path)

    # Costruisci le catene
    all_chains = []
    if not valid_callers:
        # Nessun chiamante trovato - questa è la radice
        return [[{
            "function": target_function,
            "file": repo_path,
            "line": None,
            "code": "",
            "note": "root"
        }]]

    for vc in valid_callers:
        # Ricorsione sul chiamante
        subchains = analyze_callers(repo_path, vc["caller"], depth + 1, visited, max_depth)
        for chain in subchains:
            # Rinomina "caller" in "function" per uniformità
            vc_normalized = {
                "function": vc["caller"],
                "file": vc["file"],
                "line": vc["line"],
                "code": vc["code"]
            }
            # Aggiungi questo chiamante alla catena
            all_chains.append(chain + [vc_normalized])

    return all_chains

# ------------------------------------------------------------
# MAIN
# ------------------------------------------------------------
if __name__ == "__main__":
    # Configurazione
    repo = "/home/michele/Desktop/ricerca/output_repos_cpp/CVE-2015-2313/repo/c++"
    input_json = "/home/michele/Desktop/ricerca/agents/local_agent/7thTest.context.json"
    output = "/home/michele/Desktop/ricerca/agents/call_chain/call_chains_tree_sitter.json"
    
    # Carica il JSON con tutte le funzioni
    print(f"[INFO] Loading functions from {input_json}")
    with open(input_json, "r") as f:
        functions_data = json.load(f)
    
    print(f"[INFO] Found {len(functions_data)} functions to analyze\n")
    
    # Analizza tutte le funzioni
    all_results = []
    
    for idx, func_record in enumerate(functions_data[:100], 1):
        func_id = func_record["id"]
        qualified_name = func_record["qualified_name"]
        
        print(f"\n{'='*70}")
        print(f"[{idx}/{len(functions_data)}] Analyzing: {qualified_name}")
        print(f"  ID: {func_id}")
        print(f"{'='*70}")
        
        # Analizza le call chains per questa funzione
        chains = analyze_callers(repo, qualified_name, max_depth=5)
        
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
    print(f"\n{'='*70}")
    print(f"[DONE] Analysis complete!")
    print(f"  Functions analyzed: {len(all_results)}")
    print(f"  Total call chains: {total_chains}")
    print(f"  Average chains per function: {total_chains / len(all_results):.1f}")
    print(f"  Results saved to: {output}")
    print(f"{'='*70}")