import os
import json
from clang import cindex
from py2neo import Graph, Node, Relationship
from collections import defaultdict, deque

# === CONFIG ===
cindex.Config.set_library_file("/usr/lib/llvm-14/lib/libclang.so")
TARGET_FUNCTION = "getPipelinedCap"
REPO_PATH = "/home/michele/Desktop/ricerca/output_repos_cpp/CVE-2015-2313/repo/c++"
OUTPUT_JSON = "agents/call_chain/call_chains.json"
NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASS = "password"

# === FUNZIONI UTILI ===

def find_include_paths(repo_path):
    """
    Trova tutti i possibili include paths nella repository.
    """
    include_dirs = set()
    include_dirs.add(repo_path)
    
    for root, dirs, files in os.walk(repo_path):
        # Aggiungi directories comuni
        if any(name in root for name in ['include', 'src', 'lib', 'core']):
            include_dirs.add(root)
        
        # Aggiungi directory che contengono header files
        if any(f.endswith(('.h', '.hpp', '.hxx')) for f in files):
            include_dirs.add(root)
    
    # Aggiungi include di sistema comuni per risolvere strlen, ecc.
    system_includes = [
        '/usr/include',
        '/usr/include/c++/11',
        '/usr/include/x86_64-linux-gnu',
        '/usr/include/x86_64-linux-gnu/c++/11',
        '/usr/lib/gcc/x86_64-linux-gnu/11/include',
    ]
    
    for path in system_includes:
        if os.path.exists(path):
            include_dirs.add(path)
    
    return list(include_dirs)


def get_qualified_name(cursor):
    """
    Ottiene il nome qualificato completo di una funzione/metodo.
    Es: MyClass::myMethod invece di solo myMethod
    """
    parts = []
    current = cursor
    
    while current is not None:
        if current.kind == cindex.CursorKind.NAMESPACE:
            if current.spelling:  # Skip anonymous namespaces
                parts.append(current.spelling)
        elif current.kind in [cindex.CursorKind.CLASS_DECL, 
                              cindex.CursorKind.STRUCT_DECL,
                              cindex.CursorKind.CLASS_TEMPLATE]:
            if current.spelling:
                parts.append(current.spelling)
        elif current.kind in [cindex.CursorKind.FUNCTION_DECL,
                              cindex.CursorKind.CXX_METHOD,
                              cindex.CursorKind.CONSTRUCTOR,
                              cindex.CursorKind.DESTRUCTOR,
                              cindex.CursorKind.FUNCTION_TEMPLATE]:
            if current.spelling:
                parts.append(current.spelling)
            break
        
        current = current.semantic_parent
        # Evita loop infiniti
        if current and current.kind == cindex.CursorKind.TRANSLATION_UNIT:
            break
    
    qualified = "::".join(reversed(parts))
    return qualified if qualified else (cursor.spelling or "")


def extract_functions(node, functions, file_path):
    """
    Estrae tutte le funzioni e metodi con i loro nomi qualificati.
    """
    if node.kind in [cindex.CursorKind.FUNCTION_DECL,
                     cindex.CursorKind.CXX_METHOD,
                     cindex.CursorKind.CONSTRUCTOR,
                     cindex.CursorKind.DESTRUCTOR]:
        qualified_name = get_qualified_name(node)
        simple_name = node.spelling
        
        # Memorizza sia il nome semplice che quello qualificato
        functions[qualified_name] = {
            'node': node,
            'simple_name': simple_name,
            'qualified_name': qualified_name,
            'file': file_path,
            'line': node.location.line
        }
        
        # Aggiungi anche il nome semplice per facilitare la ricerca
        if simple_name and simple_name != qualified_name:
            functions[simple_name] = functions[qualified_name]
        
        print(f"[FUNC] Found: {qualified_name} in {file_path}:{node.location.line}")
    
    for child in node.get_children():
        extract_functions(child, functions, file_path)


def resolve_callee_name(node, all_functions):
    """
    Risolve il nome della funzione chiamata, gestendo vari casi.
    """
    # Prova a ottenere la definizione referenziata
    referenced = node.referenced
    if referenced:
        qualified = get_qualified_name(referenced)
        if qualified in all_functions:
            return qualified
        if referenced.spelling in all_functions:
            return referenced.spelling
    
    # Fallback: usa displayname o spelling
    name = node.displayname or node.spelling
    
    # Pulisci il nome (rimuovi parametri se presenti)
    if '(' in name:
        name = name.split('(')[0]
    
    # Controlla se esiste nelle funzioni conosciute
    if name in all_functions:
        return name
    
    # Prova a cercare per nome semplice
    for func_name, func_info in all_functions.items():
        if isinstance(func_info, dict) and func_info.get('simple_name') == name:
            return func_name
    
    return name


def find_calls(node, current_func_name, call_graph, all_functions):
    """
    Trova tutte le chiamate a funzioni, inclusi metodi membro.
    """
    # CXX_MEMBER_CALL_EXPR potrebbe non esistere in tutte le versioni di libclang
    # Usiamo un approccio più compatibile
    call_kinds = [cindex.CursorKind.CALL_EXPR]
    
    # Aggiungi CXX_MEMBER_CALL_EXPR solo se esiste
    if hasattr(cindex.CursorKind, 'CXX_MEMBER_CALL_EXPR'):
        call_kinds.append(cindex.CursorKind.CXX_MEMBER_CALL_EXPR)
    
    if node.kind in call_kinds or node.kind == cindex.CursorKind.MEMBER_REF_EXPR:
        
        callee_name = resolve_callee_name(node, all_functions)
        
        if callee_name and callee_name != current_func_name:
            location = f"{node.location.file}:{node.location.line}" if node.location.file else "unknown"
            
            call_graph[current_func_name].append({
                "callee": callee_name,
                "location": location,
                "line": node.location.line if node.location else 0
            })
            
            print(f"[CALL] {current_func_name} -> {callee_name} @ {location}")
    
    for child in node.get_children():
        find_calls(child, current_func_name, call_graph, all_functions)


def build_call_graph(repo_path, target):
    """
    Costruisce il grafo delle chiamate completo.
    """
    call_graph = defaultdict(list)
    all_functions = {}
    
    # Prima passata: trova tutti i possibili include paths
    include_paths = find_include_paths(repo_path)
    print(f"[INFO] Found {len(include_paths)} include directories")
    
    # Raccolta di tutti i file C++
    cpp_files = []
    header_files = []
    
    # Debug: verifica se il path esiste
    if not os.path.exists(repo_path):
        print(f"[ERROR] Repository path does not exist: {repo_path}")
        return {}, [], {}
    
    print(f"[DEBUG] Walking through: {repo_path}")
    for root, dirs, files in os.walk(repo_path):
        print(f"[DEBUG] Checking directory: {root} (files: {len(files)})")
        for file in files:
            full_path = os.path.join(root, file)
            if file.endswith(('.cpp', '.cc', '.cxx', '.c', '.C')):
                cpp_files.append(full_path)
                print(f"[DEBUG] Found C++ file: {file}")
            elif file.endswith(('.h', '.hpp', '.hxx', '.hh')):
                header_files.append(full_path)
    
    print(f"[INFO] Found {len(cpp_files)} C++ implementation files")
    print(f"[INFO] Found {len(header_files)} C++ header files")
    
    # Se non ci sono .cpp, proviamo anche con gli header (molte implementazioni inline)
    if len(cpp_files) == 0 and len(header_files) > 0:
        print("[INFO] No .cpp files found, will analyze header files for inline implementations")
        cpp_files = header_files
    
    # Prima passata: estrai tutte le funzioni
    print("\n=== PHASE 1: Extracting all functions ===")
    for file_path in cpp_files:
        # Args più completi per il parsing
        args = [
            "-std=c++17",
            "-w",  # Disabilita warning
            "-xc++",  # Forza C++
        ] + [f"-I{p}" for p in include_paths]
        
        try:
            index = cindex.Index.create()
            # Opzioni per essere più permissivi
            options = (cindex.TranslationUnit.PARSE_SKIP_FUNCTION_BODIES | 
                      cindex.TranslationUnit.PARSE_INCOMPLETE)
            tu = index.parse(file_path, args=args, options=options)
            
            if not tu:
                print(f"[ERROR] Failed to create translation unit for {file_path}")
                continue
            
            # Check for diagnostics - mostra solo errori fatali
            fatal_errors = False
            for diag in tu.diagnostics:
                if diag.severity >= cindex.Diagnostic.Fatal:
                    fatal_errors = True
                    print(f"[FATAL] {file_path}: {diag.spelling}")
            
            # Estrai funzioni anche se ci sono errori non fatali
            extract_functions(tu.cursor, all_functions, file_path)
            
        except Exception as e:
            print(f"[ERROR] Exception parsing {file_path}: {e}")
    
    print(f"\n[INFO] Total functions found: {len(set(v['qualified_name'] if isinstance(v, dict) else v for v in all_functions.values()))}")
    
    # Seconda passata: estrai le chiamate
    print("\n=== PHASE 2: Extracting function calls ===")
    for file_path in cpp_files:
        args = [
            "-std=c++17",
            "-w",
            "-xc++",
        ] + [f"-I{p}" for p in include_paths]
        
        try:
            index = cindex.Index.create()
            options = cindex.TranslationUnit.PARSE_INCOMPLETE
            tu = index.parse(file_path, args=args, options=options)
            
            # Per ogni funzione in questo file, trova le sue chiamate
            for func_name, func_info in all_functions.items():
                if isinstance(func_info, dict) and func_info['file'] == file_path:
                    qualified_name = func_info['qualified_name']
                    # Cerca il nodo della funzione nel TU corrente
                    for node in tu.cursor.walk_preorder():
                        if node.kind in [cindex.CursorKind.FUNCTION_DECL,
                                        cindex.CursorKind.CXX_METHOD] and \
                           get_qualified_name(node) == qualified_name:
                            find_calls(node, qualified_name, call_graph, all_functions)
                            break
            
        except Exception as e:
            print(f"[ERROR] Failed analyzing calls in {file_path}: {e}")
    
    # Trova le call chains verso la funzione target
    chains = find_call_chains_to_target(call_graph, target, all_functions)
    
    return dict(call_graph), chains, all_functions


def find_call_chains_to_target(call_graph, target, all_functions):
    """
    Trova tutte le call chains che portano alla funzione target usando BFS.
    """
    # Trova tutte le possibili varianti del nome target
    target_names = set()
    target_names.add(target)
    
    for func_name, func_info in all_functions.items():
        if isinstance(func_info, dict):
            if func_info['simple_name'] == target or target in func_info['qualified_name']:
                target_names.add(func_info['qualified_name'])
    
    print(f"\n=== PHASE 3: Finding call chains to {target} ===")
    print(f"[INFO] Target variations: {target_names}")
    
    # Trova tutti i caller diretti del target
    direct_callers = []
    for caller, callees in call_graph.items():
        for call_info in callees:
            if any(t in call_info['callee'] or call_info['callee'] in t for t in target_names):
                direct_callers.append({
                    'caller': caller,
                    'callee': call_info['callee'],
                    'location': call_info['location']
                })
                print(f"[CHAIN] Direct: {caller} -> {call_info['callee']} @ {call_info['location']}")
    
    if not direct_callers:
        print("[WARNING] No direct callers found for target function")
        return []
    
    # BFS per trovare catene più lunghe (max depth per evitare esplosione)
    MAX_DEPTH = 10
    MAX_CHAINS = 1000
    all_chains = []
    
    for direct in direct_callers:
        # Ogni catena parte dal target
        initial_chain = [direct['caller'], direct['callee']]
        visited_in_chain = set(initial_chain)
        
        # BFS per questa catena specifica
        queue = deque([(initial_chain, direct['caller'], visited_in_chain, 1)])
        chains_from_this_direct = []
        
        while queue and len(chains_from_this_direct) < MAX_CHAINS:
            chain, current, visited, depth = queue.popleft()
            
            # Aggiungi questa catena
            if chain not in chains_from_this_direct:
                chains_from_this_direct.append(list(chain))
            
            # Se abbiamo raggiunto la profondità massima, ferma l'esplorazione
            if depth >= MAX_DEPTH:
                continue
            
            # Cerca chi chiama current
            found_caller = False
            for caller, callees in call_graph.items():
                if caller in visited:
                    continue
                    
                for call_info in callees:
                    if current == call_info['callee'] or current in call_info['callee']:
                        # Evita cicli
                        if caller not in visited:
                            new_chain = [caller] + chain
                            new_visited = visited | {caller}
                            queue.append((new_chain, caller, new_visited, depth + 1))
                            found_caller = True
        
        all_chains.extend(chains_from_this_direct)
        
        if len(all_chains) >= MAX_CHAINS:
            print(f"[WARNING] Reached maximum number of chains ({MAX_CHAINS}), stopping search")
            break
    
    # Rimuovi duplicati mantenendo l'ordine
    unique_chains = []
    seen = set()
    for chain in all_chains:
        chain_tuple = tuple(chain)
        if chain_tuple not in seen:
            seen.add(chain_tuple)
            unique_chains.append(chain)
    
    print(f"[INFO] Found {len(unique_chains)} unique call chains (max depth: {MAX_DEPTH})")
    
    # Mostra alcune statistiche
    if unique_chains:
        lengths = [len(c) for c in unique_chains]
        print(f"[INFO] Chain length stats: min={min(lengths)}, max={max(lengths)}, avg={sum(lengths)/len(lengths):.1f}")
        
        # Mostra le prime 5 catene più corte
        print(f"[INFO] Sample of shortest chains:")
        sorted_chains = sorted(unique_chains, key=len)
        for i, chain in enumerate(sorted_chains[:5]):
            print(f"  {i+1}. {' -> '.join(chain)}")
    
    return unique_chains


def save_to_json(call_graph, chains, all_functions, output_file):
    """
    Salva il grafo e le catene in formato JSON arricchito.
    """
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    
    enriched_chains = []
    for chain in chains:
        chain_info = []
        for func_name in chain:
            func_data = all_functions.get(func_name)
            if isinstance(func_data, dict):
                file_path = func_data.get('file')
                line = func_data.get('line', 0)
                code = ""
                if file_path:
                    # Prova a ottenere l'estensione della funzione dal nodo AST
                    node = func_data.get('node')
                    if node and node.extent.end.line:
                        code = extract_function_code(file_path, node.extent.start.line, node.extent.end.line)
                    else:
                        code = extract_function_code(file_path, max(1, line - 5), line + 10)
                chain_info.append({
                    "function": func_name,
                    "file": file_path,
                    "line": line,
                    "code": code.strip()
                })
            else:
                chain_info.append({
                    "function": func_name,
                    "file": None,
                    "line": None,
                    "code": "// Function info not found"
                })
        enriched_chains.append(chain_info)
    
    # Statistiche sulle chains
    chain_stats = {}
    if chains:
        lengths = [len(c) for c in chains]
        chain_stats = {
            'total_chains': len(chains),
            'min_length': min(lengths),
            'max_length': max(lengths),
            'avg_length': sum(lengths) / len(lengths)
        }
    
    data = {
        "target_function": TARGET_FUNCTION,
        "statistics": chain_stats,
        "chains_enriched": enriched_chains,
        "call_graph": {
            "total_functions": len(call_graph),
            "total_calls": sum(len(v) for v in call_graph.values()),
        }
    }
    
    enriched_file = output_file.replace(".json", "_enriched.json")
    with open(enriched_file, "w") as f:
        json.dump(data, f, indent=2)
    
    print(f"[JSON] Saved enriched call chains to {enriched_file}")


def extract_function_code(file_path, start_line, end_line):
    """Estrae il codice sorgente di una funzione da un file."""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        # Limita le righe per sicurezza
        snippet = lines[max(0, start_line-5):min(len(lines), end_line+5)]
        return "".join(snippet)
    except Exception as e:
        return f"// [ERROR] Could not extract code: {e}"


def upload_to_neo4j(call_graph):
    """
    Carica il grafo su Neo4j.
    """
    try:
        graph = Graph(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))
        graph.delete_all()
        
        for caller, calls in call_graph.items():
            caller_node = Node("Function", name=caller)
            graph.merge(caller_node, "Function", "name")
            
            for call_info in calls:
                callee_node = Node("Function", name=call_info["callee"])
                graph.merge(callee_node, "Function", "name")
                
                rel = Relationship(
                    caller_node, "CALLS", callee_node,
                    location=call_info["location"],
                    line=call_info.get("line", 0)
                )
                graph.merge(rel)
        
        print("[NEO4J] Uploaded graph successfully.")
    except Exception as e:
        print(f"[NEO4J ERROR] Failed to upload: {e}")


# === MAIN ===

if __name__ == "__main__":
    print(f"=== Call Chain Analyzer ===")
    print(f"Target Function: {TARGET_FUNCTION}")
    print(f"Repository: {REPO_PATH}")
    print()
    
    # Verifica preliminare
    if not os.path.exists(REPO_PATH):
        print(f"[FATAL ERROR] Repository path does not exist: {REPO_PATH}")
        exit(1)
    
    # Lista alcuni file per debug
    print("[DEBUG] First 10 files in repository:")
    count = 0
    for root, dirs, files in os.walk(REPO_PATH):
        for f in files:
            print(f"  - {os.path.join(root, f)}")
            count += 1
            if count >= 10:
                break
        if count >= 10:
            break
    print()
    
    call_graph, chains, all_functions = build_call_graph(REPO_PATH, TARGET_FUNCTION)
    
    # Debug: mostra alcune funzioni trovate
    if all_functions:
        print("\n[DEBUG] Sample of functions found:")
        for i, (name, info) in enumerate(list(all_functions.items())[:20]):
            if isinstance(info, dict):
                print(f"  - {name} @ {info['file']}:{info['line']}")
            if i >= 20:
                break
    
    # Cerca se la funzione target esiste
    print(f"\n[DEBUG] Searching for target function: {TARGET_FUNCTION}")
    found_target = False
    possible_matches = []
    
    for name, info in all_functions.items():
        if isinstance(info, dict):
            # Cerca match esatti o parziali
            if TARGET_FUNCTION in name or name in TARGET_FUNCTION:
                print(f"  FOUND: {name} in {info['file']}:{info['line']}")
                found_target = True
            # Cerca anche match case-insensitive o parziali
            elif TARGET_FUNCTION.lower() in name.lower():
                possible_matches.append((name, info))
    
    if possible_matches and not found_target:
        print(f"  Possible matches (case-insensitive):")
        for name, info in possible_matches[:10]:
            print(f"    - {name} in {info['file']}:{info['line']}")
    
    #if not found_target and not possible_matches:
    #    print(f"  WARNING: Target function '{TARGET_FUNCTION}' not found in codebase!")
    #    print(f"  Searching in file contents...")
        
        # Cerca direttamente nei file
    #    for file_path in cpp_files:
    #        try:
    #            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
    #                content = f.read()
    #                if TARGET_FUNCTION in content:
    #                    print(f"    Found '{TARGET_FUNCTION}' in {file_path}")
                        # Mostra le righe dove appare
    #                    lines = content.split('\n')
    #                    for i, line in enumerate(lines, 1):
    #                        if TARGET_FUNCTION in line:
    #                            print(f"      Line {i}: {line.strip()[:100]}")
    #        except Exception as e:
    #            pass
        
        print(f"  This might be:")
        print(f"    - An inline function in a header")
        print(f"    - A macro")
        print(f"    - A template function")
        print(f"    - Defined in a file that failed to parse")
    
    save_to_json(call_graph, chains, all_functions, OUTPUT_JSON)
    upload_to_neo4j(call_graph)
    
    print(f"\n=== Summary ===")
    print(f"Total functions: {len(set(v['qualified_name'] if isinstance(v, dict) else str(v) for v in all_functions.values()))}")
    print(f"Total calls: {sum(len(v) for v in call_graph.values())}")
    print(f"Call chains to target: {len(chains)}")