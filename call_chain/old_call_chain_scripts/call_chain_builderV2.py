import os
import json
from clang import cindex
from py2neo import Graph
from collections import defaultdict

# === CONFIG ===
cindex.Config.set_library_file("/usr/lib/llvm-14/lib/libclang.so")

TARGET_FUNCTION = "capnp::PipelineHook::getPipelinedCap"

NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASS = "password"

# --------------------------------------------------------------
# Utility per nomi e parsing
# --------------------------------------------------------------

def get_fully_qualified_name(cursor):
    """Restituisce il nome completo di una funzione (namespace::class::func)."""
    names = []
    c = cursor
    while c and c.kind != cindex.CursorKind.TRANSLATION_UNIT:
        if c.spelling:
            names.append(c.spelling)
        c = c.semantic_parent
    return "::".join(reversed(names))


def get_callee_name(node):
    """Estrae il nome della funzione chiamata da CALL_EXPR o MEMBER_REF_EXPR."""
    if node.kind == cindex.CursorKind.CALL_EXPR:
        for c in node.get_children():
            if c.kind == cindex.CursorKind.MEMBER_REF_EXPR:
                cls = c.semantic_parent.spelling if c.semantic_parent else ""
                return f"{cls}::{c.spelling}" if cls else c.spelling
        return node.displayname or node.spelling
    elif node.kind == cindex.CursorKind.MEMBER_REF_EXPR:
        cls = node.semantic_parent.spelling if node.semantic_parent else ""
        return f"{cls}::{node.spelling}" if cls else node.spelling
    return None


# --------------------------------------------------------------
# Ricorsione AST
# --------------------------------------------------------------

def visit_ast(node, current_func=None, call_graph=None, all_functions=None):
    if call_graph is None:
        call_graph = defaultdict(list)
    if all_functions is None:
        all_functions = {}

    # Se è una dichiarazione di funzione o metodo, aggiorna il contesto
    if node.kind in (cindex.CursorKind.FUNCTION_DECL, cindex.CursorKind.CXX_METHOD):
        current_func = get_fully_qualified_name(node)
        file_path = node.location.file.name if node.location.file else None
        all_functions[current_func] = {
            "file": file_path,
            "line": node.location.line,
            "node": node,
        }

    # Se è una chiamata di funzione
    if node.kind == cindex.CursorKind.CALL_EXPR:
        callee_name = get_callee_name(node)
        if callee_name and current_func:
            location = f"{node.location.file}:{node.location.line}" if node.location.file else "unknown"
            call_graph[current_func].append({
                "callee": callee_name,
                "file": node.location.file.name if node.location.file else None,
                "line": node.location.line
            })
            print(f"[CALL] {current_func} -> {callee_name}  @ {location}")

    # Ricorsione nei figli
    for c in node.get_children():
        visit_ast(c, current_func, call_graph, all_functions)

    return call_graph, all_functions


# --------------------------------------------------------------
# Costruzione Call-Graph globale
# --------------------------------------------------------------

def build_call_graph(repo_path):
    index = cindex.Index.create()
    call_graph = defaultdict(list)
    all_functions = {}

    for root, _, files in os.walk(repo_path):
        for f in files:
            if not f.endswith((".cpp", ".cc", ".cxx", ".h", ".hpp")):
                continue

            file_path = os.path.join(root, f)
            print(f"\n=== Parsing {file_path} ===")
            try:
                tu = index.parse(file_path, args=["-std=c++17", "-Wno-everything"])
            except Exception as e:
                print(f"✗ Failed to parse {file_path}: {e}")
                continue

            if not tu:
                print(f"✗ No translation unit for {file_path}")
                continue

            # Diagnostica
            for diag in tu.diagnostics:
                if diag.severity >= cindex.Diagnostic.Error:
                    print(f"  [ERROR] {diag.spelling}")
                elif diag.severity == cindex.Diagnostic.Warning:
                    print(f"  [WARN] {diag.spelling}")

            cg, funcs = visit_ast(tu.cursor)
            for k, v in cg.items():
                call_graph[k].extend(v)
            all_functions.update(funcs)

    return call_graph, all_functions


# --------------------------------------------------------------
# Ricostruzione delle catene
# --------------------------------------------------------------

def find_chains(call_graph, target):
    chains = []

    def dfs(current, path):
        if current == target:
            chains.append(list(path))
            return
        for call in call_graph.get(current, []):
            callee = call["callee"]
            if callee not in path:
                dfs(callee, path + [callee])

    for caller in call_graph:
        dfs(caller, [caller])

    return [c for c in chains if target in c]


# --------------------------------------------------------------
# Neo4j Upload (opzionale)
# --------------------------------------------------------------

def upload_to_neo4j(call_graph):
    try:
        graph = Graph(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))
        graph.run("RETURN 1")
        print("[NEO4J] Connected successfully.")
    except Exception as e:
        print(f"[NEO4J] Could not connect or upload: {e}")
        return

    graph.run("MATCH (n) DETACH DELETE n")  # pulizia
    for caller, calls in call_graph.items():
        for call in calls:
            callee = call["callee"]
            graph.run(
                """
                MERGE (a:Function {name:$caller})
                MERGE (b:Function {name:$callee})
                MERGE (a)-[:CALLS]->(b)
                """,
                caller=caller,
                callee=callee,
            )
    print("[NEO4J] Uploaded call graph.")


# --------------------------------------------------------------
# JSON Writer con codice
# --------------------------------------------------------------

def extract_function_code(file_path, start_line, end_line):
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
        snippet = lines[max(0, start_line-3):min(len(lines), end_line+3)]
        return "".join(snippet)
    except Exception:
        return "// [Code unavailable]"


def save_to_json(call_graph, chains, all_functions, output_file):
    os.makedirs(os.path.dirname(output_file), exist_ok=True)

    enriched_chains = []
    for chain in chains:
        chain_info = []
        for func in chain:
            func_data = all_functions.get(func, {})
            file_path = func_data.get("file")
            line = func_data.get("line", 0)
            code = ""
            if file_path and "node" in func_data:
                node = func_data["node"]
                if node.extent.start.line and node.extent.end.line:
                    code = extract_function_code(file_path, node.extent.start.line, node.extent.end.line)
            chain_info.append({
                "function": func,
                "file": file_path,
                "line": line,
                "code": code.strip(),
            })
        enriched_chains.append(chain_info)

    data = {
        "target_function": TARGET_FUNCTION,
        "total_functions": len(call_graph),
        "total_calls": sum(len(v) for v in call_graph.values()),
        "chains": enriched_chains,
    }

    out = output_file.replace(".json", "_enriched.json")
    with open(out, "w") as f:
        json.dump(data, f, indent=2)
    print(f"[JSON] Saved enriched output -> {out}")


# --------------------------------------------------------------
# MAIN
# --------------------------------------------------------------

if __name__ == "__main__":
    repo_path = os.path.abspath(".")
    call_graph, all_functions = build_call_graph(repo_path)
    chains = find_chains(call_graph, TARGET_FUNCTION)
    save_to_json(call_graph, chains, all_functions, "./output/call_chains.json")
    upload_to_neo4j(call_graph)
