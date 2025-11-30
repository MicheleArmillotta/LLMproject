#!/usr/bin/env python3


#THIS VERSION OF THE CONTEXT EXTRACTOR PUTS ALL THE ENTITIES
#IN "EXTERNAL DEFINITIONS", NO ENTITY IS IN THE CONTEXTUAL SNIPPET



import json
import os
from clang import cindex

# === CONFIG ===
cindex.Config.set_library_file("/usr/lib/llvm-14/lib/libclang.so")


def get_qualified_name(cursor):
    """Costruisce il nome qualificato completo (es. ns::Class::method)."""
    names = []
    while cursor and cursor.kind != cindex.CursorKind.TRANSLATION_UNIT:
        if cursor.spelling:
            names.append(cursor.spelling)
        cursor = cursor.semantic_parent
    return "::".join(reversed(names))


def collect_hierarchy(cursor):
    """Raccoglie le classi/struct che contengono la funzione."""
    hierarchy = []
    parent = cursor.semantic_parent
    while parent and parent.kind not in (
        cindex.CursorKind.TRANSLATION_UNIT,
        cindex.CursorKind.NAMESPACE,
    ):
        if parent.kind in (cindex.CursorKind.CLASS_DECL, cindex.CursorKind.STRUCT_DECL):
            hierarchy.append(
                {
                    "name": parent.spelling,
                    "full_name": get_qualified_name(parent),
                    "kind": "class"
                    if parent.kind == cindex.CursorKind.CLASS_DECL
                    else "struct",
                }
            )
        parent = parent.semantic_parent
    return list(reversed(hierarchy))


def extract_code_snippet(cursor):
    """Restituisce il codice di un cursore (funzione, struct, dichiarazione...)."""
    if not cursor or not cursor.location.file:
        return None
    file_path = cursor.location.file.name
    start_line = cursor.extent.start.line
    end_line = cursor.extent.end.line
    
    try:
        with open(file_path, encoding='utf-8', errors='ignore') as f:
            lines = f.read().splitlines()
        snippet = "\n".join(lines[start_line - 1 : end_line])
        return snippet
    except Exception as e:
        print(f"    ERROR: Could not read snippet from {file_path}: {e}")
        return None


def extract_container_context(cursor):
    """Estrae solo le dichiarazioni del contesto (struct/class) senza i metodi."""
    if not cursor or not cursor.location.file:
        return None
    
    file_path = cursor.location.file.name
    start_line = cursor.extent.start.line
    end_line = cursor.extent.end.line
    
    try:
        with open(file_path, encoding='utf-8', errors='ignore') as f:
            lines = f.read().splitlines()
        
        # Estrai tutto il contenuto
        full_content = "\n".join(lines[start_line - 1 : end_line])
        
        # Se è una class/struct, estrai solo la parte dichiarativa
        if cursor.kind in (cindex.CursorKind.CLASS_DECL, cindex.CursorKind.STRUCT_DECL):
            # Trova dove inizia il corpo (primo {)
            brace_pos = full_content.find('{')
            if brace_pos == -1:
                return full_content.strip()
            
            # Prendi intestazione + apertura
            header = full_content[:brace_pos+1].strip()
            
            # Estrai solo campi/membri (no metodi)
            context_parts = [header]
            
            for child in cursor.get_children():
                # Includi solo dichiarazioni di variabili, typedef, enums
                if child.kind in (
                    cindex.CursorKind.FIELD_DECL,
                    cindex.CursorKind.VAR_DECL,
                    cindex.CursorKind.TYPEDEF_DECL,
                    cindex.CursorKind.ENUM_DECL,
                    cindex.CursorKind.STRUCT_DECL,
                    cindex.CursorKind.CLASS_DECL,
                ):
                    member_snippet = extract_code_snippet(child)
                    if member_snippet:
                        # Se è una definizione inline, prendi solo la dichiarazione
                        if '{' in member_snippet:
                            member_snippet = member_snippet.split('{')[0].strip() + ';'
                        context_parts.append("  " + member_snippet)
            
            context_parts.append("  // ... metodi omessi ...")
            context_parts.append("};")
            return "\n".join(context_parts)
        
        return full_content
        
    except Exception as e:
        print(f"    ERROR: Could not read context from {file_path}: {e}")
        return None


def extract_declaration(snippet):
    """Estrae la dichiarazione da uno snippet (rimuove il corpo della funzione)."""
    if not snippet:
        return None
    if "{" in snippet:
        # mantieni solo la parte prima della definizione
        return snippet.split("{")[0].strip() + ";"
    return snippet.strip()


def collect_used_entities(cursor):
    """Raccoglie le entità usate (funzioni, variabili, membri) con posizione."""
    used = []
    seen = set()

    def visit(node, depth=0):
        for c in node.get_children():
            # Debug più dettagliato
            if c.kind in (
                cindex.CursorKind.DECL_REF_EXPR,
                cindex.CursorKind.MEMBER_REF_EXPR,
                cindex.CursorKind.CALL_EXPR,
            ):
                ref = c.referenced if c.referenced else c
                qname = get_qualified_name(ref)
                
                print(f"    {'  '*depth}Found reference: {c.kind} -> {qname}")
                
                if qname and qname not in seen:
                    seen.add(qname)
                    if ref.location.file:
                        used.append(
                            {
                                "cursor": ref,
                                "qualified_name": qname,
                                "kind": str(ref.kind),
                                "file": ref.location.file.name,
                                "line": ref.location.line,
                            }
                        )
                        print(f"    {'  '*depth}  -> Added: {qname} from {ref.location.file.name}:{ref.location.line}")
            visit(c, depth+1)

    print(f"  Collecting used entities in {cursor.spelling}...")
    visit(cursor)
    print(f"  -> Found {len(used)} unique entities")
    return sorted(used, key=lambda x: (x["file"], x["line"]))


def parse_files_with_includes(main_file, imports, args):
    """Crea TranslationUnit principale e indicizza anche gli header importati."""
    index = cindex.Index.create()
    tus = {}

    # Aggiungi le directory degli header agli include paths
    header_dirs = set()
    header_dirs.add(os.path.dirname(os.path.abspath(main_file)))
    
    for header in imports:
        if os.path.isabs(header):
            header_dirs.add(os.path.dirname(header))
        else:
            header_path = os.path.join(os.path.dirname(main_file), header)
            if os.path.exists(header_path):
                header_dirs.add(os.path.dirname(os.path.abspath(header_path)))
    
    # Aggiungi le directory ai flag di compilazione
    full_args = args + [f"-I{d}" for d in header_dirs]
    
    # Aggiungi flag per ridurre errori su header mancanti
    full_args.extend([
        "-Wno-everything",  # Disabilita tutti i warning
        "-ferror-limit=100",  # Limita gli errori
    ])
    
    print(f"\n=== Parsing {main_file} ===")
    print(f"Args: {full_args}\n")
    
    # Parse del file principale SENZA skip function bodies
    try:
        main_tu = index.parse(
            main_file, 
            args=full_args,
            options=cindex.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD |
                    cindex.TranslationUnit.PARSE_INCOMPLETE  # Tollera header mancanti
        )
        
        # Controlla diagnostics
        has_errors = False
        for diag in main_tu.diagnostics:
            if diag.severity >= cindex.Diagnostic.Error:
                print(f"ERROR: {diag.spelling}")
                if diag.location.file:
                    print(f"  at {diag.location.file.name}:{diag.location.line}:{diag.location.column}")
                has_errors = True
            elif diag.severity == cindex.Diagnostic.Warning:
                print(f"WARNING: {diag.spelling}")
        
        if has_errors:
            print("\n  Parsing completed with errors, results may be incomplete\n")
        else:
            print("Parsing successful\n")
        
        tus[main_file] = main_tu
        
    except Exception as e:
        print(f"FATAL: Failed to parse {main_file}: {e}")
        raise

    # Parse degli header
    for header in imports:
        if os.path.isabs(header):
            header_path = header
        else:
            header_path = os.path.join(os.path.dirname(main_file), header)
            
        if os.path.exists(header_path):
            try:
                print(f"Parsing header: {header_path}")
                tu = index.parse(
                    header_path, 
                    args=full_args,
                    options=cindex.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD
                )
                tus[header_path] = tu
                print(f"  ✓ Success\n")
            except Exception as e:
                print(f"  ✗ Could not parse: {e}\n")

    return tus


def extract_definitions_from_tus(tus):
    """Crea un dizionario {qualified_name: definizione completa} da tutti i TU."""
    print("=== Extracting definitions from all translation units ===")
    defs = {}
    for path, tu in tus.items():
        print(f"\nScanning {path}...")
        count = 0
        for c in tu.cursor.walk_preorder():
            if not c.spelling:
                continue
            if c.kind in (
                cindex.CursorKind.CXX_METHOD,
                cindex.CursorKind.FUNCTION_DECL,
                cindex.CursorKind.FUNCTION_TEMPLATE,
                cindex.CursorKind.VAR_DECL,
                cindex.CursorKind.FIELD_DECL,
                cindex.CursorKind.STRUCT_DECL,
                cindex.CursorKind.CLASS_DECL,
                cindex.CursorKind.TYPEDEF_DECL,
                cindex.CursorKind.ENUM_DECL,
            ):
                qn = get_qualified_name(c)
                if qn and qn not in defs:  # Non sovrascrivere
                    # Per struct/class, usa l'estrazione semplificata
                    if c.kind in (cindex.CursorKind.STRUCT_DECL, cindex.CursorKind.CLASS_DECL):
                        snippet = extract_container_context(c)
                    else:
                        snippet = extract_code_snippet(c)
                    
                    if snippet:
                        defs[qn] = {
                            "definition": snippet,
                            "file": c.location.file.name if c.location.file else None,
                            "line": c.location.line if c.location.file else None,
                            "kind": str(c.kind),
                        }
                        count += 1
        print(f"  -> Found {count} definitions")
    
    print(f"\n=== Total definitions collected: {len(defs)} ===\n")
    return defs


def find_project_includes(main_file):
    """Cerca le directory src/ e include/ nel progetto."""
    include_dirs = []
    current = os.path.dirname(os.path.abspath(main_file))
    
    # Risali fino a trovare la root del progetto o max 5 livelli
    for _ in range(5):
        # Cerca directory comuni
        for dirname in ['src', 'include', 'c++/src']:
            candidate = os.path.join(current, dirname)
            if os.path.isdir(candidate):
                include_dirs.append(candidate)
        
        parent = os.path.dirname(current)
        if parent == current:  # Raggiunta la root
            break
        current = parent
    
    return include_dirs


def extract_context(main_file, imports):
    # Trova automaticamente le directory del progetto
    project_includes = find_project_includes(main_file)
    
    # Argomenti base
    args = [
        "-std=c++17",
        "-x", "c++",
        "-I/usr/include",
        "-I/usr/local/include",
    ]
    
    # Aggiungi gli include del progetto
    for inc in project_includes:
        args.append(f"-I{inc}")
        print(f"Auto-detected project include: {inc}")
    
    tus = parse_files_with_includes(main_file, imports, args)
    definitions = extract_definitions_from_tus(tus)

    results = []
    main_tu = tus[main_file]

    id = 0

    print("=== Analyzing functions in main file ===\n")
    
    for cursor in main_tu.cursor.walk_preorder():
        if (
            cursor.location.file
            and cursor.location.file.name == main_file
            and cursor.kind in (
                cindex.CursorKind.CXX_METHOD,
                cindex.CursorKind.FUNCTION_DECL,
            )
        ):
            

            name = cursor.spelling
            print(f"\n--- Function: {name} ---")
            
            hierarchy = collect_hierarchy(cursor)
            print(f"  Hierarchy: {[h['name'] for h in hierarchy]}")
            
            used_entities = collect_used_entities(cursor)

            # Costruiamo il contextual snippet in ordine reale
            contextual_parts = []
            added_qnames = set()

            # 1. Contenitori (in ordine gerarchico) - SOLO struttura, no metodi
            for h in hierarchy:
                if h["full_name"] in definitions and h["full_name"] not in added_qnames:
                    # Cerca il cursore originale per estrarre il contesto corretto
                    container_def = definitions[h["full_name"]]
                    # Usa l'estrazione semplificata per i container
                    contextual_parts.append(container_def["definition"])
                    added_qnames.add(h["full_name"])

            # 2. NON includere le entità usate - vogliamo solo il contesto del container

            # 3. Funzione principale
            main_func = extract_code_snippet(cursor)
            if main_func:
                contextual_parts.append(main_func)

            # Estrai solo le definizioni delle entità usate
            used_definitions = {}
            for e in used_entities:
                qn = e["qualified_name"]
                if qn in definitions:
                    used_definitions[qn] = definitions[qn]

            results.append(
                {
                    "id": id,
                    "function_name": name,
                    "qualified_name": get_qualified_name(cursor),
                    "start_line": cursor.extent.start.line,
                    "end_line": cursor.extent.end.line,
                    "num_lines": cursor.extent.end.line - cursor.extent.start.line + 1,
                    "containing_classes": hierarchy,
                    "used_entities": [e["qualified_name"] for e in used_entities],
                    "contextual_snippet": "\n\n".join(
                        [p for p in contextual_parts if p]
                    ),
                    "definitions": used_definitions,
                }
            )
            id = id + 1
            print(f"  -> Collected {len(used_definitions)} definitions")

    return results

#if __name__ == "__main__":
#    import sys
#    import json
#
#    if len(sys.argv) < 3:
#        print("Usage: python cpp_context_extractor_ordered.py <file.cpp> <import1.h> [<import2.h> ...]")
#        sys.exit(1)
#
#    file_path = sys.argv[1]
#    imports = sys.argv[2:]
#
#    print(f"Main file: {file_path}")
#    print(f"Imports: {imports}")

    # Chiamata alla funzione principale
#    data = extract_context(file_path, imports)

    # ✅ Stampa su stdout invece di salvare su file
#    print(json.dumps(data, indent=2, ensure_ascii=False))