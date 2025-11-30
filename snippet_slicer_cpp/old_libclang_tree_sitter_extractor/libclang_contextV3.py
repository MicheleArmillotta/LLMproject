


#IN THIS VERSION OF THE CONTEXT EXTRACTOR ALL THE ENTITIES
#ARE DESCRIBED IN "DEFINITIONS", BUT THE ENTITIES
#OF THE SAME FILE ARE ALSO INCLUDED IN THE "CONTEXTUAL SNIPPET"




#!/usr/bin/env python3
import json
import os
from clang import cindex

# === CONFIG ===
cindex.Config.set_library_file("/usr/lib/llvm-14/lib/libclang.so")


def get_qualified_name(cursor):
    names = []
    while cursor and cursor.kind != cindex.CursorKind.TRANSLATION_UNIT:
        if cursor.spelling:
            names.append(cursor.spelling)
        cursor = cursor.semantic_parent
    return "::".join(reversed(names))


def collect_hierarchy(cursor):
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
    if not cursor or not cursor.location.file:
        return None
    file_path = cursor.location.file.name
    start_line = cursor.extent.start.line
    end_line = cursor.extent.end.line
    try:
        with open(file_path, encoding="utf-8", errors="ignore") as f:
            lines = f.read().splitlines()
        return "\n".join(lines[start_line - 1 : end_line])
    except Exception as e:
        print(f"    ERROR reading snippet from {file_path}: {e}")
        return None


def extract_container_context(cursor):
    if not cursor or not cursor.location.file:
        return None
    file_path = cursor.location.file.name
    start_line = cursor.extent.start.line
    end_line = cursor.extent.end.line
    try:
        with open(file_path, encoding="utf-8", errors="ignore") as f:
            lines = f.read().splitlines()
        full_content = "\n".join(lines[start_line - 1 : end_line])

        if cursor.kind in (cindex.CursorKind.CLASS_DECL, cindex.CursorKind.STRUCT_DECL):
            brace_pos = full_content.find("{")
            if brace_pos == -1:
                return full_content.strip()
            header = full_content[: brace_pos + 1].strip()
            context_parts = [header]
            for child in cursor.get_children():
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
                        if "{" in member_snippet:
                            member_snippet = member_snippet.split("{")[0].strip() + ";"
                        context_parts.append("  " + member_snippet)
            context_parts.append("  // ... metodi omessi ...")
            context_parts.append("};")
            return "\n".join(context_parts)

        return full_content
    except Exception as e:
        print(f"    ERROR reading context from {file_path}: {e}")
        return None


def collect_used_entities(cursor):
    used = []
    seen = set()

    def visit(node):
        for c in node.get_children():
            if c.kind in (
                cindex.CursorKind.DECL_REF_EXPR,
                cindex.CursorKind.MEMBER_REF_EXPR,
                cindex.CursorKind.CALL_EXPR,
            ):
                ref = c.referenced if c.referenced else c
                qname = get_qualified_name(ref)
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
            visit(c)

    visit(cursor)
    return sorted(used, key=lambda x: (x["file"], x["line"]))


def parse_files_with_includes(main_file, imports, args):
    index = cindex.Index.create()
    tus = {}
    header_dirs = set([os.path.dirname(os.path.abspath(main_file))])
    for header in imports:
        if os.path.isabs(header):
            header_dirs.add(os.path.dirname(header))
        else:
            header_path = os.path.join(os.path.dirname(main_file), header)
            if os.path.exists(header_path):
                header_dirs.add(os.path.dirname(os.path.abspath(header_path)))
    full_args = args + [f"-I{d}" for d in header_dirs] + [
        "-Wno-everything",
        "-ferror-limit=100",
    ]
    main_tu = index.parse(
        main_file,
        args=full_args,
        options=cindex.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD
        | cindex.TranslationUnit.PARSE_INCOMPLETE,
    )
    tus[main_file] = main_tu
    for header in imports:
        header_path = (
            header if os.path.isabs(header) else os.path.join(os.path.dirname(main_file), header)
        )
        if os.path.exists(header_path):
            tu = index.parse(
                header_path,
                args=full_args,
                options=cindex.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD,
            )
            tus[header_path] = tu
    return tus


def extract_definitions_from_tus(tus):
    defs = {}
    for path, tu in tus.items():
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
                if qn and qn not in defs:
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
    return defs


def find_project_includes(main_file):
    include_dirs = []
    current = os.path.dirname(os.path.abspath(main_file))
    for _ in range(5):
        for dirname in ["src", "include", "c++/src"]:
            candidate = os.path.join(current, dirname)
            if os.path.isdir(candidate):
                include_dirs.append(candidate)
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
    return include_dirs


def extract_context(main_file, imports):
    project_includes = find_project_includes(main_file)
    args = [
        "-std=c++17",
        "-x",
        "c++",
        "-I/usr/include",
        "-I/usr/local/include",
    ] + [f"-I{inc}" for inc in project_includes]

    tus = parse_files_with_includes(main_file, imports, args)
    definitions = extract_definitions_from_tus(tus)
    main_tu = tus[main_file]
    results = []
    fid = 0

    for cursor in main_tu.cursor.walk_preorder():
        if (
            cursor.location.file
            and cursor.location.file.name == main_file
            and cursor.kind in (cindex.CursorKind.CXX_METHOD, cindex.CursorKind.FUNCTION_DECL)
        ):
            hierarchy = collect_hierarchy(cursor)
            used_entities = collect_used_entities(cursor)

            contextual_parts = []
            added_qnames = set()

            # 1. Containers
            for h in hierarchy:
                if h["full_name"] in definitions and h["full_name"] not in added_qnames:
                    contextual_parts.append(definitions[h["full_name"]]["definition"])
                    added_qnames.add(h["full_name"])

            # 2. Local used entities (stesso file)
            for e in used_entities:
                qn = e["qualified_name"]
                if (
                    qn in definitions
                    and definitions[qn]["file"] == main_file
                    and qn not in added_qnames
                ):
                    contextual_parts.append(definitions[qn]["definition"])
                    added_qnames.add(qn)

            # 3. Main function
            main_func = extract_code_snippet(cursor)
            if main_func:
                contextual_parts.append(main_func)

            # External definitions (TUTTE, anche quelle locali)
            used_definitions = {}
            for e in used_entities:
                qn = e["qualified_name"]
                if qn in definitions:
                    used_definitions[qn] = definitions[qn]

            results.append(
                {
                    "id": fid,
                    "function_name": cursor.spelling,
                    "qualified_name": get_qualified_name(cursor),
                    "start_line": cursor.extent.start.line,
                    "end_line": cursor.extent.end.line,
                    "num_lines": cursor.extent.end.line - cursor.extent.start.line + 1,
                    "containing_classes": hierarchy,
                    "used_entities": [e["qualified_name"] for e in used_entities],
                    "contextual_snippet": "\n\n".join(contextual_parts),
                    "definitions": used_definitions,
                }
            )
            fid += 1

    return results


if __name__ == "__main__":
    import sys
    import json

    if len(sys.argv) < 3:
        print("Usage: python cpp_context_extractor_ordered.py <file.cpp> <import1.h> [<import2.h> ...]")
        sys.exit(1)

    file_path = sys.argv[1]
    imports = sys.argv[2:]

    print(f"Main file: {file_path}")
    print(f"Imports: {imports}")

    # Chiamata alla funzione principale
    data = extract_context(file_path, imports)

    # ✅ Stampa su stdout invece di salvare su file
    print(json.dumps(data, indent=2, ensure_ascii=False))
