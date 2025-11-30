#!/usr/bin/env python3
import os
import sys
import json
import tree_sitter_cpp as tscpp
from tree_sitter import Language, Parser

# Nuova API (tree-sitter >= 0.22): usa il modulo tree-sitter-cpp
CPP_LANGUAGE = Language(tscpp.language())

def extract_functions_from_cpp(file_path):
    parser = Parser()
    parser.language = CPP_LANGUAGE
    
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        source_code = f.read()
    
    tree = parser.parse(bytes(source_code, "utf8"))
    root = tree.root_node
    
    functions = []
    
    def visit(node):
        if node.type == "function_definition":
            start_line = node.start_point[0] + 1
            end_line = node.end_point[0] + 1
            num_lines = end_line - start_line + 1
            
            snippet = "\n".join(
                source_code.splitlines()[start_line - 1:end_line]
            )
            
            # Trova il nome della funzione
            name_node = None
            for child in node.children:
                if child.type == "function_declarator":
                    for c in child.children:
                        if c.type == "identifier":
                            name_node = c
                            break
            
            func_name = name_node.text.decode("utf-8") if name_node else "unknown"
            
            # Firma: tutto fino alla '{'
            body_node = node.child_by_field_name("body")
            if body_node:
                signature = source_code[node.start_byte:body_node.start_byte].strip()
            else:
                signature = source_code[node.start_byte:node.end_byte].strip()
            
            functions.append({
                "signature": signature,
                "function_name": func_name,
                "start_line": start_line,
                "end_line": end_line,
                "num_lines": num_lines,
                "file": os.path.basename(file_path),
                "path": os.path.abspath(file_path),
                "snippet": snippet
            })
        
        for child in node.children:
            visit(child)
    
    visit(root)
    return functions

def save_to_json(data, file_path):
    base_name = os.path.basename(file_path)
    output_file = f"{base_name}.json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
    return output_file

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python extract_cpp_functions_ts.py <file_cpp>")
        sys.exit(1)
    
    input_file = sys.argv[1]
    functions = extract_functions_from_cpp(input_file)
    output = save_to_json(functions, input_file)
    print(f"Funzioni estratte da '{input_file}' e salvate in '{output}'")