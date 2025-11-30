import os
from tree_sitter import Language, Parser

# === CONFIG ===
try:
    import tree_sitter_cpp as tscpp
    CPP_LANGUAGE = Language(tscpp.language())
except ImportError:
    raise ImportError("Install tree-sitter-cpp with: pip install tree-sitter tree-sitter-cpp")

class CppContextAnalyzer:
    def __init__(self):
        self.parser = Parser(CPP_LANGUAGE)

    def parse_file(self, file_path):
        """Parse a C++ file (.cpp or .h) and extract structured information."""
        with open(file_path, "rb") as f:
            code_bytes = f.read()
        code = code_bytes.decode("utf-8", errors="ignore")
        tree = self.parser.parse(code_bytes)
        root = tree.root_node

        includes = self._extract_includes(root, code)
        macros = self._extract_macros(root, code)
        globals_ = self._extract_globals(root, code)
        functions = self._extract_functions(root, code, file_path)

        return {
            "file": file_path,
            "includes": includes,
            "macros": macros,
            "globals": globals_,
            "functions": functions
        }

    # ----------------------------------------------------------------
    #  FILE-LEVEL EXTRACTION
    # ----------------------------------------------------------------
    def _extract_includes(self, root, code):
        includes = []
        for node in self._walk(root, "preproc_include"):
            includes.append(code[node.start_byte:node.end_byte].strip())
        return includes

    def _extract_macros(self, root, code):
        macros = []
        for node in self._walk(root, "preproc_def"):
            macros.append(code[node.start_byte:node.end_byte].strip())
        return macros

    def _extract_globals(self, root, code):
        """Extract top-level variables or constants."""
        globals_ = []
        for node in root.children:
            if node.type in ("declaration", "init_declarator") and not self._is_inside_function(node):
                snippet = code[node.start_byte:node.end_byte]
                globals_.append(snippet.strip())
        return globals_

    # ----------------------------------------------------------------
    #  FUNCTION-LEVEL EXTRACTION
    # ----------------------------------------------------------------
    def _extract_functions(self, root, code, file_path):
        """Extract all top-level (non-nested) functions and their contextual information."""
        functions = []
        for func_node in self._walk(root, "function_definition"):
            if self._is_inside_function(func_node):
                continue
            if func_node.parent and func_node.parent.type in ("lambda_expression", "declaration", "call_expression"):
                continue

            func_info = self._extract_function_info(func_node, code, file_path, root)
            if func_info:
                functions.append(func_info)
        return functions

    def _extract_function_info(self, func_node, code, file_path, root):
        """Extract one function’s details (parameters, calls, returns, etc.)."""
        func_name = self._get_function_name(func_node, code)
        if not func_name:
            return None
        
        # Skip malformed functions (no body or no braces) #TEST
        body = next((c for c in func_node.children if c.type == "compound_statement"), None)
        if not body:
            return None

        # Ottieni la gerarchia dei container (namespace, classi, struct)
        container = self._get_container_context(func_node, root, code)

        # Crea nome qualificato completo
        qualified_name = f"{container}::{func_name}" if container else func_name

        # Estrai parametri, chiamate, valori di ritorno
        params = self._get_parameters(func_node, code)
        calls = self._get_call_expressions(func_node, code)
        returns = self._get_return_values(func_node, code)

        start_line = func_node.start_point[0] + 1
        end_line = func_node.end_point[0] + 1

        func_code = code[func_node.start_byte:func_node.end_byte].strip()

        return {
            "name": func_name,
            "qualified_name": qualified_name,
            "container": container,
            "parameters": params,
            "calls": calls,
            "returns": returns,
            "start_line": start_line,
            "end_line": end_line,
            "snippet": func_code,
            "file": file_path
        }


    # ----------------------------------------------------------------
    #  FUNCTION DETAILS
    # ----------------------------------------------------------------
    def _get_function_name(self, func_node, code):
        for child in func_node.children:
            if child.type == "function_declarator":
                for sub in child.children:
                    if sub.type in ("identifier", "field_identifier", "qualified_identifier"):
                        return code[sub.start_byte:sub.end_byte].strip()
        return None

    def _get_container_context(self, node, root, code):
        """Recursively find surrounding namespace/class definitions."""
        context = []
        current = node
        while current.parent:
            parent = current.parent
            if parent.type in ("class_specifier", "namespace_definition", "struct_specifier"):
                name_node = next((c for c in parent.children if c.type == "type_identifier" or c.type == "identifier"), None)
                if name_node:
                    context.append(code[name_node.start_byte:name_node.end_byte])
            current = parent
        return "::".join(reversed(context)) if context else None

    def _get_parameters(self, func_node, code):
        params = []
        for param_node in self._walk(func_node, "parameter_declaration"):
            snippet = code[param_node.start_byte:param_node.end_byte].strip()
            params.append(snippet)
        return params

    def _get_call_expressions(self, func_node, code: str):
        calls = []
        for call_node in self._walk(func_node, "call_expression"):
            callee = self._extract_callee_name(call_node, code)
            args = self._extract_arguments(call_node, code)
            calls.append({
                "callee": callee,
                "args": args,
                "line": call_node.start_point[0] + 1
            })
        return calls
    
    def _extract_callee_name(self, call_node, code: str) -> str:
        """
        Estrae il nome/descrizione del callee in modo robusto.
        - Prova a trovare identifier / qualified_identifier / field_identifier.
        - Se non trova, prende il nodo immediatamente precedente ad argument_list
          e restituisce lo snippet testuale (fallback utile per chained calls/lambda/etc.)
        """
        # 1) cerca identifier-like direttamente tra i figli
        for child in call_node.children:
            if child.type in ("identifier", "field_identifier", "qualified_identifier", "scoped_identifier"):
                return code[child.start_byte:child.end_byte].strip()

        # 2) se un figlio è 'member_expression' o 'field_expression', usa lo snippet pulito
        for child in call_node.children:
            if child.type in ("member_expression", "field_expression", "nested_expression"):
                s = code[child.start_byte:child.end_byte].strip()
                # rimuovi eventuale argument list residua
                if "(" in s:
                    s = s.split("(", 1)[0].strip()
                return s

        # 3) fallback: prendi il figlio immediatamente prima di argument_list (se presente)
        arg_index = None
        for i, child in enumerate(call_node.children):
            if child.type == "argument_list":
                arg_index = i
                break
        if arg_index is not None and arg_index > 0:
            candidate = call_node.children[arg_index - 1]
            snippet = code[candidate.start_byte:candidate.end_byte].strip()
            if snippet:
                # rimuovi le parentesi se presenti
                if "(" in snippet:
                    snippet = snippet.split("(", 1)[0].strip()
                return snippet

        # 4) ultimo fallback: tutto il testo del call_node fino alla '('
        try:
            s = code[call_node.start_byte:call_node.end_byte]
            if "(" in s:
                s = s.split("(", 1)[0].strip()
            s = s if s else None
            return s
        except Exception:
            return None


    def _extract_arguments(self, call_node, code: str):
        """
        Estrae gli argomenti dal nodo call_expression:
        - preferisce leggere il nodo 'argument_list' e ricostruire gli argomenti a partire dai figli,
          evitando split testuali non affidabili quando possibile.
        - fallback: estrazione testuale centrale (rimuove parentesi esterne).
        """
        args = []

        # Prima cerca il nodo argument_list esplicito
        for child in call_node.children:
            if child.type == "argument_list":
                # costruisci argomenti guardando i figli del nodo
                # i figli tipici: '(', expr, ',', expr, ')'
                current = []
                for node in child.children:
                    text = code[node.start_byte:node.end_byte]
                    if node.type == ",":
                        # separatore: chiudi l'arg corrente
                        arg = "".join(current).strip()
                        if arg:
                            args.append(arg)
                        current = []
                    elif node.type in ("(", ")"):
                        continue
                    else:
                        current.append(text)
                # ultima arg
                if current:
                    arg = "".join(current).strip()
                    if arg:
                        args.append(arg)
                return args

        # Se non c'è argument_list, fai fallback testuale: estrai testo dentro le prime parentesi
        try:
            s = code[call_node.start_byte:call_node.end_byte]
            if "(" in s and ")" in s:
                inner = s.split("(", 1)[1].rsplit(")", 1)[0]
                # semplice split ma rimuove spazi esterni; non perfetto per template con virgole, ma ok come fallback
                parts = [p.strip() for p in inner.split(",")]
                args = [p for p in parts if p != ""]
        except Exception:
            args = []

        return args
    

    #def _get_return_values(self, func_node, code):
    #    returns = []
    #    for ret_node in self._walk(func_node, "return_statement"):
    #        snippet = code[ret_node.start_byte:ret_node.end_byte].strip()
    #        returns.append(snippet)
    #    return returns
    
    def _get_return_values(self, func_node, code: str):
        returns = []
        for ret_node in self._walk(func_node, "return_statement"):
            # Ignora i return dentro lambda o funzioni locali
            if self._is_within_nested_function(ret_node, func_node):
                continue
            start = code[:ret_node.start_byte].count("\n") + 1
            snippet = code[ret_node.start_byte:ret_node.end_byte].strip()
            returns.append(snippet)
        return returns

    def _is_within_nested_function(self, node, parent_func):
        """
        True se 'node' si trova dentro un'altra funzione o lambda rispetto al 'parent_func'.
        """
        current = node.parent
        while current is not None and current != parent_func:
            if current.type in ("function_definition", "lambda_expression"):
                return True
            current = current.parent
        return False


    # ----------------------------------------------------------------
    #  UTILS
    # ----------------------------------------------------------------
    def _walk(self, root, node_type):
        """Yield all nodes of a given type."""
        results = []
        stack = [root]
        while stack:
            node = stack.pop()
            if node.type == node_type:
                results.append(node)
            stack.extend(node.children)
        return results

    def _is_inside_function(self, node):
        """Check if a node is inside a function definition."""
        cur = node.parent
        while cur:
            if cur.type == "function_definition":
                return True
            cur = cur.parent
        return False
