import os
from tree_sitter import Language, Parser

# === CONFIG ===
try:
    import tree_sitter_c as tsc
    C_LANGUAGE = Language(tsc.language())
except ImportError:
    raise ImportError("Install tree-sitter-c with: pip install tree-sitter tree-sitter-c")


class CContextAnalyzer:
    def __init__(self):
        self.parser = Parser(C_LANGUAGE)

    def parse_file(self, file_path):
        """Parse a C file (.c or .h) and extract structured information."""
        with open(file_path, "rb") as f:
            code_bytes = f.read()
        tree = self.parser.parse(code_bytes)
        root = tree.root_node

        includes = self._extract_includes(root, code_bytes)
        macros = self._extract_macros(root, code_bytes)
        globals_ = self._extract_globals(root, code_bytes)
        functions = self._extract_functions(root, code_bytes, file_path)
        functions.extend(self._extract_syscall_macros(code_bytes, file_path))

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
    def _extract_includes(self, root, code_bytes):
        includes = []
        for node in self._walk(root, "preproc_include"):
            includes.append(self._node_text(code_bytes, node).strip())
        return includes

    def _extract_macros(self, root, code_bytes):
        macros = []
        for node in self._walk(root, "preproc_def"):
            macros.append(self._node_text(code_bytes, node).strip())
        return macros

    def _extract_globals(self, root, code_bytes):
        """Extract top-level variables or constants."""
        globals_ = []
        for node in root.children:
            if node.type in ("declaration", "init_declarator") and not self._is_inside_function(node):
                snippet = self._node_text(code_bytes, node)
                globals_.append(snippet.strip())
        return globals_

    # ----------------------------------------------------------------
    #  FUNCTION-LEVEL EXTRACTION
    # ----------------------------------------------------------------
    def _extract_functions(self, root, code_bytes, file_path):
        """Extract all top-level (non-nested) functions and their contextual information."""
        functions = []
        for func_node in self._walk(root, "function_definition"):
            if self._is_inside_function(func_node):
                continue
            if func_node.parent and func_node.parent.type in ("declaration", "call_expression"):
                continue

            func_info = self._extract_function_info(func_node, code_bytes, file_path, root)
            if func_info:
                functions.append(func_info)
        return functions

    def _extract_function_info(self, func_node, code_bytes, file_path, root):
        """Extract one function's details (parameters, calls, returns, etc.)."""
        func_name_full = self._get_function_name(func_node, code_bytes)
        if not func_name_full:
            return None

        body = next((c for c in func_node.children if c.type == "compound_statement"), None)
        if not body:
            return None

        func_name = func_name_full
        container = None
        qualified_name = func_name

        params = self._get_parameters_direct(func_node, code_bytes)
        calls = self._get_call_expressions(func_node, code_bytes)
        returns = self._get_return_values(func_node, code_bytes)

        start_line = func_node.start_point[0] + 1
        end_line = func_node.end_point[0] + 1

        func_code = self._node_text(code_bytes, func_node).strip()

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
    def _get_function_name(self, func_node, code_bytes):
        """Ottiene il nome della funzione C."""
        declarator = self._get_function_declarator(func_node)
        if not declarator:
            return None
        name_node = self._find_declarator_identifier(declarator)
        if name_node:
            return self._node_text(code_bytes, name_node).strip()
        return None

    def _get_function_declarator(self, func_node):
        declarator = func_node.child_by_field_name("declarator")
        if declarator:
            if declarator.type == "function_declarator":
                return declarator
            matches = self._walk(declarator, "function_declarator")
            if matches:
                return matches[0]
        for child in func_node.children:
            if child.type == "function_declarator":
                return child
        return None

    def _find_declarator_identifier(self, declarator):
        target = declarator.child_by_field_name("declarator")
        if target:
            return self._find_identifier(target)
        return self._find_identifier(declarator)

    def _find_identifier(self, node, skip_types=None):
        if skip_types is None:
            skip_types = {"parameter_list", "identifier_list"}
        if node.type == "identifier":
            return node
        for child in node.children:
            if child.type in skip_types:
                continue
            found = self._find_identifier(child, skip_types=skip_types)
            if found:
                return found
        return None

    def _get_container_context(self, node, root, code):
        """No container context for C."""
        return None

    def _get_parameters_direct(self, func_node, code_bytes):
        """
        Estrae SOLO i parametri diretti della funzione.
        Cerca il nodo parameter_list che e figlio diretto del function_declarator.
        """
        declarator = self._get_function_declarator(func_node)
        if not declarator:
            return None

        param_list = None
        ident_list = None
        for child in declarator.children:
            if child.type == "parameter_list":
                param_list = child
                break
            if child.type == "identifier_list":
                ident_list = child

        if param_list:
            params, saw_any = self._extract_parameter_list(param_list, code_bytes)
            if not saw_any:
                return None
            return self._normalize_parameters(params)

        if ident_list:
            params = self._extract_identifier_list(ident_list, code_bytes)
            return params if params else None

        kr_params = self._extract_kr_parameters(func_node, code_bytes)
        return kr_params if kr_params else None

    def _extract_parameter_list(self, param_list, code_bytes):
        params = []
        saw_any = False
        for child in param_list.children:
            if child.type == "parameter_declaration":
                snippet = self._node_text(code_bytes, child).strip()
                if snippet:
                    params.append(snippet)
                    saw_any = True
            elif child.type in ("variadic_parameter", "ellipsis", "..."):
                params.append("...")
                saw_any = True
        return params, saw_any

    def _extract_identifier_list(self, ident_list, code_bytes):
        params = []
        for child in ident_list.children:
            if child.type == "identifier":
                snippet = self._node_text(code_bytes, child).strip()
                if snippet:
                    params.append(snippet)
        return params

    def _extract_kr_parameters(self, func_node, code_bytes):
        body = next((c for c in func_node.children if c.type == "compound_statement"), None)
        if not body:
            return None
        params = []
        for child in func_node.children:
            if child.type == "declaration" and child.start_byte < body.start_byte:
                snippet = self._node_text(code_bytes, child).strip()
                if snippet:
                    params.append(snippet)
        return params

    def _normalize_parameters(self, params):
        if len(params) == 1 and params[0].strip() == "void":
            return []
        return params

    def _get_parameters(self, func_node, code_bytes):
        """DEPRECATED: usare _get_parameters_direct invece."""
        params = []
        for param_node in self._walk(func_node, "parameter_declaration"):
            snippet = self._node_text(code_bytes, param_node).strip()
            params.append(snippet)
        return params

    def _get_call_expressions(self, func_node, code_bytes: bytes):
        calls = []
        for call_node in self._walk(func_node, "call_expression"):
            callee = self._extract_callee_name(call_node, code_bytes)
            args = self._extract_arguments(call_node, code_bytes)
            calls.append({
                "callee": callee,
                "args": args,
                "line": call_node.start_point[0] + 1
            })
        return calls

    def _extract_callee_name(self, call_node, code_bytes: bytes) -> str:
        """
        Estrae il nome/descrizione del callee in modo robusto.
        """
        for child in call_node.children:
            if child.type in ("identifier", "field_identifier"):
                return self._node_text(code_bytes, child).strip()

        for child in call_node.children:
            if child.type in ("member_expression", "field_expression", "nested_expression"):
                s = self._node_text(code_bytes, child).strip()
                if "(" in s:
                    s = s.split("(", 1)[0].strip()
                return s

        arg_index = None
        for i, child in enumerate(call_node.children):
            if child.type == "argument_list":
                arg_index = i
                break
        if arg_index is not None and arg_index > 0:
            candidate = call_node.children[arg_index - 1]
            snippet = self._node_text(code_bytes, candidate).strip()
            if snippet:
                if "(" in snippet:
                    snippet = snippet.split("(", 1)[0].strip()
                return snippet

        try:
            s = self._node_text(code_bytes, call_node)
            if "(" in s:
                s = s.split("(", 1)[0].strip()
            s = s if s else None
            return s
        except Exception:
            return None

    def _extract_arguments(self, call_node, code_bytes: bytes):
        """Estrae gli argomenti dal nodo call_expression."""
        args = []

        for child in call_node.children:
            if child.type == "argument_list":
                current = []
                for node in child.children:
                    text = self._node_text(code_bytes, node)
                    if node.type == ",":
                        arg = "".join(current).strip()
                        if arg:
                            args.append(arg)
                        current = []
                    elif node.type in ("(", ")"):
                        continue
                    else:
                        current.append(text)
                if current:
                    arg = "".join(current).strip()
                    if arg:
                        args.append(arg)
                return args

        try:
            s = self._node_text(code_bytes, call_node)
            if "(" in s and ")" in s:
                inner = s.split("(", 1)[1].rsplit(")", 1)[0]
                parts = [p.strip() for p in inner.split(",")]
                args = [p for p in parts if p != ""]
        except Exception:
            args = []

        return args

    def _get_return_values(self, func_node, code_bytes: bytes):
        returns = []
        for ret_node in self._walk(func_node, "return_statement"):
            if self._is_within_nested_function(ret_node, func_node):
                continue
            snippet = self._node_text(code_bytes, ret_node).strip()
            returns.append(snippet)
        return returns

    def _is_within_nested_function(self, node, parent_func):
        """True se 'node' si trova dentro un'altra funzione rispetto al 'parent_func'."""
        current = node.parent
        while current is not None and current != parent_func:
            if current.type == "function_definition":
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

    def _node_text(self, code_bytes, node, start=None, end=None):
        s = start if start is not None else node.start_byte
        e = end if end is not None else node.end_byte
        return code_bytes[s:e].decode("utf-8", errors="ignore")

    # ----------------------------------------------------------------
    #  SPECIAL CASES: SYSCALL_DEFINE* macros (kernel-style)
    # ----------------------------------------------------------------
    def _extract_syscall_macros(self, code_bytes: bytes, file_path: str):
        """
        Rileva macro SYSCALL_DEFINE* che generano funzioni ma non vengono viste
        come function_definition da tree-sitter (perché non c'è preprocessing).
        """
        import re

        text = code_bytes.decode("utf-8", errors="ignore")
        functions = []

        # pattern per SYSCALL_DEFINE, SYSCALL_DEFINE0, SYSCALL_DEFINE1, etc.
        pattern = re.compile(r"SYSCALL_DEFINE\d*\s*\(")

        for m in pattern.finditer(text):
            start = m.start()
            open_paren = text.find("(", start)
            if open_paren == -1:
                continue

            close_paren = self._find_matching(text, open_paren, "(", ")")
            if close_paren == -1:
                continue

            sig = text[open_paren + 1 : close_paren]
            parts = [p.strip() for p in sig.split(",")]
            if not parts:
                continue

            func_name = parts[0]
            params_raw = parts[1:]
            params = [p for p in params_raw if p]

            brace_pos = text.find("{", close_paren)
            if brace_pos == -1:
                continue
            body_end = self._find_matching(text, brace_pos, "{", "}")
            if body_end == -1:
                continue

            snippet = text[start : body_end + 1]
            start_line = text.count("\n", 0, start) + 1
            end_line = text.count("\n", 0, body_end) + 1

            functions.append({
                "name": func_name,
                "qualified_name": func_name,
                "container": None,
                "parameters": params,
                "calls": [],
                "returns": [],
                "start_line": start_line,
                "end_line": end_line,
                "snippet": snippet.strip(),
                "file": file_path
            })

        return functions

    def _find_matching(self, text: str, start: int, open_ch: str, close_ch: str) -> int:
        """
        Trova la parentesi/brace match considerando i caratteri annidati.
        Ignora in modo semplice stringhe e commenti per evitare falsi positivi.
        """
        depth = 0
        i = start
        n = len(text)
        in_sl_comment = False
        in_ml_comment = False
        in_str = False
        str_char = ""

        while i < n:
            ch = text[i]
            nxt = text[i + 1] if i + 1 < n else ""

            if in_sl_comment:
                if ch == "\n":
                    in_sl_comment = False
                i += 1
                continue
            if in_ml_comment:
                if ch == "*" and nxt == "/":
                    in_ml_comment = False
                    i += 2
                else:
                    i += 1
                continue
            if in_str:
                if ch == "\\" and nxt:
                    i += 2
                    continue
                if ch == str_char:
                    in_str = False
                i += 1
                continue

            if ch == "/" and nxt == "/":
                in_sl_comment = True
                i += 2
                continue
            if ch == "/" and nxt == "*":
                in_ml_comment = True
                i += 2
                continue
            if ch in ("'", '"'):
                in_str = True
                str_char = ch
                i += 1
                continue

            if ch == open_ch:
                depth += 1
            elif ch == close_ch:
                depth -= 1
                if depth == 0:
                    return i
            i += 1

        return -1
