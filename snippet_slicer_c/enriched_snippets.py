import os
import json
from pathlib import Path
from typing import List, Dict, Optional, Set
from extract_infos import CContextAnalyzer


class FunctionDatabase:
    """Database in memoria per funzioni C con capacita di query e enrichment."""

    def __init__(self):
        self.functions = []
        self.file_data = {}
        self.analyzer = CContextAnalyzer()

    def build_from_repo(self, repo_path: str):
        """Scansiona ricorsivamente una repository e costruisce il database."""
        repo_path = Path(repo_path)
        c_extensions = {".c", ".h", ".i", ".inc"}

        print(f"Scanning repository: {repo_path}")

        for root, dirs, files in os.walk(repo_path):
            for file in files:
                if Path(file).suffix in c_extensions:
                    file_path = Path(root) / file
                    try:
                        self._index_file(str(file_path))
                    except Exception as e:
                        print(f"Error parsing {file_path}: {e}")

        print(f"Database built: {len(self.functions)} functions indexed from {len(self.file_data)} files")

    def _index_file(self, file_path: str):
        """Analizza un file e aggiunge le sue funzioni al database."""
        data = self.analyzer.parse_file(file_path)

        self.file_data[file_path] = {
            "includes": data["includes"],
            "macros": data["macros"],
            "globals": data["globals"]
        }

        for func in data["functions"]:
            self.functions.append(func)

    def query_function(self, callee_name: str, num_params: Optional[int] = None,
                   calling_file: Optional[str] = None, debug: bool = False) -> List[Dict]:
        """Query per trovare funzioni che matchano un callee."""
        matches = []
        if not callee_name:
            return []

        callee_name = callee_name.strip()
        normalized_name = self._normalize_callee(callee_name)
        method_name = normalized_name.split("::")[-1]

        if debug:
            print(f"\n{'='*60}")
            print("DEBUG Query:")
            print(f"  Original callee: {callee_name}")
            print(f"  Normalized: {normalized_name}")
            print(f"  Method name: {method_name}")
            print(f"  Num params: {num_params}")
            print(f"  Calling file: {calling_file}")
            print(f"{'='*60}\n")

        candidates_checked = 0
        for func in self.functions:
            func_name = func.get("name", "")
            qname = func.get("qualified_name", "")
            container = func.get("container", "")

            if method_name and func_name == method_name:
                candidates_checked += 1
                if debug:
                    fixed_count, is_variadic, is_unknown = self._get_param_match_info(func.get("parameters"))
                    print(f"Candidate #{candidates_checked}:")
                    print(f"  func_name: {func_name}")
                    print(f"  qualified_name: {qname}")
                    print(f"  container: {container}")
                    print(f"  file: {func.get('file', 'N/A')}")
                    if is_unknown:
                        print(f"  params: unknown (variadic={is_variadic})")
                    else:
                        print(f"  params: {fixed_count} (variadic={is_variadic})")

            if not self._name_matches_full(normalized_name, func_name, qname, container, method_name):
                continue

            if num_params is not None and not self._params_match(func, num_params):
                if debug and func_name == method_name:
                    fixed_count, is_variadic, is_unknown = self._get_param_match_info(func.get("parameters"))
                    if is_unknown:
                        print("  [REJECTED] params mismatch (unknown)")
                    else:
                        print(f"  [REJECTED] params mismatch ({fixed_count} != {num_params}, variadic={is_variadic})")
                continue

            score = self._calculate_match_score(func, calling_file, normalized_name)
            matches.append((score, func))

            if debug and func_name == method_name:
                print(f"  [MATCHED] Score: {score}")

        if debug:
            print(f"\nTotal candidates checked: {candidates_checked}")
            print(f"Total matches: {len(matches)}\n")

        matches.sort(key=lambda x: x[0], reverse=True)
        return [f for _, f in matches]

    def _normalize_callee(self, callee_name: str) -> str:
        """Normalizza una chiamata."""
        name = callee_name.strip()
        import re
        name = re.sub(r"<[^>]*>", "", name)
        name = name.replace("->", "::").replace(".", "::")
        while "::::" in name:
            name = name.replace("::::", "::")
        return name.strip(":")

    def _name_matches_full(self, search_name: str, func_name: str, qname: str,
                        container: Optional[str], method_name: str) -> bool:
        """Confronta un nome chiamato con il database."""
        if not search_name:
            return False

        if search_name == qname or search_name == func_name:
            return True

        if qname and search_name in qname:
            return True

        if container:
            full_name = f"{container}::{func_name}"
            if search_name in full_name or full_name.endswith(search_name):
                return True

        if method_name and func_name == method_name:
            if container or "::" in search_name:
                return True

        parts = search_name.split("::")
        if len(parts) > 1 and func_name == parts[-1]:
            return True

        return False

    def _calculate_match_score(self, func: Dict, calling_file: Optional[str],
                               callee_name: str) -> float:
        """Calcola score per ordinare i match."""
        score = 0.0
        func_file = func["file"]

        if calling_file and func_file == calling_file:
            score += 10.0

        if calling_file:
            calling_stem = Path(calling_file).stem
            func_stem = Path(func_file).stem

            if calling_stem == func_stem:
                score += 5.0

            if Path(calling_file).parent == Path(func_file).parent:
                score += 2.0

        if "::" in callee_name and func.get("container"):
            namespace_parts = callee_name.split("::")[:-1]
            if any(part in func["container"] for part in namespace_parts):
                score += 3.0

        num_params, _, is_unknown = self._get_param_match_info(func.get("parameters"))
        if not is_unknown:
            if num_params == 0:
                score += 1.0
            elif num_params <= 2:
                score += 0.5

        return score

    def _get_param_match_info(self, params):
        if params is None:
            return None, False, True
        if not params:
            return 0, False, False
        fixed = 0
        is_variadic = False
        for param in params:
            if isinstance(param, str) and param.strip() == "...":
                is_variadic = True
            else:
                fixed += 1
        return fixed, is_variadic, False

    def _params_match(self, func: Dict, num_params: int) -> bool:
        fixed_count, is_variadic, is_unknown = self._get_param_match_info(func.get("parameters"))
        if is_unknown:
            return True
        if is_variadic:
            return num_params >= fixed_count
        return fixed_count == num_params

    def get_enriched_snippet(self, func: Dict, max_depth: int = 1,
                        visited: Optional[Set[str]] = None, debug: bool = False) -> Dict:
        """
        Crea uno snippet arricchito con contesto per una funzione.
        """
        if visited is None:
            visited = set()

        func_id = func.get("qualified_name", func["name"])

        if debug:
            print(f"\n{'*'*60}")
            print(f"[ENRICHMENT START] Function: {func_id}")
            print(f"  max_depth: {max_depth}")
            print(f"  visited: {visited}")
            print(f"{'*'*60}")

        if func_id in visited:
            if debug:
                print(f"[WARN] CYCLIC REFERENCE DETECTED for {func_id}")
            return {
                "function_name": func["name"],
                "container": func.get("container"),
                "file": func["file"],
                "lines": f"{func['start_line']}-{func['end_line']}",
                "snippet": func["snippet"],
                "note": "cyclic_reference_detected"
            }

        visited.add(func_id)

        if debug:
            print(f"[OK] Added {func_id} to visited set")

        file_path = func["file"]
        file_info = self.file_data.get(file_path, {})

        macros_used = self._get_used_macros(func, file_info.get("macros", []))
        globals_used = self._get_used_globals(func, file_info.get("globals", []))

        enriched = {
            "function_name": func["name"],
            "container": func.get("container"),
            "file": file_path,
            "lines": f"{func['start_line']}-{func['end_line']}",
            "snippet": func["snippet"],
            "includes": file_info.get("includes", []),
            "macros_used": macros_used,
            "globals_used": globals_used,
            "called_functions": []
        }

        called_funcs_snippets = []
        resolved_called_ids = set()

        if debug:
            print(f"\nChecking max_depth: {max_depth}")

        if max_depth > 0:
            calls_list = func.get("calls", [])

            if debug:
                print("\n[CALLS PROCESSING]")
                print(f"  Found {len(calls_list)} calls to process")
                print(f"  Calls: {calls_list}")

            for i, call in enumerate(calls_list):
                callee_name = call["callee"]
                num_args = len(call["args"])

                if debug:
                    print(f"\n  --- Call #{i+1}/{len(calls_list)} ---")
                    print(f"  Callee: {callee_name}")
                    print(f"  Args: {num_args}")

                matches = self.query_function(callee_name, num_args, file_path, debug=debug)

                if debug:
                    print(f"  Query returned {len(matches)} matches")

                if matches:
                    called_func = matches[0]
                    called_func_id = called_func.get("qualified_name", called_func["name"])

                    if called_func_id in resolved_called_ids:
                        if debug:
                            print(f"  [WARN] Duplicate resolved callee detected, skipping: {called_func_id}")
                        continue

                    if debug:
                        print(f"  [OK] Best match: {called_func.get('qualified_name')}")
                        print(f"  Recursing with max_depth={max_depth-1}")

                    sub_enriched = self.get_enriched_snippet(
                        called_func,
                        max_depth=max_depth-1,
                        visited=visited,
                        debug=debug
                    )

                    if debug:
                        print("  Returned from recursion")
                        print(f"  sub_enriched is None: {sub_enriched is None}")
                        if sub_enriched:
                            print(f"  sub_enriched keys: {list(sub_enriched.keys())}")
                            print(f"  sub_enriched has 'note': {'note' in sub_enriched}")

                    if sub_enriched:
                        enriched["called_functions"].append({
                            "call_info": call,
                            "resolved": True,
                            "details": sub_enriched
                        })
                        called_funcs_snippets.append(called_func)
                        resolved_called_ids.add(called_func_id)

                        if debug:
                            print("  [OK] Added to called_functions")
                    else:
                        if debug:
                            print("  [WARN] sub_enriched was None, not adding")
                else:
                    if debug:
                        print("  [MISS] No matches found - marking as library/external")

                    enriched["called_functions"].append({
                        "call_info": call,
                        "resolved": False,
                        "reason": "library_or_external"
                    })
        else:
            if debug:
                print("[WARN] max_depth is 0, skipping call processing")

        enriched["contextual_snippet"] = self._build_contextual_snippet(
            func,
            file_info.get("includes", []),
            macros_used,
            globals_used,
            called_funcs_snippets
        )

        if debug:
            print(f"\n[ENRICHMENT END] {func_id}")
            print(f"  Total called_functions: {len(enriched['called_functions'])}")
            print(f"{'*'*60}\n")

        return enriched

    def _get_used_macros(self, func: Dict, macros: List[str]) -> List[str]:
        """Trova le macro usate nella funzione."""
        snippet = func["snippet"]
        used = []

        for macro in macros:
            parts = macro.split()
            if len(parts) >= 2 and parts[0] == "#define":
                macro_name = parts[1].split("(")[0]
                import re
                pattern = r"\b" + re.escape(macro_name) + r"\b"
                if re.search(pattern, snippet):
                    used.append(macro)

        return used

    def _get_used_globals(self, func: Dict, globals_list: List[str]) -> List[str]:
        """Trova le variabili globali usate nella funzione."""
        snippet = func["snippet"]
        used = []

        for global_var in globals_list:
            var_name = self._extract_var_name(global_var)
            if var_name:
                import re
                pattern = r"\b" + re.escape(var_name) + r"\b"
                if re.search(pattern, snippet):
                    used.append(global_var)

        return used

    def _extract_var_name(self, declaration: str) -> Optional[str]:
        """Estrae il nome di una variabile da una dichiarazione."""
        import re

        decl = declaration.rstrip(";").strip()

        if "=" in decl:
            decl = decl.split("=")[0].strip()

        if "[" in decl:
            decl = decl.split("[")[0].strip()

        tokens = re.findall(r"\b[a-zA-Z_][a-zA-Z0-9_]*\b", decl)

        if tokens:
            keywords = {"const", "static", "extern", "volatile", "mutable",
                       "int", "char", "float", "double", "void", "bool",
                       "short", "long", "unsigned", "signed"}

            for token in reversed(tokens):
                if token not in keywords:
                    return token

        return None

    def _build_contextual_snippet(self, func: Dict, includes: List[str],
                              macros: List[str], globals_: List[str],
                              called_funcs: List[Dict]) -> str:
        """Costruisce lo snippet contestuale."""
        lines = []

        if includes:
            for inc in includes:
                lines.append(inc)
            lines.append("")

        if macros:
            for macro in macros:
                lines.append(macro)
            lines.append("")

        if globals_:
            for glob in globals_:
                lines.append(glob if glob.endswith(";") else glob + ";")
            lines.append("")

        snippet = func["snippet"]
        lines.append(snippet)

        return "\n".join(lines)

    def export_enriched_snippets_eval(self, base_output_path: str, repo_path: str, cve_id: str, max_depth: int = 1):
        """Esporta gli snippet arricchiti organizzati per CVE/Repo/File."""
        from collections import defaultdict
        import re

        repo_path = Path(repo_path).resolve()
        repo_name = repo_path.name if repo_path.name != "repo" else repo_path.parent.name

        print(f"Organizing snippets for CVE: {cve_id}, Repo: {repo_name}")

        functions_by_file = defaultdict(list)
        for func in self.functions:
            functions_by_file[func["file"]].append(func)

        print(f"Found {len(functions_by_file)} unique files with functions")

        total_functions = 0
        for file_path, funcs in functions_by_file.items():
            file_path_obj = Path(file_path)

            try:
                rel_path = file_path_obj.relative_to(repo_path)
                file_identifier = str(rel_path).replace("/", "_").replace("\\", "_")
            except ValueError:
                file_identifier = file_path_obj.name

            file_identifier = re.sub(r"[^\w\-_]", "_", file_identifier.replace(".", "_"))

            output_dir = Path(base_output_path) / cve_id / repo_name / file_identifier
            output_dir.mkdir(parents=True, exist_ok=True)

            enriched_data = []
            print(f"\n  Processing file: {file_path} ({len(funcs)} functions)")

            for func in funcs:
                enriched = self.get_enriched_snippet(func, max_depth=max_depth)
                if enriched:
                    enriched_data.append(enriched)

            snippets_path = output_dir / "enriched_snippets.json"
            with open(snippets_path, "w", encoding="utf-8") as f:
                json.dump(enriched_data, f, indent=2, ensure_ascii=False)

            info_data = {
                "cve_id": cve_id,
                "repo_name": repo_name,
                "repo_path": str(repo_path),
                "analyzed_file": str(file_path),
                "relative_path": str(rel_path) if "rel_path" in locals() else None,
                "num_functions": len(enriched_data),
                "function_names": [f["function_name"] for f in enriched_data],
                "max_depth": max_depth
            }

            info_path = output_dir / "info.json"
            with open(info_path, "w", encoding="utf-8") as f:
                json.dump(info_data, f, indent=2, ensure_ascii=False)

            total_functions += len(enriched_data)
            print(f"    Saved {len(enriched_data)} functions")

        print(f"\n{'='*60}")
        print("Export completed!")
        print(f"  CVE: {cve_id}")
        print(f"  Total functions: {total_functions}")
        print(f"  Output: {Path(base_output_path) / cve_id / repo_name}")
        print(f"{'='*60}")


def main():

    CVE_FILE = "CVE-2021-3658"
    repo_path = "/home/michele/Desktop/ricerca/output_repos_c_ICV/CVE-2021-3658/repo/src"
    output_path = "/home/michele/Desktop/ricerca/output_repos_c/CVE-2019-15900/repo"
    base_output = "/home/michele/Desktop/ricerca/agents/local_tier_evaluation_framework/enriched_snippets_c"
    DEBUG = False

    db = FunctionDatabase()
    db.build_from_repo(repo_path)

    if DEBUG:
        db.export_enriched_snippets(output_path, max_depth=1)
    else:
        db.export_enriched_snippets_eval(base_output, repo_path, CVE_FILE, max_depth=1)

    print("\n" + "="*60)
    print("Database ready for queries!")
    print("="*60)


if __name__ == "__main__":
    main()
