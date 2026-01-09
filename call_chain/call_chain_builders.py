import os
import json
from pathlib import Path
from snippet_slicer_cpp.extract_infos import CppContextAnalyzer
import sys

class GlobalCallChainBuilder:
    """
    Costruisce tutte le catene di chiamate nel repository.
    Usa le informazioni dei callee presenti nelle funzioni estratte da CppContextAnalyzer.
    """
    def __init__(self, analyzer: CppContextAnalyzer):
        self.analyzer = analyzer
        self.functions = []
        self.func_index = {}
        self.callee_to_callers = {}
        self.repo_path = None
        self.suffix_index = {}

    # -------------------------------------------------------------------------
    # Costruzione database
    # -------------------------------------------------------------------------
    def build_function_db(self, repo_path: str):
        cpp_exts = {".cpp", ".cc", ".cxx", ".c++", ".hpp", ".h", ".hh", ".hxx"}
        self.repo_path = Path(repo_path)
        print(f"[INFO] Scanning repository: {self.repo_path}")

        for root, _, files in os.walk(self.repo_path):
            for file in files:
                if Path(file).suffix.lower() in cpp_exts:
                    fpath = Path(root) / file
                    try:
                        parsed = self.analyzer.parse_file(str(fpath))
                        self.functions.extend(parsed["functions"])
                    except Exception as e:
                        print(f"[WARN] Failed parsing {fpath}: {e}")

        self.func_index = {
            f["qualified_name"]: f
            for f in self.functions if f.get("qualified_name")
        }

        #OTTIMIZZAZIONE, MAPPING ------------

        for f in self.functions:
            q = self._normalize_name(f["qualified_name"])
            parts = q.split("::")
            short = parts[-1]
            self.suffix_index.setdefault(short, []).append(f)


        print(f"[INFO] Indexed {len(self.functions)} functions.")
        self._build_reverse_call_index()

    #def _build_reverse_call_index(self):
    #    self.callee_to_callers = {}

#        for func in self.functions:
#            caller_name = func["qualified_name"]
#            caller_file = func["file"]
#
#            for call in func.get("calls", []):
#                callee_raw = call.get("callee") or ""
#                callee_norm = self._normalize_name(callee_raw)
#                num_args = len(call.get("args", []))

                # aggiungi entry per nome breve
#                self.callee_to_callers.setdefault(callee_norm, []).append({
#                    "caller": caller_name,
#                    "file": caller_file,
#                    "line": call.get("line"),
#                    "num_args": num_args,
#                    "callee_raw": callee_raw,
#                })

                # aggiungi entry per ogni funzione che matcha il callee
#                for f in self.functions:
#                    q = self._normalize_name(f["qualified_name"])
#                    if q.endswith(callee_norm):
#                        self.callee_to_callers.setdefault(q, []).append({
#                            "caller": caller_name,
#                            "file": caller_file,
#                            "line": call.get("line"),
#                            "num_args": num_args,
#                            "callee_raw": callee_raw,
#                        })

    def _build_reverse_call_index(self):
        for func in self.functions:
            caller_name = func["qualified_name"]

            for call in func.get("calls", []):
                callee = call["callee"]
                callee_norm = self._normalize_name(callee)
                short = callee_norm.split("::")[-1]

                # lookup diretto
                for f in self.suffix_index.get(short, []):
                    self.callee_to_callers.setdefault(f["qualified_name"], []).append({
                        "caller": caller_name,
                        "line": call["line"],
                        "num_args": len(call.get("args", [])),
                        "callee_raw": callee,
                    })

    
    # -------------------------------------------------------------------------
    # Normalizzazione & matching & utility
    # -------------------------------------------------------------------------
    def progress_bar(current, total, width=40):
        """Stampa una progress bar in-place."""
        ratio = current / total
        filled = int(ratio * width)
        bar = "█" * filled + "-" * (width - filled)
        sys.stdout.write(f"\r[{bar}] {current}/{total} ({ratio*100:.1f}%)")
        sys.stdout.flush()
    
    
    def _normalize_name(self, name: str) -> str:
        """Uniforma i nomi dei callee (->, ., ::)."""
        if not name:
            return ""
        name = name.strip().replace("->", "::").replace(".", "::")
        while "::::" in name:
            name = name.replace("::::", "::")
        return name.strip(":")

    def _find_function_match(self, callee_name: str):
        key = callee_name.split("::")[-1]
        candidates = self.suffix_index.get(key, [])
        if not candidates:
            return None

        best = max(candidates, key=lambda f: len(f["qualified_name"]))
        return best

    # -------------------------------------------------------------------------
    # Ricorsione con controllo visited locale (backtracking)
    # -------------------------------------------------------------------------
    def _recurse_callers(self, func_name, visited, depth, max_depth):
        """
        Ricorsione: trova chi chiama `func_name` fino a max_depth.
        - func_name: canonical qualified_name (es "A::B::foo")
        - visited: set di canonical names già visti nel ramo (backtracking: si copia per i sotto-rami)
        """
        if depth > max_depth:
            return []
        if func_name in visited:
            # ciclo rilevato nel ramo corrente -> evita esplorare oltre
            # (debug opzionale)
            # print(f"[DEBUG] Cycle avoided in branch: {func_name}")
            return []

        # norma per cercare callers nell'indice reverse
        func_norm = self._normalize_name(func_name)

        visited.add(func_name)
        chains = []

        callers = self.callee_to_callers.get(func_norm, [])
        if not callers:
            # nessun caller -> catena termina con il func_name canonico
            return [[func_name]]

        for caller_info in callers:
            # caller_info['caller'] è probabilmente canonical (come lo abbiamo salvato)
            matched = self._find_function_match(caller_info["caller"])
            if not matched:
                # non siamo riusciti a risolvere il caller ad una definizione canonica
                # termina il ramo qui (ma mantieni il func corrente)
                chains.append([func_name])
                continue

            caller_name = matched["qualified_name"]
            # se il caller è lo stesso del callee, evita auto-loop
            if caller_name == func_name:
                # evita cicli auto-referenti
                continue

            # backtracking: copia visited per il sotto-ramo
            visited_branch = visited.copy()

            sub_chains = self._recurse_callers(
                caller_name, visited_branch, depth + 1, max_depth
            )

            for chain in sub_chains:
                chains.append(chain + [func_name])

        return chains


    # -------------------------------------------------------------------------
    # Generazione call chain globale
    # -------------------------------------------------------------------------
    def build_all_call_chains(self, max_depth=3):
        """Costruisce tutte le catene per tutte le funzioni del database."""
        all_chains = []
        print(f"[INFO] Building call chains for {len(self.functions)} functions (max_depth={max_depth})...")

        for i, func in enumerate(self.functions):
            if i % 1 == 0:
                print(f"[INFO] Processing {i}/{len(self.functions)}")

            # usa il qualified_name canonico così com'è (non la versione normalizzata)
            qname = func.get("qualified_name") or func.get("name")
            if not qname:
                continue

            raw_chains = self._recurse_callers(qname, set(), 0, max_depth)

            # Normalizza i risultati: ogni chain è lista di canonical names.
            # Filtra le chain per cui l'ultimo elemento corrisponde al target canonico.
            # Rimuovi duplicati (set di tuple).
            unique = set()
            kept = []
            for chain in raw_chains:
                if not chain:
                    continue
                # assicurati che la chain termini con il target canonico
                if chain[-1] != qname:
                    # scarta chain errate / ambigue che non finiscono col target preciso
                    continue
                t = tuple(chain)
                if t in unique:
                    continue
                unique.add(t)
                kept.append(chain)

            if kept:
                all_chains.append({
                    "target_function": qname,
                    "file": func["file"],
                    "lines": f"{func['start_line']}-{func['end_line']}",
                    "num_chains": len(kept),
                    "chains": [
                        {
                            "call_sequence": c,
                            "length": len(c),
                            "snippets": [
                                {
                                    "qualified_name": fn,
                                    "snippet": self.func_index.get(fn, {}).get("snippet", "")[:600],
                                    "file": self.func_index.get(fn, {}).get("file"),
                                    "lines": f"{self.func_index.get(fn, {}).get('start_line', '?')}-{self.func_index.get(fn, {}).get('end_line', '?')}"
                                }
                                for fn in c if fn in self.func_index
                            ]
                        }
                        for c in kept
                    ]
                })

        print(f"[INFO]Built {len(all_chains)} total call chain entries.")
        return all_chains

    # -------------------------------------------------------------------------
    # Export JSON
    # -------------------------------------------------------------------------
    def export_all_call_chains(self, output_path: str, max_depth=6):
        all_chains = self.build_all_call_chains(max_depth)
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(all_chains, f, indent=2, ensure_ascii=False)
        print(f"[+] Exported call chains to {output_path}")
        return all_chains


# -------------------------------------------------------------------------
# MAIN
# -------------------------------------------------------------------------
def main():
    CVE = "CVE-2022-40673"
    repo_name = "src"
    repo_path = "/home/michele/Desktop/ricerca/output_repos_cpp/CVE-2022-40673/repo/src"
    output_path = f"/home/michele/Desktop/ricerca/agents/local_tier_evaluation_framework/call_chains/{CVE}/{repo_name}.json"   #TO-DO = REPONAME

    analyzer = CppContextAnalyzer()
    builder = GlobalCallChainBuilder(analyzer)

    builder.build_function_db(repo_path)
    builder.export_all_call_chains(output_path, max_depth=3)


if __name__ == "__main__":
    main()