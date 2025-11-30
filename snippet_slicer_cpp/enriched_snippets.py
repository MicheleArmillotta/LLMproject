import os
import json
from pathlib import Path
from typing import List, Dict, Optional, Set
from extract_infos import CppContextAnalyzer


class FunctionDatabase:
    """Database in memoria per funzioni C++ con capacità di query e enrichment."""
    
    def __init__(self):
        self.functions = []  # Lista di tutti i record funzione
        self.file_data = {}  # Mappa file_path -> parsed data (includes, macros, globals)
        self.analyzer = CppContextAnalyzer()
    
    def build_from_repo(self, repo_path: str):
        """Scansiona ricorsivamente una repository e costruisce il database."""
        repo_path = Path(repo_path)
        cpp_extensions = {'.cpp', '.cc', '.cxx', '.c++', '.h', '.hpp', '.hxx'}
        
        print(f"Scanning repository: {repo_path}")
        
        for root, dirs, files in os.walk(repo_path):
            for file in files:
                if Path(file).suffix in cpp_extensions:
                    file_path = Path(root) / file
                    try:
                        self._index_file(str(file_path))
                    except Exception as e:
                        print(f"Error parsing {file_path}: {e}")
        
        print(f"Database built: {len(self.functions)} functions indexed from {len(self.file_data)} files")
    
    def _index_file(self, file_path: str):
        """Analizza un file e aggiunge le sue funzioni al database."""
        data = self.analyzer.parse_file(file_path)
        
        # Salva i dati a livello di file
        self.file_data[file_path] = {
            'includes': data['includes'],
            'macros': data['macros'],
            'globals': data['globals']
        }
        
        # Aggiungi ogni funzione al database
        for func in data['functions']:
            self.functions.append(func)
    
    def query_function(self, callee_name: str, num_params: Optional[int] = None, 
                       calling_file: Optional[str] = None) -> List[Dict]:
        """
        Query per trovare funzioni che matchano un callee, gestendo casi complessi:
        - "x->y", "x.y", "Namespace::Class::Func"
        - nome semplice o parziale
        """
        matches = []
        if not callee_name:
            return []

        callee_name = callee_name.strip()

        # Normalizza il nome (rimuove template, spazi doppi)
        normalized_name = self._normalize_callee(callee_name)

        for func in self.functions:
            # Nome e nome qualificato
            func_name = func.get('name', '')
            qname = func.get('qualified_name', '')
            container = func.get('container', '')

            # Match robusto su tutti i livelli
            if not self._name_matches_full(normalized_name, func_name, qname, container):
                continue

            # Controllo numero parametri (se fornito)
            if num_params is not None and len(func.get('parameters', [])) != num_params:
                continue

            score = self._calculate_match_score(func, calling_file, normalized_name)
            matches.append((score, func))

        matches.sort(key=lambda x: x[0], reverse=True)
        return [f for _, f in matches]
    

    def _normalize_callee(self, callee_name: str) -> str:
        """
        Normalizza una chiamata:
        - converte '.' e '->' in '::' per uniformità
        - rimuove template arguments (<T>)
        - rimuove doppi '::'
        """
        name = callee_name.strip()

        # Rimuovi argomenti di template
        import re
        name = re.sub(r'<[^>]*>', '', name)

        # Uniforma i separatori in stile C++
        name = name.replace('->', '::').replace('.', '::')

        # Rimuove doppi ::
        while '::::' in name:
            name = name.replace('::::', '::')

        return name.strip(':')
    

    def _name_matches_full(self, search_name: str, func_name: str, qname: str, container: Optional[str]) -> bool:
        """
        Confronta un nome chiamato (callee) con il database:
        - tenta match esatto su qualified_name
        - tenta match parziale (suffix) su namespace/class
        - tenta match semplice su nome base
        """
        if not search_name:
            return False

        # Esatto su qualified_name
        if search_name == qname:
            return True

        # Esatto su nome semplice
        if search_name == func_name:
            return True

        # Parziale su qualified_name o container
        if qname.endswith(search_name):
            return True

        if container:
            full_name = f"{container}::{func_name}"
            if full_name.endswith(search_name) or search_name in full_name:
                return True

        # Se il nome chiamante ha componenti (es. a::b::func), controlla se
        # la parte finale matcha il nome funzione
        parts = search_name.split('::')
        if parts and func_name == parts[-1]:
            return True

        return False
    
    
    def _calculate_match_score(self, func: Dict, calling_file: Optional[str], 
                               callee_name: str) -> float:
        """Calcola uno score euristico per ordinare i match."""
        score = 0.0
        
        func_file = func['file']
        
        # Stesso file = molto probabile
        if calling_file and func_file == calling_file:
            score += 10.0
        
        # Header corrispondente al file chiamante
        if calling_file:
            calling_stem = Path(calling_file).stem
            func_stem = Path(func_file).stem
            
            if calling_stem == func_stem:
                score += 5.0
            
            # Stesso directory
            if Path(calling_file).parent == Path(func_file).parent:
                score += 2.0
        
        # Match con namespace/container nel nome chiamante
        if '::' in callee_name:
            if func.get('container'):
                namespace_parts = callee_name.split('::')[:-1]
                if any(part in func['container'] for part in namespace_parts):
                    score += 3.0
        
        # Funzioni con meno parametri sono più comuni
        num_params = len(func['parameters'])
        if num_params == 0:
            score += 1.0
        elif num_params <= 2:
            score += 0.5
        
        return score
    
    def get_enriched_snippet(self, func: Dict, max_depth: int = 1, 
                            visited: Optional[Set[str]] = None) -> Dict:
        """
        Crea uno snippet arricchito con contesto per una funzione.
        
        Args:
            func: Record della funzione
            max_depth: Profondità massima di ricorsione per le chiamate
            visited: Set di funzioni già visitate (evita cicli)
        
        Returns:
            Dict con snippet arricchito
        """
        if visited is None:
            visited = set()
        
        func_id = f"{func['file']}::{func['name']}"
        if func_id in visited:
            return None
        visited.add(func_id)
        
        file_path = func['file']
        file_info = self.file_data.get(file_path, {})
        
        # Recupera macro e globals usate
        macros_used = self._get_used_macros(func, file_info.get('macros', []))
        globals_used = self._get_used_globals(func, file_info.get('globals', []))
        
        enriched = {
            'function_name': func['name'],
            'container': func.get('container'),
            'file': file_path,
            'lines': f"{func['start_line']}-{func['end_line']}",
            'snippet': func['snippet'],
            'includes': file_info.get('includes', []),
            'macros_used': macros_used,
            'globals_used': globals_used,
            'called_functions': []
        }
        
        # Aggiungi snippet delle funzioni chiamate
        called_funcs_snippets = []
        if max_depth > 0:
            for call in func.get('calls', []):
                callee_name = call['callee']
                num_args = len(call['args'])
                
                # Query per trovare la funzione chiamata
                matches = self.query_function(callee_name, num_args, file_path)
                
                if matches:
                    # Prendi il miglior match
                    called_func = matches[0]
                    
                    # Ricorsione per arricchire anche le funzioni chiamate
                    sub_enriched = self.get_enriched_snippet(
                        called_func, 
                        max_depth=max_depth-1, 
                        visited=visited
                    )
                    
                    if sub_enriched:
                        enriched['called_functions'].append({
                            'call_info': call,
                            'resolved': True,
                            'details': sub_enriched
                        })
                        called_funcs_snippets.append(called_func)
                else:
                    # Funzione di libreria o non trovata
                    enriched['called_functions'].append({
                        'call_info': call,
                        'resolved': False,
                        'reason': 'library_or_external'
                    })
        
        # Costruisci il contextual_snippet
        enriched['contextual_snippet'] = self._build_contextual_snippet(
            func, 
            file_info.get('includes', []),
            macros_used,
            globals_used,
            called_funcs_snippets
        )
        
        return enriched
    
    def _get_used_macros(self, func: Dict, macros: List[str]) -> List[str]:
        """Trova le macro usate nella funzione."""
        snippet = func['snippet']
        used = []
        
        for macro in macros:
            # Estrai il nome della macro (prima parola dopo #define)
            parts = macro.split()
            if len(parts) >= 2 and parts[0] == '#define':
                macro_name = parts[1].split('(')[0]  # Rimuovi parametri se c'è
                
                # Cerca il nome della macro come token (non sottostringa)
                # Usa word boundary per evitare match parziali
                import re
                pattern = r'\b' + re.escape(macro_name) + r'\b'
                if re.search(pattern, snippet):
                    used.append(macro)
        
        return used
    
    def _get_used_globals(self, func: Dict, globals_list: List[str]) -> List[str]:
        """Trova le variabili globali usate nella funzione."""
        snippet = func['snippet']
        used = []
        
        for global_var in globals_list:
            # Estrai il nome della variabile (ultima parola prima di ; o =)
            var_name = self._extract_var_name(global_var)
            if var_name:
                # Cerca il nome come token (non sottostringa)
                import re
                pattern = r'\b' + re.escape(var_name) + r'\b'
                if re.search(pattern, snippet):
                    used.append(global_var)
        
        return used
    
    def _extract_var_name(self, declaration: str) -> Optional[str]:
        """Estrae il nome di una variabile da una dichiarazione."""
        import re
        
        # Rimuovi ; finale e spazi
        decl = declaration.rstrip(';').strip()
        
        # Split su = se presente (prendi solo la parte di dichiarazione)
        if '=' in decl:
            decl = decl.split('=')[0].strip()
        
        # Rimuovi eventuali [] per array
        if '[' in decl:
            decl = decl.split('[')[0].strip()
        
        # Pattern per estrarre il nome della variabile
        # Cerca l'ultima parola che sia un identificatore valido
        # Ignora *, &, const, static, etc.
        tokens = re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', decl)
        
        if tokens:
            # L'ultimo token dovrebbe essere il nome della variabile
            # Ignora keyword comuni
            keywords = {'const', 'static', 'extern', 'volatile', 'mutable', 
                       'int', 'char', 'float', 'double', 'void', 'bool',
                       'short', 'long', 'unsigned', 'signed'}
            
            # Prendi l'ultimo token che non sia una keyword
            for token in reversed(tokens):
                if token not in keywords:
                    return token
        
        return None
    
    def _build_contextual_snippet(self, func: Dict, includes: List[str],
                              macros: List[str], globals_: List[str],
                              called_funcs: List[Dict]) -> str:
        """
        Costruisce lo snippet contestuale con la struttura richiesta:
        - includes
        - macros
        - globals
        - container hierarchy
        - function snippet
        - called functions (in appended sections)
        """
        lines = []

        # 1. Includes
        if includes:
            for inc in includes:
                lines.append(inc)
            lines.append("")  # riga vuota

        # 2. Macros
        if macros:
            for macro in macros:
                lines.append(macro)
            lines.append("")

        # 3. Globals
        if globals_:
            for glob in globals_:
                lines.append(glob if glob.endswith(';') else glob + ';')
            lines.append("")

        # 4. Container hierarchy + function
        container = func.get('container')
        snippet = func['snippet']

        if container:
            parts = container.split('::')
            indent = ""

            # apri container
            for part in parts:
                lines.append(f"{indent}{part} {{")
                indent += "  "

            # funzione
            for line in snippet.split('\n'):
                lines.append(f"{indent}{line}")

            # chiudi container
            for _ in range(len(parts)):
                indent = indent[:-2]
                lines.append(f"{indent}}}")

        else:
            lines.append(snippet)


        return "\n".join(lines)

    def export_enriched_snippets(self, output_path: str, max_depth: int = 1):
        """Esporta tutti gli snippet arricchiti in un file JSON."""
        enriched_data = []
        
        print(f"Generating enriched snippets for {len(self.functions)} functions...")
        
        for i, func in enumerate(self.functions):
            if i % 100 == 0:
                print(f"  Processed {i}/{len(self.functions)}")
            
            enriched = self.get_enriched_snippet(func, max_depth=max_depth)
            if enriched:
                enriched_data.append(enriched)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(enriched_data, f, indent=2, ensure_ascii=False)
        
        print(f"Exported {len(enriched_data)} enriched snippets to {output_path}")

    def export_enriched_snippets_eval(self, base_output_path: str, repo_path: str,cve_id:str ,max_depth: int = 1):
        """
        Esporta gli snippet arricchiti organizzati per CVE/Repo/File.
        
        Args:
            base_output_path: Path base dove creare la struttura (es. /output)
            repo_path: Path della repository analizzata (es. /repos/CVE-2015-2313/capnproto)
            max_depth: Profondità massima per l'enrichment
        """
        from collections import defaultdict
        import re
        
        # Estrai CVE e nome repo dal path
        repo_path = Path(repo_path).resolve()
        
        cve_id = cve_id
        
        # Nome della repo (ultima directory o penultima se l'ultima è repo/)
        repo_name = repo_path.name if repo_path.name != "repo" else repo_path.parent.name
        
        print(f"Organizing snippets for CVE: {cve_id}, Repo: {repo_name}")
        print(f"Repository path: {repo_path}")
        
        # Raggruppa funzioni per file
        functions_by_file = defaultdict(list)
        
        for func in self.functions:
            file_path = func['file']
            functions_by_file[file_path].append(func)
        
        print(f"Found {len(functions_by_file)} unique files with functions")
        
        # Processa ogni file
        total_functions = 0
        for file_path, funcs in functions_by_file.items():
            # Crea nome sicuro per il file (rimuovi caratteri speciali)
            file_path_obj = Path(file_path)
            
            # Ottieni il path relativo rispetto alla repo
            try:
                rel_path = file_path_obj.relative_to(repo_path)
                file_identifier = str(rel_path).replace('/', '_').replace('\\', '_')
            except ValueError:
                # Se il file non è nella repo, usa il nome completo
                file_identifier = file_path_obj.name
            
            # Rimuovi estensione e caratteri non validi
            file_identifier = re.sub(r'[^\w\-_]', '_', file_identifier.replace('.', '_'))
            
            # Crea la struttura di directory
            output_dir = Path(base_output_path) / cve_id / repo_name / file_identifier
            output_dir.mkdir(parents=True, exist_ok=True)
            
            # Genera snippet arricchiti per questo file
            enriched_data = []
            print(f"\n  Processing file: {file_path} ({len(funcs)} functions)")
            
            for func in funcs:
                enriched = self.get_enriched_snippet(func, max_depth=max_depth)
                if enriched:
                    enriched_data.append(enriched)
            
            # Salva enriched_snippets.json
            snippets_path = output_dir / "enriched_snippets.json"
            with open(snippets_path, 'w', encoding='utf-8') as f:
                json.dump(enriched_data, f, indent=2, ensure_ascii=False)
            
            # Salva info.json con metadati
            info_data = {
                'cve_id': cve_id,
                'repo_name': repo_name,
                'repo_path': str(repo_path),
                'analyzed_file': str(file_path),
                'relative_path': str(rel_path) if 'rel_path' in locals() else None,
                'num_functions': len(enriched_data),
                'function_names': [f['function_name'] for f in enriched_data],
                'max_depth': max_depth,
                'file_info': {
                    'includes': self.file_data.get(file_path, {}).get('includes', []),
                    'num_macros': len(self.file_data.get(file_path, {}).get('macros', [])),
                    'num_globals': len(self.file_data.get(file_path, {}).get('globals', []))
                }
            }
            
            info_path = output_dir / "info.json"
            with open(info_path, 'w', encoding='utf-8') as f:
                json.dump(info_data, f, indent=2, ensure_ascii=False)
            
            total_functions += len(enriched_data)
            print(f"    ✓ Saved {len(enriched_data)} functions to {output_dir}")
        
        print(f"\n{'='*60}")
        print(f"Export completed!")
        print(f"  CVE: {cve_id}")
        print(f"  Repo: {repo_name}")
        print(f"  Files processed: {len(functions_by_file)}")
        print(f"  Total functions: {total_functions}")
        print(f"  Output directory: {Path(base_output_path) / cve_id / repo_name}")
        print(f"{'='*60}")


def main():
    
    CVE_FILE = "CVE-2015-8790"
    repo_path = "/home/michele/Desktop/ricerca/output_repos_cpp/CVE-2015-8790/repo/src"
    output_path = f"/home/michele/Desktop/ricerca/agents/local_tier_evaluation_framework/enriched_snippets/enriched_snippets.json"
    base_output = "/home/michele/Desktop/ricerca/agents/local_tier_evaluation_framework/enriched_snippets"
    DEBUG = False

    # Crea il database
    db = FunctionDatabase()
    db.build_from_repo(repo_path)
    
    # Esporta gli snippet arricchiti
    if DEBUG:
        db.export_enriched_snippets(output_path, max_depth=1)
    else:
        db.export_enriched_snippets_eval(base_output, repo_path, CVE_FILE,max_depth=1)
    
    # Esempio di query interattiva
    print("\n" + "="*60)
    print("Database ready for queries!")
    print("="*60)
    
    # Mostra alcuni esempi
    if db.functions:
        print("\nExample: Query for 'main' function")
        results = db.query_function("main", num_params=2)
        print(f"Found {len(results)} matches")
        
        if results:
            print("\nEnriched snippet for first match:")
            enriched = db.get_enriched_snippet(results[0], max_depth=1)
            print(json.dumps(enriched, indent=2))


if __name__ == "__main__":
    main()