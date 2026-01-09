import os
import json
import subprocess
import shutil
import re

INPUT_FILE = "ReposVul_c.jsonl"
OUTPUT_DIR = "output_repos_c"
RECORD_INDEX = []  #e.g. 142
F = 0

os.makedirs(OUTPUT_DIR, exist_ok=True)

def normalize_repo_url(url):
    if "api.github.com/repos/" in url:
        # esempio: https://api.github.com/repos/irmen/Pyro3/commits/xxxxx
        parts = url.split("/")
        owner, repo = parts[4], parts[5]
        return f"https://github.com/{owner}/{repo}.git"
    return url

def run_cmd(cmd, cwd=None):
    """Run shell command safely and return success flag"""
    try:
        subprocess.run(
            cmd,
            cwd=cwd,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return True
    except subprocess.CalledProcessError as e:
        print(f"[ERRORE] comando fallito: {' '.join(cmd)}")
        if e.stderr:
            print(e.stderr.strip())
        return False

def commit_exists(repo_dir, commit_id):
    """Check if a commit exists in the repo."""
    if not commit_id:
        return False
    result = subprocess.run(
        ["git", "cat-file", "-e", commit_id],
        cwd=repo_dir,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return result.returncode == 0

def is_ancestor(repo_dir, older_commit, newer_commit):
    """Return True if older_commit is an ancestor of newer_commit."""
    if not older_commit or not newer_commit:
        return False
    result = subprocess.run(
        ["git", "merge-base", "--is-ancestor", older_commit, newer_commit],
        cwd=repo_dir,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return result.returncode == 0

def pick_vulnerable_commit(repo_dir, fix_commit, candidates):
    """Choose a vulnerable commit that is an ancestor of the fix commit."""
    ordered_candidates = []
    for candidate in candidates:
        if candidate and candidate not in ordered_candidates:
            ordered_candidates.append(candidate)

    if fix_commit:
        parent_ref = f"{fix_commit}^"
        if parent_ref not in ordered_candidates:
            ordered_candidates.append(parent_ref)

    for candidate in ordered_candidates:
        if fix_commit and candidate == fix_commit:
            print(f"[WARNING] Il commit candidato {candidate} coincide con il fix, lo salto")
            continue

        if not commit_exists(repo_dir, candidate):
            print(f"[WARNING] Commit {candidate} non trovato, lo salto")
            continue

        if fix_commit and not is_ancestor(repo_dir, candidate, fix_commit):
            print(f"[WARNING] Commit {candidate} non è antenato di {fix_commit}, lo salto")
            continue

        return candidate

    return None

with open(INPUT_FILE, "r", encoding="utf-8") as f:
    for i in range(len(RECORD_INDEXES)):
        while F != RECORD_INDEXES[i]:
            line = f.readline()
            F = F+1
        if not line:
            break
        
        entry = json.loads(line)
        
        cve_id = entry.get("cve_id", f"CVE_{i}")
        repo_url = entry.get("url") or entry.get("html_url")
        repo_url = normalize_repo_url(repo_url)
        
        fix_commit = entry.get("commit_id")
        windows_before = entry.get("windows_before", []) or []
        parents = entry.get("parents", []) or []

        # Raccogli i candidati vulnerabili in ordine di priorità
        candidate_commits = []
        for wb in windows_before:
            cid = wb.get("commit_id") or wb.get("commit_id_before")
            if cid:
                candidate_commits.append(cid)

        for parent in parents:
            cid = parent.get("commit_id_before") or parent.get("commit_id")
            if cid:
                candidate_commits.append(cid)
        
        base_dir = os.path.join(OUTPUT_DIR, cve_id)
        os.makedirs(base_dir, exist_ok=True)
        
        # Salvo i metadati (senza windows_before/after se vuoi risparmiare spazio)
        entry_copy = entry.copy()
        entry_copy.pop("windows_before", None)
        entry_copy.pop("windows_after", None)
        
        with open(os.path.join(base_dir, "cve_metadata.json"), "w", encoding="utf-8") as meta_f:
            json.dump(entry_copy, meta_f, indent=4, ensure_ascii=False)
        
        repo_dir = os.path.join(base_dir, "repo")
        resolved_vulnerable_commit = None

        if repo_url:
            if not candidate_commits and not fix_commit:
                print(f"[WARNING] Nessun commit vulnerabile da provare per {cve_id}, salto il clone")
            else:
                clone_ok = True
                if not os.path.exists(repo_dir):
                    print(f"[INFO] Clono repo {repo_url} per {cve_id}")
                    clone_ok = run_cmd(["git", "clone", repo_url, repo_dir])
                
                if clone_ok and os.path.exists(repo_dir):
                    resolved_vulnerable_commit = pick_vulnerable_commit(repo_dir, fix_commit, candidate_commits)

                    if resolved_vulnerable_commit:
                        print(f"[INFO] Checkout al commit VULNERABILE {resolved_vulnerable_commit}")
                        checkout_ok = run_cmd(["git", "checkout", resolved_vulnerable_commit], cwd=repo_dir)
                        if not checkout_ok:
                            resolved_vulnerable_commit = None
                    else:
                        print(f"[WARNING] Nessun commit vulnerabile valido trovato per {cve_id}")
                
                if not resolved_vulnerable_commit:
                    print(f"[WARNING] Impossibile garantire lo stato vulnerabile per {cve_id}, rimuovo il clone per evitare di restare su HEAD fixata")
                    shutil.rmtree(repo_dir, ignore_errors=True)
        else:
            print(f"[WARNING] Nessuna repo URL trovata per {cve_id}")

        # Salvo info sul commit vulnerabile scelto (se presente)
        vuln_info = {
            "vulnerable_commit": resolved_vulnerable_commit,
            "fix_commit": fix_commit,
            "windows_before": windows_before
        }
        with open(os.path.join(base_dir, "vulnerable_commit_info.json"), "w", encoding="utf-8") as vci:
            json.dump(vuln_info, vci, indent=4, ensure_ascii=False)
        
        # Resto del codice per salvare gli snippet...
        details = entry.get("details", [])
        if isinstance(details, dict):
            details = [details]
        
        for j, snippet in enumerate(details):
            snippet_dir = os.path.join(base_dir, f"snippet_{j}")
            os.makedirs(snippet_dir, exist_ok=True)
            
            file_lang = snippet.get("file_language", "txt").lower()

            # Estensione sicura: solo lettere, numeri e underscore
            ext = re.sub(r"[^a-z0-9_]", "_", file_lang)

            # override solo se è Python
            if "python" in file_lang:
                ext = "py"
            
            # codice prima (VULNERABILE)
            code_before = snippet.get("code_before", "")
            if code_before:
                with open(os.path.join(snippet_dir, f"code_before.{ext}"), "w", encoding="utf-8") as fcb:
                    fcb.write(code_before)
            
            # codice dopo (FIXATO)
            code_after = snippet.get("code", "")
            if code_after:
                with open(os.path.join(snippet_dir, f"code_after.{ext}"), "w", encoding="utf-8") as fca:
                    fca.write(code_after)
            
            # patch
            patch = snippet.get("patch", "")
            if patch:
                with open(os.path.join(snippet_dir, "patch.diff"), "w", encoding="utf-8") as pf:
                    pf.write(patch)
            
            # metadati snippet
            snippet_metadata = {
                "file_name": snippet.get("file_name"),
                "file_path": snippet.get("file_path"),
                "file_language": snippet.get("file_language"),
                "vulnerable_commit": resolved_vulnerable_commit,
                "fix_commit": entry.get("commit_id"),
                "commit_message": entry.get("commit_message"),
                "commit_date": entry.get("commit_date"),
            }
            with open(os.path.join(snippet_dir, "snippet_metadata.json"), "w", encoding="utf-8") as smf:
                json.dump(snippet_metadata, smf, indent=4, ensure_ascii=False)

print("Completato: controlla la cartella", OUTPUT_DIR)
