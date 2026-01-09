#!/usr/bin/env python3
"""
Costruisce la struttura output_repos_cpp/ per una CVE usando i CSV di ICVul-Dataset.

Funzioni principali:
- legge ICVul-Dataset/cve_fc_vcc_mapping.csv per ricavare repo, commit fix (fc_hash) e candidati vulnerabili (vcc_hash)
- arricchisce i metadati con commit_info.csv e repository_info.csv
- estrae snippet/diff da file_info.csv per il commit di fix
- clona la repo e fa checkout del commit vulnerabile (vcc_hash se presente, altrimenti il parent del fix)

Esempio:
    python3 icvul_builder.py CVE-2019-12529 --dataset-dir ICVul-Dataset --output-dir output_repos_cpp

Puoi passare --skip-clone per evitare il clone (tutto il resto viene comunque generato).
"""
from __future__ import annotations

import argparse
import ast
import csv
import json
import os
import re
import subprocess
import sys
from typing import Dict, List, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Genera struttura output_repos_cpp/ per una CVE dal dataset ICVul.")
    parser.add_argument("cve_id", help="ID della CVE (es. CVE-2019-12529)")
    parser.add_argument(
        "--dataset-dir",
        default="ICVul-Dataset",
        help="Cartella con i CSV del dataset ICVul-Dataset (default: ICVul-Dataset)",
    )
    parser.add_argument(
        "--output-dir",
        default="output_repos_cpp",
        help="Cartella di destinazione (default: output_repos_cpp)",
    )
    parser.add_argument(
        "--skip-clone",
        action="store_true",
        help="Non clona la repo, genera solo metadati/snippet.",
    )
    parser.add_argument(
        "--fetch-nvd",
        action="store_true",
        help="Prova a recuperare descrizione CVE da NVD (richiede rete).",
    )
    parser.add_argument(
        "--nvd-api-key",
        default=os.environ.get("NVD_API_KEY", ""),
        help="API key NVD (opzionale, può anche stare in env NVD_API_KEY).",
    )
    return parser.parse_args()


def csv_field_size_hack() -> None:
    # Evita errori su diff/sorgenti molto lunghi
    csv.field_size_limit(sys.maxsize)


def load_mapping(dataset_dir: str, cve_id: str) -> Optional[Dict[str, str]]:
    path = os.path.join(dataset_dir, "cve_fc_vcc_mapping.csv")
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get("cve_id") == cve_id:
                return row
    return None


def load_repo_info(dataset_dir: str) -> Dict[str, Dict[str, str]]:
    path = os.path.join(dataset_dir, "repository_info.csv")
    repo_info: Dict[str, Dict[str, str]] = {}
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            repo_info[row["repo_url"]] = row
    return repo_info


def load_commit_info(dataset_dir: str) -> Dict[str, Dict[str, str]]:
    path = os.path.join(dataset_dir, "commit_info.csv")
    commit_info: Dict[str, Dict[str, str]] = {}
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            commit_info[row["hash"]] = row
    return commit_info


def parse_list_field(value: str) -> List[str]:
    if not value:
        return []
    value = value.strip()
    if value.startswith("["):
        try:
            parsed = ast.literal_eval(value)
            return [str(x) for x in parsed if x]
        except Exception:
            return []
    return [v.strip() for v in value.split(",") if v.strip()]


def fetch_nvd(cve_id: str, api_key: str = "") -> Optional[Dict[str, object]]:
    """Recupera descrizione e CVSS da NVD (API v2)."""
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    headers = {"User-Agent": "icvul-builder"}
    if api_key:
        headers["apiKey"] = api_key

    try:
        req = Request(url, headers=headers)
        with urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (HTTPError, URLError, TimeoutError, ValueError) as exc:
        print(f"[WARNING] NVD fetch fallito ({exc})")
        return None

    vulns = data.get("vulnerabilities") or []
    if not vulns:
        return None
    cve = vulns[0].get("cve") or {}

    descriptions = cve.get("descriptions") or []
    desc = ""
    for d in descriptions:
        if d.get("lang") == "en":
            desc = d.get("value", "")
            break

    published = cve.get("published")

    cvss_score = None
    cvss_vector = None
    cvss_severity = None

    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key)
        if arr:
            metric = arr[0]
            cvss = metric.get("cvssData") or {}
            cvss_score = cvss.get("baseScore")
            cvss_vector = cvss.get("vectorString")
            cvss_severity = cvss.get("baseSeverity") or metric.get("baseSeverity")
            break

    return {
        "cve_description": desc,
        "publish_date": published,
        "cvss": cvss_score,
        "cvss_vector": cvss_vector,
        "cvss_severity": cvss_severity,
    }


def normalize_repo_url(url: str) -> str:
    if not url:
        return url
    if "api.github.com/repos/" in url:
        parts = url.rstrip("/").split("/")
        if len(parts) >= 2:
            owner = parts[-2]
            repo = parts[-1]
            url = f"https://github.com/{owner}/{repo}"
    if not url.endswith(".git"):
        url = url + ".git"
    return url


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def sanitize_ext(filename: str) -> str:
    ext = os.path.splitext(filename)[1].lstrip(".") or "txt"
    ext = re.sub(r"[^A-Za-z0-9_]", "_", ext)
    return ext or "txt"


def find_file_rows(dataset_dir: str, commit_hash: str) -> List[Dict[str, str]]:
    path = os.path.join(dataset_dir, "file_info.csv")
    rows: List[Dict[str, str]] = []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get("hash") == commit_hash:
                rows.append(row)
    return rows


def build_cve_metadata(
    cve_id: str,
    mapping: Dict[str, str],
    repo_row: Optional[Dict[str, str]],
    fix_commit_row: Optional[Dict[str, str]],
    nvd_data: Optional[Dict[str, object]],
) -> Dict[str, object]:
    cwe_id_raw = mapping.get("cwe_id", "")
    cwe_id = parse_list_field(cwe_id_raw) if cwe_id_raw.startswith("[") else [cwe_id_raw] if cwe_id_raw else []

    meta: Dict[str, object] = {
        "cve_id": cve_id,
        "cwe_id": cwe_id,
        "repo_url": mapping.get("repo_url"),
        "fix_commit": mapping.get("fc_hash"),
        "vcc_commits": parse_list_field(mapping.get("vcc_hash", "")),
    }

    if nvd_data:
        for key in ("cve_description", "publish_date", "cvss", "cvss_vector", "cvss_severity"):
            if key in nvd_data and nvd_data.get(key):
                meta[key] = nvd_data.get(key)

    if repo_row:
        meta["repo_name"] = repo_row.get("repo_name")
        meta["owner"] = repo_row.get("owner")
        meta["repo_language"] = repo_row.get("repo_language")
        meta["description"] = repo_row.get("description")
        meta["homepage"] = repo_row.get("homepage")
        meta["forks_count"] = repo_row.get("forks_count")
        meta["stars_count"] = repo_row.get("stars_count")
        meta["collecting_date"] = repo_row.get("collecting_date")

    if fix_commit_row:
        meta["commit_message"] = fix_commit_row.get("msg")
        meta["commit_date"] = fix_commit_row.get("author_date") or fix_commit_row.get("committer_date")
        meta["parents"] = parse_list_field(fix_commit_row.get("parents", ""))

    return meta


def run_cmd(cmd: List[str], cwd: Optional[str] = None) -> Tuple[bool, str]:
    try:
        proc = subprocess.run(
            cmd,
            cwd=cwd,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        return True, proc.stdout.strip()
    except subprocess.CalledProcessError as exc:
        return False, exc.stderr.strip()


def commit_exists(repo_dir: str, commit_id: str) -> bool:
    ok, _ = run_cmd(["git", "cat-file", "-e", commit_id], cwd=repo_dir)
    return ok


def is_ancestor(repo_dir: str, older: str, newer: str) -> bool:
    ok, _ = run_cmd(["git", "merge-base", "--is-ancestor", older, newer], cwd=repo_dir)
    return ok


def pick_vulnerable_commit(repo_dir: str, fix_commit: str, vcc_list: List[str]) -> Optional[str]:
    for cand in vcc_list:
        if commit_exists(repo_dir, cand):
            if not fix_commit or is_ancestor(repo_dir, cand, fix_commit):
                return cand
    if fix_commit and commit_exists(repo_dir, f"{fix_commit}^"):
        return f"{fix_commit}^"
    return None


def clone_and_checkout(repo_url: str, repo_dir: str, fix_commit: str, vcc_list: List[str]) -> Optional[str]:
    if not os.path.exists(repo_dir):
        ok, msg = run_cmd(["git", "clone", repo_url, repo_dir])
        if not ok:
            print(f"[ERROR] clone fallito: {msg}")
            return None
    vuln_commit = pick_vulnerable_commit(repo_dir, fix_commit, vcc_list)
    if vuln_commit:
        ok, msg = run_cmd(["git", "checkout", vuln_commit], cwd=repo_dir)
        if not ok:
            print(f"[WARNING] checkout {vuln_commit} fallito: {msg}")
            return None
    else:
        print("[WARNING] Nessun commit vulnerabile trovato (uso HEAD corrente)")
    return vuln_commit


def write_snippets(
    file_rows: List[Dict[str, str]],
    base_dir: str,
    fix_commit: str,
    vuln_commit: Optional[str],
) -> None:
    for idx, row in enumerate(file_rows):
        snippet_dir = os.path.join(base_dir, f"snippet_{idx}")
        ensure_dir(snippet_dir)

        filename = row.get("filename") or "unknown"
        ext = sanitize_ext(filename)

        code_before = row.get("code_before") or ""
        code_after = row.get("code_after") or ""
        patch = row.get("diff") or row.get("diff_parsed") or ""

        with open(os.path.join(snippet_dir, f"code_before.{ext}"), "w", encoding="utf-8") as f_before:
            f_before.write(code_before)
        with open(os.path.join(snippet_dir, f"code_after.{ext}"), "w", encoding="utf-8") as f_after:
            f_after.write(code_after)
        with open(os.path.join(snippet_dir, "patch.diff"), "w", encoding="utf-8") as f_patch:
            f_patch.write(patch)

        snippet_meta = {
            "file_name": filename,
            "old_path": row.get("old_path"),
            "new_path": row.get("new_path"),
            "file_language": ext,
            "change_type": row.get("change_type"),
            "num_lines_added": row.get("num_lines_added"),
            "num_lines_deleted": row.get("num_lines_deleted"),
            "vulnerable_commit": vuln_commit,
            "fix_commit": fix_commit,
        }
        with open(os.path.join(snippet_dir, "snippet_metadata.json"), "w", encoding="utf-8") as f_meta:
            json.dump(snippet_meta, f_meta, indent=4, ensure_ascii=False)


def main() -> None:
    args = parse_args()
    csv_field_size_hack()

    mapping = load_mapping(args.dataset_dir, args.cve_id)
    if not mapping:
        print(f"[ERROR] CVE {args.cve_id} non trovata in cve_fc_vcc_mapping.csv")
        sys.exit(1)

    repo_url_raw = mapping.get("repo_url") or ""
    repo_url = normalize_repo_url(repo_url_raw)
    fix_commit = mapping.get("fc_hash") or ""
    vcc_list = parse_list_field(mapping.get("vcc_hash", ""))

    repo_info = load_repo_info(args.dataset_dir)
    commit_info = load_commit_info(args.dataset_dir)
    nvd_data = fetch_nvd(args.cve_id, args.nvd_api_key) if args.fetch_nvd else None

    repo_row = repo_info.get(repo_url_raw) or repo_info.get(repo_url_raw.rstrip(".git"))
    fix_commit_row = commit_info.get(fix_commit)

    base_dir = os.path.join(args.output_dir, args.cve_id)
    ensure_dir(base_dir)

    # CVE metadata
    cve_meta = build_cve_metadata(args.cve_id, mapping, repo_row, fix_commit_row, nvd_data)
    with open(os.path.join(base_dir, "cve_metadata.json"), "w", encoding="utf-8") as f_meta:
        json.dump(cve_meta, f_meta, indent=4, ensure_ascii=False)

    # Clone repo e checkout vulnerabile
    vuln_commit = None
    repo_dir = os.path.join(base_dir, "repo")
    if not args.skip_clone and repo_url:
        vuln_commit = clone_and_checkout(repo_url, repo_dir, fix_commit, vcc_list)
    else:
        print("[INFO] Clone disabilitato o repo_url mancante, salto il checkout.")

    vuln_info = {
        "vulnerable_commit": vuln_commit,
        "fix_commit": fix_commit,
        "vcc_candidates": vcc_list,
    }
    with open(os.path.join(base_dir, "vulnerable_commit_info.json"), "w", encoding="utf-8") as f_vuln:
        json.dump(vuln_info, f_vuln, indent=4, ensure_ascii=False)

    # Snippet/diff dal commit di fix
    file_rows = find_file_rows(args.dataset_dir, fix_commit)
    if not file_rows:
        print(f"[WARNING] Nessun file_info trovato per commit {fix_commit}")
    else:
        write_snippets(file_rows, base_dir, fix_commit, vuln_commit)

    print(f"[OK] Output generato in {base_dir}")


if __name__ == "__main__":
    main()
