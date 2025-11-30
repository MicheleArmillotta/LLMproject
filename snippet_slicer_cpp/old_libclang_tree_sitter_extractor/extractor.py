#!/usr/bin/env python3
import os
import re
import json
import subprocess
import shutil
from libclang_contextV2 import extract_context

# === CONFIG ===
CVE_NAME = "CVE-2015-2313"   # ← cambia questo
REPO_PATH = "/home/michele/Desktop/ricerca/output_repos_cpp/CVE-2015-2313/repo/c++/src/capnp"  # ← cambia questo
OUTPUT_BASE = "/home/michele/Desktop/ricerca/agents/local_tier_evaluation_framework/enriched_snippets"

CONTEXT_EXTRACTOR = "/home/michele/Desktop/ricerca/agents/snippet_slicer_cpp/libclang_contextV2.py"  # path del context extractor

# === FUNZIONI ===

def find_cpp_files(base_path):
    """Trova ricorsivamente tutti i file .cpp in una repo."""
    cpp_files = []
    for root, _, files in os.walk(base_path):
        for f in files:
            if f.endswith(".c++"):
                cpp_files.append(os.path.join(root, f))
    return cpp_files


def extract_local_includes(file_path, repo_path):
    """
    Estrae gli include locali (#include "header.h") e restituisce i path completi.
    Cerca prima nella directory del file, poi ricorsivamente in tutta la repo.
    """
    includes = []
    include_pattern = re.compile(r'#include\s+"([^"]+)"')
    file_dir = os.path.dirname(file_path)

    try:
        with open(file_path, encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception as e:
        print(f"[WARN] Cannot read {file_path}: {e}")
        return []

    # Candidati da cercare (es. header.h, utils/common.h, ecc.)
    headers_to_find = [m.group(1) for line in lines if (m := include_pattern.search(line))]

    for header in headers_to_find:
        # 1️⃣ Cerca nella stessa directory del file
        local_path = os.path.join(file_dir, header)
        print(f"DEBUG LOCAL PATH: {local_path}")
        if os.path.exists(local_path):
            includes.append(local_path)
            continue

        # 2️⃣ Cerca ricorsivamente in tutta la repo
        found = None
        for root, _, files in os.walk(repo_path):
            if os.path.basename(header) in files:
                found = os.path.join(root, os.path.basename(header))
                break

        if found:
            includes.append(found)
        else:
            print(f"[WARN] Header '{header}' not found for {file_path}")

    return includes


def ensure_dir(path):
    """Crea la directory se non esiste."""
    os.makedirs(path, exist_ok=True)



def run_context_extractor(file_path, includes, output_path):
    """
    Esegue direttamente la funzione extract_context() per un file specifico
    e salva il risultato JSON nella posizione desiderata.
    """
    try:
        print(f"[INFO] Running extract_context() on {file_path}")
        print(f"[INFO] Includes: {includes}")

        # Esegui direttamente la funzione
        data = extract_context(file_path, includes)

        # Crea le directory di output se non esistono
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        output_file = output_path + "/snippets_context.json"
        # Salva il risultato in JSON
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        print(f"[OK] Output saved to {output_path}")
        print(f"[OK] Found {len(data)} functions in {file_path}")

        return True

    except Exception as e:
        print(f"[ERROR] Failed to process {file_path}: {e}")
        return False

def process_cpp_file(file_path, cve_name, repo_path, output_base):
    """Processa un singolo file .cpp e salva output e info."""
    rel_repo = os.path.basename(os.path.abspath(repo_path))
    rel_file_name = os.path.basename(file_path)
    rel_file_stem = os.path.splitext(rel_file_name)[0]

    # Estraggo header importati localmente
    includes = extract_local_includes(file_path,repo_path)

    print(f"DEBUG INCLUDES PATH: {includes}")

    # Costruisco la gerarchia di output
    output_dir = os.path.join(output_base, cve_name, rel_repo, rel_file_stem)
    ensure_dir(output_dir)

    # Eseguo il context_extractor
    success = run_context_extractor(file_path, includes, output_dir)

    # Scrivo info.json
    info = {
        "cve_name": cve_name,
        "repo_path": repo_path,
        "file_path": file_path,
        "file_name": rel_file_name,
        "includes": includes,
        "output_dir": output_dir,
        "status": "success" if success else "failed"
    }

    info_path = os.path.join(output_dir, "info.json")
    with open(info_path, "w", encoding="utf-8") as f:
        json.dump(info, f, indent=2, ensure_ascii=False)

    print(f"[INFO] Info saved to {info_path}")


def main():
    print(f"=== Batch Context Extraction for {CVE_NAME} ===")
    cpp_files = find_cpp_files(REPO_PATH)
    print(f"Found {len(cpp_files)} .cpp files to process.\n")

    for cpp_file in cpp_files:
        print(f"\n=== Processing {cpp_file} ===")
        process_cpp_file(cpp_file, CVE_NAME, REPO_PATH, OUTPUT_BASE)


if __name__ == "__main__":
    main()
