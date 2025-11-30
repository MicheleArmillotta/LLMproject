#!/usr/bin/env python3
import os
import json
from datetime import datetime
from agents.snippet_slicer_cpp.extract_infos import CppContextAnalyzer  # importa la classe che ti ho dato

# === CONFIG ===
SOURCE_DIR = "/home/michele/Desktop/ricerca/output_repos_cpp/CVE-2015-2313/repo/c++"  # <-- cambia path
OUTPUT_DIR = "./cpp_analysis_results"

SUPPORTED_EXTENSIONS = (".c++", "cpp",".cc", ".cxx", ".h", ".hpp")

def analyze_repo(source_dir, output_dir):
    analyzer = CppContextAnalyzer()
    os.makedirs(output_dir, exist_ok=True)
    analyzed_files = 0

    for root, _, files in os.walk(source_dir):
        for file in files:
            if not file.endswith(SUPPORTED_EXTENSIONS):
                continue

            file_path = os.path.join(root, file)
            try:
                print(f"[INFO] Analyzing {file_path}")
                result = analyzer.parse_file(file_path)

                # Genera nome file JSON corrispondente
                rel_path = os.path.relpath(file_path, source_dir)
                json_name = rel_path.replace("/", "_").replace("\\", "_") + ".json"
                output_path = os.path.join(output_dir, json_name)

                with open(output_path, "w", encoding="utf-8") as f:
                    json.dump(result, f, indent=2, ensure_ascii=False)

                print(f"  → Saved to {output_path}")
                analyzed_files += 1
            except Exception as e:
                print(f"[ERROR] Failed to analyze {file_path}: {e}")

    print("\n=== Analysis complete ===")
    print(f"  Total files analyzed: {analyzed_files}")
    print(f"  Results saved in: {os.path.abspath(output_dir)}")
    print(f"  Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

# -------------------------------------------------------------
if __name__ == "__main__":
    analyze_repo(SOURCE_DIR, OUTPUT_DIR)
