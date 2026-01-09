import json
from enriched_snippets import FunctionDatabase

CVE_FILE = "CVE-2022-40673"
repo_path = "/home/michele/Desktop/ricerca/output_repos_cpp/CVE-2022-40673/repo/src"

# Crea il database
db = FunctionDatabase()
db.build_from_repo(repo_path)

print("\n" + "="*80)
print("DIRECT TEST: HelperAdaptor::listStorages enrichment")
print("="*80)

# Trova la funzione HelperAdaptor::listStorages
target_func = None
for func in db.functions:
    if func.get('name') == 'listStorages' and func.get('container') == 'HelperAdaptor':
        target_func = func
        break

if not target_func:
    print("❌ HelperAdaptor::listStorages NOT FOUND in database!")
    print("\nAll listStorages functions:")
    for func in db.functions:
        if 'listStorages' in func.get('name', ''):
            print(f"  - {func.get('qualified_name')} in {func.get('container')}")
    exit(1)

print(f"✅ Found: {target_func.get('qualified_name')}")
print(f"   File: {target_func['file']}")
print(f"   Calls: {target_func.get('calls', [])}")

# Test enrichment con debug
print("\n" + "-"*80)
print("Testing enrichment with debug=True, max_depth=1")
print("-"*80)

enriched = db.get_enriched_snippet(target_func, max_depth=1, debug=True)

print("\n" + "-"*80)
print("RESULT:")
print("-"*80)
print(f"called_functions count: {len(enriched.get('called_functions', []))}")
print(f"\ncalled_functions content:")
print(json.dumps(enriched.get('called_functions', []), indent=2))