import os
import json
import asyncio
from datetime import datetime

from call_chain_agent.call_chain_agent import chain_agent # importa il tuo agente
from validator.validator import check_entities_exist_cpp
from validator.validator_agent import validator_agent
chain_agent_lock = asyncio.Semaphore(1)
# ==================== CONFIG ====================
BASE_OUTPUT_DIR = "/home/michele/Desktop/ricerca/agents/local_tier_evaluation_framework/chain_assessments"
DEFAULT_INPUT = "/home/michele/Desktop/ricerca/agents/local_tier_evaluation_framework/call_chains/CVE-2015-8790/repo.json"

# Imposta qui eventuali filtri (oppure lasciali a None per analizzare tutto)
FILE_FILTER = "/home/michele/Desktop/ricerca/output_repos_cpp/CVE-2015-2313/repo/c++/src/capnp/schema.c++"
FUNCTION_FILTER = "ListSchema::of"  # es. "ConstSchema::as"
LINES_FILTER = "699-730"   # es. "1578-1580"
MAX_ATTEMPTS = 1

# ==================== EXPERIMENT VERSION ====================
EXPERIMENT_VERSION = "experimentVersion3"   

FILTER_ASSESSMENT_PATH = "/home/michele/Desktop/ricerca/agents/local_tier_evaluation_framework/vulnerability_assessment/experimentVersion3/CVE-2015-8790/src/EbmlUnicodeString_cpp/vulnerability_assessment.json"

file_write_lock = asyncio.Lock()
vulnerabiliry_file_write_lock = asyncio.Lock()

# =================== SAVE UTILITY ==============

async def save_assessment(output:str, file_path:str, info:dict, Vulnerable:bool, Description:str, Used_entities:list,Hallucinated_entities:list,coverage):
    function_key = (
        info.get("target_function"),
        info.get("file"),
        info.get("lines"),
    )
    new_record = {
        "file_path": file_path,
        "id": function_key,
        "function_name": info.get("qualified_name"),
        "chains":info.get("chains"),
        "Vulnerable":Vulnerable,
        "Description":Description,
        "Used_entities": Used_entities,
        "Hallucinated_entities": Hallucinated_entities,
        "Coverage": coverage
    }

    output_path = output

    async with vulnerabiliry_file_write_lock:

        if os.path.exists(output_path):
            with open(output_path, "r", encoding="utf-8") as f:
                try:
                    data = json.load(f)
                except json.JSONDecodeError:
                    data = []
        else:
            data = []

        # Aggiungi il nuovo record
        data.append(new_record)
            
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)


# ==================== UTILITY ====================

def build_validation_prompt(core_snippet: str, vulnerability_description: str) -> str:
    prompt = f"""
================ CODE SNIPPET ================
{core_snippet}
=============================================

=============== VULNERABILITY DESCRIPTION ===============
{vulnerability_description}
=========================================================
"""
    return prompt.strip()


def ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)

def build_prompt_for_chain(chain_info, target_assessment):
    """
    Crea il prompt per una singola chain.
    target_assessment = { "Vulnerable": bool, "Description": str }
    """

    # Insert other-agent assessment at the top
    header = (
        "==== FUNCTION-LEVEL ASSESSMENT FROM ANOTHER AGENT ====\n"
        f"Vulnerable: {target_assessment.get('Vulnerable')}\n"
        f"Description: {target_assessment.get('Description')}\n"
        "======================================================\n\n"
    )

    snippets = list(reversed(chain_info.get("snippets", [])))
    prompt_parts = [header]

    for i, snip in enumerate(snippets):
        label = "---- TARGET FUNCTION ----" if i == 0 else f"---- CALLER {i} ----"
        code = snip.get("snippet", "").strip()
        prompt_parts.append(f"{label}\n{code}")

    return "\n\n".join(prompt_parts)

def build_output_path(target_file):
    parts = target_file.split("/")
    try:
        cve_index = next(i for i, p in enumerate(parts) if p.startswith("CVE-"))
    except StopIteration:
        raise ValueError(f"Impossibile trovare una directory 'CVE-' nel path: {target_file}")

    relative_path = "/".join(parts[cve_index:])
    
    base_dir = os.path.join(
        BASE_OUTPUT_DIR,
        EXPERIMENT_VERSION,          # <<<<< aggiunto qui
        os.path.dirname(relative_path)
    )
    ensure_dir(base_dir)

    return os.path.join(base_dir, "vulne_chain_assessment.json")

# ==================== FILTRI ====================
def filter_records(records, file_filter=None, func_filter=None, lines_filter=None):
    """Filtra i record in base ai parametri di configurazione."""
    filtered = []
    for record in records:
        record_file = record.get("file")
        record_func = record.get("target_function")
        record_lines = record.get("lines")

        if file_filter and file_filter != record_file:
            continue
        if func_filter and func_filter != record_func:
            continue
        if lines_filter and lines_filter != record_lines:
            continue

        filtered.append(record)
    return filtered


def filter_records_by_ids(records, id_filters_with_flags):
    """
    Filtra i record usando una lista di tuple:
    (func, file, lines, Analyze_caller_chains, Vulnerable, Description)

    Vengono selezionati solo quelli con Analyze_caller_chains == True.
    """
    filtered = []
    for record in records:
        rec_tuple = (
            record.get("target_function"),
            record.get("file"),
            record.get("lines"),
        )

        for (func, file_path, lines, analyze_flag, vuln, desc) in id_filters_with_flags:
            if rec_tuple == (func, file_path, lines) and analyze_flag is True:
                # Attach vuln assessment metadata to the record
                record["_target_vuln"] = {
                    "Vulnerable": vuln,
                    "Description": desc,
                }
                filtered.append(record)
                break

    return filtered

def load_filters_from_assessment(assessment_path):
    """Carica gli ID e anche:
       - Analyze_caller_chains
       - Vulnerable
       - Description
    """
    if not os.path.exists(assessment_path):
        raise FileNotFoundError(f"Assessment file non trovato: {assessment_path}")

    with open(assessment_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    filters = []
    for entry in data:
        if "id" in entry and isinstance(entry["id"], list) and len(entry["id"]) == 3:
            func, file_path, lines = entry["id"]
            analyze_flag = entry.get("Analyze_caller_chains", False)
            vuln = entry.get("Vulnerable", None)
            desc = entry.get("Description", None)
            filters.append((func, file_path, lines, analyze_flag, vuln, desc))

    return filters

# ==================== ANALISI ====================




async def analyze_chain(chain_record):
    """Analizza una singola catena, verifica il grounding per ogni snippet, e salva l'assessment finale."""
    target_function = chain_record.get("target_function")
    target_file = chain_record.get("file")
    target_lines = chain_record.get("lines")
    chains = chain_record.get("chains", [])

    output_path = build_output_path(target_file)

    for chain in chains:
        target_assessment = chain_record.get("_target_vuln", {})

        prompt = build_prompt_for_chain(chain, target_assessment)
        print(f"[INFO] Analizzando chain per '{target_function}' ({target_file}:{target_lines})")
        print(f"[DEBUG]: prompt:{prompt}")
        info = {
            "target_function": target_function,
            "file": target_file,
            "lines": target_lines,
            "qualified_name": target_function,
            "chains": chain,
        }
        coverage = 0.0  
        try:
            res = None
            attempt = 0

            # Esegue fino a raggiungere coverage totale 1.0 o superare max tentativi
            while attempt < MAX_ATTEMPTS:
                async with chain_agent_lock:
                    res = await chain_agent.run(prompt)
                #snippets = list(reversed(chain.get("snippets", [])))

                # Analizza il grounding snippet-per-snippet
                #snippet_coverages = []
                #for i, snip in enumerate(snippets):
                #    snippet_code = snip.get("snippet", "")
                #    matches,snippet_cov = check_entities_exist_cpp(snippet_code, res.output.Involved_entities, partial_match=False)
                #    snippet_coverages.append(snippet_cov)
                #    print(f"[DEBUG] Snippet {i+1}/{len(snippets)} coverage: {snippet_cov:.2f}")

                #coverage = sum(snippet_coverages) / len(snippet_coverages) if snippet_coverages else 0.0
                #overall_coverages.append(coverage)

                #print(f"[INFO] Coverage chain tentativo {attempt+1}: {coverage:.2f}")

                validator_prompt = build_validation_prompt(prompt, res.output.Description)
                print(f"\n[DEBUG] Validation prompt: {validator_prompt}")
                validator_res = await validator_agent.run(validator_prompt)

                if validator_res.output.Validate:
                    print(f"[OK] Coverage completa per '{target_function}'")
                    coverage = 1.0
                    break
                else:
                    # Opzionale: segnala entità mancanti per debugging
                    missing = validator_res.output.Hallucinated_entities
                    print(f"[INFO] Entità mancanti: {missing}")

                    # Puoi aggiungere qui un raffinamento del prompt o una pausa
                    await asyncio.sleep(0.5)

                attempt += 1

            #avg_coverage = max(overall_coverages) if overall_coverages else 0.0

            # Salva con coverage
            await save_assessment(
                output_path,
                target_file,
                info,
                res.output.Vulnerable,
                res.output.Description,
                validator_res.output.Used_entities,
                validator_res.output.Hallucinated_entities,
                coverage
            )

            print(f"[SUCCESS] Chain '{target_function}' salvata con coverage {coverage:.2f}")

        except Exception as e:
            print(f"[ERROR] Fallita analisi per '{target_function}': {e}")


# ==================== MAIN PROCESS ====================
async def process_chains(input_path, file_filter=None, func_filter=None, lines_filter=None, assessment_filter_path=None):
    with open(input_path, "r", encoding="utf-8") as f:
        records = json.load(f)

    if assessment_filter_path:
        print(f"[INFO] Caricamento filtri da assessment: {assessment_filter_path}")
        id_filters = load_filters_from_assessment(assessment_filter_path)
        records_to_analyze = filter_records_by_ids(records, id_filters)
        print(f"[INFO] Trovati {len(records_to_analyze)} record da analizzare in base agli ID del file assessment")
    else:
        records_to_analyze = filter_records(records, file_filter, func_filter, lines_filter)
        print(f"[INFO] Trovati {len(records_to_analyze)} record da analizzare con filtri diretti")

    for record in records_to_analyze:
        await analyze_chain(record)

    print(f"[DONE] Analisi completata.")

# ==================== ENTRYPOINT ====================
async def main():
    await process_chains(
        input_path=DEFAULT_INPUT,
        file_filter=FILE_FILTER,
        func_filter=FUNCTION_FILTER,
        lines_filter=LINES_FILTER,
        assessment_filter_path=FILTER_ASSESSMENT_PATH,
    )

if __name__ == "__main__":
    asyncio.run(main())
