import os
import json
import asyncio
from datetime import datetime
from local_agent.local_agent import (
    #SummaryDeps,
    summary_agent,
    #LocalDeps,
    local_agent,
)
from validator.validator import check_entities_exist_cpp
from validator.validator_agent import validator_agent
from pydantic import BaseModel
from typing import Any

import time

RATE_LIMIT_INTERVAL = 60.0   # 2 requests/min = 1 request/30s
_last_call_timestamp = 0.0

# ================= CONFIG =================
BASE_ENRICHED_ROOT = "/home/michele/Desktop/ricerca/agents/local_tier_evaluation_framework/enriched_snippets"
ENRICHED_PATH = "/home/michele/Desktop/ricerca/agents/local_tier_evaluation_framework/enriched_snippets/CVE-2013-7299/framework/common_messageheaderparser_cpp"

SUMMARY_PATH = "/home/michele/Desktop/ricerca/agents/local_tier_evaluation_framework/summaries"
EXPERIMENTS_PATH = "/home/michele/Desktop/ricerca/agents/local_tier_evaluation_framework/vulnerability_assessment"
EXPERIMENT_VERSION = "experimentVersion11"
#UNVERIFIED_PATH = "/home/michele/Desktop/ricerca/agents/local_tier_evaluation_framework/unverified_vuln_assessment"

DEBUG_MODE = True  # True = test manuale singolo
USE_SUMMARY_MODE = False  # False = bypassa i summary, usa codice dei callee

# ================= ASYNC CONTROL =================
summary_file_write_lock = asyncio.Lock()
vulnerabiliry_file_write_lock = asyncio.Lock()
file_write_lock = asyncio.Lock()
summary_semaphore = asyncio.Semaphore(1)
local_semaphore = asyncio.Semaphore(1)

# ================= SAVE UTILITIES ===============

async def rate_limit_tier1():
    """
    Enforces a simple rate limit:
    at most 2 analyze_record() calls per minute.
    """
    global _last_call_timestamp
    now = time.monotonic()

    elapsed = now - _last_call_timestamp
    wait_time = RATE_LIMIT_INTERVAL - elapsed

    if wait_time > 0:
        await asyncio.sleep(wait_time)

    _last_call_timestamp = time.monotonic()

async def save_summary(output: str,id:tuple, function_called:str, summary:str) -> str:
    """
    Save the AI-generated function summary and metadata to a JSON file.
    """

    # Recupera i dati dalle deps
    #deps = ctx.deps
    output_path = output

    # Recupera l'output del tool di summary precedente
    # ctx.last_output contiene il risultato dell’ultimo step del modello
    summary_data = summary
    if not summary_data:
        return "No summary available to save."

    # Prepara il dizionario con i dati da salvare
    record = {
        "id": id,
        "function_called": function_called,
        "summary": summary,
    }

    async with summary_file_write_lock:

    # Se il file esiste già, lo aggiorniamo aggiungendo la nuova entry
        if os.path.exists(output_path):
            try:
                with open(output_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if not isinstance(data, list):
                    data = [data]
            except json.JSONDecodeError:
                data = []
        else:
            data = []

        # Aggiungi il nuovo record
        data.append(record)

        # Salva nel file JSON
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    return f"Summary saved successfully to {output_path}"


async def save_assessment(output:str,file_path:str, record_id:tuple,info:dict,core_snippet:StopAsyncIteration, Vulnerable:bool, Description:str):
    new_record = {
        "file_path": file_path,
        "id": record_id,
        "function_name": info.get("function_name"),
        "contextual_snippet":core_snippet,
        "Vulnerable":Vulnerable,
        "Description":Description,
        #"Analyze_caller_chains":Should_analyze,
        #"Caller_chain_reason":Reason,
        #"Used_entities": Used_entities,
        #"Hallucinated": Hallucinated_entities,
        #"Coverage": coverage
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



async def save_assessment_semantic(
    output: str,
    file_path: str,
    record_id: tuple,
    info: dict,
    core_snippet: Any,
    sinks: list[Any],   # list of Sink or list of dicts
):
    """
    Save vulnerability assessment results to a JSON file.
    Sinks may be lists of Pydantic models or plain dictionaries.
    """

    # Convert sinks (which may be Pydantic models) to dicts
    normalized_sinks = []
    for s in sinks:
        if isinstance(s, BaseModel):
            normalized_sinks.append(s.model_dump())
        elif isinstance(s, dict):
            normalized_sinks.append(s)
        else:
            raise TypeError(
                f"Sink element is not serializable: {type(s)}. "
                "Expected Pydantic model or dict."
            )

    new_record = {
        "file_path": file_path,
        "id": record_id,
        "function_name": info.get("function_name"),
        "contextual_snippet": core_snippet,
        "sinks": normalized_sinks,
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

        data.append(new_record)

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)




# ================= UTILITIES =================
def ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)

def find_enriched_json_files(base_path):
    """Trova solo i file enriched_snippets.json, ignora info.json."""
    for root, _, files in os.walk(base_path):
        for file in files:
            if file == "enriched_snippets.json":
                yield os.path.join(root, file)

def get_relative_path_to_root(input_path: str):
    """Calcola il path relativo rispetto alla root generale, anche se ENRICHED_PATH è una sottocartella."""
    return os.path.relpath(input_path, BASE_ENRICHED_ROOT)

def get_output_path_for_summary(input_path: str):
    """Restituisce il path di output per il summary corrispondente, mantenendo la gerarchia completa."""
    relative = get_relative_path_to_root(input_path)
    base_dir = os.path.dirname(relative)
    out_dir = os.path.join(SUMMARY_PATH, base_dir)
    ensure_dir(out_dir)
    return os.path.join(out_dir, "summary.json")

def get_output_path_for_experiment(input_path: str):
    """Restituisce il path di output per la vulnerability analysis, mantenendo la gerarchia completa."""
    relative = get_relative_path_to_root(input_path)
    base_dir = os.path.dirname(relative)
    exp_dir = os.path.join(EXPERIMENTS_PATH, EXPERIMENT_VERSION, base_dir)
    ensure_dir(exp_dir)
    return os.path.join(exp_dir, "vulnerability_assessment.json"), exp_dir

# ================= SUMMARY AGENTS =================
async def analyze_definition(record, callee_name, snippet, output_json_path):
    async with summary_semaphore:
        record_function = record.get("function_name")
        record_file = record.get("file")
        record_lines = record.get("lines")

        function_key = (record_function, record_file, record_lines)

        #deps = SummaryDeps(
        #    output=output_json_path,
        #    id=function_key,
        #    function_called=callee_name
        #)

        prompt = (
            f"Analyze the following code snippet and summarize its behavior.\n"
            f"Code snippet:\n{snippet}"
        )

        try:
            print(f"[INFO] Starting summary for '{callee_name}' from '{record_function}'")
            res = await summary_agent.run(prompt) #deps
            await save_summary(output_json_path,function_key,callee_name,res.output.Summary)
            print(f"[SUCCESS] Summary creato per '{callee_name}' (key: {function_key})")
        except Exception as e:
            print(f"[ERROR] Fallita analisi di '{callee_name}': {e}")

async def process_definitions_async(input_json_path: str, output_json_path: str):
    """Processa tutte le funzioni chiamate e genera i summary."""
    with open(input_json_path, "r", encoding="utf-8") as f:
        records = json.load(f)

    tasks = []
    for record in records[:1]:  # Rimuoviamo [:1] per batch completo
        called_functions = record.get("called_functions", [])
        if not called_functions:
            continue

        for called_func in called_functions:
            if not called_func.get("resolved", False):
                continue
            callee_name = called_func.get("call_info", {}).get("callee")
            snippet = called_func.get("details", {}).get("snippet")
            if snippet and snippet.strip():
                tasks.append(analyze_definition(record, callee_name, snippet, output_json_path))

    if tasks:
        print(f"[INFO] Eseguendo {len(tasks)} summary agent per {input_json_path}")
        await asyncio.gather(*tasks)
    else:
        print(f"[WARN] Nessuna funzione risolta trovata in {input_json_path}")

# ================= LOCAL AGENTS =================
async def aggrega_info_record(record_input, summary_records):
    """Combina contextual_snippet con i summary che hanno lo stesso id."""
    contextual_snippet = record_input.get('contextual_snippet', '')
    target_id = (
        str(record_input.get("function_name")),
        str(record_input.get("file")),
        str(record_input.get("lines"))
    )

    risultato = contextual_snippet
    record_trovati = []

    for record in summary_records:
        id_summary = record.get('id')
        if (
            isinstance(id_summary, (list, tuple))
            and len(id_summary) == 3
            and str(id_summary[0]) == target_id[0]
            and str(id_summary[1]) == target_id[1]
            and str(id_summary[2]) == target_id[2]
        ):
            record_trovati.append({
                'summary': record.get('summary', ''),
                'function_called': record.get('function_called', '')
            })

    if record_trovati:
        risultato += "\n\n--- CONTEXTUAL INFORMATIONS ---\n"
        risultato += "--- summary of the functions used by the analyzed function --- \n\n"
        for i, rec in enumerate(record_trovati, 1):
            risultato += f"\n[Record {i}]\nFunction Called: {rec['function_called']}\nSummary: {rec['summary']}\n"

    return risultato


async def aggrega_callee_code(record_input):
    """Crea il core snippet con contextual_snippet + codice dei callee."""
    contextual_snippet = record_input.get("contextual_snippet", "")
    called_functions = record_input.get("called_functions", [])
    risultato ="MAIN FUNCTION:\n" + contextual_snippet + "\n\n-------- CONTEXTUAL INFORMATIONS - CALLEES CODE --------\n"
    risultato += "-------- Code of the functions used by the analyzed function -------- \n\n"

    for func in called_functions:
        callee_name = func.get("call_info", {}).get("callee", "unknown")
        snippet = func.get("details", {}).get("snippet", "")
        if snippet.strip():
            risultato += f"\nCallee: {callee_name}\n{snippet}\n"

    return risultato


def check_entities_per_snippet(record_input: dict, entities: list[str], partial_match=False):
    """
    Verifica la presenza delle entità nel contextual_snippet e nei callee
    esattamente come vengono usati per costruire il prompt.
    
    Restituisce:
      - matches aggregati {entità: True/False}
      - coverage complessiva
      - dettagli per blocco (utile per debugging o grounding report)
    """
    contextual_snippet = record_input.get("contextual_snippet", "")
    called_functions = record_input.get("called_functions", [])

    blocks = [("contextual_snippet", contextual_snippet)]
    for func in called_functions:
        callee_name = func.get("call_info", {}).get("callee", "unknown")
        snippet = func.get("details", {}).get("snippet", "")
        if snippet.strip():
            blocks.append((callee_name, snippet))

    aggregate_matches = {ent: False for ent in entities}
    block_details = {}

    for name, code in blocks:
        matches, _ = check_entities_exist_cpp(code, entities, partial_match=partial_match)
        block_details[name] = matches
        for ent, ok in matches.items():
            if ok:
                aggregate_matches[ent] = True

    coverage = sum(aggregate_matches.values()) / len(entities) if entities else 1.0
    return aggregate_matches, coverage, block_details

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



async def analyze_record(idx, record_info, summary_record, output_path, file_path, max_attempts=1):


    async with local_semaphore:
        record_function = record_info.get("function_name")
        record_file = record_info.get("file")
        record_lines = record_info.get("lines")

        record_id = (record_function, record_file, record_lines)
        print(f"\n[INFO] Elaborando record {idx} (id: {record_id})")

        try:
            # Ottieni lo snippet del codice da analizzare
            if USE_SUMMARY_MODE:
                core_snippet = await aggrega_info_record(record_info, summary_record)
            else:
                core_snippet = await aggrega_callee_code(record_info)

            res, coverage = None, 0.0

            # ===== LOOP: esegui local_agent.run finché coverage < 1.0 =====
            for attempt in range(1, max_attempts + 1):
                print(f"[INFO] Tentativo {attempt} per record {record_id}")
                res = await local_agent.run(core_snippet)
                coverage = 0.0

                # Se il risultato non ha 'Involved_entities', evita crash
                #entities = res.output.ReferencedEntities
                #if not entities:
                #    print("[WARN] Nessuna entità trovata. Coverage impostato a 0.")
                #    coverage = 0.0
                #else:
                #    matches, coverage, block_details = check_entities_per_snippet(record_info, entities)
                #print(f"[DEBUG] Coverage={coverage:.2f} | Matches={matches}")
                #for block, detail in block_details.items():
                #    print(f"[TRACE] Bloc '{block}': {detail}")

                #validator_prompt = build_validation_prompt(core_snippet, res.output.VulnerabilityReason)
                #print(f"\n[DEBUG] Validation prompt: {validator_prompt}")
                #validator_res = await validator_agent.run(validator_prompt)

                # Controlla se copertura è completa
                #if validator_res.output.Validate:
                #    print(f"[SUCCESS] Validazione completa per record {record_id}")
                    #maybe a log for extracted entities
                #    coverage = 1.0
                #    break
                #else:
                    # Opzionale: segnala entità mancanti per debugging
                #    missing = validator_res.output.Hallucinated_entities
                #    print(f"[INFO] Entità mancanti: {missing}")
                    
                    #TO-DO log for missing entities (maybe in the assessment itself) #DONE

                    # Puoi aggiungere qui un raffinamento del prompt o una pausa
                #    await asyncio.sleep(0.5)

            # ===== SALVATAGGIO RISULTATI =====
            
            #await save_assessment(output_path,file_path,record_id,record_info,core_snippet,res.output.vulnerable,res.output.description)
            await save_assessment_semantic(output_path,file_path,record_id,record_info,core_snippet,res.output.sinks)

            print(f"[SUCCESS] Record {record_id} elaborato correttamente (coverage={coverage:.2f}).")

        except Exception as e:
            print(f"[ERROR] Errore nell'elaborazione del record {record_id}: {e}")




async def process_local_agents_async(records_input, summary_path, output_path, file_path):
    with open(records_input, "r", encoding="utf-8") as f:
        records = json.load(f)

    summary_record = []
    if USE_SUMMARY_MODE and os.path.exists(summary_path):
        with open(summary_path, "r", encoding="utf-8") as f:
            summary_record = json.load(f)

    tasks = []
    for idx, record_info in enumerate(records, start=1): #[:x]
        # --- RATE LIMITING (modular, easy to comment out) ---
        #await rate_limit_tier1()
        # -----------------------------------------------------
        tasks.append(analyze_record(idx, record_info, summary_record, output_path, file_path))

    print(f"[INFO] Avvio di {len(tasks)} local agent per {records_input}")
    await asyncio.gather(*tasks)
    print(f"[INFO] Tutti i local agent completati per {records_input}")

# ================= PIPELINE (async) =================
async def generate_all_summaries():
    print("\n=== Starting SUMMARY GENERATION PHASE ===")
    for json_path in find_enriched_json_files(ENRICHED_PATH):
        out_summary_json = get_output_path_for_summary(json_path)
        out_summary_info = out_summary_json.replace(".json", "_info.json")

        ensure_dir(os.path.dirname(out_summary_json))
        await process_definitions_async(json_path, out_summary_json)

        info = {
            "source_file": json_path,
            "output_summary": out_summary_json,
            "timestamp": datetime.now().isoformat()
        }
        with open(out_summary_info, "w") as f:
            json.dump(info, f, indent=2)

    print("\nTutti i summary generati.")

async def run_all_local_analyses():
    print("\n=== Starting LOCAL AGENT PHASE ===")
    for json_path in find_enriched_json_files(ENRICHED_PATH):
        rel_path = get_relative_path_to_root(json_path)
        repo_dir = os.path.dirname(rel_path)

        summary_path = os.path.join(SUMMARY_PATH, repo_dir, "summary.json")
        output_path, exp_dir = get_output_path_for_experiment(json_path)
        info_path = os.path.join(exp_dir, "experiment_info.json")

        await process_local_agents_async(json_path, summary_path, output_path, json_path)

        info = {
            "source_snippet": json_path,
            "linked_summary": summary_path if USE_SUMMARY_MODE else "bypassed",
            "output_file": output_path,
            "prompt_version": EXPERIMENT_VERSION,
            "mode": "summary" if USE_SUMMARY_MODE else "callee-code",
            "timestamp": datetime.now().isoformat(),
        }
        with open(info_path, "w") as f:
            json.dump(info, f, indent=2)

    print("\nTutti i local agent completati.")

# ================= DEBUG MODE (async) =================
async def debug_mode(target_id):
    """
    DEBUG MODE:
    Run analysis only for the record with the specified ID.
    target_id must be a tuple: (function_name, file, lines)
    """
    print("\nDEBUG MODE ENABLED")

    summary_input = "/home/michele/Desktop/ricerca/agents/local_tier_evaluation_framework/enriched_snippets_c/CVE-2022-28321/modules/pam_access_pam_access_c/enriched_snippets.json"
    summary_output = "/home/michele/Desktop/ricerca/agents/local_agent/layout_summaries.json"
    records_input = summary_input
    summary_path = summary_output
    output_path = "/home/michele/Desktop/ricerca/agents/local_tier_evaluation_framework/test_single_record/ABLATION_CWE_862_863/CVE_2022_28321_GPT51.json"
    file_path = "/home/michele/Desktop/ricerca/output_repos_cpp/CVE-2021-4300/repo/src/main.cpp"

    # Generate summaries only if in summary mode
    if USE_SUMMARY_MODE:
        await process_definitions_async(summary_input, summary_output)

    # Load records
    with open(records_input, "r", encoding="utf-8") as f:
        all_records = json.load(f)

    # Filter only the record with the requested ID
    filtered = []
    for record in all_records:
        rid = (
            record.get("function_name"),
            record.get("file"),
            record.get("lines")
        )
        if rid == target_id:
            filtered.append(record)
            break

    if not filtered:
        print(f"[ERROR] No record found with ID: {target_id}")
        return

    # If summary mode, load summary records
    summary_record = []
    if USE_SUMMARY_MODE and os.path.exists(summary_path):
        with open(summary_path, "r", encoding="utf-8") as f:
            summary_record = json.load(f)

    # Process only the selected record
    print(f"[INFO] Running local agent for only this record: {target_id}")
    await analyze_record(
        idx=1,
        record_info=filtered[0],
        summary_record=summary_record,
        output_path=output_path,
        file_path=file_path
    )

# ================= ENTRYPOINT =================
async def main():
    if DEBUG_MODE:
        # Example target ID you want to debug
        target_id = (
            "network_netmask_match",                 # function_name
            "/home/michele/Desktop/ricerca/output_repos_c/CVE-2022-28321/repo/modules/pam_access/pam_access.c",           # file
            "722-816"                      # lines
        )
        await debug_mode(target_id)
    else:
        if USE_SUMMARY_MODE:
            await generate_all_summaries()
        await run_all_local_analyses()

if __name__ == "__main__":
    asyncio.run(main())
