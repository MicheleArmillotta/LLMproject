import json
import asyncio
import os
from local_agent.local_agent import (
    SummaryDeps,
    summary_agent,
    LocalDeps,
    local_agent,
    aggrega_info_record,
)


#Lock globale per scrittura sicura nei file JSON
file_write_lock = asyncio.Lock()

#Semafori per limitare gli agenti attivi in parallelo
summary_semaphore = asyncio.Semaphore(1)  
local_semaphore = asyncio.Semaphore(1)   


#-----------------------SUMMARY AGENT


async def process_definitions_async(input_json_path: str, output_json_path: str):
    """
    Esegue i summary agent in parallelo, con limite imposto dal semaforo.
    """
    # Carica i record dal file JSON
    with open(input_json_path, "r", encoding="utf-8") as f:
        records = json.load(f)

    async def analyze_definition(record, def_name, code_snippet):
        async with summary_semaphore:
            record_id = record.get("id")
            deps = SummaryDeps(
                output=output_json_path,
                id=record_id,
                function_called=def_name,
            )

            prompt = (
                f"Analyze the following code snippet and summarize its behavior.\n"
                f"Code snippet:\n{code_snippet}"
            )

            try:
                print(f"[INFO] Starting summary for '{def_name}' (record {record_id})")
                result = await summary_agent.run(prompt, deps=deps)
                print(f"[SUCCESS] Summary creato per '{def_name}' (ID {record_id})")
                return result
            except Exception as e:
                print(f"[ERROR] Fallita analisi di '{def_name}': {e}")
                return None

    # Crea tutti i task in parallelo
    tasks = []
    for record in records[:5]:
        definitions = record.get("definitions", {})
        if not definitions:
            print(f"[INFO] Nessuna definizione trovata per funzione {record.get('id')}")
            continue

        for def_name, def_info in definitions.items():
            code_snippet = def_info.get("definition", "").strip()
            if code_snippet:
                tasks.append(analyze_definition(record, def_name, code_snippet))

    print(f"\n[INFO] Eseguendo {len(tasks)} summary agent in parallelo...\n")

    # Avvia tutte le analisi in parallelo (rispettando il semaforo)
    results = await asyncio.gather(*tasks)
    print(f"\n[INFO] Tutti i summary agent completati.")
    return results


#-----------------------LOCAL AGENT-----------------------


async def process_local_agents_async(
    records_input: str, summary_path: str, output_path: str, file_path: str
):
    """
    Esegue i local agent in parallelo DOPO che i summary agent hanno completato.
    """
    # Carica i record principali
    with open(records_input, "r", encoding="utf-8") as f:
        data = json.load(f)
        records = data if isinstance(data, list) else [data]

    # Carica i record di summary (stesso file)
    with open(summary_path, "r", encoding="utf-8") as f:
        summary_record = json.load(f)

    async def analyze_record(idx, record_info):
        async with local_semaphore:
            record_id = record_info.get("id")
            print(f"\n[INFO] Elaborando record {idx}/{len(records)} (id: {record_id})")

            try:
                core_snippet = await aggrega_info_record(record_info, summary_record)


                print(f"DEBUG: core snippet:\n {core_snippet}")
                locDeps = LocalDeps(
                    output=output_path,
                    file_path=file_path,
                    info=record_info,
                )

                result = await local_agent.run(core_snippet, deps=locDeps)
                print(f"[SUCCESS] Record {record_id} elaborato correttamente.")
                return result
            except Exception as e:
                print(f"[ERROR] Errore nell'elaborazione del record {record_id}: {e}")
                return None

    tasks = [
        analyze_record(idx, record_info)
        for idx, record_info in enumerate(records[:5], start=1)
    ]

    print(f"\n[INFO] Eseguendo {len(tasks)} local agent in parallelo...\n")

    results = await asyncio.gather(*tasks)
    print(f"\n[INFO] Tutti i local agent completati.")
    return results

#----------------------MAIN------------------ 


async def main():
    summary_input = "/home/michele/Desktop/ricerca/agents/local_agent/7thTest.context.json"
    summary_output = "/home/michele/Desktop/ricerca/agents/local_agent/layout_summaries.json"

    records_input = "/home/michele/Desktop/ricerca/agents/local_agent/7thTest.context.json"
    summary_path = "/home/michele/Desktop/ricerca/agents/local_agent/layout_summaries.json"
    output_path = "/home/michele/Desktop/ricerca/agents/local_agent/Vulnerability_assessment.json"
    file_path = "/home/michele/Desktop/ricerca/output_repos_cpp/CVE-2015-2313/repo/c++/src/capnp/layout.c++"

    # STEP 1: esegui tutti i summary agent (in parallelo con limite)
    await process_definitions_async(summary_input, summary_output)

    # STEP 2: dopo che i summary sono completati, esegui i local agent
    await process_local_agents_async(records_input, summary_path, output_path, file_path)


if __name__ == "__main__":
    asyncio.run(main())
