import json
from pydantic_ai import Agent
from local_agent.local_agent import SummaryDeps
from local_agent.local_agent import summary_agent
from local_agent.local_agent import aggrega_info_record
from local_agent.local_agent import LocalDeps
from local_agent.local_agent import local_agent



if __name__ == "__main__":

    def process_definitions(input_json_path: str, output_json_path: str):
        # Carica i record dal file JSON
        with open(input_json_path, "r") as f:
            records = json.load(f)

        for record in records[:5]:
            record_id = record.get("id")
            #used_entities = record.get("used_entities",{})
            definitions = record.get("definitions", {})

            # Salta se non ci sono definizioni
            if not definitions:
                print(f"[INFO] Nessuna definizione trovata per funzione {record_id}")
                continue

            # Analizza ogni definizione
            for def_name, def_info in definitions.items():
                code_snippet = def_info.get("definition", "").strip()
                if not code_snippet:
                    continue

                print(f"\n[INFO] Analizzando definizione '{def_name}', function_id {record_id}: ")

                # Crea le deps per questa chiamata
                deps = SummaryDeps(
                    output=output_json_path,
                    id=record_id,
                    function_called=def_name,
                )

                # Crea il prompt da dare all'agente
                prompt = (
                    f"Analyze the following code snippet and summarize its behavior.\n"
                    f"Code snippet:\n{code_snippet}"
                )

                # Esegui il modello in modo sincrono
                try:
                    result = summary_agent.run_sync(
                        prompt,
                        deps=deps,
                    )
                    print(f"[SUCCESS] Summary creato per '{def_name}' (ID {record_id})")
                except Exception as e:
                    print(f"[ERROR] Fallita analisi di '{def_name}': {e}")

    process_definitions(   #da cambiare nel framework piu grande
        input_json_path="/home/michele/Desktop/ricerca/local_agent/7thTest.context.json",
        output_json_path="/home/michele/Desktop/ricerca/local_agent/layout_summaries.json"
    )
    
    #-----------------------------------LOCAL AGENT

    records_input = "/home/michele/Desktop/ricerca/agents/local_agent/7thTest.context.json"
    altri_record = "/home/michele/Desktop/ricerca/agents/local_agent/layout_summaries.json"
    output_path = "/home/michele/Desktop/ricerca/agents/local_agent/Vulnerability_assessment.json"
    file_path = "/home/michele/Desktop/ricerca/output_repos_cpp/CVE-2015-2313/repo/c++/src/capnp/layout.c++"

    # Carica i record principali
    with open(records_input, 'r', encoding='utf-8') as f:
        data = json.load(f)
        records = data if isinstance(data, list) else [data]

    # Carica i record di summary (sempre lo stesso file)
    with open(altri_record, 'r', encoding='utf-8') as f:
        summary_record = json.load(f)

    # Lista per salvare tutti i risultati
    results = []

    for idx, record_info in enumerate(records, start=1):
        if idx > 5:
            break
        print(f"\n[INFO] Elaborando record {idx}/{len(records)} (id: {record_info.get('id')})")

        try:
            # Aggrega le informazioni con i summaries
            core_snippet = aggrega_info_record(record_info, summary_record)

            print(f"{core_snippet}")

            # Crea le dipendenze per l'agente locale
            locDeps = LocalDeps(
                output=output_path,
                file_path=file_path,
                info=record_info,
            )

            # Esegui l'agente con il codice aggregato
            result = local_agent.run_sync(
                f"{core_snippet}",
                deps=locDeps,
            )


            print(f"[SUCCESS] Record {record_info.get('id')} elaborato correttamente.")

        except Exception as e:
            print(f"[ERROR] Errore nell'elaborazione del record {record_info.get('id')}: {e}")
            continue

    # Scrivi i risultati finali nel file di output
    #with open(output_path, 'w', encoding='utf-8') as f:
    #    json.dump(results, f, indent=2, ensure_ascii=False)





    #print("Messages:", result.all_messages())  # Mostra tutta la conversazione

    #print(result.output)