import os
import json
import asyncio
from datetime import datetime
from local_agent.local_agent import local_agent
from call_chain_agent.call_chain_agent import chain_agent
from reasoning_check.reasoning_check_agent import reasoning_check_agent, ReasoningDeps

# ================= CONFIG =================
FUNC_VULN_PATH = "/home/michele/Desktop/ricerca/agents/local_tier_evaluation_framework/vulnerability_assessment/experimentVersion2/CVE-2013-7299/framework/common_messageheaderparser_cpp/vulnerability_assessment.json"
CHAIN_VULN_PATH = "/home/michele/Desktop/ricerca/agents/local_tier_evaluation_framework/chain_assessments/CVE-2013-7299/repo/framework/common/vulne_chain_assessment.json"

OUTPUT_FUNC = "/home/michele/Desktop/ricerca/agents/local_tier_evaluation_framework/final_vuln_assessment/final_assessment_func.json"
OUTPUT_CHAIN = "/home/michele/Desktop/ricerca/agents/local_tier_evaluation_framework/final_chain_assessment/final_assessment_chain.json"

# === TEMP STRUCTURES IN MEMORY ===
TEMP_FUNC_MEM = {}
TEMP_CHAIN_MEM = {}

MAX_FEEDBACK_ROUNDS = 3

chain_file_write_lock = asyncio.Lock()
vulnerabiliry_file_write_lock = asyncio.Lock()

#================== SAVE UTILS ============

async def save_assessment(output:str,file_path:str, record_id:tuple,info:dict,core_snippet:StopAsyncIteration, Vulnerable:bool, Description:str):
    new_record = {
        "file_path": file_path,
        "id": record_id,
        "function_name": info.get("function_name"),
        "contextual_snippet":core_snippet,
        "Vulnerable":Vulnerable,
        "Description":Description,
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


async def save_assessment_chain(output:str, file_path:str, info:dict, Vulnerable:bool, Description:str):
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
    }

    output_path = output

    async with chain_file_write_lock:

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




# ================= UTILS =================
def ensure_dir(path):
    os.makedirs(os.path.dirname(path), exist_ok=True)

def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def save_json(data, path):
    ensure_dir(path)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def extract_id(record):
    """Restituisce una tupla (function_name, file_path, lines) valida."""
    return tuple(record["id"])



async def cross_feedback_reasoning(record_func, record_chain):
    func_id = extract_id(record_func)
    print(f"\n[FEEDBACK] Cross feedback reasoning for {func_id}")

    original_pair = (
        bool(record_func.get("Vulnerable", False)),
        bool(record_chain.get("Vulnerable", False)),
    )

    feedback_trace = []
    contextual_snippet = record_func.get("contextual_snippet", "")
    chain_snippets = [s.get("snippet", "") for s in record_chain.get("chains", {}).get("snippets", [])]
    func_desc = record_func.get("Description", "")
    chain_desc = record_chain.get("Description", "")

    # Ottieni o crea lista locale per questo id
    TEMP_FUNC_MEM.setdefault(func_id, [])
    TEMP_CHAIN_MEM.setdefault(func_id, [])

    verdict = None
    feedback_reason = None

    for round_idx in range(1, MAX_FEEDBACK_ROUNDS + 1):
        print(f"\n[ROUND {round_idx}] Re-evaluating {func_id}")

        # local agent
        core_snippet = contextual_snippet + "\n\n--- FEEDBACK CONTEXT ---\n" + chain_desc
        print(f"\n[DEBUG] core snippet re-eval:\n {core_snippet}")
        #locDeps = LocalDeps(output=OUTPUT_FUNC, file_path=record_func.get("file_path"),
        #                    record_id=func_id, info=record_func, core_snippet=core_snippet)
        result_func = await local_agent.run(core_snippet) #localDeps

        # chain agent
        chain_code = "\n\n".join(chain_snippets) + "\n\n--- FEEDBACK CONTEXT ---\n" + func_desc
        print(f"\n[DEBUG] chain re-eval:\n {chain_code}")
        #chDeps = ChainDeps(output=OUTPUT_CHAIN, file_path=record_func.get("file_path"), info=record_chain)
        result_chain = await chain_agent.run(chain_code) #chDeps

        # aggiungi in memoria
        TEMP_FUNC_MEM[func_id].append(result_func.output)
        TEMP_CHAIN_MEM[func_id].append(result_chain.output)

        # estrai valori
        pairs = [
            (bool(f.Vulnerable), bool(c.Vulnerable))
            for f, c in zip(TEMP_FUNC_MEM[func_id], TEMP_CHAIN_MEM[func_id])
        ]
        feedback_trace = [f"Round {i+1}: func={p[0]}, chain={p[1]}" for i, p in enumerate(pairs)]

        # === EARLY STOP RULES ===
        from collections import Counter
        if any(p == original_pair for p in pairs):
            feedback_reason = "kept_original"
            verdict = "TP" if original_pair[0] else "TN"
            break

        non_original_pairs = [p for p in pairs if p != original_pair]
        cnt = Counter(non_original_pairs)
        for pair_val, count in cnt.items():
            if count >= 2:
                feedback_reason = "changed_after_consensus"
                verdict = "TP" if pair_val[0] else "TN"
                last_idx = max(i for i, p in enumerate(pairs) if p == pair_val)
                func_temp_latest = TEMP_FUNC_MEM[func_id][last_idx]
                chain_temp_latest = TEMP_CHAIN_MEM[func_id][last_idx]
                break
        else:
            if len(set(non_original_pairs)) >= 2:
                feedback_reason = "contradictory"
                verdict = "FP"
                break

    # === post-eval ===
    if verdict is None:
        non_original_pairs = [p for p in pairs if p != original_pair]
        from collections import Counter
        cnt = Counter(non_original_pairs)
        consensus_pair = next((p for p, c in cnt.items() if c >= 2), None)

        if any(p == original_pair for p in pairs):
            feedback_reason = "kept_original"
            verdict = "TP" if original_pair[0] else "TN"
        elif consensus_pair:
            feedback_reason = "changed_after_consensus"
            verdict = "TP" if consensus_pair[0] else "TN"
            last_idx = max(i for i, p in enumerate(pairs) if p == consensus_pair)
            func_temp_latest = TEMP_FUNC_MEM[func_id][last_idx]
            chain_temp_latest = TEMP_CHAIN_MEM[func_id][last_idx]
        else:
            feedback_reason = "contradictory"
            verdict = "FP"

    print(f"[RESULT] {func_id} → {verdict} ({feedback_reason})")

    # === OUTPUT FINALI ===
    def append_final(path, rec):
        data = []
        if os.path.exists(path):
            try:
                data = json.load(open(path, "r", encoding="utf-8"))
            except Exception:
                data = []
        data.append(rec)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    if verdict == "FP":
        for r, path in [(record_func, OUTPUT_FUNC), (record_chain, OUTPUT_CHAIN)]:
            out = dict(r, final_verdict="FP", feedback_trace=feedback_trace)
            append_final(path, out)
        return verdict, feedback_trace, feedback_reason

    # aggiornamento “changed_after_consensus”
    if feedback_reason == "changed_after_consensus":
        record_func["Vulnerable"] = func_temp_latest.Vulnerable
        record_func["Description"] = func_temp_latest.Description
        record_chain["Vulnerable"] = chain_temp_latest.Vulnerable
        record_chain["Description"] = chain_temp_latest.Description

    for r, path in [(record_func, OUTPUT_FUNC), (record_chain, OUTPUT_CHAIN)]:
        out = dict(r, final_verdict=verdict, feedback_trace=feedback_trace, feedback_reason = feedback_reason)
        append_final(path, out)

    return verdict, feedback_trace, feedback_reason



# ================= CONSISTENCY CHECK =================
async def reasoning_consistency_check(record_func, record_chain):
    func_id = extract_id(record_func)
    print(f"\n[CONSISTENCY] Checking coherence for {func_id}")
    
    bool1 = record_func.get("Vulnerable","")
    bool2 = record_chain.get("Vulnerable","")
    desc1 = record_func.get("Description", "")
    desc2 = record_chain.get("Description", "")
    entities1 = record_func.get("Involved_entities","")
    entities2 = record_chain.get("Involved_entities","")

    deps = ReasoningDeps(few_shot_examples="/home/michele/Desktop/ricerca/agents/reasoning_check/learning_examples/examples.json")
    prompt = f"Compare the two vulnerability assessments:\n\n[Function Tier]\nVulnerable: {bool1}\nDescription: {desc1}\nEntities: {entities1}\n\n[Chain Tier]\nVulnerable: {bool2}\nDescription: {desc2}\nEntities: {entities2}"
    result = await reasoning_check_agent.run(prompt,deps=deps)

    result_text = result.output.Coherency
    verdict = "coerente" if result_text else "non coerente"


    print(f"[CONSISTENCY RESULT] {func_id}: {verdict}")

    # Se coerente → scrivi nei final JSON
    if verdict == "coerente":
        for path, record in [(OUTPUT_FUNC, record_func), (OUTPUT_CHAIN, record_chain)]:
            existing = []
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    existing = json.load(f)
            existing.append(record)
            with open(path, "w", encoding="utf-8") as f:
                json.dump(existing, f, indent=2)

    return verdict

# ================= MAIN LOGIC =================
async def compare_assessments(func_json, chain_json):
    func_records = {extract_id(r): r for r in func_json}
    chain_records = {extract_id(r): r for r in chain_json if extract_id(r)}

    matched_ids = set(func_records.keys()) & set(chain_records.keys())
    print(f"[INFO] Found {len(matched_ids)} overlapping IDs")

    for func_id in matched_ids:
        rec_f, rec_c = func_records[func_id], chain_records[func_id]
        vf, vc = rec_f.get("Vulnerable", False), rec_c.get("Vulnerable", False)

        if not vf and not vc:
            continue

        if vf != vc:
            # Disagreement → cross feedback reasoning
            verdict, trace, reason = await cross_feedback_reasoning(rec_f, rec_c)
        else:
            # Both true or both false → reasoning consistency check
            verdict = await reasoning_consistency_check(rec_f, rec_c)
            trace, reason = ["Direct consistency check"], "same verdicts"

        # Non serve aggiungere a final_func_results o riscrivere i file,
        # perché cross_feedback_reasoning e reasoning_consistency_check lo fanno già.
        rec_f["final_verdict"] = verdict
        rec_c["final_verdict"] = verdict
        rec_f["feedback_trace"] = trace
        rec_c["feedback_trace"] = trace
        rec_f["feedback_reason"] = reason
        rec_c["feedback_reason"] = reason

    print(f"[✓] Cross-verification process completed successfully.")


# ================= ENTRYPOINT =================
async def main():
    func_json = load_json(FUNC_VULN_PATH)
    chain_json = load_json(CHAIN_VULN_PATH)
    await compare_assessments(func_json, chain_json)

if __name__ == "__main__":
    asyncio.run(main())
