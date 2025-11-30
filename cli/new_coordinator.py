import os
import json
import asyncio
from datetime import datetime
from local_agent.local_agent import local_agent
from call_chain_agent.call_chain_agent import chain_agent
from reasoning_check.reasoning_check_agent import reasoning_check_agent,ReasoningDeps

# ================= CONFIG =================
FUNC_VULN_PATH = "/home/michele/Desktop/ricerca/agents/local_tier_evaluation_framework/vulnerability_assessment/experimentVersion1/CVE-2013-7299/framework/common_messageheaderparser_cpp/vulnerability_assessment.json"
CHAIN_VULN_PATH = "/home/michele/Desktop/ricerca/agents/local_tier_evaluation_framework/chain_assessments/CVE-2013-7299/repo/framework/common/vulne_chain_assessment.json"

OUTPUT_FUNC = "/home/michele/Desktop/ricerca/agents/local_tier_evaluation_framework/reasoning_coordinator_results/final_assessment_func.json"
OUTPUT_CHAIN = "/home/michele/Desktop/ricerca/agents/local_tier_evaluation_framework/reasoning_coordinator_results/final_assessment_chain.json"

MAX_REEVAL_ROUNDS = 3

chain_file_write_lock = asyncio.Lock()
vulnerabiliry_file_write_lock = asyncio.Lock()

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
    return tuple(record["id"])

def append_final(path, rec):
    data = []
    if os.path.exists(path):
        try:
            data = json.load(open(path, "r", encoding="utf-8"))
        except Exception:
            data = []
    data.append(rec)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


# ================= PROMPT BUILDER =================

def format_prompt(record_func, record_chain):
    func_entities = record_func.get("Involved_entities", [])
    chain_entities = record_chain.get("Involved_entities", [])
    return f"""
Compare the two vulnerability assessments:

[Function Tier]
Vulnerable: {record_func.get("Vulnerable", False)}
Description: {record_func.get("Description", "")}
Entities: {', '.join(func_entities) if func_entities else 'N/A'}

[Chain Tier]
Vulnerable: {record_chain.get("Vulnerable", False)}
Description: {record_chain.get("Description", "")}
Entities: {', '.join(chain_entities) if chain_entities else 'N/A'}
"""


# ================= FINAL SAVE HELPERS =================

def mark_as_fp(record_func, record_chain, trace):
    for r, path in [(record_func, OUTPUT_FUNC), (record_chain, OUTPUT_CHAIN)]:
        out = dict(r, final_verdict="FP", feedback_trace=trace, feedback_reason="non coherent after 3 rounds")
        append_final(path, out)


def save_final_results(record_func, record_chain, verdict, trace):
    for r, path in [(record_func, OUTPUT_FUNC), (record_chain, OUTPUT_CHAIN)]:
        out = dict(r, final_verdict=verdict, feedback_trace=trace, feedback_reason="coherent")
        append_final(path, out)


# ================= CORE LOGIC =================

async def run_reasoning_cycle(record_func, record_chain):
    func_id = extract_id(record_func)
    print(f"\n[REASONING] Start reasoning for {func_id}")

    round_trace = []

    for round_idx in range(1, MAX_REEVAL_ROUNDS + 1):
        print(f"\n[ROUND {round_idx}] Checking coherence for {func_id}")

        prompt = format_prompt(record_func, record_chain)

        print(f"\n[DEBUG] Coordinator prompt:\n {prompt}")        
        deps = ReasoningDeps(few_shot_examples="/home/michele/Desktop/ricerca/agents/reasoning_check/learning_examples/examples.json")
        #prompt = f"Compare the two vulnerability assessments:\n\n[Function Tier]\nVulnerable: {bool1}\nDescription: {desc1}\nEntities: {entities1}\n\n[Chain Tier]\nVulnerable: {bool2}\nDescription: {desc2}\nEntities: {entities2}"
        result = await reasoning_check_agent.run(prompt,deps=deps)

        coherency = bool(result.output.Coherency)
        evaluation = result.output.Evaluation
        weakest_tier = int(result.output.Weakest_tier)

        print(f"[DEBUG] Coherency: {coherency}, Weakest_tier: {weakest_tier}")
        round_trace.append({
            "round": round_idx,
            "coherency": coherency,
            "evaluation": evaluation,
            "weakest_tier": weakest_tier
        })

        # === Case 1: Coherent → finalize ===
        if coherency:
            print(f"[RESULT] Coherent after {round_idx} rounds for {func_id}")
            save_final_results(record_func, record_chain, "coherent", round_trace)
            return "coherent"

        # === Case 2: Non-coherent → re-evaluate weakest tier ===
        if weakest_tier == 1:
            print("[ACTION] Re-evaluating Function Tier")
            context = record_func.get("contextual_snippet", "")
            feedback_chain_context = record_chain["Description"]
            core_snippet = context + "\n\n--- FEEDBACK CONTEXT ---\n" + feedback_chain_context

            print(f"\n[DEBUG] core snippet re-eval:\n {core_snippet}")

            new_result = await local_agent.run(core_snippet)
            record_func["Vulnerable"] = new_result.output.Vulnerable
            record_func["Description"] = new_result.output.Description
            record_func["Involved_entities"] = new_result.output.Involved_entities

        elif weakest_tier == 2:
            print("[ACTION] Re-evaluating Chain Tier")
            chain_snippets = []
            chains = record_chain.get("chains", [])
            if isinstance(chains, dict) and "snippets" in chains:
                chain_snippets = [s.get("snippet", "") for s in chains.get("snippets", [])]
            elif isinstance(chains, list):
                chain_snippets = [s.get("snippet", "") for s in chains]
            func_desc = record_func["Description"]

            chain_code = "\n\n".join(chain_snippets) + "\n\n--- FEEDBACK CONTEXT ---\n" + func_desc
            print(f"\n[DEBUG] chain re-eval:\n {chain_code}")

            new_result = await chain_agent.run(chain_code)
            record_chain["Vulnerable"] = new_result.output.Vulnerable
            record_chain["Description"] = new_result.output.Description
            record_chain["Involved_entities"] = new_result.output.Involved_entities

        elif weakest_tier == 3:
            print("[ACTION] Re-evaluating Both Tiers")
            # function
            context = record_func.get("contextual_snippet", "")
            feedback_chain_context = record_chain.get("Descritpion","")
            core_snippet = context + "\n\n--- FEEDBACK CONTEXT ---\n" + feedback_chain_context

            print(f"\n[DEBUG] core snippet re-eval:\n {core_snippet}")
            
            new_func = await local_agent.run(core_snippet)
            record_func["Vulnerable"] = new_func.output.Vulnerable
            record_func["Description"] = new_func.output.Description
            record_func["Involved_entities"] = new_func.output.Involved_entities
            # chain
            chain_snippets = []
            chains = record_chain.get("chains", [])
            if isinstance(chains, dict) and "snippets" in chains:
                chain_snippets = [s.get("snippet", "") for s in chains.get("snippets", [])]
            elif isinstance(chains, list):
                chain_snippets = [s.get("snippet", "") for s in chains]
            func_desc = record_func["Description"]

            chain_code = "\n\n".join(chain_snippets) + "\n\n--- FEEDBACK CONTEXT ---\n" + func_desc  
            print(f"\n[DEBUG] chain re-eval:\n {chain_code}")  
            #chain_code = "\n\n".join(chain_snippets)
            new_chain = await chain_agent.run(chain_code)
            record_chain["Vulnerable"] = new_chain.output.Vulnerable
            record_chain["Description"] = new_chain.output.Description
            record_chain["Involved_entities"] = new_chain.output.Involved_entities
        else:
            print("[WARN] Invalid Weakest_tier value, skipping re-evaluation.")

    # === After max rounds with no coherence ===
    print(f"[RESULT] Non-coherent after {MAX_REEVAL_ROUNDS} rounds for {func_id}")
    mark_as_fp(record_func, record_chain, round_trace)
    return "FP"


# ================= MAIN COMPARISON LOOP =================

async def compare_assessments(func_json, chain_json):
    # map multiple function records by ID
    func_records = {}
    for r in func_json:
        func_records.setdefault(extract_id(r), []).append(r)

    # map multiple chain records by ID
    chain_records = {}
    for r in chain_json:
        chain_records.setdefault(extract_id(r), []).append(r)

    matched_ids = set(func_records.keys()) & set(chain_records.keys())
    print(f"[INFO] Found {len(matched_ids)} overlapping IDs")

    # Iterate all combinations: for each func_rec, evaluate against each chain_rec
    for func_id in matched_ids:
        print(f"\n[PROCESSING ID] {func_id}")

        func_list = func_records[func_id]
        chain_list = chain_records[func_id]

        for f_idx, func_rec in enumerate(func_list):
            for c_idx, chain_rec in enumerate(chain_list):
                print(f"\n  Pair (func {f_idx}, chain {c_idx})")
                await run_reasoning_cycle(func_rec.copy(), chain_rec.copy())

    print(f"[✓] Cross-verification process completed successfully.")


# ================= ENTRYPOINT =================
async def main():
    func_json = load_json(FUNC_VULN_PATH)
    chain_json = load_json(CHAIN_VULN_PATH)
    await compare_assessments(func_json, chain_json)

if __name__ == "__main__":
    asyncio.run(main())
