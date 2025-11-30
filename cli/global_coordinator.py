import json
import os
from pathlib import Path
import asyncio
from typing import List, Dict, Optional
import logging
from datetime import datetime
from global_coordinator.global_coordinator_agent import global_coordinator_agent

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Aumenta il parallelismo come indicato nel commento
LLM_SEMAPHORE = asyncio.Semaphore(1)      # massimo 4 agent LLM in parallelo
FILE_SEMAPHORE = asyncio.Semaphore(1)     # scrittura file sempre serializzata


def build_chain_snippet(chain_info: dict) -> str:
    snippets = list(reversed(chain_info.get("snippets", [])))

    parts = ["---- CALL CHAIN SNIPPETS ----"]
    for i, snip in enumerate(snippets):
        label = "---- TARGET FUNCTION ----" if i == 0 else f"---- CALLER {i} ----"
        parts.append(f"{label}\n{snip.get('snippet','').strip()}")

    return "\n\n".join(parts)


def build_combined_prompt(function_record: dict, chain_record: dict) -> str:
    """Prompt quando ci sono sia function che chain assessment"""
    f_v = function_record["Vulnerable"]
    f_desc = function_record["Description"]
    f_code = function_record["contextual_snippet"]

    c_v = chain_record["Vulnerable"]
    c_desc = chain_record["Description"]
    chain_code = build_chain_snippet(chain_record["chains"])

    prompt = f"""
You are the Global Coordinator Agent.
Your task is to infer whether the following vulnerability assessments together yield a credible proof-of-vulnerability (PoV) and to extract conditions and exploitation requirements.

================ FUNCTION-LEVEL ASSESSMENT ================
VULNERABLE: {f_v}
DESCRIPTION:
{f_desc}

CODE:
{f_code}

================ CHAIN-LEVEL ASSESSMENT ===================
VULNERABLE: {c_v}
DESCRIPTION:
{c_desc}

CHAIN CODE:
{chain_code}

""".strip()

    return prompt


def build_function_only_prompt(function_record: dict) -> str:
    """Prompt quando c'è solo function assessment (no chain assessment vulnerabile)"""
    f_v = function_record["Vulnerable"]
    f_desc = function_record["Description"]
    f_code = function_record["contextual_snippet"]

    prompt = f"""
You are the Global Coordinator Agent.
Your task is to infer whether the following function-level vulnerability assessment yields a credible proof-of-vulnerability (PoV) and to extract conditions and exploitation requirements.

Note: No vulnerable call chain was identified for this function, so the assessment is based solely on the function-level analysis.

================ FUNCTION-LEVEL ASSESSMENT ================
VULNERABLE: {f_v}
DESCRIPTION:
{f_desc}

CODE:
{f_code}

""".strip()

    return prompt


def build_chain_only_prompt(chain_record: dict) -> str:
    """Prompt quando c'è solo chain assessment (no function assessment vulnerabile)"""
    c_v = chain_record["Vulnerable"]
    c_desc = chain_record["Description"]
    chain_code = build_chain_snippet(chain_record["chains"])

    prompt = f"""
You are the Global Coordinator Agent.
Your task is to infer whether the following chain-level vulnerability assessment yields a credible proof-of-vulnerability (PoV) and to extract conditions and exploitation requirements.

Note: No vulnerable function-level assessment was found for this chain, so the assessment is based solely on the chain-level analysis.

================ CHAIN-LEVEL ASSESSMENT ===================
VULNERABLE: {c_v}
DESCRIPTION:
{c_desc}

CHAIN CODE:
{chain_code}

""".strip()

    return prompt


def build_output_path(base_output_dir: Path, json_file_path: str, func_id: str, chain_id: Optional[str] = None) -> Path:
    """
    Ricostruisce la struttura di output basandosi sul path del JSON file.
    Aggiunge un timestamp per evitare sovrascritture.
    Esempio input: .../vulnerability_assessment/experimentVersion3/CVE-2013-7299/framework/common/file.json
    Output: <base>/experimentVersion3/CVE-2013-7299/framework/common/final_assessment_...json
    """
    try:
        p = Path(json_file_path).resolve()
        parts = p.parts

        # Trova experimentVersionX
        exp_idx = None
        for i, comp in enumerate(parts):
            if comp.startswith("experimentVersion"):
                exp_idx = i
                break

        if exp_idx is None:
            raise ValueError(f"experimentVersionX not found in path: {json_file_path}")

        experiment = parts[exp_idx]

        # CVE directory
        if exp_idx + 1 >= len(parts):
            raise ValueError("CVE directory missing after experimentVersion in path.")

        cve = parts[exp_idx + 1]

        # Repo parts: tutto tra CVE e il nome del file
        repo_parts = parts[exp_idx + 2:-1]

        # Costruzione directory finale
        out_dir = base_output_dir / experiment / cve
        if repo_parts:
            out_dir = out_dir / Path(*repo_parts)

        out_dir.mkdir(parents=True, exist_ok=True)

        # Genera timestamp per univocità
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        
        if chain_id:
            filename = f"final_assessment_func-{func_id}_chain-{chain_id}_{timestamp}.json"
        else:
            filename = f"final_assessment_func-{func_id}_no-chain_{timestamp}.json"
        
        return out_dir / filename
    
    except Exception as e:
        logger.error(f"Error building output path from {json_file_path}: {e}")
        raise


async def run_and_save(prompt: str, outfile: Path, function_record: Optional[dict], chain_record: Optional[dict], assessment_type: str):
    """
    assessment_type può essere: 'combined', 'function_only', 'chain_only'
    """
    if assessment_type == "combined":
        func_name = function_record.get("function_name", "unknown")
        chain_id = "_".join(chain_record["id"])
        log_id = f"{func_name} - chain {chain_id}"
    elif assessment_type == "function_only":
        func_name = function_record.get("function_name", "unknown")
        log_id = f"{func_name} - function only"
    else:  # chain_only
        func_name = chain_record.get("function_name", "unknown")
        chain_id = "_".join(chain_record["id"])
        log_id = f"{func_name} - chain {chain_id} only"
    
    try:
        logger.info(f"Processing ({assessment_type}): {log_id}")
        
        # Limitazione concorrenza agent LLM
        async with LLM_SEMAPHORE:
            logger.info(f"Running agent for {log_id}")
            res = await global_coordinator_agent.run(prompt)
            logger.info(f"Agent completed for {log_id}")

        # Costruzione output record in base al tipo
        if assessment_type == "combined":
            chain_code = build_chain_snippet(chain_record["chains"])
            output_record = {
                "assessment_type": "combined",
                "id": chain_record["id"],
                "file_path": chain_record["file_path"],
                "function_name": chain_record["function_name"],
                "function_code": function_record["contextual_snippet"],
                "chain_code": chain_code,
                "False_positive_reason": res.output.FalsePositiveReason,
                "Preconditions": res.output.Preconditions,
                "Trigger_actions": res.output.TriggerActions,
                "Dangerous_post_conditions": res.output.DangerousPostconditions,
                "Initial_conditions": res.output.InitialConditions,
            }
        elif assessment_type == "function_only":
            output_record = {
                "assessment_type": "function_only",
                "id": function_record["id"],
                "file_path": function_record["file_path"],
                "function_name": function_record["function_name"],
                "function_code": function_record["contextual_snippet"],
                "chain_code": None,
                "False_positive_reason": res.output.FalsePositiveReason,
                "Preconditions": res.output.Preconditions,
                "Trigger_actions": res.output.TriggerActions,
                "Dangerous_post_conditions": res.output.DangerousPostconditions,
                "Initial_conditions": res.output.InitialConditions,
            }
        else:  # chain_only
            chain_code = build_chain_snippet(chain_record["chains"])
            output_record = {
                "assessment_type": "chain_only",
                "id": chain_record["id"],
                "file_path": chain_record["file_path"],
                "function_name": chain_record["function_name"],
                "function_code": None,
                "chain_code": chain_code,
                "False_positive_reason": res.output.FalsePositiveReason,
                "Preconditions": res.output.Preconditions,
                "Trigger_actions": res.output.TriggerActions,
                "Dangerous_post_conditions": res.output.DangerousPostconditions,
                "Initial_conditions": res.output.InitialConditions,
            }

        # Scrittura serializzata
        async with FILE_SEMAPHORE:
            outfile.parent.mkdir(parents=True, exist_ok=True)
            with open(outfile, "w") as f:
                json.dump(output_record, f, indent=2)
            logger.info(f"Saved result to: {outfile}")
    
    except Exception as e:
        logger.error(f"Error processing {log_id}: {e}", exc_info=True)
        raise


async def process_assessments(func_json_path: str, chain_json_path: str, output_base: str):
    logger.info("=" * 80)
    logger.info("Starting assessment processing")
    logger.info("=" * 80)
    
    # Verifica esistenza file
    if not Path(func_json_path).exists():
        logger.error(f"Function JSON not found: {func_json_path}")
        return
    
    if not Path(chain_json_path).exists():
        logger.error(f"Chain JSON not found: {chain_json_path}")
        return
    
    logger.info(f"Loading function data from: {func_json_path}")
    with open(func_json_path, "r") as f:
        func_data: List[Dict] = json.load(f)
    logger.info(f"Loaded {len(func_data)} function records")

    logger.info(f"Loading chain data from: {chain_json_path}")
    with open(chain_json_path, "r") as f:
        chain_data: List[Dict] = json.load(f)
    logger.info(f"Loaded {len(chain_data)} chain records")
    
    # Usa il path del JSON function per ricostruire la struttura di output
    base_json_path = func_json_path

    # Map chains by function name
    chains_by_function = {}
    vulnerable_chains = 0
    for ch in chain_data:
        if ch.get("Vulnerable", False):
            vulnerable_chains += 1
            fname = ch["function_name"]
            chains_by_function.setdefault(fname, []).append(ch)
    
    # Map functions by name
    functions_by_name = {}
    vulnerable_functions_count = 0
    for func in func_data:
        if func.get("Vulnerable", False):
            vulnerable_functions_count += 1
            fname = func["function_name"]
            functions_by_name[fname] = func
    
    logger.info(f"Found {vulnerable_chains} vulnerable chains across {len(chains_by_function)} functions")
    logger.info(f"Found {vulnerable_functions_count} vulnerable functions")

    output_base = Path(output_base)
    tasks = []
    
    processed_functions = set()

    # 1. Process combined assessments (function + chain both vulnerable)
    for func in func_data:
        if not func.get("Vulnerable", False):
            continue

        fname = func["function_name"]
        processed_functions.add(fname)

        if fname in chains_by_function:
            # Caso COMBINED: function vulnerabile E chain vulnerabile
            func_id = "_".join(func["id"])
            num_chains = len(chains_by_function[fname])
            logger.info(f"Function {fname} has {num_chains} vulnerable chain(s) - COMBINED assessment")

            for chain in chains_by_function[fname]:
                chain_id = "_".join(chain["id"])

                prompt = build_combined_prompt(func, chain)
                outfile = build_output_path(
                    output_base,
                    base_json_path,  # Usa il path del JSON, non del record
                    func_id,
                    chain_id
                )

                logger.info(f"Creating COMBINED task for func={fname}, chain={chain_id}")

                tasks.append(
                    asyncio.create_task(
                        run_and_save(prompt, outfile, func, chain, "combined")
                    )
                )
        else:
            # Caso FUNCTION ONLY: function vulnerabile ma NO chain vulnerabile
            func_id = "_".join(func["id"])
            logger.info(f"Function {fname} is vulnerable but has no vulnerable chains - FUNCTION ONLY assessment")

            prompt = build_function_only_prompt(func)
            outfile = build_output_path(
                output_base,
                base_json_path,  # Usa il path del JSON, non del record
                func_id,
                None
            )

            logger.info(f"Creating FUNCTION ONLY task for func={fname}")

            tasks.append(
                asyncio.create_task(
                    run_and_save(prompt, outfile, func, None, "function_only")
                )
            )

    # 2. Process chain-only assessments (chain vulnerable but function not vulnerable or not found)
    for fname, chains in chains_by_function.items():
        if fname in processed_functions:
            # Già processato nel caso combined
            continue
        
        # Caso CHAIN ONLY: chain vulnerabile ma function NON vulnerabile o non trovata
        logger.info(f"Chain(s) for function {fname} are vulnerable but function is not - CHAIN ONLY assessment")
        
        for chain in chains:
            chain_id = "_".join(chain["id"])
            
            prompt = build_chain_only_prompt(chain)
            # Usiamo un ID fittizio per la function visto che non c'è
            func_id = "none"
            outfile = build_output_path(
                output_base,
                base_json_path,  # Usa il path del JSON, non del record
                func_id,
                chain_id
            )

            logger.info(f"Creating CHAIN ONLY task for func={fname}, chain={chain_id}")

            tasks.append(
                asyncio.create_task(
                    run_and_save(prompt, outfile, None, chain, "chain_only")
                )
            )

    logger.info(f"Created {len(tasks)} processing tasks in total")

    if not tasks:
        logger.warning("No tasks created! Check if you have any vulnerable functions or chains.")
        return

    logger.info("Starting parallel execution...")
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    # Log risultati
    successes = sum(1 for r in results if not isinstance(r, Exception))
    failures = sum(1 for r in results if isinstance(r, Exception))
    
    logger.info("=" * 80)
    logger.info(f"Processing complete: {successes} successful, {failures} failed")
    logger.info("=" * 80)
    
    # Log errori
    for i, r in enumerate(results):
        if isinstance(r, Exception):
            logger.error(f"Task {i} failed: {r}")


if __name__ == "__main__":
    asyncio.run(
        process_assessments(
            func_json_path="/home/michele/Desktop/ricerca/agents/local_tier_evaluation_framework/vulnerability_assessment/experimentVersion3/CVE-2015-8790/src/EbmlUnicodeString_cpp/vulnerability_assessment.json",
            chain_json_path="/home/michele/Desktop/ricerca/agents/local_tier_evaluation_framework/chain_assessments/experimentVersion3/CVE-2015-8790/repo/src/vulne_chain_assessment.json",
            output_base="/home/michele/Desktop/ricerca/agents/local_tier_evaluation_framework/final_global_assessment"
        )
    )