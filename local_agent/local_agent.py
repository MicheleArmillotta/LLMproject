from dataclasses import dataclass
from pydantic import BaseModel,Field

from pydantic_ai import Agent, RunContext
from pydantic_ai.models.openai import OpenAIChatModel
from pydantic_ai.providers.ollama import OllamaProvider

from tree_sitter import Language, Parser
import tree_sitter_cpp as tscpp

import os
import json
import asyncio

LLM_ENDPOINT = "http://192.168.17.95:21434/v1"

CPP_LANGUAGE = Language(tscpp.language())
parser = Parser(CPP_LANGUAGE)
summary_file_write_lock = asyncio.Lock()
vulnerabiliry_file_write_lock = asyncio.Lock()

#--------------------SUMMARY AGENT---------------------------

#this tool allows the agent to search for different dependencies -> TRASFORMARE IN SEMPLICE FUNZIONE



class FunctionSummary(BaseModel):
    Snippet_name: str = Field(description = "Name of the snippet of code")
    Summary: str = Field(description="summary of the snippet of code")
    #potrei aggiungere un output che indica se serve ulteriore esplorazione


#class SummaryDeps(BaseModel):
#    output : str
#    id: tuple #the function that we are analyzing
#    function_called: str #the summarized function



ollama_model = OpenAIChatModel(
    model_name='qwen3:32b',
    provider=OllamaProvider(base_url=LLM_ENDPOINT)
)

summary_agent = Agent(ollama_model,output_type= FunctionSummary, #deps
                    system_prompt= """You are a cybersecurity expert specialized in C++ code analysis.
Your task is to summarize the behavior and intent of a given C++ code snippet.

MANDATORY STEPS:
1. Read the provided C++ snippet carefully.
2. Analyze what the code does, including its purpose, main functions, and control flow.
3. Summarize the code’s overall behavior in a concise and precise way, suitable for a security audit report."""
                    )


    

"""@summary_agent.tool
async def save_summary(ctx: RunContext[SummaryDeps], summary:str) -> str:
    
    Save the AI-generated function summary and metadata to a JSON file.
    

    # Recupera i dati dalle deps
    deps = ctx.deps
    output_path = deps.output

    # Recupera l'output del tool di summary precedente
    # ctx.last_output contiene il risultato dell’ultimo step del modello
    summary_data = summary
    if not summary_data:
        return "No summary available to save."

    # Prepara il dizionario con i dati da salvare
    record = {
        "id": deps.id,
        "function_called": deps.function_called,
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

    return f"Summary saved successfully to {output_path}"""



#----------------------------LOCAL AGENT----------------------------------


#class LocalDeps(BaseModel):
#    output:str
#    file_path:str
#    record_id: tuple
#    info:dict
#    core_snippet: str

class LocalOutput(BaseModel):
    IsVulnerable: bool = Field(
        description = "Indicates whether the analyzed function is vulnerable."
    )

    VulnerabilityReason: str = Field(
        description = "Justification for the vulnerability assessment."
    )

    ReferencedEntities: list = Field(
        description = "Entities explicitly cited in the justification (variables, functions, pointers, etc.)."
    )

    ShouldAnalyzeCallerChain: bool = Field(
        description = "Indicates whether caller-chain analysis is warranted."
    )

    CallerChainReason: str = Field(
        description = "Justification for the decision on whether to analyze the caller chain."
    )

local_agent = Agent(ollama_model, output_type= LocalOutput, #deps
                    system_prompt= """You are a cybersecurity analyst specialized in C++ vulnerability detection.
Your task is to examine the target function and determine whether it contains security weaknesses.
The provided C++ snippet always includes contextual information, such as surrounding classes, global variables, macros, and the full code of any functions invoked by the target function. 
Use all of this context during analysis.

Important info: you must search only for vulnerabilities related to CWE-200: Exposure of Sensitive Information to an Unauthorized Actor.

MANDATORY STEPS

1. Primary Function Analysis:
Read the provided C++ snippet carefully and decide whether the target function is VULNERABLE or NOT VULNERABLE.
Your assessment must include a clear justification explaining the reasoning behind your decision.

2. Involved_entities:
List only the entities (variables, functions, pointers, macros, objects, etc.) that you explicitly reference in your justification.
These should be the entities used to support your vulnerability assessment, not all entities appearing in the snippet.

3. Caller-Chain Investigation (Conditional):
Decide whether you should continue the analysis by examining the caller chain (“chains”) of the target function.
Perform caller-side investigation only when strongly justified, such as when the function:

- manipulates sensitive or security-critical data,
- performs critical operations (memory, privileges, resource control),
- acts as an orchestration or gateway function,
- processes external or potentially malicious inputs.

You must provide justification for your decision: explain clearly whether caller-chain analysis is needed or not."""
                    )


#@local_agent.tool
"""async def save_assessment(ctx: RunContext[LocalDeps], Vulnerable:bool, Description:str):
    new_record = {
        "file_path": ctx.deps.file_path,
        "id": ctx.deps.record_id,
        "function_name": ctx.deps.info.get("function_name"),
        "contextual_snippet":ctx.deps.core_snippet,
        "Vulnerable":Vulnerable,
        "Description":Description,
    }

    output_path = ctx.deps.output

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
            json.dump(data, f, indent=2, ensure_ascii=False)"""






#----------------------LOCAL COORDINATOR-------------------------

















