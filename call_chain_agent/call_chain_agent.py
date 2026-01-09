from dataclasses import dataclass
from pydantic import BaseModel,Field

from pydantic_ai import Agent, RunContext
from pydantic_ai.models.openai import OpenAIChatModel
from pydantic_ai.providers.ollama import OllamaProvider


import os
import json
import asyncio

LLM_ENDPOINT = ""

vulnerabiliry_file_write_lock = asyncio.Lock()

#----------------------CALL CHAIN AGENT
ollama_model = OpenAIChatModel(
    model_name='qwen3:32b',
    provider=OllamaProvider(base_url=LLM_ENDPOINT)
)

#class ChainDeps(BaseModel):
#    output:str #output path
#    file_path:str #primary function file path
#    info:dict #info about the chain

class ChainOutput(BaseModel):
    Vulnerable: bool = Field(description = "Assest if the chain is vulnerable or not")
    Description: str = Field(description = "reason of the vulnerability assestment")
    Involved_entities: list = Field(description="entities exploited by the vulnerability")



chain_agent = Agent(ollama_model,output_type= ChainOutput, #deps
                    system_prompt= """You are a cybersecurity analyst specialized in C++ vulnerability detection.
You are given a chain of functions representing the chain of callers of a specific target function.
You will also receive the function-level vulnerability assessment of the target function, produced by another analysis agent.
Use this information to understand how the target function is invoked, how data flows into it, and whether the caller chain introduces unsafe usage patterns.

Important info: you must search only for vulnerabilities related to CWE-200: Exposure of Sensitive Information to an Unauthorized Actor.

MANDATORY STEPS

1. Caller-Chain Analysis
Read the entire caller chain carefully.
Your goal is to determine whether the overall usage of the target function by its callers results in the chain being VULNERABLE or NOT VULNERABLE.
Focus strictly on behaviors that affect the target function, such as:

- unsafe or unvalidated input passed to the target function,
- propagation of tainted, external, or untrusted data into the target function,
- misuse or dangerous invocation patterns from callers,
- absence of checks or mitigations that should protect the target function.

Do not consider vulnerabilities unrelated to how callers interact with each other.

2. Justification
Provide a clear explanation supporting your vulnerability assessment, describing the relevant data flows and invocation patterns across the chain.

3. Involved_entities
List only the entities (variables, functions, pointers, macros, objects, etc.) that you reference in your justification.
These should be the entities directly tied to your reasoning about how the chain affects the target function."""
                    )


"""@chain_agent.tool
async def save_assessment(ctx: RunContext[ChainDeps], Vulnerable:bool, Description:str):
    function_key = (
        ctx.deps.info.get("target_function"),
        ctx.deps.info.get("file"),
        ctx.deps.info.get("lines"),
    )
    new_record = {
        "file_path": ctx.deps.file_path,
        "id": function_key,
        "function_name": ctx.deps.info.get("qualified_name"),
        "chains":ctx.deps.info.get("chains"),
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
