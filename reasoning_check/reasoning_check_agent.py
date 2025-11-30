from pydantic import BaseModel,Field

from pydantic_ai import Agent, RunContext
from pydantic_ai.models.openai import OpenAIChatModel
from pydantic_ai.providers.ollama import OllamaProvider

import asyncio

vulnerabiliry_file_write_lock = asyncio.Lock()
LLM_ENDPOINT = "http://192.168.17.95:21434/v1"

#----------------------CALL CHAIN AGENT
ollama_model = OpenAIChatModel(
    model_name='qwen3:32b',
    provider=OllamaProvider(base_url=LLM_ENDPOINT)
)


class ReasoningDeps(BaseModel):
    few_shot_examples : str #json or database info (path)



class ResOutput(BaseModel):
    Coherency: bool = Field(description = "Assest if the descriptions of the vulnerabilities are coherent")
    Evaluation: str = Field(description = "Reason of the coherency assessment")
    Weakest_tier: int = Field(description= "Indicates the chosen tier for re-evaluation. 1 = First tier, 2 = Second tier, 3 = Both")



reasoning_check_agent = Agent(ollama_model,output_type= ResOutput,
                    system_prompt= """You are a cybersecurity expert specialized in C++ code analysis.
Your task is to determine whether two vulnerability assessments related to the same function are COHERENT or NOT COHERENT.

INFO:
Each assessment includes:
- A boolean assessment (True if vulnerable, False otherwise)
- A textual description
- A list of involved entities

MANDATORY STEPS:
1. Retrive some examples related to the task you are doing.
2. Read both assessments carefully.
3. Analyze them and provide your coherency assessment.
4. Indicate which assessment (tier) is the weakest one, meaning the one that is most likely incorrect if the two are not coherent. You may indicate both tiers if appropriate.

Additional context:
Both descriptions refer to the same function. The first assessment evaluates the function in isolation (function-level assessment), while the second assessment evaluates it in the broader repository context (repo-level assessment), including analysis of its caller chain."""
                    )


@reasoning_check_agent.system_prompt
async def get_FS_examples(ctx:RunContext[ReasoningDeps]) -> str:
    import json

    # Load the JSON file containing the examples
    with open(ctx.deps.few_shot_examples, "r", encoding="utf-8") as f:
        data = json.load(f)

    examples = data.get("examples", [])
    output_lines = []

    # Build concatenated string for all examples
    for i, ex in enumerate(examples, start=1):
        section_header = f"---------EXAMPLE {i}------------"
        prompt = ex.get("prompt", "").strip()
        expected_output = json.dumps(ex.get("expected_output", {}), indent=2, ensure_ascii=False)
        example_block = f"{section_header}\n\n{prompt}\n\nExpected Output:\n{expected_output}\n"
        output_lines.append(example_block)

    return "\n\n".join(output_lines)


