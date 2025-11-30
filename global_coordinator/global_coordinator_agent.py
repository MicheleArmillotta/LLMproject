from dataclasses import dataclass
from pydantic import BaseModel,Field

from pydantic_ai import Agent
from pydantic_ai.models.openai import OpenAIChatModel
from pydantic_ai.providers.ollama import OllamaProvider




LLM_ENDPOINT = "http://192.168.17.95:21434/v1"


ollama_model = OpenAIChatModel(
    model_name='qwen3:32b',
    provider=OllamaProvider(base_url=LLM_ENDPOINT)
)


#----------------------------GLOBAL AGENT----------------------------------

class GlobalCoordinatorOutput(BaseModel):
    FalsePositive: bool = Field(
        descritpion = (
            "Indicates a false positive"
        )
    )


    FalsePositiveReason: str = Field(
        description = (
            "Explains why the chain cannot be exploited "
            "based on the provided code (e.g., missing entities, unreachable conditions, "
            "no attacker-controlled dataflow)."
        )
    )

    Preconditions: list = Field(
        description = (
            "List of concrete conditions that must hold before the vulnerability "
            "can be triggered (e.g., specific object state, required input configuration, "
            "parameter constraints). Extracted strictly from grounded evidence."
        )
    )

    TriggerActions: list = Field(
        description = (
            'List of attacker-controlled operations or API calls that can activate the '
            'vulnerable behavior through the analyzed chain. Must be explicitly supported by code.'
        )
    )

    DangerousPostconditions: list = Field(
        description = (
            "List of dangerous states, effects, or consequences caused by triggering "
            "the vulnerability (e.g., memory corruption, invalid pointer state, "
            "buffer overflow). Only include effects proven by grounded evidence."
        )
    )

    ExploitationExample: str = Field(
        description = (
            "Concrete, realistic, and fully-grounded example of how an attacker could "
            "trigger the vulnerability via this chain. Must not include any inferred or "
            "hallucinated behavior. Empty if no grounded example can be produced."
        )
    )

    InitialConditions: list = Field(
        description = (
            "Environmental or contextual conditions required for exploitation to be feasible "
            "(e.g., object lifetime, initialization order, external constraints). "
            "Must be derived strictly from grounded code behavior."
        )
    )


global_coordinator_agent = Agent(ollama_model, output_type= GlobalCoordinatorOutput, #deps
                    system_prompt= """
You are the Global Coordinator Agent in a multi-tier vulnerability analysis pipeline.
Your role is to evaluate vulnerability evidence and determine whether a grounded, realistic exploitation perspective (“pseudo-Proof of Vulnerability”) can be derived strictly from the provided inputs and code.
You may receive any of the following combinations:

- Function-level assessment only
- Chain-level assessment only
- Both function-level and chain-level assessments

Your reasoning and outputs must always adapt to the actual inputs received.

Important info: you must search only for vulnerabilities related to CWE-200: Exposure of Sensitive Information to an Unauthorized Actor.

INPUT FORMAT
You may receive:

Function-level assessment (optional):
- IsVulnerable
- VulnerabilityReason
- FunctionCode

Chain-level assessment (optional):
- IsVulnerable
- ChainVulnerabilityReason
- ChainCode

Either section may be missing.
You must never assume evidence that is not explicitly provided.

OBJECTIVES
Your task is to evaluate—based only on grounded code evidence:

- Whether a realistic exploitation path exists.
- Whether function-level and chain-level signals (if both present) are coherent.
- Whether attacker influence, dangerous operations, or unsafe states truly exist.
- Whether a pseudo-PoV can be constructed from the available evidence.

If grounding fails at any point → classify the result as a False Positive and explain why.

WHAT YOU MUST EXTRACT (ONLY IF FULLY GROUNDED)
For each analyzed function/chain:

1. Preconditions
Initial state or input structure required to reach the vulnerable behavior.

2. Trigger Actions
What activates the unsafe behavior (attacker action or caller behavior).

3. Dangerous Post-conditions
The dangerous state or operation that results.

4. Concrete Exploitation Example
Only if fully grounded in the provided code.

5. Initial Conditions / Environmental Requirements
Object state, configuration assumptions, context of use, etc.

You must not invent entities or behaviors not supported by the code.

FALSE POSITIVE RULES

- Mark the result as False Positive when any of the following are true:
- Missing or unresolvable referenced entities
- Incoherence between function-level and chain-level assessments
- No demonstrable attacker-influenced dataflow
- No reachable dangerous operation
- The vulnerability cannot be triggered via the provided chain
- The provided input (function or chain) is insufficient to support any grounded conclusion

When marking a False Positive, include a short explanation specifying exactly what evidence was missing, and don't extract any other information.

KEY BEHAVIOR REQUIREMENTS:

- Never infer beyond what is explicitly observable in the code.
- Never generate non-grounded pseudo-PoVs.
- When function-level or chain-level assessment is missing, rely only on the available input and code.
- If only a chain-level assessment is provided, you must still evaluate whether a grounded vulnerability exists strictly from that chain.
- If only a function-level assessment is provided, evaluate whether the function alone enables exploitation.
- Search only for vulnerabilities related to CWE-200: Exposure of Sensitive Information to an Unauthorized Actor.
- If both are present, ensure their reasoning is consistent before extracting PoV elements.
"""
                    )
