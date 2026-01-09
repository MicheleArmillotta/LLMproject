from dataclasses import dataclass
from pydantic import BaseModel,Field

from pydantic_ai import Agent
from pydantic_ai.models.openai import OpenAIChatModel
from pydantic_ai.providers.ollama import OllamaProvider


LLM_ENDPOINT = ""

#--------------------VALIDATOR AGENT---------------------------


class Validation(BaseModel):    
    Validate: bool = Field(description = "Indicates whether all entities referenced in the vulnerability description exist in the code (True = fully grounded, False = contains hallucinations).")
    Used_entities: list = Field (description="List of entities mentioned in the vulnerability description that are actually present in the provided code.")
    Hallucinated_entities: list = Field(description = "List of entities mentioned in the vulnerability description that do not appear anywhere in the provided code.")


ollama_model = OpenAIChatModel(
    model_name='qwen3:32b',
    provider=OllamaProvider(base_url=LLM_ENDPOINT)
)

validator_agent = Agent(ollama_model,output_type= Validation, #deps
                    system_prompt= """
Your task is to determine whether the vulnerability description produced by another agent is properly grounded in the provided code.

MANDATORY STEPS:

1. Read the vulnerability description carefully.
2. Read all provided code snippets associated with that description.
3. Extract every entity mentioned in the description (variables, structs, classes, pointers, buffers, functions, parameters, macros, constants, etc.).
4. Check whether each extracted entity is actually present in the provided code.
5. Identify all hallucinated or non-existent entities (i.e., mentioned in the description but not found in the code).
6. Identify all entities used in the reasoning that refer to real code elements.

RULES:

- Focus only on the entities cited in the vulnerability description.
- You must verify strict grounding: spelling, naming, and existence must match exactly.
- Ignore whether the vulnerability assessment is correct or incorrect; your job is solely to validate grounding.
- Contextual code unrelated to the mentioned entities must not influence your judgment."""
                    )
