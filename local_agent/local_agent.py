from dataclasses import dataclass
from pydantic import BaseModel,Field

from pydantic_ai import Agent, RunContext
from pydantic_ai.models.openai import OpenAIChatModel
from pydantic_ai.providers.ollama import OllamaProvider
from pydantic_ai.models.google import GoogleModel
from pydantic_ai.providers.google import GoogleProvider
from pydantic_ai import Agent
from pydantic_ai.models.openai import OpenAIChatModel
from pydantic_ai.providers.openai import OpenAIProvider
from pydantic_ai.models.openai import OpenAIResponsesModel

from tree_sitter import Language, Parser
import tree_sitter_cpp as tscpp
from typing import Optional

import os
import json
import asyncio


LLM_ENDPOINT = "http://192.168.17.134:21434/v1"

CPP_LANGUAGE = Language(tscpp.language())
parser = Parser(CPP_LANGUAGE)
summary_file_write_lock = asyncio.Lock()
vulnerabiliry_file_write_lock = asyncio.Lock()


provider = GoogleProvider(api_key='AIzaSyDYqXS9waRZgaU21FWL8bt8smCua5KhTgM')
model = GoogleModel('gemini-2.5-pro', provider=provider)

#OpenAI_provider=OpenAIProvider(api_key='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')
#openAI_model = OpenAIChatModel('gpt-5.1', provider = provider)

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

#class LocalOutput(BaseModel):
#    sink_ids: list[str] = Field(
#        description="Identifiers for each semantic sink (e.g., code span, line number, or short snippet)."
#    )
#    sink_descriptions: list[str] = Field(
#        description="Descriptions of the semantic sinks (privileged or security-relevant operations)."
#    )
#    sink_required_conditions: list[list[str]] = Field(
#        description="For each sink, list of semantic conditions required for safe execution."
#    )
#    sink_locally_satisfied_conditions: list[list[str]] = Field(
#        description="For each sink, list of semantic conditions that this function satisfies locally."
#    )






SYSTEM_PROMPT_FLOW = """You analyze a single C function to detect issues related to CWE-284: Improper Access Control.
Your task is strictly semantic.
You do not perform a full vulnerability audit.
You extract only:

- semantic sinks of access-control–relevant operations,
- conditions required to safely execute those sinks,
- local evidence that those conditions are enforced.

The prompt includes:
One main C function, which must always be analyzed.
Additional C functions that the main function calls.
These auxiliary functions serve only as contextual hints.
You must inspect them only if the main function alone does not provide enough information.

You must perform exactly three steps:

1. Identify Semantic Sinks (access-control–relevant operations):

A sink is any operation inside the function that requires an access-control decision to be safe.
These are operations whose safety depends on who is allowed to perform them.
Examples of sinks (not exhaustive, not templates):

- Performing privileged actions (file deletion, file modification, device access)
- Reading or writing sensitive files or directories
- Executing system commands or spawning processes
- Modifying shared or global state
- Performing operations on behalf of a caller
- Handling requests that trigger system-level effects
- IPC / network / RPC handlers that perform privileged work
- Changing configuration, permissions, or runtime state
- Acting on resources identified by caller-controlled input
- Any operation whose correctness depends on caller permissions

Return only sinks that appear inside the analyzed function.

2. Infer Required Semantic Conditions:

For each sink, infer the access-control conditions that must hold for the operation to be safe.
Conditions are not fixed per CWE; they must be inferred from the semantics of the sink itself.
A condition represents a necessary requirement to prevent unauthorized access.
Examples of conditions (not exhaustive, not templates):

- “The caller must be authorized before performing this operation”
- “The caller must have sufficient privileges to access this resource”
- “The operation must only be allowed for authenticated users”
- “The caller must own the resource being modified”
- “The function must verify permissions before executing the command”
- “Access must be restricted to a specific role or capability”
- “The operation must be denied if authorization fails”

Infer conditions only from the sink semantics.
Do not speculate about unrelated conditions.
If no conditions are inferable, return an empty list.

3. Validate the Conditions Locally:

Check whether the function itself enforces the inferred conditions.
Local evidence includes (non-exhaustive, not templates):

- explicit authorization checks
- permission or role checks
- capability or privilege verification
- ownership validation
- guard conditions that restrict execution
- error paths that reject unauthorized callers
- early returns on failed access checks
- safe defaults that deny access unless explicitly allowed

If a condition is enforced locally, record it as satisfied.
If the function provides no evidence of enforcing a condition, mark it as unsatisfied.
Do not determine whether the function is vulnerable.
Only extract structured semantic information.

Behavioral Rules:

Do not judge vulnerability. Only report sinks, conditions, and local validation.
If no sinks exist, return "sinks": [].
Be deterministic and conservative.
Check auxiliary functions only when necessary, i.e., when the main function lacks sufficient information to infer or validate a condition.
----------------------------------------------EXAMPLE 1-----------------------------------------------------
1. INPUT

MAIN

static int
check_rpcsec_auth(struct svc_req *rqstp)
{
    gss_ctx_id_t ctx;
    krb5_context kctx;
    OM_uint32 maj_stat, min_stat;
    gss_name_t name;
    krb5_principal princ;
    int ret, success;
    krb5_data *c1, *c2, *realm;
    gss_buffer_desc gss_str;
    kadm5_server_handle_t handle;

    success = 0;
    handle = (kadm5_server_handle_t)global_server_handle;

    if (rqstp->rq_cred.oa_flavor != RPCSEC_GSS)
        return 0;

    ctx = rqstp->rq_svccred;

    maj_stat = gss_inquire_context(
        &min_stat,
        ctx,
        NULL,
        &name,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL
    );

    if (maj_stat != GSS_S_COMPLETE) {
        krb5_klog_syslog(
            LOG_ERR,
            "check_rpcsec_auth: failed inquire_context, stat=%u",
            maj_stat
        );
        log_badauth(
            maj_stat,
            min_stat,
            &rqstp->rq_xprt->xp_raddr,
            NULL
        );
        goto fail_name;
    }

    kctx = handle->context;
    ret = gss_to_krb5_name(rqstp, kctx, name, &princ, &gss_str);
    if (ret == 0)
        goto fail_name;

    /*
     * Since we accept with GSS_C_NO_NAME, the client can authenticate
     * against the entire kdb.  Therefore, ensure that the service
     * name is something reasonable.
     */
    if (krb5_princ_size(kctx, princ) != 2)
        goto fail_princ;

    c1 = krb5_princ_component(kctx, princ, 0);
    c2 = krb5_princ_component(kctx, princ, 1);
    realm = krb5_princ_realm(kctx, princ);

    if (strncmp(handle->params.realm, realm->data, realm->length) == 0 &&
        strncmp("kadmin", c1->data, c1->length) == 0)
    {
        if (strncmp("history", c2->data, c2->length) == 0)
            goto fail_princ;
        else
            success = 1;
    }

fail_princ:
    if (!success) {
        krb5_klog_syslog(
            LOG_ERR,
            "bad service principal %.*s",
            gss_str.length,
            gss_str.value
        );
    }

    gss_release_buffer(&min_stat, &gss_str);
    krb5_free_principal(kctx, princ);

fail_name:
    gss_release_name(&min_stat, &name);
    return success;
}

-------- CONTEXTUAL INFORMATIONS - CALLEES CODE -------- 
-------- Code of the functions used by the analyzed function --------

Calle name:gss_to_krb5_name
static int
gss_to_krb5_name(struct svc_req *rqstp,
                 krb5_context ctx,
                 gss_name_t gss_name,
                 krb5_principal *princ,
                 gss_buffer_t gss_str)
{
    OM_uint32 status, minor_stat;
    gss_OID gss_type;
    char *str;
    int success;

    status = gss_display_name(&minor_stat, gss_name, gss_str, &gss_type);
    if ((status != GSS_S_COMPLETE) || (gss_type != gss_nt_krb5_name)) {
        krb5_klog_syslog(
            LOG_ERR,
            "gss_to_krb5_name: failed display_name status %d",
            status
        );
        log_badauth(
            status,
            minor_stat,
            &rqstp->rq_xprt->xp_raddr,
            NULL
        );
        return 0;
    }

    str = malloc(gss_str->length + 1);
    if (str == NULL)
        return 0;

    *str = '\0';
    strncat(str, gss_str->value, gss_str->length);

    success = (krb5_parse_name(ctx, str, princ) == 0);

    free(str);
    return success;
}


Callee name:log_badauth_display_status_1
void log_badauth_display_status_1(char *m,
                                 OM_uint32 code,
                                 int type,
                                 int rec)
{
    OM_uint32 gssstat, minor_stat;
    gss_buffer_desc msg;
    OM_uint32 msg_ctx;

    msg_ctx = 0;

    while (1) {
        gssstat = gss_display_status(
            &minor_stat,
            code,
            type,
            GSS_C_NULL_OID,
            &msg_ctx,
            &msg
        );

        if (gssstat != GSS_S_COMPLETE) {
            if (!rec) {
                log_badauth_display_status_1(
                    m,
                    gssstat,
                    GSS_C_GSS_CODE,
                    1
                );
                log_badauth_display_status_1(
                    m,
                    minor_stat,
                    GSS_C_MECH_CODE,
                    1
                );
            } else {
                krb5_klog_syslog(
                    LOG_ERR,
                    "GSS-API authentication error %s: recursive failure!",
                    msg
                );
            }
            return;
        }

        krb5_klog_syslog(
            LOG_NOTICE,
            "%s %s",
            m,
            (char *)msg.value
        );

        (void)gss_release_buffer(&minor_stat, &msg);

        if (!msg_ctx)
            break;
    }
}


2. REASONING

Identify semantic sink in the function:

The function’s semantic purpose is “authorize or deny” a request based on the authenticated GSS/Kerberos identity.
The single output that drives that decision is:
success = 1 (grant) vs default success = 0 (deny), finalized at return success;.
Therefore the semantic sink is: the assignment(s) that lead to success = 1 and the final return success.
Concretely, the sink condition is the if (...) { ... success = 1; } block.

Infer conditions that must hold (intended policy encoded by the code)

Work backward from the only path that sets success = 1:
success = 1 occurs only if all the guards on that path are satisfied. Reading those guards as policy, the intended conditions are:
C1: Request uses RPCSEC_GSS.
C2: GSS context can be queried and yields a client name (gss_inquire_context succeeds).
C3: The GSS name is a Kerberos principal and can be parsed (gss_to_krb5_name succeeds).
C4: The principal has exactly 2 components.
C5: Realm matches the configured realm.
C6: First component equals "kadmin" (service restriction).
C7: Second component is not "history" (exclude one instance).
The access-control relevant ones are C5–C7; C6 is the key “who is allowed” restriction.

Validate conditions locally (check the actual predicate matches the inferred condition):

For each inferred condition, compare:
Intended meaning (semantic condition) vs Actual implementation (concrete predicate)
For C6, intended meaning is:
“the first principal component is exactly the string kadmin”.
The implementation used is:
strncmp("kadmin", c1->data, c1->length) == 0
Validation reasoning steps:

Identify what controls the comparison length.
strncmp(a, b, n) compares at most n bytes.
Here, n = c1->length.
c1->length is attacker-controlled via the authenticated principal string (after parsing).
Check if the predicate enforces equality or only a prefix relation.
If n is the attacker’s length, then the check becomes:
“the first c1->length bytes of "kadmin" equal c1->data”.
That is a prefix-of-literal check, not equality.
Construct the minimal counterexample that satisfies the predicate but violates the intended condition.
Choose c1->data = "ka", c1->length = 2.
Then the predicate becomes strncmp("kadmin", "ka", 2) == 0 → true.
But "ka" is not equal to "kadmin".
Therefore the code allows principals whose first component is any prefix of "kadmin".
Confirm this counterexample reaches the semantic sink.
The rest of the guards on the success=1 path do not prevent c1="ka":
principal size 2 can still hold (e.g., "ka/anything@REALM"),
realm check (separately) can pass,
"history" exclusion applies to c2, not c1.
So the counterexample can propagate to success = 1 → authorization granted.
Conclude the mismatch.
Intended condition C6 (“exact match to kadmin”) is not locally validated.
Actual validated condition is weaker: “c1 is a prefix of kadmin”.

This is an access-control bug.

3. OUTPUT 

{
  "sinks": [
    {
      "sink_id": "return success;",
      "sink_description": "Authorization decision that grants or denies access to the RPC request based on the authenticated Kerberos service principal.",
      "required_conditions": [
        {
          "id": "rpcsec_gss_required",
          "description": "The RPC request must use the RPCSEC_GSS authentication mechanism.",
          "locally_satisfied": true,
          "justification": "The function explicitly checks rqstp->rq_cred.oa_flavor and immediately returns 0 if it is not RPCSEC_GSS."
        },
        {
          "id": "gss_context_valid",
          "description": "The GSS security context must be valid and successfully yield a client name.",
          "locally_satisfied": true,
          "justification": "gss_inquire_context is invoked and any non-GSS_S_COMPLETE result leads to logging and early exit."
        },
        {
          "id": "krb5_principal_parsed",
          "description": "The GSS name must correspond to a Kerberos principal and be successfully parsed.",
          "locally_satisfied": true,
          "justification": "gss_to_krb5_name enforces gss_nt_krb5_name and successful krb5_parse_name; failures cause denial."
        },
        {
          "id": "principal_has_two_components",
          "description": "The Kerberos principal must consist of exactly two components.",
          "locally_satisfied": true,
          "justification": "The function checks krb5_princ_size(kctx, princ) != 2 and rejects the request if the condition is not met."
        },
        {
          "id": "service_component_is_kadmin",
          "description": "The first Kerberos principal component must be exactly equal to the service name 'kadmin'.",
          "locally_satisfied": false
        }
      ]
    }
  ]
}


""" 


SYSTEM_PROMPT_BASELINE_CWE_200 = """You are a security expert analyzing a C++ function for potential vulnerabilities.
Analyze the following code and determine whether it may expose sensitive information to an unauthorized actor (CWE-200).
The prompt includes:
- One main function, which must always be analyzed.
- Additional C++ functions that the main function calls.
These auxiliary functions serve only as contextual hints.
You must inspect them only if the main function alone does not provide enough information.

Sensitive information may include, but is not limited to:

- internal system details
- configuration values
- file paths
- memory contents
- error messages
- metadata
- user-related data
- debugging or logging output

Consider how data is produced, processed, and returned or exposed by the function.
Pay attention to:

- what information the function outputs or returns
- whether that information could be sensitive
- whether access to that information is properly restricted
- whether error handling or logging could leak internal details
- If you believe sensitive information may be exposed:
- explain what information could be leaked
- explain under which conditions the leak could occur
- explain why the exposure would be problematic

If you believe the function is safe:

- explain why the information exposed is not sensitive or why access is properly restricted

Base your analysis strictly on the provided code.
Do not assume external protections unless they are explicitly visible."""


SYSTEM_PROMPT_BASELINE_CWE_284 = """You are a security expert analyzing a C++ function for potential vulnerabilities.
Analyze the following code and determine whether it may allow improper access control (CWE-284).

The prompt includes:
One main function, which must always be analyzed.
Additional C++ functions that the main function calls.
These auxiliary functions serve only as contextual hints.
You must inspect them only if the main function alone does not provide enough information.

Improper access control may include, but is not limited to:
- missing authorization checks
- incorrect or incomplete permission checks
- allowing operations without verifying the caller’s identity
- performing privileged actions without access validation
- insufficient restriction of sensitive operations
- incorrect enforcement of roles or privileges
- allowing unauthorized modification or access to resources

Consider how access to operations or resources is controlled within the function.
Pay attention to:

- what actions the function performs
- whether those actions require authorization
- whether the function verifies permissions or privileges before performing them
- whether access checks are missing, incorrect, or insufficient
- whether error handling allows unauthorized execution to proceed

If you believe improper access control may be present:

- explain which operation lacks proper access control
- explain under which conditions unauthorized access could occur
- explain why this would be a security problem

If you believe the function is safe:

- explain why access is properly restricted
- or why the operation does not require additional access control

Base your analysis strictly on the provided code.
Do not assume external protections unless they are explicitly visible."""


class Condition(BaseModel):
    id: str = Field(
        description="Short identifier for the inferred condition (e.g., 'auth_required', 'path_valid')."
    )
    description: str = Field(
        description="Short semantic description of the condition."
    )
    locally_satisfied: bool = Field(
        description="True if the function enforces this condition locally, False otherwise."
    )
    justification: Optional[str] = Field(
        default=None,
        description="If locally_satisfied is True, explain why. If False, leave empty."
    )

class Sink(BaseModel):
    sink_id: str = Field(
        description="Identifier for the sink (short snippet)."
    )
    sink_description: str = Field(
        description="Description of the privileged/authorization-relevant operation."
    )
    required_conditions: list[Condition] = Field(
        description="Conditions that must hold for safe execution of this sink."
    )

class LocalOutput(BaseModel):
    sinks: list[Sink] = Field(
        description="List of detected sinks with structured conditions."
    )


class plainOutModel(BaseModel):
    vulnerable: bool = Field(
        description="States if the function is vulnerable or not"
    )
    description: str = Field(
        description="Short explanation for the decision."
    )

#'gateway/openai:gpt-5.1'
local_agent = Agent('gateway/openai:gpt-5.1', output_type=  LocalOutput, #deps
                    system_prompt= SYSTEM_PROMPT_FLOW)