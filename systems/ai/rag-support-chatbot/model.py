#!/usr/bin/env python3
"""LLM-powered customer support chatbot with Retrieval-Augmented Generation (RAG).

The bot answers customer questions from a vector index built from the public
help center, internal support runbooks and resolved tickets, calls a
third-party foundation model, and can escalate by creating a ticket.

Usage:
    python model.py --dfd | dot -Tsvg -o dfd.svg
    python model.py --json findings.json
"""

from pathlib import Path

from pytm import (
    TM,
    Actor,
    Boundary,
    Classification,
    Data,
    Dataflow,
    Datastore,
    ExternalEntity,
    Finding,
    Lifetime,
    Process,
    Server,
    TLSVersion,
)

THREATS = Path(__file__).resolve().parents[3] / "threatlib" / "atlas_threats.json"

WEB_SERVICE = dict(
    isEncrypted=True, isHardened=True, authenticatesSource=True, authorizesSource=True,
    hasAccessControl=True, implementsAuthenticationScheme=True, validatesInput=True,
    sanitizesInput=True, encodesOutput=True, validatesHeaders=True, validatesContentType=True,
    invokesScriptFilters=True, implementsServerSideValidation=True, implementsStrictHTTPValidation=True,
    encodesHeaders=True, usesStrongSessionIdentifiers=True, providesIntegrity=True, checksInputBounds=True,
    implementsPOLP=True, handlesResourceConsumption=True, isResilient=True, usesCodeSigning=True,
    authenticatesDestination=True, checksDestinationRevocation=True, implementsNonce=True,
    usesEncryptionAlgorithm="AES",
)
JOB = dict(
    validatesInput=True, sanitizesInput=True, checksInputBounds=True, usesSecureFunctions=True,
    usesParameterizedInput=True, implementsAuthenticationScheme=True, authenticatesSource=True,
    authorizesSource=True, hasAccessControl=True, implementsPOLP=True, handlesResourceConsumption=True,
    isResilient=True, usesCodeSigning=True, encodesOutput=True, implementsCSRFToken=True,
    verifySessionIdentifiers=True, definesConnectionTimeout=True, disablesiFrames=True, implementsNonce=True,
    encryptsSessionData=True, usesMFA=True,
)
DATASTORE = dict(
    isEncrypted=True, isEncryptedAtRest=True, hasAccessControl=True, authorizesSource=True,
    implementsPOLP=True, validatesInput=True, usesParameterizedInput=True,
    handlesResourceConsumption=True, usesEncryptionAlgorithm="AES",
)
SECURE_FLOW = dict(
    isEncrypted=True, authenticatesDestination=True, checksDestinationRevocation=True,
    implementsAuthenticationScheme=True, authorizesSource=True, providesIntegrity=True,
    validatesInput=True, sanitizesInput=True,
)


def apply_controls(element, *profiles, **flags):
    """Set pytm control flags on an element from profiles, then per-element overrides."""
    merged = {}
    for profile in profiles:
        merged.update(profile)
    merged.update(flags)
    for name, value in merged.items():
        setattr(element.controls, name, value)
    return element


def respond(element, threat_id, response):
    """Record how a finding is handled (mitigated / transferred / accepted)."""
    finding = Finding(element, threat_id=threat_id, response=response)
    if element.overrides:  # pytm attributes are set-once; extend the stored list
        element.overrides.append(finding)
    else:
        element.overrides = [finding]


tm = TM(
    "RAG Customer Support Chatbot",
    description=(
        "Customer-facing support assistant embedded on the website and in the app. "
        "Questions are screened by a guardrail service, enriched with passages "
        "retrieved from a vector index (help center, internal runbooks, resolved "
        "tickets), and answered by a third-party foundation model. The bot can "
        "escalate to a human by creating a support ticket."
    ),
    isOrdered=True,
    mergeResponses=True,
)
tm.threatsFile = str(THREATS)
tm.assumptions = [
    "The foundation model is consumed through an enterprise API with zero-data-retention terms and a DPA.",
    "Logged-in customers are identified by a short-lived JWT minted by the main web app; anonymous chat is allowed.",
    "The bot's only side-effecting capability is creating a support ticket.",
    "Model output is never executed; it is rendered as Markdown in the chat widget.",
]

# --- Trust boundaries ---------------------------------------------------------
internet = Boundary("Internet")
model_vendor = Boundary("Model Provider")
saas = Boundary("Support SaaS")
ai_vpc = Boundary("AI Platform VPC")
data = Boundary("AI Data Stores")
data.inBoundary = ai_vpc

# --- Actors and external systems -----------------------------------------------
customer = Actor("Customer", inBoundary=internet, maxClassification=Classification.SENSITIVE)
kb_author = Actor("Support Content Author", inBoundary=saas, maxClassification=Classification.SENSITIVE)

widget = Process(
    "Chat Widget (browser)",
    inBoundary=internet,
    maxClassification=Classification.SENSITIVE,
    allowsClientSideScripting=True,
    codeType="Managed",
    description="Renders model responses as Markdown, including links and images.",
)
apply_controls(widget, JOB)
for threat_id in ("AA01", "AA02", "AC01", "AC12", "AC13"):
    respond(widget, threat_id, "accepted: the browser is untrusted; identity and authorization are enforced by the Chat API")

llm_api = ExternalEntity(
    "Foundation Model API",
    inBoundary=model_vendor,
    maxClassification=Classification.SENSITIVE,
    isThirdPartyModel=True,
    description="Hosted LLM and embeddings endpoints (enterprise tier, regional).",
)
helpdesk = ExternalEntity(
    "Helpdesk (tickets + help center)",
    inBoundary=saas,
    maxClassification=Classification.SENSITIVE,
    description="Support SaaS holding public articles, internal macros and customer tickets.",
)

# --- AI platform ---------------------------------------------------------------------
chat_api = Server(
    "Chat API",
    inBoundary=ai_vpc,
    port=443,
    protocol="HTTPS",
    minTLSVersion=TLSVersion.TLSv12,
    maxClassification=Classification.SENSITIVE,
    usesSessionTokens=True,
    description="Session management, customer identity, per-session rate and token budgets.",
)
apply_controls(chat_api, WEB_SERVICE, encryptsCookies=True, encryptsSessionData=True)
respond(chat_api, "CR01", "mitigated: chat session token in a Secure, HttpOnly cookie over TLS 1.3")

guardrails = Server(
    "Guardrail Service",
    inBoundary=ai_vpc,
    port=8443,
    protocol="HTTPS",
    maxClassification=Classification.SENSITIVE,
    description="Prompt-injection / jailbreak classifier and topic filter on user input.",
)
apply_controls(guardrails, WEB_SERVICE)

orchestrator = Server(
    "RAG Orchestrator",
    inBoundary=ai_vpc,
    port=8443,
    protocol="HTTPS",
    maxClassification=Classification.SENSITIVE,
    isLLM=True,
    hasPromptGuardrails=True,  # input screened by the guardrail service
    secretsExcludedFromPrompt=True,
    groundsResponses=True,  # answers cite retrieved passages; refuses below a similarity threshold
    # GAP: no output-side DLP; PII present in retrieved tickets can be echoed to the user.
    filtersSensitiveOutput=False,
    description="Builds the prompt (system + history + retrieved passages), calls the model, post-processes output.",
)
apply_controls(orchestrator, WEB_SERVICE)

ingestion = Process(
    "Ingestion & Embedding Job",
    inBoundary=ai_vpc,
    maxClassification=Classification.SENSITIVE,
    codeType="Managed",
    description="Nightly: pulls articles, macros and resolved tickets; chunks, embeds and upserts them.",
)
apply_controls(ingestion, JOB)

vector_db = Datastore(
    "Vector Index",
    inBoundary=data,
    isSQL=False,
    maxClassification=Classification.SENSITIVE,
    storesPII=True,
    storesSensitiveData=True,
    isVectorStore=True,
    # GAP: one index for public articles, internal-only macros and resolved tickets; no audience filter at query time.
    enforcesDocumentACL=False,
    description="Chunks + embeddings + metadata (source, url, updated_at).",
)
apply_controls(vector_db, DATASTORE)

transcripts = Datastore(
    "Conversation Store",
    inBoundary=data,
    isSQL=True,
    maxClassification=Classification.SENSITIVE,
    storesPII=True,
    storesLogData=True,
    description="Transcripts for quality review and evaluation; 90-day retention.",
)
apply_controls(transcripts, DATASTORE)

# --- Data ------------------------------------------------------------------------------
question = Data("Customer question", classification=Classification.SENSITIVE, isPII=True)
chat_token = Data("Chat session token", classification=Classification.SENSITIVE, isCredentials=True, credentialsLife=Lifetime.SHORT)
verdict = Data("Guardrail verdict", format="JSON", classification=Classification.RESTRICTED)
prompt = Data("Prompt (system + history + passages)", classification=Classification.SENSITIVE, isPII=True)
completion = Data("Model completion (Markdown)", classification=Classification.SENSITIVE, isPII=True)
passages = Data("Retrieved passages", classification=Classification.SENSITIVE, isPII=True)
source_docs = Data("Articles, macros, resolved tickets", classification=Classification.SENSITIVE, isPII=True)
chunk_text = Data("Chunk text", classification=Classification.SENSITIVE, isPII=True)
chunks = Data("Chunks + embeddings", classification=Classification.SENSITIVE, isPII=True, isStored=True)
transcript = Data("Conversation transcript", classification=Classification.SENSITIVE, isPII=True, isStored=True)
ticket = Data("Escalation ticket (summary + transcript link)", format="JSON", classification=Classification.SENSITIVE, isPII=True)
helpdesk_key = Data("Helpdesk API token", classification=Classification.SENSITIVE, isCredentials=True, credentialsLife=Lifetime.MANUAL)

# --- Dataflows: answering ------------------------------------------------------------------
ask = Dataflow(customer, widget, "Type question", data=[question])
send = Dataflow(
    widget, chat_api, "POST /messages", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[chat_token, question]
)
screen = Dataflow(chat_api, guardrails, "Screen input", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[question])
screen_result = Dataflow(
    guardrails, chat_api, "Verdict", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[verdict], responseTo=screen
)
to_orch = Dataflow(chat_api, orchestrator, "Answer request", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[question])
retrieve = Dataflow(
    vector_db, orchestrator, "Top-k passages", data=[passages], carriesUntrustedContent=True
)
call_llm = Dataflow(
    orchestrator, llm_api, "Chat completion request", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13,
    data=[prompt], hasZeroDataRetention=True,
)
llm_resp = Dataflow(
    llm_api, orchestrator, "Completion", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[completion], responseTo=call_llm
)
answer = Dataflow(orchestrator, chat_api, "Answer + citations", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[completion])
render = Dataflow(chat_api, widget, "Stream answer", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[completion])
log = Dataflow(chat_api, transcripts, "Store transcript", data=[transcript])
escalate = Dataflow(
    orchestrator, helpdesk, "create_ticket tool call", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13,
    data=[ticket, helpdesk_key], isToolCall=True, enforcesToolPolicy=True,
)

# --- Dataflows: ingestion -----------------------------------------------------------------
author = Dataflow(kb_author, helpdesk, "Publish article / macro", protocol="HTTPS", data=[source_docs])
pull = Dataflow(
    helpdesk, ingestion, "Export articles, macros, resolved tickets", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13,
    data=[source_docs, helpdesk_key], carriesUntrustedContent=True,
)
embed = Dataflow(
    ingestion, llm_api, "Embed chunks", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[chunk_text],
    hasZeroDataRetention=True,
)
upsert = Dataflow(ingestion, vector_db, "Upsert chunks", data=[chunks])

public_flows = (send, render, call_llm, llm_resp, escalate, author, pull, embed)
private_flows = (screen, screen_result, to_orch, retrieve, answer, log, upsert)
local_flows = (ask,)

for flow in public_flows + private_flows + local_flows:
    flow.maxClassification = min(flow.source.maxClassification, flow.sink.maxClassification)
    if flow is retrieve:
        # GAP: retrieved text is concatenated into the prompt with no provenance tagging or sanitization.
        apply_controls(flow, SECURE_FLOW, sanitizesInput=False)
    elif flow is answer:
        # GAP: Markdown (links, remote images) from the model is passed through unvalidated.
        apply_controls(flow, SECURE_FLOW, validatesInput=False)
    else:
        apply_controls(flow, SECURE_FLOW)
for flow in private_flows:
    flow.usesVPN = True
for flow in public_flows:
    respond(flow, "DE03", "mitigated: TLS 1.2+ to SaaS and model endpoints; private connectivity where the provider offers it")
respond(ask, "DE03", "accepted: keystrokes stay inside the user's browser")
respond(escalate, "AC22", "mitigated: helpdesk token scoped to ticket creation only, stored in a secrets manager, rotated quarterly")
respond(pull, "AC22", "mitigated: read-only export token, rotated quarterly")


if __name__ == "__main__":
    tm.process()
