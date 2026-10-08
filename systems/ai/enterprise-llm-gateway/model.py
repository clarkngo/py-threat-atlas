#!/usr/bin/env python3
"""Enterprise LLM gateway: one front door to third-party and self-hosted models, plus fine-tuning.

Employees and internal applications reach every model through a central
gateway that handles SSO, routing, PII redaction, quotas and logging. The
platform team also self-hosts open-weight models pulled from a public model
hub and fine-tunes them on curated prompt/response logs.

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
# The gateway applies these to every model behind it.
GUARDED_MODEL = dict(
    isLLM=True, hasPromptGuardrails=True, filtersSensitiveOutput=True, secretsExcludedFromPrompt=True,
    groundsResponses=True,
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
    "Enterprise LLM Gateway",
    description=(
        "Central AI platform for a 20,000-person company. A gateway authenticates "
        "employees (SSO) and internal apps (API keys), redacts PII, enforces "
        "quotas, routes to a primary third-party model provider, a fallback "
        "provider, or self-hosted open-weight models on a GPU cluster, and logs "
        "every prompt and response. Logged conversations are curated into "
        "datasets for fine-tuning the self-hosted models."
    ),
    isOrdered=True,
    mergeResponses=True,
)
tm.threatsFile = str(THREATS)
tm.assumptions = [
    "Employees paste confidential material (source code, contracts, customer data) into prompts.",
    "The primary provider is under an enterprise agreement with zero data retention.",
    "Open-weight models are downloaded from a public model hub by the platform team.",
    "Internal apps (support tools, code review bots) call the gateway with per-app API keys.",
]

# --- Trust boundaries ---------------------------------------------------------
corp = Boundary("Corporate Network")
providers = Boundary("Model Providers")
hub_boundary = Boundary("Public Model Hub")
platform = Boundary("AI Platform")
gpu = Boundary("GPU Cluster")
gpu.inBoundary = platform

# --- Actors and external entities --------------------------------------------
employee = Actor("Employee", inBoundary=corp, maxClassification=Classification.SENSITIVE)
ml_engineer = Actor("ML Platform Engineer", inBoundary=corp, isAdmin=True, maxClassification=Classification.SENSITIVE)
internal_app = ExternalEntity(
    "Internal LLM Apps",
    inBoundary=corp,
    maxClassification=Classification.SENSITIVE,
    description="Support copilots, code-review bots, document summarizers.",
)
primary = ExternalEntity(
    "Primary Model Provider", inBoundary=providers, maxClassification=Classification.SENSITIVE, isThirdPartyModel=True
)
fallback = ExternalEntity(
    "Fallback Model Provider",
    inBoundary=providers,
    maxClassification=Classification.RESTRICTED,
    isThirdPartyModel=True,
    description="Used automatically when the primary is rate-limited or down; standard API terms.",
)
model_hub = ExternalEntity(
    "Public Model Hub",
    inBoundary=hub_boundary,
    maxClassification=Classification.PUBLIC,
    description="Open-weight checkpoints, tokenizers and custom modeling code.",
)

# --- Platform --------------------------------------------------------------------------
chat_ui = Process(
    "Chat UI / IDE Plugin",
    inBoundary=corp,
    maxClassification=Classification.SENSITIVE,
    codeType="Managed",
    allowsClientSideScripting=True,
    description="Web chat and editor extensions; renders Markdown and code blocks.",
)
apply_controls(chat_ui, JOB)
for threat_id in ("AA01", "AA02", "AC01", "AC12", "AC13"):
    respond(chat_ui, threat_id, "accepted: client is untrusted; authentication and quotas are enforced by the gateway")

gateway = Server(
    "LLM Gateway",
    inBoundary=platform,
    port=443,
    protocol="HTTPS",
    minTLSVersion=TLSVersion.TLSv12,
    maxClassification=Classification.SENSITIVE,
    description="SSO / API-key auth, PII and secret redaction, per-user and per-app quotas, routing, logging.",
)
apply_controls(gateway, WEB_SERVICE)

serving = Server(
    "Self-Hosted Model Serving (vLLM)",
    inBoundary=gpu,
    port=8000,
    protocol="HTTPS",
    minTLSVersion=TLSVersion.TLSv12,
    maxClassification=Classification.SENSITIVE,
    isInferenceEndpoint=True,
    monitorsQueryPatterns=True,
    description="Open-weight and fine-tuned models on Kubernetes GPU nodes; loads weights from the registry at start.",
    **GUARDED_MODEL,
)
# GAP: loads checkpoints with trust_remote_code=True (custom modeling code from the hub runs at load time).
apply_controls(serving, WEB_SERVICE)

registry = Datastore(
    "Model Registry",
    inBoundary=platform,
    isSQL=False,
    maxClassification=Classification.SENSITIVE,
    isModelArtifact=True,
    description="Mirrored hub checkpoints (some .bin/pickle), fine-tuned adapters, model cards.",
)
# GAP: mirrored checkpoints are not scanned, hashed or signed; pickle formats accepted.
apply_controls(registry, DATASTORE, usesCodeSigning=False)

prompt_logs = Datastore(
    "Prompt & Response Logs",
    inBoundary=platform,
    isSQL=False,
    storesLogData=True,
    storesPII=True,
    storesSensitiveData=True,
    maxClassification=Classification.SENSITIVE,
    description="Full prompts and completions for 1 year: abuse review, evals, fine-tuning source.",
)
# GAP: the whole ML team can read all logs (other teams' code, HR and legal questions).
apply_controls(prompt_logs, DATASTORE, implementsPOLP=False)

curated = Datastore(
    "Fine-Tuning Datasets",
    inBoundary=platform,
    isSQL=False,
    storesPII=True,
    maxClassification=Classification.SENSITIVE,
    isTrainingData=True,
    description="Highly-rated conversations selected for supervised fine-tuning.",
)
# GAP: selection is driven by employee thumbs-up ratings; no provenance or review of examples.
apply_controls(curated, DATASTORE, providesIntegrity=False)

trainer = Process(
    "Fine-Tuning Jobs",
    inBoundary=gpu,
    maxClassification=Classification.SENSITIVE,
    codeType="Managed",
    isCloudWorkload=True,
    hasAuditLogging=True,
    description="LoRA fine-tuning of self-hosted models; writes adapters to the registry.",
)
apply_controls(trainer, JOB)

# --- Data ----------------------------------------------------------------------------------
sso = Data("SSO session", classification=Classification.RESTRICTED, isCredentials=True, credentialsLife=Lifetime.SHORT)
app_key = Data("Per-app gateway API key", classification=Classification.SENSITIVE, isCredentials=True, credentialsLife=Lifetime.LONG)
prompt = Data("Prompt (may contain code, contracts, customer data)", classification=Classification.SENSITIVE, isPII=True)
redacted = Data("Redacted prompt", classification=Classification.SENSITIVE)
completion = Data("Completion", classification=Classification.SENSITIVE)
log_row = Data("Prompt/response log record", classification=Classification.SENSITIVE, isPII=True, isStored=True)
checkpoint = Data("Checkpoint + tokenizer + modeling code", classification=Classification.PUBLIC)
mirrored = Data("Mirrored checkpoint", classification=Classification.PUBLIC, isStored=True)
weights = Data("Model weights / adapters", classification=Classification.SENSITIVE)
examples = Data("Selected conversations", classification=Classification.SENSITIVE, isPII=True, isStored=True)
train_read = Data("Training examples", classification=Classification.SENSITIVE, isPII=True)
adapter = Data("Fine-tuned adapter", classification=Classification.SENSITIVE, isStored=True)

# --- Dataflows ----------------------------------------------------------------------------
ask = Dataflow(employee, chat_ui, "Write prompt", data=[prompt])
send = Dataflow(chat_ui, gateway, "Chat request (SSO)", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[sso, prompt])
app_call = Dataflow(internal_app, gateway, "Completion request (API key)", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[app_key, prompt])
to_primary = Dataflow(gateway, primary, "Route: primary provider", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13,
                      data=[redacted], hasZeroDataRetention=True)
# GAP: automatic failover sends the same prompts to a provider without zero-data-retention terms.
to_fallback = Dataflow(gateway, fallback, "Route: fallback provider (on 429/5xx)", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13,
                       data=[redacted], hasZeroDataRetention=False)
to_serving = Dataflow(gateway, serving, "Route: self-hosted model", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[redacted])
answer = Dataflow(gateway, chat_ui, "Completion", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[completion])
log = Dataflow(gateway, prompt_logs, "Log prompt + completion", data=[log_row])
pull = Dataflow(model_hub, registry, "Mirror open-weight checkpoint", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[checkpoint, mirrored])
load = Dataflow(registry, serving, "Load weights at start", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[weights])
select = Dataflow(prompt_logs, curated, "Select highly-rated conversations", data=[examples])
train = Dataflow(curated, trainer, "Read training examples", tlsVersion=TLSVersion.TLSv13, data=[train_read])
publish = Dataflow(trainer, registry, "Register adapter", data=[adapter])
promote = Dataflow(ml_engineer, registry, "Approve model for serving", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13)

external_flows = (send, app_call, to_primary, to_fallback, pull)
internal_flows = (to_serving, answer, log, load, select, train, publish, promote)
for flow in (ask,) + external_flows + internal_flows:
    flow.maxClassification = min(flow.source.maxClassification, flow.sink.maxClassification)
    apply_controls(flow, SECURE_FLOW)
for flow in internal_flows:
    flow.usesVPN = True
for flow in external_flows:
    respond(flow, "DE03", "mitigated: TLS 1.2+ to providers and hub; corporate clients over ZTNA")
respond(ask, "DE03", "accepted: input stays on the employee's device")


if __name__ == "__main__":
    tm.process()
