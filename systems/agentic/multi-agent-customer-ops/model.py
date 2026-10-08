#!/usr/bin/env python3
"""Multi-agent customer operations: an orchestrator delegating to specialist agents over A2A.

Inbound customer emails are triaged by an intake agent; an orchestrator plans
the resolution and delegates to a refund agent (payments), an email agent
(outbound replies) and an external carrier-tracking agent operated by a
logistics partner. A supervisor approves exceptions in an ops console.

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
DATASTORE = dict(
    isEncrypted=True, isEncryptedAtRest=True, hasAccessControl=True, authorizesSource=True,
    implementsPOLP=True, validatesInput=True, usesParameterizedInput=True,
    handlesResourceConsumption=True, usesEncryptionAlgorithm="AES",
)
SECURE_FLOW = dict(
    isEncrypted=True, authenticatesDestination=True, checksDestinationRevocation=True,
    implementsAuthenticationScheme=True, authorizesSource=True, providesIntegrity=True,
    validatesInput=True, sanitizesInput=True, authenticatesSource=True,
)
# Baseline for every agent: guarded, grounded, audited, stoppable.
AGENT = dict(
    isAgent=True, isLLM=True, hasPromptGuardrails=True, secretsExcludedFromPrompt=True,
    groundsResponses=True, filtersSensitiveOutput=True, hasTamperEvidentAuditLog=True,
    hasKillSwitch=True, separatesInstructionsFromData=True,
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


def agent(name, description, **attributes):
    """An LLM agent service with the AGENT baseline; keyword arguments override it."""
    element = Server(
        name,
        inBoundary=attributes.pop("inBoundary", agents_zone),
        port=8443,
        protocol="HTTPS",
        minTLSVersion=TLSVersion.TLSv12,
        maxClassification=attributes.pop("maxClassification", Classification.SENSITIVE),
        description=description,
        **(AGENT | attributes),
    )
    return element


tm = TM(
    "Multi-Agent Customer Operations",
    description=(
        "E-commerce customer operations automated by cooperating LLM agents. An "
        "intake agent triages inbound email; an orchestrator agent plans the "
        "resolution and delegates over the A2A protocol to a refund agent "
        "(payments API), an email agent (outbound replies) and a logistics "
        "partner's carrier-tracking agent. Refunds above a threshold, and any "
        "action the orchestrator flags, go to a human supervisor."
    ),
    isOrdered=True,
    mergeResponses=True,
)
tm.threatsFile = str(THREATS)
tm.assumptions = [
    "Inbound email is untrusted: anyone can email support@ and spoof display names.",
    "Internal agents authenticate to each other with SPIFFE identities over mTLS.",
    "Refunds up to $500 are auto-approved by policy; larger refunds need a supervisor.",
    "All agents share one foundation model provider under zero-data-retention terms.",
]

# --- Trust boundaries ---------------------------------------------------------
internet = Boundary("Internet")
partner = Boundary("Logistics Partner")
vendors = Boundary("SaaS Providers")
agents_zone = Boundary("Agent Mesh")
data_zone = Boundary("Customer Data")
corp = Boundary("Corporate")

# --- Actors and external entities --------------------------------------------
customer = Actor("Customer (or impersonator)", inBoundary=internet, maxClassification=Classification.SENSITIVE)
supervisor = Actor("Support Supervisor", inBoundary=corp, maxClassification=Classification.SENSITIVE)
mail = ExternalEntity("Email Provider (inbound/outbound)", inBoundary=vendors, maxClassification=Classification.SENSITIVE)
payments = ExternalEntity("Payments API", inBoundary=vendors, maxClassification=Classification.SECRET)
llm_api = ExternalEntity("Foundation Model API", inBoundary=vendors, maxClassification=Classification.SENSITIVE, isThirdPartyModel=True)

# --- Agents --------------------------------------------------------------------------
intake = agent(
    "Intake Agent",
    "Reads inbound emails and attachments, classifies intent, extracts order IDs, opens a case.",
    # GAP: email bodies are summarized into the case as free text the orchestrator later reads as instructions.
    separatesInstructionsFromData=False,
)
apply_controls(intake, WEB_SERVICE)

orchestrator = agent(
    "Orchestrator Agent",
    "Plans the resolution for a case and delegates tasks to specialist agents over A2A.",
    requestsHumanApproval=True,
    approvalShowsRawParameters=True,
)
# GAP: no global bound on delegation depth / re-plans per case (agents can ping-pong).
apply_controls(orchestrator, WEB_SERVICE, handlesResourceConsumption=False)

refund_agent = agent(
    "Refund Agent",
    "Validates refund eligibility against order data and issues refunds via the payments API.",
    maxClassification=Classification.SECRET,
)
apply_controls(refund_agent, WEB_SERVICE)

email_agent = agent(
    "Email Agent",
    "Drafts and sends replies to customers using case context.",
)
apply_controls(email_agent, WEB_SERVICE)

carrier_agent = Server(
    "Carrier Tracking Agent (partner)",
    inBoundary=partner,
    port=443,
    protocol="HTTPS",
    maxClassification=Classification.RESTRICTED,
    description="Partner-operated agent exposed over A2A; returns shipment status and delivery evidence.",
)
apply_controls(carrier_agent, WEB_SERVICE)
respond(carrier_agent, "AC06", "transferred: partner-operated service; covered by the partner security agreement")

# --- Systems and data ----------------------------------------------------------------
console = Server(
    "Ops Console",
    inBoundary=corp,
    port=443,
    protocol="HTTPS",
    minTLSVersion=TLSVersion.TLSv12,
    maxClassification=Classification.SENSITIVE,
    usesSessionTokens=True,
    description="Supervisor queue: approve / reject flagged actions with full tool-call parameters.",
)
apply_controls(console, WEB_SERVICE, encryptsCookies=True, encryptsSessionData=True)
respond(console, "CR01", "mitigated: SSO session cookies (Secure, HttpOnly) behind ZTNA")

crm = Server(
    "Order & CRM Service",
    inBoundary=data_zone,
    port=8443,
    protocol="HTTPS",
    minTLSVersion=TLSVersion.TLSv12,
    maxClassification=Classification.SENSITIVE,
    description="Orders, customers, prior refunds. Agents get read access scoped to the case's customer.",
)
apply_controls(crm, WEB_SERVICE)

case_memory = Datastore(
    "Case Memory",
    inBoundary=data_zone,
    isSQL=False,
    maxClassification=Classification.SENSITIVE,
    storesPII=True,
    isAgentMemory=True,
    description="Per-case shared scratchpad: messages, plans, tool results, with author and source on every entry.",
)
apply_controls(case_memory, DATASTORE, providesIntegrity=True)  # per-entry author + source provenance

# --- Data ---------------------------------------------------------------------------------
inbound = Data("Customer email + attachments", classification=Classification.SENSITIVE, isPII=True)
case = Data("Case summary + extracted entities", format="JSON", classification=Classification.SENSITIVE, isPII=True, isStored=True)
case_read = Data("Case context", format="JSON", classification=Classification.SENSITIVE, isPII=True)
task = Data("A2A task (intent, case_id, parameters)", format="JSON", classification=Classification.SENSITIVE)
tracking = Data("Tracking number + shipment status", format="JSON", classification=Classification.RESTRICTED)
evidence = Data("Delivery evidence (status, photo, geo-stamp)", format="JSON", classification=Classification.RESTRICTED)
order = Data("Order & refund history", format="JSON", classification=Classification.SENSITIVE, isPII=True)
refund_req = Data("Refund (order, amount, reason)", format="JSON", classification=Classification.SENSITIVE)
pay_key = Data("Payments restricted key", classification=Classification.SECRET, isCredentials=True, credentialsLife=Lifetime.MANUAL)
reply = Data("Outbound email", classification=Classification.SENSITIVE, isPII=True)
approval = Data("Approval request (raw parameters)", format="JSON", classification=Classification.SENSITIVE)
decision = Data("Supervisor decision", format="JSON", classification=Classification.RESTRICTED)
prompt = Data("Agent prompts", classification=Classification.SENSITIVE, isPII=True)

# --- Dataflows ------------------------------------------------------------------------------
send = Dataflow(customer, mail, "Email support@", protocol="SMTP/TLS", data=[inbound])
deliver = Dataflow(mail, intake, "Inbound webhook", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[inbound],
                   carriesUntrustedContent=True)
open_case = Dataflow(intake, case_memory, "Create case", data=[case])
plan = Dataflow(case_memory, orchestrator, "Load case", tlsVersion=TLSVersion.TLSv13, data=[case_read], carriesUntrustedContent=True)
lookup = Dataflow(orchestrator, crm, "Look up order", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[order],
                  isToolCall=True, enforcesToolPolicy=True)
delegate_track = Dataflow(orchestrator, carrier_agent, "A2A: get delivery status", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13,
                          data=[task, tracking], isAgentToAgent=True)
track_result = Dataflow(carrier_agent, orchestrator, "A2A: delivery evidence", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13,
                        data=[evidence], isAgentToAgent=True, carriesUntrustedContent=True, responseTo=delegate_track)
delegate_refund = Dataflow(orchestrator, refund_agent, "A2A: issue refund", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13,
                           data=[task], isAgentToAgent=True)
check_order = Dataflow(refund_agent, crm, "Verify eligibility", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[order],
                       isToolCall=True, enforcesToolPolicy=True)
refund = Dataflow(refund_agent, payments, "create_refund (<= $500 auto-approved)", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13,
                  data=[refund_req, pay_key], isToolCall=True, enforcesToolPolicy=True, isHighImpact=True,
                  requiresHumanApproval=False)
escalate = Dataflow(orchestrator, console, "Request approval", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[approval])
review = Dataflow(supervisor, console, "Approve / reject", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[decision])
delegate_reply = Dataflow(orchestrator, email_agent, "A2A: reply to customer", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13,
                          data=[task], isAgentToAgent=True)
send_reply = Dataflow(email_agent, mail, "send_email", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[reply],
                      isToolCall=True, enforcesToolPolicy=False)
record = Dataflow(orchestrator, case_memory, "Append plan + results", data=[case])
reason = Dataflow(orchestrator, llm_api, "Model calls (all agents)", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13,
                  data=[prompt], hasZeroDataRetention=True)

external_flows = (send, deliver, delegate_track, track_result, refund, send_reply, reason)
internal_flows = (open_case, plan, lookup, delegate_refund, check_order, escalate, review, delegate_reply, record)
for flow in external_flows + internal_flows:
    flow.maxClassification = min(flow.source.maxClassification, flow.sink.maxClassification)
    if flow is delegate_track:
        # GAP: partner agent is called with a static API key; agent card unsigned, responses unsigned.
        apply_controls(flow, SECURE_FLOW, authenticatesSource=False, providesIntegrity=False)
    elif flow is track_result:
        apply_controls(flow, SECURE_FLOW, authenticatesSource=False, providesIntegrity=False, sanitizesInput=False)
    elif flow in (deliver, plan):
        apply_controls(flow, SECURE_FLOW, sanitizesInput=False)
    else:
        apply_controls(flow, SECURE_FLOW)
for flow in internal_flows:
    flow.usesVPN = True  # SPIFFE mTLS inside the agent mesh
for flow in external_flows:
    respond(flow, "DE03", "mitigated: TLS 1.2+ to providers and partner; MTA-STS on the mail domain")
respond(refund, "AC22", "mitigated: restricted key with refunds scope only, stored in a secrets manager, rotated every 90 days")


if __name__ == "__main__":
    tm.process()
