#!/usr/bin/env python3
"""Autonomous SRE incident-response agent with MCP tool servers.

An LLM agent is paged with production alerts, investigates through
observability tools, proposes and executes remediations (Kubernetes, AWS,
GitHub) with human approval in Slack, and learns from past incidents through a
persistent memory.

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
    "Autonomous SRE Incident Agent",
    description=(
        "An LLM-based agent that is triggered by production alerts, investigates "
        "with logs, metrics and traces, and remediates incidents (rollback, scale, "
        "restart, cloud configuration, hot-fix PRs) through MCP tool servers. "
        "High-impact Kubernetes actions require approval in Slack. The agent keeps "
        "a long-term memory of past incidents and the fixes that worked."
    ),
    isOrdered=True,
    mergeResponses=True,
)
tm.threatsFile = str(THREATS)
tm.assumptions = [
    "The agent is reachable only from the corporate Slack workspace and the alerting webhook.",
    "Tool servers speak MCP over streamable HTTP with OAuth 2.1 bearer tokens.",
    "Production logs contain attacker-controllable strings (HTTP paths, headers, user input).",
    "The foundation model is accessed via an enterprise API with zero data retention.",
]

# --- Trust boundaries ---------------------------------------------------------
internet = Boundary("Internet")
saas = Boundary("SaaS (Slack, PagerDuty, GitHub)")
vendor = Boundary("Model Provider")
agent_zone = Boundary("Agent Platform")
tools_zone = Boundary("MCP Tool Servers")
tools_zone.inBoundary = agent_zone
prod = Boundary("Production")

# --- Actors and external entities ---------------------------------------------
attacker = Actor("Internet Client", inBoundary=internet, maxClassification=Classification.PUBLIC,
                 description="Any user of the public app; can write arbitrary strings into logs.")
engineer = Actor("On-call Engineer", inBoundary=saas, maxClassification=Classification.SECRET)
slack = ExternalEntity("Slack (chat + approvals)", inBoundary=saas, maxClassification=Classification.SENSITIVE)
pager = ExternalEntity("PagerDuty", inBoundary=saas, maxClassification=Classification.RESTRICTED)
github = ExternalEntity("GitHub", inBoundary=saas, maxClassification=Classification.SENSITIVE)
llm_api = ExternalEntity(
    "Foundation Model API", inBoundary=vendor, maxClassification=Classification.SENSITIVE, isThirdPartyModel=True
)

# --- Agent platform ------------------------------------------------------------------
agent = Server(
    "Agent Runtime (planner + executor)",
    inBoundary=agent_zone,
    port=8443,
    protocol="HTTPS",
    minTLSVersion=TLSVersion.TLSv12,
    maxClassification=Classification.SECRET,
    isAgent=True,
    isLLM=True,
    hasPromptGuardrails=True,
    secretsExcludedFromPrompt=True,
    groundsResponses=True,
    hasTamperEvidentAuditLog=True,
    hasKillSwitch=True,
    requestsHumanApproval=True,
    # GAP: approval cards show the agent's own summary, not the raw tool-call parameters.
    approvalShowsRawParameters=False,
    # GAP: tool results (logs, events) are pasted into the same context as instructions.
    separatesInstructionsFromData=False,
    # GAP: agent output is posted to Slack without secret redaction.
    filtersSensitiveOutput=False,
    description="ReAct-style loop: plan, call tools, observe, propose remediation, execute after approval.",
)
# GAP: one standing service identity for all incidents (cluster-wide RBAC + broad AWS role).
apply_controls(agent, WEB_SERVICE, implementsPOLP=False)

sandbox = Process(
    "Script Runner",
    inBoundary=agent_zone,
    maxClassification=Classification.SECRET,
    codeType="Managed",
    executesGeneratedCode=True,
    # GAP: runs agent-written bash/python in a long-lived pod that has the agent's credentials and open egress.
    isSandboxed=False,
    description="Executes diagnostic scripts the agent writes (log parsing, curl health checks).",
)
apply_controls(sandbox, JOB, implementsPOLP=False)

memory = Datastore(
    "Incident Memory",
    inBoundary=agent_zone,
    isSQL=False,
    maxClassification=Classification.SENSITIVE,
    isAgentMemory=True,
    description="Past incidents, root causes and 'what worked' notes, written by the agent after each incident.",
)
# GAP: the agent writes memories autonomously; no review, provenance or expiry.
apply_controls(memory, DATASTORE, providesIntegrity=False)

traces = Datastore(
    "Agent Trace Store",
    inBoundary=agent_zone,
    isSQL=False,
    storesLogData=True,
    maxClassification=Classification.SECRET,
    description="Append-only trace of every task: trigger, context sources, plan, tool calls, approvals.",
)
apply_controls(traces, DATASTORE)

obs_mcp = Server(
    "Observability MCP Server",
    inBoundary=tools_zone,
    port=8443,
    protocol="HTTPS",
    minTLSVersion=TLSVersion.TLSv12,
    maxClassification=Classification.SECRET,
    isToolServer=True,
    # GAP: community server installed from a public registry; auto-updates, tool descriptions unreviewed.
    isPinnedAndVerified=False,
    description="query_logs, query_metrics, get_traces (read-only).",
)
apply_controls(obs_mcp, WEB_SERVICE)

k8s_mcp = Server(
    "Kubernetes MCP Server",
    inBoundary=tools_zone,
    port=8443,
    protocol="HTTPS",
    minTLSVersion=TLSVersion.TLSv12,
    maxClassification=Classification.SECRET,
    isToolServer=True,
    isPinnedAndVerified=True,
    description="In-house: get/describe/logs, rollout undo, scale, restart. No exec, no delete.",
)
apply_controls(k8s_mcp, WEB_SERVICE)

cloud_mcp = Server(
    "AWS MCP Server",
    inBoundary=tools_zone,
    port=8443,
    protocol="HTTPS",
    minTLSVersion=TLSVersion.TLSv12,
    maxClassification=Classification.SECRET,
    isToolServer=True,
    isPinnedAndVerified=True,
    description="Generic 'aws_cli' tool that passes arbitrary AWS CLI commands through.",
)
apply_controls(cloud_mcp, WEB_SERVICE)

gh_mcp = Server(
    "GitHub MCP Server",
    inBoundary=tools_zone,
    port=8443,
    protocol="HTTPS",
    minTLSVersion=TLSVersion.TLSv12,
    maxClassification=Classification.SECRET,
    isToolServer=True,
    isPinnedAndVerified=True,
    description="Open hot-fix PRs on a bot branch; cannot merge (branch protection).",
)
apply_controls(gh_mcp, WEB_SERVICE)

# --- Production ----------------------------------------------------------------------
app = Server(
    "Production Services",
    inBoundary=prod,
    port=443,
    protocol="HTTPS",
    minTLSVersion=TLSVersion.TLSv12,
    maxClassification=Classification.SENSITIVE,
    description="Customer-facing workloads that emit logs.",
)
apply_controls(app, WEB_SERVICE)
logs = Datastore(
    "Log & Metrics Platform",
    inBoundary=prod,
    isSQL=False,
    storesLogData=True,
    maxClassification=Classification.SENSITIVE,
    description="Centralized logs, metrics and traces.",
)
apply_controls(logs, DATASTORE)
k8s = Server(
    "EKS API (prod)",
    inBoundary=prod,
    port=443,
    protocol="HTTPS",
    minTLSVersion=TLSVersion.TLSv12,
    maxClassification=Classification.SECRET,
)
apply_controls(k8s, WEB_SERVICE)
aws = Server(
    "AWS Control Plane (prod)",
    inBoundary=prod,
    port=443,
    protocol="HTTPS",
    minTLSVersion=TLSVersion.TLSv12,
    maxClassification=Classification.SECRET,
)
apply_controls(aws, WEB_SERVICE)

# --- Data ----------------------------------------------------------------------------------
user_input = Data("HTTP request with attacker-chosen headers/paths", classification=Classification.PUBLIC)
log_lines = Data("Log lines, events, traces", classification=Classification.SENSITIVE)
alert = Data("Alert payload", format="JSON", classification=Classification.RESTRICTED)
chat = Data("Chat instructions / approval", classification=Classification.SENSITIVE)
proposal = Data("Proposed remediation (agent summary)", classification=Classification.SENSITIVE)
context = Data("Prompt: goal + memory + tool results", classification=Classification.SENSITIVE)
plan = Data("Model output: plan + tool calls", format="JSON", classification=Classification.SENSITIVE)
tool_call = Data("Tool call (name + arguments)", format="JSON", classification=Classification.SENSITIVE)
mcp_token = Data("MCP OAuth access token", classification=Classification.SECRET, isCredentials=True, credentialsLife=Lifetime.SHORT)
k8s_creds = Data("Agent ServiceAccount token", classification=Classification.SECRET, isCredentials=True, credentialsLife=Lifetime.LONG)
aws_creds = Data("Agent IAM role session", classification=Classification.SECRET, isCredentials=True, credentialsLife=Lifetime.SHORT)
script = Data("Generated diagnostic script", classification=Classification.SENSITIVE)
lesson = Data("Incident lesson / runbook note", classification=Classification.SENSITIVE, isStored=True)
recall = Data("Recalled incident notes", classification=Classification.SENSITIVE)
trace = Data("Task trace", format="JSON", classification=Classification.SENSITIVE, isStored=True)
patch = Data("Hot-fix pull request", classification=Classification.SENSITIVE)

# --- Dataflows: trigger and investigation ----------------------------------------------------
traffic = Dataflow(attacker, app, "Public request", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[user_input])
emit = Dataflow(app, logs, "Emit logs / metrics", data=[log_lines])
page = Dataflow(pager, agent, "Alert webhook", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[alert])
ask = Dataflow(engineer, slack, "Mention @sre-agent", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[chat])
relay = Dataflow(slack, agent, "Slack event", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[chat])
recall_mem = Dataflow(
    memory, agent, "Recall similar incidents", tlsVersion=TLSVersion.TLSv13, data=[recall], carriesUntrustedContent=True
)
think = Dataflow(agent, llm_api, "Reasoning step", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[context], hasZeroDataRetention=True)
think_resp = Dataflow(llm_api, agent, "Plan + tool calls", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[plan], responseTo=think)
q_logs = Dataflow(agent, obs_mcp, "query_logs / query_metrics", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13,
                  data=[tool_call, mcp_token], isToolCall=True, enforcesToolPolicy=True)
read_logs = Dataflow(logs, obs_mcp, "Fetch log lines", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[log_lines])
obs_result = Dataflow(obs_mcp, agent, "Tool result: log lines", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13,
                      data=[log_lines], carriesUntrustedContent=True)
run_script = Dataflow(agent, sandbox, "Run diagnostic script", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13,
                      data=[script], isToolCall=True, enforcesToolPolicy=False)

# --- Dataflows: remediation ----------------------------------------------------------------------
propose = Dataflow(agent, slack, "Approval request + findings", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[proposal])
k8s_call = Dataflow(agent, k8s_mcp, "rollout_undo / scale / restart", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13,
                    data=[tool_call, mcp_token], isToolCall=True, enforcesToolPolicy=True, isHighImpact=True,
                    requiresHumanApproval=True)
k8s_exec = Dataflow(k8s_mcp, k8s, "Kubernetes API call", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[k8s_creds])
aws_call = Dataflow(agent, cloud_mcp, "aws_cli (arbitrary command)", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13,
                    data=[tool_call, mcp_token], isToolCall=True, enforcesToolPolicy=False, isHighImpact=True,
                    requiresHumanApproval=False)
aws_exec = Dataflow(cloud_mcp, aws, "AWS API call", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[aws_creds])
gh_call = Dataflow(agent, gh_mcp, "open_pull_request", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13,
                   data=[tool_call, mcp_token], isToolCall=True, enforcesToolPolicy=True)
gh_exec = Dataflow(gh_mcp, github, "Create branch + PR", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[patch])
sandbox_k8s = Dataflow(sandbox, k8s, "kubectl from script", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[k8s_creds])
write_mem = Dataflow(agent, memory, "Write incident lesson", data=[lesson])
write_trace = Dataflow(agent, traces, "Append task trace", data=[trace])

saas_flows = (traffic, page, ask, relay, think, think_resp, propose, gh_exec)
internal_flows = (
    emit, recall_mem, q_logs, read_logs, obs_result, run_script, k8s_call, k8s_exec, aws_call, aws_exec, gh_call,
    sandbox_k8s, write_mem, write_trace,
)
for flow in saas_flows + internal_flows:
    flow.maxClassification = min(flow.source.maxClassification, flow.sink.maxClassification)
    if flow in (obs_result, recall_mem):
        # GAP: tool results and memories enter the context verbatim; no provenance tagging.
        apply_controls(flow, SECURE_FLOW, sanitizesInput=False)
    else:
        apply_controls(flow, SECURE_FLOW)
for flow in internal_flows:
    flow.usesVPN = True
for flow in saas_flows:
    respond(flow, "DE03", "mitigated: TLS 1.2+ to SaaS and model endpoints; Slack and PagerDuty requests are signature-verified")
respond(k8s_exec, "AC22", "accepted: tracked as AGT03 - replace with per-task, TokenRequest-issued ServiceAccount tokens")
respond(sandbox_k8s, "AC22", "accepted: tracked as AGT04 - the script runner should hold no credentials at all")


if __name__ == "__main__":
    tm.process()
