#!/usr/bin/env python3
"""Multi-tenant SaaS platform on Amazon EKS with a GitOps delivery pipeline.

Pooled multi-tenancy (shared compute and database, tenant-scoped rows),
asynchronous workers on SQS, outbound customer webhooks, and a GitHub Actions
-> ECR -> Argo CD pipeline that deploys into the cluster.

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
WORKER = dict(
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
    "Multi-Tenant SaaS on Amazon EKS",
    description=(
        "B2B analytics SaaS using pooled multi-tenancy on EKS: shared API and worker "
        "deployments, a shared Aurora PostgreSQL cluster with row-level security, a "
        "Redis cache, SQS for async jobs, and customer-configured outbound webhooks. "
        "Delivery is GitOps: GitHub Actions builds images to ECR and Argo CD syncs "
        "manifests into the cluster."
    ),
    isOrdered=True,
    mergeResponses=True,
)
tm.threatsFile = str(THREATS)
tm.assumptions = [
    "Tenant identity comes only from the verified JWT 'tenant_id' claim, set by the IdP.",
    "Pods use IRSA / EKS Pod Identity; node instance roles have no data-plane permissions.",
    "The EKS API endpoint is private; human access is via SSO-mapped, time-bound roles.",
    "GitHub Actions authenticates to AWS via OIDC federation; there are no static AWS keys in CI.",
]

# --- Trust boundaries ---------------------------------------------------------
internet = Boundary("Internet")
tenant_net = Boundary("Customer Endpoints")
github = Boundary("GitHub (SaaS)")
aws = Boundary("AWS Account (prod)")
cluster = Boundary("EKS Cluster")
cluster.inBoundary = aws
data = Boundary("Managed Data Services")
data.inBoundary = aws

# --- Actors and external entities --------------------------------------------
tenant_user = Actor("Tenant User", inBoundary=internet, maxClassification=Classification.SECRET)
developer = Actor("Developer", inBoundary=internet, maxClassification=Classification.SECRET)
customer_endpoint = ExternalEntity(
    "Customer Webhook Endpoint",
    inBoundary=tenant_net,
    maxClassification=Classification.SENSITIVE,
    description="Tenant-configured HTTPS URL that receives event notifications.",
)
repo = ExternalEntity(
    "GitHub Repositories",
    inBoundary=github,
    maxClassification=Classification.SECRET,
    description="Application code and Kubernetes manifests; branch protection + required reviews.",
)

# --- CI/CD --------------------------------------------------------------------------
ci = Server(
    "GitHub Actions (CI)",
    inBoundary=github,
    port=443,
    protocol="HTTPS",
    maxClassification=Classification.SECRET,
    isBuildSystem=True,
    description="Builds, tests and scans images; signs with cosign (keyless); pushes to ECR via OIDC role.",
)
apply_controls(ci, WEB_SERVICE)
respond(ci, "AC06", "mitigated: hosted ephemeral runners; workflows from forks never get secrets or the OIDC role")

registry = Datastore(
    "Amazon ECR",
    inBoundary=aws,
    isSQL=False,
    onAWS=True,
    maxClassification=Classification.SECRET,
    description="Immutable tags, scan-on-push, KMS encryption.",
)
apply_controls(registry, DATASTORE)

argocd = Server(
    "Argo CD (GitOps controller)",
    inBoundary=cluster,
    port=8443,
    protocol="HTTPS",
    maxClassification=Classification.SECRET,
    isBuildSystem=True,
    isCloudWorkload=True,
    hasAuditLogging=True,
    description="Pulls manifests from Git and reconciles them into the cluster.",
)
# GAP: Argo CD runs with cluster-admin, and the cluster does not verify image signatures at admission.
apply_controls(argocd, WEB_SERVICE, usesCodeSigning=False, implementsPOLP=False)

k8s_api = Server(
    "EKS Control Plane (Kubernetes API)",
    inBoundary=cluster,
    port=443,
    protocol="HTTPS",
    maxClassification=Classification.SECRET,
    description="Private endpoint; RBAC; audit logs to CloudWatch; Pod Security Admission 'restricted'.",
)
apply_controls(k8s_api, WEB_SERVICE)

# --- Runtime --------------------------------------------------------------------------
ingress = Server(
    "ALB Ingress + AWS WAF",
    inBoundary=aws,
    port=443,
    protocol="HTTPS",
    minTLSVersion=TLSVersion.TLSv12,
    maxClassification=Classification.SECRET,
    description="TLS termination, WAF managed rules, per-tenant rate-based rules.",
)
apply_controls(ingress, WEB_SERVICE, authenticatesSource=False, hasAccessControl=False, authorizesSource=False)
for threat_id, why in {
    "AA01": "transferred: JWTs are validated by the API service (and by the mesh)",
    "AA02": "transferred: principal established from the verified JWT in the API",
    "AA03": "transferred: credential checks happen in the API service",
    "AC01": "transferred: privileges evaluated by the API service",
    "AC06": "mitigated: no file uploads through the ingress",
    "AC07": "transferred: access control enforced by the API service",
    "AC08": "accepted: managed load balancer",
    "AC09": "transferred: business-logic limits live in the API service",
    "SC03": "transferred: authorization enforced downstream; WAF filters script payloads",
}.items():
    respond(ingress, threat_id, why)

api = Server(
    "Tenant API (pods)",
    inBoundary=cluster,
    port=8443,
    protocol="HTTPS",
    minTLSVersion=TLSVersion.TLSv12,
    maxClassification=Classification.SECRET,
    isCloudWorkload=True,
    isMultiTenant=True,
    enforcesTenantIsolation=True,
    hasAuditLogging=True,
    description="Validates JWT, sets app.tenant_id on each DB session, enqueues jobs.",
)
apply_controls(api, WEB_SERVICE)

worker = Process(
    "Report Worker (pods)",
    inBoundary=cluster,
    maxClassification=Classification.SENSITIVE,
    codeType="Managed",
    isCloudWorkload=True,
    isMultiTenant=True,
    enforcesTenantIsolation=True,
    hasAuditLogging=True,
    description="Consumes SQS jobs, runs tenant-scoped queries, writes results.",
)
apply_controls(worker, WORKER)

webhook_sender = Process(
    "Webhook Dispatcher (pods)",
    inBoundary=cluster,
    maxClassification=Classification.SENSITIVE,
    codeType="Managed",
    isCloudWorkload=True,
    hasAuditLogging=True,
    makesOutboundRequests=True,
    # GAP: delivers to any tenant-supplied URL; no egress proxy, IMDS hop limit not enforced.
    restrictsEgress=False,
    description="POSTs signed event payloads to tenant-configured URLs.",
)
apply_controls(webhook_sender, WORKER)

# --- Data services --------------------------------------------------------------------
db = Datastore(
    "Aurora PostgreSQL (shared, RLS)",
    inBoundary=data,
    port=5432,
    protocol="PostgreSQL/TLS",
    isSQL=True,
    onAWS=True,
    storesPII=True,
    storesSensitiveData=True,
    maxClassification=Classification.SENSITIVE,
    isMultiTenant=True,
    enforcesTenantIsolation=True,
    description="Pooled schema; every table has tenant_id + RLS policy USING (tenant_id = current_setting('app.tenant_id')).",
)
apply_controls(db, DATASTORE)

cache = Datastore(
    "ElastiCache Redis (shared)",
    inBoundary=data,
    port=6380,
    protocol="RESP/TLS",
    isSQL=False,
    onAWS=True,
    storesSensitiveData=True,
    maxClassification=Classification.SENSITIVE,
    isMultiTenant=True,
    # GAP: cache keys are derived from the report query hash only, without a tenant prefix.
    enforcesTenantIsolation=False,
    description="Caches rendered report fragments.",
)
apply_controls(cache, DATASTORE)

queue = Datastore(
    "SQS Job Queue",
    inBoundary=data,
    isSQL=False,
    onAWS=True,
    maxClassification=Classification.SENSITIVE,
    description="Report and webhook jobs; SSE-KMS; DLQ after 5 receives.",
)
apply_controls(queue, DATASTORE)

secrets = Datastore(
    "AWS Secrets Manager",
    inBoundary=data,
    isSQL=False,
    onAWS=True,
    storesSensitiveData=True,
    maxClassification=Classification.SECRET,
    description="DB credentials (rotated), webhook signing keys per tenant.",
)
apply_controls(secrets, DATASTORE)

# --- Data ----------------------------------------------------------------------------------
jwt = Data("Access token (tenant_id, roles)", format="JWT", classification=Classification.SECRET, isCredentials=True, credentialsLife=Lifetime.SHORT)
api_req = Data("Report request", format="JSON", classification=Classification.SENSITIVE)
tenant_rows = Data("Tenant business data", classification=Classification.SENSITIVE, isPII=True, isStored=True)
job = Data("Job message (tenant_id, report_id)", format="JSON", classification=Classification.RESTRICTED)
fragment = Data("Cached report fragment", classification=Classification.SENSITIVE, isStored=True)
event_payload = Data("Signed webhook payload", format="JSON", classification=Classification.SENSITIVE)
db_creds = Data("DB credentials / signing keys", classification=Classification.SECRET, isCredentials=True, credentialsLife=Lifetime.AUTO)
source = Data("Source code & manifests", classification=Classification.RESTRICTED)
image = Data("Signed container image + SBOM", classification=Classification.RESTRICTED)
oidc = Data("GitHub OIDC token -> AWS STS", format="JWT", classification=Classification.SECRET, isCredentials=True, credentialsLife=Lifetime.SHORT)

# --- Dataflows: runtime -----------------------------------------------------------------
req = Dataflow(tenant_user, ingress, "HTTPS API request (JWT)", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[jwt, api_req])
to_api = Dataflow(ingress, api, "Forward to API pods", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[jwt, api_req])
api_db = Dataflow(api, db, "Tenant-scoped query (SET app.tenant_id)", data=[tenant_rows])
api_cache = Dataflow(api, cache, "Read / write report cache", data=[fragment])
enqueue = Dataflow(api, queue, "Enqueue job", data=[job])
dequeue = Dataflow(queue, worker, "Receive job", data=[job])
worker_db = Dataflow(worker, db, "Run report query", data=[tenant_rows])
worker_cache = Dataflow(worker, cache, "Store fragment", data=[fragment])
to_webhook_q = Dataflow(worker, queue, "Enqueue webhook event", data=[job])
webhook_job = Dataflow(queue, webhook_sender, "Receive webhook job", data=[job])
get_secret = Dataflow(secrets, webhook_sender, "Fetch tenant signing key (IRSA)", data=[db_creds])
deliver = Dataflow(
    webhook_sender, customer_endpoint, "POST event to tenant URL", protocol="HTTPS", tlsVersion=TLSVersion.TLSv12,
    data=[event_payload],
)
api_secret = Dataflow(secrets, api, "Fetch DB credentials (IRSA)", tlsVersion=TLSVersion.TLSv13, data=[db_creds])

# --- Dataflows: delivery ----------------------------------------------------------------
push = Dataflow(developer, repo, "Push / PR (signed commits)", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[source])
build = Dataflow(repo, ci, "Trigger workflow", protocol="HTTPS", data=[source])
assume = Dataflow(ci, registry, "Push image (OIDC-assumed role)", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[oidc, image])
sync = Dataflow(repo, argocd, "Pull manifests", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[source])
apply = Dataflow(argocd, k8s_api, "kubectl apply (cluster-admin)", protocol="HTTPS", data=[source])
pull = Dataflow(registry, k8s_api, "Kubelet pulls image", protocol="HTTPS", data=[image])

public_flows = (req, deliver, push, build, assume, sync)
private_flows = (
    to_api, api_db, api_cache, enqueue, dequeue, worker_db, worker_cache, to_webhook_q, webhook_job,
    get_secret, api_secret, apply, pull,
)
for flow in public_flows + private_flows:
    flow.maxClassification = min(flow.source.maxClassification, flow.sink.maxClassification)
    apply_controls(flow, SECURE_FLOW)
for flow in private_flows:
    flow.usesVPN = True  # in-VPC, mesh mTLS, VPC endpoints
for flow in public_flows:
    respond(flow, "DE03", "mitigated: TLS 1.2+ with certificate validation; a VPN is not applicable to SaaS and customer endpoints")


if __name__ == "__main__":
    tm.process()
