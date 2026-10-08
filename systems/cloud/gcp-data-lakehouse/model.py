#!/usr/bin/env python3
"""Analytics lakehouse on Google Cloud: CDC ingestion, Dataflow, GCS, BigQuery, Looker and partner sharing.

Product databases stream changes into a raw zone on Cloud Storage; Dataflow
curates them into BigQuery; analysts use Looker; data scientists use Vertex AI
Workbench notebooks; a subset is shared with a marketing partner.

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
    "Analytics Lakehouse on Google Cloud",
    description=(
        "Change data capture from product databases lands in a Cloud Storage raw "
        "zone via Datastream; Dataflow curates it into BigQuery datasets with "
        "policy tags on PII columns. Analysts query through Looker, data "
        "scientists through Vertex AI Workbench notebooks, and an aggregated "
        "audience dataset is shared with a marketing partner."
    ),
    isOrdered=True,
    mergeResponses=True,
)
tm.threatsFile = str(THREATS)
tm.assumptions = [
    "One GCP organization; the lakehouse lives in a dedicated 'data-prod' project.",
    "Workforce identities come from Google Workspace with enforced 2-Step Verification.",
    "Organization policies enforce uniform bucket-level access and public access prevention.",
    "Customer data includes names, emails, addresses and purchase history (GDPR/CCPA personal data).",
]

# --- Trust boundaries ---------------------------------------------------------
product = Boundary("Product Environment")
gcp = Boundary("GCP data-prod Project")
ingest = Boundary("Ingestion")
ingest.inBoundary = gcp
warehouse = Boundary("Warehouse")
warehouse.inBoundary = gcp
corp = Boundary("Workforce")
partner = Boundary("Marketing Partner")

# --- Actors and external entities --------------------------------------------
source_db = ExternalEntity(
    "Product Databases (Cloud SQL)",
    inBoundary=product,
    maxClassification=Classification.SENSITIVE,
    description="Orders, customers, events. Read replicas exposed to Datastream.",
)
analyst = Actor("Business Analyst", inBoundary=corp, maxClassification=Classification.RESTRICTED)
scientist = Actor("Data Scientist", inBoundary=corp, maxClassification=Classification.SENSITIVE)
partner_proj = ExternalEntity(
    "Partner GCP Project",
    inBoundary=partner,
    maxClassification=Classification.RESTRICTED,
    description="Receives an audience dataset through Analytics Hub.",
)

# --- Ingestion -----------------------------------------------------------------------
datastream = Server(
    "Datastream (CDC)",
    inBoundary=ingest,
    port=443,
    protocol="HTTPS",
    minTLSVersion=TLSVersion.TLSv12,
    maxClassification=Classification.SENSITIVE,
    description="Reads binlogs over private connectivity; writes Avro files to the raw bucket.",
)
apply_controls(datastream, WEB_SERVICE)

raw = Datastore(
    "GCS Raw Zone",
    inBoundary=ingest,
    isSQL=False,
    storesPII=True,
    maxClassification=Classification.SENSITIVE,
    isObjectStorage=True,
    blocksPublicAccess=True,
    # GAP: Data Access audit logs (DATA_READ / DATA_WRITE) are off, which is the GCP default.
    hasAuditLogging=False,
    description="Unmasked CDC files; CMEK; 30-day retention.",
)
apply_controls(raw, DATASTORE)

dataflow = Process(
    "Dataflow Curation Pipeline",
    inBoundary=ingest,
    maxClassification=Classification.SENSITIVE,
    codeType="Managed",
    isCloudWorkload=True,
    hasAuditLogging=True,
    description="Deduplicates, applies schemas, tokenizes emails, loads curated tables.",
)
apply_controls(dataflow, JOB)

# --- Warehouse ------------------------------------------------------------------------
bigquery = Datastore(
    "BigQuery Curated Datasets",
    inBoundary=warehouse,
    isSQL=True,
    storesPII=True,
    maxClassification=Classification.SENSITIVE,
    hasAuditLogging=True,
    description="Policy tags on PII columns; row-level access policies by region; CMEK.",
)
apply_controls(bigquery, DATASTORE)

looker = Server(
    "Looker",
    inBoundary=warehouse,
    port=443,
    protocol="HTTPS",
    minTLSVersion=TLSVersion.TLSv12,
    maxClassification=Classification.SENSITIVE,
    usesSessionTokens=True,
    description="Semantic layer and dashboards; queries BigQuery with a service account.",
)
apply_controls(looker, WEB_SERVICE, encryptsCookies=True, encryptsSessionData=True)
respond(looker, "CR01", "mitigated: Google SSO sessions (Secure, HttpOnly), 12h max lifetime")

notebooks = Process(
    "Vertex AI Workbench Notebooks",
    inBoundary=warehouse,
    maxClassification=Classification.SENSITIVE,
    codeType="Managed",
    isCloudWorkload=True,
    hasAuditLogging=True,
    makesOutboundRequests=True,
    # GAP: notebooks have open internet egress (pip installs, arbitrary downloads/uploads).
    restrictsEgress=False,
    description="Exploratory analysis and feature engineering on curated data.",
)
# GAP: notebooks run as a shared service account with roles/bigquery.admin on the project.
apply_controls(notebooks, JOB, implementsPOLP=False)

sharing = Server(
    "Analytics Hub Listing",
    inBoundary=warehouse,
    port=443,
    protocol="HTTPS",
    maxClassification=Classification.SENSITIVE,
    description="Publishes an 'audiences' dataset to the partner project.",
)
apply_controls(sharing, WEB_SERVICE)

# --- Data ---------------------------------------------------------------------------------
cdc = Data("CDC change records (unmasked)", classification=Classification.SENSITIVE, isPII=True)
raw_files = Data("Avro files (unmasked)", classification=Classification.SENSITIVE, isPII=True, isStored=True)
raw_read = Data("Raw files for curation", classification=Classification.SENSITIVE, isPII=True)
curated = Data("Curated tables", classification=Classification.SENSITIVE, isPII=True, isStored=True)
dashboard = Data("Aggregated dashboard results", classification=Classification.RESTRICTED)
query = Data("SQL query results (row-level)", classification=Classification.SENSITIVE, isPII=True)
sa_key = Data(
    "Service-account JSON key (notebook SA)",
    classification=Classification.SECRET,
    isCredentials=True,
    credentialsLife=Lifetime.LONG,
)
audiences = Data("Audience dataset (hashed email, segment)", classification=Classification.SENSITIVE, isPII=True)
sso = Data("Workspace SSO session", classification=Classification.RESTRICTED, isCredentials=True, credentialsLife=Lifetime.SHORT)

# --- Dataflows ------------------------------------------------------------------------
replicate = Dataflow(source_db, datastream, "Replicate binlog (private connectivity)", protocol="MySQL/TLS", tlsVersion=TLSVersion.TLSv12, data=[cdc])
land = Dataflow(datastream, raw, "Write Avro files", data=[raw_files])
read_raw = Dataflow(raw, dataflow, "Read new files", tlsVersion=TLSVersion.TLSv13, data=[raw_read])
load = Dataflow(dataflow, bigquery, "Load curated tables", data=[curated])
browse = Dataflow(analyst, looker, "View dashboards", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[sso])
looker_q = Dataflow(looker, bigquery, "Run model queries", protocol="HTTPS", data=[dashboard])
explore = Dataflow(
    scientist, notebooks, "Run notebook (local gcloud with SA key)", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13,
    data=[sa_key],
)
nb_q = Dataflow(notebooks, bigquery, "Query / export tables", protocol="HTTPS", data=[query])
publish = Dataflow(bigquery, sharing, "Publish audience view", protocol="HTTPS", data=[audiences])
subscribe = Dataflow(sharing, partner_proj, "Partner subscribes (linked dataset)", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[audiences])

external_flows = (replicate, browse, explore, subscribe)
internal_flows = (land, read_raw, load, looker_q, nb_q, publish)
for flow in external_flows + internal_flows:
    flow.maxClassification = min(flow.source.maxClassification, flow.sink.maxClassification)
    apply_controls(flow, SECURE_FLOW)
for flow in internal_flows:
    flow.usesVPN = True  # Google backbone / Private Google Access
for flow in external_flows:
    respond(flow, "DE03", "mitigated: TLS 1.2+ (Google front ends; private connectivity for CDC)")


if __name__ == "__main__":
    tm.process()
