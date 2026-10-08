#!/usr/bin/env python3
"""Real-time ML fraud scoring for card payments: training pipeline, model registry and inference.

A gradient-boosted model scores every authorization in under 50 ms. Labels
come from chargebacks and analyst case decisions; models are retrained weekly
and promoted through a registry.

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
    "Real-Time ML Fraud Scoring",
    description=(
        "Card-issuer fraud platform. Authorization requests are enriched with "
        "online features and scored by a gradient-boosted model behind an internal "
        "inference endpoint; the score feeds an approve / decline / step-up "
        "decision. Weekly retraining uses transactions labeled by chargebacks and "
        "analyst case outcomes, and models are promoted through a registry."
    ),
    isOrdered=True,
    mergeResponses=True,
)
tm.threatsFile = str(THREATS)
tm.assumptions = [
    "The environment is in PCI DSS scope; PAN is tokenized before reaching the ML platform.",
    "The model is tabular (XGBoost); no third-party pretrained weights are used.",
    "Rules engine and velocity checks run alongside the model; the model is not the only control.",
    "Fraudsters cannot see scores directly, but they observe approve/decline outcomes.",
]

# --- Trust boundaries ---------------------------------------------------------
networks = Boundary("Card Networks")
oss = Boundary("Public Package Index")
authz_zone = Boundary("Authorization (PCI)")
ml_platform = Boundary("ML Platform")
lake_zone = Boundary("Data Lake")
lake_zone.inBoundary = ml_platform
corp = Boundary("Corporate Network")

# --- Actors and external entities --------------------------------------------
network = ExternalEntity(
    "Card Network (auth + disputes)",
    inBoundary=networks,
    maxClassification=Classification.SECRET,
    description="Sends ISO 8583 authorization requests and chargeback / dispute files.",
)
pypi = ExternalEntity(
    "PyPI / Conda Mirrors",
    inBoundary=oss,
    maxClassification=Classification.PUBLIC,
    description="Open-source ML dependencies (xgboost, pandas, scikit-learn).",
)
analyst = Actor("Fraud Analyst", inBoundary=corp, maxClassification=Classification.SENSITIVE)
mle = Actor("ML Engineer", inBoundary=corp, isAdmin=True, maxClassification=Classification.SENSITIVE)

# --- Online path ----------------------------------------------------------------
auth_service = Server(
    "Authorization Service",
    inBoundary=authz_zone,
    port=8443,
    protocol="HTTPS",
    minTLSVersion=TLSVersion.TLSv12,
    maxClassification=Classification.SECRET,
    description="Tokenizes PAN, calls rules + model, returns approve / decline / step-up within SLA.",
)
apply_controls(auth_service, WEB_SERVICE)

feature_store = Datastore(
    "Online Feature Store",
    inBoundary=authz_zone,
    isSQL=False,
    maxClassification=Classification.SENSITIVE,
    storesSensitiveData=True,
    description="Velocity counters, device and merchant aggregates keyed by card token.",
)
apply_controls(feature_store, DATASTORE)

inference = Server(
    "Model Inference Endpoint",
    inBoundary=ml_platform,
    port=8443,
    protocol="HTTPS",
    minTLSVersion=TLSVersion.TLSv12,
    maxClassification=Classification.SENSITIVE,
    isInferenceEndpoint=True,
    # GAP: no detection of systematic probing (many near-identical low-value attempts across cards).
    monitorsQueryPatterns=False,
    description="Loads the promoted model at start-up; returns a calibrated score and top reason codes.",
)
apply_controls(inference, WEB_SERVICE)

# --- Offline path -----------------------------------------------------------------
stream = Datastore(
    "Transaction Event Stream (Kafka)",
    inBoundary=ml_platform,
    isSQL=False,
    maxClassification=Classification.SENSITIVE,
    description="Tokenized authorization events and decisions.",
)
apply_controls(stream, DATASTORE)

lake = Datastore(
    "Training Data Lake",
    inBoundary=lake_zone,
    isSQL=False,
    maxClassification=Classification.SENSITIVE,
    storesSensitiveData=True,
    storesPII=True,
    isTrainingData=True,
    description="Historical transactions joined with labels (chargebacks, analyst decisions).",
)
# GAP: labels are overwritten in place; no dataset versioning, hashes or label-distribution checks.
apply_controls(lake, DATASTORE, providesIntegrity=False)

training = Process(
    "Training Pipeline",
    inBoundary=ml_platform,
    maxClassification=Classification.SENSITIVE,
    codeType="Managed",
    isCloudWorkload=True,
    hasAuditLogging=True,
    description="Weekly: feature engineering, XGBoost training, evaluation, registration.",
)
# GAP: the training role has read/write on the whole lake and the registry.
apply_controls(training, JOB, implementsPOLP=False)

registry = Datastore(
    "Model Registry",
    inBoundary=ml_platform,
    isSQL=False,
    maxClassification=Classification.SENSITIVE,
    isModelArtifact=True,
    description="Versioned model artifacts (pickle), metrics and stage (staging / production).",
)
# GAP: artifacts are pickled and not signed; inference loads whatever is tagged 'production'.
apply_controls(registry, DATASTORE, usesCodeSigning=False)

cases = Server(
    "Case Management",
    inBoundary=corp,
    port=443,
    protocol="HTTPS",
    minTLSVersion=TLSVersion.TLSv12,
    maxClassification=Classification.SENSITIVE,
    usesSessionTokens=True,
    description="Analysts review alerts and mark transactions fraud / not fraud.",
)
apply_controls(cases, WEB_SERVICE, encryptsCookies=True, encryptsSessionData=True)
respond(cases, "CR01", "mitigated: SSO session cookies (Secure, HttpOnly) on a ZTNA-only application")

# --- Data -------------------------------------------------------------------------------
auth_req = Data("Authorization request (PAN, amount, merchant)", classification=Classification.SECRET, isPII=True)
features = Data("Feature vector (card token)", format="JSON", classification=Classification.SENSITIVE)
score = Data("Score + reason codes", format="JSON", classification=Classification.RESTRICTED)
decision = Data("Approve / decline / step-up", classification=Classification.RESTRICTED)
event = Data("Tokenized transaction event", format="JSON", classification=Classification.SENSITIVE)
chargeback = Data("Chargeback / dispute records", classification=Classification.SENSITIVE)
label = Data("Analyst label", format="JSON", classification=Classification.SENSITIVE)
training_set = Data("Labeled training set", classification=Classification.SENSITIVE, isPII=True, isStored=True)
training_read = Data("Training snapshot", classification=Classification.SENSITIVE, isPII=True)
artifact = Data("Model artifact (.pkl) + metrics", classification=Classification.SENSITIVE, isStored=True)
artifact_load = Data("Production model artifact", classification=Classification.SENSITIVE)
packages = Data("Python packages", classification=Classification.PUBLIC)
promotion = Data("Stage transition (staging -> production)", format="JSON", classification=Classification.RESTRICTED)
sso = Data("SSO session", classification=Classification.SENSITIVE, isCredentials=True, credentialsLife=Lifetime.SHORT)

# --- Dataflows: online -----------------------------------------------------------------
authorize = Dataflow(network, auth_service, "Authorization request", protocol="ISO 8583/TLS", tlsVersion=TLSVersion.TLSv12, data=[auth_req])
get_features = Dataflow(auth_service, feature_store, "Lookup + update velocity features", data=[features])
score_req = Dataflow(auth_service, inference, "Score request", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[features])
score_resp = Dataflow(inference, auth_service, "Score", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[score], responseTo=score_req)
respond_net = Dataflow(auth_service, network, "Authorization response", protocol="ISO 8583/TLS", tlsVersion=TLSVersion.TLSv12, data=[decision])
publish = Dataflow(auth_service, stream, "Publish event", data=[event])

# --- Dataflows: offline -----------------------------------------------------------------
land = Dataflow(stream, lake, "Land events", data=[training_set])
disputes = Dataflow(network, lake, "Daily chargeback file (SFTP)", protocol="SFTP", data=[chargeback])
review = Dataflow(analyst, cases, "Review alerts / label cases", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[sso, label])
labels = Dataflow(cases, lake, "Write analyst labels", data=[label])
read_train = Dataflow(lake, training, "Read training snapshot", data=[training_read])
deps = Dataflow(pypi, training, "Install dependencies", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[packages])
register = Dataflow(training, registry, "Register model version", data=[artifact])
promote = Dataflow(mle, registry, "Promote to production", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[promotion])
load = Dataflow(registry, inference, "Load production model", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[artifact_load])

external_flows = (authorize, respond_net, disputes, deps)
internal_flows = (
    get_features, score_req, score_resp, publish, land, review, labels, read_train, register, promote, load,
)
for flow in external_flows + internal_flows:
    flow.maxClassification = min(flow.source.maxClassification, flow.sink.maxClassification)
    apply_controls(flow, SECURE_FLOW)
for flow in internal_flows:
    flow.usesVPN = True
for flow in (authorize, respond_net, disputes):
    flow.usesVPN = True  # dedicated network links / IPsec to the card network
respond(deps, "DE03", "mitigated: TLS to an internal proxy mirror; packages pinned by hash")


if __name__ == "__main__":
    tm.process()
