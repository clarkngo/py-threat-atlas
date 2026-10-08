#!/usr/bin/env python3
"""Serverless file upload pipeline on AWS.

Clients upload directly to S3 with pre-signed URLs, an S3 event triggers a
malware-scanning Lambda, clean files are promoted to a separate bucket and
served through CloudFront, and metadata is tracked in DynamoDB.

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
    DatastoreType,
    ExternalEntity,
    Finding,
    Lambda,
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
FUNCTION = dict(
    validatesInput=True, sanitizesInput=True, checksInputBounds=True, implementsAuthenticationScheme=True,
    authorizesSource=True, implementsPOLP=True, handlesResourceConsumption=True, usesCodeSigning=True,
    usesParameterizedInput=True, isResilient=True,
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
    "Serverless File Upload Pipeline (AWS)",
    description=(
        "Users upload documents and images through S3 pre-signed URLs. An S3 event "
        "triggers a containerized Lambda that scans with ClamAV, validates file type, "
        "and promotes clean files to a private bucket served via CloudFront signed "
        "URLs. Upload state is tracked in DynamoDB."
    ),
    isOrdered=True,
    mergeResponses=True,
)
tm.threatsFile = str(THREATS)
tm.assumptions = [
    "Single production AWS account inside an AWS Organization with SCPs and a separate log-archive account.",
    "All buckets use SSE-KMS with customer-managed keys and Bucket Owner Enforced object ownership.",
    "Lambdas run in private subnets; S3 and DynamoDB are reached through VPC gateway endpoints.",
    "Uploaded files are untrusted until the scanner marks them CLEAN.",
]

# --- Trust boundaries ---------------------------------------------------------
internet = Boundary("Internet")
aws = Boundary("AWS Account (prod)")
edge = Boundary("Public AWS Endpoints")
edge.inBoundary = aws
compute = Boundary("Lambda (VPC)")
compute.inBoundary = aws
storage = Boundary("Storage")
storage.inBoundary = aws

# --- Actors -----------------------------------------------------------------------
user = Actor("User (web / mobile)", inBoundary=internet, maxClassification=Classification.SECRET)
cognito = ExternalEntity(
    "Amazon Cognito User Pool",
    inBoundary=edge,
    maxClassification=Classification.SECRET,
    description="Issues JWT access tokens (OAuth 2.0, PKCE) to the client.",
)

# --- Edge -------------------------------------------------------------------------
api = Server(
    "API Gateway (HTTP API)",
    inBoundary=edge,
    port=443,
    protocol="HTTPS",
    minTLSVersion=TLSVersion.TLSv12,
    maxClassification=Classification.SECRET,
    onAWS=True,
    description="JWT authorizer (Cognito), throttling, request validation, AWS WAF.",
)
apply_controls(api, WEB_SERVICE)
cdn = Server(
    "CloudFront (signed URLs)",
    inBoundary=edge,
    port=443,
    protocol="HTTPS",
    minTLSVersion=TLSVersion.TLSv12,
    maxClassification=Classification.SENSITIVE,
    onAWS=True,
    description="Serves clean files with short-lived signed URLs; Origin Access Control to S3.",
)
apply_controls(cdn, WEB_SERVICE)
respond(cdn, "DS05", "mitigated: private content is cached per signed URL and served with Content-Disposition: attachment")

# --- Compute ----------------------------------------------------------------------
presign = Lambda(
    "Presign Lambda",
    inBoundary=compute,
    maxClassification=Classification.SENSITIVE,
    implementsAPI=True,
    usesEnvironmentVariables=True,
    isCloudWorkload=True,
    hasAuditLogging=True,
    description="Creates the DynamoDB upload record and returns a pre-signed S3 POST policy.",
)
# GAP: execution role allows s3:PutObject on arn:aws:s3:::uploads-*/* (both buckets).
apply_controls(presign, FUNCTION, implementsPOLP=False)
respond(presign, "API01", "mitigated: single route, no debug or test stages deployed; API schema enforced at the gateway")

scanner = Lambda(
    "Scan and Promote Lambda (ClamAV)",
    inBoundary=compute,
    maxClassification=Classification.SENSITIVE,
    usesEnvironmentVariables=True,
    isCloudWorkload=True,
    isEventTriggered=True,
    hasAuditLogging=True,
    makesOutboundRequests=True,  # freshclam signature updates
    restrictsEgress=True,  # egress only to the signature mirror through an allow-listed proxy
    description=(
        "Container-image Lambda. Downloads the object, runs clamscan and libmagic "
        "type detection, strips metadata from images, then copies to the clean bucket."
    ),
)
# GAP: the S3 object key and user metadata are treated as trusted and passed to subprocess calls.
apply_controls(scanner, FUNCTION, validatesInput=False, sanitizesInput=False)

# --- Storage ------------------------------------------------------------------------
quarantine = Datastore(
    "S3 Quarantine Bucket",
    inBoundary=storage,
    type=DatastoreType.AWS_S3,
    isSQL=False,
    onAWS=True,
    storesSensitiveData=True,
    maxClassification=Classification.SENSITIVE,
    isObjectStorage=True,
    blocksPublicAccess=True,
    # GAP: CloudTrail S3 data events are not enabled for this bucket.
    hasAuditLogging=False,
    description="Untrusted uploads. Lifecycle: delete after 24h. No read access except the scanner.",
)
apply_controls(quarantine, DATASTORE)

clean = Datastore(
    "S3 Clean Bucket",
    inBoundary=storage,
    type=DatastoreType.AWS_S3,
    isSQL=False,
    onAWS=True,
    storesPII=True,
    storesSensitiveData=True,
    maxClassification=Classification.SENSITIVE,
    isObjectStorage=True,
    blocksPublicAccess=True,
    hasAuditLogging=True,
    description="Scanned files. Versioning + Object Lock (governance). Read only through CloudFront OAC.",
)
apply_controls(clean, DATASTORE)

metadata = Datastore(
    "DynamoDB Upload Metadata",
    inBoundary=storage,
    isSQL=False,
    onAWS=True,
    storesPII=True,
    maxClassification=Classification.SENSITIVE,
    hasAuditLogging=True,
    description="owner_sub, object key, sha256, size, content type, scan status, timestamps.",
)
apply_controls(metadata, DATASTORE)

# --- Data --------------------------------------------------------------------------
jwt = Data("Cognito access token", format="JWT", classification=Classification.SECRET, isCredentials=True, credentialsLife=Lifetime.SHORT)
upload_req = Data("Upload request (filename, size, type)", format="JSON", classification=Classification.RESTRICTED)
presigned = Data(
    "Pre-signed POST policy (5 min, content-length-range)",
    format="JSON",
    classification=Classification.SENSITIVE,
    isCredentials=True,
    credentialsLife=Lifetime.SHORT,
)
file_untrusted = Data("Uploaded file (untrusted)", classification=Classification.SENSITIVE, isPII=True, isStored=True)
s3_event = Data("S3 ObjectCreated event (bucket, key, size)", format="JSON", classification=Classification.RESTRICTED)
file_clean = Data("Clean file", classification=Classification.SENSITIVE, isPII=True, isStored=True)
record = Data("Upload metadata record", format="JSON", classification=Classification.SENSITIVE, isPII=True, isStored=True)
signed_url = Data("CloudFront signed URL (10 min)", classification=Classification.SENSITIVE, isCredentials=True, credentialsLife=Lifetime.SHORT)
file_download = Data("Downloaded file", classification=Classification.SENSITIVE, isPII=True)

# --- Dataflows ------------------------------------------------------------------------
login = Dataflow(user, cognito, "Sign in (OAuth 2.0 + PKCE)", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13)
token = Dataflow(cognito, user, "Access token", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[jwt])
request_upload = Dataflow(
    user, api, "POST /uploads (JWT)", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[jwt, upload_req]
)
invoke_presign = Dataflow(api, presign, "Invoke with verified claims", protocol="HTTPS", data=[upload_req])
put_record = Dataflow(presign, metadata, "Create record (PENDING)", data=[record])
return_url = Dataflow(
    presign, user, "Pre-signed POST policy", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[presigned],
    usesPresignedURL=True,
)
upload = Dataflow(
    user, quarantine, "Upload file directly to S3", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13,
    data=[presigned, file_untrusted], usesPresignedURL=True,
)
event = Dataflow(quarantine, scanner, "s3:ObjectCreated trigger", data=[s3_event])
get_object = Dataflow(scanner, quarantine, "GetObject for scanning", data=[file_untrusted])
promote = Dataflow(scanner, clean, "CopyObject when CLEAN", data=[file_clean])
update_record = Dataflow(scanner, metadata, "Update status (CLEAN / INFECTED)", data=[record])
request_download = Dataflow(
    user, api, "GET /files/{id} (JWT)", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[jwt]
)
download_url = Dataflow(api, user, "CloudFront signed URL", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[signed_url])
download = Dataflow(
    user, cdn, "Download via signed URL", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[signed_url]
)
origin = Dataflow(cdn, clean, "Origin fetch (OAC, SigV4)", protocol="HTTPS", data=[file_download])

public_flows = (login, token, request_upload, return_url, upload, request_download, download_url, download)
private_flows = (invoke_presign, put_record, event, get_object, promote, update_record, origin)

for flow in public_flows + private_flows:
    flow.maxClassification = min(flow.source.maxClassification, flow.sink.maxClassification)
    if flow is upload:
        # GAP: the POST policy constrains size but not Content-Type.
        apply_controls(flow, SECURE_FLOW, validatesContentType=False)
    else:
        apply_controls(flow, SECURE_FLOW, validatesContentType=True)
for flow in private_flows:
    flow.usesVPN = True  # VPC gateway endpoints / AWS backbone
for flow in public_flows:
    respond(flow, "DE03", "mitigated: TLS 1.2+ enforced by aws:SecureTransport bucket policy and API/CloudFront security policies")


if __name__ == "__main__":
    tm.process()
