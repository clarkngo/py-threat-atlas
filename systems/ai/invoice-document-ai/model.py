#!/usr/bin/env python3
"""Invoice document AI for accounts payable: OCR + LLM extraction feeding straight-through payment.

Suppliers email PDF invoices to an AP mailbox. A pipeline OCRs them, an LLM
extracts structured fields (supplier, bank details, line items, totals),
rules match them against purchase orders and the vendor master in the ERP,
and matched invoices are scheduled for payment without human touch.

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
    "Invoice Document AI",
    description=(
        "Accounts-payable automation. Supplier invoices arrive as PDFs by email, "
        "are OCR'd by a cloud document AI service, and an LLM extracts supplier "
        "identity, remittance bank details, line items and totals as JSON. A "
        "rules engine performs three-way matching against purchase orders and "
        "goods receipts in the ERP; matched invoices go straight to the weekly "
        "payment run, and exceptions go to an AP clerk."
    ),
    isOrdered=True,
    mergeResponses=True,
)
tm.threatsFile = str(THREATS)
tm.assumptions = [
    "Anyone can email the AP mailbox; supplier domains are frequently spoofed or compromised.",
    "Invoices under $10,000 that pass three-way matching are paid with no human review.",
    "The OCR and LLM services are cloud APIs under enterprise terms with zero data retention.",
    "Vendor bank details live in the ERP vendor master and are the target of payment-diversion fraud.",
]

# --- Trust boundaries ---------------------------------------------------------
internet = Boundary("Internet")
cloud_ai = Boundary("Cloud AI Services")
ap_platform = Boundary("AP Automation Platform")
erp_zone = Boundary("ERP")
bank_zone = Boundary("Bank")
finance = Boundary("Finance Team")

# --- Actors and external entities --------------------------------------------
supplier = Actor("Supplier (or impersonator)", inBoundary=internet, maxClassification=Classification.SENSITIVE)
clerk = Actor("AP Clerk", inBoundary=finance, maxClassification=Classification.SENSITIVE)
mailbox = ExternalEntity("AP Mailbox (email provider)", inBoundary=internet, maxClassification=Classification.SENSITIVE)
ocr = ExternalEntity(
    "Document AI (OCR)", inBoundary=cloud_ai, maxClassification=Classification.SENSITIVE, isThirdPartyModel=True,
    description="Layout-aware OCR returning text, tables and bounding boxes.",
)
llm_api = ExternalEntity("Foundation Model API", inBoundary=cloud_ai, maxClassification=Classification.SENSITIVE, isThirdPartyModel=True)
bank = ExternalEntity("Bank (payment files)", inBoundary=bank_zone, maxClassification=Classification.SECRET)

# --- AP platform -------------------------------------------------------------------
intake = Server(
    "Intake Service",
    inBoundary=ap_platform,
    port=443,
    protocol="HTTPS",
    minTLSVersion=TLSVersion.TLSv12,
    maxClassification=Classification.SENSITIVE,
    description="Pulls mail via Graph API, records SPF/DKIM/DMARC results, sanitizes PDFs (CDR), stores originals.",
)
apply_controls(intake, WEB_SERVICE)

archive = Datastore(
    "Invoice Archive",
    inBoundary=ap_platform,
    isSQL=False,
    maxClassification=Classification.SENSITIVE,
    isObjectStorage=True,
    blocksPublicAccess=True,
    hasAuditLogging=True,
    description="Original PDFs and OCR output; 10-year retention for audit.",
)
apply_controls(archive, DATASTORE)

extractor = Server(
    "LLM Field Extractor",
    inBoundary=ap_platform,
    port=8443,
    protocol="HTTPS",
    minTLSVersion=TLSVersion.TLSv12,
    maxClassification=Classification.SENSITIVE,
    isLLM=True,
    hasPromptGuardrails=True,
    secretsExcludedFromPrompt=True,
    filtersSensitiveOutput=True,
    # GAP: free-text extraction; no check that each extracted value appears in the OCR text at its location.
    groundsResponses=False,
    description="Prompts the model with OCR text and a JSON schema; returns supplier, IBAN, PO number, lines, totals.",
)
apply_controls(extractor, WEB_SERVICE)

matcher = Server(
    "Matching & Rules Engine",
    inBoundary=ap_platform,
    port=8443,
    protocol="HTTPS",
    minTLSVersion=TLSVersion.TLSv12,
    maxClassification=Classification.SENSITIVE,
    description="Three-way match (PO, receipt, invoice); duplicate detection; routes exceptions to clerks.",
)
apply_controls(matcher, WEB_SERVICE)

review = Server(
    "Exception Review UI",
    inBoundary=ap_platform,
    port=443,
    protocol="HTTPS",
    minTLSVersion=TLSVersion.TLSv12,
    maxClassification=Classification.SENSITIVE,
    usesSessionTokens=True,
    description="Clerks see extracted fields next to the PDF and approve, correct or reject.",
)
apply_controls(review, WEB_SERVICE, encryptsCookies=True, encryptsSessionData=True)
respond(review, "CR01", "mitigated: SSO session cookies (Secure, HttpOnly) with phishing-resistant MFA")

# --- ERP -------------------------------------------------------------------------------
erp = Server(
    "ERP (AP + Vendor Master)",
    inBoundary=erp_zone,
    port=443,
    protocol="HTTPS",
    minTLSVersion=TLSVersion.TLSv12,
    maxClassification=Classification.SECRET,
    description="Purchase orders, goods receipts, vendor master (bank details), payment runs.",
)
apply_controls(erp, WEB_SERVICE)

# --- Data ---------------------------------------------------------------------------------
email = Data("Email + PDF invoice (untrusted)", classification=Classification.SENSITIVE)
pdf = Data("Sanitized PDF", classification=Classification.SENSITIVE, isStored=True)
pdf_send = Data("Invoice image / PDF", classification=Classification.SENSITIVE)
ocr_text = Data("OCR text + layout", format="JSON", classification=Classification.SENSITIVE)
prompt = Data("Extraction prompt (schema + OCR text)", classification=Classification.SENSITIVE)
fields = Data("Extracted fields (supplier, IBAN, PO, totals)", format="JSON", classification=Classification.SENSITIVE)
erp_lookup = Data("PO, receipts, vendor master record", format="JSON", classification=Classification.SENSITIVE)
approved = Data("Approved invoice for payment", format="JSON", classification=Classification.SENSITIVE)
exception = Data("Exception case", format="JSON", classification=Classification.SENSITIVE)
decision = Data("Clerk decision / correction", format="JSON", classification=Classification.SENSITIVE)
sso = Data("SSO session", classification=Classification.RESTRICTED, isCredentials=True, credentialsLife=Lifetime.SHORT)
payment_file = Data("Payment file (ISO 20022 pain.001)", format="XML", classification=Classification.SECRET)

# --- Dataflows -------------------------------------------------------------------------------
send = Dataflow(supplier, mailbox, "Email invoice", protocol="SMTP/TLS", data=[email])
fetch = Dataflow(mailbox, intake, "Fetch mail (Graph API)", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[email])
store = Dataflow(intake, archive, "Store sanitized PDF", data=[pdf])
to_ocr = Dataflow(intake, ocr, "OCR request", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[pdf_send], hasZeroDataRetention=True)
ocr_back = Dataflow(ocr, extractor, "OCR text + layout", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[ocr_text],
                    carriesUntrustedContent=True)
to_llm = Dataflow(extractor, llm_api, "Extraction prompt", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[prompt], hasZeroDataRetention=True)
to_match = Dataflow(extractor, matcher, "Extracted fields (JSON)", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[fields])
lookup = Dataflow(erp, matcher, "PO / receipts / vendor master", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[erp_lookup])
post = Dataflow(matcher, erp, "Post matched invoice (straight-through)", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[approved])
escalate = Dataflow(matcher, review, "Exception case", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[exception])
decide = Dataflow(clerk, review, "Approve / correct / reject", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[sso, decision])
resolve = Dataflow(review, erp, "Post reviewed invoice / update vendor", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[decision])
pay = Dataflow(erp, bank, "Weekly payment file", protocol="SFTP", data=[payment_file])

external_flows = (send, fetch, to_ocr, ocr_back, to_llm, pay, decide)
internal_flows = (store, to_match, lookup, post, escalate, resolve)
for flow in external_flows + internal_flows:
    flow.maxClassification = min(flow.source.maxClassification, flow.sink.maxClassification)
    if flow is ocr_back:
        # GAP: OCR text (including hidden / white / tiny text) goes into the prompt verbatim.
        apply_controls(flow, SECURE_FLOW, sanitizesInput=False)
    elif flow is to_match:
        # GAP: extracted JSON is schema-checked, but values are not verified against the document or vendor master.
        apply_controls(flow, SECURE_FLOW, validatesInput=False)
    else:
        apply_controls(flow, SECURE_FLOW)
for flow in internal_flows:
    flow.usesVPN = True
for flow in external_flows:
    respond(flow, "DE03", "mitigated: TLS 1.2+ (MTA-STS on the AP domain; SFTP with host-key pinning to the bank)")
respond(pay, "DO03", "mitigated: payment files are generated internally and validated against the ISO 20022 schema")
respond(pay, "DO04", "transferred: the bank's file gateway parses pain.001; the ERP never emits DTDs or entity declarations")


if __name__ == "__main__":
    tm.process()
