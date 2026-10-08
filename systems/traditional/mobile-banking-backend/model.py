#!/usr/bin/env python3
"""Mobile banking backend: native apps, device binding, step-up OTP and a SOAP bridge to core banking.

Retail customers use iOS/Android apps to check balances, add payees and send
transfers. The mobile API layer is modern; account data and postings still
live on a core-banking mainframe reached through an ESB that speaks SOAP/XML
and IBM MQ.

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
    usesEncryptionAlgorithm="AES", disablesDTD=True,
)
APP = dict(
    validatesInput=True, sanitizesInput=True, checksInputBounds=True, usesSecureFunctions=True,
    usesParameterizedInput=True, encodesOutput=True, implementsCSRFToken=True, verifySessionIdentifiers=True,
    definesConnectionTimeout=True, disablesiFrames=True, implementsNonce=True, encryptsSessionData=True,
    usesStrongSessionIdentifiers=True, encryptsCookies=True, usesMFA=True, implementsPOLP=True,
    handlesResourceConsumption=True, isResilient=True,
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
    "Mobile Banking Backend",
    description=(
        "Retail bank mobile channel. Native apps authenticate with a password "
        "plus a device-bound key pair (registered at enrollment) and app "
        "attestation. Adding a payee and large transfers require step-up "
        "verification by SMS one-time password. The mobile API calls the "
        "core-banking mainframe through an ESB that translates JSON to SOAP/XML "
        "and IBM MQ."
    ),
    isOrdered=True,
    mergeResponses=True,
)
tm.threatsFile = str(THREATS)
tm.assumptions = [
    "The device and the app binary are under the attacker's control (rooted devices, repackaged apps).",
    "TLS certificate pinning and Play Integrity / App Attest are enforced by the API gateway.",
    "The core-banking system is a vendor mainframe that cannot be modified; it trusts the ESB completely.",
    "Regulatory context: PSD2 strong customer authentication, FFIEC authentication guidance.",
]

# --- Trust boundaries ---------------------------------------------------------
device = Boundary("Customer Device")
telco = Boundary("Telco / Push Providers")
dmz = Boundary("Bank DMZ")
mobile_zone = Boundary("Mobile Channel Zone")
core_zone = Boundary("Core Banking Zone")

# --- Actors and external entities --------------------------------------------
customer = Actor("Customer", inBoundary=device, maxClassification=Classification.SECRET)
app = Process(
    "Banking App (iOS / Android)",
    inBoundary=device,
    maxClassification=Classification.SECRET,
    codeType="Managed",
    description="Native app; private key in Secure Enclave / StrongBox; certificate pinning; RASP checks.",
)
apply_controls(app, APP)
for threat_id in ("AA01", "AA02", "AC01", "AC12", "AC13", "AC15"):
    respond(app, threat_id, "accepted: the device is attacker-controllable; every authorization decision is enforced server-side")
respond(app, "CR03", "transferred: passwords are verified server-side by the auth service with rate limiting and lockout")

sms = ExternalEntity(
    "SMS Aggregator",
    inBoundary=telco,
    maxClassification=Classification.RESTRICTED,
    description="Delivers one-time passwords over SMS through mobile carriers.",
)
push = ExternalEntity("APNs / FCM", inBoundary=telco, maxClassification=Classification.RESTRICTED)

# --- Mobile channel -------------------------------------------------------------
gateway = Server(
    "Mobile API Gateway",
    inBoundary=dmz,
    port=443,
    protocol="HTTPS",
    minTLSVersion=TLSVersion.TLSv12,
    maxClassification=Classification.SECRET,
    description="TLS termination, app attestation verification, bot and velocity rules, WAF.",
)
apply_controls(gateway, WEB_SERVICE)

auth = Server(
    "Auth & Device Binding Service",
    inBoundary=mobile_zone,
    port=8443,
    protocol="HTTPS",
    minTLSVersion=TLSVersion.TLSv12,
    maxClassification=Classification.SECRET,
    usesSessionTokens=True,
    description="Password + device-key signature login; issues short-lived access tokens; runs SMS OTP step-up.",
)
apply_controls(auth, WEB_SERVICE, encryptsCookies=True, encryptsSessionData=True)
respond(auth, "CR01", "mitigated: tokens bound to the device key (DPoP-style proof), TLS 1.3 with pinning")

banking_api = Server(
    "Mobile Banking API",
    inBoundary=mobile_zone,
    port=8443,
    protocol="HTTPS",
    minTLSVersion=TLSVersion.TLSv12,
    maxClassification=Classification.SECRET,
    description="Accounts, payees, transfers; calls fraud scoring before submitting postings.",
)
apply_controls(banking_api, WEB_SERVICE)

fraud = Server(
    "Fraud Scoring",
    inBoundary=mobile_zone,
    port=8443,
    protocol="HTTPS",
    minTLSVersion=TLSVersion.TLSv12,
    maxClassification=Classification.SENSITIVE,
    description="Rules + device risk + behavioral signals; returns allow / step-up / block.",
)
apply_controls(fraud, WEB_SERVICE)

customer_db = Datastore(
    "Channel DB",
    inBoundary=mobile_zone,
    port=5432,
    protocol="PostgreSQL/TLS",
    isSQL=True,
    storesPII=True,
    maxClassification=Classification.SENSITIVE,
    description="Device registrations (public keys), payees, channel preferences, OTP attempts.",
)
apply_controls(customer_db, DATASTORE)

# --- Core banking -------------------------------------------------------------------
esb = Server(
    "ESB / SOAP Adapter",
    inBoundary=core_zone,
    port=8443,
    protocol="HTTPS",
    minTLSVersion=TLSVersion.TLSv12,
    maxClassification=Classification.SECRET,
    usesXMLParser=True,
    description="Translates JSON to SOAP/XML; enriches with customer reference data; puts messages on MQ.",
)
# GAP: legacy XML stack with DTD processing enabled (vendor default).
apply_controls(esb, WEB_SERVICE, disablesDTD=False)

core = Server(
    "Core Banking (mainframe)",
    inBoundary=core_zone,
    port=1414,
    protocol="IBM MQ",
    maxClassification=Classification.SECRET,
    description="System of record for accounts and postings; trusts every message from the ESB channel.",
)
apply_controls(core, WEB_SERVICE)

# --- Data -----------------------------------------------------------------------------
password = Data("Password", classification=Classification.SECRET, isCredentials=True, credentialsLife=Lifetime.MANUAL)
device_sig = Data("Device-key signature + attestation", classification=Classification.SENSITIVE)
token = Data("Access token (device-bound)", format="JWT", classification=Classification.SECRET, isCredentials=True, credentialsLife=Lifetime.SHORT)
otp = Data("SMS one-time password", classification=Classification.RESTRICTED, isCredentials=True, credentialsLife=Lifetime.SHORT)
request = Data("Banking request (payee / transfer)", format="JSON", classification=Classification.SENSITIVE, isPII=True)
account = Data("Balances and transactions", format="JSON", classification=Classification.SECRET, isPII=True)
risk = Data("Risk decision", format="JSON", classification=Classification.RESTRICTED)
device_rec = Data("Device registration / payee record", classification=Classification.SENSITIVE, isPII=True, isStored=True)
soap = Data("SOAP request", format="XML", classification=Classification.SECRET, isPII=True)
mq_msg = Data("MQ posting message", classification=Classification.SECRET, isPII=True)
notice = Data("Push notification (no balances)", classification=Classification.RESTRICTED)

# --- Dataflows ---------------------------------------------------------------------------
enter = Dataflow(customer, app, "Enter password / approve", data=[password])
login = Dataflow(app, gateway, "Login (password + device signature)", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13,
                 data=[password, device_sig])
to_auth = Dataflow(gateway, auth, "Forward login", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[password, device_sig])
issue = Dataflow(auth, app, "Access token", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[token])
auth_db = Dataflow(auth, customer_db, "Verify device key / record OTP attempt", data=[device_rec])
send_otp = Dataflow(auth, sms, "Send OTP for new payee / large transfer", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[otp])
deliver_otp = Dataflow(sms, customer, "SMS over carrier network", protocol="SMS", data=[otp])
call = Dataflow(app, gateway, "Banking request + token", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[token, request])
to_api = Dataflow(gateway, banking_api, "Forward request", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[token, request])
score = Dataflow(banking_api, fraud, "Score transfer", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[request])
score_resp = Dataflow(fraud, banking_api, "Risk decision", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[risk], responseTo=score)
payees = Dataflow(banking_api, customer_db, "Read / write payees", data=[device_rec])
to_esb = Dataflow(banking_api, esb, "Account / posting request", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[request])
to_core = Dataflow(esb, core, "SOAP over MQ (no TLS)", protocol="IBM MQ", data=[soap, mq_msg])
from_core = Dataflow(core, esb, "Posting result / statement", protocol="IBM MQ", data=[account], responseTo=to_core)
back = Dataflow(banking_api, app, "Response", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[account])
notify = Dataflow(banking_api, push, "Transaction alert", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[notice])

device_flows = (enter,)
public_flows = (login, issue, send_otp, deliver_otp, call, back, notify)
internal_flows = (to_auth, auth_db, to_api, score, score_resp, payees, to_esb)
legacy_flows = (to_core, from_core)
for flow in device_flows + public_flows + internal_flows + legacy_flows:
    flow.maxClassification = min(flow.source.maxClassification, flow.sink.maxClassification)
    if flow in legacy_flows:
        # GAP: the MQ channel to the mainframe has no TLS and no channel authentication records.
        apply_controls(flow, isEncrypted=False, authenticatesDestination=False, checksDestinationRevocation=False)
    else:
        apply_controls(flow, SECURE_FLOW)
for flow in internal_flows:
    flow.usesVPN = True
for flow in public_flows:
    if flow is not deliver_otp:
        respond(flow, "DE03", "mitigated: TLS 1.3 with certificate pinning in the app and to providers")
respond(enter, "DE03", "accepted: input stays on the device; screen capture is blocked on credential screens")
respond(enter, "AC22", "accepted: password lifetime is governed by the bank's credential policy; device key is the primary factor")
respond(login, "AC22", "mitigated: the password alone is insufficient; login also requires a device-bound key signature")
respond(to_auth, "AC22", "mitigated: the password alone is insufficient; login also requires a device-bound key signature")


if __name__ == "__main__":
    tm.process()
