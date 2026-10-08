#!/usr/bin/env python3
"""IoT device fleet on Azure: provisioning, telemetry, cloud-to-device commands and OTA firmware.

Tens of thousands of smart energy meters connect to Azure IoT Hub over MQTT.
Devices self-enroll through the Device Provisioning Service, stream telemetry
to an event-driven pipeline, receive operator commands (including remote
disconnect), and update firmware over the air from Blob Storage.

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
    "IoT Device Fleet on Azure",
    description=(
        "Smart energy meters connect to Azure IoT Hub over MQTT/TLS after "
        "self-enrollment through the Device Provisioning Service. Telemetry flows "
        "through Event Hubs-compatible endpoints into an Azure Functions pipeline "
        "and Cosmos DB. Utility operators send cloud-to-device commands such as "
        "remote disconnect, and firmware is delivered over the air from Blob "
        "Storage via Device Update for IoT Hub."
    ),
    isOrdered=True,
    mergeResponses=True,
)
tm.threatsFile = str(THREATS)
tm.assumptions = [
    "Devices are physically accessible to attackers (installed on the outside of homes and businesses).",
    "Each device has a unique symmetric key derived from an enrollment-group key during manufacturing.",
    "The device MCU has no secure element; keys are stored in internal flash.",
    "Remote disconnect affects electricity supply to customers and is safety-relevant.",
]

# --- Trust boundaries ---------------------------------------------------------
field = Boundary("Field (customer premises)")
factory = Boundary("Contract Manufacturer")
azure = Boundary("Azure Subscription (prod)")
ingest = Boundary("IoT Ingestion")
ingest.inBoundary = azure
processing = Boundary("Processing & Storage")
processing.inBoundary = azure
corp = Boundary("Utility Operations")

# --- Actors and external entities --------------------------------------------
meter = ExternalEntity(
    "Smart Meter (device fleet)",
    inBoundary=field,
    hasPhysicalAccess=True,
    maxClassification=Classification.SECRET,
    description="ARM Cortex-M MCU, MQTT client, relay for remote disconnect, firmware A/B slots.",
)
manufacturer = ExternalEntity(
    "Manufacturing Line",
    inBoundary=factory,
    maxClassification=Classification.SECRET,
    description="Flashes firmware and injects per-device keys derived from the enrollment-group key.",
)
operator = Actor("Grid Operator", inBoundary=corp, maxClassification=Classification.SENSITIVE)
fw_engineer = Actor("Firmware Engineer", inBoundary=corp, maxClassification=Classification.SENSITIVE)

# --- Ingestion -------------------------------------------------------------------
dps = Server(
    "Device Provisioning Service",
    inBoundary=ingest,
    port=8883,
    protocol="MQTT/TLS",
    minTLSVersion=TLSVersion.TLSv12,
    maxClassification=Classification.SECRET,
    description="Enrollment group with symmetric-key attestation; assigns devices to an IoT Hub.",
)
apply_controls(dps, WEB_SERVICE)

hub = Server(
    "Azure IoT Hub",
    inBoundary=ingest,
    port=8883,
    protocol="MQTT/TLS",
    minTLSVersion=TLSVersion.TLSv12,
    maxClassification=Classification.SECRET,
    description="Per-device identities, device twins, direct methods, message routing.",
)
apply_controls(hub, WEB_SERVICE)

# --- Processing -------------------------------------------------------------------
telemetry_fn = Lambda(
    "Telemetry Function",
    inBoundary=processing,
    maxClassification=Classification.SENSITIVE,
    isCloudWorkload=True,
    isEventTriggered=True,
    hasAuditLogging=True,
    usesEnvironmentVariables=True,
    description="Parses device payloads, detects tamper/outage events, writes readings.",
)
# GAP: authenticates to IoT Hub with the 'iothubowner' connection string (registry write + service connect).
apply_controls(telemetry_fn, FUNCTION, implementsPOLP=False)

command_api = Server(
    "Operations Portal & Command API",
    inBoundary=processing,
    port=443,
    protocol="HTTPS",
    minTLSVersion=TLSVersion.TLSv12,
    maxClassification=Classification.SENSITIVE,
    isCloudWorkload=True,
    hasAuditLogging=True,
    usesSessionTokens=True,
    description="Entra ID SSO; fleet views; invokes direct methods (reboot, disconnect, reconnect) on devices.",
)
# GAP: one 'Operator' role can disconnect any number of meters in a single bulk action.
apply_controls(command_api, WEB_SERVICE, encryptsCookies=True, encryptsSessionData=True, handlesResourceConsumption=False)
respond(command_api, "CR01", "mitigated: Entra ID session cookies (Secure, HttpOnly) with Conditional Access")

readings = Datastore(
    "Cosmos DB (readings & events)",
    inBoundary=processing,
    isSQL=False,
    storesPII=True,
    maxClassification=Classification.SENSITIVE,
    hasAuditLogging=True,
    description="Interval readings (reveal occupancy patterns), tamper and outage events.",
)
apply_controls(readings, DATASTORE)

firmware_store = Datastore(
    "Blob Storage (firmware images)",
    inBoundary=processing,
    isSQL=False,
    maxClassification=Classification.RESTRICTED,
    isObjectStorage=True,
    # GAP: container set to anonymous blob read so devices can fetch images without SAS tokens.
    blocksPublicAccess=False,
    hasAuditLogging=True,
    description="Signed firmware images and update manifests.",
)
apply_controls(firmware_store, DATASTORE)

build = Server(
    "Firmware Build & Signing Pipeline",
    inBoundary=corp,
    port=443,
    protocol="HTTPS",
    maxClassification=Classification.SECRET,
    isBuildSystem=True,
    description="Azure DevOps pipeline; signs images with a key in Azure Key Vault Managed HSM.",
)
apply_controls(build, WEB_SERVICE)

# --- Data ----------------------------------------------------------------------------
device_key = Data(
    "Per-device symmetric key", classification=Classification.SECRET, isCredentials=True, credentialsLife=Lifetime.HARDCODED
)
enroll = Data("Registration request (SAS token from device key)", classification=Classification.SENSITIVE)
assignment = Data("Hub assignment + device identity", classification=Classification.RESTRICTED)
telemetry = Data("Interval readings, tamper flags", format="JSON", classification=Classification.SENSITIVE, isPII=True)
reading_rows = Data("Readings and events", classification=Classification.SENSITIVE, isPII=True, isStored=True)
command = Data("Direct method (disconnect / reconnect / reboot)", format="JSON", classification=Classification.SENSITIVE)
hub_conn = Data("IoT Hub connection string (iothubowner)", classification=Classification.SECRET, isCredentials=True, credentialsLife=Lifetime.MANUAL)
image = Data("Signed firmware image + manifest", classification=Classification.RESTRICTED, isStored=True)
image_dl = Data("Firmware download", classification=Classification.RESTRICTED)
sso = Data("Entra ID session", classification=Classification.SENSITIVE, isCredentials=True, credentialsLife=Lifetime.SHORT)

# --- Dataflows ------------------------------------------------------------------------
inject = Dataflow(manufacturer, meter, "Flash firmware + inject device key", protocol="JTAG/SWD", data=[device_key])
register = Dataflow(meter, dps, "Register (symmetric-key attestation)", protocol="MQTT/TLS", tlsVersion=TLSVersion.TLSv12, data=[enroll])
assigned = Dataflow(dps, meter, "Assigned hub + identity", protocol="MQTT/TLS", tlsVersion=TLSVersion.TLSv12, data=[assignment], responseTo=register)
publish = Dataflow(meter, hub, "Publish telemetry (MQTT)", protocol="MQTT/TLS", tlsVersion=TLSVersion.TLSv12, data=[telemetry])
route = Dataflow(hub, telemetry_fn, "Route messages (built-in endpoint)", protocol="AMQP/TLS", tlsVersion=TLSVersion.TLSv12, data=[telemetry])
store = Dataflow(telemetry_fn, readings, "Write readings / events", data=[reading_rows])
fn_creds = Dataflow(telemetry_fn, hub, "Update device twins (iothubowner)", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[hub_conn])
login = Dataflow(operator, command_api, "SSO + fleet operations", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[sso, command])
query = Dataflow(command_api, readings, "Query readings", data=[reading_rows])
invoke = Dataflow(command_api, hub, "Invoke direct method", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[command])
deliver = Dataflow(hub, meter, "Cloud-to-device command", protocol="MQTT/TLS", tlsVersion=TLSVersion.TLSv12, data=[command])
commit = Dataflow(fw_engineer, build, "Commit firmware source", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13)
publish_fw = Dataflow(build, firmware_store, "Upload signed image", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[image])
download = Dataflow(firmware_store, meter, "Download firmware (OTA)", protocol="HTTPS", tlsVersion=TLSVersion.TLSv12, data=[image_dl])

field_flows = (register, assigned, publish, deliver, download)
internal_flows = (route, store, fn_creds, query, invoke, publish_fw)
corp_flows = (login, commit)
for flow in (inject,) + field_flows + internal_flows + corp_flows:
    flow.maxClassification = min(flow.source.maxClassification, flow.sink.maxClassification)
    apply_controls(flow, SECURE_FLOW)
for flow in internal_flows:
    flow.usesVPN = True  # Private Endpoints / Azure backbone
for flow in field_flows + corp_flows:
    respond(flow, "DE03", "mitigated: TLS 1.2+ with server certificate validation (cellular APN for meters)")
respond(inject, "DE03", "mitigated: keys injected on an isolated provisioning station inside the factory")
respond(inject, "AC22", "accepted: device keys cannot be rotated in the field on this hardware; tracked in the README as M2")
respond(fn_creds, "AC22", "accepted: tracked as CLD02 - replace with managed identity and a scoped role")
respond(meter, "HA02", "accepted: attackers can buy or remove a meter and read out its firmware; no secrets may depend on firmware secrecy")
respond(meter, "HA04", "accepted: firmware reverse engineering is assumed; security relies on per-device keys and signed updates")


if __name__ == "__main__":
    tm.process()
