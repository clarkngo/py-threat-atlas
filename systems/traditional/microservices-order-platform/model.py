#!/usr/bin/env python3
"""Microservices order platform: API gateway, service mesh, Kafka event bus and saga orchestration.

A retailer's monolith was split into independently deployed services on a
self-managed Kubernetes cluster in the company data center. Services talk
synchronously through an Istio mesh and asynchronously through Kafka; the
order workflow is a saga coordinated by an orchestrator.

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


def service(name, description, maxClassification=Classification.SENSITIVE, **controls):
    """A mesh-enrolled microservice with the hardened web-service baseline."""
    element = Server(
        name,
        inBoundary=mesh,
        port=8080,
        protocol="HTTPS (mTLS)",
        minTLSVersion=TLSVersion.TLSv12,
        maxClassification=maxClassification,
        description=description,
    )
    apply_controls(element, WEB_SERVICE, **controls)
    return element


def database(name, description, **attributes):
    element = Datastore(
        name,
        inBoundary=data,
        isSQL=True,
        storesPII=attributes.pop("storesPII", False),
        maxClassification=Classification.SENSITIVE,
        description=description,
        **attributes,
    )
    apply_controls(element, DATASTORE)
    return element


tm = TM(
    "Microservices Order Platform",
    description=(
        "Order management decomposed into microservices on a self-managed "
        "Kubernetes cluster. An API gateway validates customer JWTs and routes "
        "to services in an Istio mesh (mTLS, SPIFFE identities). The order saga "
        "is coordinated by an orchestrator over Kafka: reserve inventory, "
        "authorize payment, confirm order, notify the customer. Each service "
        "owns its database; secrets come from HashiCorp Vault."
    ),
    isOrdered=True,
    mergeResponses=True,
)
tm.threatsFile = str(THREATS)
tm.assumptions = [
    "The cluster runs in the company data center; the mesh enforces STRICT mTLS for enrolled workloads.",
    "Customers authenticate with the corporate CIAM; the gateway validates JWT signature, issuer, audience and expiry.",
    "Each service has its own database and credentials, issued dynamically by Vault.",
    "The legacy pricing service has not been migrated into the mesh yet.",
]

# --- Trust boundaries ---------------------------------------------------------
internet = Boundary("Internet")
dmz = Boundary("DMZ")
cluster = Boundary("Kubernetes Cluster")
mesh = Boundary("Service Mesh (mTLS)")
mesh.inBoundary = cluster
data = Boundary("Data Services")
# Data services sit beside the mesh (not nested) so the DFD has room for their flows.
legacy_zone = Boundary("Legacy VLAN")
partners = Boundary("Third Parties")

# --- Actors and external entities --------------------------------------------
customer = Actor("Customer (web / mobile)", inBoundary=internet, maxClassification=Classification.SENSITIVE)
psp = ExternalEntity("Payment Gateway", inBoundary=partners, maxClassification=Classification.SECRET)
email = ExternalEntity("Email / SMS Provider", inBoundary=partners, maxClassification=Classification.RESTRICTED)

# --- Edge -----------------------------------------------------------------------
gateway = Server(
    "API Gateway (Kong)",
    inBoundary=dmz,
    port=443,
    protocol="HTTPS",
    minTLSVersion=TLSVersion.TLSv12,
    maxClassification=Classification.SENSITIVE,
    description="JWT validation, rate limits, routing; injects X-User-Id / X-Roles headers for upstream services.",
)
apply_controls(gateway, WEB_SERVICE)

# --- Services ---------------------------------------------------------------------
orders = service(
    "Order Service",
    "Order API and read models. Trusts X-User-Id from the gateway to scope queries.",
    # GAP: accepts identity headers from any in-mesh caller, not only the gateway (no AuthorizationPolicy
    # restricting who may set them), so any compromised service can act as any customer.
    authenticatesSource=False,
)
saga = service(
    "Order Saga Orchestrator",
    "Drives reserve -> authorize -> confirm, with compensations on failure. Consumes and produces Kafka events.",
)
inventory = service("Inventory Service", "Stock reservations with TTL; compensating release on saga failure.")
payment = service(
    "Payment Service",
    "Authorizes and captures via the payment gateway using tokens; never sees PAN.",
    maxClassification=Classification.SECRET,  # holds the gateway API key
)
notify = service(
    "Notification Service",
    "Renders email/SMS templates from order events and sends them through the provider.",
)

pricing = Server(
    "Legacy Pricing Service",
    inBoundary=legacy_zone,
    port=8080,
    protocol="HTTP",
    maxClassification=Classification.RESTRICTED,
    description="Java monolith module on a VM; not mesh-enrolled; plaintext HTTP; no service authentication.",
)
# GAP: plaintext, unauthenticated, unpatched JVM; reachable from the whole VLAN.
apply_controls(
    pricing, WEB_SERVICE,
    isEncrypted=False, authenticatesSource=False, implementsAuthenticationScheme=False, isHardened=False,
)

# --- Data services ------------------------------------------------------------------
kafka = Datastore(
    "Kafka Event Bus",
    inBoundary=data,
    port=9093,
    protocol="Kafka/TLS",
    isSQL=False,
    isShared=True,
    maxClassification=Classification.SENSITIVE,
    description="Topics: order.*, inventory.*, payment.*. TLS listeners.",
)
# GAP: TLS but no per-topic ACLs; any client certificate from the cluster CA can produce to any topic.
apply_controls(kafka, DATASTORE, hasAccessControl=False, authorizesSource=False)

order_db = database("Order DB", "Orders, line items, shipping addresses.", storesPII=True)
inventory_db = database("Inventory DB", "Stock levels and reservations.")
payment_db = database("Payment DB", "Payment intents, gateway references, idempotency keys.")
vault = Datastore(
    "HashiCorp Vault",
    inBoundary=data,
    port=8200,
    protocol="HTTPS",
    isSQL=False,
    maxClassification=Classification.SECRET,
    description="Dynamic DB credentials and gateway API keys via Kubernetes auth.",
)
apply_controls(vault, DATASTORE)

# --- Data ---------------------------------------------------------------------------
jwt = Data("Customer JWT", format="JWT", classification=Classification.SENSITIVE, isCredentials=True, credentialsLife=Lifetime.SHORT)
order_req = Data("Order request (items, address)", format="JSON", classification=Classification.SENSITIVE, isPII=True)
identity = Data("Identity headers (X-User-Id, X-Roles)", classification=Classification.SENSITIVE)
price_quote = Data("Price quote", format="JSON", classification=Classification.RESTRICTED)
event = Data("Domain event (OrderPlaced, PaymentAuthorized, ...)", format="JSON", classification=Classification.SENSITIVE)
order_row = Data("Order record", classification=Classification.SENSITIVE, isPII=True, isStored=True)
stock_row = Data("Reservation record", classification=Classification.RESTRICTED, isStored=True)
payment_row = Data("Payment record", classification=Classification.SENSITIVE, isStored=True)
pay_token = Data("Payment token + amount", format="JSON", classification=Classification.SENSITIVE)
db_creds = Data("Dynamic DB credentials", classification=Classification.SECRET, isCredentials=True, credentialsLife=Lifetime.SHORT)
message = Data("Rendered email / SMS", classification=Classification.RESTRICTED, isPII=True)

# --- Dataflows ------------------------------------------------------------------------
place = Dataflow(customer, gateway, "POST /orders (JWT)", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[jwt, order_req])
route = Dataflow(gateway, orders, "Route + identity headers", protocol="HTTPS (mTLS)", tlsVersion=TLSVersion.TLSv13, data=[order_req, identity])
quote = Dataflow(orders, pricing, "GET /price (plaintext)", protocol="HTTP", data=[price_quote])
save_order = Dataflow(orders, order_db, "Insert order (PENDING)", data=[order_row])
placed = Dataflow(orders, kafka, "Publish OrderPlaced", data=[event])
to_saga = Dataflow(kafka, saga, "Consume order.* / payment.* / inventory.*", tlsVersion=TLSVersion.TLSv13, data=[event])
reserve = Dataflow(saga, inventory, "Reserve stock", protocol="HTTPS (mTLS)", tlsVersion=TLSVersion.TLSv13, data=[order_req])
reserve_db = Dataflow(inventory, inventory_db, "Write reservation", data=[stock_row])
authorize = Dataflow(saga, payment, "Authorize payment", protocol="HTTPS (mTLS)", tlsVersion=TLSVersion.TLSv13, data=[pay_token])
charge = Dataflow(payment, psp, "Authorize / capture", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[pay_token])
pay_db = Dataflow(payment, payment_db, "Write payment record", data=[payment_row])
paid = Dataflow(payment, kafka, "Publish PaymentAuthorized", data=[event])
confirmed = Dataflow(saga, kafka, "Publish OrderConfirmed / compensations", data=[event])
to_notify = Dataflow(kafka, notify, "Consume order.confirmed", tlsVersion=TLSVersion.TLSv13, data=[event])
send = Dataflow(notify, email, "Send confirmation", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[message])
creds = Dataflow(vault, payment, "Lease DB creds + gateway key", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[db_creds])

external_flows = (place, charge, send)
internal_flows = (
    route, quote, save_order, placed, to_saga, reserve, reserve_db, authorize, pay_db, paid, confirmed, to_notify, creds,
)
for flow in external_flows + internal_flows:
    flow.maxClassification = min(flow.source.maxClassification, flow.sink.maxClassification)
    if flow is quote:
        apply_controls(flow, authenticatesDestination=False, checksDestinationRevocation=False)  # plaintext HTTP
    else:
        apply_controls(flow, SECURE_FLOW)
for flow in internal_flows:
    if flow is not quote:
        flow.usesVPN = True  # mesh mTLS inside the cluster
for flow in external_flows:
    respond(flow, "DE03", "mitigated: TLS 1.2+ with certificate validation to customers and providers")
respond(creds, "AC22", "mitigated: Vault dynamic credentials with 1h TTL, revoked on pod termination")


if __name__ == "__main__":
    tm.process()
