#!/usr/bin/env python3
"""E-commerce checkout with a tokenizing payment provider (PCI DSS v4.0, SAQ A-EP scope).

Card data is entered into the payment provider's hosted fields (iframes) and
never touches merchant servers. The merchant still owns the page that hosts
those iframes, which is why script integrity (PCI DSS 6.4.3 / 11.6.1) matters.

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

# Control profiles: the hardened baseline each element type starts from.
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
    "E-commerce Checkout with Tokenized Payments",
    description=(
        "Direct-to-consumer storefront. Shoppers build a cart and check out; card "
        "details are captured by the payment provider's hosted fields and exchanged "
        "for a single-use token. The merchant confirms payment through signed "
        "webhooks before fulfilling the order."
    ),
    isOrdered=True,
    mergeResponses=True,
)
tm.threatsFile = str(THREATS)
tm.assumptions = [
    "PAN, CVV and expiry are entered only into provider-hosted iframes (SAQ A-EP scope).",
    "Prices, discounts and totals are always recalculated server-side from catalog data.",
    "Order state changes to PAID only on a verified payment webhook, never on a client redirect.",
    "Back-office access requires corporate SSO with phishing-resistant MFA (FIDO2).",
]

# --- Trust boundaries ---------------------------------------------------------
internet = Boundary("Internet")
psp_boundary = Boundary("Payment Provider")
saas = Boundary("Third-party SaaS")
edge = Boundary("Edge / CDN")
app = Boundary("Commerce VPC")
cde = Boundary("Data Tier")
cde.inBoundary = app
corp = Boundary("Corporate Network")

# --- Actors -------------------------------------------------------------------
shopper = Actor("Shopper", inBoundary=internet, maxClassification=Classification.TOP_SECRET)
ops = Actor("Back-office Operator", inBoundary=corp, isAdmin=True, maxClassification=Classification.SENSITIVE)

checkout_page = Process(
    "Checkout Page (browser)",
    inBoundary=internet,
    maxClassification=Classification.SECRET,
    allowsClientSideScripting=True,
    codeType="Managed",
    description="Merchant page embedding provider hosted fields plus first- and third-party scripts.",
)
apply_controls(
    checkout_page,
    validatesInput=True, sanitizesInput=True, encodesOutput=True, checksInputBounds=True,
    usesSecureFunctions=True, implementsCSRFToken=True, verifySessionIdentifiers=True,
    definesConnectionTimeout=True, usesStrongSessionIdentifiers=True, encryptsCookies=True,
    implementsPOLP=True, handlesResourceConsumption=True, isResilient=True, implementsNonce=True,
    disablesiFrames=True,  # CSP frame-ancestors 'none' on the checkout page itself
    # GAP: CSP allows the marketing tag manager to load scripts from arbitrary origins,
    # and there is no script inventory or change detection (PCI DSS 6.4.3 / 11.6.1).
    providesIntegrity=False,
)
respond(checkout_page, "CR03", "transferred: account passwords are verified by the storefront (rate limits, breached-password screening)")
for threat_id in ("AA01", "AA02", "AC01", "AC12", "AC13"):
    respond(checkout_page, threat_id, "accepted: the browser is untrusted; pricing, authorization and payment state are enforced server-side")

psp = ExternalEntity(
    "Payment Provider (hosted fields + API)",
    inBoundary=psp_boundary,
    maxClassification=Classification.TOP_SECRET,
    description="PCI DSS Level 1 provider. Tokenizes cards, runs 3-D Secure, sends signed webhooks.",
)
tag_manager = ExternalEntity(
    "Marketing Tag Manager",
    inBoundary=saas,
    maxClassification=Classification.PUBLIC,
    description="Third-party analytics and advertising scripts loaded on every page.",
)
email = ExternalEntity(
    "Transactional Email Service",
    inBoundary=saas,
    maxClassification=Classification.RESTRICTED,
)

# --- Edge and application -------------------------------------------------------
cdn = Server(
    "CDN + WAF + Bot Management",
    inBoundary=edge,
    port=443,
    protocol="HTTPS",
    minTLSVersion=TLSVersion.TLSv12,
    maxClassification=Classification.SENSITIVE,
)
apply_controls(cdn, WEB_SERVICE, authenticatesSource=False, hasAccessControl=False, authorizesSource=False)
for threat_id, why in {
    "AA01": "transferred: shopper sessions are authenticated by the storefront",
    "AA02": "transferred: principal established by the storefront session",
    "AA03": "transferred: credential checks happen in the storefront",
    "AC01": "transferred: privileges are evaluated by the order service",
    "AC06": "mitigated: no upload endpoints exposed; WAF blocks multipart bodies",
    "AC07": "transferred: access control is enforced by origin services",
    "AC08": "accepted: managed CDN, no registry exposed",
    "AC09": "transferred: business-logic limits live in the order service",
    "SC03": "transferred: authorization is enforced downstream; WAF filters script payloads",
}.items():
    respond(cdn, threat_id, why)

storefront = Server(
    "Storefront (SSR web app)",
    inBoundary=app,
    port=8443,
    protocol="HTTPS",
    minTLSVersion=TLSVersion.TLSv12,
    maxClassification=Classification.SENSITIVE,
    usesSessionTokens=True,
    usesCache=True,
    description="Server-side rendered catalog, cart and checkout pages; guest and account sessions.",
)
apply_controls(storefront, WEB_SERVICE, encryptsCookies=True, encryptsSessionData=True)
respond(storefront, "CR01", "mitigated: Secure/HttpOnly/SameSite=Lax cookies, HSTS preload, session rotation at login and checkout")
respond(storefront, "DS05", "mitigated: CDN and app caches vary on session; Cache-Control: no-store on cart, checkout and account pages")

orders = Server(
    "Order & Pricing Service",
    inBoundary=app,
    port=8443,
    protocol="HTTPS",
    minTLSVersion=TLSVersion.TLSv12,
    maxClassification=Classification.SECRET,  # holds the provider API key via secrets manager
    description="Recalculates totals, applies promotions, reserves inventory, creates payment intents.",
)
# GAP: no velocity limits on payment-intent creation or coupon redemption (card testing, coupon abuse).
apply_controls(orders, WEB_SERVICE, handlesResourceConsumption=False)

webhooks = Server(
    "Payment Webhook Receiver",
    inBoundary=app,
    port=8443,
    protocol="HTTPS",
    minTLSVersion=TLSVersion.TLSv12,
    maxClassification=Classification.SENSITIVE,
    description="Verifies provider HMAC signatures and transitions orders to PAID / FAILED / REFUNDED.",
)
# GAP: signature verified, but no timestamp tolerance or event-ID de-duplication (replay).
apply_controls(webhooks, WEB_SERVICE, implementsNonce=False)

backoffice = Server(
    "Back-office Portal",
    inBoundary=corp,
    port=443,
    protocol="HTTPS",
    minTLSVersion=TLSVersion.TLSv12,
    maxClassification=Classification.SECRET,  # holds a refund-scoped provider key
    usesSessionTokens=True,
    description="Order lookup, refunds and promotions for staff, behind corporate SSO.",
)
# GAP: refunds of any amount by any operator; no dual control above a threshold.
apply_controls(backoffice, WEB_SERVICE, encryptsCookies=True, encryptsSessionData=True, implementsPOLP=False)
respond(backoffice, "CR01", "mitigated: SSO session cookies are Secure/HttpOnly; portal reachable only via ZTNA")

order_db = Datastore(
    "Orders DB (PostgreSQL)",
    inBoundary=cde,
    port=5432,
    protocol="PostgreSQL/TLS",
    isSQL=True,
    storesPII=True,
    storesSensitiveData=True,
    maxClassification=Classification.SENSITIVE,
    description="Orders, addresses, payment token references and last4. No PAN or CVV.",
)
apply_controls(order_db, DATASTORE)

# --- Data ---------------------------------------------------------------------
card_data = Data(
    "Card data (PAN, expiry, CVV)",
    classification=Classification.TOP_SECRET,
    isCredentials=True,
    credentialsLife=Lifetime.LONG,
)
payment_token = Data("Single-use payment token", classification=Classification.SENSITIVE, isCredentials=True, credentialsLife=Lifetime.SHORT)
cart = Data("Cart, address, promo code", format="JSON", classification=Classification.SENSITIVE, isPII=True)
session = Data("Session cookie", classification=Classification.SENSITIVE, isCredentials=True, credentialsLife=Lifetime.AUTO)
intent = Data("Payment intent (amount, currency, idempotency key)", format="JSON", classification=Classification.RESTRICTED)
api_key = Data("Provider secret API key", classification=Classification.SECRET, isCredentials=True, credentialsLife=Lifetime.MANUAL)
webhook_event = Data("Signed webhook event", format="JSON", classification=Classification.RESTRICTED)
order_record = Data("Order record", format="JSON", classification=Classification.SENSITIVE, isPII=True, isStored=True)
receipt = Data("Receipt (name, items, last4)", classification=Classification.RESTRICTED, isPII=True)
scripts = Data("Third-party JavaScript", classification=Classification.PUBLIC)

# --- Dataflows -------------------------------------------------------------------
browse = Dataflow(shopper, cdn, "Browse / add to cart", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[cart, session])
to_store = Dataflow(cdn, storefront, "Forward to origin", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[cart, session])
load_tags = Dataflow(tag_manager, checkout_page, "Load marketing scripts", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[scripts])
enter_card = Dataflow(
    shopper, psp, "Enter card in hosted fields (iframe)", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[card_data]
)
token_back = Dataflow(psp, checkout_page, "Payment token + 3DS result", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[payment_token])
place_order = Dataflow(
    checkout_page, cdn, "POST /checkout (token + cart)", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13,
    data=[payment_token, cart, session],
)
to_orders = Dataflow(storefront, orders, "Create order", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[payment_token, cart])
create_intent = Dataflow(
    orders, psp, "Create / confirm payment intent", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13,
    data=[intent, payment_token, api_key],
)
webhook = Dataflow(psp, webhooks, "payment_intent.succeeded webhook", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[webhook_event])
mark_paid = Dataflow(webhooks, order_db, "Mark order PAID", data=[order_record])
save_order = Dataflow(orders, order_db, "Persist order (PENDING)", data=[order_record])
send_receipt = Dataflow(orders, email, "Send receipt", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[receipt])
staff = Dataflow(ops, backoffice, "Search orders / issue refund", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[order_record])
bo_db = Dataflow(backoffice, order_db, "Read / update orders", data=[order_record])
refund = Dataflow(backoffice, psp, "Refund via provider API", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[intent, api_key])

public_flows = (browse, load_tags, enter_card, token_back, place_order, create_intent, webhook, send_receipt, refund)
private_flows = (to_store, to_orders, mark_paid, save_order, staff, bo_db)

for flow in public_flows + private_flows:
    flow.maxClassification = min(flow.source.maxClassification, flow.sink.maxClassification)
    if flow is load_tags:
        # Third-party scripts are fetched unauthenticated and run with full page privileges.
        apply_controls(flow, SECURE_FLOW, implementsAuthenticationScheme=False, authorizesSource=False, providesIntegrity=False)
    else:
        apply_controls(flow, SECURE_FLOW)
for flow in private_flows:
    flow.usesVPN = True
for flow in public_flows:
    respond(flow, "DE03", "mitigated: TLS 1.2+ (1.3 preferred) with HSTS; a VPN is not applicable to public or SaaS endpoints")

respond(enter_card, "AC22", "transferred: card data is captured and vaulted by the PCI DSS Level 1 provider; the merchant never stores it")
respond(create_intent, "AC22", "mitigated: restricted API key scoped to PaymentIntents, stored in a secrets manager, rotated every 90 days")
respond(refund, "AC22", "mitigated: separate restricted key with refund scope only; rotated every 90 days")


if __name__ == "__main__":
    tm.process()
