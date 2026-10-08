#!/usr/bin/env python3
"""SaaS login with OAuth 2.0 / OpenID Connect through an external identity provider.

Pattern: Backend-for-Frontend (BFF). The browser SPA never holds OAuth tokens;
the BFF runs the Authorization Code + PKCE flow as a confidential client and
gives the browser only an HttpOnly, SameSite session cookie.

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


def apply_controls(element, **flags):
    """Set pytm control flags on an element (pytm resets controls in __init__)."""
    for name, value in flags.items():
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
    "SaaS Login with OAuth 2.0 / OIDC",
    description=(
        "Multi-tenant B2B SaaS web application. Users authenticate through an "
        "external OpenID Connect identity provider using Authorization Code + "
        "PKCE. A Backend-for-Frontend exchanges the code for tokens, stores them "
        "server-side, and issues an opaque session cookie to the browser SPA."
    ),
    isOrdered=True,
    mergeResponses=True,
)
tm.threatsFile = str(THREATS)
tm.assumptions = [
    "The identity provider is a SOC 2 Type II certified SaaS IdP; MFA is enforced by tenant policy.",
    "Public endpoints sit behind a CDN/WAF that terminates TLS 1.3 with HSTS preload.",
    "Tenant ID is derived only from verified ID-token claims, never from request parameters.",
    "No XML is parsed anywhere in this system (OIDC only, no SAML).",
]

# --- Trust boundaries ---------------------------------------------------------
internet = Boundary("Internet")
idp_boundary = Boundary("Identity Provider")
edge = Boundary("Edge / DMZ")
app_vpc = Boundary("Application VPC")
data_tier = Boundary("Data Tier")
data_tier.inBoundary = app_vpc

# --- Actors and external entities --------------------------------------------
user = Actor("End User", inBoundary=internet, maxClassification=Classification.SECRET)
admin = Actor("Tenant Admin", inBoundary=internet, isAdmin=True, maxClassification=Classification.SECRET)

idp = ExternalEntity(
    "OIDC Identity Provider",
    inBoundary=idp_boundary,
    maxClassification=Classification.SECRET,
    description="Hosted IdP (e.g. Okta, Entra ID, Auth0) issuing signed ID and access tokens.",
)

spa = Process(
    "SPA (browser)",
    inBoundary=internet,
    maxClassification=Classification.SECRET,
    allowsClientSideScripting=True,
    codeType="Managed",
    description="React single-page app. Holds no tokens; relies on the session cookie.",
)
apply_controls(
    spa,
    validatesInput=True,
    sanitizesInput=True,  # framework auto-escaping + DOMPurify for rich text
    encodesOutput=True,
    checksInputBounds=True,
    usesSecureFunctions=True,
    disablesiFrames=True,  # CSP frame-ancestors 'none'
    implementsCSRFToken=True,
    verifySessionIdentifiers=True,
    definesConnectionTimeout=True,
    usesStrongSessionIdentifiers=True,
    encryptsCookies=True,
    implementsPOLP=True,
    handlesResourceConsumption=True,
    isResilient=True,
)

for threat_id in ("AA01", "AA02", "AC01", "AC12", "AC13"):
    respond(spa, threat_id, "accepted: the browser is untrusted; all authentication and authorization is enforced server-side")
respond(spa, "CR03", "transferred: the SPA never handles passwords; credentials are entered only at the IdP")

# --- Edge --------------------------------------------------------------------
gateway = Server(
    "API Gateway + WAF",
    inBoundary=edge,
    port=443,
    protocol="HTTPS",
    minTLSVersion=TLSVersion.TLSv12,
    maxClassification=Classification.SECRET,
    description="Managed WAF (OWASP CRS), rate limiting, request size limits, TLS termination.",
)
apply_controls(
    gateway,
    isEncrypted=True,
    isHardened=True,
    validatesInput=True,
    sanitizesInput=True,
    encodesOutput=True,
    validatesHeaders=True,
    validatesContentType=True,
    invokesScriptFilters=True,
    implementsStrictHTTPValidation=True,
    encodesHeaders=True,
    checksInputBounds=True,
    handlesResourceConsumption=True,
    isResilient=True,
    authenticatesDestination=True,
    checksDestinationRevocation=True,
    usesEncryptionAlgorithm="AES",
    # The gateway forwards to the BFF, which owns authentication and authorization.
    authenticatesSource=False,
    hasAccessControl=False,
    authorizesSource=False,
)
respond(gateway, "AA01", "transferred: authentication is enforced by the BFF on every route except /login and /callback")
respond(gateway, "AA02", "transferred: principal is established by the BFF from the IdP-signed ID token")
respond(gateway, "AA03", "transferred: session validation happens in the BFF; gateway only forwards")
respond(gateway, "AC06", "mitigated: no file upload endpoints; WAF blocks multipart bodies on auth routes")
respond(gateway, "AC07", "transferred: route-level authorization lives in the BFF and API")
respond(gateway, "AC08", "accepted: managed gateway, no host registry exposed")
respond(gateway, "AC09", "transferred: business-logic authorization lives in the API")
respond(gateway, "AA04", "transferred: server-side validation is performed by the BFF and API")
respond(gateway, "SC03", "transferred: authorization is enforced downstream; WAF managed rules filter script payloads")
respond(gateway, "AC11", "transferred: session identifiers are issued and verified by the BFF")
respond(gateway, "AC16", "transferred: session identifiers are 256-bit CSPRNG values issued by the BFF")
respond(gateway, "AC17", "transferred: server-side sessions live in the BFF and are rotated on login")
respond(gateway, "CR03", "transferred: passwords are verified only by the IdP (breached-password checks, lockout, MFA)")
respond(gateway, "AC01", "transferred: privileges are evaluated by the BFF and API")
respond(gateway, "SC05", "accepted: managed service; client integrity is covered by SRI + CSP on the SPA")

# --- Application tier --------------------------------------------------------
bff = Server(
    "BFF / Auth Service",
    inBoundary=app_vpc,
    port=8443,
    protocol="HTTPS",
    minTLSVersion=TLSVersion.TLSv12,
    maxClassification=Classification.SECRET,
    usesSessionTokens=True,
    description=(
        "Confidential OIDC client. Generates state, nonce and PKCE verifier; "
        "validates ID tokens (iss, aud, exp, nonce, signature via JWKS); maps the "
        "session cookie to server-side tokens; rotates session ID on login."
    ),
)
apply_controls(
    bff,
    isEncrypted=True,
    isHardened=True,
    authenticatesSource=True,
    authenticatesDestination=True,
    checksDestinationRevocation=True,
    implementsAuthenticationScheme=True,
    authorizesSource=True,
    hasAccessControl=True,
    implementsNonce=True,
    usesStrongSessionIdentifiers=True,
    encryptsSessionData=True,
    encryptsCookies=True,
    validatesInput=True,
    sanitizesInput=True,
    encodesOutput=True,
    validatesHeaders=True,
    validatesContentType=True,
    invokesScriptFilters=True,
    implementsServerSideValidation=True,
    implementsStrictHTTPValidation=True,
    encodesHeaders=True,
    providesIntegrity=True,
    checksInputBounds=True,
    usesMFA=True,
    implementsPOLP=True,
    isResilient=True,
    usesEncryptionAlgorithm="AES",
    # GAP: no per-account / per-IP throttling of /callback and /token beyond edge limits.
    handlesResourceConsumption=False,
    # GAP: container images are not signed or verified at deploy.
    usesCodeSigning=False,
)
respond(bff, "CR01", "mitigated: cookie is __Host- prefixed, Secure, HttpOnly, SameSite=Lax; TLS 1.3 + HSTS preload; session ID rotated on login")

app_api = Server(
    "Tenant Application API",
    inBoundary=app_vpc,
    port=8443,
    protocol="HTTPS",
    minTLSVersion=TLSVersion.TLSv12,
    maxClassification=Classification.SECRET,
    description="Business API. Authorizes every request against tenant and role claims.",
)
apply_controls(
    app_api,
    isEncrypted=True,
    isHardened=True,
    authenticatesSource=True,  # mTLS from the BFF + validated access token
    authorizesSource=True,
    hasAccessControl=True,
    implementsAuthenticationScheme=True,
    validatesInput=True,
    sanitizesInput=True,
    encodesOutput=True,
    validatesHeaders=True,
    validatesContentType=True,
    invokesScriptFilters=True,
    implementsServerSideValidation=True,
    usesStrongSessionIdentifiers=True,
    providesIntegrity=True,
    checksInputBounds=True,
    implementsPOLP=True,
    handlesResourceConsumption=True,
    isResilient=True,
    usesEncryptionAlgorithm="AES",
    # GAP: HTTP/1.1 between gateway and API without strict parsing (desync risk).
    implementsStrictHTTPValidation=False,
    encodesHeaders=False,
    usesCodeSigning=False,
)

# --- Data tier ---------------------------------------------------------------
session_store = Datastore(
    "Session Store (Redis)",
    inBoundary=data_tier,
    port=6380,
    protocol="RESP/TLS",
    isSQL=False,
    storesSensitiveData=True,
    maxClassification=Classification.SECRET,
    description="Opaque session ID -> envelope-encrypted refresh/access tokens. TTL = idle timeout.",
)
apply_controls(
    session_store,
    isEncrypted=True,
    isEncryptedAtRest=True,
    hasAccessControl=True,
    authorizesSource=True,
    implementsPOLP=True,
    validatesInput=True,
    handlesResourceConsumption=True,
    usesEncryptionAlgorithm="AES",
)

user_db = Datastore(
    "User & Tenant DB (PostgreSQL)",
    inBoundary=data_tier,
    port=5432,
    protocol="PostgreSQL/TLS",
    isSQL=True,
    storesPII=True,
    storesSensitiveData=True,
    maxClassification=Classification.SENSITIVE,
    description="User profiles, tenant membership, roles. Row-level security keyed on tenant_id.",
)
apply_controls(
    user_db,
    isEncrypted=True,
    isEncryptedAtRest=True,
    hasAccessControl=True,
    authorizesSource=True,
    implementsPOLP=True,
    validatesInput=True,
    usesParameterizedInput=True,
    handlesResourceConsumption=True,
    usesEncryptionAlgorithm="AES",
)

audit_log = Datastore(
    "Security Audit Log",
    inBoundary=data_tier,
    port=443,
    protocol="HTTPS",
    isSQL=False,
    storesLogData=True,
    maxClassification=Classification.RESTRICTED,
    description="Append-only (WORM) log of auth events: login, logout, MFA, role change.",
)
apply_controls(
    audit_log,
    isEncrypted=True,
    isEncryptedAtRest=True,
    hasAccessControl=True,
    authorizesSource=True,
    implementsPOLP=True,
    handlesResourceConsumption=True,
    usesEncryptionAlgorithm="AES",
    # GAP: events are not schema-validated, enabling CRLF / log-forging via user-agent fields.
    validatesInput=False,
)

# --- Data --------------------------------------------------------------------
auth_request = Data("Authorization request (state, nonce, PKCE challenge)", classification=Classification.RESTRICTED)
auth_code = Data(
    "Authorization code",
    classification=Classification.SECRET,
    isCredentials=True,
    credentialsLife=Lifetime.SHORT,
)
tokens = Data(
    "ID / access / refresh tokens",
    format="JWT",
    classification=Classification.SECRET,
    isCredentials=True,
    credentialsLife=Lifetime.SHORT,
)
stored_tokens = Data(
    "Encrypted token envelope",
    classification=Classification.SECRET,
    isCredentials=True,
    credentialsLife=Lifetime.AUTO,
    isStored=True,
)
access_token = Data(
    "Access token (audience = API)",
    format="JWT",
    classification=Classification.SECRET,
    isCredentials=True,
    credentialsLife=Lifetime.SHORT,
)
session_cookie = Data(
    "Session cookie (__Host-, HttpOnly, Secure, SameSite=Lax)",
    classification=Classification.SECRET,
    isCredentials=True,
    credentialsLife=Lifetime.AUTO,
)
api_request = Data("API request", format="JSON", classification=Classification.SENSITIVE)
user_profile = Data(
    "User profile & tenant roles",
    format="JSON",
    classification=Classification.SENSITIVE,
    isPII=True,
    isStored=True,
)
audit_event = Data(
    "Auth audit event (user ID, IP, outcome)",
    format="JSON",
    classification=Classification.RESTRICTED,
    isPII=True,
    isStored=True,
)

# --- Dataflows: login --------------------------------------------------------
login = Dataflow(user, gateway, "GET /login", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13)
login_fwd = Dataflow(gateway, bff, "Forward /login", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13)
redirect = Dataflow(
    bff, user, "302 to IdP /authorize", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[auth_request]
)
authn = Dataflow(
    user, idp, "Authenticate at IdP (password + MFA)", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13,
    data=[auth_request],
)
callback = Dataflow(
    idp, user, "Redirect to /callback?code&state", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[auth_code]
)
callback_fwd = Dataflow(
    user, gateway, "GET /callback", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[auth_code]
)
callback_bff = Dataflow(
    gateway, bff, "Forward /callback", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[auth_code]
)
token_req = Dataflow(
    bff, idp, "POST /token (code + PKCE verifier + private_key_jwt)", protocol="HTTPS",
    tlsVersion=TLSVersion.TLSv13, data=[auth_code],
)
token_resp = Dataflow(
    idp, bff, "Token response", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[tokens], responseTo=token_req
)
store_session = Dataflow(bff, session_store, "Store tokens by session ID", data=[stored_tokens])
upsert_user = Dataflow(bff, user_db, "JIT provision / load user", data=[user_profile])
audit = Dataflow(bff, audit_log, "Write login event", data=[audit_event])
set_cookie = Dataflow(
    bff, user, "Set-Cookie: session", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[session_cookie]
)

# --- Dataflows: authenticated use -------------------------------------------
spa_api = Dataflow(
    spa, gateway, "API call + session cookie", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13,
    data=[session_cookie, api_request],
)
api_fwd = Dataflow(gateway, bff, "Forward API call", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13, data=[api_request])
bff_api = Dataflow(
    bff, app_api, "Call API with access token (mTLS)", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13,
    data=[access_token, api_request],
)
api_db = Dataflow(app_api, user_db, "Tenant-scoped query (RLS)", data=[user_profile])
admin_flow = Dataflow(
    admin, gateway, "Role management (step-up MFA, acr=mfa)", protocol="HTTPS", tlsVersion=TLSVersion.TLSv13,
    data=[session_cookie, api_request],
)

# --- Transport controls --------------------------------------------------------
public_flows = (login, redirect, authn, callback, callback_fwd, token_req, token_resp, set_cookie, spa_api, admin_flow)
private_flows = (login_fwd, callback_bff, store_session, upsert_user, audit, api_fwd, bff_api, api_db)

for flow in public_flows + private_flows:
    flow.maxClassification = min(flow.source.maxClassification, flow.sink.maxClassification)
    apply_controls(
        flow,
        isEncrypted=True,
        authenticatesDestination=True,
        checksDestinationRevocation=True,
        implementsAuthenticationScheme=True,  # session cookie, OIDC state/PKCE, or mTLS
        authorizesSource=True,
        providesIntegrity=True,
    )

for flow in private_flows:
    flow.usesVPN = True  # private subnets, service mesh mTLS

for flow in public_flows:
    respond(flow, "DE03", "mitigated: TLS 1.3 only, HSTS preload; a VPN is not applicable to public clients")


if __name__ == "__main__":
    tm.process()
