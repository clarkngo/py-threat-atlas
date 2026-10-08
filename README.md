# Py-Threat-Atlas

**Threat models as code, from web apps to autonomous agents.**

Py-Threat-Atlas is a curated set of system architectures, each modeled as an executable [OWASP pytm](https://github.com/OWASP/pytm) script. Every system has a generated data flow diagram, a STRIDE findings register produced by pytm, and a written mitigation strategy mapped to OWASP, NIST and industry standards.

The catalog goes in four tiers. Each tier keeps the threats of the one before it and adds new ones:

| Tier | What changes | Systems |
|---|---|---|
| **Traditional** | Web, mobile, API, identity and microservices: the baseline | [SaaS Login with OAuth 2.0 / OIDC](systems/traditional/saas-oidc-login/) · [E-commerce Checkout with Tokenized Payments](systems/traditional/ecommerce-checkout/) · [Mobile Banking Backend](systems/traditional/mobile-banking-backend/) · [Microservices Order Platform](systems/traditional/microservices-order-platform/) |
| **Cloud-native** | Identity and configuration become the perimeter | [Serverless File Upload Pipeline (AWS)](systems/cloud/serverless-file-upload/) · [Multi-Tenant SaaS on Amazon EKS](systems/cloud/multi-tenant-eks-saas/) |
| **AI-enabled** | Untrusted text becomes an instruction channel; models become artifacts | [RAG Customer Support Chatbot](systems/ai/rag-support-chatbot/) · [Real-Time ML Fraud Scoring](systems/ai/ml-fraud-scoring/) |
| **Agentic** | Prompt injection becomes privileged action | [Autonomous SRE Incident Agent](systems/agentic/sre-incident-agent/) · [Multi-Agent Customer Operations](systems/agentic/multi-agent-customer-ops/) |

| System | Findings | Open | Highest open severity |
|---|---:|---:|---|
| [SaaS Login with OAuth 2.0 / OIDC](systems/traditional/saas-oidc-login/) | 39 | 7 | High |
| [E-commerce Checkout with Tokenized Payments](systems/traditional/ecommerce-checkout/) | 33 | 3 | High |
| [Mobile Banking Backend](systems/traditional/mobile-banking-backend/) | 35 | 17 | High |
| [Microservices Order Platform](systems/traditional/microservices-order-platform/) | 21 | 17 | Very High |
| [Serverless File Upload Pipeline (AWS)](systems/cloud/serverless-file-upload/) | 21 | 11 | Very High |
| [Multi-Tenant SaaS on Amazon EKS](systems/cloud/multi-tenant-eks-saas/) | 22 | 6 | Very High |
| [RAG Customer Support Chatbot](systems/ai/rag-support-chatbot/) | 21 | 4 | Very High |
| [Real-Time ML Fraud Scoring](systems/ai/ml-fraud-scoring/) | 9 | 7 | Very High |
| [Autonomous SRE Incident Agent](systems/agentic/sre-incident-agent/) | 25 | 15 | Very High |
| [Multi-Agent Customer Operations](systems/agentic/multi-agent-customer-ops/) | 23 | 13 | Very High |

## How the models work

Each `model.py` describes a **realistic, mostly hardened design**. Elements start from a control profile with sensible defaults, and the known design gaps are set explicitly with a `# GAP:` comment. For findings the design already handles, pytm's `overrides` record a `response` (`mitigated:`, `transferred:` or `accepted:` plus a rationale). The **open** findings in each register are therefore the real residual risks, not rule-engine noise.

Every README contains:

1. **System Overview & Context**: what the system does and why it is built this way
2. **Architecture Highlights**: components, trust boundaries, data flow patterns
3. **Data flow diagram**: generated from the model
4. **Automated STRIDE Threat Analysis**: the pytm findings interpreted by category, plus a *manual analysis* table for threats the rule engine can't express
5. **Mitigation Strategy & Recommendations**: prioritized (P1–P3) and mapped to standards
6. **pytm Findings Register**: generated between `<!-- atlas:findings:begin/end -->` markers; never edit it by hand

## The Atlas threat library

`threatlib/atlas_threats.json` is the library every model loads. It merges:

- The **103 stock pytm rules** (CAPEC-derived), each tagged with a primary STRIDE category, with fixes for five rules that are broken in pytm 1.3.1: four with inverted conditions (`INP19`, `INP21`, `INP22`, `DR01`), and `DO04`, which crashes on any dataflow carrying XML.
- **32 Atlas extension rules** in [`threatlib/atlas_extensions.json`](threatlib/atlas_extensions.json):
  - `CLD01–08`: cloud. Public buckets, over-privileged workload identity, SSRF to metadata, pre-signed URL abuse, event injection, missing audit trail, CI/CD artifact tampering, cross-tenant access.
  - `AI01–12`: LLM and ML, mapped to the **OWASP Top 10 for LLM Applications 2025** and **MITRE ATLAS**.
  - `AGT01–12`: agentic systems, mapped to the **OWASP Top 10 for Agentic Applications** and the **OWASP Agentic AI Threats & Mitigations** taxonomy.

Extension rules read custom element attributes through `getattr(target, ..., False)`. Models that don't set an attribute are unaffected:

| Attribute | Set on | Enables |
|---|---|---|
| `isCloudWorkload`, `makesOutboundRequests`, `restrictsEgress`, `hasAuditLogging` | Server / Process / Lambda | `CLD02`, `CLD03`, `CLD06` |
| `isObjectStorage`, `blocksPublicAccess` | Datastore | `CLD01`, `CLD06` |
| `usesPresignedURL` | Dataflow | `CLD04` |
| `isEventTriggered` | Lambda / Process | `CLD05` |
| `isBuildSystem` | Server / Process | `CLD07` |
| `isMultiTenant`, `enforcesTenantIsolation` | Datastore / Server / Process | `CLD08` |
| `isLLM`, `hasPromptGuardrails`, `filtersSensitiveOutput`, `secretsExcludedFromPrompt`, `groundsResponses` | Server / Process | `AI01`, `AI03`, `AI05`, `AI09`, `AI10` |
| `carriesUntrustedContent` | Dataflow (into an LLM or agent) | `AI02` |
| `isThirdPartyModel` (sink), `hasZeroDataRetention` | ExternalEntity / Dataflow | `AI11` |
| `isVectorStore`, `enforcesDocumentACL` | Datastore | `AI06` |
| `isTrainingData`, `isModelArtifact` | Datastore | `AI07`, `AI08` |
| `isInferenceEndpoint`, `monitorsQueryPatterns` | Server | `AI09`, `AI12` |
| `isAgent`, `separatesInstructionsFromData`, `hasTamperEvidentAuditLog`, `hasKillSwitch`, `requestsHumanApproval`, `approvalShowsRawParameters` | Server / Process | `AGT01`, `AGT03`, `AGT08`, `AGT10`–`AGT12` |
| `isToolCall`, `enforcesToolPolicy`, `isHighImpact`, `requiresHumanApproval` | Dataflow | `AGT02`, `AGT09` |
| `executesGeneratedCode`, `isSandboxed` | Server / Process | `AGT04` |
| `isAgentMemory` | Datastore | `AGT05` |
| `isAgentToAgent` | Dataflow | `AGT06` |
| `isToolServer`, `isPinnedAndVerified` | Server / ExternalEntity | `AGT07` |

## Run it locally

Requires Python 3.12+ and Graphviz (`brew install graphviz` / `apt install graphviz`).

```bash
pip install -r requirements.txt
```

```bash
python tools/atlas.py refresh
```

```bash
python tools/atlas.py site
```

```bash
python -m http.server 8000 --directory _site
```

`refresh` runs every model, rewrites each `dfd.svg` and updates the findings register in each README. `site` renders `_site/`. To work on one model directly:

```bash
cd systems/ai/rag-support-chatbot && python model.py --dfd | dot -Tpng -o dfd.png
```

## Adding a system

1. Create `systems/<tier>/<slug>/model.py`. Copy the helpers (`apply_controls`, `respond`, control profiles) from an existing model in the same tier and set `tm.threatsFile` to the Atlas library.
2. Model the boundaries, elements and flows. Set gaps explicitly (`# GAP:`) and record a `respond(...)` for every finding the design already handles.
3. Write `README.md` with the six sections above. The first `# ` heading is the title; the first `> ` blockquote is the summary shown on the index card. End the file with the empty `<!-- atlas:findings:begin -->` / `<!-- atlas:findings:end -->` markers.
4. Run `python tools/atlas.py refresh` and commit the model, the README and `dfd.svg`.
5. To add or change a rule, edit `threatlib/atlas_extensions.json` and run `python tools/build_threatlib.py`.

CI ([`.github/workflows/static.yml`](.github/workflows/static.yml)) verifies that the threat library and every README findings register are current, builds the site, and deploys it to GitHub Pages from `main`.
