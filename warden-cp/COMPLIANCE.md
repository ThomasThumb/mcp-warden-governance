# Compliance control mapping — SOC 2, ISO/IEC 42001, EU AI Act

**Read this first:** neither of us is a lawyer, and this document is not
legal advice. It maps specific *technical controls* in `mcp-warden` /
`warden-cp` to specific requirements in three frameworks, so an actual
compliance/legal review has a real starting point instead of a blank page.
Whether any of this even applies to what you're building — e.g. whether a
given agent counts as a "high-risk AI system" under the EU AI Act's Annex
III — is a legal determination about your specific use case, not something
this codebase can decide for you. Get qualified counsel for that call before
you rely on anything below.

## Where things stand as of this writing (July 2026)

The EU AI Act's high-risk obligations (Articles 9-17 for providers, Article
26 for deployers) are legally set to become enforceable August 2, 2026. The
European Commission proposed delaying parts of this via the "Digital
Omnibus" package, and Council/Parliament were in trilogue negotiations as of
early 2026 - but nothing delaying it had passed into law as of this writing.
Treat August 2, 2026 as the real date unless you've confirmed otherwise
directly, not because a proposal to delay it exists.

## SOC 2 (Trust Services Criteria)

SOC 2 is an attestation, not a checklist a codebase can "pass" - an auditor
evaluates whether controls are designed and operating effectively over a
period of time. What this build gives you evidence *for*:

| Control area | What we have | What's still on you |
|---|---|---|
| Logical access (CC6-series) | Real API-key auth on every control-plane endpoint (`auth.rs`), per-agent-session scoped tokens, explicit revocation | Key rotation policy, offboarding process for departed employees' keys, MFA on however operators reach the box itself |
| System monitoring (CC7-series) | Hash-chained audit log with a verify endpoint, rate limiting | Alerting/SIEM integration, an actual on-call process for what happens when `/v1/audit/verify` reports a break |
| Change management | Versioned policy bundles and org-Rego policies (every change has a version, timestamp, and author) | A documented change-approval process around *who* is allowed to push a new policy version |
| Risk mitigation | Default-deny policy floor, degraded-mode gate requiring explicit human confirmation | A written incident response plan; this codebase logs incidents, it doesn't run your response process |
| Confidentiality | Signing key persisted with restrictive file permissions, secrets never logged in plaintext (audit stores arg *hashes*) | Encryption at rest for the database itself, a real secrets vault for upstream server credentials (see mcp-warden's open gap) |

## ISO/IEC 42001 (AI Management System)

ISO 42001's Annex A has 38 controls across 9 objectives - AI policy,
internal organization, resources, impact assessment, AI system lifecycle,
data, information for interested parties, responsible use, and third-party
relationships. It's a management-system standard: most of it is
documentation and process, not code. What this build supports directly:

- **Human oversight** (the objective most directly relevant here): the
  policy floor + required-approval default + degraded-mode go/no-go gate are
  the technical half of "humans can monitor, interrupt, and override AI
  system actions." The org-Rego auto-approve mechanism is designed so it
  narrows human review to genuinely low-risk cases *by explicit policy*,
  not by silently disabling oversight.
- **AI system lifecycle / monitoring**: tool-fingerprint drift detection
  (`tool_fingerprints` table) gives you a technical record of when a
  connected tool's behavior changed, which is exactly the kind of
  "monitoring after deployment" evidence ISO 42001 wants.
- **Third-party relationships**: the inventory table (which gateway is
  running which upstream server, owned by whom) is a real asset for the
  AI-supply-chain-due-diligence controls, but the *due diligence itself*
  (vetting a third-party MCP server before you connect it) is a process you
  still have to run.
- **Not covered by code at all**: bias/fairness assessment, societal impact
  assessment, training records, a Statement of Applicability, and the
  cross-functional governance structure (named owners, documented
  authority) the standard actually certifies against. Don't let a green
  audit log convince anyone that's covered.

## EU AI Act

The most concretely actionable article for this specific system is
**Article 12** (automatic event logging over the AI system's lifetime).
It doesn't explicitly say "tamper-proof," but logs with no integrity
guarantee carry little evidentiary weight if you ever need to show a
regulator or auditor they weren't altered after the fact. That's the
entire reason `audit_events` is hash-chained rather than a plain table -
`GET /v1/audit/verify` is the artifact you'd actually produce on request.

Other articles this build's controls touch:

| Article | What it requires | What we have |
|---|---|---|
| Art. 9 (risk management) | Continuous risk management across the system's life | The floor/Rego layering + drift detection are ongoing controls, not a one-time assessment - but the *documented* risk management process is still yours to write |
| Art. 12 (record-keeping) | Automatic logging over the system's lifetime | Hash-chained audit log, minimum 6-month retention is on you to configure (nothing here auto-deletes, but nothing enforces retention either - that's a deployment decision) |
| Art. 14 (human oversight) | Humans can monitor and intervene | Default-to-approval, degraded-mode human gate, revocable agent sessions |
| Art. 15 (cybersecurity / "action layer" resilience) | The APIs/tools an agent calls are explicitly in scope, not just the model | This is what `mcp-warden`'s entire injection-filter + policy-floor + integrity-hash stack is *for* - MCP tool calls are exactly the "action layer" the Act's recitals on multi-agent systems (Recitals 99-100) are describing |

**What this cannot tell you:** whether your specific agent, doing your
specific task, counts as "high-risk" under Annex III (credit, hiring,
healthcare, insurance, law enforcement, etc. are the named categories) or
whether Article 6(3)'s carve-out for systems that don't materially
influence outcomes applies to you. That classification decision is exactly
where you need a lawyer, not a longer README.

## The honest summary

This build gives you real, checkable technical evidence for the "logging,"
"human oversight," and "monitoring" legs of all three frameworks. It gives
you nothing for the "governance process," "documented risk assessments,"
"training records," "bias/fairness review," and "legal classification"
legs — because those aren't code problems. Anyone telling you a tool alone
makes you "SOC 2 / ISO 42001 / EU AI Act compliant" is selling you
something. Treat this document as the technical half of a much larger
binder, not the whole binder.

## Sources consulted while writing this

- https://artificialintelligenceact.eu/article/12/ and /article/9/, /14/, /15/, /26/
- https://digital-strategy.ec.europa.eu/en/policies/regulatory-framework-ai
- https://www.knowlee.ai/blog/iso-42001-checklist-ai-management
- https://mindsetcyber.com.au/iso-42001-controls-list/
- https://salt.security/eu-ai-act-compliance
- https://truescreen.io/insights/ai-act-record-keeping-requirements/
- https://labs.cloudsecurityalliance.org/research/csa-research-note-eu-ai-act-high-risk-compliance-deadline-20/
