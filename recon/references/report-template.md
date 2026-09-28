# Recon report template

Synthesize Phase 2 analysis into this structure. Fill every section from
evidence you actually collected; write "(none observed)" where a section is
empty rather than omitting it. Ground each claim in evidence and label
confidence honestly (`low` / `medium` / `high`).

Severity: `info` · `low` · `medium` · `high` · `critical`.

---

# Recon Report — <target name>

- **Generated:** <ISO 8601 timestamp>
- **Targets:** <domains / hosts / AI endpoints swept>
- **Overall confidence:** low | medium | high

**Objective:** <what this recon set out to characterize>

## Summary

<2–4 sentences: the most important things learned about the target's AI app and
infrastructure, and the shape of the attack surface.>

## Attack surface

<Narrative overview: entry points, exposed vs. protected surface, the highest-
value avenues a downstream attack-planning step should focus on.>

## Infrastructure

- **Subdomains:** <list, or "(none)">
- **DNS records:** <notable A/MX/TXT/NS/CNAME facts>
- **Technologies:** <servers, frameworks, CDNs, langs inferred from banners/headers/cookies>
- **TLS:** <cert issuer/validity/SANs; protocol/cipher; any weakness>
- **Open services:** <port/service/version lines for authorized hosts>
- **Notes:** <anything else>

## AI application

- **Suspected model:** <family/version> (confidence: low|medium|high)
- **Refusal behavior:** <canned vs. reasoned; category coverage; consistency>
- **Guardrails observed:** <list>
- **Prompt-leak indicators:** <system-prompt text recovered/hinted, or "(none)">
- **Exposed tools:** <tool/function names + parameters + reachable systems>
- **Injection surface:** <direct override susceptibility; indirect/RAG handling>
- **Notes:** <anything else>

## Findings

For each finding:

### [SEVERITY] <title>  _(category: infra | ai | osint, confidence: low|medium|high)_

<Description of what it is and why it matters.>

**Evidence:**
- <concrete observation: a response, header, banner, status code, cert field…>

**Recommendation:** <what to do about it / what to probe next>

_(Rank findings most-severe first. Use "(none)" if there are none.)_

## Recommended next steps (for downstream attack planning)

- <specific, evidence-grounded next actions — e.g. "fetch the OpenAPI doc at
  /v3/api-docs (200) to enumerate the API", "the chatbot leaked a 'search_docs'
  tool — map its parameters">

## Evidence log

- <the scans/probes actually run, so the report is reproducible>

## Errors / notes

- <refused calls, timeouts, degraded scans (e.g. nmap absent → connect-scan
  fallback), or anything that limited coverage>
