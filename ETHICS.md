# Ethics

> This is engineering documentation, **not legal advice**. Consult counsel before any Class-C testing, especially cross-border.

**Principles**
1. Never touch a running computer you don't own. Default third-party testing to Class B (self-host the package).
2. No real PII, ever. All sensitive-looking data is synthetic (IEEE-CIS-seeded) or a planted honeytoken; breaches are confirmed by canary hits.
3. Scope widening is a human decision, never an autonomous one (GPG-signed + CODEOWNERS review).
4. Real findings go through coordinated disclosure (see `DISCLOSURE.md`).

**Legal posture (rationale, not advice).** *Van Buren v. United States* (2021) narrowed CFAA "exceeds authorized access," and the May 2022 DOJ policy declines to charge good-faith research — but that's prosecutorial discretion, not immunity, and doesn't bar civil claims. RedCell does **not** rely on that doctrine: Class A/B involve no access to a computer you don't own, and Class C requires affirmative authorization.

**EU AI Act framing.** A fintech transaction-triage / credit-adjacent agent is plausibly Annex III high-risk (note the financial-fraud-detection nuance). Article 15 requires adversarial robustness and cybersecurity — RedCell's frozen-corpus before/after collapse is exactly that evidence, mapped control-by-control on the leaderboard. *(Verify the current Annex III application date — the Digital Omnibus proposes deferring it toward 2027.)*

**Honest limitations.** CVSS v4.0 fits LLM/agent vulns poorly (OWASP-LLM ids are the primary taxonomy). Self-hosting tests the software, not the operator's deployment. The gate protects against accidental scope-widening, not a malicious operator who signs a bad scope file.
