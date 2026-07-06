# Frozen attack corpus

The corpus is the **scientific control** behind the headline before/after number. It is content-addressed and immutable per version.

```
corpus/
  v1.0.0/
    attacks.jsonl              # exact rendered payloads (incl. winning mutations)
    manifest.lock.json         # corpus_version = sha256(sorted case_ids)
    baseline_scorecard.json    # ASR against the undefended agent (committed)
  CHANGELOG.md
```

**Freeze protocol** (all of it, or the number is fiction):
1. `case_id = sha256(canonical_json(case_minus_id))` — any edit is detectable.
2. `corpus_version = v{n}+sha256(sorted case_ids)`, git-tagged.
3. Environment lockfile: pinned model ids + fingerprints, temperature 0, decode seeds, library versions, guard/model revisions.
4. Fixtures pinned: IEEE-CIS-seeded tool responses are frozen bytes (no live DB during scoring).
5. Separation of duties: the mutator is **disabled** during scoring, so v1 and v2 runs execute the byte-identical corpus.
6. Held-out ~20% split that defenses are never tuned against (overfitting guard).

The pre-defense and post-defense runs load the same tag and are scored under the same pinned `verifier_version` — so the ASR collapse is attributable to the defenses, not a weaker/stronger attacker.

> **Report both numbers.** The frozen-corpus collapse (non-adaptive) *and* the adaptive number — the mutation loop turned loose on the *defended* agent. The adaptive result is the honest, more impressive engineering story.
