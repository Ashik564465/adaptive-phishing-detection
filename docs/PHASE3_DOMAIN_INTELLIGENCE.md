# Phase 3: Domain Intelligence

## Scope

The risk engine collects URL normalization, registered-domain, DNS, domain
metadata, TLS, and passive domain-forensics evidence before RAG investigation.
These collectors are supporting intelligence; they do not replace threat feeds
or identity engines.

## Components

- `src/intelligence/url_normalizer.py`
  - Parses scheme, hostname, port, path, query, fragment, subdomain, and
    registrable domain using `tldextract`.
  - Preserves the original URL.
  - Caches normalized results in memory.
- `src/intelligence/dns_intelligence.py`
  - Resolves A, AAAA, MX, NS, CNAME, and TXT records with a three-second
    resolver timeout.
  - Returns `available`, `partial`, `no_records`, `timeout`, or `unavailable`
    states and never turns a DNS failure into a phishing verdict.
- `src/intelligence/domain_intelligence.py`
  - Returns URL/domain metadata.
  - Uses explicit `unknown` values when WHOIS metadata is unavailable.
  - Does not fabricate creation dates or domain ages.
- `src/intelligence/tls_intelligence.py`
  - Performs a five-second TLS handshake.
  - Reports certificate subject, issuer, SANs, validity, and hostname match.
  - Distinguishes certificate mismatch from connection errors.
- `src/intelligence/domain_forensics.py`
  - Collects DNS, RDAP, Certificate Transparency, subdomain, IP-prefix, and
    ASN evidence with source statuses, timestamps, and errors.
  - Its single per-analysis result supplies the collector's DNS and registration
    context where available, avoiding duplicate DNS/RDAP lookups.
  - Raw provider output and normalized findings are returned under
    `evidence.domain_forensics`; provider failure remains unavailable evidence.
  - Domain age is contextual and neutral in the decision policy. CT history,
    discovered subdomains, and infrastructure are contextual only.

## Evidence hierarchy

The submitted URL is normalized once and remains the only URL analyzed.
Independent evidence is collected before model inference: verified brand
identity and registered domain; threat-intelligence matches; DNS; registration
and age; TLS; passive domain forensics; typosquatting and homograph analysis.
The engine then determines whether those results are conclusive, conflicting,
inconclusive, or unavailable. XGBoost runs only for a conflict or when
independent evidence cannot support a reliable result. Final arbitration keeps
confirmed malicious evidence decisive.

Decision policy precedence:

- Confirmed threat-intelligence matches produce phishing or malware decisions
  separately and cannot be negated by ordinary domain age, identity, DNS, or
  TLS context.
- An isolated brand mismatch, similarity match, mixed-script signal, or TLS
  hostname mismatch is suspicious and requires review, not proof of phishing.
  Confirmed threat intelligence is decisive; otherwise multiple independent
  malicious evidence groups are required for a phishing decision.
- Brand identity distinguishes a brand's registered domains from explicitly
  verified hostnames hosted beneath another organization's registered domain.
  For example, `aws.amazon.com` and `www.aws.amazon.com` are exact verified AWS
  hostnames under `amazon.com`; this does not make arbitrary `amazon.com`
  subdomains official AWS hosts. Hostname matching uses the exact configured
  names, so attacker-controlled suffixes do not inherit trust. An unlisted
  child hostname is unknown, not automatically official.
- XGBoost is a fallback, not an unconditional evidence source. A reliable
  confirmed threat or a verified official identity without independent
  malicious findings ends inference without invoking the model. Conflicting,
  incomplete, unavailable, or inconclusive independent evidence invokes it.
- A high raw ML score is retained when the model is invoked, but an ML-only
  vote does not establish phishing or overturn an exact verified official
  identity. With no independent support, a high score leaves the result
  unknown and monitored.
- A high ML signal plus a newly registered domain (under 30 days) or another
  directional warning may result in a suspicious/review decision, never a
  confirmed phishing verdict from ML alone. Registration age alone remains
  contextual.
- A verified official-domain match supports a safe decision unless confirmed
  threat-intelligence or independent malicious evidence applies. It
  does not prove that a path or hosted resource is safe.
- Unavailable or unknown sources contribute no benign vote. Insufficient
  directional evidence remains unknown.
- `analysis.independent_evidence_status`, `analysis.ml_used`, and
  `analysis.ml_fallback_reason` expose whether fallback inference was needed.
  `supporting_signals`, `contradicting_signals`, and `unavailable_sources`
  explain the resulting evidence picture. Missing providers never count as
  clean results.
- URL path and query data remain part of the submitted URL and are available
  to its normal analyzers. A path segment such as `/redirect/` does not trigger
  destination discovery, a separate lookup, or a special decision.

Supporting evidence includes the raw uncalibrated ML output, DNS observations, HTTPS presence,
certificate metadata, domain metadata, and RAG context. Unknown or unavailable
data is not treated as safe.
An established registration age, ordinary DNS observations, or a matching TLS
certificate cannot establish legitimacy. A high ML prediction that conflicts
with verified identity remains visible, but does not overturn that identity
match on its own. A high ML output without independent directional support
remains unknown; a new registration may provide contextual corroboration but
does not prove malice. Confirmed threat-feed matches and strong independent
malicious evidence remain decisive despite normal infrastructure observations.
A high raw ML score remains visible as a supporting signal and is not erased
by identity evidence.

## RAG integration

The risk engine passes domain, DNS, and TLS context to the local RAG provider.
RAG explains and contextualizes evidence but cannot override deterministic
identity or threat-intelligence decisions.

The API returns a compact canonical response by default. It includes
`analysis`, `scores`, `identity`, `threat_intelligence`,
`domain_intelligence`, `dns`, `tls`, `domain_forensics`, `reasoning`, `rag`,
`metadata`, and normalized `evidence_sources`. Each evidence source reports
status, observed values, normalized findings, category, reliability,
provenance, decision impact, and errors. Detailed mode additionally includes
raw provider observations in `details.evidence_sources`; the compact
`domain_forensics` section continues to summarize source statuses without
embedding full provider payloads.

### Risk values and evidence semantics

- `scores.ml_phishing_probability` is retained as a backward-compatible field
  name, but its value is the raw XGBoost `predict_proba` output in the inclusive
  range 0–1. The repository has no calibration artifact or held-out calibration
  evidence, so it must not be interpreted as a validated calibrated
  probability. `scores.ml_raw_score` is the semantically accurate alias. The
  value is `null` when prediction is missing, non-finite, or outside the range.
- `scores.final_risk_score` is the post-arbitration weighted evidence total:
  weak/moderate/strong/critical evidence weighs 10/25/50/100 points;
  malicious evidence adds and benign evidence subtracts; DNS/TLS weights are
  doubled; and correlated identity observations contribute only their strongest
  weight per direction. The result is clamped to 0–100. It is not a probability
  and is not the decision threshold. A score of zero means the weighted net is
  non-positive after clamping, not that phishing risk is zero.
- When verified identity offsets a high ML evidence contribution, the final
  risk score can be zero while `scores.ml_raw_score` remains high. The zero is
  the net weighted evidence score, not a zero model prediction.
- `analysis.confidence` is a heuristic 10–100 evidence-support measure, not a
  calibrated probability. It starts at 50, adds 40 for reliable critical
  evidence or otherwise 30 for strong evidence, adds 10 for more than one
  independent evidence group, subtracts 10 plus up to 25 according to the
  ratio of the weaker to stronger directional support in an unresolved
  disagreement (or 10 for other contradictions), and caps model-supported
  review outcomes at 55, then is clamped to 10–100.
  These values remain policy heuristics, not measured confidence calibration.
  Correlated identity detectors count as one group; contextual maturity and a
  matching TLS hostname do not raise it.
- `analysis.risk_level`, `analysis.decision`, `analysis.decision_basis`, and
  `analysis.recommended_action` come from the existing decision-policy
  branches. Risk level is policy output, not a bucket derived from the
  weighted score.
- The legacy `FinalDecision.to_pipeline_dict()` projection is not part of the
  compact response; when called directly it mirrors the canonical decision,
  and its legacy `phishing_score` is the raw XGBoost output or `null`, not a
  calibrated probability or an age-adjusted risk estimate.
- `reasoning.evidence_agreement` considers directional evidence, including
  the raw ML result even when the contradiction analyzer overrides it.
  Unknown/unavailable feeds and neutral ML output do not vote. Correlated
  brand, typo, and homograph signals form one identity group. Domain age and a
  hostname-matching TLS certificate are contextual, not evidence of legitimacy.
- Agreement labels are based on independent voting groups: `strong_agreement`
  means at least two groups support one direction; `moderate_agreement` means
  one group votes; `mixed` means independent groups vote in both directions
  without an explicit contradiction record; `strong_contradiction` means
  opposite-direction groups and an explicit contradiction are both present;
  `insufficient` means there are no directional groups.
- `reasoning.evidence_quality` describes the strength of relevant directional
  evidence: `high` requires critical evidence with reliability at least 0.9,
  otherwise `moderate` means at least one strong signal, `low` means there is
  only weaker directional evidence, and `unknown` means no relevant
  directional evidence. Neutral or unavailable observations do not increase it.
- Domain maturity remains observable in `domain_forensics.findings`. Its
  `influenced_decision` value is true only when a reliable age under 30 days
  corroborates a separate high ML signal and causes a review-only suspicious
  decision. Age alone does not add or subtract weighted risk points.
- `tls.hostname_match` reports whether the certificate validated for the
  requested hostname. `tls.valid_at_observation` is the separate date-validity
  check against `tls.certificate_observed_at`; `tls.collected_at` is the scan
  completion time. A hostname match establishes neither brand ownership nor
  site legitimacy. Certificate-validation errors without retrievable validity
  dates leave date validity unknown.
- Threat-intelligence provider errors remain `error`/unavailable and are not
  serialized as clean matches.
- ML raw-output thresholds are provisional defaults: review at 0.85, strong at
  0.95, and weak benign evidence below 0.15. They are configurable with
  `RISK_ML_REVIEW_THRESHOLD`, `RISK_ML_STRONG_THRESHOLD`, and
  `RISK_ML_BENIGN_THRESHOLD`. They are not calibrated probability thresholds.
- The additive `scores.final_risk_score_explanation` and
  `reasoning.risk_score_explanation` detail the risk-increasing and
  risk-mitigating weighted points, independent evidence groups, net, and
  clamped result. Thus a score of zero alongside a high raw ML output means
  risk-increasing and risk-mitigating points offset or the net was clamped; it
  does not mean the ML model had no suspicion.
- `reasoning.evidence_coverage` distinguishes collected source status from
  evidence direction. Forensics and successful DNS/TLS collection remain
  contextual and do not act as benign evidence.

### Model validation status and evaluation

The checked-in dataset has 572,301 rows, 572,301 unique URLs, 148,360 distinct
`source_domain` values, and 423,941 repeated-domain rows. It contains 300,000
Tranco examples, all labeled legitimate, and 272,301 PhishTank/synthetic
examples, all labeled phishing. This is perfect label/source confounding;
Google appears only in phishing-labeled rows, while SBI and VIT have no rows.
The trained model contains no provenance, train/test split, or calibration
metadata, and the repository has no training/evaluation script. Consequently,
metrics computed by splitting this same dataset cannot be represented as a
valid independent evaluation of the saved model, and no calibration is
justified from it.

A reproducible-size sample of 500 rows from each source/label group showed that
Tranco legitimate examples have zero subdomain length/count in that sample,
while PhishTank and synthetic phishing examples commonly have nonzero
subdomains. For `aws.amazon.com`, the saved model's top contributions are
`subdomain_length` (+9.25 log-odds) and `subdomain_count` (+1.52 log-odds);
the same features dominate `www.vit.ac.in`. This is consistent with the
dataset's source confounding, not a calibrated phishing probability. The
feature extractor and saved feature order remain unchanged pending
representative, source-independent evaluation.

`scripts/evaluate_model.py` is a reproducible evaluation utility for a future
independent labeled sample. It requires a one-domain-per-line manifest of the
saved model's training domains, rejects overlapping evaluation domains, splits
validation/calibration and final test domains with a fixed seed, reports
precision, recall, F1, PR-AUC, ROC-AUC, confusion matrix, false-positive and
false-negative rates, Brier score, log loss, reliability bins, configured
operating thresholds, and official/redirect/lookalike subgroups. It compares
sigmoid and isotonic calibration only when the disjoint calibration split
contains at least 100 examples from each class; it never persists a calibrator.
Calibrator adoption requires representative labels and improvements in both
Brier score and log loss on the untouched test split.

The additive response fields use schema version 2.1; existing version 2.0
fields retain their meanings. Clients should ignore unknown fields.

Clients that need raw forensic provider output can opt in on the existing
`POST /analyze` endpoint by sending the boolean `"include_details": true`:

```json
{
  "url": "https://example.com",
  "include_details": true
}
```

Detailed mode adds only:

```json
"details": {
  "domain_forensics": {}
}
```

The compact decision and scores are identical in both modes. Raw forensic
details are reused from the same analysis and do not trigger a second scan.
`scores.ml_phishing_probability` is the raw model output when available;
`scores.final_risk_score` is the separate post-arbitration weighted risk score
and is not a probability.

The existing consumer-facing contract therefore omits legacy duplicate
`pipeline`, `parsed_domain`, and `infrastructure_checks` copies:

```json
{
  "analysis": {},
  "scores": {},
  "identity": {},
  "threat_intelligence": {},
  "domain_intelligence": {},
  "dns": {},
  "tls": {},
  "domain_forensics": {},
  "reasoning": {},
  "rag": {},
  "metadata": {}
}
```

No HTML dashboard file is currently part of this repository; consumers can
render the compact response without requiring raw provider details.

## Verification commands

From `D:\project\adaptive-phishing`:

```cmd
python -c "from src.intelligence.domain_intelligence import analyze_domain; print(analyze_domain('https://accounts.google.com'))"
python -c "from src.intelligence.dns_intelligence import analyze_dns; print(analyze_dns('google.com'))"
python -c "from src.intelligence.tls_intelligence import analyze_tls; print(analyze_tls('google.com', 443))"
python -m unittest src.risk.tests.test_risk_engine -v
python -m unittest tests.test_domain_forensics -v
```

Expected core decisions:

```text
https://accounts.google.com => safe | official_identity_verified
https://g00gle.com => phishing | strong_impersonation_evidence
https://google.com.evil.com/login => phishing
```

Punycode is represented in the final JSON under:

```json
"evidence": {
  "homograph": {
    "punycode": true
  }
}
```

## Evidence arbitration

The risk engine evaluates all collected evidence together. It tracks:

- evidence direction and strength
- detector reliability
- independent source agreement
- contradictions between benign and malicious signals
- unavailable or unknown providers

RAG remains contextual and is not counted as an independent malicious signal.
Threat-feed absence, DNS failure, TLS failure, and missing domain metadata do
not become safe or phishing verdicts by themselves.

The final JSON includes:

```json
"reasoning": {
  "evidence_agreement": "strong_agreement",
  "evidence_quality": "high"
}
```

Possible agreement states are `strong_agreement`, `moderate_agreement`,
`mixed`, `strong_contradiction`, and `insufficient`. Contradictory strong
evidence can produce `unknown` rather than forcing a binary verdict.

## Validated legitimate cases

Validated historical cases are stored in
`data/rag/cases/validated_cases.json` and matched by registered domain. A
matching `confirmed_legitimate` case contributes benign evidence, but it does
not suppress stronger malicious evidence from threat intelligence, identity,
typosquatting, homograph, or TLS checks.

The public `rag` response is intentionally concise. It may contain one
`closest_case`, a small list of `supporting_knowledge` entries, and an
`investigation` summary. Retrieval-only fields such as document IDs, tags,
categories, queries, and vector-search scores remain internal.
