# Changelog

## 0.4.0 - 2026-09-25

### Added
- **PII registry bundle 1.2.0 (24 countries, incl. AU TFN/ABN/Medicare).**
- **The country layer: 24 country profiles, 54 patterns, 20 check digits.**
  Patterns, keywords, redaction labels and checksum gates are generated from
  Tork's own country registry and consumed verbatim from the SDK bundle
  (`Registry-Version: 1.2.0`, content `cfd4f61ebaf45e74`). Countries: AU, US, GB, EU, AE, SA, NG, IN, JP,
  CN, KR, BR, CA, ZA, GH, IT, KE, MU, MX, MY, PK, SG, TH, ID.
- **Rule 1a: `au_tfn`, `au_abn` and `au_medicare` now run on every document,**
  not just when Australia activates -- the ABN's own corpus sentence
  activates no region at all. `au_tfn` and `au_abn` gate on a required
  checksum (a failing TFN falls back to a generic near-miss redaction; a
  failing ABN simply does not match); `au_medicare`'s checksum is advisory
  only and never blocks a match. Closes the bundle 1.1.0 gap where
  `checksums.json` named these three but `patterns` shipped none of them.
- New namespace `Tork::Governance::Pii`: `PATTERNS` (the bundle's 54 patterns),
  `SIGNALS` and `COUNTRY_PATTERNS` (the 51 activation signals and the country
  map), `Checksums` (20 algorithms) and `Country` (the matcher). All pure and
  local: no network, no clock.
- `PIIResult` gains `country_matches`, `country_labels` and `regions`, all
  defaulting to empty so existing construction still works.
  `PIIDetector.detect(text, regions)` forces a set of country profiles on; the
  single-argument form is unchanged.
- **Nine check digits ported by hand.** The bundle names twenty algorithms and
  specifies the eleven that reduce to a weight vector and a modulus; the other
  nine (`br_cpf`, `br_cnpj`, `cn_resident_id`, `de_steuer_id`, `fr_nir`,
  `it_codice_fiscale`, `jp_my_number`, `kr_rrn`, `sg_nric`) are ported from the
  cloud's `lib/pii/checksums.ts`, each tested against the issuing authority's
  own worked example where one is published.

### Fixed
- **SDK-RUBY-PARTIAL-REDACTION.** Until 0.3.0 each type was redacted with its
  own `gsub` over text a previous type had already rewritten, while `matches`
  carried indices into the *original* text. Two types matching overlapping
  spans could leave half an identifier standing beside a redaction token --
  digits exposed in output the caller had been told was redacted. Every match
  is now collected against the original text, overlaps are resolved before
  anything is rewritten, and the surviving spans are spliced right to left in
  one pass. `no partial redaction` asserts the invariant across all 268
  vectors.
- **The gemspec read the wrong version constant.** `tork-governance.gemspec`
  took `spec.version` from `lib/tork/version.rb` -- `Tork::VERSION`, which
  belongs to the separate `Tork` API client that also lives in this repository.
  It now reads `TorkGovernance::VERSION` from
  `lib/tork_governance/version.rb`. The two happened to agree; nothing kept
  them in step, so a bump to one would have shipped the other's number.

### Notes
- This release folds in 0.3.0, which is in this repository but was never
  published to RubyGems (RubyGems is at 0.2.0).
- **`bundle exec rspec` does not run green, for a reason that predates this
  release and is untouched by it.** `spec/tork_spec.rb` covers the separate
  `Tork` API client and needs a `stub_tork_request` helper that exists nowhere
  in the repository, and `spec/spec_helper.rb` never requires `lib/tork`, so
  the whole run aborts with "uninitialized constant Tork" before any example.
  The governance suite -- `spec/tork_governance_spec.rb`,
  `spec/pii_type_parity_spec.rb`, `spec/tool_result_scan_spec.rb` and the new
  `spec/pii_country_spec.rb` -- runs green at 464 examples, 0 failures. Fixing
  the orphaned spec means adding the missing helper (WebMock is already a
  development dependency) and is a separate piece of work.
- **`PIIMatch#value` still carries the RAW matched value here**, where every
  other Tork SDK stores the literal `"[REDACTED]"` so a caller cannot log the
  sensitive value straight out of a detection result. It is asserted by
  `spec/tork_governance_spec.rb:166`, so changing it is a deliberate breaking
  change rather than something to slip into a minor. Flagged, not changed.
- **The bundle now states the whole contract, and this SDK implements it.**
  Bundle 1.0.0's README documented three rules; measured against the cloud's
  golden snapshot they disagreed with it on 14 of 86 country-corpus cases, so
  this SDK carried two more of its own. Bundle **1.1.0 documents seven**, marks
  each SDK or cloud-only, and ships the data all seven need in every language
  file -- the activation signals, the country map, the asymmetric 60/40 window,
  the symmetric 60 context window, the whole-word vocabulary, the near-miss
  policy, the table constants and the reference labels. So the locally generated
  activation layer is **deleted**, no window is hard-coded any more, and rules 6
  (near miss), 7 (column header) and 7b (nearest label) are implemented here for
  the first time. Every rule now reads its data off the placed bundle.
- Advisory checksums never reject a match: `ca_sin`, `emirates_id`,
  `de_tax_id`, `kr_rrn`, `sa_national_id`. Korea stopped issuing check digits on
  20 Oct 2020.
- Not ported, and still cloud-only: the slot, context,
  gravity and name layers, industry profiles, and org configuration.
- **Indonesia is the country 1.1.0 added, and it is the one that proves the
  whole-word rule.** `id_nik`'s only short spellings -- NIK, KTP, NPWP -- are
  `wholeWordKeywords`, not ordinary keywords, because `nik` sits inside
  *teknik*, *elektronik*, *klinik* and *pabrik*. Matching them by substring
  would open the gate on an Indonesian sales ledger; matching them on a word
  boundary catches "NIK 3171010101900001" and leaves *teknik* alone. An SDK that
  merged the two lists would be shipping a false-positive bug, so the boundary
  test is implemented rather than the shortcut, and four unit cases assert both
  halves.
- **FLAGGED, upstream: bundle 1.1.0 cannot detect Australia's TFN, ABN or
  Medicare number.** `checksums.json` declares `au_tfn` and `au_abn` as
  `requiredBy` and `au_medicare` as `advisoryFor` patterns of those names, and
  `patterns` ships none of them -- the AU profile carries only `au_acn` and
  `au_phone_intl`. The AU activation signals are still keyed on "tfn", "tax
  file" and "medicare", so the bundle switches Australia on for identifiers it
  then has no pattern to catch. The cloud detects all three. This is a recall
  gap no SDK can close from the bundle, and the six parity cases it costs are
  recorded in the fixture as `BUNDLE GAP` rather than silently accepted.

## 0.2.2 - 2026-03-09

### Added
- feat: agent/session context fields (agent_id, agent_role, session_id, session_turn)
