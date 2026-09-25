# frozen_string_literal: true

# Country-layer parity tests.
#
# The fixtures are generated from the cloud's own evidence, not written here:
#
#   pii_unit_cases.json  one valid sample per registry pattern, a
#                        checksum-broken variant for each pattern whose
#                        checksum is a gate, and the Indonesian boundary cases.
#   pii_vectors.json     all 2,092 inputs of the cloud's golden snapshot: every
#                        country-corpus sentence for all 249 ISO jurisdictions,
#                        and the whole 1,523-line business false-positive corpus.
#
# expectedOutput is the COUNTRY LAYER alone. Where the cloud's own output
# differs, the case carries cloudOutput and a divergence naming the cause.

require "spec_helper"
require "json"

RSpec.describe Tork::Governance::Pii::Country do
  C = Tork::Governance::Pii::Country
  R = Tork::Governance::Pii
  NIK = "3171010101900001"

  let(:vectors) { JSON.parse(File.read(File.expand_path("fixtures/pii_vectors.json", __dir__))) }
  let(:units)   { JSON.parse(File.read(File.expand_path("fixtures/pii_unit_cases.json", __dir__))) }
  let(:corpus)  { vectors["cases"].reject { |c| c["kind"] == "business-fp" } }
  let(:business) { vectors["cases"].select { |c| c["kind"] == "business-fp" } }

  def redact(s)
    C.apply_redactions(s, C.detect(s))
  end

  describe "the bundle" do
    it "is the version and content the fixtures were generated from" do
      expect(R::REGISTRY_VERSION).to eq(vectors["bundleVersion"])
      expect(R::CONTENT_HASH).to eq(vectors["contentHash"])
    end

    it "carries 54 patterns across 24 profiles, with 51 activation signals" do
      expect(R::PATTERNS.length).to eq(54)
      expect(R::COUNTRIES.length).to eq(24)
      expect(R::SIGNALS.length).to eq(51)
    end

    it "ships the 3 alwaysOn Australian patterns bundle 1.2.0 added (rule 1a)" do
      always_on = R::PATTERNS.select { |p| p[:always_on] }
      expect(always_on.map { |p| p[:name] }.sort).to eq(%w[au_abn au_medicare au_tfn])
      expect(C::ALWAYS_ON_PATTERNS.map { |p| p[:name] }.sort).to eq(%w[au_abn au_medicare au_tfn])
    end

    it "covers Indonesia, added in 1.1.0" do
      id = R::COUNTRIES.find { |c| c[:code] == "ID" }
      expect(id).not_to be_nil, "Indonesia is missing from the bundle"
      expect(id[:patterns]).to include("id_nik")
      nik = R::PATTERNS.find { |p| p[:name] == "id_nik" }
      expect(nik[:label]).to eq("NIK")
      expect(nik[:whole_word_keywords]).to include("nik")
    end

    it "reads its windows from the bundle, and they are not all the same number" do
      expect(C::KEYWORD_WINDOW_BEFORE).to eq(60)
      expect(C::KEYWORD_WINDOW_AFTER).to eq(40)
      expect(C::CONTEXT_WINDOW).to eq(60)
      expect(C::KEYWORD_WINDOW_AFTER).not_to eq(C::KEYWORD_WINDOW_BEFORE)
    end

    it "names a checksum function for every pattern that declares one" do
      R::PATTERNS.each do |p|
        next unless p[:checksum]

        expect(R::Checksums::FUNCTIONS[p[:checksum]]).to respond_to(:call), "#{p[:name]} -> #{p[:checksum]}"
      end
    end

    it "uses only the portable regex subset" do
      forbidden = { "(?=" => "lookahead", "(?!" => "negative lookahead", "(?<=" => "lookbehind",
                    "(?<!" => "negative lookbehind", '\p{' => "unicode property escape", "(?>" => "atomic group" }
      (R::PATTERNS.map { |p| p[:regex] } + R::SIGNALS.map { |s| s[:regex] }).each do |src|
        forbidden.each { |bad, why| expect(src).not_to include(bad), "#{src} uses #{why}" }
      end
    end
  end

  describe "per-pattern unit cases" do
    it "detects or rejects each sample as the cloud does" do
      by_name = R::PATTERNS.each_with_object({}) { |p, h| h[p[:name]] = p }
      expect(units).not_to be_empty
      units.each do |c|
        pattern = by_name[c["pattern"]]
        expect(pattern).not_to be_nil, "#{c['pattern']} is not in the bundle"
        hit = C.detect(c["input"], [pattern]).find { |m| m.name == c["pattern"] }
        if c["expectDetected"]
          expect(hit).not_to be_nil, "expected #{c['pattern']} to match #{c['input'].inspect}"
          expect(c["input"][hit.start_index...hit.end_index]).to eq(c["sample"])
          expect(hit.redaction).to eq(c["redaction"])
        else
          expect(hit).to be_nil, "expected #{c['pattern']} NOT to match #{c['input'].inspect}"
        end
      end
    end
  end

  describe "golden-snapshot parity" do
    it "reproduces the cloud on every corpus vector" do
      failures = []
      corpus.each do |c|
        regions = C.infer_regions(c["input"])
        matches = C.detect(c["input"])
        out = C.apply_redactions(c["input"], matches)
        failures << "#{c['id']} activation #{regions.inspect} != #{c['expectedRegions'].inspect}" if regions != c["expectedRegions"]
        failures << "#{c['id']} redaction #{out.inspect} != #{c['expectedOutput'].inspect}" if out != c["expectedOutput"]
        labels = matches.map(&:label).uniq
        names = matches.map(&:name).uniq
        failures << "#{c['id']} labels #{labels.inspect} != #{c['expectedLabels'].inspect}" if labels != c["expectedLabels"]
        failures << "#{c['id']} names #{names.inspect} != #{c['expectedNames'].inspect}" if names != c["expectedNames"]
      end
      expect(failures).to eq([])
      expect(corpus.length).to be > 500
    end

    it "adds no false positive to the business corpus" do
      expect(business.length).to be > 1500
      bad = business.reject { |c| C.detect(c["input"]).empty? }.map { |c| c["id"] }
      expect(bad).to eq([])
    end

    it "reproduces the cloud activation on every business-corpus line" do
      bad = business.reject { |c| C.infer_regions(c["input"]) == c["expectedRegions"] }.map { |c| c["id"] }
      expect(bad).to eq([])
    end

    it "diverges from the cloud only for the cloud-only L0 layer, since bundle 1.2.0 closed the AU gap" do
      diverged = vectors["cases"].select { |c| c["divergence"] }
      diverged.each do |c|
        expect(c["divergence"]).to match(/\AL0:/), c["id"]
      end
      # Bundle 1.2.0 ships au_tfn, au_abn and au_medicare as alwaysOn patterns
      # (rule 1a), so the BUNDLE GAP divergence bundle 1.1.0 carried is gone.
      gaps = diverged.select { |c| c["divergence"].start_with?("BUNDLE GAP:") }
      expect(gaps).to eq([])
    end

    it "never leaves a digit standing beside a redaction token" do
      bad = vectors["cases"].select do |c|
        redact(c["input"]) =~ /\d\[[A-Z_]+_REDACTED\]|\[[A-Z_]+_REDACTED\]\d/
      end.map { |c| c["id"] }
      expect(bad).to eq([])
    end

    it "never leaves a detected identifier in the output" do
      failures = []
      vectors["cases"].each do |c|
        matches = C.detect(c["input"])
        next if matches.empty?

        out = C.apply_redactions(c["input"], matches)
        matches.each do |m|
          raw = c["input"][m.start_index...m.end_index]
          failures << "#{c['id']}: #{raw.inspect} survived" if out.include?(raw)
        end
      end
      expect(failures).to eq([])
    end
  end

  describe "Indonesia — the rule the bundle added in 1.1.0" do
    it "detects the short spelling, which is a whole-word keyword only" do
      s = "NIK #{NIK} untuk pendaftaran rekening di Jakarta, Indonesia."
      expect(C.infer_regions(s)).to eq(["ID"])
      expect(redact(s)).to eq("NIK [NIK_REDACTED] untuk pendaftaran rekening di Jakarta, Indonesia.")
    end

    it "detects the long spelling, which is an ordinary substring keyword" do
      expect(redact("Nomor Induk Kependudukan #{NIK} untuk pendaftaran.")).to include("[NIK_REDACTED]")
    end

    it "does NOT open the gate on 'nik' inside an ordinary Indonesian word" do
      %w[teknik elektronik klinik pabrik piknik].each do |word|
        expect(C.detect("Faktur #{word} #{NIK} untuk pelanggan.")).to eq([]), "#{word} opened the gate"
      end
    end

    it "does not redact a bare NIK with no label" do
      expect(C.detect(NIK)).to eq([])
    end
  end

  describe "the rules 1.1.0 added to the SDK half of the contract" do
    it "rule 6: a checksum-failing identifier is redacted generically, not released" do
      out = redact("South African ID number 8001015009088 for the FICA check.")
      expect(out).not_to include("8001015009088")
      expect(out).to include("[NATIONAL_ID_REDACTED]")
    end

    it "rule 7: a column header is the context for a bare value cell" do
      csv = ["Name,CNIC,City", "Ali,42201-1234567-1,Karachi",
             "Sana,42201-7654321-2,Lahore", "Omar,42201-1111111-3,Multan"].join("\n")
      expect(C.table_scopes(csv)).not_to be_empty
      expect(redact(csv)).not_to include("42201-1234567-1")
    end

    it "rule 7: a generic header does NOT act as context" do
      csv = ["Name,Order ID Number,City", "Ali,42201-1234567-1,Karachi",
             "Sana,42201-7654321-2,Lahore", "Omar,42201-1111111-3,Multan"].join("\n")
      expect(C.detect(csv)).to eq([])
    end

    it "rule 7b: a commercial label closer than the identifier word closes the gate" do
      s = "Please do not send your CNIC. Use the job number 4220112345671."
      at = s.index("4220112345671")
      expect(C.labelled_as_reference?(s, at, at + 13, ["cnic"])).to be(true)
      expect(redact(s)).to include("4220112345671")
    end

    it "rule 7b can only ever close a gate, never open one" do
      expect(C.detect("Order 12345678901234 with no identifier word anywhere.")).to eq([])
    end

    it "rule 5: a country match supersedes a wider L0 range it contains" do
      s = "CPF 529.982.247-25 para a nota fiscal no Brasil."
      at = s.index("529.982.247-25")
      res = C.detect_with_ranges(s, nil, [[at - 1, at + 14]])
      expect(res[:matches].map(&:name)).to include("br_cpf")
      expect(res[:superseded].length).to eq(1)
    end

    it "whole-word matching respects a boundary at each end" do
      expect(C.has_whole_word_context_around?("nik 123", 4, 7, ["nik"])).to be(true)
      expect(C.has_whole_word_context_around?("teknik 123", 7, 10, ["nik"])).to be(false)
    end
  end

  describe "the 3 alwaysOn Australian patterns bundle 1.2.0 added (rule 1a)" do
    it "detects a valid TFN with its keyword, checksum passing" do
      s = "My tax file number is 876 543 210 for the ATO return."
      expect(C.infer_regions(s)).to eq(["AU"])
      matches = C.detect(s)
      expect(matches.map(&:name)).to eq(["au_tfn"])
      expect(redact(s)).to eq("My tax file number is [TFN_REDACTED] for the ATO return.")
    end

    it "falls back to a generic near-miss when a TFN's required checksum fails" do
      s = "My tax file number is 876 543 211 for the ATO return."
      matches = C.detect(s)
      expect(matches.map(&:name)).to eq(["national_id_near_miss"])
      expect(matches.map(&:label)).to eq(["NATIONAL_ID"])
      expect(redact(s)).to eq("My tax file number is [NATIONAL_ID_REDACTED] for the ATO return.")
    end

    it "detects a valid ABN with its keyword, checksum passing, even though ABN activates no region" do
      s = "Supplier ABN 51 824 753 556 appears on the Australian invoice."
      expect(C.infer_regions(s)).to eq([])
      matches = C.detect(s)
      expect(matches.map(&:name)).to eq(["au_abn"])
      expect(redact(s)).to eq("Supplier ABN [ABN_REDACTED] appears on the Australian invoice.")
    end

    it "an ABN's required checksum failing drops the match rather than falling back to a near-miss" do
      s = "Supplier ABN 51 824 753 557 appears on the Australian invoice."
      expect(C.detect(s)).to eq([])
      expect(redact(s)).to eq(s)
    end

    it "detects a valid Medicare number with its keyword" do
      s = "Patient Medicare number 2123 45670 1 for the bulk-billed visit."
      matches = C.detect(s)
      expect(matches.map(&:name)).to eq(["au_medicare"])
      expect(redact(s)).to eq("Patient Medicare number [MEDICARE_REDACTED] for the bulk-billed visit.")
    end

    it "still detects a Medicare number whose (community-sourced) checksum fails -- advisory, never a gate" do
      s = "Patient Medicare number 2123 45671 1 for the bulk-billed visit."
      matches = C.detect(s)
      expect(matches.map(&:name)).to eq(["au_medicare"])
      expect(redact(s)).to eq("Patient Medicare number [MEDICARE_REDACTED] for the bulk-billed visit.")
    end

    it "runs before an activated country pattern, so the activated pattern can still supersede it (rule 5)" do
      always_on_names = C::ALWAYS_ON_PATTERNS.map { |p| p[:name] }
      expect(C.patterns_for_regions(["AU"]).first(3).map { |p| p[:name] }).to eq(always_on_names)
    end

    it "does not redact a bare TFN, ABN or Medicare number with no keyword" do
      expect(C.detect("876 543 210")).to eq([])
      expect(C.detect("51 824 753 556")).to eq([])
      expect(C.detect("2123 45670 1")).to eq([])
    end
  end

  describe "PIIMatch#value" do
    it "returns the RAW matched value, not the redaction (breaking change from 0.x)" do
      s = "NIK #{NIK} untuk pendaftaran."
      m = C.detect(s).first
      expect(m.value).to eq(NIK)
      expect(m.redaction).to eq("[NIK_REDACTED]")
    end
  end
end
