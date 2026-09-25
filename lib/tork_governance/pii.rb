# frozen_string_literal: true

require 'set'

require_relative 'pii/country'

module TorkGovernance
  # PII types
  module PIIType
    SSN = "ssn"
    CREDIT_CARD = "credit_card"
    EMAIL = "email"
    PHONE = "phone"
    ADDRESS = "address"
    IP_ADDRESS = "ip_address"
    DATE_OF_BIRTH = "date_of_birth"
    PASSPORT = "passport"
    DRIVERS_LICENSE = "drivers_license"
    BANK_ACCOUNT = "bank_account"
  end

  # PII detection patterns
  PII_PATTERNS = {
    PIIType::SSN => {
      pattern: /\b\d{3}-\d{2}-\d{4}\b/,
      redaction: "[SSN_REDACTED]"
    },
    PIIType::CREDIT_CARD => {
      pattern: /\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/,
      redaction: "[CARD_REDACTED]"
    },
    PIIType::EMAIL => {
      pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/,
      redaction: "[EMAIL_REDACTED]"
    },
    PIIType::PHONE => {
      pattern: /\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/,
      redaction: "[PHONE_REDACTED]"
    },
    PIIType::ADDRESS => {
      pattern: /\b\d{1,5}\s+\w+(?:\s+\w+)*\s+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|Court|Ct|Way|Place|Pl)\b/i,
      redaction: "[ADDRESS_REDACTED]"
    },
    PIIType::IP_ADDRESS => {
      pattern: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/,
      redaction: "[IP_REDACTED]"
    },
    PIIType::DATE_OF_BIRTH => {
      pattern: /\b(?:0[1-9]|1[0-2])\/(?:0[1-9]|[12]\d|3[01])\/(?:19|20)\d{2}\b/,
      redaction: "[DOB_REDACTED]"
    },
    PIIType::PASSPORT => {
      pattern: /\b[A-Z]{1,2}\d{6,9}\b/,
      redaction: "[PASSPORT_REDACTED]"
    },
    PIIType::DRIVERS_LICENSE => {
      pattern: /\b[A-Z]\d{7,14}\b/,
      redaction: "[DL_REDACTED]"
    },
    PIIType::BANK_ACCOUNT => {
      pattern: /\b\d{8,17}\b/,
      redaction: "[ACCOUNT_REDACTED]"
    }
  }.freeze

  # PII match result
  class PIIMatch
    attr_reader :type, :value, :start_index, :end_index

    def initialize(type:, value:, start_index:, end_index:)
      @type = type
      @value = value
      @start_index = start_index
      @end_index = end_index
    end
  end

  # PII detection result
  class PIIResult
    attr_reader :has_pii, :types, :count, :matches, :redacted_text,
                :country_matches, :country_labels, :regions

    def initialize(has_pii:, types:, count:, matches:, redacted_text:,
                   country_matches: [], country_labels: [], regions: [])
      @has_pii = has_pii
      @types = types
      @count = count
      @matches = matches
      @redacted_text = redacted_text
      # Country-registry detections, kept separate from +matches+ so the ten
      # L0 type symbols stay the closed set they have always been.
      @country_matches = country_matches
      # Redaction labels of those matches, e.g. "NATIONAL_ID".
      @country_labels = country_labels
      # Country profiles the text activated, in registry order.
      @regions = regions
    end

    alias has_pii? has_pii
  end

  # PII detector
  class PIIDetector
    # Detect PII in +text+.
    #
    # +regions+ forces a set of country profiles on, case-insensitively; nil or
    # [] infers them from the content.
    #
    # REDACTION IS ONE PASS. Until 0.3.0 each type was redacted with its own
    # +gsub+ over text a previous type had already rewritten, while +matches+
    # carried indices into the ORIGINAL text. Two types matching overlapping
    # spans could leave half an identifier standing beside a redaction token --
    # digits exposed in output the caller had been told was redacted. Every
    # match is now collected against the original text, overlaps are resolved
    # before anything is rewritten, and the surviving spans are spliced right to
    # left in a single pass.
    def self.detect(text, regions = nil)
      l0 = []
      PII_PATTERNS.each do |pii_type, config|
        pattern = config[:pattern]
        redaction = config[:redaction]
        pos = 0
        while (m = pattern.match(text, pos))
          start_index = m.begin(0)
          end_index = m.end(0)
          pos = end_index > start_index ? end_index : start_index + 1
          next if end_index == start_index

          l0 << {
            match: PIIMatch.new(
              type: pii_type,
              value: m[0],
              start_index: start_index,
              end_index: end_index
            ),
            redaction: redaction
          }
        end
      end

      active_regions =
        if regions.is_a?(Array) && !regions.empty?
          regions.map(&:upcase)
        else
          Tork::Governance::Pii::Country.infer_regions(text)
        end

      country_matches = Tork::Governance::Pii::Country.detect(
        text, Tork::Governance::Pii::Country.patterns_for_regions(active_regions)
      )

      # Resolve overlaps before anything is rewritten. A country identifier
      # supersedes any L0 span it fully contains -- the cloud does the same,
      # which is how a Saudi national ID stops coming back as [PHONE_REDACTED].
      claimed = country_matches.map { |c| [c.start_index, c.end_index] }
      spans = country_matches.map do |c|
        Tork::Governance::Pii::Country::RedactionSpan.new(
          start_index: c.start_index, end_index: c.end_index, redaction: c.redaction
        )
      end

      matches = []
      types = Set.new

      l0.each do |hit|
        m = hit[:match]
        start_index = m.start_index
        end_index = m.end_index
        overlapping = claimed.select { |(rs, re)| start_index < re && end_index > rs }

        unless overlapping.empty?
          swallows_all = overlapping.all? do |(rs, re)|
            cs, ce = Tork::Governance::Pii::Country.trimmed_core(text, rs, re)
            start_index <= cs && end_index >= ce
          end
          next unless swallows_all

          # An L0 span that fully contains a country span still loses: the
          # country label is the more specific claim.
          hits_country = overlapping.any? do |(rs, re)|
            country_matches.any? { |c| c.start_index == rs && c.end_index == re }
          end
          next if hits_country

          overlapping.each do |o|
            claimed.delete(o)
            spans.reject! { |sp| sp.start_index == o[0] && sp.end_index == o[1] }
          end
        end

        claimed << [start_index, end_index]
        spans << Tork::Governance::Pii::Country::RedactionSpan.new(
          start_index: start_index, end_index: end_index, redaction: hit[:redaction]
        )
        matches << m
        types << m.type
      end

      matches.sort_by!(&:start_index)

      PIIResult.new(
        has_pii: matches.any? || country_matches.any?,
        types: types.to_a,
        count: matches.size + country_matches.size,
        matches: matches,
        redacted_text: Tork::Governance::Pii::Country.apply_redactions(text, spans),
        country_matches: country_matches,
        country_labels: country_matches.map(&:label).uniq,
        regions: active_regions
      )
    end
  end
end
