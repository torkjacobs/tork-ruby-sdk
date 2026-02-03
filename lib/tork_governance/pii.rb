# frozen_string_literal: true

require 'set'

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
    attr_reader :has_pii, :types, :count, :matches, :redacted_text

    def initialize(has_pii:, types:, count:, matches:, redacted_text:)
      @has_pii = has_pii
      @types = types
      @count = count
      @matches = matches
      @redacted_text = redacted_text
    end

    alias has_pii? has_pii
  end

  # PII detector
  class PIIDetector
    def self.detect(text)
      matches = []
      types = Set.new
      redacted_text = text.dup

      PII_PATTERNS.each do |pii_type, config|
        pattern = config[:pattern]
        redaction = config[:redaction]

        text.scan(pattern) do |match|
          match_data = Regexp.last_match
          matches << PIIMatch.new(
            type: pii_type,
            value: match_data[0],
            start_index: match_data.begin(0),
            end_index: match_data.end(0)
          )
          types << pii_type
        end

        redacted_text = redacted_text.gsub(pattern, redaction)
      end

      PIIResult.new(
        has_pii: matches.any?,
        types: types.to_a,
        count: matches.size,
        matches: matches,
        redacted_text: redacted_text
      )
    end
  end
end
