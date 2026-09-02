# frozen_string_literal: true

require "spec_helper"

# Guards SDK-DECLARED-PII-TYPES-WITHOUT-PATTERNS-ACROSS-SDKS (P1): every PII
# type this SDK declares must have a live pattern in PII_PATTERNS. Fails if a
# future PIIType constant is added without a matching pattern entry.
RSpec.describe "PIIType / PII_PATTERNS parity" do
  let(:declared_types) do
    TorkGovernance::PIIType.constants.map { |c| TorkGovernance::PIIType.const_get(c) }
  end

  it "has a live PII_PATTERNS entry for every declared PIIType" do
    missing = declared_types.reject { |type| TorkGovernance::PII_PATTERNS.key?(type) }
    expect(missing).to eq([])
  end

  it "has a non-empty pattern and redaction label for every declared type" do
    declared_types.each do |type|
      config = TorkGovernance::PII_PATTERNS[type]
      expect(config[:pattern]).to be_a(Regexp)
      expect(config[:redaction]).to be_a(String)
      expect(config[:redaction]).not_to be_empty
    end
  end

  # TIER 1 parity: this SDK ships the same 10-type basic vocabulary as the
  # JS SDK, with JS-identical labels. It does not claim the Python SDK's
  # regional/industry tier.
  it "matches the JS SDK's Tier 1 10-type vocabulary with identical labels" do
    js_tier1_types = %w[
      ssn credit_card email phone address ip_address date_of_birth
      passport drivers_license bank_account
    ].sort
    expect(declared_types.sort).to eq(js_tier1_types)
  end
end
