# frozen_string_literal: true

require "spec_helper"

# Every declared PIIType needs a working detection pattern, proven by a
# positive and a negative example (SDK-DECLARED-PII-TYPES-WITHOUT-PATTERNS).
RSpec.describe "per-type PII detection" do
  EXAMPLES = {
    TorkGovernance::PIIType::SSN => ["My SSN is 123-45-6789", "ref 12-345-678"],
    TorkGovernance::PIIType::CREDIT_CARD => ["Card: 4111-1111-1111-1111", "Card: 4111-1111-11"],
    TorkGovernance::PIIType::EMAIL => ["mail john@example.com", "mail john at example"],
    TorkGovernance::PIIType::PHONE => ["Call 555-123-4567", "Call 555-12"],
    TorkGovernance::PIIType::ADDRESS => ["Lives at 42 Wallaby Way", "Lives at the Wallaby"],
    TorkGovernance::PIIType::IP_ADDRESS => ["Host 192.168.1.1", "Host 999.999.999.999"],
    TorkGovernance::PIIType::DATE_OF_BIRTH => ["DOB 01/15/1990", "DOB 13/45/1990"],
    TorkGovernance::PIIType::PASSPORT => ["Passport AB1234567", "Passport AB12"],
    TorkGovernance::PIIType::DRIVERS_LICENSE => ["Licence D12345678", "Licence D123"],
    TorkGovernance::PIIType::BANK_ACCOUNT => ["Account 123456789012", "Account 1234567"]
  }.freeze

  it "covers every declared type" do
    declared = TorkGovernance::PIIType.constants.map { |c| TorkGovernance::PIIType.const_get(c) }
    expect(EXAMPLES.keys.sort).to eq(declared.sort)
  end

  EXAMPLES.each do |type, (positive, negative)|
    it "#{type}: matches the positive example" do
      expect(TorkGovernance::PIIDetector.detect(positive, []).types).to include(type)
    end

    it "#{type}: does not match the negative example" do
      expect(TorkGovernance::PIIDetector.detect(negative, []).types).not_to include(type)
    end
  end
end
