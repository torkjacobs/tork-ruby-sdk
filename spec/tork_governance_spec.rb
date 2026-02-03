# frozen_string_literal: true

require "spec_helper"

# Comprehensive tests for Tork Governance Ruby SDK
# Matches Python SDK test coverage

RSpec.describe TorkGovernance do
  # ==========================================================================
  # Version Tests
  # ==========================================================================

  describe "VERSION" do
    it "is defined" do
      expect(TorkGovernance::VERSION).not_to be_nil
    end

    it "follows semantic versioning" do
      expect(TorkGovernance::VERSION).to match(/^\d+\.\d+\.\d+/)
    end
  end

  # ==========================================================================
  # ACTIONS Tests
  # ==========================================================================

  describe "ACTIONS" do
    it "includes allow action" do
      expect(TorkGovernance::ACTIONS[:allow]).to eq("allow")
    end

    it "includes deny action" do
      expect(TorkGovernance::ACTIONS[:deny]).to eq("deny")
    end

    it "includes redact action" do
      expect(TorkGovernance::ACTIONS[:redact]).to eq("redact")
    end

    it "includes escalate action" do
      expect(TorkGovernance::ACTIONS[:escalate]).to eq("escalate")
    end

    it "has 4 actions" do
      expect(TorkGovernance::ACTIONS.keys.length).to eq(4)
    end
  end

  # ==========================================================================
  # Module Methods Tests
  # ==========================================================================

  describe ".govern" do
    it "returns a GovernResult" do
      result = TorkGovernance.govern("Hello world")
      expect(result).to be_a(TorkGovernance::GovernResult)
    end

    it "allows clean text" do
      result = TorkGovernance.govern("Hello world")
      expect(result.action).to eq("allow")
    end

    it "redacts text with PII" do
      result = TorkGovernance.govern("My SSN is 123-45-6789")
      expect(result.action).to eq("redact")
      expect(result.output).to eq("My SSN is [SSN_REDACTED]")
    end
  end

  describe ".client" do
    it "returns a Client instance" do
      expect(TorkGovernance.client).to be_a(TorkGovernance::Client)
    end

    it "returns the same client on multiple calls" do
      client1 = TorkGovernance.client
      client2 = TorkGovernance.client
      expect(client1).to eq(client2)
    end
  end

  describe ".configure" do
    it "creates a new client with custom settings" do
      TorkGovernance.configure(policy_version: "2.0.0")
      expect(TorkGovernance.client.policy_version).to eq("2.0.0")
    end
  end
end

# ==========================================================================
# PIIType Tests
# ==========================================================================

RSpec.describe TorkGovernance::PIIType do
  it "defines SSN" do
    expect(TorkGovernance::PIIType::SSN).to eq("ssn")
  end

  it "defines CREDIT_CARD" do
    expect(TorkGovernance::PIIType::CREDIT_CARD).to eq("credit_card")
  end

  it "defines EMAIL" do
    expect(TorkGovernance::PIIType::EMAIL).to eq("email")
  end

  it "defines PHONE" do
    expect(TorkGovernance::PIIType::PHONE).to eq("phone")
  end

  it "defines ADDRESS" do
    expect(TorkGovernance::PIIType::ADDRESS).to eq("address")
  end

  it "defines IP_ADDRESS" do
    expect(TorkGovernance::PIIType::IP_ADDRESS).to eq("ip_address")
  end

  it "defines DATE_OF_BIRTH" do
    expect(TorkGovernance::PIIType::DATE_OF_BIRTH).to eq("date_of_birth")
  end
end

# ==========================================================================
# PII_PATTERNS Tests
# ==========================================================================

RSpec.describe "TorkGovernance::PII_PATTERNS" do
  it "has SSN pattern" do
    expect(TorkGovernance::PII_PATTERNS[TorkGovernance::PIIType::SSN]).not_to be_nil
  end

  it "has EMAIL pattern" do
    expect(TorkGovernance::PII_PATTERNS[TorkGovernance::PIIType::EMAIL]).not_to be_nil
  end

  it "has correct SSN redaction" do
    expect(TorkGovernance::PII_PATTERNS[TorkGovernance::PIIType::SSN][:redaction]).to eq("[SSN_REDACTED]")
  end

  it "has correct EMAIL redaction" do
    expect(TorkGovernance::PII_PATTERNS[TorkGovernance::PIIType::EMAIL][:redaction]).to eq("[EMAIL_REDACTED]")
  end
end

# ==========================================================================
# PIIMatch Tests
# ==========================================================================

RSpec.describe TorkGovernance::PIIMatch do
  let(:match) do
    TorkGovernance::PIIMatch.new(
      type: TorkGovernance::PIIType::SSN,
      value: "123-45-6789",
      start_index: 10,
      end_index: 21
    )
  end

  it "stores the type" do
    expect(match.type).to eq(TorkGovernance::PIIType::SSN)
  end

  it "stores the value" do
    expect(match.value).to eq("123-45-6789")
  end

  it "stores the start index" do
    expect(match.start_index).to eq(10)
  end

  it "stores the end index" do
    expect(match.end_index).to eq(21)
  end
end

# ==========================================================================
# PIIResult Tests
# ==========================================================================

RSpec.describe TorkGovernance::PIIResult do
  let(:result) do
    TorkGovernance::PIIResult.new(
      has_pii: true,
      types: [TorkGovernance::PIIType::SSN],
      count: 1,
      matches: [],
      redacted_text: "My SSN is [SSN_REDACTED]"
    )
  end

  it "stores has_pii" do
    expect(result.has_pii).to be true
  end

  it "provides has_pii? method" do
    expect(result.has_pii?).to be true
  end

  it "stores types" do
    expect(result.types).to include(TorkGovernance::PIIType::SSN)
  end

  it "stores count" do
    expect(result.count).to eq(1)
  end

  it "stores redacted_text" do
    expect(result.redacted_text).to eq("My SSN is [SSN_REDACTED]")
  end
end

# ==========================================================================
# PIIDetector Tests
# ==========================================================================

RSpec.describe TorkGovernance::PIIDetector do
  describe ".detect" do
    it "detects SSN" do
      result = TorkGovernance::PIIDetector.detect("My SSN is 123-45-6789")
      expect(result.has_pii?).to be true
      expect(result.types).to include(TorkGovernance::PIIType::SSN)
    end

    it "detects email" do
      result = TorkGovernance::PIIDetector.detect("Contact me at john@example.com")
      expect(result.has_pii?).to be true
      expect(result.types).to include(TorkGovernance::PIIType::EMAIL)
    end

    it "detects credit card" do
      result = TorkGovernance::PIIDetector.detect("Card: 4111-1111-1111-1111")
      expect(result.has_pii?).to be true
      expect(result.types).to include(TorkGovernance::PIIType::CREDIT_CARD)
    end

    it "detects phone number" do
      result = TorkGovernance::PIIDetector.detect("Call me at 555-123-4567")
      expect(result.has_pii?).to be true
      expect(result.types).to include(TorkGovernance::PIIType::PHONE)
    end

    it "detects IP address" do
      result = TorkGovernance::PIIDetector.detect("Server IP: 192.168.1.1")
      expect(result.has_pii?).to be true
      expect(result.types).to include(TorkGovernance::PIIType::IP_ADDRESS)
    end

    it "detects date of birth" do
      result = TorkGovernance::PIIDetector.detect("DOB: 01/15/1990")
      expect(result.has_pii?).to be true
      expect(result.types).to include(TorkGovernance::PIIType::DATE_OF_BIRTH)
    end

    it "does not detect PII in clean text" do
      result = TorkGovernance::PIIDetector.detect("Hello world")
      expect(result.has_pii?).to be false
      expect(result.count).to eq(0)
    end

    it "detects multiple PII types" do
      result = TorkGovernance::PIIDetector.detect("SSN: 123-45-6789, Email: test@test.com")
      expect(result.has_pii?).to be true
      expect(result.types).to include(TorkGovernance::PIIType::SSN)
      expect(result.types).to include(TorkGovernance::PIIType::EMAIL)
      expect(result.count).to eq(2)
    end

    it "redacts SSN" do
      result = TorkGovernance::PIIDetector.detect("My SSN is 123-45-6789")
      expect(result.redacted_text).to eq("My SSN is [SSN_REDACTED]")
    end

    it "redacts email" do
      result = TorkGovernance::PIIDetector.detect("Contact: john@example.com")
      expect(result.redacted_text).to eq("Contact: [EMAIL_REDACTED]")
    end

    it "redacts credit card" do
      result = TorkGovernance::PIIDetector.detect("Card: 4111-1111-1111-1111")
      expect(result.redacted_text).to eq("Card: [CARD_REDACTED]")
    end

    it "redacts multiple instances" do
      result = TorkGovernance::PIIDetector.detect("SSN: 123-45-6789, Another: 987-65-4321")
      expect(result.count).to eq(2)
      expect(result.redacted_text).to include("[SSN_REDACTED]")
    end

    it "handles empty string" do
      result = TorkGovernance::PIIDetector.detect("")
      expect(result.has_pii?).to be false
      expect(result.count).to eq(0)
      expect(result.redacted_text).to eq("")
    end

    it "returns matches with correct indices" do
      result = TorkGovernance::PIIDetector.detect("SSN: 123-45-6789")
      expect(result.matches).not_to be_empty
      expect(result.matches.first.start_index).to be >= 0
      expect(result.matches.first.end_index).to be > result.matches.first.start_index
    end
  end
end

# ==========================================================================
# Client Tests
# ==========================================================================

RSpec.describe TorkGovernance::Client do
  let(:client) { TorkGovernance::Client.new }

  describe "#initialize" do
    it "creates with default config" do
      expect(client.policy_version).to eq("1.0.0")
      expect(client.default_action).to eq("redact")
    end

    it "creates with custom policy version" do
      custom = TorkGovernance::Client.new(policy_version: "2.0.0")
      expect(custom.policy_version).to eq("2.0.0")
    end

    it "creates with custom default action" do
      custom = TorkGovernance::Client.new(default_action: TorkGovernance::ACTIONS[:deny])
      expect(custom.default_action).to eq("deny")
    end
  end

  describe "#govern" do
    it "returns allow action for clean text" do
      result = client.govern("Hello world")
      expect(result.action).to eq("allow")
      expect(result.output).to eq("Hello world")
    end

    it "returns redact action for text with PII" do
      result = client.govern("My SSN is 123-45-6789")
      expect(result.action).to eq("redact")
      expect(result.output).to eq("My SSN is [SSN_REDACTED]")
    end

    it "includes receipt in result" do
      result = client.govern("test")
      expect(result.receipt).not_to be_nil
      expect(result.receipt.id).to start_with("rcpt_")
    end

    it "includes PII result" do
      result = client.govern("SSN: 123-45-6789")
      expect(result.pii).not_to be_nil
      expect(result.pii.has_pii?).to be true
    end

    it "generates receipt with correct hashes" do
      result = client.govern("test")
      expect(result.receipt.input_hash).to start_with("sha256:")
      expect(result.receipt.output_hash).to start_with("sha256:")
    end

    it "respects deny action configuration" do
      deny_client = TorkGovernance::Client.new(default_action: TorkGovernance::ACTIONS[:deny])
      result = deny_client.govern("SSN: 123-45-6789")
      expect(result.action).to eq("deny")
      expect(result.output).to eq("SSN: 123-45-6789")
    end

    it "handles multiple governs" do
      client.govern("test1")
      client.govern("test2")
      expect(client.stats[:total_calls]).to eq(2)
    end
  end

  describe "#stats" do
    it "returns zero stats initially" do
      expect(client.stats[:total_calls]).to eq(0)
      expect(client.stats[:total_pii_detected]).to eq(0)
    end

    it "tracks total calls" do
      client.govern("test")
      client.govern("test2")
      expect(client.stats[:total_calls]).to eq(2)
    end

    it "tracks PII detected" do
      client.govern("SSN: 123-45-6789")
      client.govern("clean text")
      expect(client.stats[:total_pii_detected]).to eq(1)
    end

    it "tracks action counts" do
      client.govern("SSN: 123-45-6789")
      client.govern("clean text")
      expect(client.stats[:action_counts]["redact"]).to eq(1)
      expect(client.stats[:action_counts]["allow"]).to eq(1)
    end
  end

  describe "#reset_stats" do
    it "resets all stats to zero" do
      client.govern("SSN: 123-45-6789")
      client.govern("test")
      client.reset_stats
      expect(client.stats[:total_calls]).to eq(0)
      expect(client.stats[:total_pii_detected]).to eq(0)
    end

    it "resets action counts" do
      client.govern("SSN: 123-45-6789")
      client.reset_stats
      expect(client.stats[:action_counts]["redact"]).to eq(0)
    end
  end
end

# ==========================================================================
# GovernResult Tests
# ==========================================================================

RSpec.describe TorkGovernance::GovernResult do
  let(:client) { TorkGovernance::Client.new }

  describe "#allowed?" do
    it "returns true for allowed result" do
      result = client.govern("Hello world")
      expect(result.allowed?).to be true
    end

    it "returns false for redacted result" do
      result = client.govern("SSN: 123-45-6789")
      expect(result.allowed?).to be false
    end
  end

  describe "#redacted?" do
    it "returns true for redacted result" do
      result = client.govern("SSN: 123-45-6789")
      expect(result.redacted?).to be true
    end

    it "returns false for allowed result" do
      result = client.govern("Hello world")
      expect(result.redacted?).to be false
    end
  end

  describe "#to_h" do
    it "converts to hash" do
      result = client.govern("test")
      hash = result.to_h
      expect(hash).to have_key(:action)
      expect(hash).to have_key(:output)
      expect(hash).to have_key(:pii)
      expect(hash).to have_key(:receipt)
    end
  end
end

# ==========================================================================
# Receipt Tests
# ==========================================================================

RSpec.describe TorkGovernance::Receipt do
  describe ".generate" do
    let(:receipt) do
      TorkGovernance::Receipt.generate(
        input: "test",
        output: "test",
        action: "allow",
        pii_types: [],
        pii_count: 0,
        policy_version: "1.0.0",
        processing_time_ns: 1000
      )
    end

    it "generates unique IDs" do
      receipt1 = TorkGovernance::Receipt.generate(
        input: "test", output: "test", action: "allow",
        pii_types: [], pii_count: 0, policy_version: "1.0.0", processing_time_ns: 1000
      )
      receipt2 = TorkGovernance::Receipt.generate(
        input: "test", output: "test", action: "allow",
        pii_types: [], pii_count: 0, policy_version: "1.0.0", processing_time_ns: 1000
      )
      expect(receipt1.id).not_to eq(receipt2.id)
    end

    it "has rcpt_ prefix" do
      expect(receipt.id).to start_with("rcpt_")
    end

    it "has timestamp" do
      expect(receipt.timestamp).not_to be_nil
    end

    it "has input hash" do
      expect(receipt.input_hash).to start_with("sha256:")
    end

    it "has output hash" do
      expect(receipt.output_hash).to start_with("sha256:")
    end

    it "has action" do
      expect(receipt.action).to eq("allow")
    end

    it "has policy version" do
      expect(receipt.policy_version).to eq("1.0.0")
    end

    it "has processing time" do
      expect(receipt.processing_time_ns).to eq(1000)
    end
  end

  describe ".hash_text" do
    it "generates sha256 prefixed hash" do
      hash = TorkGovernance::Receipt.hash_text("test")
      expect(hash).to start_with("sha256:")
    end

    it "generates consistent hashes" do
      hash1 = TorkGovernance::Receipt.hash_text("test")
      hash2 = TorkGovernance::Receipt.hash_text("test")
      expect(hash1).to eq(hash2)
    end

    it "generates different hashes for different inputs" do
      hash1 = TorkGovernance::Receipt.hash_text("test1")
      hash2 = TorkGovernance::Receipt.hash_text("test2")
      expect(hash1).not_to eq(hash2)
    end

    it "generates 64 character hex hash after prefix" do
      hash = TorkGovernance::Receipt.hash_text("test")
      hex_part = hash.sub("sha256:", "")
      expect(hex_part.length).to eq(64)
    end
  end

  describe "#verify" do
    let(:receipt) do
      TorkGovernance::Receipt.generate(
        input: "test", output: "test", action: "allow",
        pii_types: [], pii_count: 0, policy_version: "1.0.0", processing_time_ns: 1000
      )
    end

    it "verifies correct input/output" do
      expect(receipt.verify("test", "test")).to be true
    end

    it "fails verification with wrong input" do
      expect(receipt.verify("wrong", "test")).to be false
    end

    it "fails verification with wrong output" do
      expect(receipt.verify("test", "wrong")).to be false
    end
  end

  describe "#to_h" do
    let(:receipt) do
      TorkGovernance::Receipt.generate(
        input: "test", output: "test", action: "allow",
        pii_types: [], pii_count: 0, policy_version: "1.0.0", processing_time_ns: 1000
      )
    end

    it "converts to hash" do
      hash = receipt.to_h
      expect(hash).to have_key(:id)
      expect(hash).to have_key(:timestamp)
      expect(hash).to have_key(:input_hash)
      expect(hash).to have_key(:output_hash)
      expect(hash).to have_key(:action)
    end
  end
end

# ==========================================================================
# Edge Cases Tests
# ==========================================================================

RSpec.describe "Edge Cases" do
  let(:client) { TorkGovernance::Client.new }

  it "handles long text" do
    long_text = "A" * 100_000
    result = client.govern(long_text)
    expect(result.action).to eq("allow")
  end

  it "handles unicode" do
    result = client.govern("Hello \u4e16\u754c, SSN: 123-45-6789")
    expect(result.pii.has_pii?).to be true
  end

  it "handles special characters" do
    result = client.govern("Special chars: !@#$%^&*()")
    expect(result.action).to eq("allow")
  end

  it "handles newlines" do
    result = client.govern("Line1\nLine2\nSSN: 123-45-6789")
    expect(result.pii.has_pii?).to be true
  end

  it "handles tabs" do
    result = client.govern("Tab\there\tSSN: 123-45-6789")
    expect(result.pii.has_pii?).to be true
  end

  it "handles repeated governs" do
    100.times do |i|
      result = client.govern("Test #{i}")
      expect(result.receipt).not_to be_nil
    end
    expect(client.stats[:total_calls]).to eq(100)
  end

  it "handles empty string" do
    result = client.govern("")
    expect(result.action).to eq("allow")
  end

  it "handles adjacent PII" do
    result = client.govern("123-45-6789 987-65-4321")
    expect(result.pii.count).to eq(2)
  end
end
