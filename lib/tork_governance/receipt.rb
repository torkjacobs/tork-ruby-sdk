# frozen_string_literal: true

require "securerandom"
require "digest"
require "time"

module TorkGovernance
  # Cryptographic governance receipt
  class Receipt
    attr_reader :id, :timestamp, :input_hash, :output_hash, :action,
                :pii_types, :pii_count, :policy_version, :processing_time_ns

    def initialize(
      id:,
      timestamp:,
      input_hash:,
      output_hash:,
      action:,
      pii_types:,
      pii_count:,
      policy_version:,
      processing_time_ns:
    )
      @id = id
      @timestamp = timestamp
      @input_hash = input_hash
      @output_hash = output_hash
      @action = action
      @pii_types = pii_types
      @pii_count = pii_count
      @policy_version = policy_version
      @processing_time_ns = processing_time_ns
    end

    # Generate a receipt from governance operation
    def self.generate(input:, output:, action:, pii_types:, pii_count:, policy_version:, processing_time_ns:)
      new(
        id: "rcpt_#{SecureRandom.uuid.delete('-')[0, 32]}",
        timestamp: Time.now.utc.iso8601(6),
        input_hash: hash_text(input),
        output_hash: hash_text(output),
        action: action,
        pii_types: pii_types,
        pii_count: pii_count,
        policy_version: policy_version,
        processing_time_ns: processing_time_ns
      )
    end

    # Verify receipt against input/output
    def verify(input, output)
      input_hash == self.class.hash_text(input) &&
        output_hash == self.class.hash_text(output)
    end

    # Convert to hash for JSON serialization
    def to_h
      {
        id: id,
        timestamp: timestamp,
        input_hash: input_hash,
        output_hash: output_hash,
        action: action,
        pii_types: pii_types,
        pii_count: pii_count,
        policy_version: policy_version,
        processing_time_ns: processing_time_ns
      }
    end

    def self.hash_text(text)
      "sha256:#{Digest::SHA256.hexdigest(text)}"
    end
  end
end
