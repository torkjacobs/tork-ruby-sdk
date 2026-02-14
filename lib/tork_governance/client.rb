# frozen_string_literal: true

module TorkGovernance
  # Governance result
  class GovernResult
    attr_reader :action, :output, :pii, :receipt, :region, :industry

    def initialize(action:, output:, pii:, receipt:, region: nil, industry: nil)
      @action = action
      @output = output
      @pii = pii
      @receipt = receipt
      @region = region
      @industry = industry
    end

    def allowed?
      action == ACTIONS[:allow]
    end

    def denied?
      action == ACTIONS[:deny]
    end

    def redacted?
      action == ACTIONS[:redact]
    end

    def to_h
      {
        action: action,
        output: output,
        pii: {
          has_pii: pii.has_pii?,
          types: pii.types,
          count: pii.count
        },
        receipt: receipt.to_h
      }
    end
  end

  # Main Tork governance client
  class Client
    attr_reader :api_key, :policy_version, :default_action, :stats

    def initialize(api_key: nil, policy_version: "1.0.0", default_action: ACTIONS[:redact])
      @api_key = api_key
      @policy_version = policy_version
      @default_action = default_action
      @stats = {
        total_calls: 0,
        total_pii_detected: 0,
        total_processing_ns: 0,
        action_counts: Hash.new(0)
      }
    end

    # Apply governance to content
    #
    # @param input [String] the content to govern
    # @param region [Array<String>, nil] optional regional PII profiles (e.g. ["ae", "in"])
    # @param industry [String, nil] optional industry profile (e.g. "healthcare", "finance", "legal")
    # @return [GovernResult] the governance result
    #
    # @example
    #   client = TorkGovernance::Client.new
    #   result = client.govern("My email is test@example.com")
    #   puts result.output # "My email is [EMAIL_REDACTED]"
    #   puts result.receipt.id # "rcpt_..."
    def govern(input, region: nil, industry: nil)
      start_time = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)

      # Detect PII
      pii = PIIDetector.detect(input)

      # Determine action and output
      if pii.has_pii?
        action = default_action
        output = action == ACTIONS[:redact] ? pii.redacted_text : input
      else
        action = ACTIONS[:allow]
        output = input
      end

      processing_time_ns = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond) - start_time

      # Generate receipt
      receipt = Receipt.generate(
        input: input,
        output: output,
        action: action,
        pii_types: pii.types,
        pii_count: pii.count,
        policy_version: policy_version,
        processing_time_ns: processing_time_ns
      )

      # Update stats
      @stats[:total_calls] += 1
      @stats[:total_pii_detected] += 1 if pii.has_pii?
      @stats[:total_processing_ns] += processing_time_ns
      @stats[:action_counts][action] += 1

      GovernResult.new(
        action: action,
        output: output,
        pii: pii,
        receipt: receipt,
        region: region,
        industry: industry
      )
    end

    # Reset statistics
    def reset_stats
      @stats = {
        total_calls: 0,
        total_pii_detected: 0,
        total_processing_ns: 0,
        action_counts: Hash.new(0)
      }
    end
  end
end
