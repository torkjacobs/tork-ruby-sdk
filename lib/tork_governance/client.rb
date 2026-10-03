# frozen_string_literal: true

module TorkGovernance
  # Governance result
  class GovernResult
    attr_reader :action, :output, :pii, :receipt, :region, :industry, :session_context

    def initialize(action:, output:, pii:, receipt:, region: nil, industry: nil, session_context: nil)
      @action = action
      @output = output
      @pii = pii
      @receipt = receipt
      @region = region
      @industry = industry
      @session_context = session_context
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
      }.tap { |h| h[:session_context] = session_context if session_context }
    end
  end

  # What Client#scan_tool_result returns: the pure scan result (sanitized,
  # findings, blocked, reason -- exactly the shape of
  # ToolResultScan.scan_tool_result's own return value, so either form can
  # be consumed by the same code), plus the receipt recording it.
  class GovernedToolResultScanResult
    attr_reader :sanitized, :findings, :blocked, :reason, :receipt

    def initialize(sanitized:, findings:, blocked:, receipt:, reason: nil)
      @sanitized = sanitized
      @findings = findings
      @blocked = blocked
      @reason = reason
      @receipt = receipt
    end

    alias blocked? blocked
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
    # @param agent_id [String, nil] identifier for the agent making the call
    # @param agent_role [String, nil] role of the agent: "planner", "worker", or "judge"
    # @param session_id [String, nil] groups all calls from the same agent session
    # @param session_turn [Integer, nil] position in the conversation (1, 2, 3...)
    # @return [GovernResult] the governance result
    #
    # @example
    #   client = TorkGovernance::Client.new
    #   result = client.govern("My email is test@example.com")
    #   puts result.output # "My email is [EMAIL_REDACTED]"
    #   puts result.receipt.id # "rcpt_..."
    def govern(input, region: nil, industry: nil, agent_id: nil, agent_role: nil, session_id: nil, session_turn: nil)
      unless session_turn.nil? || session_turn.is_a?(Integer)
        raise ArgumentError, "session_turn must be an Integer"
      end

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

      # Build session context if any agent/session fields are provided
      session_context = nil
      unless [agent_id, agent_role, session_id, session_turn].all?(&:nil?)
        session_context = {
          agent_id: agent_id,
          agent_role: agent_role,
          session_id: session_id,
          session_turn: session_turn
        }.compact
      end

      GovernResult.new(
        action: action,
        output: output,
        pii: pii,
        receipt: receipt,
        region: region,
        industry: industry,
        session_context: session_context
      )
    end

    # Scan a tool result (MCP server response, or any external system's
    # output) for PII and prompt injection BEFORE it is appended to model
    # context, and record the scan on a receipt.
    #
    # The scan itself is the pure ToolResultScan.scan_tool_result -- on-device,
    # synchronous, zero network calls, using the same PII detector as
    # #govern. This method adds the receipt: `receipt.tool_result_scan`
    # carries counts by kind and type, the tool name, the server URI,
    # whether the result was blocked, and the SDK version. It never carries
    # the payload, a matched substring, or a location path.
    #
    # This is a CLIENT-SIDE, CLIENT-ATTESTED control: it runs in the
    # caller's process, so the receipt records `attested_by: 'client'` and
    # `capture_mode: 'edge'` -- Tork did not execute this scan and cannot
    # verify it ran at all.
    #
    # @param tool_name [String] name of the tool that produced this result
    # @param payload [Object] the tool result itself (any JSON-shaped value); never leaves the machine
    # @param server_uri [String, nil] URI of the MCP server (or other origin), recorded when present
    # @param block_on_injection [Boolean] block the result when injection heuristics fire (default false)
    # @param custom_patterns [Hash{String,Symbol=>Regexp}, nil] extra redaction patterns
    # @param max_depth [Integer] maximum nesting depth to walk
    # @return [GovernedToolResultScanResult]
    def scan_tool_result(
      tool_name:,
      payload:,
      server_uri: nil,
      block_on_injection: false,
      custom_patterns: nil,
      max_depth: ToolResultScan::DEFAULT_MAX_DEPTH
    )
      start_time = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)

      scan = ToolResultScan.scan_tool_result(
        tool_name: tool_name,
        payload: payload,
        server_uri: server_uri,
        block_on_injection: block_on_injection,
        custom_patterns: custom_patterns,
        max_depth: max_depth
      )

      pii_types = ToolResultScan.scan_pii_types(scan.findings)
      pii_count = ToolResultScan.scan_pii_count(scan.findings)
      injection_count = ToolResultScan.scan_injection_count(scan.findings)

      # Fixed mapping, deliberately NOT default_action: unlike #govern, this
      # path always returns masked output when it returns any, so the
      # action must describe what actually happened to the tool result.
      # Every SDK mirroring this must use the same mapping.
      #   blocked            -> deny     (nothing is returned to append)
      #   injection detected -> escalate (returned, flagged for a human)
      #   PII masked         -> redact
      #   nothing found      -> allow
      action =
        if scan.blocked
          ACTIONS[:deny]
        elsif injection_count.positive?
          ACTIONS[:escalate]
        elsif pii_count.positive?
          ACTIONS[:redact]
        else
          ACTIONS[:allow]
        end

      processing_time_ns = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond) - start_time

      # Hashes, not content: hash_text is SHA256, so neither the payload nor
      # the sanitized copy is recoverable from the receipt. A blocked scan
      # has no output to hash and records the hash of the empty string.
      receipt = Receipt.generate(
        input: ToolResultScan.stable_stringify(payload),
        output: scan.blocked ? "" : ToolResultScan.stable_stringify(scan.sanitized),
        action: action,
        pii_types: pii_types,
        pii_count: pii_count,
        policy_version: policy_version,
        processing_time_ns: processing_time_ns,
        tool_result_scan: ToolResultScan.build_tool_result_scan_block(
          tool_name: tool_name,
          server_uri: server_uri,
          result: scan,
          sdk_version: TorkGovernance::VERSION
        )
      )

      @stats[:total_calls] += 1
      @stats[:total_pii_detected] += 1 if pii_count.positive?
      @stats[:total_processing_ns] += processing_time_ns
      @stats[:action_counts][action] += 1

      GovernedToolResultScanResult.new(
        sanitized: scan.sanitized,
        findings: scan.findings,
        blocked: scan.blocked,
        reason: scan.reason,
        receipt: receipt
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
