# frozen_string_literal: true

require_relative "tork_governance/version"
require_relative "tork_governance/pii"
require_relative "tork_governance/tool_result_scan"
require_relative "tork_governance/receipt"
require_relative "tork_governance/client"

module TorkGovernance
  class Error < StandardError; end
  class BlockedError < Error; end

  # Governance actions
  ACTIONS = {
    allow: "allow",
    deny: "deny",
    redact: "redact",
    escalate: "escalate"
  }.freeze

  class << self
    # Quick governance check
    #
    # @param content [String] the content to govern
    # @return [GovernResult] the governance result
    #
    # @example
    #   result = TorkGovernance.govern("My SSN is 123-45-6789")
    #   puts result.output # "My SSN is [SSN_REDACTED]"
    def govern(content)
      client.govern(content)
    end

    # Scan a tool result (MCP server response, or any external system's
    # output) for PII and prompt injection before it is appended to model
    # context, recorded on a receipt.
    #
    # @param tool_name [String] name of the tool that produced this result
    # @param payload [Object] the tool result itself (any JSON-shaped value)
    # @param server_uri [String, nil] URI of the MCP server, recorded when present
    # @return [TorkGovernance::GovernedToolResultScanResult]
    def scan_tool_result(tool_name:, payload:, server_uri: nil, **opts)
      client.scan_tool_result(tool_name: tool_name, payload: payload, server_uri: server_uri, **opts)
    end

    # Get or create the default client
    #
    # @return [Client] the default client instance
    def client
      @client ||= Client.new
    end

    # Configure the default client
    #
    # @param api_key [String] API key (optional for on-device)
    # @param policy_version [String] policy version
    def configure(api_key: nil, policy_version: "1.0.0")
      @client = Client.new(api_key: api_key, policy_version: policy_version)
    end
  end
end
