# frozen_string_literal: true

module Tork
  module Resources
    # Evaluation resource for content evaluation
    class Evaluation
      # @param client [Tork::Client] The API client
      def initialize(client)
        @client = client
      end

      # Evaluate content against policies
      # @param prompt [String] The prompt/input to evaluate
      # @param response [String, nil] The response/output to evaluate
      # @param policy_id [String, nil] Specific policy ID (uses default if nil)
      # @param checks [Array<String>] Checks to perform (pii, toxicity, moderation)
      # @param options [Hash] Additional options
      # @return [Hash] Evaluation result
      def create(prompt:, response: nil, policy_id: nil, checks: nil, **options)
        body = { content: prompt }
        body[:response] = response if response
        body[:policy_id] = policy_id if policy_id
        body[:checks] = checks if checks
        body.merge!(options) unless options.empty?

        @client.post("/evaluate", body)
      end

      # Get an evaluation by ID
      # @param id [String] Evaluation ID
      # @return [Hash] Evaluation details
      def get(id)
        @client.get("/evaluations/#{id}")
      end

      # List recent evaluations
      # @param page [Integer] Page number
      # @param per_page [Integer] Items per page
      # @param policy_id [String, nil] Filter by policy
      # @param status [String, nil] Filter by status (passed, failed, flagged)
      # @param start_date [String, nil] Start date (ISO 8601)
      # @param end_date [String, nil] End date (ISO 8601)
      # @return [Hash] List of evaluations
      def list(page: 1, per_page: 20, policy_id: nil, status: nil, start_date: nil, end_date: nil)
        params = { page: page, per_page: per_page }
        params[:policy_id] = policy_id if policy_id
        params[:status] = status if status
        params[:start_date] = start_date if start_date
        params[:end_date] = end_date if end_date
        @client.get("/evaluations", params)
      end

      # Batch evaluate multiple content items
      # @param items [Array<Hash>] Array of items to evaluate
      # @param policy_id [String, nil] Policy to apply to all
      # @return [Hash] Batch evaluation results
      def batch(items, policy_id: nil)
        body = { items: items }
        body[:policy_id] = policy_id if policy_id
        @client.post("/evaluate/batch", body)
      end

      # Evaluate and get detailed analysis
      # @param prompt [String] Content to analyze
      # @param analysis_types [Array<String>] Types of analysis
      # @return [Hash] Detailed analysis
      def analyze(prompt:, analysis_types: %w[pii toxicity sentiment topics])
        @client.post("/evaluate/analyze", {
          content: prompt,
          analysis_types: analysis_types
        })
      end

      # Check PII in content
      # @param content [String] Content to check
      # @param pii_types [Array<String>, nil] Specific PII types to detect
      # @param redact [Boolean] Whether to return redacted version
      # @return [Hash] PII detection results
      def detect_pii(content:, pii_types: nil, redact: false)
        body = { content: content, redact: redact }
        body[:pii_types] = pii_types if pii_types
        @client.post("/pii/detect", body)
      end

      # Redact PII from content
      # @param content [String] Content to redact
      # @param pii_types [Array<String>, nil] Specific PII types to redact
      # @param replacement [String] Replacement format (mask, type, custom)
      # @return [Hash] Redacted content
      def redact_pii(content:, pii_types: nil, replacement: "mask")
        body = { content: content, replacement: replacement }
        body[:pii_types] = pii_types if pii_types
        @client.post("/pii/redact", body)
      end

      # Check for jailbreak attempts
      # @param prompt [String] Prompt to check
      # @return [Hash] Jailbreak detection results
      def detect_jailbreak(prompt:)
        @client.post("/jailbreak/detect", { prompt: prompt })
      end

      # Validate RAG chunks
      # @param chunks [Array<Hash>] RAG chunks to validate
      # @param query [String] Original query
      # @return [Hash] Validation results
      def validate_rag(chunks:, query:)
        @client.post("/rag/validate", {
          chunks: chunks,
          query: query
        })
      end
    end
  end
end
