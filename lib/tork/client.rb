# frozen_string_literal: true

require "faraday"
require "faraday/retry"
require "json"

module Tork
  # HTTP client for interacting with the Tork API
  class Client
    attr_reader :config

    # Initialize a new client
    # @param api_key [String, nil] API key (uses config if not provided)
    # @param base_url [String, nil] Base URL (uses config if not provided)
    # @param config [Configuration, nil] Configuration object
    def initialize(api_key: nil, base_url: nil, config: nil)
      @config = config || Tork.configuration.dup
      @config.api_key = api_key if api_key
      @config.base_url = base_url if base_url
      @config.validate!

      @connection = build_connection
    end

    # Access policy resources
    # @return [Resources::Policy]
    def policies
      @policies ||= Resources::Policy.new(self)
    end

    # Access evaluation resources
    # @return [Resources::Evaluation]
    def evaluations
      @evaluations ||= Resources::Evaluation.new(self)
    end

    # Access metrics resources
    # @return [Resources::Metrics]
    def metrics
      @metrics ||= Resources::Metrics.new(self)
    end

    # Shorthand for evaluating content
    # @param prompt [String] The prompt to evaluate
    # @param response [String, nil] The response to evaluate
    # @param policy_id [String, nil] Policy ID to use
    # @param options [Hash] Additional options
    # @return [Hash] Evaluation result
    def evaluate(prompt:, response: nil, policy_id: nil, **options)
      evaluations.create(
        prompt: prompt,
        response: response,
        policy_id: policy_id,
        **options
      )
    end

    # Make a GET request
    # @param path [String] API path
    # @param params [Hash] Query parameters
    # @return [Hash] Parsed response
    def get(path, params = {})
      request(:get, path, params: params)
    end

    # Make a POST request
    # @param path [String] API path
    # @param body [Hash] Request body
    # @return [Hash] Parsed response
    def post(path, body = {})
      request(:post, path, body: body)
    end

    # Make a PUT request
    # @param path [String] API path
    # @param body [Hash] Request body
    # @return [Hash] Parsed response
    def put(path, body = {})
      request(:put, path, body: body)
    end

    # Make a PATCH request
    # @param path [String] API path
    # @param body [Hash] Request body
    # @return [Hash] Parsed response
    def patch(path, body = {})
      request(:patch, path, body: body)
    end

    # Make a DELETE request
    # @param path [String] API path
    # @return [Hash] Parsed response
    def delete(path)
      request(:delete, path)
    end

    private

    def build_connection
      Faraday.new(url: config.base_url) do |conn|
        # Request configuration
        conn.request :json
        conn.headers["Authorization"] = "Bearer #{config.api_key}"
        conn.headers["User-Agent"] = config.full_user_agent
        conn.headers["Content-Type"] = "application/json"
        conn.headers["Accept"] = "application/json"

        # Retry configuration with exponential backoff
        conn.request :retry,
                     max: config.max_retries,
                     interval: config.retry_base_delay,
                     interval_randomness: 0.5,
                     backoff_factor: 2,
                     max_interval: config.retry_max_delay,
                     retry_statuses: [408, 500, 502, 503, 504],
                     retry_if: ->(env, _exception) { retryable?(env) },
                     retry_block: ->(env, _options, retries, exception) {
                       log_retry(env, retries, exception)
                     }

        # Response parsing
        conn.response :json, content_type: /\bjson$/
        conn.response :logger, config.logger, bodies: true if config.logger

        # Timeout
        conn.options.timeout = config.timeout
        conn.options.open_timeout = 10

        # Adapter
        conn.adapter Faraday.default_adapter
      end
    end

    def request(method, path, params: nil, body: nil)
      response = @connection.send(method) do |req|
        req.url path
        req.params = params if params
        req.body = body.to_json if body
      end

      handle_response(response)
    rescue Faraday::TimeoutError
      raise TimeoutError
    rescue Faraday::ConnectionFailed
      raise ConnectionError
    end

    def handle_response(response)
      case response.status
      when 200..299
        response.body || {}
      when 401
        raise AuthenticationError, extract_error_message(response)
      when 404
        raise NotFoundError, extract_error_message(response)
      when 422
        handle_validation_error(response)
      when 429
        handle_rate_limit(response)
      when 400..499
        raise ValidationError.new(extract_error_message(response), details: response.body)
      when 500..599
        raise ServerError, extract_error_message(response)
      else
        raise Error.new(
          "Unexpected response: #{response.status}",
          http_status: response.status
        )
      end
    end

    def handle_rate_limit(response)
      retry_after = response.headers["Retry-After"]&.to_i
      message = extract_error_message(response)

      if config.raise_on_rate_limit
        raise RateLimitError.new(message, retry_after: retry_after)
      else
        {
          error: true,
          code: "RATE_LIMIT_ERROR",
          message: message,
          retry_after: retry_after
        }
      end
    end

    def handle_validation_error(response)
      body = response.body || {}

      if body.dig("error", "code") == "POLICY_VIOLATION"
        raise PolicyViolationError.new(
          extract_error_message(response),
          violations: body.dig("error", "violations") || []
        )
      else
        raise ValidationError.new(extract_error_message(response), details: body)
      end
    end

    def extract_error_message(response)
      body = response.body
      return "Unknown error" unless body.is_a?(Hash)

      body.dig("error", "message") ||
        body["message"] ||
        body["error"] ||
        "Request failed with status #{response.status}"
    end

    def retryable?(env)
      # Don't retry POST/PUT/PATCH unless idempotent
      return true if %i[get head delete].include?(env.method)

      # Retry server errors for all methods
      env.status.nil? || env.status >= 500
    end

    def log_retry(env, retries, exception)
      return unless config.logger

      config.logger.warn(
        "[Tork] Retry ##{retries} for #{env.method.upcase} #{env.url}: " \
        "#{exception&.message || "status #{env.status}"}"
      )
    end
  end
end
