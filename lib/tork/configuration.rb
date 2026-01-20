# frozen_string_literal: true

module Tork
  # Configuration class for Tork SDK
  class Configuration
    # @return [String] The API key for authentication
    attr_accessor :api_key

    # @return [String] The base URL for the Tork API
    attr_accessor :base_url

    # @return [Integer] Request timeout in seconds
    attr_accessor :timeout

    # @return [Integer] Maximum number of retries for failed requests
    attr_accessor :max_retries

    # @return [Float] Base delay for exponential backoff (in seconds)
    attr_accessor :retry_base_delay

    # @return [Float] Maximum delay between retries (in seconds)
    attr_accessor :retry_max_delay

    # @return [Boolean] Whether to raise on rate limit or return error response
    attr_accessor :raise_on_rate_limit

    # @return [Logger, nil] Logger instance for debugging
    attr_accessor :logger

    # @return [String, nil] Custom user agent string
    attr_accessor :user_agent

    # Default configuration values
    DEFAULTS = {
      base_url: "https://api.tork.network/v1",
      timeout: 30,
      max_retries: 3,
      retry_base_delay: 0.5,
      retry_max_delay: 30.0,
      raise_on_rate_limit: true,
      logger: nil,
      user_agent: nil
    }.freeze

    def initialize
      DEFAULTS.each do |key, value|
        send("#{key}=", value)
      end
      @api_key = ENV["TORK_API_KEY"]
    end

    # Validate the configuration
    # @raise [Tork::AuthenticationError] if API key is missing
    def validate!
      raise AuthenticationError, "API key is required" if api_key.nil? || api_key.empty?
    end

    # Reset configuration to defaults
    def reset!
      DEFAULTS.each do |key, value|
        send("#{key}=", value)
      end
      @api_key = ENV["TORK_API_KEY"]
    end

    # Build user agent string
    # @return [String]
    def full_user_agent
      base = "tork-ruby/#{Tork::VERSION} Ruby/#{RUBY_VERSION}"
      user_agent ? "#{user_agent} #{base}" : base
    end
  end
end
