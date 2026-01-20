# frozen_string_literal: true

require_relative "tork/version"
require_relative "tork/errors"
require_relative "tork/configuration"
require_relative "tork/client"
require_relative "tork/resources/policy"
require_relative "tork/resources/evaluation"
require_relative "tork/resources/metrics"

# Tork AI Governance SDK for Ruby
#
# @example Basic usage
#   Tork.configure do |config|
#     config.api_key = "tork_your_api_key"
#   end
#
#   client = Tork::Client.new
#   result = client.evaluate(prompt: "Hello world")
#
# @example Direct client initialization
#   client = Tork::Client.new(api_key: "tork_your_api_key")
#   result = client.evaluate(prompt: "Hello world")
#
module Tork
  class << self
    # @return [Configuration] Global configuration instance
    def configuration
      @configuration ||= Configuration.new
    end

    # Configure the Tork SDK
    # @yield [Configuration] Configuration instance
    # @example
    #   Tork.configure do |config|
    #     config.api_key = "tork_your_api_key"
    #     config.timeout = 60
    #   end
    def configure
      yield(configuration)
    end

    # Reset configuration to defaults
    def reset_configuration!
      @configuration = Configuration.new
    end

    # Create a new client with global configuration
    # @return [Client]
    def client
      @client ||= Client.new
    end

    # Reset the default client
    def reset_client!
      @client = nil
    end

    # Convenience method to evaluate content
    # @param prompt [String] Content to evaluate
    # @param options [Hash] Additional options
    # @return [Hash] Evaluation result
    def evaluate(prompt:, **options)
      client.evaluate(prompt: prompt, **options)
    end

    # Access policies via default client
    # @return [Resources::Policy]
    def policies
      client.policies
    end

    # Access evaluations via default client
    # @return [Resources::Evaluation]
    def evaluations
      client.evaluations
    end

    # Access metrics via default client
    # @return [Resources::Metrics]
    def metrics
      client.metrics
    end
  end
end
