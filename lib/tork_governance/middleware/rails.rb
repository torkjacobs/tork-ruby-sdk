# frozen_string_literal: true

require "json"

module TorkGovernance
  module Middleware
    # Rails middleware for Tork governance
    #
    # Add to config/application.rb:
    #   config.middleware.use TorkGovernance::Middleware::Rails
    #
    # Configure in an initializer:
    #   TorkGovernance.configure(
    #     api_key: ENV['TORK_API_KEY'],
    #     policy_version: '1.0.0'
    #   )
    #
    # Access result in controllers:
    #   result = request.env['tork.result']
    #
    # @example Basic usage
    #   # config/application.rb
    #   config.middleware.use TorkGovernance::Middleware::Rails,
    #     protected_paths: ['/api/'],
    #     skip_paths: ['/api/health']
    #
    # @example Controller usage
    #   class ChatController < ApplicationController
    #     def create
    #       tork_result = request.env['tork.result']
    #       if tork_result&.redacted?
    #         # Use redacted content
    #         content = tork_result.output
    #       end
    #       render json: { message: 'ok' }
    #     end
    #   end
    class Rails
      CONTENT_KEYS = %w[content message text prompt query input].freeze

      def initialize(app, options = {})
        @app = app
        @client = options[:client] || TorkGovernance.client
        @protected_paths = options[:protected_paths] || ["/api/"]
        @skip_paths = options[:skip_paths] || []
        @on_block = options[:on_block]
      end

      def call(env)
        request = Rack::Request.new(env)

        # Only process POST, PUT, PATCH
        unless %w[POST PUT PATCH].include?(request.request_method)
          return @app.call(env)
        end

        # Check skip paths
        if @skip_paths.any? { |p| request.path.start_with?(p) }
          return @app.call(env)
        end

        # Check protected paths
        unless @protected_paths.any? { |p| request.path.start_with?(p) }
          return @app.call(env)
        end

        # Try to parse JSON body
        begin
          body = request.body.read
          request.body.rewind
          return @app.call(env) if body.empty?

          data = JSON.parse(body)
          content = extract_content(data)
          return @app.call(env) unless content

          # Govern content
          result = @client.govern(content)
          env["tork.result"] = result
          env["tork.receipt_id"] = result.receipt.id

          # Handle deny action
          if result.denied?
            if @on_block
              return @on_block.call(env, result)
            end

            return [
              403,
              { "Content-Type" => "application/json" },
              [JSON.generate({
                error: "Request blocked by governance policy",
                receipt_id: result.receipt.id,
                pii_types: result.pii.types
              })]
            ]
          end

          # Store redacted content for downstream use
          if result.redacted? && result.pii.has_pii?
            env["tork.redacted_content"] = result.output
          end

        rescue JSON::ParserError
          # Not JSON, pass through
        end

        @app.call(env)
      end

      private

      def extract_content(data)
        return nil unless data.is_a?(Hash)

        CONTENT_KEYS.each do |key|
          return data[key] if data[key].is_a?(String) && !data[key].empty?
        end
        nil
      end
    end

    # Rails concern for controller integration
    #
    # @example Include in controller
    #   class ApiController < ApplicationController
    #     include TorkGovernance::Middleware::RailsConcern
    #
    #     before_action :require_tork_governance, only: [:create, :update]
    #   end
    module RailsConcern
      extend ActiveSupport::Concern if defined?(ActiveSupport::Concern)

      def tork_result
        request.env["tork.result"]
      end

      def tork_receipt_id
        request.env["tork.receipt_id"]
      end

      def tork_redacted_content
        request.env["tork.redacted_content"]
      end

      def require_tork_governance
        if tork_result&.denied?
          render json: {
            error: "Request blocked by governance policy",
            receipt_id: tork_receipt_id
          }, status: :forbidden
        end
      end
    end

    # Railtie for automatic Rails integration
    class Railtie < ::Rails::Railtie if defined?(::Rails::Railtie)
      initializer "tork_governance.configure_middleware" do |app|
        app.middleware.use TorkGovernance::Middleware::Rails
      end
    end
  end
end
