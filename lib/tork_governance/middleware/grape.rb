# frozen_string_literal: true

require "json"

module TorkGovernance
  module Middleware
    # Grape API middleware for Tork governance
    #
    # Add to your Grape API:
    #   class API < Grape::API
    #     use TorkGovernance::Middleware::Grape
    #   end
    #
    # Configure globally:
    #   TorkGovernance.configure(
    #     api_key: ENV['TORK_API_KEY'],
    #     policy_version: '1.0.0'
    #   )
    #
    # Access result in endpoints:
    #   result = env['tork.result']
    #
    # @example Basic usage
    #   class API < Grape::API
    #     use TorkGovernance::Middleware::Grape,
    #       protected_paths: ['/api/'],
    #       skip_paths: ['/api/health']
    #
    #     post '/chat' do
    #       tork_result = env['tork.result']
    #       if tork_result&.redacted?
    #         # Content has been redacted
    #       end
    #       { status: 'ok' }
    #     end
    #   end
    #
    # @example With Grape helpers
    #   class API < Grape::API
    #     helpers TorkGovernance::Middleware::GrapeHelpers
    #
    #     post '/chat' do
    #       result = tork_result
    #       receipt_id = tork_receipt_id
    #       { status: 'ok', receipt_id: receipt_id }
    #     end
    #   end
    class Grape
      CONTENT_KEYS = %w[content message text prompt query input].freeze

      def initialize(app, options = {})
        @app = app
        @client = options[:client] || TorkGovernance.client
        @protected_paths = options[:protected_paths] || ["/"]
        @skip_paths = options[:skip_paths] || []
        @on_block = options[:on_block]
        @govern_response = options.fetch(:govern_response, false)
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
            return handle_blocked(env, result)
          end

          # Replace body with redacted content if needed
          if result.redacted? && result.pii.has_pii?
            env["tork.redacted_content"] = result.output
            # Update request body with redacted content
            redacted_data = data.dup
            update_content(redacted_data, result.output)
            env["rack.input"] = StringIO.new(JSON.generate(redacted_data))
          end

        rescue JSON::ParserError
          # Not JSON, pass through
        end

        # Call the app
        status, headers, response = @app.call(env)

        # Optionally govern response
        if @govern_response && json_response?(headers)
          status, headers, response = govern_response(status, headers, response)
        end

        [status, headers, response]
      end

      private

      def extract_content(data)
        return nil unless data.is_a?(Hash)

        CONTENT_KEYS.each do |key|
          return data[key] if data[key].is_a?(String) && !data[key].empty?
        end
        nil
      end

      def update_content(data, new_content)
        return unless data.is_a?(Hash)

        CONTENT_KEYS.each do |key|
          if data[key].is_a?(String) && !data[key].empty?
            data[key] = new_content
            return
          end
        end
      end

      def handle_blocked(env, result)
        if @on_block
          return @on_block.call(env, result)
        end

        [
          403,
          { "Content-Type" => "application/json" },
          [JSON.generate({
            error: "Request blocked by governance policy",
            receipt_id: result.receipt.id,
            pii_types: result.pii.types
          })]
        ]
      end

      def json_response?(headers)
        content_type = headers["Content-Type"] || ""
        content_type.include?("application/json")
      end

      def govern_response(status, headers, response)
        body = response_body(response)
        return [status, headers, response] if body.empty?

        begin
          data = JSON.parse(body)
          content = extract_content(data)
          return [status, headers, response] unless content

          result = @client.govern(content)

          if result.redacted? && result.pii.has_pii?
            update_content(data, result.output)
            new_body = JSON.generate(data)
            headers["Content-Length"] = new_body.bytesize.to_s
            return [status, headers, [new_body]]
          end
        rescue JSON::ParserError
          # Not JSON, pass through
        end

        [status, headers, response]
      end

      def response_body(response)
        body = []
        response.each { |part| body << part }
        body.join
      end
    end

    # Grape helpers for easy access to Tork results
    #
    # @example Usage
    #   class API < Grape::API
    #     helpers TorkGovernance::Middleware::GrapeHelpers
    #
    #     post '/chat' do
    #       result = tork_result
    #       redacted = tork_redacted_content
    #       { result: result&.action, redacted: redacted }
    #     end
    #   end
    module GrapeHelpers
      def tork_result
        env["tork.result"]
      end

      def tork_receipt_id
        env["tork.receipt_id"]
      end

      def tork_redacted_content
        env["tork.redacted_content"]
      end

      def tork_blocked?
        tork_result&.denied?
      end

      def tork_redacted?
        tork_result&.redacted? && tork_result&.pii&.has_pii?
      end

      # Use in before filter to ensure governance passed
      def require_tork_governance!
        if tork_blocked?
          error!({
            error: "Request blocked by governance policy",
            receipt_id: tork_receipt_id
          }, 403)
        end
      end
    end
  end
end
