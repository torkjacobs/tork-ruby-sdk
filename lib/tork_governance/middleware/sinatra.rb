# frozen_string_literal: true

require "json"

module TorkGovernance
  module Middleware
    # Sinatra extension for Tork governance
    #
    # @example Classic style
    #   require 'sinatra'
    #   require 'tork_governance'
    #   require 'tork_governance/middleware/sinatra'
    #
    #   register TorkGovernance::Middleware::Sinatra
    #
    #   post '/chat' do
    #     result = tork_result
    #     { message: 'ok', receipt_id: result.receipt.id }.to_json
    #   end
    #
    # @example Modular style
    #   class App < Sinatra::Base
    #     register TorkGovernance::Middleware::Sinatra
    #
    #     set :tork_protected_paths, ['/api/']
    #
    #     post '/api/chat' do
    #       content_type :json
    #       { output: tork_result.output }.to_json
    #     end
    #   end
    module Sinatra
      CONTENT_KEYS = %w[content message text prompt query input].freeze

      def self.registered(app)
        app.helpers Helpers

        app.set :tork_client, TorkGovernance.client
        app.set :tork_protected_paths, ["/api/"]
        app.set :tork_skip_paths, []

        app.before do
          next unless %w[POST PUT PATCH].include?(request.request_method)

          # Check skip paths
          next if settings.tork_skip_paths.any? { |p| request.path_info.start_with?(p) }

          # Check protected paths
          next unless settings.tork_protected_paths.any? { |p| request.path_info.start_with?(p) }

          # Try to parse JSON body
          begin
            request.body.rewind
            body = request.body.read
            request.body.rewind
            next if body.empty?

            data = JSON.parse(body)
            content = extract_content(data)
            next unless content

            # Govern content
            result = settings.tork_client.govern(content)
            @tork_result = result

            # Handle deny action
            if result.denied?
              halt 403, { "Content-Type" => "application/json" }, JSON.generate({
                error: "Request blocked by governance policy",
                receipt_id: result.receipt.id,
                pii_types: result.pii.types
              })
            end
          rescue JSON::ParserError
            # Not JSON, pass through
          end
        end
      end

      module Helpers
        # Get the Tork governance result
        #
        # @return [TorkGovernance::GovernResult, nil] the governance result
        def tork_result
          @tork_result
        end

        # Get the receipt ID
        #
        # @return [String, nil] the receipt ID
        def tork_receipt_id
          @tork_result&.receipt&.id
        end

        # Get the redacted content
        #
        # @return [String, nil] the redacted content if available
        def tork_redacted_content
          @tork_result&.output if @tork_result&.redacted? && @tork_result&.pii&.has_pii?
        end

        # Manually govern content
        #
        # @param content [String] the content to govern
        # @return [TorkGovernance::GovernResult] the governance result
        def govern(content)
          settings.tork_client.govern(content)
        end

        # Require governance to pass (use in routes)
        #
        # @example
        #   post '/sensitive' do
        #     require_governance!
        #     # ... handle request
        #   end
        def require_governance!
          if @tork_result&.denied?
            halt 403, { "Content-Type" => "application/json" }, JSON.generate({
              error: "Request blocked by governance policy",
              receipt_id: @tork_result.receipt.id
            })
          end
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
    end

    # Rack middleware for Sinatra (alternative to extension)
    #
    # @example
    #   use TorkGovernance::Middleware::SinatraRack
    class SinatraRack < Rails
      # Inherits from Rails middleware, same behavior
    end
  end
end
