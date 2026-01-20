# frozen_string_literal: true

module Tork
  module Resources
    # Policy resource for managing governance policies
    class Policy
      # @param client [Tork::Client] The API client
      def initialize(client)
        @client = client
      end

      # List all policies
      # @param page [Integer] Page number (default: 1)
      # @param per_page [Integer] Items per page (default: 20)
      # @param status [String, nil] Filter by status (active, draft, archived)
      # @return [Hash] List of policies with pagination info
      def list(page: 1, per_page: 20, status: nil)
        params = { page: page, per_page: per_page }
        params[:status] = status if status
        @client.get("/policies", params)
      end

      # Get a specific policy
      # @param id [String] Policy ID
      # @return [Hash] Policy details
      def get(id)
        @client.get("/policies/#{id}")
      end

      # Create a new policy
      # @param name [String] Policy name
      # @param description [String, nil] Policy description
      # @param rules [Array<Hash>] Policy rules
      # @param enabled [Boolean] Whether policy is enabled (default: true)
      # @param options [Hash] Additional options
      # @return [Hash] Created policy
      def create(name:, rules:, description: nil, enabled: true, **options)
        body = {
          name: name,
          rules: rules,
          enabled: enabled,
          **options
        }
        body[:description] = description if description
        @client.post("/policies", body)
      end

      # Update a policy
      # @param id [String] Policy ID
      # @param attributes [Hash] Attributes to update
      # @return [Hash] Updated policy
      def update(id, **attributes)
        @client.patch("/policies/#{id}", attributes)
      end

      # Delete a policy
      # @param id [String] Policy ID
      # @return [Hash] Deletion confirmation
      def delete(id)
        @client.delete("/policies/#{id}")
      end

      # Duplicate a policy
      # @param id [String] Policy ID to duplicate
      # @param name [String, nil] New name for the duplicate
      # @return [Hash] Duplicated policy
      def duplicate(id, name: nil)
        body = {}
        body[:name] = name if name
        @client.post("/policies/#{id}/duplicate", body)
      end

      # Enable a policy
      # @param id [String] Policy ID
      # @return [Hash] Updated policy
      def enable(id)
        update(id, enabled: true)
      end

      # Disable a policy
      # @param id [String] Policy ID
      # @return [Hash] Updated policy
      def disable(id)
        update(id, enabled: false)
      end

      # Get policy versions
      # @param id [String] Policy ID
      # @return [Hash] List of versions
      def versions(id)
        @client.get("/policies/#{id}/versions")
      end

      # Restore a policy version
      # @param id [String] Policy ID
      # @param version_id [String] Version ID to restore
      # @return [Hash] Restored policy
      def restore_version(id, version_id)
        @client.post("/policies/#{id}/versions/#{version_id}/restore")
      end

      # Test a policy with sample content
      # @param id [String] Policy ID
      # @param content [String] Content to test
      # @param context [Hash] Additional context
      # @return [Hash] Test results
      def test(id, content:, context: {})
        @client.post("/policies/#{id}/test", {
          content: content,
          context: context
        })
      end
    end
  end
end
