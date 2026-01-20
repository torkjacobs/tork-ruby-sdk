# frozen_string_literal: true

module Tork
  module Resources
    # Metrics resource for analytics and reporting
    class Metrics
      # @param client [Tork::Client] The API client
      def initialize(client)
        @client = client
      end

      # Get Torking X score for an evaluation
      # @param evaluation_id [String] Evaluation ID
      # @return [Hash] Torking X metrics
      def torking_x(evaluation_id:)
        @client.get("/metrics/torking-x/#{evaluation_id}")
      end

      # Get usage statistics
      # @param period [String] Time period (day, week, month, year)
      # @param start_date [String, nil] Start date (ISO 8601)
      # @param end_date [String, nil] End date (ISO 8601)
      # @return [Hash] Usage statistics
      def usage(period: "month", start_date: nil, end_date: nil)
        params = { period: period }
        params[:start_date] = start_date if start_date
        params[:end_date] = end_date if end_date
        @client.get("/metrics/usage", params)
      end

      # Get policy performance metrics
      # @param policy_id [String, nil] Specific policy ID
      # @param period [String] Time period
      # @return [Hash] Policy metrics
      def policy_performance(policy_id: nil, period: "month")
        params = { period: period }
        params[:policy_id] = policy_id if policy_id
        @client.get("/metrics/policies", params)
      end

      # Get violation statistics
      # @param period [String] Time period
      # @param group_by [String] Grouping (policy, type, severity)
      # @return [Hash] Violation statistics
      def violations(period: "month", group_by: "type")
        @client.get("/metrics/violations", {
          period: period,
          group_by: group_by
        })
      end

      # Get PII detection statistics
      # @param period [String] Time period
      # @return [Hash] PII statistics
      def pii_stats(period: "month")
        @client.get("/metrics/pii", { period: period })
      end

      # Get latency metrics
      # @param period [String] Time period
      # @param percentiles [Array<Integer>] Percentiles to calculate
      # @return [Hash] Latency metrics
      def latency(period: "day", percentiles: [50, 95, 99])
        @client.get("/metrics/latency", {
          period: period,
          percentiles: percentiles.join(",")
        })
      end

      # Get cost metrics
      # @param period [String] Time period
      # @param group_by [String] Grouping (day, policy, model)
      # @return [Hash] Cost breakdown
      def costs(period: "month", group_by: "day")
        @client.get("/metrics/costs", {
          period: period,
          group_by: group_by
        })
      end

      # Get real-time metrics
      # @return [Hash] Current metrics snapshot
      def realtime
        @client.get("/metrics/realtime")
      end

      # Get compliance report
      # @param start_date [String] Start date (ISO 8601)
      # @param end_date [String] End date (ISO 8601)
      # @param format [String] Report format (json, pdf)
      # @return [Hash] Compliance report data
      def compliance_report(start_date:, end_date:, format: "json")
        @client.get("/metrics/compliance", {
          start_date: start_date,
          end_date: end_date,
          format: format
        })
      end

      # Get dashboard summary
      # @return [Hash] Dashboard metrics
      def dashboard
        @client.get("/metrics/dashboard")
      end

      # Export metrics
      # @param type [String] Export type (usage, violations, costs)
      # @param start_date [String] Start date
      # @param end_date [String] End date
      # @param format [String] Export format (csv, json)
      # @return [Hash] Export URL or data
      def export(type:, start_date:, end_date:, format: "csv")
        @client.post("/metrics/export", {
          type: type,
          start_date: start_date,
          end_date: end_date,
          format: format
        })
      end
    end
  end
end
