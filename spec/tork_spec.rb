# frozen_string_literal: true

require "spec_helper"

RSpec.describe Tork do
  it "has a version number" do
    expect(Tork::VERSION).not_to be_nil
    expect(Tork::VERSION).to eq("0.1.0")
  end

  describe ".configure" do
    it "yields configuration" do
      Tork.configure do |config|
        config.api_key = "test_key"
        config.timeout = 60
      end

      expect(Tork.configuration.api_key).to eq("test_key")
      expect(Tork.configuration.timeout).to eq(60)
    end
  end

  describe ".reset_configuration!" do
    it "resets configuration to defaults" do
      Tork.configure { |c| c.timeout = 120 }
      Tork.reset_configuration!

      expect(Tork.configuration.timeout).to eq(30)
    end
  end
end

RSpec.describe Tork::Configuration do
  subject(:config) { described_class.new }

  describe "#initialize" do
    it "sets default values" do
      expect(config.base_url).to eq("https://api.tork.network/v1")
      expect(config.timeout).to eq(30)
      expect(config.max_retries).to eq(3)
    end

    it "reads API key from environment" do
      allow(ENV).to receive(:[]).with("TORK_API_KEY").and_return("env_key")
      new_config = described_class.new
      expect(new_config.api_key).to eq("env_key")
    end
  end

  describe "#validate!" do
    it "raises error when API key is missing" do
      config.api_key = nil
      expect { config.validate! }.to raise_error(Tork::AuthenticationError)
    end

    it "does not raise when API key is present" do
      config.api_key = "test_key"
      expect { config.validate! }.not_to raise_error
    end
  end

  describe "#full_user_agent" do
    it "includes SDK version and Ruby version" do
      expect(config.full_user_agent).to include("tork-ruby/#{Tork::VERSION}")
      expect(config.full_user_agent).to include("Ruby/#{RUBY_VERSION}")
    end

    it "prepends custom user agent" do
      config.user_agent = "MyApp/1.0"
      expect(config.full_user_agent).to start_with("MyApp/1.0")
    end
  end
end

RSpec.describe Tork::Client do
  let(:api_key) { "tork_test_key_12345" }
  let(:client) { described_class.new(api_key: api_key) }

  describe "#initialize" do
    it "creates client with API key" do
      expect(client.config.api_key).to eq(api_key)
    end

    it "raises error without API key" do
      expect { described_class.new(api_key: nil) }.to raise_error(Tork::AuthenticationError)
    end

    it "uses custom base URL" do
      custom_client = described_class.new(
        api_key: api_key,
        base_url: "https://custom.api.com"
      )
      expect(custom_client.config.base_url).to eq("https://custom.api.com")
    end
  end

  describe "#policies" do
    it "returns Policy resource" do
      expect(client.policies).to be_a(Tork::Resources::Policy)
    end

    it "memoizes the resource" do
      expect(client.policies).to be(client.policies)
    end
  end

  describe "#evaluations" do
    it "returns Evaluation resource" do
      expect(client.evaluations).to be_a(Tork::Resources::Evaluation)
    end
  end

  describe "#metrics" do
    it "returns Metrics resource" do
      expect(client.metrics).to be_a(Tork::Resources::Metrics)
    end
  end

  describe "#evaluate" do
    before do
      stub_tork_request(:post, "/evaluate", response_body: {
        success: true,
        data: { passed: true, score: 0.95 }
      })
    end

    it "evaluates content" do
      result = client.evaluate(prompt: "Hello world")
      expect(result["success"]).to be(true)
    end
  end

  describe "error handling" do
    it "raises AuthenticationError on 401" do
      stub_tork_request(:get, "/policies", status: 401, response_body: {
        error: { message: "Invalid API key" }
      })

      expect { client.get("/policies") }.to raise_error(Tork::AuthenticationError)
    end

    it "raises NotFoundError on 404" do
      stub_tork_request(:get, "/policies/123", status: 404, response_body: {
        error: { message: "Policy not found" }
      })

      expect { client.get("/policies/123") }.to raise_error(Tork::NotFoundError)
    end

    it "raises RateLimitError on 429" do
      stub_request(:get, "https://api.tork.network/v1/policies")
        .to_return(
          status: 429,
          body: { error: { message: "Rate limit exceeded" } }.to_json,
          headers: { "Content-Type" => "application/json", "Retry-After" => "60" }
        )

      expect { client.get("/policies") }.to raise_error(Tork::RateLimitError) do |error|
        expect(error.retry_after).to eq(60)
      end
    end

    it "raises ServerError on 500" do
      stub_tork_request(:get, "/policies", status: 500, response_body: {
        error: { message: "Internal server error" }
      })

      expect { client.get("/policies") }.to raise_error(Tork::ServerError)
    end
  end
end

RSpec.describe Tork::Resources::Policy do
  let(:client) { Tork::Client.new(api_key: "tork_test_key") }
  let(:policies) { client.policies }

  describe "#list" do
    before do
      stub_tork_request(:get, "/policies", response_body: {
        success: true,
        data: [{ id: "pol_1", name: "Default Policy" }],
        pagination: { page: 1, total: 1 }
      })
    end

    it "returns list of policies" do
      result = policies.list
      expect(result["data"]).to be_an(Array)
    end
  end

  describe "#get" do
    before do
      stub_tork_request(:get, "/policies/pol_123", response_body: {
        success: true,
        data: { id: "pol_123", name: "Test Policy" }
      })
    end

    it "returns policy details" do
      result = policies.get("pol_123")
      expect(result["data"]["id"]).to eq("pol_123")
    end
  end

  describe "#create" do
    before do
      stub_tork_request(:post, "/policies", response_body: {
        success: true,
        data: { id: "pol_new", name: "New Policy" }
      })
    end

    it "creates a policy" do
      result = policies.create(
        name: "New Policy",
        rules: [{ type: "block", pattern: "test" }]
      )
      expect(result["success"]).to be(true)
    end
  end

  describe "#update" do
    before do
      stub_tork_request(:patch, "/policies/pol_123", response_body: {
        success: true,
        data: { id: "pol_123", name: "Updated Policy" }
      })
    end

    it "updates a policy" do
      result = policies.update("pol_123", name: "Updated Policy")
      expect(result["data"]["name"]).to eq("Updated Policy")
    end
  end

  describe "#delete" do
    before do
      stub_tork_request(:delete, "/policies/pol_123", response_body: {
        success: true,
        message: "Policy deleted"
      })
    end

    it "deletes a policy" do
      result = policies.delete("pol_123")
      expect(result["success"]).to be(true)
    end
  end
end

RSpec.describe Tork::Resources::Evaluation do
  let(:client) { Tork::Client.new(api_key: "tork_test_key") }
  let(:evaluations) { client.evaluations }

  describe "#create" do
    before do
      stub_tork_request(:post, "/evaluate", response_body: {
        success: true,
        data: {
          id: "eval_123",
          passed: true,
          score: 0.95,
          checks: { pii: false, toxicity: false }
        }
      })
    end

    it "evaluates content" do
      result = evaluations.create(prompt: "Hello world")
      expect(result["data"]["passed"]).to be(true)
    end

    it "accepts policy_id" do
      result = evaluations.create(prompt: "Test", policy_id: "pol_123")
      expect(result["success"]).to be(true)
    end
  end

  describe "#detect_pii" do
    before do
      stub_tork_request(:post, "/pii/detect", response_body: {
        success: true,
        data: {
          has_pii: true,
          types: ["email", "phone"],
          entities: [
            { type: "email", value: "***@***.com", start: 10, end: 25 }
          ]
        }
      })
    end

    it "detects PII in content" do
      result = evaluations.detect_pii(content: "Contact me at test@example.com")
      expect(result["data"]["has_pii"]).to be(true)
    end
  end

  describe "#detect_jailbreak" do
    before do
      stub_tork_request(:post, "/jailbreak/detect", response_body: {
        success: true,
        data: {
          is_jailbreak: false,
          confidence: 0.98,
          techniques: []
        }
      })
    end

    it "checks for jailbreak attempts" do
      result = evaluations.detect_jailbreak(prompt: "What is the weather?")
      expect(result["data"]["is_jailbreak"]).to be(false)
    end
  end
end

RSpec.describe Tork::Resources::Metrics do
  let(:client) { Tork::Client.new(api_key: "tork_test_key") }
  let(:metrics) { client.metrics }

  describe "#torking_x" do
    before do
      stub_tork_request(:get, "/metrics/torking-x/eval_123", response_body: {
        success: true,
        data: {
          score: 0.92,
          dimensions: {
            safety: 0.95,
            compliance: 0.90,
            quality: 0.91
          }
        }
      })
    end

    it "returns Torking X metrics" do
      result = metrics.torking_x(evaluation_id: "eval_123")
      expect(result["data"]["score"]).to eq(0.92)
    end
  end

  describe "#usage" do
    before do
      stub_tork_request(:get, "/metrics/usage", response_body: {
        success: true,
        data: {
          total_calls: 10000,
          period: "month",
          breakdown: { evaluate: 8000, pii: 2000 }
        }
      })
    end

    it "returns usage statistics" do
      result = metrics.usage(period: "month")
      expect(result["data"]["total_calls"]).to eq(10000)
    end
  end

  describe "#dashboard" do
    before do
      stub_tork_request(:get, "/metrics/dashboard", response_body: {
        success: true,
        data: {
          evaluations_today: 500,
          violations_today: 12,
          avg_latency_ms: 45
        }
      })
    end

    it "returns dashboard metrics" do
      result = metrics.dashboard
      expect(result["data"]["evaluations_today"]).to eq(500)
    end
  end
end
