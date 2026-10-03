# frozen_string_literal: true

require "spec_helper"
require_relative "../lib/tork"

RSpec.describe "agent telemetry fields" do
  let(:client) { TorkGovernance::Client.new }

  describe TorkGovernance::Client do
    it "passes the fields through when set" do
      r = client.govern("hi", agent_id: "a1", agent_role: "worker", session_id: "s1", session_turn: 3)
      expect(r.session_context).to eq(agent_id: "a1", agent_role: "worker", session_id: "s1", session_turn: 3)
      expect(r.to_h[:session_context]).to eq(r.session_context)
    end

    it "omits them when not set" do
      r = client.govern("hi")
      expect(r.session_context).to be_nil
      expect(r.to_h).not_to have_key(:session_context)
    end

    it "includes only the fields that are set" do
      expect(client.govern("hi", agent_id: "a1").session_context).to eq(agent_id: "a1")
    end

    it "keeps session_turn 0 rather than dropping it" do
      expect(client.govern("hi", session_turn: 0).session_context).to eq(session_turn: 0)
    end

    it "rejects a non-integer session_turn" do
      expect { client.govern("hi", session_turn: "3") }.to raise_error(ArgumentError, /session_turn/)
    end
  end

  describe Tork::Resources::Evaluation do
    let(:api) { double("Tork::Client") }
    let(:evaluation) { described_class.new(api) }

    it "sends the fields in the request body when set" do
      expect(api).to receive(:post).with(
        "/evaluate",
        { content: "x", agent_id: "a1", agent_role: "judge", session_id: "s1", session_turn: 2 }
      )
      evaluation.create(prompt: "x", agent_id: "a1", agent_role: "judge", session_id: "s1", session_turn: 2)
    end

    it "omits the fields from the request body when not set" do
      expect(api).to receive(:post).with("/evaluate", { content: "x" })
      evaluation.create(prompt: "x")
    end

    it "rejects a non-integer session_turn" do
      expect { evaluation.create(prompt: "x", session_turn: 1.5) }.to raise_error(ArgumentError)
    end
  end
end
