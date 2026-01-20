# frozen_string_literal: true

require "simplecov" if ENV["COVERAGE"]

SimpleCov.start do
  add_filter "/spec/"
  add_group "Library", "lib"
end if ENV["COVERAGE"]

require "tork"
require "webmock/rspec"
require "vcr"

VCR.configure do |config|
  config.cassette_library_dir = "spec/fixtures/vcr_cassettes"
  config.hook_into :webmock
  config.configure_rspec_metadata!
  config.filter_sensitive_data("<API_KEY>") { ENV.fetch("TORK_API_KEY", "test_api_key") }
end

RSpec.configure do |config|
  # Enable flags like --only-failures and --next-failure
  config.example_status_persistence_file_path = ".rspec_status"

  # Disable RSpec exposing methods globally on `Module` and `main`
  config.disable_monkey_patching!

  config.expect_with :rspec do |c|
    c.syntax = :expect
  end

  config.before(:each) do
    Tork.reset_configuration!
    Tork.reset_client!
  end

  config.around(:each, :vcr) do |example|
    VCR.use_cassette(example.metadata[:vcr], record: :new_episodes) do
      example.run
    end
  end
end

# Test helpers
module TestHelpers
  def stub_tork_request(method, path, response_body: {}, status: 200)
    stub_request(method, "https://api.tork.network/v1#{path}")
      .to_return(
        status: status,
        body: response_body.to_json,
        headers: { "Content-Type" => "application/json" }
      )
  end

  def configure_tork(api_key: "tork_test_key_12345")
    Tork.configure do |config|
      config.api_key = api_key
    end
  end
end

RSpec.configure do |config|
  config.include TestHelpers
end
