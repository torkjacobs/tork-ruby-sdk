# frozen_string_literal: true

require_relative "lib/tork_governance/version"

Gem::Specification.new do |spec|
  spec.name = "tork_governance"
  spec.version = TorkGovernance::VERSION
  spec.authors = ["Tork Network"]
  spec.email = ["support@tork.network"]

  spec.summary = "On-device AI governance with PII detection and cryptographic receipts"
  spec.description = <<~DESC
    TorkGovernance provides on-device AI governance capabilities including:
    - PII detection (SSN, credit card, email, phone, etc.)
    - Automatic redaction
    - Cryptographic governance receipts
    - Framework integrations (Rails, Sinatra)
  DESC
  spec.homepage = "https://tork.network"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.0.0"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "https://github.com/torknetwork/tork-governance-ruby"
  spec.metadata["changelog_uri"] = "https://github.com/torknetwork/tork-governance-ruby/blob/main/CHANGELOG.md"

  spec.files = Dir.chdir(__dir__) do
    `git ls-files -z`.split("\x0").reject do |f|
      (File.expand_path(f) == __FILE__) ||
        f.start_with?(*%w[bin/ test/ spec/ features/ .git .github appveyor Gemfile])
    end
  end
  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_dependency "rack", ">= 2.0"

  spec.add_development_dependency "bundler", "~> 2.0"
  spec.add_development_dependency "rake", "~> 13.0"
  spec.add_development_dependency "rspec", "~> 3.0"
  spec.add_development_dependency "rubocop", "~> 1.0"
end
