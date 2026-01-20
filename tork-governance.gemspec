# frozen_string_literal: true

require_relative "lib/tork/version"

Gem::Specification.new do |spec|
  spec.name = "tork-governance"
  spec.version = Tork::VERSION
  spec.authors = ["Tork Network"]
  spec.email = ["support@tork.network"]

  spec.summary = "Ruby SDK for Tork AI Governance Platform"
  spec.description = <<~DESC
    Official Ruby SDK for the Tork AI Governance Platform. Provides comprehensive
    tools for AI safety, content moderation, PII detection, policy enforcement,
    and compliance monitoring for LLM applications.
  DESC
  spec.homepage = "https://tork.network"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 2.7.0"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "https://github.com/torkjacobs/tork-ruby-sdk"
  spec.metadata["changelog_uri"] = "https://github.com/torkjacobs/tork-ruby-sdk/blob/main/CHANGELOG.md"
  spec.metadata["documentation_uri"] = "https://docs.tork.network/sdks/ruby"
  spec.metadata["bug_tracker_uri"] = "https://github.com/torkjacobs/tork-ruby-sdk/issues"
  spec.metadata["rubygems_mfa_required"] = "true"

  # Specify which files should be added to the gem
  spec.files = Dir.chdir(__dir__) do
    `git ls-files -z`.split("\x0").reject do |f|
      (File.expand_path(f) == __FILE__) ||
        f.start_with?(*%w[bin/ test/ spec/ features/ .git .github appveyor Gemfile])
    end
  end
  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  # Runtime dependencies
  spec.add_dependency "faraday", "~> 2.0"
  spec.add_dependency "faraday-retry", "~> 2.0"

  # Development dependencies
  spec.add_development_dependency "bundler", "~> 2.0"
  spec.add_development_dependency "rake", "~> 13.0"
  spec.add_development_dependency "rspec", "~> 3.0"
  spec.add_development_dependency "rubocop", "~> 1.0"
  spec.add_development_dependency "rubocop-rspec", "~> 2.0"
  spec.add_development_dependency "simplecov", "~> 0.22"
  spec.add_development_dependency "vcr", "~> 6.0"
  spec.add_development_dependency "webmock", "~> 3.0"
  spec.add_development_dependency "yard", "~> 0.9"
end
