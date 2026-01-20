# frozen_string_literal: true

require "bundler/gem_tasks"
require "rspec/core/rake_task"
require "rubocop/rake_task"

RSpec::Core::RakeTask.new(:spec)
RuboCop::RakeTask.new

task default: %i[spec rubocop]

desc "Run tests with coverage"
task :coverage do
  ENV["COVERAGE"] = "true"
  Rake::Task[:spec].invoke
end

desc "Generate documentation"
task :doc do
  sh "yard doc --output-dir doc lib/**/*.rb"
end

desc "Open documentation in browser"
task :doc_server do
  sh "yard server --reload"
end

desc "Build and install gem locally"
task :local_install do
  sh "gem build tork-governance.gemspec"
  sh "gem install tork-governance-#{Tork::VERSION}.gem"
end

desc "Release gem to RubyGems"
task :publish do
  sh "gem build tork-governance.gemspec"
  sh "gem push tork-governance-#{Tork::VERSION}.gem"
end
