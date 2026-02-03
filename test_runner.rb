#!/usr/bin/env ruby
# frozen_string_literal: true

require_relative 'lib/tork_governance'

# Simple test runner for Ruby SDK
puts 'Running Ruby SDK tests...'
tests_passed = 0

def run_test(name)
  result = yield
  if result
    puts "  [PASS] #{name}"
    1
  else
    puts "  [FAIL] #{name}"
    0
  end
rescue => e
  puts "  [ERROR] #{name}: #{e.message}"
  0
end

# PIIType tests
puts ''
puts '=== PIIType Tests ==='
tests_passed += run_test('SSN type defined') { TorkGovernance::PIIType::SSN == 'ssn' }
tests_passed += run_test('EMAIL type defined') { TorkGovernance::PIIType::EMAIL == 'email' }
tests_passed += run_test('CREDIT_CARD type defined') { TorkGovernance::PIIType::CREDIT_CARD == 'credit_card' }
tests_passed += run_test('PHONE type defined') { TorkGovernance::PIIType::PHONE == 'phone' }
tests_passed += run_test('IP_ADDRESS type defined') { TorkGovernance::PIIType::IP_ADDRESS == 'ip_address' }
tests_passed += run_test('DATE_OF_BIRTH type defined') { TorkGovernance::PIIType::DATE_OF_BIRTH == 'date_of_birth' }
tests_passed += run_test('ADDRESS type defined') { TorkGovernance::PIIType::ADDRESS == 'address' }

# ACTIONS tests
puts ''
puts '=== ACTIONS Tests ==='
tests_passed += run_test('allow action') { TorkGovernance::ACTIONS[:allow] == 'allow' }
tests_passed += run_test('deny action') { TorkGovernance::ACTIONS[:deny] == 'deny' }
tests_passed += run_test('redact action') { TorkGovernance::ACTIONS[:redact] == 'redact' }
tests_passed += run_test('escalate action') { TorkGovernance::ACTIONS[:escalate] == 'escalate' }

# PIIDetector tests
puts ''
puts '=== PIIDetector Tests ==='
tests_passed += run_test('detect SSN') do
  result = TorkGovernance::PIIDetector.detect('My SSN is 123-45-6789')
  result.has_pii? && result.types.include?(TorkGovernance::PIIType::SSN)
end
tests_passed += run_test('detect email') do
  result = TorkGovernance::PIIDetector.detect('Contact: john@example.com')
  result.has_pii? && result.types.include?(TorkGovernance::PIIType::EMAIL)
end
tests_passed += run_test('detect credit card') do
  result = TorkGovernance::PIIDetector.detect('Card: 4111-1111-1111-1111')
  result.has_pii? && result.types.include?(TorkGovernance::PIIType::CREDIT_CARD)
end
tests_passed += run_test('detect phone') do
  result = TorkGovernance::PIIDetector.detect('Call: 555-123-4567')
  result.has_pii? && result.types.include?(TorkGovernance::PIIType::PHONE)
end
tests_passed += run_test('detect IP address') do
  result = TorkGovernance::PIIDetector.detect('Server: 192.168.1.1')
  result.has_pii? && result.types.include?(TorkGovernance::PIIType::IP_ADDRESS)
end
tests_passed += run_test('detect DOB') do
  result = TorkGovernance::PIIDetector.detect('DOB: 01/15/1990')
  result.has_pii? && result.types.include?(TorkGovernance::PIIType::DATE_OF_BIRTH)
end
tests_passed += run_test('no PII in clean text') do
  result = TorkGovernance::PIIDetector.detect('Hello world')
  result.has_pii? == false && result.count == 0
end
tests_passed += run_test('redact SSN') do
  result = TorkGovernance::PIIDetector.detect('My SSN is 123-45-6789')
  result.redacted_text == 'My SSN is [SSN_REDACTED]'
end
tests_passed += run_test('redact email') do
  result = TorkGovernance::PIIDetector.detect('Contact: john@example.com')
  result.redacted_text == 'Contact: [EMAIL_REDACTED]'
end
tests_passed += run_test('detect multiple PII') do
  result = TorkGovernance::PIIDetector.detect('SSN: 123-45-6789 Email: test@test.com')
  result.count == 2
end
tests_passed += run_test('empty string') do
  result = TorkGovernance::PIIDetector.detect('')
  result.has_pii? == false && result.count == 0
end

# Client tests
puts ''
puts '=== Client Tests ==='
tests_passed += run_test('create with default config') do
  client = TorkGovernance::Client.new
  client.policy_version == '1.0.0' && client.default_action == 'redact'
end
tests_passed += run_test('create with custom policy version') do
  client = TorkGovernance::Client.new(policy_version: '2.0.0')
  client.policy_version == '2.0.0'
end
tests_passed += run_test('govern clean text returns allow') do
  client = TorkGovernance::Client.new
  result = client.govern('Hello world')
  result.action == 'allow' && result.output == 'Hello world'
end
tests_passed += run_test('govern with PII returns redact') do
  client = TorkGovernance::Client.new
  result = client.govern('My SSN is 123-45-6789')
  result.action == 'redact' && result.output == 'My SSN is [SSN_REDACTED]'
end
tests_passed += run_test('govern includes receipt') do
  client = TorkGovernance::Client.new
  result = client.govern('test')
  result.receipt.id.start_with?('rcpt_')
end
tests_passed += run_test('govern receipt has correct hashes') do
  client = TorkGovernance::Client.new
  result = client.govern('test')
  result.receipt.input_hash.start_with?('sha256:') && result.receipt.output_hash.start_with?('sha256:')
end
tests_passed += run_test('deny action config') do
  client = TorkGovernance::Client.new(default_action: TorkGovernance::ACTIONS[:deny])
  result = client.govern('SSN: 123-45-6789')
  result.action == 'deny' && result.output == 'SSN: 123-45-6789'
end

# Stats tests
puts ''
puts '=== Stats Tests ==='
tests_passed += run_test('initial stats are zero') do
  client = TorkGovernance::Client.new
  client.stats[:total_calls] == 0 && client.stats[:total_pii_detected] == 0
end
tests_passed += run_test('track total calls') do
  client = TorkGovernance::Client.new
  client.govern('test1')
  client.govern('test2')
  client.stats[:total_calls] == 2
end
tests_passed += run_test('track PII detected') do
  client = TorkGovernance::Client.new
  client.govern('SSN: 123-45-6789')
  client.govern('clean text')
  client.stats[:total_pii_detected] == 1
end
tests_passed += run_test('reset stats') do
  client = TorkGovernance::Client.new
  client.govern('SSN: 123-45-6789')
  client.reset_stats
  client.stats[:total_calls] == 0
end

# Receipt tests
puts ''
puts '=== Receipt Tests ==='
tests_passed += run_test('generate unique IDs') do
  r1 = TorkGovernance::Receipt.generate(input: 'test', output: 'test', action: 'allow', pii_types: [], pii_count: 0, policy_version: '1.0.0', processing_time_ns: 1000)
  r2 = TorkGovernance::Receipt.generate(input: 'test', output: 'test', action: 'allow', pii_types: [], pii_count: 0, policy_version: '1.0.0', processing_time_ns: 1000)
  r1.id != r2.id
end
tests_passed += run_test('receipt ID prefix') do
  receipt = TorkGovernance::Receipt.generate(input: 'test', output: 'test', action: 'allow', pii_types: [], pii_count: 0, policy_version: '1.0.0', processing_time_ns: 1000)
  receipt.id.start_with?('rcpt_')
end
tests_passed += run_test('hash_text prefix') do
  hash = TorkGovernance::Receipt.hash_text('test')
  hash.start_with?('sha256:')
end
tests_passed += run_test('hash_text consistent') do
  h1 = TorkGovernance::Receipt.hash_text('test')
  h2 = TorkGovernance::Receipt.hash_text('test')
  h1 == h2
end
tests_passed += run_test('hash_text different for different inputs') do
  h1 = TorkGovernance::Receipt.hash_text('test1')
  h2 = TorkGovernance::Receipt.hash_text('test2')
  h1 != h2
end
tests_passed += run_test('verify receipt') do
  receipt = TorkGovernance::Receipt.generate(input: 'test', output: 'test', action: 'allow', pii_types: [], pii_count: 0, policy_version: '1.0.0', processing_time_ns: 1000)
  receipt.verify('test', 'test')
end
tests_passed += run_test('verify fails with wrong input') do
  receipt = TorkGovernance::Receipt.generate(input: 'test', output: 'test', action: 'allow', pii_types: [], pii_count: 0, policy_version: '1.0.0', processing_time_ns: 1000)
  receipt.verify('wrong', 'test') == false
end

# GovernResult tests
puts ''
puts '=== GovernResult Tests ==='
tests_passed += run_test('allowed? method') do
  client = TorkGovernance::Client.new
  result = client.govern('Hello world')
  result.allowed?
end
tests_passed += run_test('redacted? method') do
  client = TorkGovernance::Client.new
  result = client.govern('SSN: 123-45-6789')
  result.redacted?
end
tests_passed += run_test('to_h method') do
  client = TorkGovernance::Client.new
  result = client.govern('test')
  hash = result.to_h
  hash.key?(:action) && hash.key?(:output) && hash.key?(:pii) && hash.key?(:receipt)
end

# Edge cases
puts ''
puts '=== Edge Cases Tests ==='
tests_passed += run_test('long text') do
  client = TorkGovernance::Client.new
  long_text = 'A' * 100_000
  result = client.govern(long_text)
  result.action == 'allow'
end
tests_passed += run_test('unicode text') do
  client = TorkGovernance::Client.new
  result = client.govern("Hello \u4e16\u754c, SSN: 123-45-6789")
  result.pii.has_pii?
end
tests_passed += run_test('newlines') do
  client = TorkGovernance::Client.new
  result = client.govern("Line1\nLine2\nSSN: 123-45-6789")
  result.pii.has_pii?
end
tests_passed += run_test('tabs') do
  client = TorkGovernance::Client.new
  result = client.govern("Tab\there\tSSN: 123-45-6789")
  result.pii.has_pii?
end
tests_passed += run_test('repeated governs') do
  client = TorkGovernance::Client.new
  100.times { |i| client.govern("Test #{i}") }
  client.stats[:total_calls] == 100
end

puts ''
puts '========================================'
puts "Ruby SDK Tests: #{tests_passed} passed"
puts '========================================'
