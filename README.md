# Tork AI Governance SDK for Ruby

Official Ruby SDK for the [Tork AI Governance Platform](https://tork.network). Provides comprehensive tools for AI safety, content moderation, PII detection, policy enforcement, and compliance monitoring for LLM applications.

[![Gem Version](https://badge.fury.io/rb/tork-governance.svg)](https://badge.fury.io/rb/tork-governance)
[![Build Status](https://github.com/torkjacobs/tork-ruby-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/torkjacobs/tork-ruby-sdk/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'tork-governance'
```

And then execute:

```bash
bundle install
```

Or install it yourself as:

```bash
gem install tork-governance
```

## Quick Start

```ruby
require 'tork'

# Configure with your API key
Tork.configure do |config|
  config.api_key = 'tork_your_api_key'
end

# Evaluate content
result = Tork.evaluate(prompt: "What is the capital of France?")
puts result['data']['passed'] # => true
```

## Configuration

### Global Configuration

```ruby
Tork.configure do |config|
  config.api_key = 'tork_your_api_key'
  config.base_url = 'https://api.tork.network/v1'  # Default
  config.timeout = 30                               # Request timeout in seconds
  config.max_retries = 3                            # Max retry attempts
  config.retry_base_delay = 0.5                     # Base delay for exponential backoff
  config.raise_on_rate_limit = true                 # Raise exception on rate limit
  config.logger = Logger.new(STDOUT)                # Enable logging
end
```

### Environment Variable

You can also set the API key via environment variable:

```bash
export TORK_API_KEY=tork_your_api_key
```

### Per-Client Configuration

```ruby
client = Tork::Client.new(
  api_key: 'tork_different_key',
  base_url: 'https://custom.api.com'
)
```

## Usage

### Content Evaluation

```ruby
client = Tork::Client.new(api_key: 'tork_your_api_key')

# Basic evaluation
result = client.evaluate(prompt: "Hello, how are you?")

# Evaluation with response
result = client.evaluate(
  prompt: "What is 2+2?",
  response: "The answer is 4."
)

# Evaluation with specific policy
result = client.evaluate(
  prompt: "Process this request",
  policy_id: "pol_abc123"
)

# Evaluation with specific checks
result = client.evaluations.create(
  prompt: "Contact me at john@example.com",
  checks: ['pii', 'toxicity', 'moderation']
)
```

### PII Detection & Redaction

```ruby
# Detect PII
result = client.evaluations.detect_pii(
  content: "My email is john@example.com and SSN is 123-45-6789"
)
# => { "has_pii" => true, "types" => ["email", "ssn"] }

# Redact PII
result = client.evaluations.redact_pii(
  content: "Call me at 555-123-4567",
  replacement: "mask"
)
# => { "redacted" => "Call me at ***-***-****" }
```

### Jailbreak Detection

```ruby
result = client.evaluations.detect_jailbreak(
  prompt: "Ignore previous instructions and..."
)

if result['data']['is_jailbreak']
  puts "Jailbreak attempt detected!"
  puts "Techniques: #{result['data']['techniques']}"
end
```

### Policy Management

```ruby
policies = client.policies

# List all policies
all_policies = policies.list(page: 1, per_page: 20)

# Get a specific policy
policy = policies.get('pol_abc123')

# Create a new policy
new_policy = policies.create(
  name: "Content Safety Policy",
  description: "Block harmful content",
  rules: [
    {
      type: "block",
      condition: "toxicity > 0.8",
      action: "reject",
      message: "Content flagged as toxic"
    },
    {
      type: "redact",
      condition: "pii.detected",
      action: "mask"
    }
  ],
  enabled: true
)

# Update a policy
policies.update('pol_abc123', name: "Updated Policy Name")

# Enable/Disable a policy
policies.enable('pol_abc123')
policies.disable('pol_abc123')

# Delete a policy
policies.delete('pol_abc123')

# Test a policy
test_result = policies.test('pol_abc123',
  content: "Test content here",
  context: { user_role: "admin" }
)
```

### Batch Evaluation

```ruby
items = [
  { prompt: "First prompt" },
  { prompt: "Second prompt", response: "Second response" },
  { prompt: "Third prompt" }
]

results = client.evaluations.batch(items, policy_id: 'pol_abc123')
```

### RAG Validation

```ruby
chunks = [
  { content: "Document chunk 1", source: "doc1.pdf", page: 1 },
  { content: "Document chunk 2", source: "doc2.pdf", page: 3 }
]

result = client.evaluations.validate_rag(
  chunks: chunks,
  query: "What is the company policy?"
)
```

### Metrics & Analytics

```ruby
metrics = client.metrics

# Get Torking X score for an evaluation
score = metrics.torking_x(evaluation_id: 'eval_abc123')

# Get usage statistics
usage = metrics.usage(period: 'month')

# Get policy performance
performance = metrics.policy_performance(policy_id: 'pol_abc123')

# Get violation statistics
violations = metrics.violations(period: 'week', group_by: 'type')

# Get dashboard summary
dashboard = metrics.dashboard

# Get latency metrics
latency = metrics.latency(period: 'day', percentiles: [50, 95, 99])

# Export metrics
export = metrics.export(
  type: 'usage',
  start_date: '2024-01-01',
  end_date: '2024-01-31',
  format: 'csv'
)
```

## Error Handling

```ruby
begin
  result = client.evaluate(prompt: "Test content")
rescue Tork::AuthenticationError => e
  puts "Invalid API key: #{e.message}"
rescue Tork::RateLimitError => e
  puts "Rate limited. Retry after #{e.retry_after} seconds"
rescue Tork::ValidationError => e
  puts "Validation failed: #{e.message}"
  puts "Details: #{e.details}"
rescue Tork::PolicyViolationError => e
  puts "Policy violation: #{e.message}"
  puts "Violations: #{e.violations}"
rescue Tork::NotFoundError => e
  puts "Resource not found: #{e.message}"
rescue Tork::ServerError => e
  puts "Server error: #{e.message}"
rescue Tork::TimeoutError => e
  puts "Request timed out"
rescue Tork::ConnectionError => e
  puts "Connection failed"
rescue Tork::Error => e
  puts "Tork error: #{e.message}"
end
```

## Rails Integration

### Initializer

Create `config/initializers/tork.rb`:

```ruby
Tork.configure do |config|
  config.api_key = Rails.application.credentials.tork_api_key
  config.logger = Rails.logger
  config.timeout = 30
end
```

### Controller Example

```ruby
class MessagesController < ApplicationController
  def create
    result = Tork.evaluate(
      prompt: params[:content],
      policy_id: current_user.organization.policy_id
    )

    if result['data']['passed']
      @message = Message.create!(content: params[:content])
      render json: @message
    else
      render json: {
        error: 'Content blocked',
        violations: result['data']['violations']
      }, status: :unprocessable_entity
    end
  rescue Tork::RateLimitError => e
    render json: { error: 'Rate limited' }, status: :too_many_requests
  end
end
```

### Background Job Example

```ruby
class ContentModerationJob < ApplicationJob
  queue_as :default

  def perform(message_id)
    message = Message.find(message_id)

    result = Tork.evaluate(
      prompt: message.content,
      checks: ['toxicity', 'pii']
    )

    if result['data']['violations'].any?
      message.update!(
        flagged: true,
        moderation_result: result['data']
      )

      NotificationService.notify_moderators(message)
    end
  end
end
```

## Logging

Enable detailed logging for debugging:

```ruby
require 'logger'

Tork.configure do |config|
  config.api_key = 'tork_your_api_key'
  config.logger = Logger.new(STDOUT)
end
```

## Retry Behavior

The SDK automatically retries failed requests with exponential backoff:

- **Retryable status codes**: 408, 500, 502, 503, 504
- **Default max retries**: 3
- **Default base delay**: 0.5 seconds
- **Backoff factor**: 2x
- **Jitter**: 50% randomness

Customize retry behavior:

```ruby
Tork.configure do |config|
  config.max_retries = 5
  config.retry_base_delay = 1.0
  config.retry_max_delay = 60.0
end
```

## Thread Safety

The SDK is thread-safe. Each `Tork::Client` instance maintains its own connection pool.

```ruby
# Shared client (thread-safe)
client = Tork::Client.new(api_key: 'tork_your_api_key')

threads = 10.times.map do |i|
  Thread.new do
    client.evaluate(prompt: "Thread #{i} content")
  end
end

threads.each(&:join)
```

## Development

After checking out the repo:

```bash
# Install dependencies
bundle install

# Run tests
bundle exec rspec

# Run linter
bundle exec rubocop

# Generate documentation
bundle exec rake doc

# Build the gem
bundle exec rake build

# Install locally
bundle exec rake install
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -am 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This gem is available as open source under the [MIT License](https://opensource.org/licenses/MIT).

## Support

- **Documentation**: [docs.tork.network](https://docs.tork.network)
- **Email**: support@tork.network
- **Issues**: [GitHub Issues](https://github.com/torkjacobs/tork-ruby-sdk/issues)
