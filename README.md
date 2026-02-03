# Tork Governance Ruby SDK

On-device AI governance with PII detection, redaction, and cryptographic receipts for Ruby applications.

[![Gem Version](https://badge.fury.io/rb/tork-governance.svg)](https://badge.fury.io/rb/tork-governance)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Installation

Add to your Gemfile:

```ruby
gem 'tork-governance'
```

Or install directly:

```bash
gem install tork-governance
```

## Quick Start

```ruby
require 'tork_governance'

tork = TorkGovernance::Client.new

# Detect and redact PII
result = tork.govern("My SSN is 123-45-6789 and email is john@example.com")

puts result.output  # "My SSN is [SSN_REDACTED] and email is [EMAIL_REDACTED]"
puts result.pii.types  # ['ssn', 'email']
puts result.receipt.id  # Cryptographic receipt ID
```

## Supported Frameworks (2 Adapters)

### Web Frameworks
- **Rails** - Middleware and controller integration
- **Grape** - API middleware and helpers

## Framework Examples

### Rails Middleware

```ruby
# config/application.rb
module MyApp
  class Application < Rails::Application
    config.middleware.use TorkGovernance::Middleware::Rails,
      protected_paths: ['/api/'],
      skip_paths: ['/api/health']
  end
end
```

```ruby
# In controllers
class ChatController < ApplicationController
  def create
    tork_result = request.env['tork.result']
    render json: { status: 'ok', receipt_id: tork_result&.receipt&.id }
  end
end
```

### Grape API Middleware

```ruby
require 'tork_governance/middleware/grape'

class API < Grape::API
  use TorkGovernance::Middleware::Grape,
    protected_paths: ['/api/'],
    skip_paths: ['/api/health']

  helpers TorkGovernance::Middleware::GrapeHelpers

  post '/chat' do
    result = tork_result
    receipt_id = tork_receipt_id

    if tork_blocked?
      error!({ error: 'Content blocked' }, 403)
    end

    { status: 'ok', receipt_id: receipt_id }
  end
end
```

### Grape Helper Methods

```ruby
helpers TorkGovernance::Middleware::GrapeHelpers

# Available helpers:
tork_result           # Get full governance result
tork_receipt_id       # Get receipt ID
tork_redacted_content # Get redacted content
tork_blocked?         # Check if request was blocked
tork_redacted?        # Check if content was redacted
require_tork_governance!  # Raises 403 if blocked
```

## Configuration

```ruby
TorkGovernance.configure(
  api_key: ENV['TORK_API_KEY'],
  policy_version: '1.0.0',
  default_action: :redact
)
```

## PII Detection

Detects 50+ PII types including:

| Category | Types |
|----------|-------|
| **US** | SSN, EIN, ITIN, Passport, Driver's License |
| **Australia** | TFN, ABN, ACN, Medicare |
| **Financial** | Credit Card, Bank Account, SWIFT/BIC |
| **Universal** | Email, IP Address, URL, Phone, DOB |

## Documentation

- [Full Documentation](https://docs.tork.network)
- [API Reference](https://docs.tork.network/api/ruby)

## License

MIT License - see [LICENSE](LICENSE) for details.
