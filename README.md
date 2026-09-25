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

## Country PII detection

23 country profiles, 50 patterns and 20 check digits, generated from Tork's own
country registry (bundle `1.0.0`) and computed entirely on-device.

Countries: AU, US, GB, EU, AE, SA, NG, IN, JP, CN, KR, BR, CA, ZA, GH, IT, KE,
MU, MX, MY, PK, SG, TH.

A country's patterns switch on when the text activates that country — the same
content signals the cloud uses — so ordinary business text is not measured
against 50 national-identifier patterns it could never contain. On the
1,159-line business corpus this SDK is tested against, nothing is redacted.

```ruby
r = TorkGovernance::PIIDetector.detect(
  'South African ID number 8001015009087 for the FICA check.'
)

r.regions        # ["ZA"]
r.country_labels # ["ZA_ID"]
r.redacted_text  # "South African ID number [ZA_ID_REDACTED] for the FICA check."
```

Force profiles on when you already know the jurisdiction:

```ruby
forced = TorkGovernance::PIIDetector.detect(
  'Documento 529.982.247-25 arquivado.', ['br']
)
# forced.redacted_text == "Documento [CPF_REDACTED] arquivado."
```

Three gates keep the false-positive rate down, and all three must pass:

1. **Activation** — one of the country's content signals fires.
2. **Keyword** — for 18 of the 24 national, tax and health identifiers, one of
   the identifier's keywords must appear within 60 characters before the match
   or 40 after.
3. **Check digit** — for the 10 identifiers whose issuing authority publishes
   the algorithm, a number of the right shape that fails its check digit is not
   that country's identifier. Where the algorithm is community-sourced rather
   than authority-published (`ca_sin`, `emirates_id`, `de_tax_id`, `kr_rrn`,
   `sa_national_id`) the checksum is advisory and never rejects a match.

Still cloud-only, and not in this SDK: the near-miss fallback, the slot,
context, gravity and name layers, industry profiles, and org configuration.

## Scanning tool results

A tool result returned by an MCP server — or any external system you do not control — is untrusted input that is about to be appended to a model's context. `TorkGovernance::ToolResultScan.scan_tool_result` scans it first, on-device, for PII and prompt injection:

```ruby
require 'tork_governance'

tork = TorkGovernance::Client.new
scan = tork.scan_tool_result(
  tool_name: 'lookup_customer',
  server_uri: 'mcp://crm.internal/customers',
  payload: tool_result,          # whatever the server returned
  block_on_injection: true
)

if scan.blocked
  warn(scan.reason)               # do not append anything
else
  append_to_context(scan.sanitized) # PII masked in place
end

scan.findings
# [#<struct TorkGovernance::ToolResultScan::ToolResultFinding kind="pii", type="email", count=1, location="$.content[0].text">,
#  #<struct ... kind="injection", type="heuristic:instruction_override", count=1, location="$.content[0].text">]
```

There is also a standalone `TorkGovernance::ToolResultScan.scan_tool_result(tool_name:, payload:, ...)` module method with the same keyword arguments that returns `sanitized`/`findings`/`blocked`/`reason` and produces no receipt.

- **PII uses the same on-device detector as `govern`** — same patterns, same redaction labels. Matches are masked in place; the payload structure is otherwise unchanged, and a clean payload comes back untouched (`equal?` its input).
- **Injection detection is heuristic.** A conservative pattern set (`tork-injection-heuristics-v1`) covering instruction-override phrases, role reassignment, and exfiltration URLs. Every injection finding is typed `heuristic:<name>` because that is exactly what it is: a regex match over untrusted text, with false positives and false negatives, not a verified determination. Without `block_on_injection`, matches are reported and the result is still returned; with it, `sanitized` is `nil` so no masked copy can be appended by accident.
- **Zero network calls.** The scan is pure and synchronous. The payload never leaves the machine.
- **Recorded on the receipt as counts only.** `receipt.tool_result_scan` carries `attested_by: 'client'`, `capture_mode: 'edge'`, the tool name and server URI, counts by kind and type, the blocked flag, and the SDK version. It never carries the payload, a matched value, or a location path.
- **PII parity tier: TIER 1.** This SDK detects the same 10-type basic vocabulary as the JS SDK (`ssn`, `credit_card`, `email`, `phone`, `address`, `ip_address`, `date_of_birth`, `passport`, `drivers_license`, `bank_account`), with JS-identical type labels. It does **not** implement the Python SDK's regional/industry pattern tier — there is no `region:`/`industry:` support in `scan_tool_result`.

**This is a client-side, client-attested control.** The scan runs in your process, and the receipt says so: Tork did not execute it and cannot verify it ran at all. **Gateway-side enforcement, where a caller cannot skip the scan, is a separate and later control.** Do not read a `tool_result_scan` block as proof that every tool result reaching a model was scanned; read it as a record of the scans a caller chose to run.

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

Detects the 10-type Tier 1 basic vocabulary, with labels identical to the JS SDK's Tier 1 tier:

| Type | Label |
|------|-------|
| SSN | `ssn` |
| Credit Card | `credit_card` |
| Email | `email` |
| Phone | `phone` |
| Address | `address` |
| IP Address | `ip_address` |
| Date of Birth | `date_of_birth` |
| Passport | `passport` |
| Driver's License | `drivers_license` |
| Bank Account | `bank_account` |

This SDK does not implement region-specific (e.g. AU TFN/ABN/ACN/Medicare, US EIN/ITIN, SWIFT/BIC) or industry-specific patterns — that is the Python SDK's regional tier, not this one.

## Documentation

- [Full Documentation](https://docs.tork.network)
- [API Reference](https://docs.tork.network/api/ruby)

## License

MIT License - see [LICENSE](LICENSE) for details.
