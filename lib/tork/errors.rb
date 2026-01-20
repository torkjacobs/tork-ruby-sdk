# frozen_string_literal: true

module Tork
  # Base error class for all Tork errors
  class Error < StandardError
    attr_reader :http_status, :code, :details

    def initialize(message = nil, http_status: nil, code: nil, details: nil)
      @http_status = http_status
      @code = code
      @details = details
      super(message)
    end
  end

  # Raised when API authentication fails
  class AuthenticationError < Error
    def initialize(message = "Invalid or missing API key")
      super(message, http_status: 401, code: "AUTHENTICATION_ERROR")
    end
  end

  # Raised when rate limit is exceeded
  class RateLimitError < Error
    attr_reader :retry_after

    def initialize(message = "Rate limit exceeded", retry_after: nil)
      @retry_after = retry_after
      super(message, http_status: 429, code: "RATE_LIMIT_ERROR")
    end
  end

  # Raised when a resource is not found
  class NotFoundError < Error
    def initialize(message = "Resource not found")
      super(message, http_status: 404, code: "NOT_FOUND")
    end
  end

  # Raised when request validation fails
  class ValidationError < Error
    def initialize(message = "Validation failed", details: nil)
      super(message, http_status: 400, code: "VALIDATION_ERROR", details: details)
    end
  end

  # Raised when the server returns an error
  class ServerError < Error
    def initialize(message = "Server error")
      super(message, http_status: 500, code: "SERVER_ERROR")
    end
  end

  # Raised when a request times out
  class TimeoutError < Error
    def initialize(message = "Request timed out")
      super(message, code: "TIMEOUT_ERROR")
    end
  end

  # Raised when a connection cannot be established
  class ConnectionError < Error
    def initialize(message = "Failed to connect to Tork API")
      super(message, code: "CONNECTION_ERROR")
    end
  end

  # Raised when a policy violation is detected
  class PolicyViolationError < Error
    attr_reader :violations

    def initialize(message = "Policy violation detected", violations: [])
      @violations = violations
      super(message, http_status: 422, code: "POLICY_VIOLATION")
    end
  end

  # Raised when usage limit is exceeded
  class UsageLimitError < Error
    def initialize(message = "Usage limit exceeded")
      super(message, http_status: 429, code: "USAGE_LIMIT_ERROR")
    end
  end
end
