# frozen_string_literal: true

require "set"
require "json"

module TorkGovernance
  # Tool-result scanning (DECIDED-TACT2-V2-C).
  #
  # A tool result returned by an MCP server -- or by any external system the
  # caller does not control -- is untrusted input that is about to be
  # appended to a model's context. This module scans it BEFORE that happens,
  # on-device, for two things:
  #
  #   1. PII, using the SAME on-device detector as govern() (PIIDetector in
  #      ./pii). Nothing new was written for this: same patterns, same
  #      redaction labels, same zero-network guarantee.
  #   2. Prompt injection, using the conservative heuristic pattern set
  #      below. Every injection finding is labelled `heuristic:<type>` so no
  #      caller can mistake a regex hit for a verified determination.
  #
  # ZERO NETWORK. Every method here is pure and synchronous: no socket, no
  # I/O, no clock. The payload never leaves the machine.
  #
  # This is a byte-for-byte port of tool-result-scan.ts (see
  # DECIDED-TACT2-V2-C in the JS SDK session). What must match the JS SDK
  # exactly: the `tool_result_scan` receipt block (snake_case keys, emitted
  # alphabetically, optional keys omitted rather than nulled),
  # attested_by='client', capture_mode='edge',
  # injection_ruleset='tork-injection-heuristics-v1', the `heuristic:`
  # finding-type prefix, the three injection type names
  # (instruction_override, role_reassignment, exfiltration_url), the
  # four-way action mapping (in Client#scan_tool_result), the location path
  # grammar ($.a[0].b), and the injection regex sources themselves.
  # Traversal mechanics, cycle guarding, and identity preservation are
  # reimplemented in Ruby idiom but preserve the same semantics as the
  # TypeScript source.
  #
  # PARITY TIER: this SDK ships TIER 1 only -- the same 10-type basic PII
  # vocabulary as the JS SDK, with JS-identical labels (see ./pii). It does
  # not implement the Python SDK's regional/industry pattern tier.
  module ToolResultScan
    # One (kind, type) match count at one location in a scanned payload.
    # kind is 'pii' or 'injection'. For kind='pii', type is a PIIType value
    # ('ssn', 'email', ...). For kind='injection', type is always
    # `heuristic:<name>` -- the prefix is part of the value, not decoration,
    # so a downstream reader of a receipt cannot mistake a pattern hit for a
    # verified determination.
    ToolResultFinding = Struct.new(:kind, :type, :count, :location, keyword_init: true)

    # Result of scanning one tool result payload. `sanitized` is the payload
    # with PII masked in place, structurally identical otherwise; sub-trees
    # containing no PII keep their original object identity, so a clean
    # payload comes back untouched. `sanitized` is `nil` when `blocked` is
    # true -- there is deliberately no masked payload to accidentally
    # append.
    class ToolResultScanResult
      attr_reader :sanitized, :findings, :blocked, :reason

      def initialize(sanitized:, findings:, blocked:, reason: nil)
        @sanitized = sanitized
        @findings = findings
        @blocked = blocked
        @reason = reason
      end

      alias blocked? blocked
    end

    # ==========================================================================
    # Injection heuristics
    # ==========================================================================

    # Prefix on every injection finding's `type`. Not cosmetic: these
    # patterns are regexes over untrusted text, they carry false positives
    # and false negatives, and the label travels with the finding into the
    # receipt.
    INJECTION_HEURISTIC_PREFIX = "heuristic:"

    # Identifies this exact pattern set in receipts. Bump when the patterns
    # change, so a receipt says which ruleset produced its counts. Every SDK
    # mirroring this implementation must emit the SAME value for the same
    # ruleset -- it is a shared identifier, not a per-language one.
    INJECTION_RULESET = "tork-injection-heuristics-v1"

    # Conservative on purpose. Each pattern targets a phrase that has no
    # plausible reason to appear in a legitimate tool result -- a database
    # row, a search hit, a file listing. Broader "suspicious language"
    # matching would fire on ordinary documentation and support tickets, and
    # an alert nobody believes is worse than no alert.
    #
    # Regex sources are ported verbatim from tool-result-scan.ts's
    # INJECTION_PATTERNS. ENGINE WORKAROUNDS:
    #   - JS regex literals need the `g` (global) flag to find every match;
    #     Ruby's String#scan/#gsub already finds every non-overlapping match
    #     with a plain pattern, so `g` has no Ruby equivalent and is simply
    #     dropped -- and unlike JS's stateful `lastIndex` on a `/g` RegExp,
    #     Ruby Regexp objects carry no scan position, so (unlike the JS
    #     source) there is no need to rebuild a fresh Regexp per call.
    #   - JS's `m` flag makes `^`/`$` match at line boundaries (it does NOT
    #     affect `.`). Ruby's `^`/`$` already match at line boundaries by
    #     default -- that is simply how Ruby anchors work, with no opt-in
    #     needed -- so the JS `gim`-flagged pattern below only needs Ruby's
    #     `i` flag. (Ruby's own `m` flag means something different --
    #     dot-matches-newline -- so it must NOT be added here; none of these
    #     patterns use a bare `.` metacharacter, so this distinction doesn't
    #     otherwise affect behavior.)
    #   - `%r{...}` literals are used instead of `/.../ ` so the `https?://`
    #     URL patterns don't need their slashes backslash-escaped the way
    #     the JS source escapes them.
    INJECTION_PATTERNS = [
      # -- instruction override --------------------------------------------
      {
        type: "instruction_override",
        pattern: %r{\b(?:ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}\b(?:previous|prior|earlier|above|preceding|all|any)\b[^.\n]{0,30}\b(?:instruction|instructions|prompt|prompts|rule|rules|direction|directions|guideline|guidelines)\b}i
      },
      {
        type: "instruction_override",
        pattern: %r{\b(?:the\s+)?(?:instructions?|prompts?|rules?)\s+(?:above|below|before\s+this)\s+(?:are|is)\s+(?:now\s+)?(?:void|invalid|obsolete|outdated|no\s+longer\s+(?:valid|active|in\s+effect))\b}i
      },
      {
        type: "instruction_override",
        pattern: %r{\bdisregard\s+(?:your|the)\s+(?:system\s+)?(?:prompt|instructions?|guidelines?)\b}i
      },

      # -- role reassignment ------------------------------------------------
      {
        type: "role_reassignment",
        pattern: %r{\byou\s+are\s+(?:now|no\s+longer)\s+(?:a|an|the)\b}i
      },
      {
        type: "role_reassignment",
        pattern: %r{\b(?:from\s+now\s+on|starting\s+now|for\s+the\s+rest\s+of\s+this\s+(?:conversation|session))\b[^.\n]{0,30}\byou\s+(?:are|will|must|should)\b}i
      },
      {
        type: "role_reassignment",
        pattern: %r{\bnew\s+(?:system\s+)?(?:instructions?|prompt|persona|role)\s*:}i
      },
      {
        type: "role_reassignment",
        pattern: %r{\b(?:enable|enter|activate|switch\s+to)\s+(?:developer|god|dan|jailbreak|unrestricted)\s+mode\b}i
      },
      {
        type: "role_reassignment",
        pattern: %r{\b(?:act|behave|respond|pretend\s+to\s+be)\s+as\s+(?:if\s+you\s+(?:are|were)\s+)?(?:an?\s+)?(?:dan|unrestricted|unfiltered|uncensored|jailbroken)\b}i
      },
      {
        # A role header smuggled into content -- "system:" /
        # "<|im_start|>system" at the start of a line is a
        # conversation-structure forgery, not prose.
        type: "role_reassignment",
        pattern: %r{^[ \t>*-]*(?:<\|im_start\|>\s*)?(?:system|assistant|developer)\s*(?::|\]|>)}i
      },

      # -- exfiltration -----------------------------------------------------
      {
        # A markdown image/link whose URL carries the content out as a query
        # parameter -- the classic zero-click exfiltration shape.
        type: "exfiltration_url",
        pattern: %r{!?\[[^\]\n]*\]\(\s*https?://[^)\s]*[?&][^)\s]*(?:data|payload|prompt|content|text|secret|token|key|conversation|history)=[^)\s]*\)}i
      },
      {
        type: "exfiltration_url",
        pattern: %r{\bhttps?://\S*[?&](?:data|payload|secret|token|api[_-]?key|apikey|password|credential|conversation|history)=}i
      },
      {
        type: "exfiltration_url",
        pattern: %r{\b(?:send|post|upload|forward|transmit|exfiltrate|leak|report)\b[^.\n]{0,60}\bto\s+https?://\S+}i
      }
    ].freeze

    # Distinct injection types the ruleset can emit, for documentation/tests.
    INJECTION_TYPES = INJECTION_PATTERNS.map { |p| p[:type] }.uniq.sort.freeze

    # ==========================================================================
    # Traversal
    # ==========================================================================

    DEFAULT_MAX_DEPTH = 32

    IDENTIFIER = /^[A-Za-z_$][A-Za-z0-9_$]*$/.freeze

    def self.child_path(parent, key)
      IDENTIFIER.match?(key) ? "#{parent}.#{key}" : "#{parent}[#{key.to_s.to_json}]"
    end
    private_class_method :child_path

    # Scan one string: PII (via the shared detector) then injection
    # heuristics. Returns the masked string plus any findings, both keyed to
    # `location`.
    def self.scan_string(text, location, custom_patterns, findings)
      pii = PIIDetector.detect(text)

      if pii.count.positive?
        # Counts per type, emitted in a stable (sorted) order so two runs
        # over the same payload produce identical findings.
        per_type = Hash.new(0)
        pii.matches.each { |match| per_type[match.type] += 1 }
        per_type.keys.sort.each do |type|
          findings << ToolResultFinding.new(kind: "pii", type: type, count: per_type[type], location: location)
        end
      end

      per_injection_type = Hash.new(0)
      INJECTION_PATTERNS.each do |entry|
        count = text.scan(entry[:pattern]).length
        per_injection_type[entry[:type]] += count if count.positive?
      end
      per_injection_type.keys.sort.each do |type|
        findings << ToolResultFinding.new(
          kind: "injection",
          type: "#{INJECTION_HEURISTIC_PREFIX}#{type}",
          count: per_injection_type[type],
          location: location
        )
      end

      redacted = pii.redacted_text
      # NOTE (inherited from JS's detectPII): custom patterns redact but are
      # not counted, so they can change `sanitized` without producing a
      # finding. ENGINE DIFFERENCE: JS's String#replace only replaces every
      # match when the caller's RegExp carries the `g` flag (otherwise just
      # the first); Ruby's #gsub always replaces every match -- there is no
      # Ruby equivalent of a non-global #replace to mirror a non-`g` custom
      # pattern, so a caller-supplied pattern here always redacts globally.
      if custom_patterns
        custom_patterns.each do |name, pattern|
          redacted = redacted.gsub(pattern, "[#{name.to_s.upcase}_REDACTED]")
        end
      end
      redacted
    end
    private_class_method :scan_string

    # Walk the payload, scanning every string. Returns a structure with PII
    # masked in place; sub-trees with nothing to mask keep their original
    # identity (so an untouched payload is `equal?` its input).
    #
    # Only strings are scanned. Numbers, booleans, and anything else
    # non-Hash/non-Array pass through untouched -- a bank account stored as
    # a JSON number is NOT detected. Cycles are left as-is and not
    # re-entered.
    def self.walk(value, location, depth, max_depth, custom_patterns, findings, seen)
      return scan_string(value, location, custom_patterns, findings) if value.is_a?(String)
      return value if depth >= max_depth || value.nil? || !(value.is_a?(Hash) || value.is_a?(Array))

      return value if seen.include?(value.object_id)

      seen << value.object_id

      if value.is_a?(Array)
        changed = false
        out = value.each_with_index.map do |item, index|
          next_item = walk(item, "#{location}[#{index}]", depth + 1, max_depth, custom_patterns, findings, seen)
          changed ||= item_changed?(item, next_item)
          next_item
        end
        return changed ? out : value
      end

      changed = false
      out = {}
      value.each do |key, item|
        next_item = walk(item, child_path(location, key), depth + 1, max_depth, custom_patterns, findings, seen)
        changed ||= item_changed?(item, next_item)
        out[key] = next_item
      end
      changed ? out : value
    end
    private_class_method :walk

    # String leaves always come back from #scan_string as a freshly
    # allocated String (PIIDetector#detect dups/gsubs unconditionally), so
    # comparing by object identity would report "changed" even when the
    # content is byte-for-byte the same. JS's `next !== item` doesn't have
    # this problem because JS strings are primitives compared by value; Hash
    # and Array, in both languages, are containers compared by reference. So
    # strings compare by value here and containers by identity, matching
    # what `!==` actually does in the JS source for each type.
    def self.item_changed?(item, next_item)
      item.is_a?(String) ? next_item != item : !next_item.equal?(item)
    end
    private_class_method :item_changed?

    # ==========================================================================
    # Public API
    # ==========================================================================

    # Scan a tool result for PII and prompt injection before it is appended
    # to model context. Pure, synchronous, on-device: makes no network call
    # and mutates nothing.
    #
    # For the receipt-linked form (attested_by='client', capture_mode='edge'),
    # use `Client#scan_tool_result`, which wraps this and records the scan.
    def self.scan_tool_result(
      tool_name:,
      payload:,
      server_uri: nil,
      block_on_injection: false,
      custom_patterns: nil,
      max_depth: DEFAULT_MAX_DEPTH
    )
      findings = []
      sanitized = walk(payload, "$", 0, max_depth, custom_patterns, findings, Set.new)

      injection_count = findings.sum { |f| f.kind == "injection" ? f.count : 0 }
      blocked = !!block_on_injection && injection_count.positive?

      if blocked
        types = findings.select { |f| f.kind == "injection" }.map(&:type).uniq.sort
        reason =
          "Blocked: #{injection_count} prompt-injection heuristic match(es) [#{types.join(', ')}] in the result of " \
          "tool \"#{tool_name}\". These are heuristic pattern matches (#{INJECTION_RULESET}), not a verified " \
          "determination. sanitized is nil so no masked copy can be appended to context by accident."
        return ToolResultScanResult.new(sanitized: nil, findings: findings, blocked: true, reason: reason)
      end

      ToolResultScanResult.new(sanitized: sanitized, findings: findings, blocked: false)
    end

    # ==========================================================================
    # Receipt block
    # ==========================================================================

    # The `tool_result_scan` block recorded on the receipt.
    #
    # snake_case, keys emitted in alphabetical order, optional keys OMITTED
    # entirely rather than set to nil -- every SDK that mirrors this must
    # produce a byte-identical block for the same scan.
    #
    # It carries COUNTS ONLY. No payload, no matched substring, no location
    # path, no tool argument ever appears here.
    def self.counts_by_type(findings, kind)
      totals = Hash.new(0)
      findings.each do |finding|
        next unless finding.kind == kind

        totals[finding.type] += finding.count
      end
      totals.keys.sort.each_with_object({}) { |type, out| out[type] = totals[type] }
    end
    private_class_method :counts_by_type

    # Build the receipt block for a completed scan. Insertion order here IS
    # the emitted key order: alphabetical, with optional keys omitted.
    def self.build_tool_result_scan_block(tool_name:, result:, sdk_version:, server_uri: nil)
      pii = counts_by_type(result.findings, "pii")
      injection = counts_by_type(result.findings, "injection")
      sum = ->(counts) { counts.values.sum }

      block = {
        attested_by: "client",
        blocked: result.blocked,
        capture_mode: "edge",
        findings: { injection: injection, pii: pii },
        injection_ruleset: INJECTION_RULESET
      }
      block[:reason] = result.reason unless result.reason.nil?
      block[:sdk_language] = "ruby"
      block[:sdk_version] = sdk_version
      block[:server_uri] = server_uri unless server_uri.nil?
      block[:tool_name] = tool_name
      block[:totals] = { injection: sum.call(injection), pii: sum.call(pii) }
      block
    end

    # Distinct PII types in a scan result, for the attestation canonical form.
    def self.scan_pii_types(findings)
      findings.select { |f| f.kind == "pii" }.map(&:type).uniq.sort
    end

    # Total PII match count in a scan result.
    def self.scan_pii_count(findings)
      findings.sum { |f| f.kind == "pii" ? f.count : 0 }
    end

    # Total injection match count in a scan result.
    def self.scan_injection_count(findings)
      findings.sum { |f| f.kind == "injection" ? f.count : 0 }
    end

    # Deterministic serialisation for hashing a tool-result payload: Hash
    # keys sorted, so two structurally identical payloads always hash the
    # same regardless of key insertion order. Cycles collapse to a stable
    # placeholder rather than recursing forever -- a receipt must never fail
    # to be produced because a tool returned something exotic. The output is
    # fed straight into SHA256 (see Receipt.hash_text) and is never stored
    # or sent.
    def self.stable_stringify(value, seen = {})
      return "null" if value.nil?
      return value.to_json if value.is_a?(String)
      return value.to_s if [true, false].include?(value)
      return (value.finite? ? value.to_s : '"[non-finite]"') if value.is_a?(Numeric)

      unless value.is_a?(Array) || value.is_a?(Hash)
        return "[#{value.class}]".to_json
      end

      return '"[circular]"' if seen.key?(value.object_id)

      seen[value.object_id] = true

      if value.is_a?(Array)
        return "[#{value.map { |item| stable_stringify(item, seen) }.join(',')}]"
      end

      entries = value.sort_by { |k, _| k.to_s }.map { |k, v| "#{k.to_s.to_json}:#{stable_stringify(v, seen)}" }
      "{#{entries.join(',')}}"
    end
  end
end
