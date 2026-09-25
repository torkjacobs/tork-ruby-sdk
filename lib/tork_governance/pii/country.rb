# frozen_string_literal: true

# The country layer: 24 country profiles, 51 patterns, 20 check digits.
#
# This implements the seven rules that generated/sdk-registry/README.md marks
# SDK, from the bundle alone. Bundle 1.1.0 carries the data all seven need --
# the activation signals, the country map, the three windows, the whole-word
# vocabulary, the near-miss policy, the table constants and the reference
# labels -- so nothing here is hand-written registry data and no window is
# hard-coded.
#
#   1. ACTIVATE   a country's patterns run only when one of its signals fires.
#   2. MATCH      the regex, case-sensitively, globally.
#   3. KEYWORD    whole-word (symmetric CONTEXT_WINDOW) or column verdict or
#                 the ASYMMETRIC substring window (60 before, 40 after); then
#                 7b may close the gate again.
#   4. CHECKSUM   when required. Advisory checksums never reject.
#   5. SUPERSEDE  a match containing every range it overlaps takes them.
#   6. NEAR MISS  a checksum-failing identifier is redacted generically.
#   7. COLUMN     in a delimited table a bare value cell is judged by its header.
#   7b. NEAREST LABEL  a closer commercial label closes the gate.
#
# Still cloud-only, by design: the universal (L0) patterns, the slot, context,
# gravity and name layers, industry profiles and org configuration.

require_relative 'registry'
require_relative 'checksums'

module Tork
  module Governance
    module Pii
      # One country identifier found in the content.
      #
      # NOTE: `value` returns the RAW matched text, not the redaction. That is a
      # breaking change from 0.x, where it returned the redaction token; it is
      # left as-is deliberately so a caller can see what matched, and flagged in
      # the CHANGELOG rather than changed silently.
      PIIMatch = Struct.new(:name, :country, :label, :type, :redaction, :start_index, :end_index, :value) do
        def to_h
          { name: name, country: country, label: label, type: type,
            redaction: redaction, start_index: start_index, end_index: end_index }
        end
      end

      module Country
        # A span of the original text and the token that replaces it.
        # Constructed with keyword arguments by TorkGovernance::PIIDetector.
        RedactionSpan = Struct.new(:start_index, :end_index, :redaction, keyword_init: true)

        module_function

        # Characters before a match that count as nearby for the substring gate.
        KEYWORD_WINDOW_BEFORE = Pii::KEYWORD_WINDOW_BEFORE
        # Characters after. Deliberately NOT the same number as BEFORE.
        KEYWORD_WINDOW_AFTER = Pii::KEYWORD_WINDOW_AFTER
        # The symmetric window: whole-word keywords and the near-miss gate.
        CONTEXT_WINDOW = Pii::CONTEXT_WINDOW

        BY_NAME = PATTERNS.each_with_object({}) { |p, h| h[p[:name]] = p }.freeze
        # Rule 1a: these run on every document, whatever rule 1 (country
        # activation) returns, and run before the activated country patterns
        # so an activated pattern can still supersede one under rule 5.
        ALWAYS_ON_PATTERNS = PATTERNS.select { |p| p[:always_on] }.freeze
        COUNTRY_PATTERNS = COUNTRIES.each_with_object({}) { |c, h| h[c[:code]] = c[:patterns] }.freeze
        SIGNAL_ORDER = SIGNALS.map { |s| s[:country] }.uniq.freeze
        COMPILED = PATTERNS.each_with_object({}) { |p, h| h[p[:name]] = Regexp.new(p[:regex]) }.freeze
        COMPILED_SIGNALS = SIGNALS.map do |s|
          Regexp.new(s[:regex], s[:flags].include?('i') ? Regexp::IGNORECASE : 0)
        end.freeze
        GENERIC_SET = GENERIC_ID_KEYWORDS.to_set rescue GENERIC_ID_KEYWORDS.each_with_object({}) { |k, h| h[k] = true }
        NATIONAL_ID_KEYWORDS = (GENERIC_ID_KEYWORDS + LOCAL_ID_KEYWORDS).freeze

        ALNUM = /[a-z0-9]/.freeze
        ALNUM_ANY = /[0-9A-Za-z]/.freeze

        def generic?(keyword)
          GENERIC_SET.is_a?(Hash) ? GENERIC_SET.key?(keyword) : GENERIC_SET.include?(keyword)
        end

        # A pattern's whole vocabulary: the substring keywords and the whole-word ones.
        def all_keywords_of(pattern)
          ww = pattern[:whole_word_keywords]
          ww.empty? ? pattern[:keywords] : pattern[:keywords] + ww
        end

        # The half of a vocabulary that names ONE country's identifier.
        def specific_keywords(keywords)
          keywords.reject { |k| generic?(k) }
        end

        # Rule 3, substring half: ASYMMETRIC -- 60 before the match, 40 after it.
        def has_nearby_context?(content, start_i, end_i, keywords)
          before = content[[0, start_i - KEYWORD_WINDOW_BEFORE].max...start_i].to_s.downcase
          after = content[end_i, KEYWORD_WINDOW_AFTER].to_s.downcase
          keywords.any? { |kw| before.include?(kw) || after.include?(kw) }
        end

        def window_around(content, start_i, end_i)
          lo = [0, start_i - CONTEXT_WINDOW].max
          hi = [content.length, end_i + CONTEXT_WINDOW].min
          content[lo...hi].to_s
        end

        # Symmetric CONTEXT_WINDOW either side, substring. Used by rule 6.
        def has_context_around?(content, start_i, end_i, keywords)
          w = window_around(content, start_i, end_i).downcase
          keywords.any? { |kw| w.include?(kw) }
        end

        # Rule 3, whole-word half: symmetric CONTEXT_WINDOW, a boundary each side,
        # a boundary being "not a letter or digit".
        #
        # This is the gate Indonesia needs: `nik` sits inside teknik, elektronik,
        # klinik and pabrik, so a substring test would open the gate on a ledger.
        def has_whole_word_context_around?(content, start_i, end_i, words)
          return false if words.nil? || words.empty?

          w = window_around(content, start_i, end_i).downcase
          n = w.length
          words.each do |word|
            from = 0
            loop do
              i = w.index(word, from)
              break if i.nil?

              before_ok = i.zero? || !ALNUM.match?(w[i - 1])
              j = i + word.length
              after_ok = j >= n || !ALNUM.match?(w[j])
              return true if before_ok && after_ok

              from = i + 1
            end
          end
          false
        end

        def document_has_whole_word?(content, words)
          return false if words.nil? || words.empty?

          has_whole_word_context_around?(content, 0, content.length, words)
        end

        # ── rule 1: activation ────────────────────────────────────────────────

        # The countries this text activates, in the bundle's signal order.
        def infer_regions(content)
          regions = []
          lower = content.downcase
          SIGNAL_ORDER.each do |code|
            SIGNALS.each_with_index do |signal, i|
              next unless signal[:country] == code
              next unless COMPILED_SIGNALS[i].match?(content)

              by_substring = !signal[:keywords].empty? && signal[:keywords].any? { |k| lower.include?(k) }
              by_whole_word = document_has_whole_word?(content, signal[:whole_word_keywords])
              # Both lists empty means the shape alone is distinctive enough.
              if (!signal[:keywords].empty? || !signal[:whole_word_keywords].empty?) &&
                 !by_substring && !by_whole_word
                next
              end

              target = signal[:activates].to_s.empty? ? code : signal[:activates]
              regions << target unless regions.include?(target)
              break # one signal per country is enough
            end
          end
          regions
        end

        def patterns_for_regions(regions)
          out = []
          seen = {}
          regions.each do |code|
            (COUNTRY_PATTERNS[code.to_s.upcase] || []).each do |name|
              next if seen[name] || BY_NAME[name].nil?

              seen[name] = true
              out << BY_NAME[name]
            end
          end
          out
        end

        # ── rule 7: the column is the context ─────────────────────────────────

        def looks_like_header?(cells, delimiter)
          minimum = delimiter == ',' ? TABLE_MIN_COMMA_COLUMNS : 2
          return false if cells.length < minimum

          cells.all? do |c|
            t = c.strip
            next false if t.empty? || t.length > TABLE_MAX_HEADER_LENGTH
            next false unless /[A-Za-zÀ-￿]/.match?(t)
            next false if /\A\+?[\d\s.\-\/]+\z/.match?(t)
            next false if /[.?!]/.match?(t)

            t.split(/\s+/).length <= TABLE_MAX_HEADER_WORDS
          end
        end

        # The cells of `content`, when it is a delimited table with a header row.
        def table_scopes(content)
          lines = content.split("\n", -1)
          return [] if lines.length < TABLE_MIN_ROWS

          offsets = []
          at = 0
          lines.each do |line|
            offsets << at
            at += line.length + 1
          end

          TABLE_DELIMITERS.each do |delimiter|
            header_cells = lines[0].split(delimiter, -1)
            next unless looks_like_header?(header_cells, delimiter)

            width = header_cells.length
            data_rows = []
            (1...lines.length).each do |i|
              next if lines[i].strip.empty?
              return [] if lines[i].split(delimiter, -1).length != width

              data_rows << i
            end
            next if data_rows.length < TABLE_MIN_ROWS - 1

            scopes = []
            data_rows.each do |row|
              cells = lines[row].split(delimiter, -1)
              row_start = offsets[row]
              row_end = row_start + lines[row].length
              cell_start = row_start
              width.times do |col|
                scopes << { start: cell_start, end: cell_start + cells[col].length,
                            header: header_cells[col].strip.downcase,
                            row_start: row_start, row_end: row_end }
                cell_start += cells[col].length + delimiter.length
              end
            end
            return scopes
          end
          []
        end

        # A whole-word match, not a substring.
        def header_names?(header, keywords)
          keywords.each do |kw|
            i = header.index(kw)
            next if i.nil?

            before_ok = i.zero? || !ALNUM.match?(header[i - 1])
            j = i + kw.length
            after_ok = j >= header.length || !ALNUM.match?(header[j])
            return true if before_ok && after_ok
          end
          false
        end

        # nil when the window should be consulted as usual.
        def column_verdict(content, scopes, start_i, end_i, all, specific)
          return nil if scopes.empty?

          cell = scopes.find { |s| start_i >= s[:start] && end_i <= s[:end] }
          return nil if cell.nil?

          # A cell whose own row names the identifier is prose in a delimited block.
          row_text = content[cell[:row_start]...cell[:row_end]].to_s.downcase
          return nil if all.any? { |k| row_text.include?(k) }

          !specific.empty? && header_names?(cell[:header], specific)
        end

        # ── rule 7b: nearest label wins ───────────────────────────────────────

        def closest_before(before, keywords)
          best = nil
          keywords.each do |kw|
            i = before.rindex(kw)
            next if i.nil?

            d = before.length - (i + kw.length)
            best = d if best.nil? || d < best
          end
          best
        end

        def closest_after(after, keywords)
          best = nil
          keywords.each do |kw|
            i = after.index(kw)
            next if i.nil?

            best = i if best.nil? || i < best
          end
          best
        end

        # Whether the number is labelled as a commercial reference more closely
        # than as an identifier. It can only ever close a gate, never open one.
        def labelled_as_reference?(content, start_i, end_i, identifier_keywords)
          before = content[[0, start_i - LABEL_WINDOW].max...start_i].to_s.downcase
          ref = closest_before(before, REFERENCE_LABELS)
          return false if ref.nil? || ref > LABEL_REACH
          return true if identifier_keywords.nil? || identifier_keywords.empty?

          id_before = closest_before(before, identifier_keywords)
          return false if !id_before.nil? && id_before <= ref

          after = content[end_i, LABEL_WINDOW].to_s.downcase
          id_after = closest_after(after, identifier_keywords)
          return false if !id_after.nil? && id_after <= ref

          true
        end

        # ── the pass ──────────────────────────────────────────────────────────

        # The span with leading and trailing non-alphanumeric characters removed.
        def trimmed_core(content, start_i, end_i)
          s = start_i
          e = end_i
          s += 1 while s < e && !ALNUM_ANY.match?(content[s])
          e -= 1 while e > s && !ALNUM_ANY.match?(content[e - 1])
          s == e ? [start_i, end_i] : [s, e]
        end

        # Country matches for `content`, de-overlapped and ordered by position.
        #
        # `patterns` bypasses activation; `existing_ranges` are your own L0
        # spans, so rule 5 can supersede them.
        def detect_with_ranges(content, patterns = nil, existing_ranges = [])
          active = patterns ||
                   (ALWAYS_ON_PATTERNS + patterns_for_regions(infer_regions(content))).uniq { |p| p[:name] }
          return { matches: [], superseded: [] } if active.empty?

          tables = table_scopes(content)
          active_existing = existing_ranges.dup
          superseded = []
          claimed = []
          found = []
          near_misses = []

          active.each do |pattern|
            content.to_enum(:scan, COMPILED[pattern[:name]]).each do
              m = Regexp.last_match
              text = m[0]
              next if text.empty?

              start_i = m.begin(0)
              end_i = start_i + text.length

              # Rules 3, 7 and 7b.
              if pattern[:requires_keyword] && !pattern[:keywords].empty?
                all = all_keywords_of(pattern)
                ok = has_whole_word_context_around?(content, start_i, end_i, pattern[:whole_word_keywords])
                unless ok
                  column = column_verdict(content, tables, start_i, end_i, all, specific_keywords(all))
                  ok = column.nil? ? has_nearby_context?(content, start_i, end_i, pattern[:keywords]) : column
                end
                next unless ok
                next if labelled_as_reference?(content, start_i, end_i, pattern[:keywords])
              end

              # Rule 4, and rule 6's candidate.
              if pattern[:checksum_required] && pattern[:checksum]
                fn = Checksums::FUNCTIONS[pattern[:checksum]]
                if fn && !fn.call(text)
                  if pattern[:near_miss_fallback]
                    extra = pattern[:near_miss_keywords].empty? ? pattern[:keywords] : pattern[:near_miss_keywords]
                    vocabulary = extra.empty? ? NATIONAL_ID_KEYWORDS : NATIONAL_ID_KEYWORDS + extra
                    near_misses << [start_i, end_i] if has_context_around?(content, start_i, end_i, vocabulary)
                  end
                  next
                end
              end

              # Rule 5.
              overlapping = (active_existing + claimed).select { |rs, re| start_i < re && end_i > rs }
              unless overlapping.empty?
                supersedes_all = overlapping.all? do |rs, re|
                  cs, ce = trimmed_core(content, rs, re)
                  start_i <= cs && end_i >= ce
                end
                next unless supersedes_all

                overlapping.each do |o|
                  if active_existing.delete(o)
                    superseded << o
                  end
                  claimed.delete(o)
                  found.reject! { |f| f.start_index == o[0] && f.end_index == o[1] }
                end
              end

              claimed << [start_i, end_i]
              found << PIIMatch.new(pattern[:name], pattern[:country], pattern[:label],
                                    pattern[:type], pattern[:redaction], start_i, end_i, text)
            end
          end

          # Rule 6, last: a near miss can only ever fill a hole.
          taken = active_existing + claimed
          near_misses.each do |cs, ce|
            next if taken.any? { |rs, re| cs < re && ce > rs }

            taken << [cs, ce]
            found << PIIMatch.new(NEAR_MISS_TYPE, '', 'NATIONAL_ID', NEAR_MISS_TYPE,
                                  NEAR_MISS_REDACTION, cs, ce, content[cs...ce])
          end

          found.sort_by!(&:start_index)
          { matches: found, superseded: superseded }
        end

        def detect(content, patterns = nil)
          detect_with_ranges(content, patterns)[:matches]
        end

        # Replace every span with its redaction, right to left.
        #
        # Right to left is what keeps the earlier indices valid, and splicing
        # whole spans in one pass is what guarantees no partial redaction: a
        # digit can never be left standing beside a redaction token, because
        # nothing is ever matched against text a previous replacement rewrote.
        def apply_redactions(text, spans)
          return text if spans.empty?

          out = text.dup
          spans.sort_by(&:start_index).reverse_each do |s|
            out = out[0...s.start_index] + s.redaction + out[s.end_index..]
          end
          out
        end
      end
    end
  end
end
