# frozen_string_literal: true

module Tork
  module Governance
    module Pii
      # Check digits for the country registry.
      #
      # The SDK bundle NAMES twenty algorithms and gives weights and a modulus
      # for the eleven that reduce to them; the other nine are marked
      # kind:"custom" and carry no specification, so they are ported here by
      # hand from the cloud's lib/pii/checksums.ts -- the single implementation
      # the cloud and the country corpus both use. Keeping the arithmetic
      # identical is what makes a receipt block from this SDK byte-identical to
      # one from the JavaScript SDK.
      #
      # Every method is pure: a String in, a boolean out. No I/O, no clock.
      module Checksums
        module_function

        def digits_of(str)
          str.gsub(/\D/, '')
        end

        def digit_list(str)
          digits_of(str).each_char.map { |c| c.ord - 48 }
        end

        # Remainder of a long decimal digit string modulo m, digit by digit.
        def mod_digits(digits, m)
          digits.each_char.reduce(0) { |r, ch| (r * 10 + (ch.ord - 48)) % m }
        end

        def all_same_digit?(str)
          !str.empty? && str.chars.uniq.size == 1
        end

        def stripped_upper(str)
          str.gsub(/\s/, '').upcase
        end

        def weighted(digits, weights)
          digits.each_with_index.sum { |d, i| d * weights[i] }
        end

        # Luhn / ISO-IEC 7812-1 mod-10.
        def luhn(input)
          d = digit_list(input)
          return false if d.size < 2

          sum = 0
          dbl = false
          d.reverse_each do |n|
            n *= 2 if dbl
            n -= 9 if dbl && n > 9
            sum += n
            dbl = !dbl
          end
          (sum % 10).zero?
        end

        VERHOEFF_MUL = [
          [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
          [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
          [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
          [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
          [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
          [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
          [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
          [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
          [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
          [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]
        ].freeze

        VERHOEFF_PERM = [
          [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
          [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
          [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
          [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
          [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
          [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
          [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
          [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]
        ].freeze

        # Verhoeff, the Aadhaar check digit (UIDAI Circular No. 1 of 2018).
        def verhoeff(input)
          c = 0
          digit_list(input).reverse.each_with_index do |digit, i|
            c = VERHOEFF_MUL[c][VERHOEFF_PERM[i % 8][digit]]
          end
          c.zero?
        end

        # Australian TFN (ATO): weights 1,4,3,7,5,8,6,9,10, sum mod 11 == 0.
        def au_tfn(input)
          d = digit_list(input)
          return false unless d.size == 9

          (weighted(d, [1, 4, 3, 7, 5, 8, 6, 9, 10]) % 11).zero?
        end

        # Australian ABN (ABR): subtract 1 from the first digit, weights
        # 10,1,3..19, sum mod 89 == 0.
        def au_abn(input)
          d = digit_list(input)
          return false unless d.size == 11

          d = d.dup
          d[0] -= 1
          (weighted(d, [10, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19]) % 89).zero?
        end

        # Australian Medicare card number (Services Australia).
        def au_medicare(input)
          d = digit_list(input)
          return false if d.size < 10
          return false unless (2..6).cover?(d[0])

          weighted(d.first(8), [1, 3, 7, 9, 1, 3, 7, 9]) % 10 == d[8]
        end

        # UK NHS number (NHS Data Model and Dictionary): weights 10..2,
        # check = 11 - (sum mod 11); 11 -> 0; 10 is invalid.
        def uk_nhs(input)
          d = digit_list(input)
          return false unless d.size == 10

          check = 11 - (weighted(d.first(9), (2..10).to_a.reverse) % 11)
          check = 0 if check == 11
          return false if check == 10

          check == d[9]
        end

        # Brazil CPF (Receita Federal): two sequential mod-11 check digits.
        def br_cpf(input)
          d = digit_list(input)
          return false unless d.size == 11
          return false if all_same_digit?(digits_of(input))

          calc = lambda do |len|
            sum = (0...len).sum { |i| d[i] * (len + 1 - i) }
            r = (sum * 10) % 11
            r == 10 ? 0 : r
          end
          calc.call(9) == d[9] && calc.call(10) == d[10]
        end

        # Brazil CNPJ (Receita Federal): two mod-11 check digits with different
        # weight vectors per pass.
        def br_cnpj(input)
          d = digit_list(input)
          return false unless d.size == 14
          return false if all_same_digit?(digits_of(input))

          calc = lambda do |weights|
            r = weighted(d.first(weights.size), weights) % 11
            r < 2 ? 0 : 11 - r
          end
          calc.call([5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]) == d[12] &&
            calc.call([6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]) == d[13]
        end

        # Japan My Number (MIC Ordinance No. 85 of 2014).
        def jp_my_number(input)
          d = digit_list(input)
          return false unless d.size == 12

          sum = (1..11).sum do |n|
            q = n <= 6 ? n + 1 : n - 5
            d[11 - n] * q
          end
          r = sum % 11
          check = r <= 1 ? 0 : 11 - r
          check == d[11]
        end

        CN_SHAPE = /\A\d{17}[\dX]\z/.freeze

        # China resident ID (GB 11643-1999): ISO 7064 MOD 11-2 over 17 digits,
        # with a check character that may be X.
        def cn_resident_id(input)
          s = stripped_upper(input)
          return false unless CN_SHAPE.match?(s)

          body = s[0, 17].each_char.map { |c| c.ord - 48 }
          sum = weighted(body, [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2])
          '10X98765432'[sum % 11] == s[17]
        end

        # Korea RRN, for numbers issued before 20 Oct 2020.
        #
        # ADVISORY ONLY, never a gate: numbers issued from 20 Oct 2020 are
        # randomly assigned and carry no check digit.
        def kr_rrn(input)
          d = digit_list(input)
          return false unless d.size == 13

          sum = weighted(d.first(12), [2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5])
          (11 - (sum % 11)) % 10 == d[12]
        end

        SG_SHAPE = /\A[STFGM]\d{7}[A-Z]\z/.freeze

        # Singapore NRIC/FIN (ICA): weights 2,7,6,5,4,3,2 and a prefix-dependent
        # check-letter table.
        def sg_nric(input)
          s = stripped_upper(input)
          return false unless SG_SHAPE.match?(s)

          body = s[1, 7].each_char.map { |c| c.ord - 48 }
          sum = weighted(body, [2, 7, 6, 5, 4, 3, 2])
          prefix = s[0]
          sum += 4 if %w[T G].include?(prefix)
          sum += 3 if prefix == 'M'

          table = if %w[S T].include?(prefix)
                    'JZIHGFEDCBA'
                  elsif prefix == 'M'
                    'KLJNPQRTUWX'
                  else
                    'XWUTRQPNMLK'
                  end
          table[sum % 11] == s[8]
        end

        CF_ODD = begin
          map = {}
          '0123456789'.each_char.with_index do |c, i|
            map[c] = [1, 0, 5, 7, 9, 13, 15, 17, 19, 21][i]
          end
          letter_values = [1, 0, 5, 7, 9, 13, 15, 17, 19, 21, 2, 4, 18,
                           20, 11, 3, 6, 8, 12, 14, 16, 10, 22, 25, 24, 23]
          ('A'..'Z').each_with_index { |c, i| map[c] = letter_values[i] }
          map.freeze
        end

        CF_SHAPE = /\A[A-Z]{6}\d{2}[A-Z]\d{2}[A-Z]\d{3}[A-Z]\z/.freeze

        # Italy codice fiscale (Agenzia delle Entrate): odd and even position
        # character tables, summed mod 26, mapped to a check letter.
        def it_codice_fiscale(input)
          s = stripped_upper(input)
          return false unless CF_SHAPE.match?(s)

          sum = 0
          15.times do |i|
            c = s[i]
            sum += if i.even?
                     CF_ODD[c]
                   elsif c =~ /\d/
                     c.to_i
                   else
                     c.ord - 65
                   end
          end
          (65 + (sum % 26)).chr == s[15]
        end

        NIR_SHAPE = /\A[12]\d{2}\d{2}(\d{2}|2A|2B)\d{3}\d{3}\d{2}\z/.freeze

        # France NIR (Insee): 97-complement over the 13-digit body, with the
        # Corsican 2A/2B department codes mapped to digits first.
        def fr_nir(input)
          s = stripped_upper(input)
          return false unless NIR_SHAPE.match?(s)

          s = s.sub('2A', '19').sub('2B', '18')
          97 - mod_digits(s[0, 13], 97) == s[13, 2].to_i
        end

        # Germany Steuer-IdNr (BZSt): ISO 7064 MOD 11,10 over 10 digits.
        def de_steuer_id(input)
          d = digit_list(input)
          return false unless d.size == 11
          return false if d[0].zero?

          product = 10
          10.times do |i|
            sum = (d[i] + product) % 10
            sum = 10 if sum.zero?
            product = (sum * 2) % 11
          end
          check = 11 - product
          check = 0 if check == 10
          check == d[10]
        end

        # Thailand national ID (DOPA): weights 13..2 over 12 digits,
        # check = (11 - sum mod 11) mod 10.
        def th_national_id(input)
          d = digit_list(input)
          return false unless d.size == 13

          sum = weighted(d.first(12), (2..13).to_a.reverse)
          (11 - (sum % 11)) % 10 == d[12]
        end

        # Canada SIN (Service Canada): Luhn over 9 digits. Advisory -- the
        # algorithm is community-sourced, not authority-published.
        def ca_sin(input)
          digits_of(input).length == 9 && luhn(input)
        end

        # South Africa ID (SARS PAYE BRS Appendix B 8.3): Luhn over 13 digits.
        def za_id(input)
          digits_of(input).length == 13 && luhn(input)
        end

        # UAE Emirates ID (ICP): Luhn over 15 digits starting 784. Advisory.
        def ae_emirates_id(input)
          d = digits_of(input)
          d.length == 15 && d.start_with?('784') && luhn(d)
        end

        # Saudi national ID / iqama: Luhn over 10 digits starting 1 or 2. Advisory.
        def sa_national_id(input)
          d = digits_of(input)
          d.length == 10 && %w[1 2].include?(d[0]) && luhn(d)
        end

        # Keyed by the bundle's `checksum` field.
        FUNCTIONS = {
          'luhn' => method(:luhn),
          'verhoeff' => method(:verhoeff),
          'au_tfn' => method(:au_tfn),
          'au_abn' => method(:au_abn),
          'au_medicare' => method(:au_medicare),
          'uk_nhs' => method(:uk_nhs),
          'br_cpf' => method(:br_cpf),
          'br_cnpj' => method(:br_cnpj),
          'jp_my_number' => method(:jp_my_number),
          'cn_resident_id' => method(:cn_resident_id),
          'kr_rrn' => method(:kr_rrn),
          'sg_nric' => method(:sg_nric),
          'it_codice_fiscale' => method(:it_codice_fiscale),
          'fr_nir' => method(:fr_nir),
          'de_steuer_id' => method(:de_steuer_id),
          'th_national_id' => method(:th_national_id),
          'ca_sin' => method(:ca_sin),
          'za_id' => method(:za_id),
          'ae_emirates_id' => method(:ae_emirates_id),
          'sa_national_id' => method(:sa_national_id)
        }.freeze

        def functions
          FUNCTIONS
        end

        # The checksum named by the bundle, or nil if it is not implemented.
        def get(name)
          return nil if name.nil?

          FUNCTIONS[name]
        end
      end
    end
  end
end
