//
// Created by Spencer Michaels on 10/1/18.
//

#ifndef XENDBG_GDBREQUESTPACKETBASE_HPP
#define XENDBG_GDBREQUESTPACKETBASE_HPP

#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>

#define DECLARE_SIMPLE_REQUEST(name, ch) \
  class name : public GDBRequestBase { \
  public: \
    explicit name(const std::string &data) \
      : GDBRequestBase(data, ch) \
    { \
      expect_end(); \
    }; \
  }

namespace xd::gdb::req {

  class RequestPacketParseException : public std::runtime_error {
  public:
    RequestPacketParseException(const std::string &msg)
        : std::runtime_error(msg) {};
  };

  class GDBRequestBase {
  public:
    GDBRequestBase(const std::string &data, char header)
        : _data(data), _it(_data.begin())
    {
      expect_char(header);
    };

    GDBRequestBase(const std::string &data, const std::string &header)
        : _data(data), _it(_data.begin())
    {
      expect_string(header);
    };

    size_t get_num_remaining() {
      return _data.end() - _it;
    };

    bool has_more(size_t n = 1) {
      return (size_t)( _data.end() - _it) >= n;
    }

    void assert_char_not(char ch) {
      expect_more();
      if (peek() == ch)
        throw RequestPacketParseException(
            std::string("assert_char_not(") + ch + ") failed");
    };

    bool check_char(char ch) {
      bool found = (peek() == ch);
      if (found)
        get_char();
      return found;
    };

    bool check_string(const std::string &s) {
      bool found = ((size_t)(_data.end() - _it) >= s.size()) &&
                   std::equal(s.begin(), s.end(), _it, _data.end());

      if (found)
        _it += s.size();
      return found;
    };

    void expect_char(char ch) {
      if (get_char() != ch)
        throw RequestPacketParseException(
            std::string("expect_char(") + ch + ") failed");
    };

    void skip_space() {
      while (peek() == ' ')
        get_char();
    };

    void expect_string(const std::string& s) {
      for (const auto c : s) {
        expect_char(c);
      }
    }

    void expect_more(size_t n = 1) {
      if (!has_more(n))
        throw RequestPacketParseException(
            std::string("expect_more(") + std::to_string(n) + ") failed");
    }

    void expect_end() {
      if (has_more())
        throw RequestPacketParseException("expect_end() failed");
    }

    char peek() {
      expect_more();
      return *_it;
    };

    char get_char() {
      expect_more();
      return *_it++;
    };

    uint8_t read_byte() {
      const auto from_hex = [](const auto c) {
        if (c >= '0' && c <= '9')
          return c - '0';

        auto cl = std::tolower(c);
        if (cl >= 'a' && cl <= 'f')
          return 0xa + (cl - 'a');

        throw RequestPacketParseException(
            std::string("read_byte failed on invalid hex char '")
            + std::to_string((unsigned)cl) + "'");
      };

      uint8_t c1 = from_hex(get_char());
      uint8_t c2 = from_hex(get_char());

      return (c1 << 4) + c2;
    };

    template <typename Value_t>
    Value_t read_hex_number() {
      size_t end;
      const std::string num_str(_it, _data.end());
      Value_t num = std::stoull(num_str, &end, 2*sizeof(uint64_t));

      _it += end;

      return num;
    };

    template <typename Value_t>
    Value_t read_hex_number_respecting_endianness() {
      Value_t value;
      uint8_t *value_ptr = (uint8_t*)&value;
      size_t remaining = 2*sizeof(Value_t);

      while (has_more() && remaining) {
        *value_ptr++ = read_byte();
        remaining -= 2;
      }

      if (remaining)
        throw RequestPacketParseException("Incomplete hex number");

      return value;
    };

    std::string read_until_end() {
      std::string s;
      while (has_more()) {
        s.push_back(get_char());
      }
      if (has_more())
        get_char();
      return s;
    }

    std::string read_until_char_or_end(char ch) {
      std::string s;
      while (has_more() && peek() != ch) {
        s.push_back(get_char());
      }
      if (has_more())
        get_char();
      return s;
    }

    template <typename Word_t>
    std::optional<Word_t> read_word_unsigned_opt() {
      static constexpr auto SIZE = 2*sizeof(Word_t);
      static const auto NOT_SPECIFIED = std::string(SIZE, 'x');

      expect_more(SIZE);
      const std::string s(_it, _it + SIZE);

      if (s == NOT_SPECIFIED)
        return std::nullopt;

      size_t end;
      Word_t num = std::stoull(s, &end, 16);
      if (end != SIZE)
        throw RequestPacketParseException("Incomplete hex number");

      _it += SIZE;
      return num;
    }

  private:
    const std::string _data;
    std::string::const_iterator _it;
  };

}

#endif //XENDBG_GDBREQUESTPACKETBASE_HPP

