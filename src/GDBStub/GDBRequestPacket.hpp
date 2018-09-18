//
// Created by Spencer Michaels on 9/5/18.
//

#ifndef XENDBG_GDBREQUESTPACKET_HPP
#define XENDBG_GDBREQUESTPACKET_HPP

#include <iostream>
#include <optional>
#include <queue>
#include <sstream>
#include <stdexcept>
#include <string>
#include <variant>
#include <vector>

#include "../Registers/RegistersX86.hpp"
#include "../Util/overloaded.hpp"

#define DECLARE_SIMPLE_REQUEST(name, ch) \
  class name : public GDBRequestPacketBase { \
  public: \
    name(const std::string &data) \
      : GDBRequestPacketBase(data, ch) \
    { \
      expect_end(); \
    }; \
  }

#define DECLARE_SIGNAL_REQUESTS(name1, ch1, name2, ch2) \
  DECLARE_SIMPLE_REQUEST(name1, ch1); \
  class name2 : public GDBRequestPacketBase { \
  public: \
    name2(const std::string &data) \
      : GDBRequestPacketBase(data, ch2), _signal(0) \
    { \
      _signal = read_byte(); \
      expect_end(); \
    }; \
    uint8_t get_signal() { return _signal; }; \
  private: \
    uint8_t _signal; \
  }

#define DECLARE_BREAKPOINT_REQUEST(name, ch) \
  class name : public GDBRequestPacketBase { \
  public: \
    name(const std::string &data) \
      : GDBRequestPacketBase(data, ch) \
    { \
      _type = read_hex_number<uint8_t>(); \
      expect_char(','); \
      _address = read_hex_number<uint64_t>(); \
      expect_char(','); \
      _kind = read_hex_number<uint8_t>(); \
      expect_end(); \
    }; \
    uint64_t get_address() const { return _address; }; \
    uint8_t get_type() const { return _type; }; \
    uint8_t get_kind() const { return _kind; }; \
  private: \
    uint64_t _address; \
    uint8_t _type, _kind; \
  }

namespace xd::dbg::gdbstub::pkt {

  /*
  class RequestPacketParseException : public std::runtime_error {
  public:
    RequestPacketParseException(const std::string &msg);
  };
  */
  class RequestPacketParseException : public std::exception {
  };

  class GDBRequestPacketBase {
  public:
    GDBRequestPacketBase(const std::string &data, char header)
      : _data(data), _it(_data.begin())
    {
      expect_char(header);
    };
    
    GDBRequestPacketBase(const std::string &data, const std::string &header)
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
        throw RequestPacketParseException();
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
        throw RequestPacketParseException();
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
        throw RequestPacketParseException();
    }

    void expect_end() {
      if (has_more())
        throw RequestPacketParseException();
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

        throw RequestPacketParseException();
      };

      uint8_t c1 = from_hex(get_char());
      uint8_t c2 = from_hex(get_char());

      return (c1 << 4) + c2;
    };

    template <typename Value_t>
    uint64_t read_hex_number() {
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
        throw RequestPacketParseException();

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
        throw RequestPacketParseException();

      _it += SIZE;
      return num;
    }

  private:
    const std::string _data;
    std::string::const_iterator _it;
  };

  class StartNoAckModeRequest : public GDBRequestPacketBase {
  public:
    StartNoAckModeRequest(const std::string &data)
      : GDBRequestPacketBase(data, "QStartNoAckMode")
    {
      expect_end();
    };
  };

  class QuerySupportedRequest : public GDBRequestPacketBase {
  public:
    QuerySupportedRequest(const std::string &data)
      : GDBRequestPacketBase(data, "qSupported")
    {
      expect_char(':');
      while (has_more()) {
        const auto feature = read_until_char_or_end(';');
        _features.push_back(feature);
      }
      expect_end();
    };

    const std::vector<std::string> get_features() { return _features; };

  private:
    std::vector<std::string> _features;
  };

  DECLARE_SIMPLE_REQUEST(QueryThreadSuffixSupportedRequest, "QThreadSuffixSupported");
  DECLARE_SIMPLE_REQUEST(QueryListThreadsInStopReplySupportedRequest, "QListThreadsInStopReply");

  class RestartRequest : public GDBRequestPacketBase {
  public:
    RestartRequest(const std::string &data)
      : GDBRequestPacketBase(data, 'R')
    {
      read_byte(); // Required, but ignored
      expect_end();
    };
  };
  
  class DetachRequest : public GDBRequestPacketBase {
  public:
    DetachRequest(const std::string &data)
      : GDBRequestPacketBase(data, 'D'), _pid(0)
    {
      if (has_more()) {
        expect_char(';');
        _pid = read_hex_number<size_t>();
      }
      expect_end();
    };

  private:
    size_t _pid;
  };

  class QueryCurrentThreadIDRequest : public GDBRequestPacketBase {
  public:
    QueryCurrentThreadIDRequest(const std::string &data)
      : GDBRequestPacketBase(data, "qC")
    {
      expect_end();
    };
  };

  class QueryThreadInfoStartRequest : public GDBRequestPacketBase {
  public:
    QueryThreadInfoStartRequest(const std::string &data)
      : GDBRequestPacketBase(data, "qfThreadInfo")
    {
      expect_end();
    };
  };

  class QueryThreadInfoContinuingRequest : public GDBRequestPacketBase {
  public:
    QueryThreadInfoContinuingRequest(const std::string &data)
      : GDBRequestPacketBase(data, "qsThreadInfo")
    {
      expect_end();
    };
  };

  class QueryRegisterInfoRequest : public GDBRequestPacketBase {
  public:
    QueryRegisterInfoRequest(const std::string &data)
      : GDBRequestPacketBase(data, "qRegisterInfo")
    {
      _register_id = read_hex_number<uint16_t>();
      expect_end();
    };

    uint16_t get_register_id() const { return _register_id; };

  private:
    uint16_t _register_id;
  };

  DECLARE_SIMPLE_REQUEST(StopReasonRequest, '?');
  DECLARE_SIMPLE_REQUEST(KillRequest, 'k');

  class SetThreadRequest : public GDBRequestPacketBase {
  public:
    SetThreadRequest(const std::string &data)
      : GDBRequestPacketBase(data, 'H')
    {
      if (check_char('c'))
        _op = Op::StepAndContinue;
      else if (check_char('g'))
        _op = Op::StepAndContinue;

      _thread_id = read_hex_number<size_t>();
      expect_end();
    };

    enum class Op {
      StepAndContinue,
      General,
    };

  private:
    Op _op;
    size_t _thread_id;
  };

  class RegisterReadRequest : public GDBRequestPacketBase {
  public:
    RegisterReadRequest(const std::string &data)
      : GDBRequestPacketBase(data, 'p')
    {
      _register_id = read_hex_number<uint16_t>();
      if (check_char(';')) {
        expect_string("thread:");
        _thread_id = read_hex_number<size_t>();
        expect_char(';');
      } else {
        _thread_id = (size_t)-1;
      }
      expect_end();
    };

    uint16_t get_register_id() const { return _register_id; };
    size_t get_thread_id() const { return _thread_id; };

  private:
    uint16_t _register_id;
    size_t _thread_id;
  };

  class RegisterWriteRequest : public GDBRequestPacketBase {
  public:
    RegisterWriteRequest(const std::string &data)
      : GDBRequestPacketBase(data, 'P')
    {
      _register_id = read_hex_number<uint16_t>();
      expect_char('=');
      _value = read_hex_number_respecting_endianness<uint64_t>();
      if (check_char(';')) {
        expect_string("thread:");
        _thread_id = read_hex_number<size_t>();
        expect_char(';');
      }
      expect_end();
    };

    uint16_t get_register_id() const { return _register_id; };
    uint64_t get_value() const { return _value; };
    size_t get_thread_id() const { return _thread_id; };

  private:
    uint16_t _register_id;
    uint64_t _value;
    size_t _thread_id;
  };

  DECLARE_SIMPLE_REQUEST(GeneralRegistersBatchReadRequest, 'g');

  class GeneralRegistersBatchWriteRequest : public GDBRequestPacketBase {
  private:
    using Value = std::variant<uint64_t, uint32_t, uint16_t, uint8_t>;
    using Values =  std::vector<std::pair<size_t, Value>>;

  public:
    GeneralRegistersBatchWriteRequest(const std::string &data)
      : GDBRequestPacketBase(data, 'g')
    {
      using Regs64 = xd::reg::x86_64::RegistersX86_64;
      using Regs32 = xd::reg::x86_32::RegistersX86_32;

      size_t index = 0;
      const auto size = get_num_remaining()/2;

      if (size == Regs64::size) {
        Regs64::for_each_metadata([this, &index](const auto md) {
          const auto word = read_word(md);
          if (word)
            _values.push_back(std::make_pair(index, *word));
          ++index;
        });
      } else if (size == Regs32::size) {
        Regs32::for_each_metadata([this, &index](const auto md) {
          const auto word = read_word(md);
          if (word)
            _values.push_back(std::make_pair(index, *word));
          ++index;
        });
      } else {
        throw RequestPacketParseException();
      }
      expect_end();
    };

    const Values& get_values() const { return _values; };

  private:
    Values _values;

    template <typename Metadata_t>
    std::optional<typename Metadata_t::Register::Value> read_word(
        const Metadata_t&)
    {
      using RegisterValue = typename Metadata_t::Register::Value;
      return read_word_unsigned_opt<RegisterValue>();
    }
  };

  class MemoryReadRequest : public GDBRequestPacketBase {
  public:
    MemoryReadRequest(const std::string &data)
      : GDBRequestPacketBase(data, 'm')
    {
      _address = read_hex_number<uint64_t>();
      expect_char(',');
      _length = read_hex_number<uint64_t>();
      expect_end();
    };

    uint64_t get_address() const { return _address; };
    uint64_t get_length() const { return _length; };

  private:
    uint64_t _address;
    uint64_t _length;
  };

  class MemoryWriteRequest : public GDBRequestPacketBase {
  public:
    MemoryWriteRequest(const std::string &data)
      : GDBRequestPacketBase(data, 'M')
    {
      _address = read_hex_number<uint64_t>();
      expect_char(',');
      _length = read_hex_number<uint64_t>();
      expect_char(':');

      _data.reserve(_length);
      for (size_t i = 0; i < _length; ++i)
        _data.push_back(read_byte());

      expect_end();
    };

    uint64_t get_address() const { return _address; };
    uint64_t get_length() const { return _length; };
    const std::vector<unsigned char>& get_data() const { return _data; };

  private:
    uint64_t _address;
    uint64_t _length;
    std::vector<unsigned char> _data;
  };

  DECLARE_SIGNAL_REQUESTS(ContinueRequest, 'c', ContinueSignalRequest, 'C');
  DECLARE_SIGNAL_REQUESTS(StepRequest, 's', StepSignalRequest, 'S');

  DECLARE_BREAKPOINT_REQUEST(BreakpointInsertRequest, 'Z');
  DECLARE_BREAKPOINT_REQUEST(BreakpointRemoveRequest, 'z');

  DECLARE_SIMPLE_REQUEST(QueryHostInfoRequest, "qHostInfo");
  DECLARE_SIMPLE_REQUEST(QueryProcessInfoRequest, "qProcessInfo");

  class QueryMemoryRegionInfoRequest : public GDBRequestPacketBase {
  public:
    QueryMemoryRegionInfoRequest(const std::string &data)
      : GDBRequestPacketBase(data, "qMemoryRegionInfo")
    {
      expect_char(':');
      _address = read_hex_number<uint64_t>();
      expect_end();
    };

    uint64_t get_address() const { return _address; };

  private:
    uint64_t _address;
  };

  using GDBRequestPacket = std::variant<
    StartNoAckModeRequest,
    QuerySupportedRequest,
    QueryThreadSuffixSupportedRequest,
    QueryListThreadsInStopReplySupportedRequest,
    QueryCurrentThreadIDRequest,
    QueryThreadInfoStartRequest,
    QueryThreadInfoContinuingRequest,
    QueryHostInfoRequest,
    QueryProcessInfoRequest,
    QueryRegisterInfoRequest,
    QueryMemoryRegionInfoRequest,
    StopReasonRequest,
    KillRequest,
    SetThreadRequest,
    RegisterReadRequest,
    RegisterWriteRequest,
    GeneralRegistersBatchReadRequest,
    GeneralRegistersBatchWriteRequest,
    MemoryReadRequest,
    MemoryWriteRequest,
    ContinueRequest,
    ContinueSignalRequest,
    StepRequest,
    StepSignalRequest,
    BreakpointInsertRequest,
    BreakpointRemoveRequest,
    RestartRequest,
    DetachRequest>;

}

#endif //XENDBG_GDBREQUESTPACKET_HPP
