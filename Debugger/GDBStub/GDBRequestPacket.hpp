//
// Created by Spencer Michaels on 9/5/18.
//

#ifndef XENDBG_GDBREQUESTPACKET_HPP
#define XENDBG_GDBREQUESTPACKET_HPP

#include <iostream>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <variant>
#include <vector>

#include "GDBRegisters.hpp"

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
      expect_space(); \
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
      : GDBRequestPacketBase(data, 'z') \
    { \
      expect_space(); \
      _type = read_hex_number(); \
      expect_char(','); \
      _address = read_hex_number(); \
      expect_char(','); \
      _kind = read_hex_number(); \
      expect_end(); \
    }; \
    uint64_t get_address() const { return _address; }; \
    uint8_t get_type() const { return _type; }; \
    uint8_t get_kind() const { return _kind; }; \
    const char * data() const { return &_data[0]; }; \
  private: \
    uint64_t _address; \
    uint8_t _type, _kind; \
    std::vector<char> _data; \
  }

namespace xd::dbg::gdbstub::pkt {

  class RequestPacketParseException : public std::exception {
  };

  class GDBRequestPacketBase {
  public:
    GDBRequestPacketBase(const std::string &data, char header)
      : _data(data), _it(_data.begin())
    {
      expect_char(header);
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

    void expect_space() {
      expect_char(' ');
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
      uint8_t c1 = get_char();
      uint8_t c2 = get_char();
      return (c1 << 4) + c2;
    };

    uint64_t read_hex_number() {
      assert_char_not('-');

      size_t end;
      uint64_t num = std::stoull(_data, &end, 16);
      _it = _data.begin() + end;
      return num;
    };

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

      _it = _data.begin() + SIZE;
      return num;
    }

  private:
    const std::string _data;
    std::string::const_iterator _it;
  };

  class RestartRequest : public GDBRequestPacketBase {
  public:
    RestartRequest(const std::string &data)
      : GDBRequestPacketBase(data, 'R')
    {
      expect_space();
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
        _pid = read_hex_number();
      }
      expect_end();
    };

  private:
    size_t _pid;
  };

  class QueryThreadInfoRequest : public GDBRequestPacketBase {
  public:
    QueryThreadInfoRequest(const std::string &data)
      : GDBRequestPacketBase(data, 'q'), _pid(0)
    {
      expect_string("fThreadInfo");
      expect_end();
    };

  private:
    int _pid;
  };

  DECLARE_SIMPLE_REQUEST(StopReasonRequest, '?');

  class SetThreadRequest : public GDBRequestPacketBase {
  public:
    SetThreadRequest(const std::string &data)
      : GDBRequestPacketBase(data, 'H')
    {
      expect_space();
      if (check_char('c'))
        _op = Op::StepAndContinue;
      else if (check_char('g'))
        _op = Op::StepAndContinue;

      expect_space();
      _thread_id = read_hex_number();
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

  DECLARE_SIMPLE_REQUEST(GeneralRegisterReadRequest, 'g');

  class GeneralRegisterWriteRequest : public GDBRequestPacketBase {
  public:
    GeneralRegisterWriteRequest(const std::string &data)
      : GDBRequestPacketBase(data, 'g')
    {
      expect_space();

      const auto size = get_num_remaining();
      if (size == 2*sizeof(GDBRegisters64)) {
        _registers = read_registers<GDBRegisters64>();
      } else if (size == 2*sizeof(GDBRegisters32)) {
        _registers = read_registers<GDBRegisters32>();
      } else {
        throw RequestPacketParseException();
      }
    };

    const GDBRegisters &get_registers() const { return _registers; };

  private:
    template <typename Regs_t>
    Regs_t read_registers() {
      Regs_t regs;
      using Word = typename decltype(regs.values)::ValueType;
      using Flag = typename decltype(regs.flags)::ValueType;

      auto values_ptr = (Word*)&regs.values;
      auto flags_ptr = (Flag*)&regs.flags;
      const auto num_regs = sizeof(Regs_t)/sizeof(Word);

      for (size_t i = 0; i < num_regs; ++i) {
        const auto word_opt = read_word_unsigned_opt<Word>();
        *values_ptr++ = word_opt ? *word_opt : 0;
        *flags_ptr++ = word_opt.has_value();
      }

      return regs;
    }

  private:
    GDBRegisters _registers;
  };

  class MemoryReadRequest : public GDBRequestPacketBase {
  public:
    MemoryReadRequest(const std::string &data)
      : GDBRequestPacketBase(data, 'm')
    {
      expect_space();
      _address = read_hex_number();
      expect_char(',');
      _length = read_hex_number();
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
      expect_space();
      _address = read_hex_number();
      expect_char(',');
      _length = read_hex_number();
      expect_char(':');

      _data.reserve(_length);
      for (size_t i = 0; i < _length; ++i) {
        _data.push_back(read_byte());
      }

      expect_end();
    };

    uint64_t get_address() const { return _address; };
    uint64_t get_length() const { return _length; };
    const char * data() const { return &_data[0]; };

  private:
    uint64_t _address;
    uint64_t _length;
    std::vector<char> _data;
  };

  DECLARE_SIGNAL_REQUESTS(ContinueRequest, 'c', ContinueSignalRequest, 'C');
  DECLARE_SIGNAL_REQUESTS(StepRequest, 's', StepSignalRequest, 'S');

  DECLARE_BREAKPOINT_REQUEST(BreakpointInsertRequest, 'z');
  DECLARE_BREAKPOINT_REQUEST(BreakpointRemoveRequest, 'Z');

  using GDBRequestPacket = std::variant<
    QueryThreadInfoRequest,
    StopReasonRequest,
    SetThreadRequest,
    GeneralRegisterReadRequest,
    GeneralRegisterWriteRequest,
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
