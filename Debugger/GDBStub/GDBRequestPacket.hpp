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
#include "../../Util/overloaded.hpp"

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
      skip_space(); \
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
      skip_space(); \
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
      uint8_t c1 = get_char();
      uint8_t c2 = get_char();
      return (c1 << 4) + c2;
    };

    uint64_t read_hex_number() {
      size_t end;
      const std::string num_str(_it, _data.end());
      uint64_t num = std::stoull(num_str, &end, 16);

      _it += end;

      return num;
    };

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

      _it = _data.begin() + SIZE;
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
      skip_space();
      expect_char(':');
      while (has_more()) {
        const auto feature = read_until_char_or_end(';');
        std::cout << feature << std::endl;
        _features.push_back(feature);
      }
      expect_end();
    };

    const std::vector<std::string> get_features() { return _features; };

  private:
    std::vector<std::string> _features;
  };

  class RestartRequest : public GDBRequestPacketBase {
  public:
    RestartRequest(const std::string &data)
      : GDBRequestPacketBase(data, 'R')
    {
      skip_space();
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
      _register_id = read_hex_number();
      expect_end();
    };

    uint16_t get_register_id() const { return _register_id; };

  private:
    uint16_t _register_id;
  };

  DECLARE_SIMPLE_REQUEST(StopReasonRequest, '?');

  class SetThreadRequest : public GDBRequestPacketBase {
  public:
    SetThreadRequest(const std::string &data)
      : GDBRequestPacketBase(data, 'H')
    {
      skip_space();
      if (check_char('c'))
        _op = Op::StepAndContinue;
      else if (check_char('g'))
        _op = Op::StepAndContinue;

      skip_space();
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

  class RegisterReadRequest : public GDBRequestPacketBase {
  public:
    RegisterReadRequest(const std::string &data)
      : GDBRequestPacketBase(data, 'p')
    {
      skip_space();
      _register_id = read_hex_number();
      expect_end();
    };

    uint16_t get_register_id() const { return _register_id; };

  private:
    uint16_t _register_id;
  };

  class RegisterWriteRequest : public GDBRequestPacketBase {
  public:
    RegisterWriteRequest(const std::string &data)
      : GDBRequestPacketBase(data, 'P')
    {
      skip_space();
      _register_id = read_byte();
      expect_char('=');
      _value = read_hex_number();
      expect_end();
    };

    uint16_t get_register_id() const { return _register_id; };
    uint64_t get_value() const { return _value; };

  private:
    uint16_t _register_id;
    uint64_t _value;
  };

  DECLARE_SIMPLE_REQUEST(GeneralRegistersBatchReadRequest, 'g');

  class GeneralRegistersBatchWriteRequest : public GDBRequestPacketBase {
  public:
    GeneralRegistersBatchWriteRequest(const std::string &data)
      : GDBRequestPacketBase(data, 'g')
    {
      skip_space();

      const auto size = get_num_remaining()/2;
      if (size == sizeof(GDBRegisters64Values)) {
        _registers = read_registers_64();
      } else if (size == sizeof(GDBRegisters32Values)) {
        _registers = read_registers_32();
      } else {
        throw RequestPacketParseException();
      }
    };

    const GDBRegisters &get_registers() const { return _registers; };

  private:
    GDBRegisters64 read_registers_64() {
      GDBRegisters64 regs;

      read_register(regs.values.rax, regs.flags.rax);
      read_register(regs.values.rbx, regs.flags.rbx);
      read_register(regs.values.rcx, regs.flags.rcx);
      read_register(regs.values.rdx, regs.flags.rdx);
      read_register(regs.values.rsi, regs.flags.rsi);
      read_register(regs.values.rdi, regs.flags.rdi);
      read_register(regs.values.rbp, regs.flags.rbp);
      read_register(regs.values.rsp, regs.flags.rsp);

      read_register(regs.values.r8, regs.flags.r8);
      read_register(regs.values.r9, regs.flags.r9);
      read_register(regs.values.r10, regs.flags.r10);
      read_register(regs.values.r11, regs.flags.r11);
      read_register(regs.values.r12, regs.flags.r12);
      read_register(regs.values.r13, regs.flags.r13);
      read_register(regs.values.r14, regs.flags.r14);
      read_register(regs.values.r15, regs.flags.r15);

      read_register(regs.values.rip, regs.flags.rip);

      read_register(regs.values.rflags, regs.flags.rflags);
      read_register(regs.values.cs, regs.flags.cs);
      read_register(regs.values.ss, regs.flags.ss);
      read_register(regs.values.ds, regs.flags.ds);
      read_register(regs.values.es, regs.flags.es);
      read_register(regs.values.fs, regs.flags.fs);
      read_register(regs.values.gs, regs.flags.gs);

      return regs;
    }

    GDBRegisters32 read_registers_32() {
      GDBRegisters32 regs;

      read_register(regs.values.eax, regs.flags.eax);
      read_register(regs.values.eax, regs.flags.ecx);
      read_register(regs.values.eax, regs.flags.edx);
      read_register(regs.values.eax, regs.flags.ebx);
      read_register(regs.values.eax, regs.flags.esp);
      read_register(regs.values.eax, regs.flags.ebp);
      read_register(regs.values.eax, regs.flags.esi);
      read_register(regs.values.eax, regs.flags.edi);

      read_register(regs.values.eax, regs.flags.eip);

      read_register(regs.values.eax, regs.flags.eflags);

      read_register(regs.values.eax, regs.flags.cs);
      read_register(regs.values.eax, regs.flags.ss);
      read_register(regs.values.eax, regs.flags.ds);
      read_register(regs.values.eax, regs.flags.es);
      read_register(regs.values.eax, regs.flags.fs);
      read_register(regs.values.eax, regs.flags.gs);

      return regs;
    }

    template <typename Reg_t, typename Flag_t>
    void read_register(Reg_t &value, Flag_t &flag) {
      const auto value_opt = read_word_unsigned_opt<Reg_t>();
      if (value_opt)
        value = *value_opt;
      flag = value_opt.has_value();
    }

  private:
    GDBRegisters _registers;
  };

  class MemoryReadRequest : public GDBRequestPacketBase {
  public:
    MemoryReadRequest(const std::string &data)
      : GDBRequestPacketBase(data, 'm')
    {
      skip_space();
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
      skip_space();
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
    const char * get_data() const { return &_data[0]; };

  private:
    uint64_t _address;
    uint64_t _length;
    std::vector<char> _data;
  };

  DECLARE_SIGNAL_REQUESTS(ContinueRequest, 'c', ContinueSignalRequest, 'C');
  DECLARE_SIGNAL_REQUESTS(StepRequest, 's', StepSignalRequest, 'S');

  DECLARE_BREAKPOINT_REQUEST(BreakpointInsertRequest, 'z');
  DECLARE_BREAKPOINT_REQUEST(BreakpointRemoveRequest, 'Z');

  DECLARE_SIMPLE_REQUEST(QueryHostInfoRequest, "qHostInfo");
  DECLARE_SIMPLE_REQUEST(QueryProcessInfoRequest, "qProcessInfo");

  using GDBRequestPacket = std::variant<
    StartNoAckModeRequest,
    QuerySupportedRequest,
    QueryCurrentThreadIDRequest,
    QueryThreadInfoStartRequest,
    QueryThreadInfoContinuingRequest,
    QueryHostInfoRequest,
    QueryProcessInfoRequest,
    QueryRegisterInfoRequest,
    StopReasonRequest,
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
