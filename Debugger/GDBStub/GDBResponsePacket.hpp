//
// Created by Spencer Michaels on 9/5/18.
//

#ifndef XENDBG_GDBRESPONSEPACKET_HPP
#define XENDBG_GDBRESPONSEPACKET_HPP

#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <variant>
#include <vector>

#include "../../Registers/RegistersX86.hpp"
#include "../../Util/overloaded.hpp"

namespace xd::dbg::gdbstub::pkt {

  namespace {
    // Writes the bytes of a value of arbitrary size in guest order
    template <typename Value_t>
    void write_bytes(std::stringstream &ss, Value_t value) {
      unsigned char *p = (unsigned char*)&value;
      unsigned char *end = p + sizeof(Value_t);

      ss << std::hex << std::setfill('0');
      while (p != end)
        ss << std::setw(2) << (unsigned)(*p++);
    }

    std::string hexify(const std::string& s) {
      std::stringstream ss;
      ss << std::hex << std::setfill('0');
      for (const unsigned char &c : s)
        ss << std::setw(2) << (unsigned)c;
      return ss.str();
    }

    template <typename Key_t, typename Value_t>
    void add_list_entry(std::stringstream &ss, Key_t key, Value_t value) {
      ss << key;
      ss << ":";
      ss << value;
      ss << ";";
    }
  }

  class GDBResponsePacket {
  public:
    virtual ~GDBResponsePacket() = default;
    virtual std::string to_string() const = 0;
  };

  class OKResponse : public GDBResponsePacket {
  public:
    std::string to_string() const override { return "OK"; };
  };

  class NotSupportedResponse : public GDBResponsePacket {
  public:
    std::string to_string() const override { return ""; };
  };

  class ErrorResponse : public GDBResponsePacket {
  public:
    ErrorResponse(uint8_t error_code)
      : _error_code(error_code) {};

    std::string to_string() const override {
      std::stringstream ss;
      ss << "E" << std::hex << std::setfill('0') << std::setw(2) << (unsigned)_error_code;
      return ss.str();
    };

  private:
    uint8_t _error_code;
  };

  class QuerySupportedResponse : public GDBResponsePacket {
  public:
    QuerySupportedResponse(std::vector<std::string> features)
      : _features(features) {};

    std::string to_string() const override {
      if (_features.empty())
        return "";

      std::stringstream ss;
      ss << _features.front();
      std::for_each(_features.begin()+1, _features.end(),
        [&ss](const auto& feature) {
          ss << ";" << feature;
        }
      );
      return ss.str();
    }

  private:
    std::vector<std::string> _features;
  };

  // NOTE: thread ID 0 = any thread, ID -1 = all threads
  // so these have to be zero-indexed.
  class QueryCurrentThreadIDResponse : public GDBResponsePacket {
  public:
    QueryCurrentThreadIDResponse(size_t thread_id)
      : _thread_id(thread_id) {}

    std::string to_string() const override {
      std::stringstream ss;
      ss << "QC";
      if (_thread_id == (size_t)-1) {
        ss << "-1";
      } else {
        ss << std::hex;
        ss << _thread_id;
      }
      return ss.str();
    }

  private:
    size_t _thread_id;
  };

  class QueryThreadInfoResponse : public GDBResponsePacket {
  public:
    QueryThreadInfoResponse(std::vector<size_t> thread_ids)
      : _thread_ids(thread_ids)
    {
      if (thread_ids.empty())
        throw std::runtime_error("Must provide at least one thread ID!");
    };

    std::string to_string() const override {
      std::stringstream ss;

      ss << "m";
      ss << std::hex;
      ss << _thread_ids.front();
      std::for_each(_thread_ids.begin()+1, _thread_ids.end(),
        [&ss](const auto& tid) {
          ss << "," << tid;
        });

      return ss.str();
    };

  private:
    const std::vector<size_t> _thread_ids;
  };

  class QueryThreadInfoEndResponse : public GDBResponsePacket {
  public:
    std::string to_string() const override {
      return "l";
    };
  };

  class RegisterReadResponse : public GDBResponsePacket {
  public:
    RegisterReadResponse(uint64_t value, int width = sizeof(uint64_t))
      : _value(value), _width(width) {};

    std::string to_string() const override {
      std::stringstream ss;
      write_bytes(ss, _value);
      return ss.str();
    };

  private:
    uint64_t _value;
    int _width;
  };

  class GeneralRegistersBatchReadResponse : public GDBResponsePacket {
  public:
    GeneralRegistersBatchReadResponse(reg::RegistersX86 registers)
      : _registers(registers) {}

  std::string to_string() const override {
    std::stringstream ss;

    ss << std::hex << std::setfill('0');
    std::visit(util::overloaded {
      [&ss](const reg::x86_64::RegistersX86_64& regs) {
        regs.for_each([&ss](const auto&, const auto &reg) {
          write_register(ss, reg);
        });
      },
      [&ss](const reg::x86_32::RegistersX86_32& regs) {
        regs.for_each([&ss](const auto&, const auto &reg) {
          write_register(ss, reg);
        });
      },
    }, _registers);

    return ss.str();
  }

  template <typename Reg_t>
  static void write_register(std::stringstream &ss, const Reg_t&reg) {
    ss << std::setw(2*sizeof(typename Reg_t::Value)) << reg;
  }

  private:
    reg::RegistersX86 _registers;
  };

  class MemoryReadResponse : public GDBResponsePacket {
  public:
    MemoryReadResponse(const unsigned char * const data, size_t length)
      : _data(data, data + length) {};

    std::string to_string() const override {
      std::stringstream ss;

      ss << std::hex << std::setfill('0');
      std::for_each(_data.begin(), _data.end(),
        [&ss](const unsigned char &ch) {
          ss << std::setw(2) << (unsigned)ch;
        });

      return ss.str();
    };

  private:
    std::vector<unsigned char> _data;
  };

  class StopReasonSignalResponse : public GDBResponsePacket {
  public:
    StopReasonSignalResponse(uint8_t signal, size_t thread_id)
      : _signal(signal), _thread_id(thread_id) {};

    std::string to_string() const override {
      std::stringstream ss;
      ss << "T";
      ss << std::hex << std::setfill('0') << std::setw(2);
      ss << (unsigned)_signal;
      ss << "thread:";
      ss << _thread_id;
      ss << ";name:test";
      ss << ";threads:";
      ss << _thread_id;
      ss << ";reason:signal;";
      return ss.str();
    };

  private:
    uint8_t _signal;
    size_t _thread_id;
  };

  // See https://github.com/llvm-mirror/lldb/blob/master/docs/lldb-gdb-remote.txt#L756
  class QueryHostInfoResponse : public GDBResponsePacket {
  public:
    QueryHostInfoResponse(unsigned word_size, std::string hostname)
      : _word_size(word_size), _hostname(std::move(hostname)) 
    {};

    std::string to_string() const override {
      std::stringstream ss;


      ss << "triple:7838365f36342d70632d6c696e75782d676e75;ptrsize:8;endian:little;hostname:7468696e6b706164;";
      //add_list_entry(ss, "triple", hexify(make_triple()));
      add_list_entry(ss, "endian", "little"); // TODO can this ever be big?
      add_list_entry(ss, "ptrsize", _word_size);
      add_list_entry(ss, "hostname", hexify(_hostname));
      return ss.str();
    };

  private:
    std::string make_triple() const {
      const auto arch = (_word_size == sizeof(uint64_t)) ? "x86_64" : "x86";
      const auto vendor = "pc";
      const auto os_type = "nacl";

      std::string triple;
      triple += arch;
      triple += "-";
      triple += vendor;
      triple += "-";
      triple += os_type;

      return triple;
    }

    unsigned _word_size;
    std::string _hostname;
  };

  class QueryProcessInfoResponse : public GDBResponsePacket {
  public:
    QueryProcessInfoResponse(size_t pid)
      : _pid(pid) {};

    std::string to_string() const override {
      std::stringstream ss;
      add_list_entry(ss, "pid", _pid);
      add_list_entry(ss, "ptrsize", sizeof(uint64_t));
      add_list_entry(ss, "endian", "little");     // TODO
      return ss.str();
    };

  private:
    size_t _pid;
  };

  class QueryRegisterInfoResponse : public GDBResponsePacket {
  public:
    QueryRegisterInfoResponse(
        std::string name, size_t width, size_t offset,
          size_t gcc_register_id)
      : _name(std::move(name)), _width(width), _offset(offset),
        _gcc_register_id(gcc_register_id)
    {};

    std::string to_string() const override {
      std::stringstream ss;
      add_list_entry(ss, "name", _name);
      add_list_entry(ss, "bitsize", _width);
      add_list_entry(ss, "offset", _offset);
      add_list_entry(ss, "encoding", "uint");
      add_list_entry(ss, "format", "hex");
      add_list_entry(ss, "set", "General Purpose Registers");
      if (_gcc_register_id != (size_t)-1) {
        add_list_entry(ss, "ehframe", _gcc_register_id);
        add_list_entry(ss, "dwarf", _gcc_register_id); // TODO
      }
      return ss.str();
    };

  private:
    std::string _name;
    size_t _width;
    size_t _offset;
    size_t _gcc_register_id;
  };

}

#endif //XENDBG_GDBRESPONSEPACKET_HPP
