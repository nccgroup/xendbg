//
// Created by Spencer Michaels on 9/5/18.
//

#ifndef XENDBG_GDBRESPONSEPACKET_HPP
#define XENDBG_GDBRESPONSEPACKET_HPP

#include <iomanip>
#include <sstream>
#include <string>
#include <variant>
#include <vector>

#include "GDBRegisters.hpp"
#include "../../Util/overloaded.hpp"

namespace xd::dbg::gdbstub::pkt {

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
      ss << "E" << std::hex << std::setfill('0') << std::setw(2) << _error_code;
      return ss.str();
    };

  private:
    uint8_t _error_code;
  };

  class QueryThreadInfoResponse : public GDBResponsePacket {
  public:
    QueryThreadInfoResponse(std::vector<size_t> thread_ids)
      : _thread_ids(thread_ids) {};

    std::string to_string() const override {
      std::stringstream ss;

      ss << "m";
      if (!_thread_ids.empty()) {
        ss << _thread_ids.front();
        std::for_each(_thread_ids.begin()+1, _thread_ids.end(),
          [&ss](const auto& tid) {
            ss << "," << tid;
          });
      }
      ss << "l";

      return ss.str();
    };

  private:
    const std::vector<size_t> _thread_ids;
  };

  class GeneralRegisterReadResponse : public GDBResponsePacket {
  public:
    GeneralRegisterReadResponse(GDBRegisters registers)
      : _registers(registers) {}

  std::string to_string() const override {
    std::stringstream ss;
    ss << std::hex;

    std::visit(util::overloaded {
      [this, &ss](const GDBRegisters64& regs) {
        write_registers(ss, regs);
      },
      [this, &ss](const GDBRegisters32& regs) {
        write_registers(ss, regs);
      },
    }, _registers);

    return ss.str();
  }

  template <typename Regs_t>
  void write_registers(std::stringstream &ss, const Regs_t &regs) const {
    using Word = typename decltype(regs.values)::ValueType;

    const auto num_regs = sizeof(Regs_t)/sizeof(Word);
    Word *regs_ptr = (Word*)&regs.values;

    for (size_t i = 0; i < num_regs; ++i) {
      ss << *((Word*)(regs_ptr++));
    }
  }

  private:
      GDBRegisters _registers;
  };

  class MemoryReadResponse : public GDBResponsePacket {
  public:
    MemoryReadResponse(const char * const data, size_t length)
      : _data(data, data + length) {};

    std::string to_string() const override {
      std::stringstream ss;

      ss << std::hex << std::setfill('0');
      std::for_each(_data.begin(), _data.end(),
        [&ss](const auto &ch) {
          ss << std::setw(2) << ch;
        });

      return ss.str();
    };

  private:
    std::vector<char> _data;
  };

}

#endif //XENDBG_GDBRESPONSEPACKET_HPP
