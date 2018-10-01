//
// Created by Spencer Michaels on 10/1/18.
//

#ifndef XENDBG_GDBREGISTERRESPONSE_HPP
#define XENDBG_GDBREGISTERRESPONSE_HPP

#include <variant>

#include <Registers/RegistersX86Any.hpp>

#include "GDBResponseBase.hpp"

namespace xd::gdb::rsp {

  class RegisterReadResponse : public GDBResponse {
  public:
    explicit RegisterReadResponse(uint64_t value, int width = sizeof(uint64_t))
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

  class GeneralRegistersBatchReadResponse : public GDBResponse {
  public:
    explicit GeneralRegistersBatchReadResponse(xd::reg::RegistersX86Any registers)
      : _registers(std::move(registers)) {}

    std::string to_string() const override {
      std::stringstream ss;

      ss << std::hex << std::setfill('0');
      std::visit(util::overloaded {
        [&ss](const xd::reg::x86_64::RegistersX86_64& regs) {
          regs.for_each([&ss](const auto&, const auto &reg) {
            write_register(ss, reg);
          });
        },
        [&ss](const xd::reg::x86_32::RegistersX86_32& regs) {
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
    xd::reg::RegistersX86Any _registers;
  };

}

#endif //XENDBG_GDBREGISTERRESPONSE_HPP
