//
// Created by Spencer Michaels on 10/1/18.
//

#include <GDBServer/GDBResponse/GDBRegisterResponse.hpp>

using namespace xd::gdb::rsp;

std::string RegisterReadResponse::to_string() const {
  std::stringstream ss;
  write_bytes(ss, _value);
  return ss.str();
};

std::string GeneralRegistersBatchReadResponse::to_string() const {
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
