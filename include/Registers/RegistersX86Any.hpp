//
// Created by Spencer Michaels on 9/10/18.
//

#ifndef XENDBG_REGISTERSX86ANY_HPP
#define XENDBG_REGISTERSX86ANY_HPP

#include <variant>

#include "RegistersX86_32.hpp"
#include "RegistersX86_64.hpp"
#include <Util/overloaded.hpp>

namespace xd::reg {

  using RegistersX86Any = std::variant<
    x86_32::RegistersX86_32,
    x86_64::RegistersX86_64>;

  template <typename Reg32_t, typename Reg64_t>
  uint64_t read_register(const RegistersX86Any &regs) {
    return std::visit(util::overloaded {
        [](const reg::x86_32::RegistersX86_32 &regs) {
          return (uint64_t)regs.get<Reg32_t>();
        },
        [](const reg::x86_64::RegistersX86_64 &regs) {
          return (uint64_t)regs.get<Reg64_t>();
        }
    }, regs);
  }

}

#endif //XENDBG_REGISTERS_HPP
