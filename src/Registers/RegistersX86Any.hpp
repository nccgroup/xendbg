//
// Created by Spencer Michaels on 9/10/18.
//

#ifndef XENDBG_REGISTERSX86ANY_HPP
#define XENDBG_REGISTERSX86ANY_HPP

#include <variant>

#include "RegistersX86_32.hpp"
#include "RegistersX86_64.hpp"

namespace xd::reg {

  using RegistersX86Any = std::variant<
    x86_32::RegistersX86_32,
    x86_64::RegistersX86_64>;

}

#endif //XENDBG_REGISTERS_HPP
