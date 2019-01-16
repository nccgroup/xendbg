//
// Copyright (C) 2018-2019 NCC Group
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
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
