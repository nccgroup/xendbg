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
