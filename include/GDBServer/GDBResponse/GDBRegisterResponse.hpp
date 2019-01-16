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

    std::string to_string() const override;

  private:
    uint64_t _value;
    int _width;
  };

  class GeneralRegistersBatchReadResponse : public GDBResponse {
  public:
    explicit GeneralRegistersBatchReadResponse(xd::reg::RegistersX86Any registers)
      : _registers(std::move(registers)) {}

    std::string to_string() const override;

    template <typename Reg_t>
    static void write_register(std::stringstream &ss, const Reg_t&reg) {
      ss << std::setw(2*sizeof(typename Reg_t::Value)) << reg;
    }

  private:
    xd::reg::RegistersX86Any _registers;
  };

}

#endif //XENDBG_GDBREGISTERRESPONSE_HPP
