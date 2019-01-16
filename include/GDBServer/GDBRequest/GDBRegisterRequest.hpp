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

#ifndef XENDBG_GDBREGISTERREQUEST_HPP
#define XENDBG_GDBREGISTERREQUEST_HPP

#include <variant>
#include <vector>

#include <Registers/RegistersX86_32.hpp>
#include <Registers/RegistersX86_64.hpp>

#include "GDBRequestBase.hpp"

namespace xd::gdb::req {

  class GeneralRegistersBatchReadRequest : public GDBRequestBase {
  public:
    explicit GeneralRegistersBatchReadRequest(const std::string &data);

    size_t get_thread_id() const { return _thread_id; };

  private:
    size_t _thread_id;
  };

  class RegisterReadRequest : public GDBRequestBase {
  public:
    explicit RegisterReadRequest(const std::string &data);

    uint16_t get_register_id() const { return _register_id; };
    size_t get_thread_id() const { return _thread_id; };

  private:
    uint16_t _register_id;
    size_t _thread_id;
  };

  class RegisterWriteRequest : public GDBRequestBase {
  public:
    explicit RegisterWriteRequest(const std::string &data);

    uint16_t get_register_id() const { return _register_id; };
    uint64_t get_value() const { return _value; };
    size_t get_thread_id() const { return _thread_id; };

  private:
    uint16_t _register_id;
    uint64_t _value;
    size_t _thread_id;
  };

  class GeneralRegistersBatchWriteRequest : public GDBRequestBase {
  private:
    using Value = std::variant<uint64_t, uint32_t, uint16_t, uint8_t>;
    using Values =  std::vector<std::pair<size_t, Value>>;

  public:
    explicit GeneralRegistersBatchWriteRequest(const std::string &data);

    const Values& get_values() const { return _values; };

  private:
    Values _values;

    template <typename Metadata_t>
    std::optional<typename Metadata_t::Register::Value> read_word(
        const Metadata_t&)
    {
      using RegisterValue = typename Metadata_t::Register::Value;
      return read_word_unsigned_opt<RegisterValue>();
    }
  };

}

#endif //XENDBG_GDBREGISTERREQUEST_HPP
